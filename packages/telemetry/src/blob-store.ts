import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { findEnclosingGitMarker, RuntimeFenceError } from "@hunt-command/shared";
import { scrubSecretsValue } from "./scrubber.ts";

const SHA256_HEX_RE = /^[0-9a-f]{64}$/;

export interface BlobPutResult {
  sha256: string;
  uncompressedBytes: number;
  compressedBytes: number;
  deduplicated: boolean;
  blobPath: string;
}

export interface MessagesBatchPutResult {
  hashes: string[];
  totalUncompressedBytes: number;
  compressedBytesWritten: number;
  deduplicatedCount: number;
}

export interface ColdBlobGcOptions {
  maxAgeMs?: number;
  maxTotalBytes?: number;
  pinnedHashes?: ReadonlySet<string>;
  nowMs?: number;
}

export interface ColdBlobGcResult {
  scannedBlobs: number;
  removedBlobs: number;
  freedBytes: number;
  remainingBytes: number;
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map((item) => canonicalJson(item)).join(",") + "]";
  }
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return (
    "{" +
    entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(",") +
    "}"
  );
}

function sha256Hex(bytes: Uint8Array): string {
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update(bytes);
  return hasher.digest("hex");
}

/**
 * Cold Content-Addressed Zstd Store (`runtime/telemetry/blobs/<aa>/<sha256>.zst`).
 * Compresses individual message/tool blocks via `Bun.zstdCompressSync` after deterministic
 * credential scrubbing so cached multi-turn prompt prefixes deduplicate to 0 extra bytes.
 */
export class ContentAddressedZstdBlobStore {
  public readonly blobsDir: string;

  constructor(blobsDir: string) {
    const resolved = path.resolve(blobsDir);
    const gitMarker = findEnclosingGitMarker(resolved);
    if (gitMarker !== null) {
      throw new RuntimeFenceError(resolved, gitMarker);
    }
    this.blobsDir = resolved;
    fs.mkdirSync(this.blobsDir, { recursive: true });
  }

  public resolveBlobPath(sha256: string): string {
    if (!SHA256_HEX_RE.test(sha256)) {
      throw new Error(`Invalid blob SHA-256 identifier: '${sha256}'`);
    }
    return path.join(this.blobsDir, sha256.slice(0, 2), `${sha256}.zst`);
  }

  public hasBlock(sha256: string): boolean {
    if (!SHA256_HEX_RE.test(sha256)) {
      return false;
    }
    return fs.existsSync(this.resolveBlobPath(sha256));
  }

  public putBlock(block: unknown): BlobPutResult {
    const scrubbed = scrubSecretsValue(block);
    const serialized = canonicalJson(scrubbed);
    const rawBytes = Buffer.from(serialized, "utf8");
    const sha256 = sha256Hex(rawBytes);
    const shardDir = path.join(this.blobsDir, sha256.slice(0, 2));
    const targetPath = path.join(shardDir, `${sha256}.zst`);

    if (fs.existsSync(targetPath)) {
      const existingStat = fs.statSync(targetPath);
      return {
        sha256,
        uncompressedBytes: rawBytes.byteLength,
        compressedBytes: existingStat.size,
        deduplicated: true,
        blobPath: targetPath,
      };
    }

    fs.mkdirSync(shardDir, { recursive: true });
    const compressed = Bun.zstdCompressSync(rawBytes);
    const tmpPath = path.join(
      shardDir,
      `${sha256}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`,
    );

    try {
      fs.writeFileSync(tmpPath, compressed);
      try {
        fs.renameSync(tmpPath, targetPath);
      } catch (err) {
        if (fs.existsSync(targetPath)) {
          fs.rmSync(tmpPath, { force: true });
          const existingStat = fs.statSync(targetPath);
          return {
            sha256,
            uncompressedBytes: rawBytes.byteLength,
            compressedBytes: existingStat.size,
            deduplicated: true,
            blobPath: targetPath,
          };
        }
        throw err;
      }
    } finally {
      if (fs.existsSync(tmpPath)) {
        fs.rmSync(tmpPath, { force: true });
      }
    }

    return {
      sha256,
      uncompressedBytes: rawBytes.byteLength,
      compressedBytes: compressed.byteLength,
      deduplicated: false,
      blobPath: targetPath,
    };
  }

  public putMessages(messages: readonly unknown[]): MessagesBatchPutResult {
    const hashes: string[] = [];
    let totalUncompressedBytes = 0;
    let compressedBytesWritten = 0;
    let deduplicatedCount = 0;

    for (const message of messages) {
      const res = this.putBlock(message);
      hashes.push(res.sha256);
      totalUncompressedBytes += res.uncompressedBytes;
      if (res.deduplicated) {
        deduplicatedCount++;
      } else {
        compressedBytesWritten += res.compressedBytes;
      }
    }

    return {
      hashes,
      totalUncompressedBytes,
      compressedBytesWritten,
      deduplicatedCount,
    };
  }

  public getBlock<T = unknown>(sha256: string): T | null {
    const targetPath = this.resolveBlobPath(sha256);
    if (!fs.existsSync(targetPath)) {
      return null;
    }

    const compressed = fs.readFileSync(targetPath);
    const decompressed = Bun.zstdDecompressSync(compressed);
    const actualHash = sha256Hex(decompressed);
    if (actualHash !== sha256) {
      throw new Error(
        `Integrity failure reading blob '${sha256}': decompressed SHA-256 was '${actualHash}'`,
      );
    }

    const text = Buffer.from(decompressed).toString("utf8");
    return JSON.parse(text) as T;
  }

  public getMessages<T = unknown>(hashes: readonly string[]): T[] {
    const results: T[] = [];
    for (const hash of hashes) {
      const block = this.getBlock<T>(hash);
      if (block === null) {
        throw new Error(`Missing cold telemetry message blob '${hash}'`);
      }
      results.push(block);
    }
    return results;
  }

  public gc(options: ColdBlobGcOptions = {}): ColdBlobGcResult {
    const maxAgeMs = options.maxAgeMs ?? 14 * 24 * 60 * 60 * 1000;
    const maxTotalBytes = options.maxTotalBytes ?? 2 * 1024 * 1024 * 1024;
    const pinned = options.pinnedHashes ?? new Set<string>();
    const nowMs = options.nowMs ?? Date.now();

    const entries: Array<{
      hash: string;
      fullPath: string;
      size: number;
      mtimeMs: number;
    }> = [];

    if (!fs.existsSync(this.blobsDir)) {
      return { scannedBlobs: 0, removedBlobs: 0, freedBytes: 0, remainingBytes: 0 };
    }

    for (const shard of fs.readdirSync(this.blobsDir, { withFileTypes: true })) {
      if (!shard.isDirectory() || !/^[0-9a-f]{2}$/.test(shard.name)) {
        continue;
      }
      const shardPath = path.join(this.blobsDir, shard.name);
      for (const file of fs.readdirSync(shardPath, { withFileTypes: true })) {
        if (!file.isFile() || !file.name.endsWith(".zst")) {
          continue;
        }
        const hash = file.name.slice(0, -4);
        if (!SHA256_HEX_RE.test(hash)) {
          continue;
        }
        const fullPath = path.join(shardPath, file.name);
        const stat = fs.statSync(fullPath);
        entries.push({
          hash,
          fullPath,
          size: stat.size,
          mtimeMs: stat.mtimeMs,
        });
      }
    }

    let totalBytes = entries.reduce((sum, e) => sum + e.size, 0);
    let removedBlobs = 0;
    let freedBytes = 0;

    // Sort oldest first for deterministic age + LRU-style cap eviction.
    entries.sort((a, b) => a.mtimeMs - b.mtimeMs || (a.hash < b.hash ? -1 : 1));

    for (const entry of entries) {
      if (pinned.has(entry.hash)) {
        continue;
      }
      const expired = nowMs - entry.mtimeMs > maxAgeMs;
      const overCap = totalBytes > maxTotalBytes;
      if (expired || overCap) {
        fs.rmSync(entry.fullPath, { force: true });
        totalBytes -= entry.size;
        freedBytes += entry.size;
        removedBlobs++;
      }
    }

    return {
      scannedBlobs: entries.length,
      removedBlobs,
      freedBytes,
      remainingBytes: totalBytes,
    };
  }
}
