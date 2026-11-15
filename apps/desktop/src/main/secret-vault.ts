/**
 * Adapted from omp-desktop/app/src/main/features/bot/secrets.ts
 * Copyright (c) omp-desktop contributors (MIT License — see root THIRD-PARTY-NOTICES.md).
 * Modified for Hunt Command v2: Windows DPAPI (`safeStorage`) encrypted vault for Slack Socket Mode
 * (`xoxb-` / `xapp-`) or Connected Elastic keys. Decrypted strictly inside main at point of use;
 * never returned over IPC to the renderer, never passed in bot environments, and never logged.
 */
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import path from "node:path";
import { isRecord } from "../shared/guards.ts";

export interface Cipher {
  isEncryptionAvailable(): boolean;
  encryptString(plain: string): Buffer;
  decryptString(encrypted: Buffer): string;
}

export class SecretVault {
  public readonly file: string;
  readonly #cipher: Cipher;
  #entries: Record<string, string>;

  constructor(dir: string, cipher: Cipher) {
    this.file = path.join(dir, "secrets.json");
    this.#cipher = cipher;
    this.#entries = this.#load();
  }

  get available(): boolean {
    return this.#cipher.isEncryptionAvailable();
  }

  listRefs(): string[] {
    return Object.keys(this.#entries).sort();
  }

  has(ref: string): boolean {
    return Object.hasOwn(this.#entries, ref);
  }

  set(ref: string, secret: string): void {
    if (!this.available) {
      throw new Error("OS encryption (DPAPI safeStorage) is unavailable; refusing to persist secret");
    }
    const trimmed = secret.trim();
    if (trimmed.length === 0 || trimmed.length > 4096) {
      throw new Error("Secret must be 1..4096 non-whitespace characters");
    }
    this.#entries[ref] = this.#cipher.encryptString(trimmed).toString("base64");
    this.#save();
  }

  /** Decrypts strictly inside main process; error messages never echo ciphertext or plaintext. */
  getDecryptedInMainOnly(ref: string): string | null {
    const stored = this.#entries[ref];
    if (stored === undefined) {
      return null;
    }
    try {
      return this.#cipher.decryptString(Buffer.from(stored, "base64"));
    } catch {
      throw new Error("Stored secret could not be decrypted by OS DPAPI");
    }
  }

  delete(ref: string): void {
    if (!this.has(ref)) {
      return;
    }
    delete this.#entries[ref];
    this.#save();
  }

  #load(): Record<string, string> {
    try {
      const parsed: unknown = JSON.parse(readFileSync(this.file, "utf8"));
      if (!isRecord(parsed)) {
        return {};
      }
      const out: Record<string, string> = {};
      for (const [key, value] of Object.entries(parsed)) {
        if (typeof value === "string") {
          out[key] = value;
        }
      }
      return out;
    } catch {
      return {};
    }
  }

  #save(): void {
    mkdirSync(path.dirname(this.file), { recursive: true });
    const tmp = `${this.file}.tmp`;
    writeFileSync(tmp, `${JSON.stringify(this.#entries, null, 2)}\n`, {
      encoding: "utf8",
      mode: 0o600,
    });
    renameSync(tmp, this.file);
  }
}
