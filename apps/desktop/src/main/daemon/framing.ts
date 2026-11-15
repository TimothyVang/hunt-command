/**
 * Adapted from omp-desktop/app/src/main/rpc/framing.ts
 * Copyright (c) omp-desktop contributors (MIT License — see root THIRD-PARTY-NOTICES.md).
 * Modified for Hunt Command v2: bounded newline-delimited JSON framing for stdio RPC
 * between Electron main and persistent Bun `hunt-daemon`.
 */

export const DEFAULT_MAX_NDJSON_LINE_BYTES = 4 * 1024 * 1024;
const LF = 0x0a;

export class LineSplitter {
  #parts: Buffer[] = [];
  #size = 0;
  #discarding = false;

  constructor(
    private readonly onLine: (line: Buffer) => void,
    private readonly onOversize: (bytes: number) => void,
    public maxLineBytes: number = DEFAULT_MAX_NDJSON_LINE_BYTES,
  ) {}

  push(chunk: Buffer): void {
    let start = 0;
    while (start < chunk.length) {
      const nl = chunk.indexOf(LF, start);
      const end = nl === -1 ? chunk.length : nl;
      const piece = chunk.subarray(start, end);
      if (!this.#discarding) {
        if (this.#size + piece.length > this.maxLineBytes) {
          this.#discarding = true;
          this.onOversize(this.#size + piece.length);
          this.#parts = [];
        } else if (piece.length > 0) {
          this.#parts.push(piece);
        }
      }
      this.#size += piece.length;
      if (nl === -1) {
        return;
      }
      if (!this.#discarding) {
        const line =
          this.#parts.length === 1 ? (this.#parts[0] as Buffer) : Buffer.concat(this.#parts);
        this.#parts = [];
        this.#size = 0;
        this.onLine(line);
      } else {
        this.#discarding = false;
        this.#size = 0;
      }
      start = nl + 1;
    }
  }

  end(): void {
    if (!this.#discarding && this.#parts.length > 0) {
      const line = Buffer.concat(this.#parts);
      this.#parts = [];
      this.#size = 0;
      this.onLine(line);
    }
    this.#parts = [];
    this.#size = 0;
    this.#discarding = false;
  }
}
