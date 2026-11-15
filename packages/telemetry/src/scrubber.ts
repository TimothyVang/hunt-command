/**
 * Deterministic pre-write and pre-wire credential scrubber.
 * Runs BEFORE hot SQLite span writes, cold Zstd blob compression, OTLP export, and LLM tool returns.
 */

import { scrubSecretText, scrubSecretValue } from "@hunt-command/shared";

/** Credential scrubbing is the single shared implementation in `@hunt-command/shared`. */
export function scrubSecrets(input: string): string {
  return scrubSecretText(input);
}

export function scrubSecretsValue<T>(value: T): T {
  return scrubSecretValue(value);
}

export function truncateUtf8Safe(input: string, maxBytes: number): string {
  if (maxBytes <= 0 || input.length === 0) {
    return "";
  }
  const buf = Buffer.from(input, "utf8");
  if (buf.byteLength <= maxBytes) {
    return input;
  }

  let end = maxBytes;
  while (end > 0 && (buf[end]! & 0xc0) === 0x80) {
    end--;
  }
  return buf.subarray(0, end).toString("utf8");
}

/**
 * Scrubs credentials FIRST (defeating boundary-split leaks) and returns a <= maxBytes UTF-8 preview.
 */
export function scrubQueryPreview(queryText: string, maxBytes = 512): string {
  const scrubbed = scrubSecrets(queryText);
  return truncateUtf8Safe(scrubbed, maxBytes);
}
