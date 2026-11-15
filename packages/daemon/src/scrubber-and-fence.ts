import crypto from "node:crypto";
import {
  DataPlaneAccessError,
  MAX_TOOL_RESULT_BYTES,
  assertReadOnlyOperation,
  assertRoleOwnsTool,
  scrubSecretText,
  scrubSecretValue,
  type HuntToolName,
  type ProfileId,
} from "@hunt-command/shared";
import type { RoleCapabilityToken } from "./ports.ts";

const NONCE_HEX_RE = /^[0-9a-f]{32}$/;

// ANSI CSI & OSC escape sequences
const ANSI_ESCAPE_RE =
  /\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]/g;

// Unicode bidi controls (U+202A..U+202E, U+2066..U+2069, U+061C, U+200E, U+200F)
const BIDI_CONTROL_RE = /[\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/g;

// Zero-width & invisible format chars (U+200B..U+200D, U+2060, U+FEFF, U+00AD)
const ZERO_WIDTH_RE = /[\u00AD\u200B-\u200D\u2060\uFEFF]/g;

// C0 & C1 control characters except \n (0x0A) and \t (0x09, normalized to space)
const C0_C1_CONTROL_RE = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/g;

// Any attempted literal or malformed untrusted_tool_result XML tag smuggling inside tool data
const FENCE_TAG_SMUGGLE_RE = /<\/?\s*untrusted_tool_result[^>]*>/gi;

/** Credential scrubbing is the single shared implementation in `@hunt-command/shared`. */
export function scrubCredentials(input: string): string {
  return scrubSecretText(input);
}

export function stripControlAndInvisibleChars(input: string): string {
  return input
    .replace(/\r\n?/g, "\n")
    .replace(/\t/g, " ")
    .replace(ANSI_ESCAPE_RE, "")
    .replace(BIDI_CONTROL_RE, "")
    .replace(ZERO_WIDTH_RE, "")
    .replace(C0_C1_CONTROL_RE, "");
}

export function generateFenceNonce128(): string {
  return crypto.randomBytes(16).toString("hex");
}

export interface Utf8TruncateResult {
  readonly text: string;
  readonly truncated: boolean;
  readonly originalBytes: number;
  readonly finalBytes: number;
}

/**
 * Slices `text` cleanly on a UTF-8 codepoint boundary so the returned string
 * is `<= maxBytes` UTF-8 bytes and never produces U+FFFD replacement characters.
 */
export function truncateUtf8Safe(text: string, maxBytes: number): Utf8TruncateResult {
  if (maxBytes < 0 || !Number.isInteger(maxBytes)) {
    throw new RangeError(`maxBytes must be a non-negative integer, got ${maxBytes}`);
  }
  const buf = Buffer.from(text, "utf8");
  if (buf.byteLength <= maxBytes) {
    return {
      text,
      truncated: false,
      originalBytes: buf.byteLength,
      finalBytes: buf.byteLength,
    };
  }
  if (maxBytes === 0) {
    return { text: "", truncated: true, originalBytes: buf.byteLength, finalBytes: 0 };
  }

  let end = maxBytes;
  // Walk back over UTF-8 continuation bytes (10xxxxxx = 0x80..0xBF)
  while (end > 0 && (buf[end]! & 0xc0) === 0x80) {
    end -= 1;
  }
  // Verify the lead byte at `end` is completely contained within `maxBytes`
  if (end < maxBytes) {
    const lead = buf[end]!;
    let seqLen = 1;
    if ((lead & 0xe0) === 0xc0) seqLen = 2;
    else if ((lead & 0xf0) === 0xe0) seqLen = 3;
    else if ((lead & 0xf8) === 0xf0) seqLen = 4;

    if (end + seqLen > maxBytes) {
      // Drop incomplete multi-byte codepoint at boundary
    } else {
      end += seqLen;
    }
  }

  const sliced = buf.subarray(0, end).toString("utf8");
  return {
    text: sliced,
    truncated: true,
    originalBytes: buf.byteLength,
    finalBytes: Buffer.byteLength(sliced, "utf8"),
  };
}

export interface FenceToolOutputOptions {
  readonly nonce128?: string;
  readonly maxPayloadBytes?: number;
}

export interface FencedToolOutput {
  readonly nonce128: string;
  readonly innerBytes: number;
  readonly totalWrappedBytes: number;
  readonly truncated: boolean;
  readonly originalBytes: number;
  readonly wrappedText: string;
}

function serializeRawToolValue(rawOutput: unknown): string {
  if (typeof rawOutput === "string") {
    return rawOutput;
  }
  if (rawOutput === undefined) {
    return "null";
  }
  return JSON.stringify(rawOutput);
}

/**
 * Serializes, credential-scrubs, strips bidi/zero-width/ANSI control chars,
 * removes any nonce or tag collision, caps payload bytes at `<= MAX_TOOL_RESULT_BYTES`
 * (`24_576 B`) BEFORE wrapping so `@oh-my-pi`'s `truncateTail` (`50 KB`) never slices off
 * the opening fence, and wraps in `<untrusted_tool_result_${nonce128}>...</untrusted_tool_result_${nonce128}>`.
 */
export function fenceToolOutput(
  rawOutput: unknown,
  options?: FenceToolOutputOptions,
): FencedToolOutput {
  const nonce128 = (options?.nonce128 ?? generateFenceNonce128()).toLowerCase();
  if (!NONCE_HEX_RE.test(nonce128)) {
    throw new Error("nonce128 must be an exact 32-char lowercase hex CSPRNG value");
  }
  const maxPayloadBytes = options?.maxPayloadBytes ?? MAX_TOOL_RESULT_BYTES;
  if (maxPayloadBytes <= 0 || maxPayloadBytes > MAX_TOOL_RESULT_BYTES) {
    throw new RangeError(
      `maxPayloadBytes must be within 1..${MAX_TOOL_RESULT_BYTES}, got ${maxPayloadBytes}`,
    );
  }

  // Scrub structurally first (credential-named keys, strings nested inside strings), then the
  // serialized text, so JSON embedded in a string value is caught before quotes get escaped.
  const serialized = serializeRawToolValue(scrubSecretValue(rawOutput));
  const scrubbed = scrubCredentials(serialized);
  const cleaned = stripControlAndInvisibleChars(scrubbed);

  // Strip any attempted fence tag smuggling or literal nonce collision (after invisible-char removal!)
  const nonceCollisionRe = new RegExp(nonce128, "gi");
  const collisionFree = cleaned
    .replace(FENCE_TAG_SMUGGLE_RE, "[stripped_fence_tag]")
    .replace(nonceCollisionRe, "[stripped_nonce]");

  const rawBytes = Buffer.byteLength(collisionFree, "utf8");
  let innerBody = collisionFree;
  let truncated = false;

  if (rawBytes > maxPayloadBytes) {
    truncated = true;
    // Reserve space for deterministic truncation suffix inside the 24 KiB payload cap
    const maxSuffixTemplate = `\n...[truncated: ${rawBytes}B -> ${maxPayloadBytes}B cap]`;
    const suffixBytes = Buffer.byteLength(maxSuffixTemplate, "utf8");
    const headBudget = Math.max(0, maxPayloadBytes - suffixBytes);
    const head = truncateUtf8Safe(collisionFree, headBudget);
    innerBody = head.text + maxSuffixTemplate;
    // Guarantee strict <= maxPayloadBytes invariant even on tiny test caps
    if (Buffer.byteLength(innerBody, "utf8") > maxPayloadBytes) {
      innerBody = truncateUtf8Safe(innerBody, maxPayloadBytes).text;
    }
  }

  const innerBytes = Buffer.byteLength(innerBody, "utf8");
  const openTag = `<untrusted_tool_result_${nonce128}>`;
  const closeTag = `</untrusted_tool_result_${nonce128}>`;
  const wrappedText = `${openTag}\n${innerBody}\n${closeTag}`;

  return {
    nonce128,
    innerBytes,
    totalWrappedBytes: Buffer.byteLength(wrappedText, "utf8"),
    truncated,
    originalBytes: rawBytes,
    wrappedText,
  };
}

const MUTATING_KEY_RE =
  /^(?:_update|_delete|_bulk|_reindex|_create|delete|drop|truncate|insert|update|mutate|write)$/i;
const MUTATING_HTTP_METHODS = new Set(["PUT", "DELETE", "PATCH"]);

export function detectMutatingToolParams(params: Record<string, unknown>): boolean {
  for (const [key, value] of Object.entries(params)) {
    if (MUTATING_KEY_RE.test(key) && Boolean(value)) {
      return true;
    }
    if (key.toLowerCase() === "method" && typeof value === "string") {
      const upper = value.trim().toUpperCase();
      if (MUTATING_HTTP_METHODS.has(upper)) {
        return true;
      }
    }
    if (key.toLowerCase() === "endpoint" && typeof value === "string") {
      if (/\/(?:_update|_delete_by_query|_bulk|_reindex|_forcemerge)\b/i.test(value)) {
        return true;
      }
    }
  }
  return false;
}

/**
 * Mints and verifies closure-bound `HMAC-SHA256(masterSecret, runId\0stepId\0profile)` tokens
 * so tool execution NEVER trusts an LLM-supplied `profile` argument.
 */
export class RoleCapabilityAuthority {
  readonly #masterSecret: Buffer;

  constructor(masterSecret?: Buffer | string) {
    if (masterSecret === undefined) {
      this.#masterSecret = crypto.randomBytes(32);
    } else if (typeof masterSecret === "string") {
      if (Buffer.byteLength(masterSecret, "utf8") < 16) {
        throw new Error("RoleCapabilityAuthority masterSecret string must be >= 16 bytes");
      }
      this.#masterSecret = Buffer.from(masterSecret, "utf8");
    } else {
      if (masterSecret.byteLength < 16) {
        throw new Error("RoleCapabilityAuthority masterSecret buffer must be >= 16 bytes");
      }
      this.#masterSecret = Buffer.from(masterSecret);
    }
  }

  private computeMacHex(runId: string, stepId: string, profile: ProfileId): string {
    return crypto
      .createHmac("sha256", this.#masterSecret)
      .update(`${runId}\0${stepId}\0${profile}`, "utf8")
      .digest("hex");
  }

  public mint(runId: string, stepId: string, profile: ProfileId): RoleCapabilityToken {
    return Object.freeze({
      runId,
      stepId,
      profile,
      signatureHex: this.computeMacHex(runId, stepId, profile),
    });
  }

  public verifyToken(token: RoleCapabilityToken): void {
    if (
      !token ||
      typeof token.runId !== "string" ||
      typeof token.stepId !== "string" ||
      typeof token.profile !== "string" ||
      typeof token.signatureHex !== "string" ||
      !/^[0-9a-f]{64}$/i.test(token.signatureHex)
    ) {
      throw new DataPlaneAccessError(403, "tool_not_owned", "Invalid role capability token");
    }
    const expectedHex = this.computeMacHex(token.runId, token.stepId, token.profile);
    const actualBuf = Buffer.from(token.signatureHex.toLowerCase(), "hex");
    const expectedBuf = Buffer.from(expectedHex, "hex");
    if (
      actualBuf.byteLength !== expectedBuf.byteLength ||
      !crypto.timingSafeEqual(actualBuf, expectedBuf)
    ) {
      throw new DataPlaneAccessError(
        403,
        "tool_not_owned",
        "Role capability HMAC signature mismatch",
      );
    }
  }

  public authorizeToolCall(
    token: RoleCapabilityToken,
    toolName: HuntToolName,
    params: Record<string, unknown> = {},
  ): void {
    this.verifyToken(token);
    assertReadOnlyOperation(detectMutatingToolParams(params));
    assertRoleOwnsTool(token.profile, toolName, token.stepId);
  }
}
