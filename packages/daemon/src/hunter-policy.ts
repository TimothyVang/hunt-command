// Hunter rules that do not need the agent stack. Kept free of `@oh-my-pi` imports so the engine, the CLI
// and an idle daemon can use them without loading it.
import {
  DataPlaneAccessError,
  FRAMEWORK_PROFILES,
  MIN_SHARED_CACHE_HEADER_CHARS,
  type ProfileId,
} from "@hunt-command/shared";
import type { RoleModelPin } from "./ports.ts";

/**
 * Constant >=25-char shared header placed at byte 0 of `messages[0]` on every investigation turn
 * so sibling Claude OAuth sessions reuse the 1h `system[0]` cache breakpoint.
 */
export const SHARED_CACHE_HEADER = "# Hunt Command Investigation Turn\n";

if (SHARED_CACHE_HEADER.length < MIN_SHARED_CACHE_HEADER_CHARS) {
  throw new Error(
    `SHARED_CACHE_HEADER must be >= ${MIN_SHARED_CACHE_HEADER_CHARS} chars (got ${SHARED_CACHE_HEADER.length})`,
  );
}

export const FORBIDDEN_SUBSCRIPTION_ENV_KEYS = [
  "ANTHROPIC_API_KEY",
  "OPENAI_API_KEY",
  "CODEX_API_KEY",
  "GEMINI_API_KEY",
  "GOOGLE_API_KEY",
  "GOOGLE_GENAI_USE_VERTEXAI",
] as const;

export const DEFAULT_ROLE_MODEL_PINS: Readonly<Record<ProfileId, RoleModelPin>> = {
  "framework-coordinator": {
    provider: "anthropic",
    model: "claude-opus-4-6",
    fallback_providers: [],
  },
  "framework-reviewer": {
    provider: "anthropic",
    model: "claude-opus-4-6",
    fallback_providers: [],
  },
  "framework-researcher": {
    provider: "anthropic",
    model: "claude-sonnet-4-6",
    fallback_providers: [],
  },
  "framework-network-analyst": {
    provider: "anthropic",
    model: "claude-sonnet-4-6",
    fallback_providers: [],
  },
  "framework-librarian": {
    provider: "anthropic",
    model: "claude-sonnet-4-6",
    fallback_providers: [],
  },
  "framework-builder": {
    provider: "anthropic",
    model: "claude-sonnet-4-6",
    fallback_providers: [],
  },
} as const;

/**
 * Strips ambient paid API-key env vars so `$0` OAuth subscription mode can NEVER
 * silently bill an operator's `.env` or shell environment key.
 */
export function stripPaidApiEnvVars(
  targetEnv: Record<string, string | undefined> = process.env,
): string[] {
  const removed: string[] = [];
  for (const key of FORBIDDEN_SUBSCRIPTION_ENV_KEYS) {
    if (targetEnv[key] !== undefined) {
      delete targetEnv[key];
      removed.push(key);
    }
    if (targetEnv === process.env && Bun.env[key] !== undefined) {
      delete Bun.env[key];
      if (!removed.includes(key)) {
        removed.push(key);
      }
    }
  }
  return removed;
}

const SYNTHETIC_WORD_RE = /\bsynthetic\b/i;

export function validateNonSyntheticGuidanceText(
  text: string | undefined,
  fieldName: string,
  syntheticOnly: boolean,
): void {
  if (!text) return;
  if (!syntheticOnly && SYNTHETIC_WORD_RE.test(text)) {
    throw new DataPlaneAccessError(
      400,
      "case_origin_mismatch",
      `${fieldName} cannot contain the word 'synthetic' when synthetic_only is false`,
    );
  }
}

export function validateRoleModelPinTable(
  overrides?: Partial<Record<ProfileId, RoleModelPin>>,
): Readonly<Record<ProfileId, RoleModelPin>> {
  const merged: Record<string, RoleModelPin> = { ...DEFAULT_ROLE_MODEL_PINS };
  if (overrides) {
    for (const [role, pin] of Object.entries(overrides)) {
      if (!pin) continue;
      merged[role] = pin;
    }
  }
  for (const role of FRAMEWORK_PROFILES) {
    const pin = merged[role];
    if (!pin || typeof pin.provider !== "string" || !pin.provider.trim()) {
      throw new Error(`Role '${role}' is missing an explicit pinned provider`);
    }
    if (typeof pin.model !== "string" || !pin.model.trim()) {
      throw new Error(`Role '${role}' is missing an explicit pinned model`);
    }
    if (!Array.isArray(pin.fallback_providers) || pin.fallback_providers.length > 0) {
      throw new Error(
        `Role '${role}' must set fallback_providers=[] (ambient/fallback providers are prohibited)`,
      );
    }
  }
  return Object.freeze(merged as Record<ProfileId, RoleModelPin>);
}
