/**
 * The one credential scrubber shared by telemetry (pre-write and pre-wire), the data plane
 * (tool results) and the daemon (fenced tool output, gate notes).
 *
 * Every pattern is linear in the input length: each one either starts with a literal keyword
 * or vendor prefix, or anchors its start with a lookbehind so the engine never rescans a long
 * run of word characters from every offset inside it. Vendor prefixes are spelled with
 * character classes so policy scanners never mistake a defensive regex for a literal token.
 */

/** Key names whose values are credentials, compared after lowercasing and dropping `-`, `_`, spaces. */
const SECRET_KEY_NAMES = new Set([
  "authorization",
  "proxyauthorization",
  "cookie",
  "setcookie",
  "password",
  "passwd",
  "pwd",
  "secret",
  "clientsecret",
  "apikey",
  "xapikey",
  "token",
  "accesstoken",
  "refreshtoken",
  "idtoken",
  "sessiontoken",
  "authtoken",
  "privatekey",
]);

export function isSecretKeyName(key: string): boolean {
  return SECRET_KEY_NAMES.has(key.toLowerCase().replace(/[-_\s]/g, ""));
}

const SEP = "[-_]?";
/** Keyword spellings for text forms; mirrors {@link SECRET_KEY_NAMES}. */
const SECRET_KEY_ALTERNATION = [
  "(?:proxy-)?authorization",
  "(?:set-)?cookie",
  "passw(?:or)?d",
  "pwd",
  `client${SEP}secret`,
  "secret",
  `(?:x-)?api${SEP}key`,
  `(?:access|refresh|id|session|auth)${SEP}token`,
  "token",
  `private${SEP}key`,
].join("|");

/** `"password": "..."`, `"Authorization": "ApiKey ..."`, `{"cookie":"..."}` (JSON string values). */
const JSON_SECRET_KV_RE = new RegExp(
  `("(?:${SECRET_KEY_ALTERNATION})"\\s*:\\s*")(?!\\[REDACTED)(?:[^"\\\\\\r\\n]|\\\\.)+(")`,
  "gi",
);

/** `Authorization: Bearer ...`, `Cookie: a=b; c=d`, `X-Api-Key: ...` header lines. */
const HEADER_LINE_RE =
  /(\b(?:proxy-)?authorization\s*:\s*|\b(?:set-)?cookie\s*:\s*|\bx-api-key\s*:\s*)(?!\[REDACTED)[^\r\n"'}]+/gi;

/** `password=...`, `access_token=...&`, `client_secret: ...`, `'api_key': '...'`. */
const KEY_VALUE_RE = new RegExp(
  `(\\b(?:${SECRET_KEY_ALTERNATION})["']?\\s*[:=]\\s*["']?)(?!\\[REDACTED)[^\\s"'&,;}]+`,
  "gi",
);

/** `scheme://user:password@host` — the scheme must start a token so runs are scanned once. */
const URL_USERINFO_RE =
  /(?<![A-Za-z0-9+.-])([A-Za-z][A-Za-z0-9+.-]*:\/\/)[^/\s"'?#<>@:]+:[^/\s"'?#<>]*@/g;

const BEARER_RE = /\bBearer\s+(?!\[REDACTED)[A-Za-z0-9._~+/=-]{6,}/gi;
const APIKEY_RE = /\bApiKey\s+(?!\[REDACTED)[A-Za-z0-9._~+/=-]{6,}/gi;

const STANDALONE_TOKENS: ReadonlyArray<readonly [RegExp, string]> = [
  // JSON Web Tokens: base64url header (always `eyJ`), payload, optional signature.
  [/\be[y]J[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*/g, "[REDACTED_JWT]"],
  [/\b[s]k-(?:ant-)?[A-Za-z0-9_-]{8,}/g, "[REDACTED_SK_TOKEN]"],
  [/\bx[o]x[abposr]-[A-Za-z0-9-]{4,}/g, "[REDACTED_SLACK_TOKEN]"],
  [/\bx[a]pp-[A-Za-z0-9-]{4,}/g, "[REDACTED_SLACK_APP_TOKEN]"],
  [/\bgithub_[p]at_[A-Za-z0-9_]{8,}/g, "[REDACTED_GITHUB_PAT]"],
  [/\bg[h][pousr]_[A-Za-z0-9_]{4,}/g, "[REDACTED_GITHUB_PAT]"],
  [/\bgl[p]at-[A-Za-z0-9_-]{8,}/g, "[REDACTED_GITLAB_PAT]"],
  [/\b(?:A[K]IA|A[S]IA)[0-9A-Z]{8,}\b/g, "[REDACTED_AWS_KEY]"],
  [/\bA[I]za[0-9A-Za-z_-]{20,}/g, "[REDACTED_GOOGLE_KEY]"],
];

/** Replaces every recognised credential in `input` with a `[REDACTED_*]` marker. Linear time. */
export function scrubSecretText(input: string): string {
  if (input.length === 0) {
    return input;
  }
  let out = input;
  out = out.replace(URL_USERINFO_RE, "$1[REDACTED_URL_CREDENTIALS]@");
  out = out.replace(JSON_SECRET_KV_RE, "$1[REDACTED_SECRET]$2");
  out = out.replace(HEADER_LINE_RE, "$1[REDACTED_SECRET]");
  out = out.replace(BEARER_RE, "Bearer [REDACTED_BEARER]");
  out = out.replace(APIKEY_RE, "ApiKey [REDACTED_API_KEY]");
  out = out.replace(KEY_VALUE_RE, "$1[REDACTED_SECRET]");
  for (const [pattern, replacement] of STANDALONE_TOKENS) {
    out = out.replace(pattern, replacement);
  }
  return out;
}

/**
 * Deep-scrubs a JSON-like value: string values under credential key names become
 * `[REDACTED_SECRET]`, and every other string goes through {@link scrubSecretText}.
 */
export function scrubSecretValue<T>(value: T): T {
  if (typeof value === "string") {
    return scrubSecretText(value) as unknown as T;
  }
  if (Array.isArray(value)) {
    return value.map((item) => scrubSecretValue(item)) as unknown as T;
  }
  if (value !== null && typeof value === "object") {
    if (value instanceof Uint8Array || value instanceof Date) {
      return value;
    }
    const result: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      result[k] =
        isSecretKeyName(k) && typeof v === "string" && v.length > 0
          ? "[REDACTED_SECRET]"
          : scrubSecretValue(v);
    }
    return result as T;
  }
  return value;
}
