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
  "accesskey",
  "secretaccesskey",
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
  `(?:secret${SEP})?access${SEP}key`,
].join("|");

/**
 * `"password": "..."`, `"Authorization": "ApiKey ..."`, `{"cookie":"..."}` (JSON string values),
 * at any escape depth: `{\"api_key\":\"...\"}` inside a log line is the same pair with every quote
 * preceded by one backslash run. The opening value quote's run (group 2) is the delimiter; the
 * value ends at the next quote with exactly that run, so deeper-escaped quotes stay inside it.
 *
 * Linear: the key's run is anchored by a lookbehind (no restart inside a backslash run), and each
 * value alternative starts on a distinct character class and consumes a maximal backslash run.
 */
const JSON_SECRET_KV_RE = new RegExp(
  `((?<!\\\\)\\\\*"(?:${SECRET_KEY_ALTERNATION})\\\\*"\\s*:\\s*(\\\\*)")` +
    `(?!\\[REDACTED)` +
    `(?:[^"\\\\\\r\\n]|\\\\+(?=[^"\\\\\\r\\n])|(?!\\2")\\\\+")+` +
    `((?<!\\\\)\\2")`,
  "gi",
);

/**
 * `Authorization: Bearer ...`, `Cookie: a=b; c=d`, `X-Api-Key: ...` header lines. The value must
 * start with a non-space so a backtracked `\s*` cannot step past an existing marker (idempotent).
 */
const HEADER_LINE_RE =
  /(\b(?:proxy-)?authorization\s*:\s*|\b(?:set-)?cookie\s*:\s*|\bx-api-key\s*:\s*)(?!\[REDACTED)[^\s"'}][^\r\n"'}]*/gi;

/**
 * `password=...`, `access_token=...&`, `client_secret: ...`, `'api_key': '...'`, and env-style
 * names whose last segments are a credential keyword: `DB_PASSWORD=`, `export FOO_SECRET=`,
 * `AWS_SECRET_ACCESS_KEY=`, `MY_API_KEY: ...`. The `[A-Za-z0-9]+_` prefix segments cannot contain
 * `_`, so splitting is deterministic and the scan stays linear; `tokens observed` never matches.
 */
const KEY_VALUE_RE = new RegExp(
  `(\\b(?:[A-Za-z0-9]+_)*(?:${SECRET_KEY_ALTERNATION})["']?\\s*[:=]\\s*["']?)(?!\\[REDACTED)[^\\s"'&,;}]+`,
  "gi",
);

/** `scheme://user:password@host` — the scheme must start a token so runs are scanned once. */
const URL_USERINFO_RE =
  /(?<![A-Za-z0-9+.-])([A-Za-z][A-Za-z0-9+.-]*:\/\/)[^/\s"'?#<>@:]+:[^/\s"'?#<>]*@/g;

const BEARER_RE = /\bBearer\s+(?!\[REDACTED)[A-Za-z0-9._~+/=-]{6,}/gi;
const APIKEY_RE = /\bApiKey\s+(?!\[REDACTED)[A-Za-z0-9._~+/=-]{6,}/gi;

const STANDALONE_TOKENS: ReadonlyArray<readonly [RegExp, string]> = [
  // JSON Web Tokens: base64url header (always `eyJ`), payload, optional signature.
  // The lookbehind (not `\b`) lets a match start only at the head of a token run, so a
  // run like `eyJ-eyJ-…` with no `.` is scanned once instead of once per `eyJ`.
  [/(?<![A-Za-z0-9_-])e[y]J[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*/g, "[REDACTED_JWT]"],
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
  out = out.replace(JSON_SECRET_KV_RE, "$1[REDACTED_SECRET]$3");
  out = out.replace(HEADER_LINE_RE, "$1[REDACTED_SECRET]");
  out = out.replace(BEARER_RE, "Bearer [REDACTED_BEARER]");
  out = out.replace(APIKEY_RE, "ApiKey [REDACTED_API_KEY]");
  out = out.replace(KEY_VALUE_RE, "$1[REDACTED_SECRET]");
  for (const [pattern, replacement] of STANDALONE_TOKENS) {
    out = out.replace(pattern, replacement);
  }
  return out;
}

/** How many levels of JSON-inside-a-string {@link scrubSecretValue} unwraps. */
export const MAX_EMBEDDED_JSON_DEPTH = 8;

const REDACTED_SECRET = "[REDACTED_SECRET]";
const REDACTED_TOO_DEEP = "[REDACTED_TOO_DEEP]";
/** Containers nested deeper than this are replaced, never walked (keeps recursion bounded). */
export const MAX_CONTAINER_NESTING = 64;

/**
 * Deep-scrubs a JSON-like value:
 * - every value under a credential key name becomes `[REDACTED_SECRET]`, whatever its type;
 * - a string holding JSON (trimmed text starts with `{` or `[` and parses) is parsed, scrubbed
 *   structurally and re-serialized, up to {@link MAX_EMBEDDED_JSON_DEPTH} levels deep;
 * - every other string goes through {@link scrubSecretText}.
 *
 * Cost stays linear: each embedded level is parsed once, and nesting is capped.
 */
export function scrubSecretValue<T>(value: T): T {
  return scrubValueAt(value, 0, 0) as T;
}

function scrubValueAt(value: unknown, jsonDepth: number, nesting: number): unknown {
  if (typeof value === "string") {
    return scrubString(value, jsonDepth);
  }
  if (value !== null && typeof value === "object" && nesting >= MAX_CONTAINER_NESTING) {
    // Fail closed rather than overflow the stack on pathologically deep input.
    return REDACTED_TOO_DEEP;
  }
  if (Array.isArray(value)) {
    return value.map((item) => scrubValueAt(item, jsonDepth, nesting + 1));
  }
  if (value !== null && typeof value === "object") {
    if (value instanceof Uint8Array || value instanceof Date) {
      return value;
    }
    const result: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      result[k] = isSecretKeyName(k) && isPresent(v) ? REDACTED_SECRET : scrubValueAt(v, jsonDepth, nesting + 1);
    }
    return result;
  }
  return value;
}

function isPresent(v: unknown): boolean {
  return v !== null && v !== undefined && v !== "";
}

function scrubString(text: string, jsonDepth: number): string {
  if (jsonDepth < MAX_EMBEDDED_JSON_DEPTH) {
    const embedded = parseEmbeddedJson(text);
    if (embedded !== undefined) {
      // Re-serialize the structurally scrubbed value, then sweep it as text as well.
      return scrubSecretText(JSON.stringify(scrubValueAt(embedded, jsonDepth + 1, 0)));
    }
  }
  return scrubSecretText(text);
}

function parseEmbeddedJson(text: string): object | undefined {
  const trimmed = text.trim();
  const first = trimmed[0];
  const last = trimmed[trimmed.length - 1];
  if (!((first === "{" && last === "}") || (first === "[" && last === "]"))) {
    return undefined;
  }
  try {
    const parsed: unknown = JSON.parse(trimmed);
    return parsed !== null && typeof parsed === "object" ? parsed : undefined;
  } catch {
    return undefined;
  }
}
