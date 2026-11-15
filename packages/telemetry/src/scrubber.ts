/**
 * Deterministic pre-write and pre-wire credential scrubber.
 * Runs BEFORE hot SQLite span writes, cold Zstd blob compression, OTLP export, and LLM tool returns.
 */

const SECRET_OBJECT_KEY_RE =
  /^(?:authorization|cookie|set-cookie|refresh_token|api_key|x-api-key|access_token|client_secret|proxy-authorization)$/i;

const URL_USERINFO_CRED_RE = /([A-Za-z][A-Za-z0-9+.-]*:\/\/)([^/\s"'?#<>@]+:[^/\s"'?#<>]*)@/g;

const AUTH_HEADER_LINE_RE =
  /(\b(?:Proxy-)?Authorization\s*:\s*)(?:Bearer|ApiKey|Basic|Token|Digest)\s+[^\r\n,"';}]+/gi;

const AUTH_HEADER_GENERIC_RE =
  /(\b(?:Proxy-)?Authorization\s*:\s*)(?!\[REDACTED)[A-Za-z0-9._~+/=-]{8,}/gi;

const AUTH_JSON_KV_RE = /("(?:proxy-)?authorization"\s*:\s*")([^"]+)(")/gi;

const COOKIE_HEADER_LINE_RE = /(\b(?:Set-)?Cookie\s*:\s*)(?!\[REDACTED)[^\r\n"'}]+/gi;

const COOKIE_JSON_KV_RE = /("(?:set-)?cookie"\s*:\s*")([^"]+)(")/gi;

const REFRESH_JSON_KV_RE = /("refresh_token"\s*:\s*")([^"]+)(")/gi;
const REFRESH_QUERY_KV_RE = /(\brefresh_token\s*=\s*)(?!\[REDACTED)[^&\s"';,}]+/gi;
const REFRESH_COLON_KV_RE = /(\brefresh_token\s*:\s*)(?!\[REDACTED)[^\s"';,}]+/gi;

const BEARER_STANDALONE_RE = /\bBearer\s+(?!\[REDACTED)[A-Za-z0-9._~+/=-]{6,}/gi;
const APIKEY_STANDALONE_RE = /\bApiKey\s+(?!\[REDACTED)[A-Za-z0-9._~+/=-]{6,}/gi;

const SK_TOKEN_RE = /\bsk-(?:ant-[A-Za-z0-9_-]{4,}|[A-Za-z0-9_-]{8,})\b/g;
const SLACK_BOT_RE = /\bxoxb-[A-Za-z0-9-]{4,}\b/g;
const SLACK_APP_RE = /\bxapp-[A-Za-z0-9-]{4,}\b/g;
const GITHUB_PAT_RE = /\bghp_[A-Za-z0-9_]{4,}\b/g;
const GITHUB_OAUTH_RE = /\bgho_[A-Za-z0-9_]{4,}\b/g;
const AWS_ACCESS_KEY_RE = /\bAKIA[0-9A-Z]{8,}\b/g;

export function scrubSecrets(input: string): string {
  if (input.length === 0) {
    return input;
  }

  let out = input;
  out = out.replace(URL_USERINFO_CRED_RE, "$1[REDACTED_URL_CREDENTIALS]@");
  out = out.replace(AUTH_JSON_KV_RE, "$1[REDACTED_AUTH]$3");
  out = out.replace(COOKIE_JSON_KV_RE, "$1[REDACTED_COOKIE]$3");
  out = out.replace(REFRESH_JSON_KV_RE, "$1[REDACTED_REFRESH_TOKEN]$3");
  out = out.replace(AUTH_HEADER_LINE_RE, "$1[REDACTED_AUTH]");
  out = out.replace(AUTH_HEADER_GENERIC_RE, "$1[REDACTED_AUTH]");
  out = out.replace(COOKIE_HEADER_LINE_RE, "$1[REDACTED_COOKIE]");
  out = out.replace(REFRESH_QUERY_KV_RE, "$1[REDACTED_REFRESH_TOKEN]");
  out = out.replace(REFRESH_COLON_KV_RE, "$1[REDACTED_REFRESH_TOKEN]");
  out = out.replace(BEARER_STANDALONE_RE, "Bearer [REDACTED_BEARER]");
  out = out.replace(APIKEY_STANDALONE_RE, "ApiKey [REDACTED_API_KEY]");
  out = out.replace(SK_TOKEN_RE, "[REDACTED_SK_TOKEN]");
  out = out.replace(SLACK_BOT_RE, "[REDACTED_SLACK_BOT_TOKEN]");
  out = out.replace(SLACK_APP_RE, "[REDACTED_SLACK_APP_TOKEN]");
  out = out.replace(GITHUB_PAT_RE, "[REDACTED_GITHUB_PAT]");
  out = out.replace(GITHUB_OAUTH_RE, "[REDACTED_GITHUB_OAUTH]");
  out = out.replace(AWS_ACCESS_KEY_RE, "[REDACTED_AWS_KEY]");

  return out;
}

export function scrubSecretsValue<T>(value: T): T {
  if (typeof value === "string") {
    return scrubSecrets(value) as unknown as T;
  }

  if (Array.isArray(value)) {
    return value.map((item) => scrubSecretsValue(item)) as unknown as T;
  }

  if (value !== null && typeof value === "object") {
    if (value instanceof Uint8Array || value instanceof Date) {
      return value;
    }
    const result: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (SECRET_OBJECT_KEY_RE.test(k) && typeof v === "string" && v.length > 0) {
        result[k] = "[REDACTED_SECRET]";
      } else {
        result[k] = scrubSecretsValue(v);
      }
    }
    return result as T;
  }

  return value;
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
