/**
 * Fenced Watch Browser Request Policy & Loopback Proxy Fence.
 *
 * TypeScript port of `framework/hunt_lab/browser_policy.py` hardened for Hunt Command v2 (#178 G1.3, #189):
 * - Pinned `127.0.0.1:<port>` loopback origins ONLY (`localhost`, `0.0.0.0`, `[::1]`, and remote hosts refused).
 * - Lab origin: read-only (`GET` only); `X-Hunt-Lab-Secret` injected ONLY on `labOrigin`, stripped everywhere else.
 * - Kibana origin: Discover-only (`/app/discover`), `/internal/bsearch` pinned to `hunt-lab-case-events` +
 *   case time window (`ese`/`es` strategies only; ES|QL, SQL, EQL refused), value suggestions forced to `terms_agg`.
 * - Arkime origin: read-only sessions/spiview/spigraph/unique/connections, every `expression` wrapped in
 *   `(<expr>) && tags == "case:<caseId>"` and clamped to `[startSec, stopSec]`; admin/pcap/raw/scrub/delete routes blocked.
 * - Session proxy blackhole (`http://127.0.0.1:1` with `<allowed 127.0.0.1:ports>;<-loopback>`) backs up CDP `Fetch.enable`.
 */

export const SEARCH_KEYS = ["expression", "date", "startTime", "stopTime"] as const;
export const MAX_ARKIME_EXPRESSION_LENGTH = 1000;

export const ARKIME_SEARCH_PREFIXES = [
  "/api/sessions",
  "/api/spiview",
  "/api/spigraph",
  "/api/unique",
  "/api/multiunique",
  "/api/connections",
  "/api/buildquery",
  "/sessions.json",
  "/spiview.json",
  "/spigraph.json",
  "/unique.txt",
  "/multiunique.txt",
  "/connections.json",
] as const;

export const ARKIME_DENIED_RE =
  /delete|scrub|tags|\/users\b|settings|hunt|send|pcap|\/raw|packets|upload|csv|entire|bodyhash|\/session\/|\/files|\/history|\/es(?:admin|indices|shards|tasks|recovery|nodes)|\/parliament|\/cyberchef|\/notifier|\/cron|\/shortcut|\/lookup|\/reindex/i;

export const KIBANA_INDEX = "hunt-lab-case-events";
export const KIBANA_APP = "/app/discover";
export const KIBANA_TIME_FIELD = "@timestamp";

const KIBANA_STATIC_RE =
  /^\/(?:bootstrap\.js|[0-9a-f]{12}\/(?:bundles|ui)\/[\w@%+.,~/-]+|translations\/[0-9a-f]{12}\/[A-Za-z-]+\.json)$/;

const KIBANA_READS_GET_RE =
  /^\/(?:app\/discover|api\/(?:licensing\/info|banners\/info|spaces\/space|alerting\/rule_types)|internal\/(?:spaces\/_active_space|security\/(?:me|session|user_profile)|core\/pricing|fields_metadata|data_views\/has_(?:data_views|es_data)))$/;

const KIBANA_READS_POST_RE = /^\/api\/core\/capabilities$/;

const KIBANA_SEARCH_PATH = "/internal/bsearch";
const KIBANA_SEARCH_STRATEGIES = new Set(["ese", "es"]);
const KIBANA_SEARCH_KEYS = new Set([
  "query",
  "sort",
  "fields",
  "size",
  "from",
  "version",
  "_source",
  "highlight",
  "stored_fields",
  "runtime_mappings",
  "script_fields",
  "aggs",
  "aggregations",
  "track_total_hits",
  "docvalue_fields",
  "search_after",
  "timeout",
  "terminate_after",
]);

const KIBANA_SUGGESTIONS_PATH = `/internal/kibana/suggestions/values/${KIBANA_INDEX}`;
const KIBANA_CONTENT_RE = /^\/api\/content_management\/rpc\/(?:get|search|mSearch|bulkGet)$/;
const SAFE_CASE_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;

export class WatchPolicyRefused extends Error {
  public readonly reason: string;

  constructor(reason: string) {
    super(reason);
    this.name = "WatchPolicyRefused";
    this.reason = reason;
  }
}

export interface WatchScope {
  readonly caseId: string;
  readonly labOrigin: string;
  readonly arkimeOrigin: string;
  readonly kibanaOrigin: string | null;
  readonly startSec: number;
  readonly stopSec: number;
  readonly labSecret?: string;
}

export interface CreateWatchScopeInput {
  caseId: string;
  labOrigin: string;
  arkimeOrigin: string;
  kibanaOrigin?: string | null;
  startSec: number;
  stopSec: number;
  labSecret?: string;
}

export interface WatchVerdict {
  readonly block?: string;
  readonly url?: string;
  readonly body?: string;
  readonly expression?: string;
}

export const ALLOW_VERDICT: WatchVerdict = Object.freeze({});

export interface WatchHeaderEntry {
  name: string;
  value: string;
}

/**
 * Parses and normalizes a strictly pinned `http(s)://127.0.0.1:<port>` origin.
 * Rejects `localhost`, `0.0.0.0`, IPv6 loopback, credentials, or any non-127.0.0.1 host.
 */
export function parsePinnedLoopbackOrigin(rawUrl: string): string | null {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return null;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return null;
  }
  if (parsed.username !== "" || parsed.password !== "") {
    return null;
  }
  if (parsed.hostname !== "127.0.0.1") {
    return null;
  }
  const effectivePort =
    parsed.port !== "" ? Number(parsed.port) : parsed.protocol === "https:" ? 443 : 80;
  if (!Number.isInteger(effectivePort) || effectivePort < 1 || effectivePort > 65_535) {
    return null;
  }
  return `${parsed.protocol}//127.0.0.1:${effectivePort}`;
}

function hostPortFromPinnedOrigin(pinnedOrigin: string): string {
  const parsed = new URL(pinnedOrigin);
  const port = parsed.port !== "" ? parsed.port : parsed.protocol === "https:" ? "443" : "80";
  return `127.0.0.1:${port}`;
}

export function createWatchScope(input: CreateWatchScopeInput): WatchScope {
  if (!SAFE_CASE_ID_RE.test(input.caseId)) {
    throw new Error(`Invalid WatchScope caseId '${input.caseId}'`);
  }
  const labOrigin = parsePinnedLoopbackOrigin(input.labOrigin);
  if (!labOrigin) {
    throw new Error(
      `WatchScope labOrigin must be a pinned 127.0.0.1:<port> URL (got '${input.labOrigin}')`,
    );
  }
  const arkimeOrigin = parsePinnedLoopbackOrigin(input.arkimeOrigin);
  if (!arkimeOrigin) {
    throw new Error(
      `WatchScope arkimeOrigin must be a pinned 127.0.0.1:<port> URL (got '${input.arkimeOrigin}')`,
    );
  }
  let kibanaOrigin: string | null = null;
  if (input.kibanaOrigin !== undefined && input.kibanaOrigin !== null) {
    kibanaOrigin = parsePinnedLoopbackOrigin(input.kibanaOrigin);
    if (!kibanaOrigin) {
      throw new Error(
        `WatchScope kibanaOrigin must be a pinned 127.0.0.1:<port> URL (got '${input.kibanaOrigin}')`,
      );
    }
  }
  const startSec = Math.floor(input.startSec);
  const stopSec = Math.floor(input.stopSec);
  if (!Number.isFinite(startSec) || !Number.isFinite(stopSec) || startSec >= stopSec) {
    throw new Error("WatchScope requires finite startSec < stopSec");
  }

  return {
    caseId: input.caseId,
    labOrigin,
    arkimeOrigin,
    kibanaOrigin,
    startSec,
    stopSec,
    ...(input.labSecret ? { labSecret: input.labSecret } : {}),
  };
}

export function listAllowedWatchOrigins(scope: WatchScope): string[] {
  const origins = [scope.labOrigin, scope.arkimeOrigin];
  if (scope.kibanaOrigin !== null) {
    origins.push(scope.kibanaOrigin);
  }
  return [...new Set(origins)];
}

/**
 * Builds Electron `session.setProxy` rules that route every non-allowlisted host/port
 * (including `localhost`, `[::1]`, unpinned `127.0.0.1` ports, and all internet egress)
 * into closed loopback port `127.0.0.1:1`.
 */
export function buildWatchProxyConfig(scope: WatchScope): {
  proxyRules: string;
  proxyBypassRules: string;
} {
  const bypassTargets = listAllowedWatchOrigins(scope).map(hostPortFromPinnedOrigin);
  return {
    proxyRules: "http://127.0.0.1:1",
    proxyBypassRules: [...bypassTargets, "<-loopback>"].join(";"),
  };
}

/**
 * Pages the main frame may navigate to: `about:blank`, `labOrigin`, `arkimeOrigin`,
 * or `kibanaOrigin` strictly on `/app/discover`.
 */
export function documentAllowed(scope: WatchScope, url: string): boolean {
  if (url === "about:blank") {
    return true;
  }
  const source = parsePinnedLoopbackOrigin(url);
  if (!source) {
    return false;
  }
  if (source === scope.labOrigin || source === scope.arkimeOrigin) {
    return true;
  }
  if (scope.kibanaOrigin !== null && source === scope.kibanaOrigin) {
    try {
      const parsed = new URL(url);
      const trimmedPath = parsed.pathname.replace(/\/+$/, "");
      return trimmedPath === KIBANA_APP;
    } catch {
      return false;
    }
  }
  return false;
}

/**
 * Rejects Arkime filter expressions that could escape the `(<expression>) && tags == "case:<id>"` wrapper.
 */
export function checkArkimeExpression(expression: unknown): string {
  if (typeof expression !== "string" || expression.length > MAX_ARKIME_EXPRESSION_LENGTH) {
    throw new WatchPolicyRefused("arkime_expression_rejected");
  }
  for (let i = 0; i < expression.length; i++) {
    const code = expression.charCodeAt(i);
    if (code < 32 || code === 127) {
      throw new WatchPolicyRefused("arkime_expression_rejected");
    }
  }

  let depth = 0;
  let quote: '"' | "/" | null = null;
  let escaped = false;

  for (const ch of expression) {
    if (quote !== null) {
      if (escaped) {
        escaped = false;
      } else if (ch === "\\") {
        escaped = true;
      } else if (ch === quote) {
        quote = null;
      }
    } else if (ch === '"' || ch === "/") {
      quote = ch;
    } else if (ch === "(") {
      depth += 1;
    } else if (ch === ")") {
      depth -= 1;
      if (depth < 0) {
        throw new WatchPolicyRefused("arkime_expression_rejected");
      }
    }
  }

  if (quote !== null || depth !== 0) {
    throw new WatchPolicyRefused("arkime_expression_rejected");
  }
  return expression.trim();
}

export function scopedArkimeExpression(caseId: string, expression: unknown): string {
  if (!SAFE_CASE_ID_RE.test(caseId)) {
    throw new WatchPolicyRefused("arkime_expression_rejected");
  }
  const tag = `tags == "case:${caseId}"`;
  const checked = checkArkimeExpression(expression);
  return checked.length > 0 ? `(${checked}) && ${tag}` : tag;
}

function parseSeconds(value: unknown): number | null {
  const text =
    (typeof value === "string" || typeof value === "number") && typeof value !== "boolean"
      ? String(value)
      : "";
  return /^[0-9]{1,12}$/.test(text) ? Number(text) : null;
}

export function clampWindow(
  scope: WatchScope,
  start: unknown,
  stop: unknown,
): readonly [number, number] {
  const parsedStart = parseSeconds(start);
  const parsedStop = parseSeconds(stop);
  if (parsedStart !== null && parsedStop !== null) {
    const clampedStart = Math.max(parsedStart, scope.startSec);
    const clampedStop = Math.min(parsedStop, scope.stopSec);
    if (clampedStart < clampedStop) {
      return [clampedStart, clampedStop];
    }
  }
  return [scope.startSec, scope.stopSec];
}

function buildScopedArkimeFields(
  scope: WatchScope,
  values: Record<string, unknown>,
): { expression: string; startTime: number; stopTime: number } {
  const [startTime, stopTime] = clampWindow(scope, values.startTime, values.stopTime);
  const rawExpr =
    values.expression === undefined || values.expression === null || values.expression === ""
      ? ""
      : values.expression;
  return {
    expression: scopedArkimeExpression(scope.caseId, rawExpr),
    startTime,
    stopTime,
  };
}

function parseQueryPairs(rawQuery: string): Array<[string, string]> {
  const clean = rawQuery.startsWith("?") ? rawQuery.slice(1) : rawQuery;
  if (clean.length === 0) {
    return [];
  }
  const params = new URLSearchParams(clean);
  const pairs: Array<[string, string]> = [];
  for (const [k, v] of params.entries()) {
    pairs.push([k, v]);
  }
  return pairs;
}

function encodeQueryPairs(pairs: ReadonlyArray<readonly [string, string]>): string {
  const params = new URLSearchParams();
  for (const [k, v] of pairs) {
    params.append(k, v);
  }
  return params.toString();
}

function scopeArkimePairs(
  scope: WatchScope,
  pairs: ReadonlyArray<readonly [string, string]>,
): { pairs: Array<[string, string]>; expression: string } {
  const keyCounts = new Map<string, number>();
  const asRecord: Record<string, unknown> = {};
  for (const [name, value] of pairs) {
    keyCounts.set(name, (keyCounts.get(name) ?? 0) + 1);
    asRecord[name] = value;
  }
  for (const key of SEARCH_KEYS) {
    if ((keyCounts.get(key) ?? 0) > 1) {
      throw new WatchPolicyRefused("arkime_ambiguous_search");
    }
  }
  const scoped = buildScopedArkimeFields(scope, asRecord);
  const searchKeySet = new Set<string>(SEARCH_KEYS);
  const rest: Array<[string, string]> = pairs
    .filter(([name]) => !searchKeySet.has(name))
    .map(([name, value]) => [name, value]);

  return {
    pairs: [
      ...rest,
      ["expression", scoped.expression],
      ["startTime", String(scoped.startTime)],
      ["stopTime", String(scoped.stopTime)],
    ],
    expression: scoped.expression,
  };
}

function isPlainObject(val: unknown): val is Record<string, unknown> {
  return typeof val === "object" && val !== null && !Array.isArray(val);
}

function scopeArkimeBody(
  scope: WatchScope,
  body: string,
): { body: string; expression: string } {
  if (body.trimStart().startsWith("{")) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(body);
    } catch {
      throw new WatchPolicyRefused("arkime_body_rejected");
    }
    if (!isPlainObject(parsed)) {
      throw new WatchPolicyRefused("arkime_body_rejected");
    }
    const scoped = buildScopedArkimeFields(scope, parsed);
    const searchKeySet = new Set<string>(SEARCH_KEYS);
    const merged: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(parsed)) {
      if (!searchKeySet.has(k)) {
        merged[k] = v;
      }
    }
    merged.expression = scoped.expression;
    merged.startTime = scoped.startTime;
    merged.stopTime = scoped.stopTime;
    return {
      body: JSON.stringify(merged),
      expression: scoped.expression,
    };
  }

  const { pairs, expression } = scopeArkimePairs(scope, parseQueryPairs(body));
  return {
    body: encodeQueryPairs(pairs),
    expression,
  };
}

function parseKibanaJsonBody(body: string | null | undefined): Record<string, unknown> {
  if (body === null || body === undefined) {
    throw new WatchPolicyRefused("kibana_body_unavailable");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new WatchPolicyRefused("kibana_body_rejected");
  }
  if (!isPlainObject(parsed)) {
    throw new WatchPolicyRefused("kibana_body_rejected");
  }
  return parsed;
}

export function buildKibanaCaseRange(scope: WatchScope): Record<string, unknown> {
  return {
    range: {
      [KIBANA_TIME_FIELD]: {
        gte: scope.startSec * 1000,
        lt: scope.stopSec * 1000,
        format: "epoch_millis",
      },
    },
  };
}

export function kibanaWindow(scope: WatchScope): readonly [string, string] {
  const startIso = new Date(scope.startSec * 1000).toISOString();
  const stopIso = new Date(scope.stopSec * 1000 - 1).toISOString();
  return [startIso, stopIso];
}

function pinKibanaBatchSearch(scope: WatchScope, body: string | null | undefined): string {
  const values = parseKibanaJsonBody(body);
  const batch = values.batch;
  if (!Array.isArray(batch) || batch.length === 0) {
    throw new WatchPolicyRefused("kibana_body_rejected");
  }

  for (const item of batch) {
    if (!isPlainObject(item) || !isPlainObject(item.options)) {
      throw new WatchPolicyRefused("kibana_search_denied");
    }
    const strategy = item.options.strategy;
    if (typeof strategy !== "string" || !KIBANA_SEARCH_STRATEGIES.has(strategy)) {
      throw new WatchPolicyRefused("kibana_search_denied");
    }
    const reqObj = isPlainObject(item.request) ? item.request : null;
    const params = reqObj && isPlainObject(reqObj.params) ? reqObj.params : null;
    if (!params || params.index !== KIBANA_INDEX) {
      throw new WatchPolicyRefused("kibana_index_denied");
    }
    if (params.body === undefined) {
      params.body = {};
    }
    if (!isPlainObject(params.body)) {
      throw new WatchPolicyRefused("kibana_search_denied");
    }
    for (const key of Object.keys(params.body)) {
      if (!KIBANA_SEARCH_KEYS.has(key)) {
        throw new WatchPolicyRefused("kibana_search_denied");
      }
    }
    const existingQuery = params.body.query;
    params.body.query = {
      bool: {
        must: existingQuery ? [existingQuery] : [],
        filter: [buildKibanaCaseRange(scope)],
      },
    };
  }

  return JSON.stringify(values);
}

function decideKibanaRequest(
  scope: WatchScope,
  method: string,
  parsedUrl: URL,
  body: string | null | undefined,
): WatchVerdict {
  const pathname = parsedUrl.pathname;
  if (method === "GET" && KIBANA_STATIC_RE.test(pathname)) {
    return ALLOW_VERDICT;
  }
  if (method === "GET" && KIBANA_READS_GET_RE.test(pathname)) {
    return ALLOW_VERDICT;
  }
  if (method === "POST" && KIBANA_READS_POST_RE.test(pathname)) {
    return ALLOW_VERDICT;
  }
  if (
    (method === "GET" && pathname === "/internal/data_views/fields") ||
    (method === "POST" && pathname === "/internal/data_views/_fields_for_wildcard")
  ) {
    const patterns = parseQueryPairs(parsedUrl.search)
      .filter(([name]) => name === "pattern")
      .map(([, val]) => val);
    return patterns.length === 1 && patterns[0] === KIBANA_INDEX
      ? ALLOW_VERDICT
      : { block: "kibana_index_denied" };
  }
  if (method !== "POST") {
    return { block: "kibana_route_denied" };
  }
  if (pathname === KIBANA_SEARCH_PATH) {
    return { body: pinKibanaBatchSearch(scope, body) };
  }
  if (pathname === KIBANA_SUGGESTIONS_PATH) {
    const parsedBody = parseKibanaJsonBody(body);
    return { body: JSON.stringify({ ...parsedBody, method: "terms_agg" }) };
  }
  if (KIBANA_CONTENT_RE.test(pathname)) {
    const parsedBody = parseKibanaJsonBody(body);
    return parsedBody.contentTypeId === "index-pattern"
      ? ALLOW_VERDICT
      : { block: "kibana_route_denied" };
  }
  return { block: "kibana_route_denied" };
}

/**
 * Evaluates a single paused Watch Browser request (`Fetch.requestPaused`).
 * `body` should be `null` when `hasPostData` is true on a POST request whose body could not be read.
 */
export function decideWatchRequest(
  scope: WatchScope,
  rawMethod: string,
  url: string,
  body: string | null = "",
): WatchVerdict {
  const method = rawMethod.toUpperCase();
  try {
    const source = parsePinnedLoopbackOrigin(url);
    if (!source) {
      return { block: "origin_not_lab" };
    }
    if (source === scope.labOrigin) {
      return method === "GET" ? ALLOW_VERDICT : { block: "lab_read_only" };
    }
    const parsedUrl = new URL(url);
    if (scope.kibanaOrigin !== null && source === scope.kibanaOrigin) {
      return decideKibanaRequest(scope, method, parsedUrl, body);
    }
    if (source !== scope.arkimeOrigin) {
      return { block: "origin_not_lab" };
    }

    let decodedPath: string;
    try {
      decodedPath = decodeURIComponent(parsedUrl.pathname);
    } catch {
      return { block: "arkime_route_denied" };
    }
    if (ARKIME_DENIED_RE.test(decodedPath)) {
      return { block: "arkime_route_denied" };
    }

    const isSearchRoute = ARKIME_SEARCH_PREFIXES.some((prefix) =>
      parsedUrl.pathname.startsWith(prefix),
    );
    const queryPairs = parseQueryPairs(parsedUrl.search);
    const searchKeySet = new Set<string>(SEARCH_KEYS);
    const hasSearchQueryParam = queryPairs.some(([name]) => searchKeySet.has(name));

    if (method === "GET" && !isSearchRoute && !hasSearchQueryParam) {
      return ALLOW_VERDICT;
    }
    if (method !== "GET" && !(method === "POST" && isSearchRoute)) {
      return { block: "arkime_read_only" };
    }

    const scopedQuery = scopeArkimePairs(scope, queryPairs);
    const nextUrlObj = new URL(url);
    nextUrlObj.search = encodeQueryPairs(scopedQuery.pairs);
    const rewrittenUrl = nextUrlObj.toString();

    if (method === "POST" && body === null) {
      throw new WatchPolicyRefused("arkime_body_unavailable");
    }
    if (method === "POST" && body !== null && body.trim().length > 0) {
      const scopedPost = scopeArkimeBody(scope, body);
      return {
        url: rewrittenUrl,
        body: scopedPost.body,
        expression: scopedPost.expression,
      };
    }
    return {
      url: rewrittenUrl,
      expression: scopedQuery.expression,
    };
  } catch (err) {
    if (err instanceof WatchPolicyRefused) {
      return { block: err.reason };
    }
    return { block: "policy_internal_error" };
  }
}

/**
 * Strips any page-supplied `X-Hunt-Lab-Secret` header across all origins, and injects
 * `X-Hunt-Lab-Secret` ONLY when `targetUrl` resolves to `scope.labOrigin`.
 */
export function sanitizeWatchRequestHeaders(
  scope: WatchScope,
  targetUrl: string,
  incomingHeaders: ReadonlyArray<WatchHeaderEntry>,
): WatchHeaderEntry[] {
  const filtered = incomingHeaders.filter(
    (entry) => entry.name.toLowerCase() !== "x-hunt-lab-secret",
  );
  const targetOrigin = parsePinnedLoopbackOrigin(targetUrl);
  if (targetOrigin === scope.labOrigin && scope.labSecret && scope.labSecret.length > 0) {
    filtered.push({ name: "X-Hunt-Lab-Secret", value: scope.labSecret });
  }
  return filtered;
}
