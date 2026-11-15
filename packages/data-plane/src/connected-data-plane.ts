import crypto from "node:crypto";
import fs from "node:fs";
import https from "node:https";
import path from "node:path";
import {
  ALWAYS_FIELDS,
  type DataOrigin,
  DEFAULT_FIELDS,
  EVENT_FIELDS,
  type HistogramInterval,
  INTERVALS,
  isAllowedAggField,
  isAllowedSearchField,
  LEADING_WILDCARD_RE,
  QUERY_FIELDS,
} from "@hunt-command/shared";
import { throwDataPlaneError } from "./errors.ts";
import {
  type ArkimeSessionsParams,
  type ArkimeSessionsResult,
  type ArkimeUniqueParams,
  type ArkimeUniqueResult,
  type CitationVerificationResult,
  coerceBoundedInt,
  type DetectionTestParams,
  type DetectionTestResult,
  type ElasticAggregateBucket,
  type ElasticAggregateParams,
  type ElasticAggregateResult,
  type ElasticSearchParams,
  type ElasticSearchResult,
  type HuntDataPlane,
  type HuntLabQueryParams,
  type HuntLabQueryResult,
  type IntelLookupParams,
  type IntelLookupResult,
  type LabBrowserParams,
  type LabBrowserResult,
  type PacketFieldsParams,
  type PacketFieldsResult,
} from "./pack-and-guard.ts";
import {
  epochMillisFromNs,
  filterTopLevelFields,
  flattenFields,
  parseTimestampNs,
  pickFieldValue,
} from "./timestamps-and-ip.ts";

export const DEFAULT_CONNECTED_API_KEY_ENV = "HUNT_ELASTIC_API_KEY";
export const CONNECTED_KEEP_ALIVE = "30m";
export const CONNECTED_SETTLE_SECONDS = 15 * 60;
const MAX_HOSTS = 50;
const PROFILE_CHUNK_BYTES = 1024 * 1024;
const PRIVILEGE_BATCH = 200;
const MAX_BACKEND_BYTES = 2 * 1024 * 1024;
const MAX_HISTOGRAM_BUCKETS = 2_000;
const MAX_RESULT = 200;

const INDEX_PATTERN_RE = /^[A-Za-z0-9*][A-Za-z0-9._*,+-]{0,254}$/;
const ENV_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const CASE_ID_RE = /^[a-z0-9-]{3,64}$/;
const ERROR_TYPE_RE = /^[a-z_]{1,100}$/;
const CITATION_FORM_RE = /^evt-\d{16}$/;
const SORT_TIMESTAMP_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:[0-5]\d:[0-5]\d(?:\.\d{1,9})?Z$/;

type ConnectedSortTuple = [timestamp: string, shardDoc: number];

// ============================================================================
// Exact 139 Base Write Privileges & Actions + 16 Newer Probes (connected.py:87-152)
// ============================================================================

export const WRITE_INDEX_PRIVILEGES = [
  "all",
  "manage",
  "write",
  "index",
  "create",
  "create_doc",
  "create_index",
  "delete",
  "delete_index",
  "maintenance",
  "manage_ilm",
  "manage_follow_index",
  "manage_leader_index",
  "auto_configure",
] as const;

export const WRITE_CLUSTER_PRIVILEGES = [
  "all",
  "manage",
  "manage_security",
  "manage_api_key",
  "manage_own_api_key",
  "manage_index_templates",
  "manage_ingest_pipelines",
  "manage_ilm",
  "manage_pipeline",
  "manage_watcher",
  "manage_ml",
  "manage_transform",
  "manage_rollup",
  "manage_ccr",
  "manage_slm",
  "create_snapshot",
  "manage_enrich",
  "manage_token",
  "manage_saml",
  "manage_oidc",
  "grant_api_key",
  "delegate_pki",
  "manage_autoscaling",
  "manage_logstash_pipelines",
  "cancel_task",
] as const;

export const WRITE_INDEX_ACTIONS = [
  "indices:data/write/index",
  "indices:data/write/bulk",
  "indices:data/write/bulk[s]",
  "indices:data/write/delete",
  "indices:data/write/update",
  "indices:data/write/delete/byquery",
  "indices:data/write/update/byquery",
  "indices:admin/create",
  "indices:admin/auto_create",
  "indices:admin/delete",
  "indices:admin/mapping/put",
  "indices:admin/mapping/auto_put",
  "indices:admin/settings/update",
  "indices:admin/close",
  "indices:admin/open",
  "indices:admin/aliases",
  "indices:admin/rollover",
  "indices:admin/resize",
  "indices:admin/forcemerge",
  "indices:admin/refresh",
  "indices:admin/flush",
  "indices:admin/block/add",
  "indices:admin/cache/clear",
  "indices:admin/reload_analyzers",
  "indices:admin/ilm/remove_policy",
  "indices:admin/ilm/retry",
  "indices:admin/data_stream/create",
  "indices:admin/data_stream/delete",
  "indices:admin/data_stream/migrate",
  "indices:admin/data_stream/modify",
  "indices:admin/data_stream/promote",
  "indices:admin/data_stream/lifecycle/put",
  "indices:admin/data_stream/lifecycle/delete",
  "indices:admin/data_stream/options/put",
  "indices:admin/data_stream/options/delete",
  "indices:admin/xpack/ccr/put_follow",
  "indices:admin/xpack/ccr/unfollow",
  "indices:admin/xpack/downsample",
  "indices:admin/freeze",
  "indices:admin/seq_no/add_retention_lease",
] as const;

export const WRITE_CLUSTER_ACTIONS = [
  "cluster:admin/settings/update",
  "cluster:admin/reroute",
  "cluster:admin/tasks/cancel",
  "cluster:admin/ingest/pipeline/put",
  "cluster:admin/ingest/pipeline/delete",
  "cluster:admin/script/put",
  "cluster:admin/script/delete",
  "cluster:admin/component_template/put",
  "cluster:admin/component_template/delete",
  "cluster:admin/repository/put",
  "cluster:admin/repository/delete",
  "cluster:admin/snapshot/create",
  "cluster:admin/snapshot/delete",
  "cluster:admin/snapshot/restore",
  "cluster:admin/ilm/put",
  "cluster:admin/ilm/delete",
  "cluster:admin/slm/put",
  "cluster:admin/slm/delete",
  "cluster:admin/transform/put",
  "cluster:admin/transform/delete",
  "cluster:admin/xpack/enrich/put",
  "cluster:admin/xpack/enrich/execute",
  "cluster:admin/xpack/enrich/delete",
  "cluster:admin/xpack/watcher/watch/put",
  "cluster:admin/xpack/ml/job/put",
  "cluster:admin/logstash/pipeline/put",
  "cluster:admin/synonyms/put",
  "cluster:admin/synonyms/delete",
  "cluster:admin/synonym_rules/put",
  "cluster:admin/synonym_rules/delete",
  "cluster:admin/xpack/query_rules/put",
  "cluster:admin/xpack/inference/put",
  "cluster:admin/xpack/connector/put",
  "cluster:admin/xpack/application/search_application/put",
  "cluster:admin/data_stream/global_retention/put",
  "cluster:admin/xpack/security/api_key/create",
  "cluster:admin/xpack/security/api_key/invalidate",
  "cluster:admin/xpack/security/user/put",
  "cluster:admin/xpack/security/role/put",
  "cluster:admin/xpack/security/role_mapping/put",
  "cluster:admin/xpack/security/service_account/token/create",
  "cluster:admin/xpack/license/put",
  "cluster:admin/features/reset",
  "cluster:admin/nodes/reload_secure_settings",
  "indices:admin/template/put",
  "indices:admin/template/delete",
  "indices:admin/index_template/put",
  "indices:admin/index_template/delete",
  "cluster:admin/snapshot/clone",
  "cluster:admin/xpack/watcher/watch/delete",
  "cluster:admin/xpack/ml/job/delete",
  "cluster:admin/logstash/pipeline/delete",
  "cluster:admin/xpack/query_rules/delete",
  "cluster:admin/xpack/inference/delete",
  "cluster:admin/xpack/connector/delete",
  "cluster:admin/xpack/application/search_application/delete",
  "cluster:admin/xpack/security/user/delete",
  "cluster:admin/xpack/security/user/change_password",
  "cluster:admin/xpack/security/role/delete",
  "cluster:admin/xpack/security/role_mapping/delete",
  "cluster:admin/xpack/license/delete",
] as const;

export const NEWER_INDEX_PRIVILEGES = [
  "manage_data_stream_lifecycle",
  "manage_failure_store",
  "cross_cluster_replication",
  "cross_cluster_replication_internal",
] as const;

export const NEWER_CLUSTER_PRIVILEGES = [
  "manage_service_account",
  "manage_user_profile",
  "manage_search_application",
  "manage_behavioral_analytics",
  "post_behavioral_analytics_event",
  "manage_search_synonyms",
  "manage_search_query_rules",
  "manage_connector",
  "write_connector_secrets",
  "manage_inference",
  "write_fleet_secrets",
  "manage_esql",
] as const;

const ALLOWED_CLUSTER_DESCRIPTOR_PRIVS = new Set(["monitor"]);
const ALLOWED_INDEX_DESCRIPTOR_PRIVS = new Set(["read", "view_index_metadata"]);
const DESCRIPTOR_KEYS = new Set([
  "cluster",
  "indices",
  "applications",
  "run_as",
  "metadata",
  "transient_metadata",
  "remote_indices",
  "remote_cluster",
  "global",
  "restriction",
  "description",
]);
const INDEX_ENTRY_KEYS = new Set([
  "names",
  "privileges",
  "allow_restricted_indices",
  "field_security",
  "query",
]);

const CONFIG_KEYS = new Set(["url", "index", "ca_file", "api_key_env"]);
const CASE_REQUIRED_KEYS = new Set([
  "case_id",
  "question",
  "schema_version",
  "sources",
  "time_range_utc",
  "data_origin",
  "network_capture",
]);

export interface ConnectedElasticConfig {
  url: string;
  index: string;
  ca_file?: string;
  api_key_env?: string;
}

export interface ConnectedCaseDefinition {
  case_id: string;
  question: string;
  schema_version: 1;
  sources: Array<{ artifact: string; coverage: string }>;
  time_range_utc: {
    start_inclusive: string;
    end_exclusive: string;
  };
  data_origin: "work-connected";
  network_capture: "none";
  hosts?: string[];
}

export type ConnectedHttpsTransport = (
  method: string,
  url: string,
  headers: Record<string, string>,
  body: Uint8Array | null,
) => Promise<{ status: number; payload: Uint8Array }>;

export interface CitationPointer {
  _index?: string;
  _id: string;
}

export class ConnectConfigError extends Error {
  public readonly code?: string;

  constructor(message: string, code?: string) {
    super(message);
    this.name = "ConnectConfigError";
    this.code = code;
  }
}

export function parseClusterBase(rawUrl: unknown): { base: string; clusterHostPort: string; hostname: string } {
  if (typeof rawUrl !== "string" || !rawUrl.startsWith("https://")) {
    throw new ConnectConfigError("--url must be an https:// Elasticsearch address");
  }
  if (rawUrl.includes("?") || rawUrl.includes("#")) {
    throw new ConnectConfigError(
      "--url must not carry credentials, a query or a fragment; the API key comes from the environment",
    );
  }
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new ConnectConfigError("--url is not a valid https:// URL");
  }
  if (
    parsed.protocol !== "https:" ||
    !parsed.hostname ||
    parsed.username.length > 0 ||
    parsed.password.length > 0 ||
    rawUrl.slice(8).split("/")[0]?.includes("@")
  ) {
    throw new ConnectConfigError(
      "--url must be https://HOST:PORT without credentials, a query or a fragment",
    );
  }
  const cleanPath = parsed.pathname.replace(/\/+$/, "");
  const base = `https://${parsed.host}${cleanPath}`;
  return {
    base,
    clusterHostPort: parsed.host,
    hostname: parsed.hostname,
  };
}

export function validateConnectedConfig(raw: unknown): Required<Pick<ConnectedElasticConfig, "url" | "index" | "api_key_env">> & { ca_file?: string } {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new ConnectConfigError("the connect config must hold a JSON object");
  }
  const obj = raw as Record<string, unknown>;
  for (const key of Object.keys(obj)) {
    if (!CONFIG_KEYS.has(key)) {
      throw new ConnectConfigError(
        `the connect config may hold only ${[...CONFIG_KEYS].sort().join(", ")}`,
      );
    }
  }
  parseClusterBase(obj.url);
  if (typeof obj.index !== "string" || !INDEX_PATTERN_RE.test(obj.index)) {
    throw new ConnectConfigError(
      "the connect config index must be an index name or pattern such as logs-*, on this cluster",
    );
  }
  if (obj.ca_file !== undefined && obj.ca_file !== null) {
    if (typeof obj.ca_file !== "string" || !fs.existsSync(obj.ca_file) || !fs.statSync(obj.ca_file).isFile()) {
      throw new ConnectConfigError("the connect config ca_file is not a file");
    }
  }
  const apiKeyEnv =
    obj.api_key_env === undefined ? DEFAULT_CONNECTED_API_KEY_ENV : obj.api_key_env;
  if (typeof apiKeyEnv !== "string" || !ENV_NAME_RE.test(apiKeyEnv)) {
    throw new ConnectConfigError("the connect config api_key_env must name an environment variable");
  }
  return {
    url: obj.url as string,
    index: obj.index,
    api_key_env: apiKeyEnv,
    ...(typeof obj.ca_file === "string" ? { ca_file: obj.ca_file } : {}),
  };
}

function isPrintableAscii(str: string): boolean {
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    if (c < 0x20 || c > 0x7e) return false;
  }
  return true;
}

export function validateConnectedCase(
  raw: unknown,
  nowEpochMs = Date.now(),
): ConnectedCaseDefinition {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new ConnectConfigError("the case file must hold a JSON object");
  }
  const obj = raw as Record<string, unknown>;
  const keys = Object.keys(obj).filter((k) => k !== "hosts");
  if (
    keys.length !== CASE_REQUIRED_KEYS.size ||
    keys.some((k) => !CASE_REQUIRED_KEYS.has(k))
  ) {
    throw new ConnectConfigError(
      `the case file must hold exactly ${[...CASE_REQUIRED_KEYS].sort().join(", ")} and optional hosts`,
    );
  }
  if (obj.schema_version !== 1) {
    throw new ConnectConfigError("the case schema_version must be 1");
  }
  if (
    !Array.isArray(obj.sources) ||
    obj.sources.length === 0 ||
    !obj.sources.every(
      (s) =>
        s !== null &&
        typeof s === "object" &&
        !Array.isArray(s) &&
        Object.keys(s as object).length === 2 &&
        typeof (s as Record<string, unknown>).artifact === "string" &&
        ((s as Record<string, unknown>).artifact as string).trim().length > 0 &&
        typeof (s as Record<string, unknown>).coverage === "string" &&
        ((s as Record<string, unknown>).coverage as string).trim().length > 0,
    )
  ) {
    throw new ConnectConfigError(
      'sources must list {"artifact", "coverage"} texts saying what the window holds, naming no cluster or index',
    );
  }
  if (typeof obj.case_id !== "string" || !CASE_ID_RE.test(obj.case_id)) {
    throw new ConnectConfigError("case_id must match [a-z0-9-]{3,64}");
  }
  if (typeof obj.question !== "string" || obj.question.trim().length === 0) {
    throw new ConnectConfigError("the case needs a question");
  }
  if (obj.data_origin !== "work-connected") {
    throw new ConnectConfigError('a connected case must say "data_origin": "work-connected"');
  }
  if (obj.network_capture !== "none") {
    throw new ConnectConfigError(
      'a connected case has no packet capture: it must say "network_capture": "none"',
    );
  }

  const tr = obj.time_range_utc;
  if (
    tr === null ||
    typeof tr !== "object" ||
    Array.isArray(tr) ||
    Object.keys(tr as object).length !== 2 ||
    typeof (tr as Record<string, unknown>).start_inclusive !== "string" ||
    typeof (tr as Record<string, unknown>).end_exclusive !== "string"
  ) {
    throw new ConnectConfigError(
      "time_range_utc needs ISO start_inclusive and end_exclusive, and nothing else",
    );
  }

  const startIso = (tr as Record<string, string>).start_inclusive!;
  const endIso = (tr as Record<string, string>).end_exclusive!;
  let startNs: bigint;
  let endNs: bigint;
  try {
    startNs = parseTimestampNs(startIso);
    endNs = parseTimestampNs(endIso);
  } catch {
    throw new ConnectConfigError("time_range_utc times need valid ISO UTC timestamps");
  }
  if (startNs >= endNs) {
    throw new ConnectConfigError("time_range_utc must be a nonempty window");
  }

  const endMs = epochMillisFromNs(endNs);
  if (endMs > nowEpochMs - CONNECTED_SETTLE_SECONDS * 1000) {
    throwDataPlaneError(
      400,
      "window_not_closed",
      "window_not_closed: the case window must end at least 15 minutes ago",
    );
  }

  if (obj.hosts !== undefined) {
    if (
      !Array.isArray(obj.hosts) ||
      obj.hosts.length < 1 ||
      obj.hosts.length > MAX_HOSTS ||
      !obj.hosts.every(
        (h) =>
          typeof h === "string" &&
          h.trim() === h &&
          h.length > 0 &&
          h.length <= 100 &&
          isPrintableAscii(h),
      ) ||
      new Set(obj.hosts).size !== obj.hosts.length
    ) {
      throw new ConnectConfigError(
        `hosts must list 1 to ${MAX_HOSTS} distinct exact host.name values`,
      );
    }
  }

  return obj as unknown as ConnectedCaseDefinition;
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Checks whether any bot-visible case field names the cluster hostname or any member of `config.index`
 * as a whole word (`connected.py:287-295`).
 */
export function namesCluster(
  caseDef: ConnectedCaseDefinition,
  config: Pick<ConnectedElasticConfig, "url" | "index">,
): boolean {
  const texts = [
    caseDef.case_id,
    caseDef.question,
    ...(caseDef.hosts ?? []),
    ...caseDef.sources.flatMap((s) => [s.artifact, s.coverage]),
  ]
    .join(" ")
    .toLowerCase();

  const { hostname } = parseClusterBase(config.url);
  const candidates = [
    hostname,
    ...config.index.split(",").map((m) => m.replace(/^-+/, "")),
  ].filter((c) => c.length > 0);

  return candidates.some((name) => {
    const re = new RegExp(`(?<![a-z0-9-])${escapeRegExp(name.toLowerCase())}(?![a-z0-9-])`);
    return re.test(texts);
  });
}

export function readAndScrubApiKeyFromEnv(
  environ: Record<string, string | undefined>,
  envName: string,
): string {
  const raw = environ[envName] ?? "";
  // Always delete from environ immediately so child processes / bots never inherit it!
  delete environ[envName];

  if (!raw) {
    throwDataPlaneError(
      403,
      "leaked_api_key_in_env",
      `environment variable ${envName} holds no API key`,
    );
  }
  for (let i = 0; i < raw.length; i++) {
    const c = raw.charCodeAt(i);
    if (c <= 0x20 || c >= 0x7f) {
      throw new ConnectConfigError(
        `the API key in ${envName} holds whitespace, a line break or a non-ASCII character`,
      );
    }
  }
  return raw;
}

/**
 * Scans `<hermesRoot>/.env`, `<hermesRoot>/config.yaml`, `<hermesRoot>/profiles/<p>/.env`,
 * and `<hermesRoot>/profiles/<p>/config.yaml` in `1 MiB` overlapping windows so an API key
 * straddling a chunk boundary is still caught (`connected.py:261-285`).
 */
export function scanApiKeyInBotProfiles(hermesRootDir: string, apiKey: string): boolean {
  const root = path.resolve(hermesRootDir);
  const candidates: string[] = [
    path.join(root, ".env"),
    path.join(root, "config.yaml"),
  ];

  const profilesDir = path.join(root, "profiles");
  if (fs.existsSync(profilesDir)) {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(profilesDir, { withFileTypes: true });
    } catch {
      throwDataPlaneError(
        403,
        "profile_unreadable",
        `profile_unreadable: ${profilesDir} cannot be listed to verify API key isolation`,
      );
    }
    for (const ent of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      if (ent.isDirectory() || ent.isSymbolicLink()) {
        candidates.push(path.join(profilesDir, ent.name, ".env"));
        candidates.push(path.join(profilesDir, ent.name, "config.yaml"));
      }
    }
  }

  const needle = Buffer.from(apiKey, "ascii");
  const overlap = Math.max(0, needle.byteLength - 1);
  const readBuf = Buffer.allocUnsafe(PROFILE_CHUNK_BYTES);

  for (const filePath of candidates) {
    let fd: number;
    try {
      fd = fs.openSync(filePath, "r");
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === "ENOENT") {
        continue;
      }
      throwDataPlaneError(
        403,
        "profile_unreadable",
        `profile_unreadable: ${filePath} cannot be read to check that it does not hold the API key`,
      );
    }

    try {
      let tail: Buffer = Buffer.alloc(0);
      while (true) {
        let n = 0;
        try {
          n = fs.readSync(fd, readBuf, 0, readBuf.byteLength, null);
        } catch {
          throwDataPlaneError(
            403,
            "profile_unreadable",
            `profile_unreadable: ${filePath} read failed during API key check`,
          );
        }
        if (n <= 0) break;
        const windowBuf =
          tail.byteLength > 0
            ? Buffer.concat([tail, readBuf.subarray(0, n)])
            : readBuf.subarray(0, n);
        if (windowBuf.indexOf(needle) !== -1) {
          return true;
        }
        tail =
          overlap > 0 && windowBuf.byteLength > overlap
            ? Buffer.from(windowBuf.subarray(windowBuf.byteLength - overlap))
            : Buffer.from(windowBuf);
      }
    } finally {
      fs.closeSync(fd);
    }
  }

  return false;
}

/**
 * `F04` Collision-Proof Citation Mint:
 * Hashes `sha256(_index + "\0" + _id)` (not bare `_id`) so daily rollover indices (`logs-01`, `logs-02`)
 * with colliding `_id` values never alias to the same `evt-<16d>` citation!
 */
export function formatConnectedCitation(indexName: string, docId: string): string {
  const material = `${indexName}\0${docId}`;
  const digest = crypto.createHash("sha256").update(material, "utf8").digest();
  const top64 = digest.readBigUInt64BE(0);
  const mod16 = top64 % 10_000_000_000_000_000n;
  return `evt-${mod16.toString().padStart(16, "0")}`;
}

/**
 * Mirrors `connected.py:refuse_regex`: rejects unquoted `/regex/` terms anywhere (including inside
 * `[a TO b]` / `{a TO b}` ranges) with `400 regex_not_supported`, and rejects quotes inside ranges
 * or unclosed quotes with `400 invalid_query`.
 */
export function refuseConnectedRegex(text: string): void {
  let quoted = false;
  let escaped = false;
  let ranged = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    if (escaped) {
      escaped = false;
    } else if (ch === "\\") {
      escaped = true;
    } else if (quoted) {
      quoted = ch !== '"';
    } else if (ranged) {
      if (ch === "/") {
        throwDataPlaneError(400, "regex_not_supported", "Lucene /regex/ terms are refused on connected clusters");
      }
      if (ch === '"') {
        throwDataPlaneError(400, "invalid_query", "Quotes inside range bounds are refused");
      }
      ranged = ch !== "]" && ch !== "}";
    } else if (ch === "[" || ch === "{") {
      ranged = true;
    } else if (ch === '"') {
      quoted = true;
    } else if (ch === "/") {
      throwDataPlaneError(400, "regex_not_supported", "Lucene /regex/ terms are refused on connected clusters");
    }
  }

  if (quoted) {
    throwDataPlaneError(400, "invalid_query", "Unclosed quote in Lucene query");
  }
}

function globMatchCase(text: string, pattern: string): boolean {
  let regex = "^";
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i]!;
    if (ch === "*") regex += ".*";
    else if (ch === "?") regex += ".";
    else regex += escapeRegExp(ch);
  }
  regex += "$";
  return new RegExp(regex).test(text);
}

function decodeLuceneEscapes(value: string): string {
  return value.replace(/\\(?:u([0-9a-fA-F]{4})|([\s\S]))/g, (_m, hex: string | undefined, ch: string | undefined) => {
    if (hex !== undefined) {
      return String.fromCharCode(Number.parseInt(hex, 16));
    }
    return ch ?? "";
  });
}

/**
 * Direct zero-redirect, proxy-immune `node:https` transport (`agent: false`, `rejectUnauthorized: true`).
 * Never consults `HTTPS_PROXY`/`HTTP_PROXY`/`ALL_PROXY` and never follows `3xx` redirects.
 */
export function createVerifiedHttpsTransport(
  caFile?: string,
  timeoutMs = 15_000,
): ConnectedHttpsTransport {
  const caPem = caFile ? fs.readFileSync(caFile) : undefined;

  return (method, rawUrl, headers, body) =>
    new Promise((resolve, reject) => {
      const parsed = new URL(rawUrl);
      const reqHeaders: Record<string, string> = { ...headers };
      if (body !== null) {
        reqHeaders["Content-Length"] = String(body.byteLength);
      }

      const req = https.request(
        {
          protocol: "https:",
          hostname: parsed.hostname,
          port: parsed.port ? Number(parsed.port) : 443,
          path: `${parsed.pathname}${parsed.search}`,
          method,
          headers: reqHeaders,
          agent: false,
          rejectUnauthorized: true,
          ...(caPem ? { ca: caPem } : {}),
        },
        (res) => {
          const status = res.statusCode ?? 0;
          if (status >= 300 && status < 400) {
            res.resume();
            reject(new Error("HTTPS redirect refused"));
            return;
          }
          const chunks: Buffer[] = [];
          let totalBytes = 0;
          res.on("data", (chunk: Buffer) => {
            totalBytes += chunk.byteLength;
            if (totalBytes > MAX_BACKEND_BYTES + 1) {
              req.destroy(new Error("Oversized Elasticsearch response"));
              return;
            }
            chunks.push(chunk);
          });
          res.on("end", () => {
            resolve({ status, payload: Buffer.concat(chunks) });
          });
          res.on("error", reject);
        },
      );

      req.setTimeout(timeoutMs, () => {
        req.destroy(new Error("HTTPS timeout"));
      });
      req.on("error", reject);
      if (body !== null) {
        req.write(body);
      }
      req.end();
    });
}

export function checkElasticsearchVersion(info: unknown): string {
  if (info === null || typeof info !== "object" || Array.isArray(info)) {
    throw new ConnectConfigError("the server did not identify itself as Elasticsearch");
  }
  const version = (info as Record<string, unknown>).version;
  if (version === null || typeof version !== "object" || Array.isArray(version)) {
    throw new ConnectConfigError("the server did not identify itself as Elasticsearch");
  }
  const vObj = version as Record<string, unknown>;
  const dist = vObj.distribution === undefined ? "elasticsearch" : vObj.distribution;
  const numStr = vObj.number;
  const tagline = (info as Record<string, unknown>).tagline;
  if (
    dist !== "elasticsearch" ||
    typeof numStr !== "string" ||
    (typeof tagline === "string" && tagline.toLowerCase().includes("opensearch"))
  ) {
    throw new ConnectConfigError("the server did not identify itself as Elasticsearch");
  }
  const m = /^(\d+)\.(\d+)/.exec(numStr);
  if (!m) {
    throw new ConnectConfigError("the server did not identify itself as Elasticsearch");
  }
  const major = Number(m[1]);
  const minor = Number(m[2]);
  if (major < 7 || (major === 7 && minor < 12)) {
    throw new ConnectConfigError(
      `Elasticsearch ${numStr} lacks point-in-time search; 7.12 or later is required`,
    );
  }
  return numStr;
}

export interface OpenConnectedHuntDataPlaneOptions {
  config: ConnectedElasticConfig;
  caseDefinition: ConnectedCaseDefinition;
  environ?: Record<string, string | undefined>;
  hermesHomeDir?: string;
  stateDir?: string;
  transport?: ConnectedHttpsTransport;
  nowEpochMs?: number;
}

export class ConnectedHuntDataPlane implements HuntDataPlane {
  public readonly caseId: string;
  public readonly dataOrigin: DataOrigin = "work-connected";
  public readonly syntheticOnly = false;
  public readonly hasNetworkCapture = false;
  public readonly hasIntelFeed = false;

  public clusterVersion = "";
  public readonly clusterHostPort: string;

  private readonly base: string;
  private readonly indexPattern: string;
  private readonly authorizationHeader: string;
  private readonly send: ConnectedHttpsTransport;
  private readonly caseDef: ConnectedCaseDefinition;
  private readonly scopeFilters: Array<Record<string, unknown>>;
  private readonly startMs: number;
  private readonly endMs: number;
  private readonly citationsPath: string | null;
  private readonly activePitPath: string | null;

  private pit: string | null = null;
  private generation: number;
  private lastSearchGeneration: number;
  private knownFields: ReadonlySet<string> = new Set();
  private aggregatableFields: ReadonlySet<string> = new Set();
  private readonly citations = new Map<string, CitationPointer[]>();
  private closed = false;

  private constructor(params: {
    base: string;
    clusterHostPort: string;
    indexPattern: string;
    apiKey: string;
    send: ConnectedHttpsTransport;
    caseDef: ConnectedCaseDefinition;
    citationsPath: string | null;
    activePitPath: string | null;
  }) {
    this.base = params.base;
    this.clusterHostPort = params.clusterHostPort;
    this.indexPattern = params.indexPattern;
    this.authorizationHeader = `ApiKey ${params.apiKey}`;
    this.send = params.send;
    this.caseDef = params.caseDef;
    this.caseId = params.caseDef.case_id;
    this.citationsPath = params.citationsPath;
    this.activePitPath = params.activePitPath;

    const startNs = parseTimestampNs(params.caseDef.time_range_utc.start_inclusive);
    const endNs = parseTimestampNs(params.caseDef.time_range_utc.end_exclusive);
    this.startMs = epochMillisFromNs(startNs);
    this.endMs = epochMillisFromNs(endNs);

    this.scopeFilters = [
      {
        range: {
          "@timestamp": {
            gte: params.caseDef.time_range_utc.start_inclusive,
            lt: params.caseDef.time_range_utc.end_exclusive,
          },
        },
      },
    ];
    if (params.caseDef.hosts && params.caseDef.hosts.length > 0) {
      this.scopeFilters.push({
        terms: { "host.name": [...params.caseDef.hosts] },
      });
    }

    this.generation = crypto.randomInt(1, 0x7fffffff);
    this.lastSearchGeneration = this.generation;

    if (this.citationsPath && fs.existsSync(this.citationsPath)) {
      const content = fs.readFileSync(this.citationsPath, "utf8");
      for (const line of content.split(/\r?\n/)) {
        if (!line.trim()) continue;
        const rec = JSON.parse(line) as { evt: string; _index?: string; _id: string };
        if (typeof rec.evt === "string" && typeof rec._id === "string") {
          let list = this.citations.get(rec.evt);
          if (!list) {
            list = [];
            this.citations.set(rec.evt, list);
          }
          list.push({
            ...(typeof rec._index === "string" ? { _index: rec._index } : {}),
            _id: rec._id,
          });
        }
      }
    }
  }

  public static async open(
    options: OpenConnectedHuntDataPlaneOptions,
  ): Promise<ConnectedHuntDataPlane> {
    const validatedConfig = validateConnectedConfig(options.config);
    const validatedCase = validateConnectedCase(options.caseDefinition, options.nowEpochMs);

    if (namesCluster(validatedCase, validatedConfig)) {
      throw new ConnectConfigError(
        "the case file names the cluster host or the index pattern; /case is what the bots see",
      );
    }

    const env = options.environ ?? process.env;
    const apiKey = readAndScrubApiKeyFromEnv(env, validatedConfig.api_key_env);

    if (options.hermesHomeDir) {
      if (scanApiKeyInBotProfiles(options.hermesHomeDir, apiKey)) {
        throwDataPlaneError(
          403,
          "key_in_bot_profile",
          "key_in_bot_profile: the API key is in a Hermes .env or config.yaml, where a bot would load it",
        );
      }
    }

    let citationsPath: string | null = null;
    let activePitPath: string | null = null;
    if (options.stateDir) {
      const resolvedState = path.resolve(options.stateDir);
      // Verify stateDir is never inside a Git checkout!
      let cur = resolvedState;
      while (true) {
        if (fs.existsSync(path.join(cur, ".git"))) {
          throw new ConnectConfigError("stateDir must not be inside a Git checkout");
        }
        const parent = path.dirname(cur);
        if (parent === cur) break;
        cur = parent;
      }
      const caseFolder = path.join(resolvedState, validatedCase.case_id);
      fs.mkdirSync(caseFolder, { recursive: true, mode: 0o700 });
      citationsPath = path.join(caseFolder, "citations.jsonl");
      activePitPath = path.join(caseFolder, "active_pit.json");
    }

    const { base, clusterHostPort } = parseClusterBase(validatedConfig.url);
    const transport =
      options.transport ?? createVerifiedHttpsTransport(validatedConfig.ca_file, 15_000);

    const instance = new ConnectedHuntDataPlane({
      base,
      clusterHostPort,
      indexPattern: validatedConfig.index,
      apiKey,
      send: transport,
      caseDef: validatedCase,
      citationsPath,
      activePitPath,
    });

    await instance.verifyAndOpenSnapshot();
    return instance;
  }

  private encodeIndexPath(): string {
    return encodeURIComponent(this.indexPattern)
      .replace(/%2A/gi, "*")
      .replace(/%2C/gi, ",")
      .replace(/%2B/gi, "+");
  }

  private async callEs(
    method: string,
    routePath: string,
    body?: Record<string, unknown> | null,
  ): Promise<{ status: number; value: Record<string, unknown> | null }> {
    const headers: Record<string, string> = {
      Accept: "application/json",
      Authorization: this.authorizationHeader,
    };
    let bodyBytes: Uint8Array | null = null;
    if (body !== undefined && body !== null) {
      bodyBytes = Buffer.from(JSON.stringify(body), "utf8");
      headers["Content-Type"] = "application/json";
    }

    let resp: { status: number; payload: Uint8Array };
    try {
      resp = await this.send(method, `${this.base}${routePath}`, headers, bodyBytes);
    } catch {
      throwDataPlaneError(503, "backend_not_ready", "backend_not_ready");
    }

    if (resp.payload.byteLength > MAX_BACKEND_BYTES) {
      throwDataPlaneError(503, "backend_not_ready", "Oversized Elasticsearch response");
    }

    try {
      const parsed = JSON.parse(Buffer.from(resp.payload).toString("utf8")) as unknown;
      if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) {
        return { status: resp.status, value: parsed as Record<string, unknown> };
      }
      return { status: resp.status, value: null };
    } catch {
      return { status: resp.status, value: null };
    }
  }

  private async requireEs(
    method: string,
    routePath: string,
    body: Record<string, unknown> | null,
    action: string,
    unknownNameOk = false,
  ): Promise<Record<string, unknown> | null> {
    let status: number;
    let value: Record<string, unknown> | null;
    try {
      ({ status, value } = await this.callEs(method, routePath, body));
    } catch {
      throw new ConnectConfigError(`${action}: cannot reach Elasticsearch at ${this.clusterHostPort}`);
    }

    if (status < 200 || status >= 300 || !value) {
      const errObj = value?.error;
      const errType =
        errObj && typeof errObj === "object" && !Array.isArray(errObj)
          ? (errObj as Record<string, unknown>).type
          : undefined;
      if (unknownNameOk && status === 400 && errType === "illegal_argument_exception") {
        return null;
      }
      const safeDetail =
        typeof errType === "string" && ERROR_TYPE_RE.test(errType) ? ` (${errType})` : "";
      throw new ConnectConfigError(
        `${action}: Elasticsearch returned HTTP ${status}${safeDetail}`,
      );
    }
    return value;
  }

  private async verifyAndOpenSnapshot(): Promise<void> {
    // 1. Cluster version & distribution check (Elasticsearch >= 7.12, never OpenSearch)
    const info = await this.requireEs("GET", "/", null, "read cluster version");
    this.clusterVersion = checkElasticsearchVersion(info);

    // 2. Layer 1: API key role_descriptors allowlist
    await this.checkRoleDescriptors();

    // 3. Layer 2: Resolve concrete indices/aliases/data_streams + check all 139 + newer write privileges
    const resolved = (await this.requireEs(
      "GET",
      `/_resolve/index/${this.encodeIndexPath()}`,
      null,
      "resolve the index pattern",
    ))!;

    const resolvedSet = new Set<string>();
    for (const kind of ["indices", "aliases", "data_streams"] as const) {
      const list = resolved[kind];
      if (!Array.isArray(list)) continue;
      for (const item of list) {
        if (!item || typeof item !== "object" || Array.isArray(item)) continue;
        const rec = item as Record<string, unknown>;
        if (typeof rec.name === "string") resolvedSet.add(rec.name);
        for (const subKey of ["backing_indices", "indices", "aliases"] as const) {
          const sub = rec[subKey];
          if (Array.isArray(sub)) {
            for (const s of sub) {
              if (typeof s === "string") resolvedSet.add(s);
            }
          }
        }
      }
    }
    resolvedSet.delete(this.indexPattern);
    const names = [this.indexPattern, ...[...resolvedSet].sort()];

    const knownNewerCluster: string[] = [];
    for (const priv of NEWER_CLUSTER_PRIVILEGES) {
      const probe = await this.requireEs(
        "POST",
        "/_security/user/_has_privileges",
        { cluster: [priv] },
        "check key privileges",
        true,
      );
      if (probe !== null) knownNewerCluster.push(priv);
    }

    const knownNewerIndex: string[] = [];
    for (const priv of NEWER_INDEX_PRIVILEGES) {
      const probe = await this.requireEs(
        "POST",
        "/_security/user/_has_privileges",
        { index: [{ names: [this.indexPattern], privileges: [priv] }] },
        "check key privileges",
        true,
      );
      if (probe !== null) knownNewerIndex.push(priv);
    }

    const clusterAsked = [
      ...WRITE_CLUSTER_PRIVILEGES,
      ...WRITE_CLUSTER_ACTIONS,
      ...knownNewerCluster,
    ];
    const indexAsked = [
      ...WRITE_INDEX_PRIVILEGES,
      ...WRITE_INDEX_ACTIONS,
      ...knownNewerIndex,
    ];

    const grantedIndices: Record<string, Record<string, unknown>> = {};
    let grantedCluster: Record<string, unknown> = {};

    for (let start = 0; start < names.length; start += PRIVILEGE_BATCH) {
      const batchNames = names.slice(start, start + PRIVILEGE_BATCH);
      const body: Record<string, unknown> = {
        index: [{ names: batchNames, privileges: ["read", ...indexAsked] }],
      };
      if (start === 0) {
        body.cluster = clusterAsked;
      }
      const granted = (await this.requireEs(
        "POST",
        "/_security/user/_has_privileges",
        body,
        "check key privileges",
      ))!;
      if (granted.index && typeof granted.index === "object" && !Array.isArray(granted.index)) {
        Object.assign(grantedIndices, granted.index as Record<string, Record<string, unknown>>);
      }
      if (
        start === 0 &&
        granted.cluster &&
        typeof granted.cluster === "object" &&
        !Array.isArray(granted.cluster)
      ) {
        grantedCluster = granted.cluster as Record<string, unknown>;
      }
    }

    const rootIdxGrants = grantedIndices[this.indexPattern];
    const indexPrivViolation =
      !rootIdxGrants ||
      rootIdxGrants.read !== true ||
      names.some((name) => {
        const entry = grantedIndices[name];
        return !entry || indexAsked.some((priv) => entry[priv] !== false);
      });
    const clusterPrivViolation = clusterAsked.some(
      (priv) => grantedCluster[priv] !== false,
    );

    if (indexPrivViolation || clusterPrivViolation) {
      throwDataPlaneError(
        403,
        "key_not_read_only",
        `key_not_read_only: the key must read ${this.indexPattern} and hold no write, delete or manage privilege`,
      );
    }

    // 4. Field capabilities
    const caps = (await this.requireEs(
      "GET",
      `/${this.encodeIndexPath()}/_field_caps?fields=*&include_unmapped=false`,
      null,
      "read field capabilities",
    ))!;
    const fieldsObj =
      caps.fields && typeof caps.fields === "object" && !Array.isArray(caps.fields)
        ? (caps.fields as Record<string, Record<string, unknown>>)
        : {};
    const allFields = new Set<string>(Object.keys(fieldsObj));
    const aggSet = new Set<string>();
    for (const [fName, typesObj] of Object.entries(fieldsObj)) {
      if (!typesObj || typeof typesObj !== "object") continue;
      for (const kindSpec of Object.values(typesObj)) {
        if (
          kindSpec &&
          typeof kindSpec === "object" &&
          (kindSpec as Record<string, unknown>).aggregatable === true
        ) {
          aggSet.add(fName);
        }
      }
    }
    this.knownFields = allFields;
    this.aggregatableFields = aggSet;

    // 5. Crash Reaper: reap any leaked stale PIT from a crashed previous session before opening ours!
    await this.reapStalePitOnDisk();

    // 6. Open fresh Point-in-Time
    this.pit = await this.openPit();
    this.persistActivePit(this.pit);
  }

  private async checkRoleDescriptors(): Promise<void> {
    const refuse: () => never = () =>
      throwDataPlaneError(
        403,
        "key_not_read_only",
        `key_not_read_only: use an API key created with role descriptors granting only read/view_index_metadata on ${this.indexPattern} and monitor on cluster`,
      );

    const authResp = (await this.requireEs(
      "GET",
      "/_security/_authenticate",
      null,
      "read the key identity",
    ))!;
    const apiKeyInfo = authResp.api_key;
    if (
      !apiKeyInfo ||
      typeof apiKeyInfo !== "object" ||
      Array.isArray(apiKeyInfo) ||
      typeof (apiKeyInfo as Record<string, unknown>).id !== "string" ||
      !((apiKeyInfo as Record<string, unknown>).id as string)
    ) {
      refuse();
    }
    const ownId = (apiKeyInfo as Record<string, string>).id!;

    const keyResp = (await this.requireEs(
      "GET",
      `/_security/api_key?id=${encodeURIComponent(ownId)}`,
      null,
      "read the key role descriptors",
    ))!;
    const apiKeys = Array.isArray(keyResp.api_keys) ? keyResp.api_keys : [];
    const matched = apiKeys.filter(
      (k): k is Record<string, unknown> =>
        k !== null && typeof k === "object" && !Array.isArray(k) && (k as Record<string, unknown>).id === ownId,
    );
    if (matched.length !== 1) {
      refuse();
    }
    const descriptors = matched[0]!.role_descriptors;
    if (
      !descriptors ||
      typeof descriptors !== "object" ||
      Array.isArray(descriptors) ||
      Object.keys(descriptors as object).length === 0
    ) {
      refuse();
    }

    for (const desc of Object.values(descriptors as Record<string, unknown>)) {
      if (!desc || typeof desc !== "object" || Array.isArray(desc)) {
        refuse();
      }
      const d = desc as Record<string, unknown>;
      for (const k of Object.keys(d)) {
        if (!DESCRIPTOR_KEYS.has(k)) refuse();
      }
      for (const forbidden of [
        "run_as",
        "applications",
        "global",
        "remote_indices",
        "remote_cluster",
      ] as const) {
        const val = d[forbidden];
        if (val !== undefined && val !== null) {
          if (Array.isArray(val) && val.length === 0) continue;
          if (typeof val === "object" && !Array.isArray(val) && Object.keys(val).length === 0) {
            continue;
          }
          refuse();
        }
      }
      const clusterPrivs = d.cluster === undefined ? [] : d.cluster;
      if (
        !Array.isArray(clusterPrivs) ||
        clusterPrivs.some(
          (p) => typeof p !== "string" || !ALLOWED_CLUSTER_DESCRIPTOR_PRIVS.has(p),
        )
      ) {
        refuse();
      }

      const indicesList = d.indices === undefined ? [] : d.indices;
      if (!Array.isArray(indicesList)) {
        refuse();
      }
      for (const entry of indicesList) {
        if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
          refuse();
        }
        const e = entry as Record<string, unknown>;
        for (const ek of Object.keys(e)) {
          if (!INDEX_ENTRY_KEYS.has(ek)) refuse();
        }
        if (e.allow_restricted_indices === true) {
          refuse();
        }
        if (
          !Array.isArray(e.privileges) ||
          e.privileges.some(
            (p) => typeof p !== "string" || !ALLOWED_INDEX_DESCRIPTOR_PRIVS.has(p),
          )
        ) {
          refuse();
        }
      }
    }
  }

  private async reapStalePitOnDisk(): Promise<void> {
    if (!this.activePitPath || !fs.existsSync(this.activePitPath)) {
      return;
    }
    try {
      const raw = JSON.parse(fs.readFileSync(this.activePitPath, "utf8")) as {
        url?: string;
        pit_id?: string;
      };
      if (raw.url === this.base && typeof raw.pit_id === "string" && raw.pit_id.length > 0) {
        try {
          await this.callEs("DELETE", "/_pit", { id: raw.pit_id });
        } catch {
          // Best-effort crash reap
        }
      }
    } catch {
      // Malformed stale file
    } finally {
      fs.rmSync(this.activePitPath, { force: true });
    }
  }

  private persistActivePit(pitId: string | null): void {
    if (!this.activePitPath) return;
    if (!pitId) {
      fs.rmSync(this.activePitPath, { force: true });
      return;
    }
    fs.writeFileSync(
      this.activePitPath,
      JSON.stringify({
        url: this.base,
        pit_id: pitId,
        updated_at: new Date().toISOString(),
      }),
      { mode: 0o600 },
    );
  }

  private async openPit(): Promise<string> {
    const resp = (await this.requireEs(
      "POST",
      `/${this.encodeIndexPath()}/_pit?keep_alive=${CONNECTED_KEEP_ALIVE}`,
      null,
      "open point in time",
    ))!;
    const pitId = resp.id;
    if (typeof pitId !== "string" || !pitId) {
      throw new ConnectConfigError("open point in time: Elasticsearch returned no point-in-time id");
    }
    return pitId;
  }

  private static isSnapshotLost(
    status: number,
    value: Record<string, unknown> | null,
  ): boolean {
    if (status === 404) return true;
    if (status === 200 && value) {
      const shards = value._shards as Record<string, unknown> | undefined;
      const failures = Array.isArray(shards?.failures) ? shards.failures : [];
      return failures.some(
        (f) =>
          f !== null &&
          typeof f === "object" &&
          typeof (f as Record<string, unknown>).reason === "object" &&
          ((f as Record<string, Record<string, unknown>>).reason?.type ===
            "search_context_missing_exception"),
      );
    }
    return false;
  }

  private static isQueryRefusedByShards(value: Record<string, unknown>): boolean {
    const shards = value._shards as Record<string, unknown> | undefined;
    const failures = Array.isArray(shards?.failures) ? shards.failures : [];
    return (
      failures.length > 0 &&
      failures.every(
        (f) =>
          f !== null &&
          typeof f === "object" &&
          typeof (f as Record<string, unknown>).reason === "object" &&
          ["query_shard_exception", "parse_exception"].includes(
            String((f as Record<string, Record<string, unknown>>).reason?.type ?? ""),
          ),
      )
    );
  }

  private async reopenPit(expectedGeneration: number): Promise<void> {
    if (this.generation !== expectedGeneration) return;
    try {
      this.pit = await this.openPit();
      this.persistActivePit(this.pit);
    } catch {
      throwDataPlaneError(503, "backend_not_ready", "backend_not_ready");
    }
    this.generation += 1;
  }

  private collectAggTermsFields(aggs: Record<string, unknown> | undefined): string[] {
    if (!aggs) return [];
    const out: string[] = [];
    for (const spec of Object.values(aggs)) {
      if (!spec || typeof spec !== "object" || Array.isArray(spec)) continue;
      const s = spec as Record<string, unknown>;
      if (s.terms && typeof s.terms === "object") {
        const f = (s.terms as Record<string, unknown>).field;
        if (typeof f === "string") out.push(f);
      }
      if (s.aggs && typeof s.aggs === "object") {
        out.push(...this.collectAggTermsFields(s.aggs as Record<string, unknown>));
      }
    }
    return out;
  }

  private async runSearch(body: Record<string, unknown>): Promise<Record<string, unknown>> {
    if (this.closed) {
      throwDataPlaneError(503, "backend_not_ready", "ConnectedHuntDataPlane is closed");
    }

    const termsFields = this.collectAggTermsFields(
      body.aggs as Record<string, unknown> | undefined,
    );
    if (termsFields.some((f) => f === "event.id" || !this.aggregatableFields.has(f))) {
      throwDataPlaneError(400, "field_unavailable", "Field is not aggregatable on connected cluster");
    }

    let status = 503;
    let value: Record<string, unknown> | null = null;
    let usedGen = this.generation;

    for (const attempt of [1, 2] as const) {
      const currentPit = this.pit;
      usedGen = this.generation;
      ({ status, value } = await this.callEs(
        "POST",
        "/_search?allow_partial_search_results=false",
        {
          ...body,
          pit: { id: currentPit, keep_alive: CONNECTED_KEEP_ALIVE },
        },
      ));

      if (!ConnectedHuntDataPlane.isSnapshotLost(status, value) || attempt === 2) {
        break;
      }
      await this.reopenPit(usedGen);
      if (Object.prototype.hasOwnProperty.call(body, "search_after")) {
        throwDataPlaneError(400, "cursor_expired", "Pagination snapshot expired; restart search");
      }
    }

    if (status === 400) {
      throwDataPlaneError(400, "invalid_query", "Cluster rejected Lucene query");
    }
    if (status < 200 || status >= 300 || !value) {
      throwDataPlaneError(503, "backend_not_ready", "backend_not_ready");
    }

    const shards = value._shards as Record<string, unknown> | undefined;
    const failedShards = typeof shards?.failed === "number" ? shards.failed : 0;
    if (value.timed_out === true || failedShards > 0) {
      if (ConnectedHuntDataPlane.isQueryRefusedByShards(value)) {
        throwDataPlaneError(400, "invalid_query", "Shard rejected Lucene query");
      }
      throwDataPlaneError(503, "backend_not_ready", "Partial Elasticsearch response");
    }

    const hits = (value.hits as Record<string, unknown> | undefined)?.hits;
    if (
      Array.isArray(body.sort) &&
      Array.isArray(hits) &&
      hits.some((hit) => !ConnectedHuntDataPlane.isSortTuple(hit?.sort))
    ) {
      throwDataPlaneError(503, "backend_not_ready", "Invalid Elasticsearch sort tuple");
    }

    if (this.generation === usedGen && typeof value.pit_id === "string" && value.pit_id.length > 0) {
      if (value.pit_id !== this.pit) {
        this.pit = value.pit_id;
        this.persistActivePit(this.pit);
      }
    }
    this.lastSearchGeneration = usedGen;
    return value;
  }

  public citeHit(indexName: string, docId: string): string {
    const cited = formatConnectedCitation(indexName, docId);
    let list = this.citations.get(cited);
    if (!list) {
      list = [];
      this.citations.set(cited, list);
    }
    const exists = list.some((p) => p._index === indexName && p._id === docId);
    if (!exists) {
      list.push({ _index: indexName, _id: docId });
      if (this.citationsPath) {
        fs.appendFileSync(
          this.citationsPath,
          `${JSON.stringify({ evt: cited, _index: indexName, _id: docId })}\n`,
          "utf8",
        );
      }
    }
    return cited;
  }

  private transformHitDocument(hit: Record<string, unknown>): Record<string, unknown> {
    const rawSource =
      hit._source && typeof hit._source === "object" && !Array.isArray(hit._source)
        ? { ...(hit._source as Record<string, unknown>) }
        : {};
    delete rawSource["event.id"];
    const hitIndex = typeof hit._index === "string" ? hit._index : this.indexPattern;
    const hitId = String(hit._id ?? "");
    const evObj =
      rawSource.event && typeof rawSource.event === "object" && !Array.isArray(rawSource.event)
        ? { ...(rawSource.event as Record<string, unknown>) }
        : {};
    evObj.id = this.citeHit(hitIndex, hitId);
    rawSource.event = evObj;
    return rawSource;
  }

  /**
   * Rewrites `event.id:evt-<16d>`, `"evt-<16d>"`, bare `evt-<16d>`, and `event.id:("evt-<16d>" OR ...)`
   * to collision-proof `(_index:"..." AND _id:"...")` clauses, while blocking any direct or escaped
   * reference to `event.id` (`event\.id`, `\u0065vent.id`, `event.id*`, `_exists_:event.id`).
   */
  public resolveCitationsInLucene(rawText: string): string {
    const phrases: string[] = [];
    const keep = (val: string): string => {
      phrases.push(val);
      return `\x00${phrases.length - 1}\x00`;
    };

    const resolveDocs = (citedList: readonly string[]): string => {
      const pointerClauses: string[] = [];
      for (const cited of citedList) {
        const ptrs = CITATION_FORM_RE.test(cited) ? (this.citations.get(cited) ?? []) : [];
        if (ptrs.length === 0) {
          throwDataPlaneError(400, "unknown_citation", `Unknown citation '${cited}'`);
        }
        for (const p of ptrs) {
          const escId = p._id.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
          if (p._index) {
            const escIdx = p._index.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
            pointerClauses.push(`(_index:"${escIdx}" AND _id:"${escId}")`);
          } else {
            pointerClauses.push(`_id:"${escId}"`);
          }
        }
      }
      return `(${pointerClauses.join(" OR ")})`;
    };

    // Extract _exists_ targets before hiding quotes
    const decodedFull = decodeLuceneEscapes(rawText);
    const existsTargets: string[] = [];
    const existsRe = /\b_exists_\s*:\s*(\([^()]*\)|"[^"]*"|[^\s()]+)/g;
    for (const m of decodedFull.matchAll(existsRe)) {
      const grp = m[1]!;
      const subTerms = grp.match(/"[^"]*"|[^\s()"]+/g) ?? [];
      for (const st of subTerms) {
        if (st === "AND" || st === "OR" || st === "NOT" || st === "&&" || st === "||") continue;
        existsTargets.push(st.replace(/^"+|"+$/g, "").replace(/^[+!-]+/, ""));
      }
    }

    // Hide escapes & non-citation phrases so `\"` or `"srv-evt-1"` isn't misread
    const hiddenQuotes = rawText.replace(/\\.|"(?:\\.|[^"\\])*"/g, (match) => {
      if (/^"evt-\d+"$/.test(match)) {
        return match;
      }
      return keep(match);
    });

    const barePat = "(?<![\\w.\\x00])(?<![\\w.\\x00]-)evt-\\d+(?![\\w.*?\\x00-])";
    const citedPat = `(?:"evt-(?:\\d+)"|${barePat})`;
    const groupBodyRe = new RegExp(`^\\s*${citedPat}(?:\\s+OR\\s+${citedPat})*\\s*$`);
    const citationRe = new RegExp(
      `\\bevent\\.id\\s*:\\s*\\((?<group>[^()]*)\\)|(?:\\bevent\\.id\\s*:\\s*)?(?:"(?<quoted>evt-\\d+)"|(?<bare>${barePat}))`,
      "g",
    );

    const rewritten = hiddenQuotes.replace(citationRe, (...args) => {
      const groups = args[args.length - 1] as {
        group?: string;
        quoted?: string;
        bare?: string;
      };
      if (groups.group !== undefined) {
        if (!groupBodyRe.test(groups.group)) {
          throwDataPlaneError(400, "invalid_query", "Invalid event.id:(...) citation group");
        }
        const ids = groups.group.match(/evt-\d+/g) ?? [];
        return keep(resolveDocs(ids));
      }
      const single = groups.quoted ?? groups.bare ?? "";
      return keep(resolveDocs([single]));
    });

    // Unescape non-phrase escapes to catch `event\.id`, `\u0065vent.id`, `event.*`, etc.
    const unescapedScan = decodeLuceneEscapes(
      rewritten.replace(/\x00(\d+)\x00/g, (_m, idxStr: string) => {
        const orig = phrases[Number(idxStr)]!;
        return orig.startsWith("\\") ? orig : " ";
      }),
    );

    const fieldRe = /([\^~]?)([^\s()!^~:"[\]{}/\\]+)\s*:/g;
    const fieldNames = [...existsTargets];
    for (const fm of unescapedScan.matchAll(fieldRe)) {
      const after = fm[1] ?? "";
      const rawName = fm[2]!;
      const cleaned = (after ? rawName.replace(/^\d+(?:\.\d+)?/, "") : rawName).replace(
        /^[+-]+/,
        "",
      );
      if (cleaned) fieldNames.push(cleaned);
    }

    const protectedFields = new Set<string>([
      "event.id",
      "event.id.keyword",
      "event.id.text",
      ...[...this.knownFields].filter((f) => f.startsWith("event.id.")),
    ]);

    if (
      /\bevent\.id\b/.test(unescapedScan) ||
      fieldNames.some((pattern) =>
        [...protectedFields].some((prot) => globMatchCase(prot, pattern)),
      )
    ) {
      throwDataPlaneError(
        400,
        "invalid_query",
        "Direct queries against cluster event.id are prohibited; cite returned evt-<16d> IDs",
      );
    }

    return rewritten.replace(/\x00(\d+)\x00/g, (_m, idxStr: string) => phrases[Number(idxStr)]!);
  }

  private buildEventEsQuery(rawQ: string | undefined): Record<string, unknown> {
    const q = rawQ ?? "";
    if (q.length > 500) {
      throwDataPlaneError(400, "invalid_query", "Lucene query exceeds 500 characters");
    }
    for (let i = 0; i < q.length; i++) {
      const c = q.charCodeAt(i);
      if (c < 32 || c === 127) {
        throwDataPlaneError(400, "invalid_query", "Control characters in Lucene query");
      }
    }
    if (LEADING_WILDCARD_RE.test(q)) {
      throwDataPlaneError(400, "leading_wildcard_not_supported", "Leading wildcards are refused");
    }

    const filters: Array<Record<string, unknown>> = structuredClone(this.scopeFilters);
    const trimmed = q.trim();
    if (trimmed.length > 0) {
      const rewritten = this.resolveCitationsInLucene(trimmed);
      refuseConnectedRegex(rewritten);
      filters.push({
        query_string: {
          query: rewritten,
          fields: QUERY_FIELDS.filter((f) => f !== "event.id"),
          default_operator: "AND",
          allow_leading_wildcard: false,
          analyze_wildcard: true,
          lenient: true,
        },
      });
    }

    return { bool: { filter: filters } };
  }

  private buildEsSort(order: "asc" | "desc"): Array<Record<string, unknown>> {
    return [
      { "@timestamp": { order, numeric_type: "date_nanos", format: "strict_date_optional_time_nanos" } },
      { _shard_doc: order },
    ];
  }

  private static isSortTuple(value: unknown): value is ConnectedSortTuple {
    if (
      !Array.isArray(value) ||
      value.length !== 2 ||
      typeof value[0] !== "string" ||
      !SORT_TIMESTAMP_RE.test(value[0]) ||
      !Number.isSafeInteger(value[1]) ||
      value[1] < 0
    ) {
      return false;
    }
    try {
      parseTimestampNs(value[0]);
      return true;
    } catch {
      return false;
    }
  }

  private encodeAfterToken(sortTuple: unknown): string {
    if (
      !ConnectedHuntDataPlane.isSortTuple(sortTuple) ||
      !Number.isSafeInteger(this.lastSearchGeneration) ||
      this.lastSearchGeneration < 1
    ) {
      throwDataPlaneError(503, "backend_not_ready", "Invalid Elasticsearch cursor tuple");
    }
    const payload = JSON.stringify([...sortTuple, this.lastSearchGeneration]);
    return Buffer.from(payload, "utf8").toString("base64url");
  }

  private decodeAfterToken(token: string): ConnectedSortTuple {
    if (typeof token !== "string" || !/^[A-Za-z0-9_-]{1,400}$/.test(token)) {
      throwDataPlaneError(400, "invalid_query", "Invalid after token");
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(Buffer.from(token, "base64url").toString("utf8"));
    } catch {
      throwDataPlaneError(400, "invalid_query", "Malformed after token");
    }
    if (
      !Array.isArray(parsed) ||
      parsed.length !== 3 ||
      !ConnectedHuntDataPlane.isSortTuple(parsed.slice(0, 2)) ||
      !Number.isSafeInteger(parsed[2]) ||
      parsed[2] < 1
    ) {
      throwDataPlaneError(400, "invalid_query", "Invalid after token structure");
    }
    if (parsed[2] !== this.generation) {
      throwDataPlaneError(400, "cursor_expired", "Snapshot generation changed; cursor expired");
    }
    return [parsed[0] as string, parsed[1] as number];
  }

  private assertCaseParam(caseIdParam: string | undefined): void {
    if (caseIdParam !== undefined && caseIdParam !== this.caseId) {
      throwDataPlaneError(400, "case_mismatch", `Expected case '${this.caseId}'`);
    }
  }

  public getCaseInfo(): Record<string, unknown> {
    // Only bot-safe fields, never cluster URL or index names!
    return {
      case_id: this.caseDef.case_id,
      question: this.caseDef.question,
      schema_version: this.caseDef.schema_version,
      sources: structuredClone(this.caseDef.sources),
      time_range_utc: structuredClone(this.caseDef.time_range_utc),
      data_origin: this.caseDef.data_origin,
      network_capture: this.caseDef.network_capture,
      ...(this.caseDef.hosts ? { hosts: [...this.caseDef.hosts] } : {}),
    };
  }

  public async elasticSearch(params: ElasticSearchParams): Promise<ElasticSearchResult> {
    this.assertCaseParam(params.case_id);
    const size = coerceBoundedInt(params.size, 50, 1, MAX_RESULT, "invalid_query");
    const sort = params.sort ?? "asc";
    if (sort !== "asc" && sort !== "desc") {
      throwDataPlaneError(400, "invalid_query", "sort must be 'asc' or 'desc'");
    }

    let requestedFields: string[] = [...DEFAULT_FIELDS];
    if (params.fields !== undefined) {
      const items = params.fields.split(",").map((s) => s.trim());
      if (
        items.length === 0 ||
        items.length > 40 ||
        items.some((s) => !s) ||
        new Set(items).size !== items.length
      ) {
        throwDataPlaneError(400, "invalid_field_list", "Invalid fields parameter");
      }
      for (const f of items) {
        if (!isAllowedSearchField(f)) {
          throwDataPlaneError(400, "field_not_allowed", `Field '${f}' is not allowlisted`);
        }
      }
      requestedFields = items;
    }
    const fields = [
      ...ALWAYS_FIELDS,
      ...requestedFields.filter((f) => !(ALWAYS_FIELDS as readonly string[]).includes(f)),
    ];

    const body: Record<string, unknown> = {
      query: this.buildEventEsQuery(params.q),
      size,
      sort: this.buildEsSort(sort),
      _source: fields,
      track_total_hits: true,
      timeout: "10s",
    };
    if (params.after !== undefined) {
      body.search_after = this.decodeAfterToken(params.after);
    }

    const resp = await this.runSearch(body);
    const hitsWrapper = (resp.hits ?? {}) as Record<string, unknown>;
    const totalObj = (hitsWrapper.total ?? { value: 0, relation: "eq" }) as {
      value: number;
      relation: "eq" | "gte";
    };
    const rawHits = Array.isArray(hitsWrapper.hits)
      ? (hitsWrapper.hits as Array<Record<string, unknown>>)
      : [];

    const hits = rawHits.map((h) => flattenFields(this.transformHitDocument(h), fields));
    const lastHit = rawHits.length === size ? rawHits[rawHits.length - 1] : undefined;
    const nextAfter =
      lastHit && Array.isArray(lastHit.sort) ? this.encodeAfterToken(lastHit.sort) : null;

    return {
      case_id: this.caseId,
      total: totalObj.value,
      total_relation: totalObj.relation ?? "eq",
      returned: hits.length,
      hits,
      next_after: nextAfter,
    };
  }

  public async elasticAggregate(params: ElasticAggregateParams): Promise<ElasticAggregateResult> {
    this.assertCaseParam(params.case_id);
    const field = params.field;
    const size = coerceBoundedInt(params.size, 20, 1, 100, "invalid_query");

    let aggregation: Record<string, unknown>;
    const extraBounds: Array<Record<string, unknown>> = [];

    if (field === "@timestamp") {
      const interval = (params.interval ?? "1h") as HistogramInterval;
      if (!Object.prototype.hasOwnProperty.call(INTERVALS, interval)) {
        throwDataPlaneError(400, "invalid_query", "interval must be 1m, 5m, 15m or 1h");
      }
      if (
        Math.ceil((this.endMs - this.startMs) / 1000 / INTERVALS[interval]) >
        MAX_HISTOGRAM_BUCKETS
      ) {
        throwDataPlaneError(400, "invalid_query", "interval too fine for the case window");
      }
      aggregation = {
        date_histogram: {
          field: "@timestamp",
          fixed_interval: interval,
          min_doc_count: 1,
          format: "yyyy-MM-dd'T'HH:mm:ss'Z'",
        },
      };
      extraBounds.push({
        range: {
          "@timestamp": {
            gte: this.startMs,
            lt: this.endMs,
            format: "epoch_millis",
          },
        },
      });
    } else if (isAllowedAggField(field)) {
      if (params.interval !== undefined) {
        throwDataPlaneError(400, "invalid_query", "interval applies only to @timestamp");
      }
      aggregation = { terms: { field, size } };
    } else {
      throwDataPlaneError(400, "field_not_allowed", `Field '${field}' is not allowed`);
    }

    aggregation.aggs = {
      sample: {
        top_hits: {
          size: 1,
          _source: ["event.id"],
          sort: this.buildEsSort("asc"),
        },
      },
    };

    const query = this.buildEventEsQuery(params.q);
    ((query.bool as Record<string, unknown>).filter as unknown[]).push(...extraBounds);

    const resp = await this.runSearch({
      query,
      size: 0,
      track_total_hits: true,
      timeout: "10s",
      aggs: { values: aggregation },
    });

    const total = ((resp.hits as Record<string, { value: number }>)?.total?.value) ?? 0;
    const aggRes = ((resp.aggregations as Record<string, unknown>)?.values ?? {}) as Record<
      string,
      unknown
    >;
    const rawBuckets = Array.isArray(aggRes.buckets)
      ? (aggRes.buckets as Array<Record<string, unknown>>)
      : [];

    const buckets: ElasticAggregateBucket[] = rawBuckets.map((b) => {
      const sampleHits = (
        ((b.sample as Record<string, unknown>)?.hits as Record<string, unknown>)?.hits ?? []
      ) as Array<Record<string, unknown>>;
      let sampleEventId: string | null = null;
      if (sampleHits.length > 0) {
        const doc = this.transformHitDocument({ _source: {}, ...sampleHits[0]! });
        const picked = pickFieldValue(doc, "event.id");
        if (typeof picked === "string") sampleEventId = picked;
      }
      return {
        key: (b.key_as_string as string | undefined) ?? (b.key as string | number),
        count: Number(b.doc_count ?? 0),
        sample_event_id: sampleEventId,
      };
    });

    const out: ElasticAggregateResult = {
      case_id: this.caseId,
      field,
      total,
      buckets,
    };
    if (typeof aggRes.sum_other_doc_count === "number") {
      out.other = aggRes.sum_other_doc_count;
    }
    return out;
  }

  public async detectionTest(params: DetectionTestParams): Promise<DetectionTestResult> {
    this.assertCaseParam(params.case_id);
    const name = (params.name ?? "").trim();
    if (!name || name.length > 80) {
      throwDataPlaneError(400, "invalid_query", "Detection name must be 1..80 characters");
    }

    const resp = await this.runSearch({
      query: this.buildEventEsQuery(params.q),
      size: 10,
      sort: this.buildEsSort("asc"),
      _source: [...DEFAULT_FIELDS],
      track_total_hits: true,
      timeout: "10s",
      aggs: {
        hosts: { terms: { field: "host.name", size: 20 } },
        first: { min: { field: "@timestamp" } },
        last: { max: { field: "@timestamp" } },
      },
    });

    const hitsWrapper = (resp.hits ?? {}) as Record<string, unknown>;
    const total = ((hitsWrapper.total as { value?: number })?.value) ?? 0;
    const rawHits = Array.isArray(hitsWrapper.hits)
      ? (hitsWrapper.hits as Array<Record<string, unknown>>)
      : [];
    const aggs = (resp.aggregations ?? {}) as Record<string, Record<string, unknown>>;
    const hostBuckets = Array.isArray(aggs.hosts?.buckets)
      ? (aggs.hosts!.buckets as Array<Record<string, unknown>>)
      : [];

    const firstAgg = aggs.first ?? {};
    const lastAgg = aggs.last ?? {};

    return {
      case_id: this.caseId,
      name,
      total,
      hosts: hostBuckets.map((b) => ({
        key: String(b.key),
        count: Number(b.doc_count ?? 0),
      })),
      first:
        firstAgg.value !== null && firstAgg.value !== undefined
          ? String(firstAgg.value_as_string ?? firstAgg.value)
          : null,
      last:
        lastAgg.value !== null && lastAgg.value !== undefined
          ? String(lastAgg.value_as_string ?? lastAgg.value)
          : null,
      sample: rawHits.map((h) => flattenFields(this.transformHitDocument(h), DEFAULT_FIELDS)),
    };
  }

  public intelLookup(_params: IntelLookupParams): never {
    throwDataPlaneError(
      400,
      "no_intel_source",
      "Connected work-elastic cases do not ship a local threat-intel feed",
    );
  }

  public arkimeSessions(_params: ArkimeSessionsParams): never {
    throwDataPlaneError(
      400,
      "no_network_capture",
      "Connected work-elastic cases have no packet capture",
    );
  }

  public arkimeUnique(_params: ArkimeUniqueParams): never {
    throwDataPlaneError(
      400,
      "no_network_capture",
      "Connected work-elastic cases have no packet capture",
    );
  }

  public packetFields(_params: PacketFieldsParams): never {
    throwDataPlaneError(
      400,
      "no_network_capture",
      "Connected work-elastic cases have no packet capture",
    );
  }

  public async huntLabQuery(params: HuntLabQueryParams): Promise<HuntLabQueryResult> {
    this.assertCaseParam(params.case_id);
    if (params.dataset === "case") {
      return this.getCaseInfo();
    }
    if (params.dataset === "network") {
      throwDataPlaneError(400, "no_network_capture", "Connected case has no packet capture");
    }
    if (params.dataset !== "events") {
      throwDataPlaneError(400, "invalid_dataset", `Unsupported dataset '${String(params.dataset)}'`);
    }

    const limit = coerceBoundedInt(params.limit, 50, 1, MAX_RESULT, "invalid_pagination");
    const offset = coerceBoundedInt(params.offset, 0, 0, 5_000, "invalid_pagination");
    const query = this.buildEventEsQuery(params.q);
    if (params.host && params.host.trim().length > 0) {
      ((query.bool as Record<string, unknown>).filter as unknown[]).push({
        term: { "host.name": params.host.trim() },
      });
    }

    const resp = await this.runSearch({
      query,
      size: limit,
      from: offset,
      sort: this.buildEsSort("asc"),
      _source: [...EVENT_FIELDS],
      track_total_hits: true,
      timeout: "10s",
    });

    const hitsWrapper = (resp.hits ?? {}) as Record<string, unknown>;
    const totalObj = (hitsWrapper.total ?? { value: 0, relation: "eq" }) as {
      value: number;
      relation: "eq" | "gte";
    };
    const rawHits = Array.isArray(hitsWrapper.hits)
      ? (hitsWrapper.hits as Array<Record<string, unknown>>)
      : [];
    const records = rawHits.map((h) =>
      filterTopLevelFields(this.transformHitDocument(h), EVENT_FIELDS),
    );

    return {
      case_id: this.caseId,
      dataset: "events",
      total: totalObj.value,
      total_relation: totalObj.relation ?? "eq",
      offset,
      limit,
      returned: records.length,
      more: offset + records.length < totalObj.value,
      records,
      read_only: true,
    };
  }

  public labBrowser(_params: LabBrowserParams): never {
    throwDataPlaneError(
      400,
      "no_lab_browser",
      "Connected work-elastic cases do not expose interactive Watch browser",
    );
  }

  public verifyCitations(citations: readonly string[]): CitationVerificationResult {
    const eventIds: string[] = [];
    const unresolved: string[] = [];
    const malformed: string[] = [];
    const unique = [...new Set(citations)];

    for (const c of unique) {
      if (CITATION_FORM_RE.test(c)) {
        if ((this.citations.get(c)?.length ?? 0) > 0) {
          eventIds.push(c);
        } else {
          unresolved.push(c);
        }
      } else if (/^(?:evt-[A-Za-z0-9_-]+|frame-0*[1-9][0-9]{0,9}|ioc-[A-Za-z0-9_-]+)$/.test(c)) {
        unresolved.push(c);
      } else {
        malformed.push(c);
      }
    }

    return {
      allValid: unresolved.length === 0 && malformed.length === 0,
      checkedCount: unique.length,
      resolved: { eventIds, frameIds: [], iocIds: [] },
      unresolved,
      malformed,
    };
  }

  public async inScopeEventCount(): Promise<number> {
    const resp = await this.runSearch({
      query: { bool: { filter: structuredClone(this.scopeFilters) } },
      size: 0,
      track_total_hits: true,
      timeout: "10s",
    });
    return ((resp.hits as Record<string, { value?: number }>)?.total?.value) ?? 0;
  }

  public async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    const activePit = this.pit;
    this.pit = null;
    if (activePit) {
      try {
        await this.callEs("DELETE", "/_pit", { id: activePit });
      } catch {
        // Best-effort PIT cleanup on shutdown
      }
    }
    this.persistActivePit(null);
  }
}
