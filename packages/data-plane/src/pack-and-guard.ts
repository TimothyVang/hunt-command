import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { stripVTControlCharacters } from "node:util";
import {
  assertReadOnlyOperation,
  assertRoleOwnsTool,
  DATA_ORIGINS,
  DATA_PLANE_TOOLS,
  type DataOrigin,
  type DataPlaneToolName,
  type HistogramInterval,
  type ProfileId,
} from "@hunt-command/shared";
import { scrubSecretsValue } from "@hunt-command/telemetry";
import { throwDataPlaneError } from "./errors.ts";
import { parseTimestampNs } from "./timestamps-and-ip.ts";

const CASE_ID_RE = /^[a-z0-9-]{3,64}$/;
const WIN32_RESERVED_DEVICE_RE = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/i;
const SAFE_REL_ARTIFACT_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/;

const TOOL_RESULT_MAX_BYTES = 24 * 1024;
const TOOL_RESULT_FENCE_BYTES = Buffer.byteLength(
  `<untrusted_tool_result_${"0".repeat(32)}>\n\n</untrusted_tool_result_${"0".repeat(32)}>`,
  "utf8",
);
const TOOL_RESULT_CONTENT_BYTES = TOOL_RESULT_MAX_BYTES - TOOL_RESULT_FENCE_BYTES;
const TOOL_RESULT_INVISIBLE_RE = /[\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/g;

function stripToolResultControls(value: unknown): unknown {
  if (typeof value === "string") {
    return stripVTControlCharacters(value).replace(TOOL_RESULT_INVISIBLE_RE, "");
  }
  if (Array.isArray(value)) {
    return value.map(stripToolResultControls);
  }
  if (value !== null && typeof value === "object" && !(value instanceof Date) && !(value instanceof Uint8Array)) {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [
        stripVTControlCharacters(key).replace(TOOL_RESULT_INVISIBLE_RE, ""),
        stripToolResultControls(item),
      ]),
    );
  }
  return value;
}

/** Normalize controls before scrubbing so invisible characters cannot disguise credentials. */
export function sanitizeToolResult(rawResult: unknown): unknown {
  return scrubSecretsValue(stripToolResultControls(rawResult));
}

function serializeToolResult(result: unknown): string {
  const serialized = JSON.stringify(result);
  if (serialized === undefined) {
    throw new TypeError("Tool result is not JSON serializable");
  }
  // Escapes preserve data while preventing case text from introducing any fence tag.
  return serialized.replace(/</g, "\\u003c");
}

export interface ToolResultPage {
  wire: string;
  next_after: string | null;
}

export interface ToolResultPager {
  first(tool: DataPlaneToolName, result: unknown): ToolResultPage;
  next(tool: DataPlaneToolName, token: string): ToolResultPage;
  clear(): void;
}

interface ToolResultSnapshot {
  readonly tool: DataPlaneToolName;
  readonly json: string;
  readonly offset: number;
}

function assertPagerTool(tool: DataPlaneToolName): void {
  if (!(DATA_PLANE_TOOLS as readonly unknown[]).includes(tool)) {
    throwDataPlaneError(403, "tool_not_owned", "Unknown data-plane tool");
  }
}

function fenceSerializedToolResult(json: string): string {
  const nonce = crypto.randomBytes(16).toString("hex");
  return `<untrusted_tool_result_${nonce}>\n${json}\n</untrusted_tool_result_${nonce}>`;
}

/**
 * Each outstanding token owns one immutable, already-sanitized JSON snapshot.
 * Transport continuations never requery a backend or reinterpret its own cursor.
 * Consuming the final page releases the snapshot; abandoned pages remain available
 * for the lifetime of this pager rather than silently expiring or losing data.
 */
export function createToolResultPager(): ToolResultPager {
  const pending = new Map<string, ToolResultSnapshot>();

  const chunk = (snapshot: ToolResultSnapshot): ToolResultPage => {
    const token = crypto.randomBytes(32).toString("hex");
    const envelope = (data: string, next_after: string | null): string =>
      serializeToolResult({ result_chunk: { encoding: "json", data, next_after } });
    const continuedBudget = TOOL_RESULT_CONTENT_BYTES - Buffer.byteLength(envelope("", token), "utf8");
    const finalBudget = TOOL_RESULT_CONTENT_BYTES - Buffer.byteLength(envelope("", null), "utf8");
    let end = snapshot.offset;
    let continuedEnd = end;
    let bytes = 0;
    // Count the JSON-string-escaped UTF-8 cost, advancing only whole code points.
    // The snapshot is JSON text, so malformed source surrogates are already escaped.
    while (end < snapshot.json.length) {
      const point = snapshot.json.codePointAt(end)!;
      const width = point > 0xffff ? 2 : 1;
      const cost = point === 0x22 || point === 0x5c ? 2
        : point < 0x20 ? (point === 8 || point === 9 || point === 10 || point === 12 || point === 13 ? 2 : 6)
        : point < 0x80 ? 1 : point < 0x800 ? 2 : point < 0x10000 ? 3 : 4;
      if (bytes + cost > finalBudget) break;
      bytes += cost;
      end += width;
      if (bytes <= continuedBudget) continuedEnd = end;
    }
    const complete = end === snapshot.json.length;
    if (!complete) end = continuedEnd;
    const next_after = complete ? null : token;
    const wire = fenceSerializedToolResult(envelope(snapshot.json.slice(snapshot.offset, end), next_after));
    if (next_after !== null) {
      pending.set(next_after, Object.freeze({ ...snapshot, offset: end }));
    }
    return { wire, next_after };
  };

  return Object.freeze({
    first(tool: DataPlaneToolName, result: unknown): ToolResultPage {
      assertPagerTool(tool);
      const json = serializeToolResult(sanitizeToolResult(result));
      if (Buffer.byteLength(json, "utf8") <= TOOL_RESULT_CONTENT_BYTES) {
        return { wire: fenceSerializedToolResult(json), next_after: null };
      }
      return chunk(Object.freeze({ tool, json, offset: 0 }));
    },
    next(tool: DataPlaneToolName, token: string): ToolResultPage {
      assertPagerTool(tool);
      if (typeof token !== "string" || !/^[0-9a-f]{64}$/.test(token)) {
        throwDataPlaneError(400, "invalid_pagination", "Invalid result continuation");
      }
      const snapshot = pending.get(token);
      if (!snapshot || snapshot.tool !== tool) {
        throwDataPlaneError(400, "invalid_pagination", "Invalid result continuation");
      }
      const page = chunk(snapshot);
      pending.delete(token);
      return page;
    },
    clear(): void {
      pending.clear();
    },
  });
}

export interface ValidatedCaseSource {
  artifact: string;
  coverage: string;
}

export interface ValidatedCasePack {
  caseDir: string;
  caseJsonPath: string;
  rawCaseObject: Record<string, unknown>;
  caseId: string;
  question: string;
  dataOrigin: DataOrigin;
  syntheticOnly: boolean;
  startInclusiveIso: string;
  endExclusiveIso: string;
  startNs: bigint;
  endNs: bigint;
  networkCapture: "present" | "none";
  hosts?: readonly string[];
  eventsPath: string | null;
  intelPath: string | null;
  pcapPath: string | null;
}

export interface ValidateCasePackOptions {
  expectedDataOrigin?: DataOrigin;
  allowWorkConnected?: boolean;
}

export function assertNoSpecialOrReparsePath(targetPath: string, label = "path"): string {
  if (typeof targetPath !== "string" || targetPath.trim().length === 0) {
    throwDataPlaneError(400, "invalid_arguments", `Empty ${label}`);
  }

  // Reject UNC paths (\\server\share or //server/share) and Win32 device namespaces (\\.\, \\?\)
  if (
    targetPath.startsWith("\\\\") ||
    targetPath.startsWith("//") ||
    /^[\\/]{2}[.?][\\/]/.test(targetPath)
  ) {
    throwDataPlaneError(
      403,
      "origin_not_allowed",
      `Refusing UNC or Win32 device ${label}: '${targetPath}'`,
    );
  }

  const resolved = path.resolve(targetPath);
  const segments = resolved.split(/[\\/]+/).filter(Boolean);
  for (const seg of segments) {
    // Strip drive colon on first segment if Windows drive
    const checkSeg = /^[A-Za-z]:$/.test(seg) ? "" : seg;
    if (checkSeg && WIN32_RESERVED_DEVICE_RE.test(checkSeg)) {
      throwDataPlaneError(
        403,
        "origin_not_allowed",
        `Refusing reserved device name in ${label}: '${seg}'`,
      );
    }
    if (
      checkSeg.toLowerCase() === "operator-only" ||
      checkSeg.toLowerCase() === "truth.json"
    ) {
      throwDataPlaneError(
        403,
        "origin_not_allowed",
        `Refusing sealed operator-only path in ${label}`,
      );
    }
  }

  if (!fs.existsSync(resolved)) {
    throwDataPlaneError(400, "invalid_arguments", `Missing ${label} on disk`);
  }

  // Walk every existing ancestor to detect symlinks, NTFS junctions, and reparse points.
  let cur = resolved;
  while (true) {
    const lstat = fs.lstatSync(cur);
    if (lstat.isSymbolicLink()) {
      throwDataPlaneError(
        403,
        "origin_not_allowed",
        `Refusing symlink or junction in ${label}: '${cur}'`,
      );
    }
    const parent = path.dirname(cur);
    if (parent === cur) {
      break;
    }
    cur = parent;
  }

  const real = fs.realpathSync(resolved);
  const normResolved =
    process.platform === "win32" ? path.normalize(resolved).toLowerCase() : path.normalize(resolved);
  const normReal =
    process.platform === "win32" ? path.normalize(real).toLowerCase() : path.normalize(real);

  if (normResolved !== normReal) {
    throwDataPlaneError(
      403,
      "origin_not_allowed",
      `Refusing reparse/junction target mismatch in ${label}`,
    );
  }

  return real;
}

/**
 * Pack Validator (`F01`): rejects UNC, Win32 device, symlink, and NTFS junction/reparse paths,
 * verifies `case.json` structure and non-empty UTC window, and enforces `data_origin` match.
 * Never touches or stats `operator-only/` or `truth.json`.
 */
export function validateCasePack(
  caseDirOrJsonPath: string,
  options: ValidateCasePackOptions = {},
): ValidatedCasePack {
  const safeInput = assertNoSpecialOrReparsePath(caseDirOrJsonPath, "case path");
  const stat = fs.statSync(safeInput);
  const caseDir = stat.isDirectory() ? safeInput : path.dirname(safeInput);
  const caseJsonPath = stat.isDirectory() ? path.join(caseDir, "case.json") : safeInput;

  const verifiedCaseJson = assertNoSpecialOrReparsePath(caseJsonPath, "case.json");

  let rawObj: unknown;
  try {
    rawObj = JSON.parse(fs.readFileSync(verifiedCaseJson, "utf8"));
  } catch {
    throwDataPlaneError(400, "invalid_arguments", "case.json is not valid JSON");
  }

  if (rawObj === null || typeof rawObj !== "object" || Array.isArray(rawObj)) {
    throwDataPlaneError(400, "invalid_arguments", "case.json must hold a JSON object");
  }
  const caseObj = rawObj as Record<string, unknown>;

  const caseId = caseObj.case_id;
  if (typeof caseId !== "string" || !CASE_ID_RE.test(caseId)) {
    throwDataPlaneError(400, "invalid_arguments", "case.json case_id must match [a-z0-9-]{3,64}");
  }

  const rawOrigin = caseObj.data_origin;
  if (
    typeof rawOrigin !== "string" ||
    !(DATA_ORIGINS as readonly string[]).includes(rawOrigin)
  ) {
    throwDataPlaneError(400, "origin_not_allowed", "Invalid data_origin in case.json");
  }
  const dataOrigin = rawOrigin as DataOrigin;
  const syntheticOnly = dataOrigin === "synthetic";

  if (
    caseObj.synthetic_only !== undefined &&
    caseObj.synthetic_only !== syntheticOnly
  ) {
    throwDataPlaneError(
      400,
      "case_origin_mismatch",
      "case.json synthetic_only contradicts data_origin",
    );
  }

  if (dataOrigin === "work-connected" && options.allowWorkConnected !== true) {
    throwDataPlaneError(
      403,
      "origin_not_allowed",
      "work-connected cases must be served via ConnectedHuntDataPlane, never EmbeddedHuntDataPlane",
    );
  }

  if (dataOrigin !== "synthetic") {
    if (!options.expectedDataOrigin) {
      throwDataPlaneError(
        403,
        "origin_not_allowed",
        `Non-synthetic case '${caseId}' (${dataOrigin}) requires explicit expectedDataOrigin`,
      );
    }
    if (options.expectedDataOrigin !== dataOrigin) {
      throwDataPlaneError(
        400,
        "case_origin_mismatch",
        `Expected data_origin '${options.expectedDataOrigin}' but case.json declares '${dataOrigin}'`,
      );
    }
  } else if (
    options.expectedDataOrigin !== undefined &&
    options.expectedDataOrigin !== "synthetic"
  ) {
    throwDataPlaneError(
      400,
      "case_origin_mismatch",
      `Expected data_origin '${options.expectedDataOrigin}' but case.json is 'synthetic'`,
    );
  }

  let startInclusiveIso: string | undefined;
  let endExclusiveIso: string | undefined;

  if (caseObj.time_range_utc && typeof caseObj.time_range_utc === "object") {
    const tr = caseObj.time_range_utc as Record<string, unknown>;
    if (typeof tr.start_inclusive === "string" && typeof tr.end_exclusive === "string") {
      startInclusiveIso = tr.start_inclusive;
      endExclusiveIso = tr.end_exclusive;
    }
  } else if (caseObj.time_window && typeof caseObj.time_window === "object") {
    const tw = caseObj.time_window as Record<string, unknown>;
    if (typeof tw.start_iso === "string" && typeof tw.end_iso === "string") {
      startInclusiveIso = tw.start_iso;
      endExclusiveIso = tw.end_iso;
    }
  }

  if (!startInclusiveIso || !endExclusiveIso) {
    throwDataPlaneError(
      400,
      "invalid_arguments",
      "case.json requires time_range_utc.{start_inclusive,end_exclusive}",
    );
  }

  let startNs: bigint;
  let endNs: bigint;
  try {
    startNs = parseTimestampNs(startInclusiveIso);
    endNs = parseTimestampNs(endExclusiveIso);
  } catch {
    throwDataPlaneError(400, "invalid_arguments", "Invalid UTC timestamps in case.json");
  }

  if (startNs >= endNs) {
    throwDataPlaneError(400, "invalid_arguments", "case.json time_range_utc must be non-empty");
  }

  if (
    caseObj.network_capture !== undefined &&
    caseObj.network_capture !== "none"
  ) {
    throwDataPlaneError(
      400,
      "invalid_arguments",
      'case.json network_capture may only be "none" when specified',
    );
  }

  const checkOptionalArtifact = (relName: string): string | null => {
    if (!SAFE_REL_ARTIFACT_RE.test(relName) || relName.toLowerCase() === "truth.json") {
      throwDataPlaneError(403, "origin_not_allowed", `Forbidden artifact name '${relName}'`);
    }
    const candidate = path.join(caseDir, relName);
    if (!fs.existsSync(candidate)) {
      return null;
    }
    return assertNoSpecialOrReparsePath(candidate, relName);
  };

  const eventsPath = checkOptionalArtifact("events.jsonl");
  const intelPath = checkOptionalArtifact("intel.jsonl");
  const rawPcapRel =
    typeof caseObj.pcap_relpath === "string" ? caseObj.pcap_relpath : null;
  let pcapPath: string | null = null;
  if (caseObj.network_capture !== "none") {
    if (rawPcapRel) {
      pcapPath = checkOptionalArtifact(rawPcapRel);
    } else {
      pcapPath =
        checkOptionalArtifact("traffic.pcap") ?? checkOptionalArtifact("traffic.pcapng");
    }
  }

  const networkCapture: "present" | "none" =
    caseObj.network_capture === "none" || pcapPath === null ? "none" : "present";

  const question =
    typeof caseObj.question === "string" && caseObj.question.trim().length > 0
      ? caseObj.question
      : typeof caseObj.title === "string"
        ? caseObj.title
        : "";

  let hosts: readonly string[] | undefined;
  if (Array.isArray(caseObj.hosts)) {
    hosts = caseObj.hosts.filter((h): h is string => typeof h === "string");
  }

  return {
    caseDir,
    caseJsonPath: verifiedCaseJson,
    rawCaseObject: caseObj,
    caseId,
    question,
    dataOrigin,
    syntheticOnly,
    startInclusiveIso,
    endExclusiveIso,
    startNs,
    endNs,
    networkCapture,
    hosts,
    eventsPath,
    intelPath,
    pcapPath,
  };
}

/**
 * Coerces bounded integer arguments, cleanly handling string integers like `"30"` that bots emit
 * while rejecting floats, negatives, hex, whitespace, booleans, and out-of-range values.
 */
export function coerceBoundedInt(
  rawValue: unknown,
  defaultValue: number,
  low: number,
  high: number,
  errorCode: "invalid_query" | "invalid_pagination" = "invalid_query",
): number {
  if (rawValue === undefined || rawValue === null) {
    return defaultValue;
  }

  let parsed: number;
  if (typeof rawValue === "number") {
    if (!Number.isInteger(rawValue)) {
      throwDataPlaneError(400, errorCode, "Expected integer parameter");
    }
    parsed = rawValue;
  } else if (typeof rawValue === "string") {
    if (!/^[0-9]{1,10}$/.test(rawValue)) {
      throwDataPlaneError(400, errorCode, "Expected unsigned integer string");
    }
    parsed = Number.parseInt(rawValue, 10);
  } else {
    throwDataPlaneError(400, errorCode, "Expected integer parameter");
  }

  if (parsed < low || parsed > high) {
    throwDataPlaneError(400, errorCode, `Integer out of range [${low}, ${high}]`);
  }
  return parsed;
}

export interface ElasticSearchParams {
  case_id?: string;
  q?: string;
  size?: number | string;
  sort?: "asc" | "desc";
  after?: string;
  fields?: string;
}

export interface ElasticSearchResult {
  case_id: string;
  total: number;
  total_relation: "eq" | "gte";
  returned: number;
  hits: Array<Record<string, unknown>>;
  next_after: string | null;
}

export interface ElasticAggregateParams {
  case_id?: string;
  q?: string;
  field: string;
  size?: number | string;
  interval?: HistogramInterval;
}

export interface ElasticAggregateBucket {
  key: string | number;
  count: number;
  sample_event_id: string | null;
}

export interface ElasticAggregateResult {
  case_id: string;
  field: string;
  total: number;
  buckets: ElasticAggregateBucket[];
  other?: number;
}

export interface DetectionTestParams {
  case_id?: string;
  q: string;
  name: string;
}

export interface DetectionTestResult {
  case_id: string;
  name: string;
  total: number;
  hosts: Array<{ key: string; count: number }>;
  first: string | null;
  last: string | null;
  sample: Array<Record<string, unknown>>;
}

export interface IntelLookupParams {
  case_id?: string;
  values: string;
}

export interface IntelLookupResult {
  case_id: string;
  matches: Array<Record<string, unknown>>;
  unmatched: string[];
}

export interface ArkimeSessionsParams {
  case_id?: string;
  expression?: string;
  length?: number | string;
  start?: number | string;
  fields?: string;
}

export interface ArkimeSessionsResult {
  case_id: string;
  recordsFiltered: number;
  returned: number;
  sessions: Array<Record<string, unknown>>;
}

export interface ArkimeUniqueParams {
  case_id?: string;
  expression?: string;
  field: string;
  counts?: number | string;
}

export interface ArkimeUniqueResult {
  case_id: string;
  field: string;
  returned: number;
  truncated: boolean;
  values: Array<{ value: string; count?: number }>;
}

export interface PacketFieldsParams {
  case_id?: string;
  fields?: string;
  filter?: string;
  length?: number | string;
  start?: number | string;
}

export interface PacketFieldsResult {
  case_id: string;
  fields: string[];
  start: number;
  returned: number;
  more: boolean;
  truncated: boolean;
  rows: Array<Record<string, unknown>>;
}

export interface HuntLabQueryParams {
  case_id?: string;
  dataset: "case" | "events" | "network";
  q?: string;
  host?: string;
  limit?: number | string;
  offset?: number | string;
}

export interface HuntLabQueryRecordsResult {
  case_id: string;
  dataset: "events" | "network";
  total: number;
  total_relation: "eq" | "gte";
  offset: number;
  limit: number;
  returned: number;
  more: boolean;
  records: Array<Record<string, unknown>>;
  read_only: true;
}

export type HuntLabQueryResult = Record<string, unknown> | HuntLabQueryRecordsResult;

export type WatchPageId =
  | "lab_console"
  | "kibana_discover"
  | "arkime_sessions"
  | "arkime_spiview";

export interface LabBrowserParams {
  case_id?: string;
  page: WatchPageId;
  q?: string;
  host?: string;
  expression?: string;
  field?: string;
}

export interface LabBrowserResult {
  case_id: string;
  page: WatchPageId;
  url: string;
  title: string;
  summary: string;
  returned: number;
  blocked_requests: number;
  html_preview?: string;
}

export type AuthorizeWatchTool = (tool: DataPlaneToolName) => void;

export interface CitationVerificationResult {
  allValid: boolean;
  checkedCount: number;
  resolved: {
    eventIds: string[];
    frameIds: string[];
    iocIds: string[];
  };
  unresolved: string[];
  malformed: string[];
}

export interface HuntDataPlane {
  readonly caseId: string;
  readonly dataOrigin: DataOrigin;
  readonly syntheticOnly: boolean;
  readonly hasNetworkCapture: boolean;
  readonly hasIntelFeed: boolean;

  getCaseInfo(): Record<string, unknown>;
  elasticSearch(params: ElasticSearchParams): Promise<ElasticSearchResult> | ElasticSearchResult;
  elasticAggregate(
    params: ElasticAggregateParams,
  ): Promise<ElasticAggregateResult> | ElasticAggregateResult;
  detectionTest(params: DetectionTestParams): Promise<DetectionTestResult> | DetectionTestResult;
  intelLookup(params: IntelLookupParams): Promise<IntelLookupResult> | IntelLookupResult;
  arkimeSessions(params: ArkimeSessionsParams): Promise<ArkimeSessionsResult> | ArkimeSessionsResult;
  arkimeUnique(params: ArkimeUniqueParams): Promise<ArkimeUniqueResult> | ArkimeUniqueResult;
  packetFields(params: PacketFieldsParams): Promise<PacketFieldsResult> | PacketFieldsResult;
  huntLabQuery(params: HuntLabQueryParams): Promise<HuntLabQueryResult> | HuntLabQueryResult;
  labBrowser(
    params: LabBrowserParams,
    authorizeTool?: AuthorizeWatchTool,
  ): Promise<LabBrowserResult> | LabBrowserResult;
  verifyCitations(citations: readonly string[]): Promise<CitationVerificationResult> | CitationVerificationResult;
  close(): Promise<void> | void;
}

export interface RoleCapabilityToken {
  readonly huntId: string;
  readonly caseId: string;
  readonly profile: ProfileId;
  readonly stepId?: string;
  readonly issuedAtMs: number;
  readonly signatureHex: string;
}

export interface RoleScopedDataPlane {
  readonly profile: ProfileId;
  readonly stepId?: string;
  readonly caseId: string;
  executeTool(
    tool: DataPlaneToolName,
    args: Record<string, unknown>,
    options?: { method?: string },
  ): Promise<string>;
}

export interface RoleCapabilityMint {
  issueCapability(params: {
    huntId: string;
    caseId: string;
    profile: ProfileId;
    stepId?: string;
  }): RoleCapabilityToken;
  verifyCapability(token: RoleCapabilityToken, expectedCaseId: string): void;
  bindDataPlane(dataPlane: HuntDataPlane, token: RoleCapabilityToken): RoleScopedDataPlane;
}

/**
 * Closure-bound `HMAC-SHA256` capability mint & verifier.
 * The 256-bit HMAC secret lives exclusively inside the closure scope and is never exposed
 * on any returned object property, preventing forgery or unauthorized cross-role tool access.
 */
export function createRoleCapabilityMint(explicitSecret?: Uint8Array): RoleCapabilityMint {
  const secretKey = Buffer.from(explicitSecret ?? crypto.randomBytes(32));
  if (secretKey.byteLength < 32) {
    throw new Error("Role capability HMAC key must be at least 32 bytes");
  }

  const computeMac = (
    huntId: string,
    caseId: string,
    profile: ProfileId,
    stepId: string | undefined,
    issuedAtMs: number,
  ): Buffer => {
    const h = crypto.createHmac("sha256", secretKey);
    h.update(`${huntId}\0${caseId}\0${profile}\0${stepId ?? ""}\0${issuedAtMs}`);
    return h.digest();
  };

  const verifyCapability = (token: RoleCapabilityToken, expectedCaseId: string): void => {
    if (
      !token ||
      typeof token.signatureHex !== "string" ||
      !/^[0-9a-f]{64}$/.test(token.signatureHex)
    ) {
      throwDataPlaneError(403, "unauthorized_instance", "Malformed role capability signature");
    }
    if (token.caseId !== expectedCaseId) {
      throwDataPlaneError(
        403,
        "unauthorized_instance",
        `Capability bound to case '${token.caseId}', not '${expectedCaseId}'`,
      );
    }
    const expectedMac = computeMac(
      token.huntId,
      token.caseId,
      token.profile,
      token.stepId,
      token.issuedAtMs,
    );
    const actualMac = Buffer.from(token.signatureHex, "hex");
    if (
      actualMac.byteLength !== expectedMac.byteLength ||
      !crypto.timingSafeEqual(actualMac, expectedMac)
    ) {
      throwDataPlaneError(403, "unauthorized_instance", "Forged or invalid role capability HMAC");
    }
  };

  const issueCapability = (params: {
    huntId: string;
    caseId: string;
    profile: ProfileId;
    stepId?: string;
  }): RoleCapabilityToken => {
    const issuedAtMs = Date.now();
    const signatureHex = computeMac(
      params.huntId,
      params.caseId,
      params.profile,
      params.stepId,
      issuedAtMs,
    ).toString("hex");

    return Object.freeze({
      huntId: params.huntId,
      caseId: params.caseId,
      profile: params.profile,
      ...(params.stepId !== undefined ? { stepId: params.stepId } : {}),
      issuedAtMs,
      signatureHex,
    });
  };

  const bindDataPlane = (
    dataPlane: HuntDataPlane,
    token: RoleCapabilityToken,
  ): RoleScopedDataPlane => {
    verifyCapability(token, dataPlane.caseId);
    const pager = createToolResultPager();

    const executeTool = async (
      tool: DataPlaneToolName,
      args: Record<string, unknown>,
      options?: { method?: string },
    ): Promise<string> => {
      // Re-verify closure HMAC on every invocation in case token object was mutated/swapped.
      verifyCapability(token, dataPlane.caseId);

      const rawMethod = options?.method ?? "GET";
      assertReadOnlyOperation(typeof rawMethod !== "string" || rawMethod.toUpperCase() !== "GET");
      assertRoleOwnsTool(token.profile, tool, token.stepId);

      if (args === null || typeof args !== "object" || Array.isArray(args)) {
        throwDataPlaneError(400, "invalid_query", "Tool arguments must be an object");
      }

      if (args.case_id !== undefined && args.case_id !== dataPlane.caseId) {
        if (typeof args.case_id !== "string" || !CASE_ID_RE.test(args.case_id)) {
          throwDataPlaneError(400, "explicit_case_id_required", "Invalid or missing case_id");
        }
        throwDataPlaneError(400, "case_mismatch", `Case mismatch: expected '${dataPlane.caseId}'`);
      }

      if (Object.prototype.hasOwnProperty.call(args, "result_after")) {
        if (typeof args.result_after !== "string"
          || Object.keys(args).some((key) => key !== "result_after" && key !== "case_id")) {
          throwDataPlaneError(400, "invalid_pagination", "Result continuation cannot include query arguments");
        }
        return pager.next(tool, args.result_after).wire;
      }

      let rawResult: unknown;
      switch (tool) {
        case "elastic_search":
          rawResult = await dataPlane.elasticSearch(args as unknown as ElasticSearchParams);
          break;
        case "elastic_aggregate":
          rawResult = await dataPlane.elasticAggregate(args as unknown as ElasticAggregateParams);
          break;
        case "detection_test":
          rawResult = await dataPlane.detectionTest(args as unknown as DetectionTestParams);
          break;
        case "intel_lookup":
          rawResult = await dataPlane.intelLookup(args as unknown as IntelLookupParams);
          break;
        case "arkime_sessions":
          rawResult = await dataPlane.arkimeSessions(args as unknown as ArkimeSessionsParams);
          break;
        case "arkime_unique":
          rawResult = await dataPlane.arkimeUnique(args as unknown as ArkimeUniqueParams);
          break;
        case "packet_fields":
          rawResult = await dataPlane.packetFields(args as unknown as PacketFieldsParams);
          break;
        case "hunt_lab_query":
          rawResult = await dataPlane.huntLabQuery(args as unknown as HuntLabQueryParams);
          break;
        case "lab_browser":
          rawResult = await dataPlane.labBrowser(
            args as unknown as LabBrowserParams,
            (pageTool) => {
              verifyCapability(token, dataPlane.caseId);
              assertRoleOwnsTool(token.profile, pageTool, token.stepId);
            },
          );
          break;
        default:
          throwDataPlaneError(403, "tool_not_owned", `Unknown data-plane tool '${String(tool)}'`);
      }

      return pager.first(tool, rawResult).wire;
    };

    return Object.freeze({
      profile: token.profile,
      ...(token.stepId !== undefined ? { stepId: token.stepId } : {}),
      caseId: dataPlane.caseId,
      executeTool,
    });
  };

  return Object.freeze({
    issueCapability,
    verifyCapability,
    bindDataPlane,
  });
}
