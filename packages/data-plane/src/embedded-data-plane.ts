import { Database } from "bun:sqlite";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import {
  ALWAYS_FIELDS,
  ARKIME_DEFAULT_FIELDS,
  ARKIME_SESSION_FIELDS,
  ARKIME_UNIQUE_FIELDS,
  type CaseMetadata,
  type DataOrigin,
  type DataPlaneToolName,
  DEFAULT_FIELDS,
  EVENT_FIELDS,
  type HistogramInterval,
  INTEL_FIELDS,
  INTERVALS,
  isAllowedAggField,
  isAllowedSearchField,
  KEYWORD_FIELDS,
  LABEL_FIELD_RE,
  MAX_PACKET_START,
  PACKET_ALWAYS_FIELDS,
  PACKET_DEFAULT_FIELDS,
  PACKET_FIELDS,
  REAL_DATA_ORIGIN_LABELS,
  resolveRuntimeDir,
} from "@hunt-command/shared";
import { extractDataPlaneError, throwDataPlaneError } from "./errors.ts";
import { compileLuceneQueryString, type SqlParam } from "./lucene-compiler.ts";
import {
  checkArkimeBalancedExpression,
  compileArkimeExpression,
  compileNetworkDatasetFilter,
  compilePacketDisplayFilter,
} from "./network-compilers.ts";
import {
  type ArkimeSessionsParams,
  type AuthorizeWatchTool,
  type ArkimeSessionsResult,
  type ArkimeUniqueParams,
  type ArkimeUniqueResult,
  type CitationVerificationResult,
  type CitedRecord,
  coerceBoundedInt,
  type DetectionTestParams,
  type DetectionTestResult,
  type ElasticAggregateBucket,
  type ElasticAggregateParams,
  type ElasticAggregateResult,
  type ElasticSearchParams,
  type ElasticSearchResult,
  budgetElasticSearchResult,
  fenceToolResult,
  type HuntDataPlane,
  type HuntLabQueryParams,
  type HuntLabQueryResult,
  type IntelLookupParams,
  type IntelLookupResult,
  type LabBrowserParams,
  type LabBrowserResult,
  type PacketFieldsParams,
  type PacketFieldsResult,
  type ValidatedCasePack,
  type ValidateCasePackOptions,
  sanitizeToolResult,
  validateCasePack,
  type WatchPageId,
} from "./pack-and-guard.ts";
import { indexPcapIntoDatabase, runPcapIndexerWorker } from "./pcap-worker.ts";
import {
  epochMillisFromNs,
  filterTopLevelFields,
  flattenFields,
  formatIsoSecondsZ,
  formatNsAsIso,
  ipToBytes16,
  parseTimestampNs,
  pickFieldValue,
} from "./timestamps-and-ip.ts";

const CACHE_SCHEMA_VERSION = "hunt-command-embedded-cache-v2";
const MAX_RESULT = 200;
const MAX_HISTOGRAM_BUCKETS = 2_000;
const MAX_UNIQUE_VALUES = 1_000;
const MAX_BACKEND_BYTES = 2 * 1024 * 1024;

const LONG_KEYWORD_FIELDS: ReadonlySet<string> = new Set([
  "process.command_line",
  "process.parent.command_line",
  "url.full",
  "file.path",
  "user_agent.original",
]);

const EVENT_IP_FIELDS: ReadonlySet<string> = new Set([
  "host.ip",
  "source.ip",
  "destination.ip",
  "dns.resolved_ip",
]);

const PACKET_ALLOWED_SET: ReadonlySet<string> = new Set<string>(PACKET_FIELDS);
const ARKIME_SESSION_SET: ReadonlySet<string> = new Set<string>(ARKIME_SESSION_FIELDS);

function hashFileStream(hash: crypto.Hash, filePath: string | null, tag: string): void {
  hash.update(`\0${tag}\0`);
  if (!filePath) {
    hash.update("ABSENT");
    return;
  }
  const fd = fs.openSync(filePath, "r");
  try {
    const buf = new Uint8Array(65_536);
    while (true) {
      const n = fs.readSync(fd, buf, 0, buf.length, null);
      if (n <= 0) break;
      hash.update(buf.subarray(0, n));
    }
  } finally {
    fs.closeSync(fd);
  }
}

export function computeCaseSnapshotHash(pack: ValidatedCasePack): string {
  const hash = crypto.createHash("sha256");
  hash.update(CACHE_SCHEMA_VERSION);
  hashFileStream(hash, pack.caseJsonPath, "case.json");
  hashFileStream(hash, pack.eventsPath, "events.jsonl");
  hashFileStream(hash, pack.intelPath, "intel.jsonl");
  hashFileStream(hash, pack.pcapPath, "traffic.pcap");
  return hash.digest("hex").slice(0, 24);
}

function computeCaseStatFingerprint(pack: ValidatedCasePack): string {
  const hash = crypto.createHash("sha256");
  hash.update(CACHE_SCHEMA_VERSION);
  for (const [tag, filePath] of [
    ["case.json", pack.caseJsonPath],
    ["events.jsonl", pack.eventsPath],
    ["intel.jsonl", pack.intelPath],
    ["traffic.pcap", pack.pcapPath],
  ] as const) {
    hash.update(`\0${tag}\0`);
    if (!filePath) {
      hash.update("ABSENT");
      continue;
    }
    const st = fs.statSync(filePath, { bigint: true });
    hash.update(`${filePath}:${st.size}:${st.mtimeNs}:${st.ctimeNs}`);
  }
  return hash.digest("hex");
}

function statIndexPathForPack(cacheDir: string, pack: ValidatedCasePack): string {
  const dirKey = crypto.createHash("sha256").update(pack.caseDir).digest("hex").slice(0, 12);
  return path.join(cacheDir, `${pack.caseId}-${dirKey}.stat.json`);
}

function tryReadFastCacheTarget(
  cacheDir: string,
  pack: ValidatedCasePack,
  statFp: string,
): { snapHash: string; cacheDbPath: string } | null {
  const idxPath = statIndexPathForPack(cacheDir, pack);
  if (!fs.existsSync(idxPath)) return null;
  try {
    const parsed = JSON.parse(fs.readFileSync(idxPath, "utf8")) as {
      statFp?: string;
      snapHash?: string;
    };
    if (
      parsed.statFp === statFp &&
      typeof parsed.snapHash === "string" &&
      /^[0-9a-f]{24}$/.test(parsed.snapHash)
    ) {
      const cacheDbPath = path.join(cacheDir, `${pack.caseId}-${parsed.snapHash}.sqlite`);
      if (fs.existsSync(cacheDbPath)) {
        return { snapHash: parsed.snapHash, cacheDbPath };
      }
    }
  } catch {
    // Ignore malformed stat hint; fall back to full SHA-256 stream
  }
  return null;
}

function writeFastCacheTarget(
  cacheDir: string,
  pack: ValidatedCasePack,
  statFp: string,
  snapHash: string,
): void {
  try {
    const idxPath = statIndexPathForPack(cacheDir, pack);
    fs.writeFileSync(idxPath, JSON.stringify({ statFp, snapHash }), "utf8");
  } catch {
    // Non-fatal cache hint
  }
}

function streamJsonlLines(filePath: string, onLine: (line: string, lineNum: number) => void): void {
  const fd = fs.openSync(filePath, "r");
  try {
    const buf = Buffer.allocUnsafe(65_536);
    const decoder = new TextDecoder("utf-8");
    let carry = "";
    let lineNum = 0;

    while (true) {
      const bytesRead = fs.readSync(fd, buf, 0, buf.length, null);
      if (bytesRead <= 0) break;
      carry += decoder.decode(buf.subarray(0, bytesRead), { stream: true });
      let nl = carry.indexOf("\n");
      while (nl !== -1) {
        const rawLine = carry.slice(0, nl).replace(/\r$/, "");
        carry = carry.slice(nl + 1);
        lineNum++;
        if (rawLine.trim().length > 0) {
          onLine(rawLine, lineNum);
        }
        nl = carry.indexOf("\n");
      }
    }
    carry += decoder.decode();
    const tail = carry.replace(/\r$/, "");
    if (tail.trim().length > 0) {
      lineNum++;
      onLine(tail, lineNum);
    }
  } finally {
    fs.closeSync(fd);
  }
}

function extractScalarStrings(raw: unknown): string[] {
  if (raw === undefined || raw === null) {
    return [];
  }
  if (typeof raw === "string") {
    return [raw];
  }
  if (typeof raw === "number" || typeof raw === "boolean") {
    return [String(raw)];
  }
  if (Array.isArray(raw)) {
    const out: string[] = [];
    for (const item of raw) {
      for (const s of extractScalarStrings(item)) {
        out.push(s);
      }
    }
    return out;
  }
  return [];
}

function parseFiniteNum(str: string): number | null {
  if (/^-?[0-9]+(?:\.[0-9]+)?$/.test(str)) {
    const n = Number(str);
    return Number.isFinite(n) ? n : null;
  }
  return null;
}

function initCacheTables(db: Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS cache_meta (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS events_hot (
      doc_id INTEGER PRIMARY KEY,
      ts_ns INTEGER NOT NULL,
      ts_iso TEXT NOT NULL,
      event_id TEXT NOT NULL,
      host_name TEXT,
      has_message INTEGER NOT NULL DEFAULT 0,
      has_script_block INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS event_blobs (
      doc_id INTEGER PRIMARY KEY,
      raw_json_zst BLOB NOT NULL
    );

    CREATE TABLE IF NOT EXISTS event_kv (
      doc_id INTEGER NOT NULL,
      field TEXT NOT NULL,
      val_str TEXT NOT NULL,
      val_num REAL
    );

    CREATE TABLE IF NOT EXISTS event_ips (
      doc_id INTEGER NOT NULL,
      field TEXT NOT NULL,
      ip_bin BLOB NOT NULL
    );

    CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
      message,
      script_block_text,
      process_command_line,
      process_parent_command_line,
      url_full,
      file_path,
      user_agent_original,
      tokenize = 'unicode61'
    );

    CREATE VIRTUAL TABLE IF NOT EXISTS events_fts_vocab USING fts5vocab(events_fts, instance);

    CREATE TABLE IF NOT EXISTS intel_items (
      ioc_row_id INTEGER PRIMARY KEY,
      ioc_id TEXT NOT NULL,
      indicator_value_lower TEXT NOT NULL,
      indicator_value TEXT NOT NULL,
      feed_name TEXT NOT NULL,
      flat_json TEXT NOT NULL
    );
  `);
}

function createEventAndIntelIndexes(db: Database): void {
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_events_ts_asc ON events_hot(ts_ns ASC, event_id ASC);
    CREATE INDEX IF NOT EXISTS idx_events_event_id ON events_hot(event_id);
    CREATE INDEX IF NOT EXISTS idx_events_host ON events_hot(host_name, ts_ns);
    CREATE INDEX IF NOT EXISTS idx_event_kv_field_str ON event_kv(field, val_str, doc_id);
    CREATE INDEX IF NOT EXISTS idx_event_kv_field_num ON event_kv(field, val_num, doc_id);
    CREATE INDEX IF NOT EXISTS idx_event_kv_doc_field ON event_kv(doc_id, field);
    CREATE INDEX IF NOT EXISTS idx_event_ips_lookup ON event_ips(field, ip_bin, doc_id);
    CREATE INDEX IF NOT EXISTS idx_intel_val_lower ON intel_items(indicator_value_lower, indicator_value, feed_name);
    CREATE INDEX IF NOT EXISTS idx_intel_ioc_id ON intel_items(ioc_id);
  `);
}

function ingestEventsAndIntelIntoDb(db: Database, pack: ValidatedCasePack): void {
  initCacheTables(db);

  if (pack.eventsPath) {
    const insertHot = db.prepare(
      `INSERT INTO events_hot (doc_id, ts_ns, ts_iso, event_id, host_name, has_message, has_script_block)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    );
    const insertBlob = db.prepare(
      `INSERT INTO event_blobs (doc_id, raw_json_zst) VALUES (?, ?)`,
    );
    const insertKv = db.prepare(
      `INSERT INTO event_kv (doc_id, field, val_str, val_num) VALUES (?, ?, ?, ?)`,
    );
    const insertIp = db.prepare(
      `INSERT INTO event_ips (doc_id, field, ip_bin) VALUES (?, ?, ?)`,
    );
    const insertFts = db.prepare(
      `INSERT INTO events_fts (
         rowid, message, script_block_text, process_command_line,
         process_parent_command_line, url_full, file_path, user_agent_original
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    );

    const BATCH = 2_500;
    let docSeq = 0;
    let pendingLines: string[] = [];

    const indexDocKvField = (docId: number, field: string, rawVal: unknown): void => {
      const scalars = extractScalarStrings(rawVal);
      if (scalars.length === 0) return;
      const ignoreAbove = LONG_KEYWORD_FIELDS.has(field) ? 8192 : 1024;
      const seen = new Set<string>();
      for (const s of scalars) {
        if (Buffer.byteLength(s, "utf8") > ignoreAbove) {
          continue;
        }
        if (seen.has(s)) continue;
        seen.add(s);
        insertKv.run(docId, field, s, parseFiniteNum(s));

        if (EVENT_IP_FIELDS.has(field)) {
          const bin = ipToBytes16(s);
          if (bin) {
            insertIp.run(docId, field, bin);
          }
        }
      }
    };

    const flushBatch = db.transaction((lines: readonly string[]) => {
      for (const line of lines) {
        const doc = JSON.parse(line) as Record<string, unknown>;
        docSeq += 1;
        const docId = docSeq;

        const rawTs = pickFieldValue(doc, "@timestamp");
        const tsIso = typeof rawTs === "string" ? rawTs : pack.startInclusiveIso;
        const tsNs = parseTimestampNs(tsIso);

        const rawEvtId = pickFieldValue(doc, "event.id");
        const eventId =
          typeof rawEvtId === "string" && rawEvtId.length > 0
            ? rawEvtId
            : `evt-${String(docId).padStart(6, "0")}`;

        // Ensure event.id is populated on stored JSON if missing
        if (typeof rawEvtId !== "string" || rawEvtId.length === 0) {
          const evObj =
            doc.event && typeof doc.event === "object" && !Array.isArray(doc.event)
              ? { ...(doc.event as Record<string, unknown>), id: eventId }
              : { id: eventId };
          doc.event = evObj;
        }

        const rawHost = pickFieldValue(doc, "host.name");
        const hostName =
          typeof rawHost === "string"
            ? rawHost
            : Array.isArray(rawHost) && typeof rawHost[0] === "string"
              ? rawHost[0]
              : null;

        const msgVal = pickFieldValue(doc, "message");
        const msgText = extractScalarStrings(msgVal).join(" ");
        const sbVal = pickFieldValue(doc, "powershell.file.script_block_text");
        const sbText = extractScalarStrings(sbVal).join(" ");

        insertHot.run(
          docId,
          tsNs,
          tsIso,
          eventId,
          hostName,
          msgText.length > 0 ? 1 : 0,
          sbText.length > 0 ? 1 : 0,
        );

        const zstBytes = Bun.zstdCompressSync(Buffer.from(JSON.stringify(doc), "utf8"));
        insertBlob.run(docId, zstBytes);

        for (const kwField of KEYWORD_FIELDS) {
          if (kwField === "event.id") {
            insertKv.run(docId, "event.id", eventId, null);
            continue;
          }
          const v = pickFieldValue(doc, kwField);
          if (v !== undefined) {
            indexDocKvField(docId, kwField, v);
          }
        }

        // Extra numeric / DNS answer / dynamic labels.* fields
        for (const extraField of [
          "network.bytes",
          "network.packets",
          "dns.answers.name",
          "dns.answers.type",
          "dns.resolved_ip",
        ]) {
          const v = pickFieldValue(doc, extraField);
          if (v !== undefined) {
            indexDocKvField(docId, extraField, v);
          }
        }

        if (doc.labels && typeof doc.labels === "object" && !Array.isArray(doc.labels)) {
          for (const [k, v] of Object.entries(doc.labels as Record<string, unknown>)) {
            const labelField = `labels.${k}`;
            if (LABEL_FIELD_RE.test(labelField)) {
              indexDocKvField(docId, labelField, v);
            }
          }
        }

        const cmdLine = extractScalarStrings(pickFieldValue(doc, "process.command_line")).join(" ");
        const parentCmdLine = extractScalarStrings(
          pickFieldValue(doc, "process.parent.command_line"),
        ).join(" ");
        const urlFull = extractScalarStrings(pickFieldValue(doc, "url.full")).join(" ");
        const filePath = extractScalarStrings(pickFieldValue(doc, "file.path")).join(" ");
        const uaOrig = extractScalarStrings(pickFieldValue(doc, "user_agent.original")).join(" ");

        if (
          msgText ||
          sbText ||
          cmdLine ||
          parentCmdLine ||
          urlFull ||
          filePath ||
          uaOrig
        ) {
          insertFts.run(
            docId,
            msgText,
            sbText,
            cmdLine,
            parentCmdLine,
            urlFull,
            filePath,
            uaOrig,
          );
        }
      }
    });

    try {
      streamJsonlLines(pack.eventsPath, (line) => {
        pendingLines.push(line);
        if (pendingLines.length >= BATCH) {
          flushBatch(pendingLines);
          pendingLines = [];
        }
      });
      if (pendingLines.length > 0) {
        flushBatch(pendingLines);
        pendingLines = [];
      }
    } finally {
      insertHot.finalize();
      insertBlob.finalize();
      insertKv.finalize();
      insertIp.finalize();
      insertFts.finalize();
    }
  }

  if (pack.intelPath) {
    const insertIntel = db.prepare(
      `INSERT INTO intel_items (
         ioc_row_id, ioc_id, indicator_value_lower, indicator_value, feed_name, flat_json
       ) VALUES (?, ?, ?, ?, ?, ?)`,
    );
    try {
      let iocSeq = 0;
      const intelRows: string[] = [];
      streamJsonlLines(pack.intelPath, (line) => {
        intelRows.push(line);
      });

      const flushIntel = db.transaction((lines: readonly string[]) => {
        for (const line of lines) {
          const doc = JSON.parse(line) as Record<string, unknown>;
          if (typeof doc.case_id === "string" && doc.case_id !== pack.caseId) {
            continue;
          }
          iocSeq += 1;
          const flat = flattenFields(doc, INTEL_FIELDS);
          const iocId =
            typeof flat.id === "string" && flat.id.length > 0
              ? flat.id
              : `ioc-${String(iocSeq).padStart(5, "0")}`;
          flat.id = iocId;
          const indVal = typeof flat["indicator.value"] === "string" ? flat["indicator.value"] : "";
          const feedName =
            typeof flat["threat.feed.name"] === "string" ? flat["threat.feed.name"] : "";
          if (!indVal) continue;
          insertIntel.run(
            iocSeq,
            iocId,
            indVal.toLowerCase(),
            indVal,
            feedName,
            JSON.stringify(flat),
          );
        }
      });
      flushIntel(intelRows);
    } finally {
      insertIntel.finalize();
    }
  }

  createEventAndIntelIndexes(db);
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function checkCleanText(value: string | undefined, maxLen: number, errorCode: "invalid_query" | "invalid_arguments" = "invalid_query"): string {
  const s = value ?? "";
  if (s.length > maxLen) {
    throwDataPlaneError(400, errorCode, `Text exceeds ${maxLen} characters`);
  }
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 32 || c === 127) {
      throwDataPlaneError(400, errorCode, "Control characters are not allowed");
    }
  }
  return s;
}

function parseFieldList(
  rawFields: string | undefined,
  defaultList: readonly string[],
  isAllowed: (field: string) => boolean,
  maxFields = 40,
): string[] {
  if (rawFields === undefined || rawFields === null) {
    return [...defaultList];
  }
  if (typeof rawFields !== "string" || rawFields.length > 2600) {
    throwDataPlaneError(400, "invalid_field_list", "Invalid fields list");
  }
  const items = rawFields.split(",").map((s) => s.trim());
  if (
    items.length === 0 ||
    items.length > maxFields ||
    items.some((s) => s.length === 0) ||
    new Set(items).size !== items.length
  ) {
    throwDataPlaneError(400, "invalid_field_list", "Duplicate, empty, or oversized field list");
  }
  for (const item of items) {
    if (!isAllowed(item)) {
      throwDataPlaneError(400, "field_not_allowed", `Field '${item}' is not allowlisted`);
    }
  }
  return items;
}

function encodeEmbeddedCursor(tsNs: bigint, eventId: string): string {
  const json = JSON.stringify([tsNs.toString(), eventId]);
  return Buffer.from(json, "utf8").toString("base64url");
}

function decodeEmbeddedCursor(token: string): { tsNs: bigint; eventId: string } {
  if (typeof token !== "string" || !/^[A-Za-z0-9_-]{1,400}$/.test(token)) {
    throwDataPlaneError(400, "invalid_query", "Invalid pagination cursor");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(token, "base64url").toString("utf8"));
  } catch {
    throwDataPlaneError(400, "invalid_query", "Malformed pagination cursor");
  }
  if (!Array.isArray(parsed) || parsed.length !== 2) {
    throwDataPlaneError(400, "invalid_query", "Invalid pagination cursor payload");
  }
  const [rawTs, rawId] = parsed;
  if (
    (typeof rawTs !== "string" && typeof rawTs !== "number") ||
    typeof rawId !== "string" ||
    rawId.length === 0 ||
    rawId.length > 128
  ) {
    throwDataPlaneError(400, "invalid_query", "Invalid pagination cursor types");
  }
  try {
    const tsNs = typeof rawTs === "number" ? BigInt(Math.trunc(rawTs)) : BigInt(rawTs);
    return { tsNs, eventId: rawId };
  } catch {
    throwDataPlaneError(400, "invalid_query", "Invalid cursor timestamp");
  }
}

// ============================================================================
// Watch Browser Policy (`browser_policy.py` port for CDP / Local Watch Guard)
// ============================================================================

export interface WatchScope {
  readonly caseId: string;
  readonly labOrigin: string;
  readonly arkimeOrigin: string;
  readonly kibanaOrigin?: string | null;
  readonly startSec: number;
  readonly stopSec: number;
}

export interface WatchVerdict {
  readonly block: string | null;
  readonly url?: string;
  readonly body?: string;
  readonly expression?: string;
}

const ARKIME_DENIED_PATH_RE =
  /delete|scrub|tags|\/users\b|settings|hunt|send|pcap|\/raw|packets|upload|csv|entire|bodyhash|\/session\/|\/files|\/history|\/es(?:admin|indices|shards|tasks|recovery|nodes)|\/parliament|\/cyberchef|\/notifier|\/cron|\/shortcut|\/lookup|\/reindex/i;

const ARKIME_SEARCH_PREFIXES = [
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

function extractCleanOrigin(rawUrl: string): string | null {
  try {
    const u = new URL(rawUrl);
    if ((u.protocol !== "http:" && u.protocol !== "https:") || !u.hostname || u.username || u.password) {
      return null;
    }
    const port = u.port ? Number(u.port) : u.protocol === "https:" ? 443 : 80;
    return `${u.protocol}//${u.hostname}:${port}`;
  } catch {
    return null;
  }
}

const ARKIME_SEARCH_KEYS = ["expression", "date", "startTime", "stopTime"] as const;

function parseArkimeSeconds(value: unknown): number | null {
  const str =
    (typeof value === "string" || typeof value === "number") && typeof value !== "boolean"
      ? String(value)
      : "";
  return /^[0-9]{1,12}$/.test(str) ? Number.parseInt(str, 10) : null;
}

function clampArkimeWindow(
  scope: WatchScope,
  rawStart: unknown,
  rawStop: unknown,
): [number, number] {
  const start = parseArkimeSeconds(rawStart);
  const stop = parseArkimeSeconds(rawStop);
  if (start !== null && stop !== null) {
    const clampedStart = Math.max(start, scope.startSec);
    const clampedStop = Math.min(stop, scope.stopSec);
    if (clampedStart < clampedStop) {
      return [clampedStart, clampedStop];
    }
  }
  return [scope.startSec, scope.stopSec];
}

function scopeArkimeFields(
  scope: WatchScope,
  values: Readonly<Record<string, unknown>>,
): { expression: string; startTime: number; stopTime: number } | { block: string } {
  const rawExpr = values.expression === undefined || values.expression === null ? "" : values.expression;
  if (typeof rawExpr !== "string") {
    return { block: "arkime_expression_rejected" };
  }
  let cleanExpr: string;
  try {
    cleanExpr = checkArkimeBalancedExpression(rawExpr);
  } catch {
    return { block: "arkime_expression_rejected" };
  }
  const tag = `tags == "case:${scope.caseId}"`;
  const scopedExpr = cleanExpr ? `(${cleanExpr}) && ${tag}` : tag;
  const [startTime, stopTime] = clampArkimeWindow(scope, values.startTime, values.stopTime);
  return { expression: scopedExpr, startTime, stopTime };
}

function scopeArkimePairs(
  scope: WatchScope,
  pairs: ReadonlyArray<readonly [string, string]>,
): { pairs: Array<[string, string]>; expression: string } | { block: string } {
  for (const key of ARKIME_SEARCH_KEYS) {
    let count = 0;
    for (const [name] of pairs) {
      if (name === key) count += 1;
    }
    if (count > 1) {
      return { block: "arkime_ambiguous_search" };
    }
  }
  const dict: Record<string, unknown> = {};
  for (const [name, value] of pairs) {
    dict[name] = value;
  }
  const scoped = scopeArkimeFields(scope, dict);
  if ("block" in scoped) {
    return scoped;
  }
  const rest: Array<[string, string]> = [];
  for (const [name, value] of pairs) {
    if (!(ARKIME_SEARCH_KEYS as readonly string[]).includes(name)) {
      rest.push([name, value]);
    }
  }
  rest.push(
    ["expression", scoped.expression],
    ["startTime", String(scoped.startTime)],
    ["stopTime", String(scoped.stopTime)],
  );
  return { pairs: rest, expression: scoped.expression };
}

function scopeArkimePostBody(
  scope: WatchScope,
  body: string,
): { body: string; expression: string } | { block: string } {
  const trimmed = body.trimStart();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(body);
    } catch {
      return { block: "arkime_body_rejected" };
    }
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      return { block: "arkime_body_rejected" };
    }
    const values = parsed as Record<string, unknown>;
    const scoped = scopeArkimeFields(scope, values);
    if ("block" in scoped) {
      return scoped;
    }
    const rest: Record<string, unknown> = {};
    for (const [name, value] of Object.entries(values)) {
      if (!(ARKIME_SEARCH_KEYS as readonly string[]).includes(name)) {
        rest[name] = value;
      }
    }
    return {
      body: JSON.stringify({
        ...rest,
        expression: scoped.expression,
        startTime: scoped.startTime,
        stopTime: scoped.stopTime,
      }),
      expression: scoped.expression,
    };
  }

  const formParams = new URLSearchParams(body);
  const rawPairs = [...formParams.entries()] as Array<[string, string]>;
  const scopedPairs = scopeArkimePairs(scope, rawPairs);
  if ("block" in scopedPairs) {
    return scopedPairs;
  }
  const encoded = new URLSearchParams(scopedPairs.pairs).toString();
  return { body: encoded, expression: scopedPairs.expression };
}

const KIBANA_INDEX = "hunt-lab-case-events";
const KIBANA_STATIC_RE =
  /^\/(?:bootstrap\.js|[0-9a-f]{12}\/(?:bundles|ui)\/[\w@%+.,~/-]+|translations\/[0-9a-f]{12}\/[A-Za-z-]+\.json)$/;
const KIBANA_GET_READS_RE =
  /^\/(?:app\/discover|api\/(?:licensing\/info|banners\/info|spaces\/space|alerting\/rule_types)|internal\/(?:spaces\/_active_space|security\/(?:me|session|user_profile)|core\/pricing|fields_metadata|data_views\/has_(?:data_views|es_data)))$/;
const KIBANA_POST_READS_RE = /^\/api\/core\/capabilities$/;
const KIBANA_CONTENT_RE = /^\/api\/content_management\/rpc\/(?:get|search|mSearch|bulkGet)$/;
const KIBANA_SEARCH_STRATEGIES: ReadonlySet<string> = new Set(["ese", "es"]);
const KIBANA_SEARCH_KEYS: ReadonlySet<string> = new Set([
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

function parseKibanaJsonBody(
  body: string | null,
): Record<string, unknown> | { block: string } {
  if (body === null) {
    return { block: "kibana_body_unavailable" };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return { block: "kibana_body_rejected" };
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { block: "kibana_body_rejected" };
  }
  return parsed as Record<string, unknown>;
}

function decideKibanaWatchRequest(
  scope: WatchScope,
  upperMethod: string,
  u: URL,
  body: string | null,
): WatchVerdict {
  const pathname = u.pathname;
  if (upperMethod === "GET" && KIBANA_STATIC_RE.test(pathname)) {
    return { block: null };
  }
  if (upperMethod === "GET" && KIBANA_GET_READS_RE.test(pathname)) {
    return { block: null };
  }
  if (upperMethod === "POST" && KIBANA_POST_READS_RE.test(pathname)) {
    return { block: null };
  }
  if (
    (upperMethod === "GET" && pathname === "/internal/data_views/fields") ||
    (upperMethod === "POST" && pathname === "/internal/data_views/_fields_for_wildcard")
  ) {
    const patterns = u.searchParams.getAll("pattern");
    return patterns.length === 1 && patterns[0] === KIBANA_INDEX
      ? { block: null }
      : { block: "kibana_index_denied" };
  }
  if (upperMethod !== "POST") {
    return { block: "kibana_route_denied" };
  }
  if (pathname === "/internal/bsearch") {
    const values = parseKibanaJsonBody(body);
    if ("block" in values && Object.keys(values).length === 1 && typeof values.block === "string") {
      return { block: values.block };
    }
    const doc = values as Record<string, unknown>;
    const batch = doc.batch;
    if (!Array.isArray(batch) || batch.length === 0) {
      return { block: "kibana_body_rejected" };
    }
    for (const item of batch) {
      if (item === null || typeof item !== "object" || Array.isArray(item)) {
        return { block: "kibana_search_denied" };
      }
      const rec = item as Record<string, unknown>;
      const opts = rec.options;
      if (
        opts === null ||
        typeof opts !== "object" ||
        Array.isArray(opts) ||
        !KIBANA_SEARCH_STRATEGIES.has(String((opts as Record<string, unknown>).strategy ?? ""))
      ) {
        return { block: "kibana_search_denied" };
      }
      const reqObj = rec.request;
      const params =
        reqObj !== null && typeof reqObj === "object" && !Array.isArray(reqObj)
          ? (reqObj as Record<string, unknown>).params
          : null;
      if (
        params === null ||
        typeof params !== "object" ||
        Array.isArray(params) ||
        (params as Record<string, unknown>).index !== KIBANA_INDEX
      ) {
        return { block: "kibana_index_denied" };
      }
      const paramsRec = params as Record<string, unknown>;
      if (paramsRec.body === undefined) {
        paramsRec.body = {};
      }
      const search = paramsRec.body;
      if (search === null || typeof search !== "object" || Array.isArray(search)) {
        return { block: "kibana_search_denied" };
      }
      const searchRec = search as Record<string, unknown>;
      for (const k of Object.keys(searchRec)) {
        if (!KIBANA_SEARCH_KEYS.has(k)) {
          return { block: "kibana_search_denied" };
        }
      }
      const existingQuery = searchRec.query;
      searchRec.query = {
        bool: {
          must: existingQuery ? [existingQuery] : [],
          filter: [
            {
              range: {
                "@timestamp": {
                  gte: scope.startSec * 1000,
                  lt: scope.stopSec * 1000,
                  format: "epoch_millis",
                },
              },
            },
          ],
        },
      };
    }
    return { block: null, body: JSON.stringify(doc) };
  }
  if (pathname === `/internal/kibana/suggestions/values/${KIBANA_INDEX}`) {
    const values = parseKibanaJsonBody(body);
    if ("block" in values && Object.keys(values).length === 1 && typeof values.block === "string") {
      return { block: values.block };
    }
    return {
      block: null,
      body: JSON.stringify({ ...(values as Record<string, unknown>), method: "terms_agg" }),
    };
  }
  if (KIBANA_CONTENT_RE.test(pathname)) {
    const values = parseKibanaJsonBody(body);
    if ("block" in values && Object.keys(values).length === 1 && typeof values.block === "string") {
      return { block: values.block };
    }
    return (values as Record<string, unknown>).contentTypeId === "index-pattern"
      ? { block: null }
      : { block: "kibana_route_denied" };
  }
  return { block: "kibana_route_denied" };
}

export function decideWatchRequest(
  scope: WatchScope,
  method: string,
  rawUrl: string,
  body: string | null = "",
): WatchVerdict {
  const upperMethod = method.toUpperCase();
  const srcOrigin = extractCleanOrigin(rawUrl);
  if (!srcOrigin) {
    return { block: "origin_not_lab" };
  }
  if (srcOrigin === scope.labOrigin) {
    return upperMethod === "GET" ? { block: null } : { block: "lab_read_only" };
  }
  if (scope.kibanaOrigin && srcOrigin === scope.kibanaOrigin) {
    return decideKibanaWatchRequest(scope, upperMethod, new URL(rawUrl), body);
  }
  if (srcOrigin !== scope.arkimeOrigin) {
    return { block: "origin_not_lab" };
  }

  const u = new URL(rawUrl);
  let decodedPath: string;
  try {
    decodedPath = decodeURIComponent(u.pathname);
  } catch {
    return { block: "arkime_route_denied" };
  }
  if (ARKIME_DENIED_PATH_RE.test(decodedPath)) {
    return { block: "arkime_route_denied" };
  }
  const isSearch = ARKIME_SEARCH_PREFIXES.some((p) => u.pathname.startsWith(p));

  if (
    upperMethod === "GET" &&
    !isSearch &&
    !ARKIME_SEARCH_KEYS.some((k) => u.searchParams.has(k))
  ) {
    return { block: null };
  }
  if (upperMethod !== "GET" && !(upperMethod === "POST" && isSearch)) {
    return { block: "arkime_read_only" };
  }

  const queryPairs = [...u.searchParams.entries()] as Array<[string, string]>;
  const scopedQuery = scopeArkimePairs(scope, queryPairs);
  if ("block" in scopedQuery) {
    return { block: scopedQuery.block };
  }
  u.search = new URLSearchParams(scopedQuery.pairs).toString();

  if (upperMethod === "POST") {
    if (body === null) {
      return { block: "arkime_body_unavailable" };
    }
    if (body.trim().length > 0) {
      const scopedBody = scopeArkimePostBody(scope, body);
      if ("block" in scopedBody) {
        return { block: scopedBody.block };
      }
      return {
        block: null,
        url: u.toString(),
        body: scopedBody.body,
        expression: scopedBody.expression,
      };
    }
  }

  return {
    block: null,
    url: u.toString(),
    expression: scopedQuery.expression,
  };
}

// ============================================================================
// EmbeddedHuntDataPlane Options & Implementation
// ============================================================================

export interface EmbeddedHuntDataPlaneOptions extends ValidateCasePackOptions {
  cacheDir?: string;
  forceRebuild?: boolean;
}

export interface LocalDataPlaneHttpHandle {
  readonly host: "127.0.0.1";
  readonly port: number;
  readonly baseUrl: string;
  readonly instanceId: string;
  readonly secret: string;
  close(): Promise<void>;
}

interface ActivityEntry {
  seq: number;
  time: string;
  profile: string;
  tool: string;
  endpoint: string;
  params: Record<string, string>;
  result_count: number | null;
  total: number | null;
  error: string | null;
}

const WATCH_PAGES = {
  lab_console: { path: "/view", tool: "elastic_search" },
  kibana_discover: { path: "/watch/kibana_discover", tool: "elastic_search" },
  arkime_sessions: { path: "/watch/arkime_sessions", tool: "arkime_sessions" },
  arkime_spiview: { path: "/watch/arkime_spiview", tool: "arkime_unique" },
} as const satisfies Record<WatchPageId, { path: string; tool: DataPlaneToolName }>;

export class EmbeddedHuntDataPlane implements HuntDataPlane {
  public readonly caseId: string;
  public readonly dataOrigin: DataOrigin;
  public readonly syntheticOnly: boolean;
  public readonly hasNetworkCapture: boolean;
  public readonly hasIntelFeed: boolean;
  public readonly cacheDbPath: string;
  public readonly cacheHit: boolean;
  public readonly loadDurationMs: number;

  private readonly pack: ValidatedCasePack;
  private readonly db: Database;
  private readonly startMs: number;
  private readonly endMs: number;
  private localServer: LocalDataPlaneHttpHandle | null = null;
  private readonly watchGrants = new Map<string, {
    page: WatchPageId;
    authorizeTool?: AuthorizeWatchTool;
  }>();
  private closed = false;

  private constructor(params: {
    pack: ValidatedCasePack;
    db: Database;
    cacheDbPath: string;
    cacheHit: boolean;
    loadDurationMs: number;
  }) {
    this.pack = params.pack;
    this.db = params.db;
    this.cacheDbPath = params.cacheDbPath;
    this.cacheHit = params.cacheHit;
    this.loadDurationMs = params.loadDurationMs;

    this.caseId = params.pack.caseId;
    this.dataOrigin = params.pack.dataOrigin;
    this.syntheticOnly = params.pack.syntheticOnly;
    this.hasNetworkCapture = params.pack.networkCapture === "present";
    this.hasIntelFeed = params.pack.intelPath !== null;
    this.startMs = epochMillisFromNs(params.pack.startNs);
    this.endMs = epochMillisFromNs(params.pack.endNs);
  }

  /**
   * Opens a case directory or `case.json` asynchronously, indexing PCAPs in a Bun `Worker`
   * on cold cache misses and attaching `{ readonly: true }` in `<20ms` on warm cache hits.
   */
  public static async open(
    caseDirOrJsonPath: string,
    options: EmbeddedHuntDataPlaneOptions = {},
  ): Promise<EmbeddedHuntDataPlane> {
    const t0 = performance.now();
    const pack = validateCasePack(caseDirOrJsonPath, options);
    const cacheDir = options.cacheDir
      ? resolveRuntimeDir(options.cacheDir).rootDir
      : path.join(resolveRuntimeDir().rootDir, "case-cache");
    fs.mkdirSync(cacheDir, { recursive: true });

    const statFp = computeCaseStatFingerprint(pack);
    const fastTarget = !options.forceRebuild
      ? tryReadFastCacheTarget(cacheDir, pack, statFp)
      : null;

    let snapHash: string;
    let cacheDbPath: string;
    let cacheHit = false;

    if (fastTarget && EmbeddedHuntDataPlane.isCacheComplete(fastTarget.cacheDbPath)) {
      snapHash = fastTarget.snapHash;
      cacheDbPath = fastTarget.cacheDbPath;
      cacheHit = true;
    } else {
      snapHash = computeCaseSnapshotHash(pack);
      cacheDbPath = path.join(cacheDir, `${pack.caseId}-${snapHash}.sqlite`);
      if (!options.forceRebuild && fs.existsSync(cacheDbPath)) {
        cacheHit = EmbeddedHuntDataPlane.isCacheComplete(cacheDbPath);
        if (cacheHit) {
          writeFastCacheTarget(cacheDir, pack, statFp, snapHash);
        }
      }
    }

    if (!cacheHit) {
      const tmpPath = path.join(
        cacheDir,
        `.${pack.caseId}-${snapHash}.building-${process.pid}-${crypto.randomBytes(4).toString("hex")}.sqlite`,
      );
      try {
        const buildDb = new Database(tmpPath, { create: true });
        buildDb.exec("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;");
        ingestEventsAndIntelIntoDb(buildDb, pack);
        buildDb.exec("PRAGMA wal_checkpoint(TRUNCATE);");
        buildDb.close();

        if (pack.pcapPath && pack.networkCapture === "present") {
          await runPcapIndexerWorker({
            dbPath: tmpPath,
            pcapPath: pack.pcapPath,
            caseId: pack.caseId,
            startNs: pack.startNs,
            endNs: pack.endNs,
          });
        }

        const finalizeDb = new Database(tmpPath);
        finalizeDb.exec(`
          INSERT OR REPLACE INTO cache_meta (key, value) VALUES ('ready', '1');
          INSERT OR REPLACE INTO cache_meta (key, value) VALUES ('schema', '${CACHE_SCHEMA_VERSION}');
          PRAGMA wal_checkpoint(TRUNCATE);
          PRAGMA journal_mode = DELETE;
        `);
        finalizeDb.close();

        try {
          fs.renameSync(tmpPath, cacheDbPath);
        } catch (err) {
          if (!fs.existsSync(cacheDbPath)) {
            throw err;
          }
          try {
            fs.rmSync(tmpPath, { force: true });
          } catch {
            // best-effort cleanup
          }
        }
        for (const ext of ["-wal", "-shm"]) {
          try {
            fs.rmSync(`${tmpPath}${ext}`, { force: true });
          } catch {
            // best-effort cleanup
          }
        }
        writeFastCacheTarget(cacheDir, pack, statFp, snapHash);
      } catch (err) {
        for (const ext of ["", "-wal", "-shm"]) {
          try {
            fs.rmSync(`${tmpPath}${ext}`, { force: true });
          } catch {
            // Never mask original indexing error with Windows EBUSY
          }
        }
        throw err;
      }
    }

    const roDb = new Database(cacheDbPath, { readonly: true });
    const loadDurationMs = performance.now() - t0;
    return new EmbeddedHuntDataPlane({
      pack,
      db: roDb,
      cacheDbPath,
      cacheHit,
      loadDurationMs,
    });
  }

  /**
   * Synchronous convenience constructor (uses identical cache format & dissector on current thread).
   */
  public static openSync(
    caseDirOrJsonPath: string,
    options: EmbeddedHuntDataPlaneOptions = {},
  ): EmbeddedHuntDataPlane {
    const t0 = performance.now();
    const pack = validateCasePack(caseDirOrJsonPath, options);
    const cacheDir = options.cacheDir
      ? resolveRuntimeDir(options.cacheDir).rootDir
      : path.join(resolveRuntimeDir().rootDir, "case-cache");
    fs.mkdirSync(cacheDir, { recursive: true });

    const statFp = computeCaseStatFingerprint(pack);
    const fastTarget = !options.forceRebuild
      ? tryReadFastCacheTarget(cacheDir, pack, statFp)
      : null;

    let snapHash: string;
    let cacheDbPath: string;
    let cacheHit = false;

    if (fastTarget && EmbeddedHuntDataPlane.isCacheComplete(fastTarget.cacheDbPath)) {
      snapHash = fastTarget.snapHash;
      cacheDbPath = fastTarget.cacheDbPath;
      cacheHit = true;
    } else {
      snapHash = computeCaseSnapshotHash(pack);
      cacheDbPath = path.join(cacheDir, `${pack.caseId}-${snapHash}.sqlite`);
      if (!options.forceRebuild && fs.existsSync(cacheDbPath)) {
        cacheHit = EmbeddedHuntDataPlane.isCacheComplete(cacheDbPath);
        if (cacheHit) {
          writeFastCacheTarget(cacheDir, pack, statFp, snapHash);
        }
      }
    }

    if (!cacheHit) {
      const tmpPath = path.join(
        cacheDir,
        `.${pack.caseId}-${snapHash}.sync-${process.pid}-${crypto.randomBytes(4).toString("hex")}.sqlite`,
      );
      try {
        const buildDb = new Database(tmpPath, { create: true });
        buildDb.exec("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;");
        ingestEventsAndIntelIntoDb(buildDb, pack);
        if (pack.pcapPath && pack.networkCapture === "present") {
          indexPcapIntoDatabase(buildDb, pack.pcapPath, pack.caseId, pack.startNs, pack.endNs);
        }
        buildDb.exec(`
          INSERT OR REPLACE INTO cache_meta (key, value) VALUES ('ready', '1');
          INSERT OR REPLACE INTO cache_meta (key, value) VALUES ('schema', '${CACHE_SCHEMA_VERSION}');
          PRAGMA wal_checkpoint(TRUNCATE);
          PRAGMA journal_mode = DELETE;
        `);
        buildDb.close();

        fs.renameSync(tmpPath, cacheDbPath);
        for (const ext of ["-wal", "-shm"]) {
          try {
            fs.rmSync(`${tmpPath}${ext}`, { force: true });
          } catch {
            // best-effort cleanup
          }
        }
        writeFastCacheTarget(cacheDir, pack, statFp, snapHash);
      } catch (err) {
        for (const ext of ["", "-wal", "-shm"]) {
          try {
            fs.rmSync(`${tmpPath}${ext}`, { force: true });
          } catch {
            // Never mask original indexing error
          }
        }
        throw err;
      }
    }

    const roDb = new Database(cacheDbPath, { readonly: true });
    const loadDurationMs = performance.now() - t0;
    return new EmbeddedHuntDataPlane({
      pack,
      db: roDb,
      cacheDbPath,
      cacheHit,
      loadDurationMs,
    });
  }

  private static isCacheComplete(dbPath: string): boolean {
    let checkDb: Database | null = null;
    try {
      checkDb = new Database(dbPath, { readonly: true });
      const row = checkDb
        .query("SELECT value FROM cache_meta WHERE key = 'ready'")
        .get() as { value: string } | null;
      if (row?.value !== "1") {
        return false;
      }
      const vocabRow = checkDb
        .query("SELECT 1 FROM sqlite_master WHERE name = 'events_fts_vocab'")
        .get();
      return vocabRow !== null;
    } catch {
      return false;
    } finally {
      if (checkDb) {
        try {
          checkDb.close();
        } catch {
          // ignore
        }
      }
    }
  }

  private assertOpen(): void {
    if (this.closed) {
      throwDataPlaneError(503, "backend_not_ready", "EmbeddedHuntDataPlane is closed");
    }
  }

  private assertCaseParam(caseIdParam: string | undefined): void {
    if (caseIdParam !== undefined && caseIdParam !== this.caseId) {
      throwDataPlaneError(
        400,
        "case_mismatch",
        `Expected case_id '${this.caseId}', got '${caseIdParam}'`,
      );
    }
  }

  private requireCapture(): void {
    if (!this.hasNetworkCapture) {
      throwDataPlaneError(
        400,
        "no_network_capture",
        `Case '${this.caseId}' ships no network packet capture`,
      );
    }
  }

  private loadEventSourceDoc(docId: number): Record<string, unknown> {
    const row = this.db
      .query("SELECT raw_json_zst FROM event_blobs WHERE doc_id = ?")
      .get(docId) as { raw_json_zst: Uint8Array } | null;
    if (!row) {
      return {};
    }
    const rawBytes = Bun.zstdDecompressSync(row.raw_json_zst);
    return JSON.parse(Buffer.from(rawBytes).toString("utf8")) as Record<string, unknown>;
  }

  private buildScopedEventWhere(q: string | undefined, hostFilter?: string): {
    whereSql: string;
    params: SqlParam[];
  } {
    const compiled = compileLuceneQueryString(q ?? "");
    const clauses: string[] = ["e.ts_ns >= ?", "e.ts_ns < ?"];
    const params: SqlParam[] = [this.pack.startNs, this.pack.endNs];

    if (this.pack.hosts && this.pack.hosts.length > 0) {
      const ph = this.pack.hosts.map(() => "?").join(", ");
      clauses.push(`e.host_name IN (${ph})`);
      for (const h of this.pack.hosts) params.push(h);
    }

    if (hostFilter && hostFilter.length > 0) {
      clauses.push("e.host_name = ?");
      params.push(hostFilter);
    }

    if (compiled.whereSql !== "1 = 1") {
      clauses.push(`(${compiled.whereSql})`);
      params.push(...compiled.params);
    }

    return {
      whereSql: clauses.join(" AND "),
      params,
    };
  }

  public getCaseInfo(): Record<string, unknown> {
    this.assertOpen();
    return structuredClone(this.pack.rawCaseObject);
  }

  /**
   * The validated case as the shared `CaseMetadata` contract. `sources` lists the evidence
   * artifacts this data plane actually serves (the source ids a handoff may cite).
   */
  public describeCase(): CaseMetadata {
    this.assertOpen();
    const relArtifact = (absPath: string): string =>
      path.relative(this.pack.caseDir, absPath).split(path.sep).join("/");
    const sources = [this.pack.eventsPath, this.pack.intelPath, this.pack.pcapPath]
      .filter((p): p is string => p !== null)
      .map(relArtifact);
    const rawTitle = this.pack.rawCaseObject.title;
    const title =
      typeof rawTitle === "string" && rawTitle.trim().length > 0
        ? rawTitle.trim()
        : this.pack.question.trim() || this.caseId;
    return {
      case_id: this.caseId,
      title,
      data_origin: this.dataOrigin,
      synthetic_only: this.syntheticOnly,
      time_window: {
        start_iso: this.pack.startInclusiveIso,
        end_iso: this.pack.endExclusiveIso,
      },
      sources,
      ...(this.pack.pcapPath !== null && this.hasNetworkCapture
        ? { pcap_relpath: relArtifact(this.pack.pcapPath) }
        : {}),
    };
  }

  public elasticSearch(params: ElasticSearchParams): ElasticSearchResult {
    this.assertOpen();
    this.assertCaseParam(params.case_id);

    const size = coerceBoundedInt(params.size, 50, 1, MAX_RESULT, "invalid_query");
    const sort = params.sort ?? "asc";
    if (sort !== "asc" && sort !== "desc") {
      throwDataPlaneError(400, "invalid_query", "sort must be 'asc' or 'desc'");
    }

    const requestedFields = parseFieldList(params.fields, DEFAULT_FIELDS, isAllowedSearchField);
    const fields = [
      ...ALWAYS_FIELDS,
      ...requestedFields.filter((f) => !(ALWAYS_FIELDS as readonly string[]).includes(f)),
    ];

    const scoped = this.buildScopedEventWhere(params.q);

    const totalRow = this.db
      .query(`SELECT COUNT(*) AS cnt FROM events_hot e WHERE ${scoped.whereSql}`)
      .get(...scoped.params) as { cnt: number };
    const total = totalRow.cnt;

    const pageParams: SqlParam[] = [...scoped.params];
    let cursorClause = "";
    if (params.after !== undefined) {
      const cursor = decodeEmbeddedCursor(params.after);
      if (sort === "asc") {
        cursorClause = " AND (e.ts_ns > ? OR (e.ts_ns = ? AND e.event_id > ?))";
      } else {
        cursorClause = " AND (e.ts_ns < ? OR (e.ts_ns = ? AND e.event_id < ?))";
      }
      pageParams.push(cursor.tsNs, cursor.tsNs, cursor.eventId);
    }

    const orderSql =
      sort === "asc"
        ? "ORDER BY e.ts_ns ASC, e.event_id ASC"
        : "ORDER BY e.ts_ns DESC, e.event_id DESC";
    pageParams.push(size);

    const rows = this.db
      .query(
        `SELECT e.doc_id, CAST(e.ts_ns AS TEXT) AS ts_ns_str, e.event_id
         FROM events_hot e
         WHERE ${scoped.whereSql}${cursorClause}
         ${orderSql}
         LIMIT ?`,
      )
      .all(...pageParams) as Array<{ doc_id: number; ts_ns_str: string; event_id: string }>;

    const hits = rows.map((r) => {
      const doc = this.loadEventSourceDoc(r.doc_id);
      return flattenFields(doc, fields);
    });

    const lastRow = rows.length === size ? rows[rows.length - 1] : undefined;
    const nextAfter = lastRow
      ? encodeEmbeddedCursor(BigInt(lastRow.ts_ns_str), lastRow.event_id)
      : null;

    return budgetElasticSearchResult({
      case_id: this.caseId,
      total,
      total_relation: "eq",
      returned: hits.length,
      hits,
      next_after: nextAfter,
    }, (count) => {
      const last = rows[count - 1]!;
      return encodeEmbeddedCursor(BigInt(last.ts_ns_str), last.event_id);
    });
  }

  public elasticAggregate(params: ElasticAggregateParams): ElasticAggregateResult {
    this.assertOpen();
    this.assertCaseParam(params.case_id);

    const field = checkCleanText(params.field, 64, "invalid_query");
    if (!field) {
      throwDataPlaneError(400, "field_not_allowed", "Missing aggregation field");
    }
    const size = coerceBoundedInt(params.size, 20, 1, 100, "invalid_query");

    if (field === "@timestamp") {
      const interval: HistogramInterval = (params.interval ?? "1h") as HistogramInterval;
      if (!Object.prototype.hasOwnProperty.call(INTERVALS, interval)) {
        throwDataPlaneError(400, "invalid_query", "interval must be 1m, 5m, 15m, or 1h");
      }
      const intervalSec = INTERVALS[interval];
      const windowSpanSec = (this.endMs - this.startMs) / 1000;
      if (Math.ceil(windowSpanSec / intervalSec) > MAX_HISTOGRAM_BUCKETS) {
        throwDataPlaneError(400, "invalid_query", "interval too fine for the case window");
      }

      const scoped = this.buildScopedEventWhere(params.q);
      const totalRow = this.db
        .query(`SELECT COUNT(*) AS cnt FROM events_hot e WHERE ${scoped.whereSql}`)
        .get(...scoped.params) as { cnt: number };

      const bucketNs = BigInt(intervalSec) * 1_000_000_000n;
      const histRows = this.db
        .query(
          `SELECT CAST((e.ts_ns / ?) * ? AS TEXT) AS bucket_start_ns_str,
                  COUNT(*) AS doc_count,
                  MIN(printf('%020d|%s', e.ts_ns, e.event_id)) AS earliest_packed
           FROM events_hot e
           WHERE ${scoped.whereSql}
           GROUP BY (e.ts_ns / ?) * ?
           HAVING doc_count >= 1
           ORDER BY (e.ts_ns / ?) * ? ASC`,
        )
        .all(
          bucketNs,
          bucketNs,
          ...scoped.params,
          bucketNs,
          bucketNs,
          bucketNs,
          bucketNs,
        ) as Array<{
        bucket_start_ns_str: string;
        doc_count: number;
        earliest_packed: string | null;
      }>;

      const buckets: ElasticAggregateBucket[] = histRows.map((hr) => {
        const epochMs = Number(BigInt(hr.bucket_start_ns_str) / 1_000_000n);
        const sampleEventId = hr.earliest_packed
          ? hr.earliest_packed.slice(hr.earliest_packed.indexOf("|") + 1)
          : null;
        return {
          key: formatIsoSecondsZ(epochMs),
          count: hr.doc_count,
          sample_event_id: sampleEventId,
        };
      });

      return {
        case_id: this.caseId,
        field,
        total: totalRow.cnt,
        buckets,
      };
    }

    if (!isAllowedAggField(field)) {
      throwDataPlaneError(400, "field_not_allowed", `Field '${field}' is not aggregatable`);
    }
    if (params.interval !== undefined) {
      throwDataPlaneError(400, "invalid_query", "interval applies only to @timestamp");
    }

    const scoped = this.buildScopedEventWhere(params.q);
    const totalRow = this.db
      .query(`SELECT COUNT(*) AS cnt FROM events_hot e WHERE ${scoped.whereSql}`)
      .get(...scoped.params) as { cnt: number };

    const termRows = this.db
      .query(
        `SELECT kv.val_str AS bucket_key,
                COUNT(DISTINCT e.doc_id) AS doc_count,
                MIN(printf('%020d|%s', e.ts_ns, e.event_id)) AS earliest_packed
         FROM events_hot e
         JOIN event_kv kv ON kv.doc_id = e.doc_id AND kv.field = ?
         WHERE ${scoped.whereSql}
         GROUP BY kv.val_str
         ORDER BY doc_count DESC, kv.val_str ASC`,
      )
      .all(field, ...scoped.params) as Array<{
      bucket_key: string;
      doc_count: number;
      earliest_packed: string | null;
    }>;

    const topRows = termRows.slice(0, size);
    const otherCount = termRows
      .slice(size)
      .reduce((acc, r) => acc + r.doc_count, 0);

    const buckets: ElasticAggregateBucket[] = topRows.map((tr) => ({
      key: tr.bucket_key,
      count: tr.doc_count,
      sample_event_id: tr.earliest_packed
        ? tr.earliest_packed.slice(tr.earliest_packed.indexOf("|") + 1)
        : null,
    }));

    return {
      case_id: this.caseId,
      field,
      total: totalRow.cnt,
      buckets,
      other: otherCount,
    };
  }

  public detectionTest(params: DetectionTestParams): DetectionTestResult {
    this.assertOpen();
    this.assertCaseParam(params.case_id);

    const name = checkCleanText(params.name, 80, "invalid_query").trim();
    if (!name) {
      throwDataPlaneError(400, "invalid_query", "Detection name is required");
    }
    if (params.q === undefined || params.q === null) {
      throwDataPlaneError(400, "invalid_query", "Detection query q is required");
    }

    const scoped = this.buildScopedEventWhere(params.q);
    const stats = this.db
      .query(
        `SELECT COUNT(*) AS cnt,
                CAST(MIN(e.ts_ns) AS TEXT) AS min_ns_str,
                CAST(MAX(e.ts_ns) AS TEXT) AS max_ns_str
         FROM events_hot e
         WHERE ${scoped.whereSql}`,
      )
      .get(...scoped.params) as {
      cnt: number;
      min_ns_str: string | null;
      max_ns_str: string | null;
    };

    const hostRows = this.db
      .query(
        `SELECT e.host_name AS host_key, COUNT(*) AS doc_count
         FROM events_hot e
         WHERE ${scoped.whereSql} AND e.host_name IS NOT NULL
         GROUP BY e.host_name
         ORDER BY doc_count DESC, e.host_name ASC
         LIMIT 20`,
      )
      .all(...scoped.params) as Array<{ host_key: string; doc_count: number }>;

    const sampleDocs = this.db
      .query(
        `SELECT e.doc_id
         FROM events_hot e
         WHERE ${scoped.whereSql}
         ORDER BY e.ts_ns ASC, e.event_id ASC
         LIMIT 10`,
      )
      .all(...scoped.params) as Array<{ doc_id: number }>;

    const sample = sampleDocs.map((s) =>
      flattenFields(this.loadEventSourceDoc(s.doc_id), DEFAULT_FIELDS),
    );

    return {
      case_id: this.caseId,
      name,
      total: stats.cnt,
      hosts: hostRows.map((h) => ({ key: h.host_key, count: h.doc_count })),
      first: stats.min_ns_str !== null ? formatNsAsIso(BigInt(stats.min_ns_str)) : null,
      last: stats.max_ns_str !== null ? formatNsAsIso(BigInt(stats.max_ns_str)) : null,
      sample,
    };
  }

  public intelLookup(params: IntelLookupParams): IntelLookupResult {
    this.assertOpen();
    this.assertCaseParam(params.case_id);

    const rawValues = checkCleanText(params.values, 50 * 201, "invalid_query");
    if (!rawValues) {
      throwDataPlaneError(400, "invalid_query", "values parameter is required");
    }

    const requested: string[] = [];
    for (const part of rawValues.split(",")) {
      const trimmed = part.trim();
      if (!trimmed || trimmed.length > 200) {
        throwDataPlaneError(400, "invalid_query", "Each indicator value must be 1..200 characters");
      }
      if (!requested.includes(trimmed)) {
        requested.push(trimmed);
      }
    }
    if (requested.length === 0 || requested.length > 50) {
      throwDataPlaneError(400, "invalid_query", "At most 50 indicator values allowed");
    }

    const lowers = [...new Set(requested.map((r) => r.toLowerCase()))];
    const placeholders = lowers.map(() => "?").join(", ");
    const rows = this.db
      .query(
        `SELECT indicator_value_lower, flat_json
         FROM intel_items
         WHERE indicator_value_lower IN (${placeholders})
         ORDER BY indicator_value ASC, feed_name ASC
         LIMIT 500`,
      )
      .all(...lowers) as Array<{ indicator_value_lower: string; flat_json: string }>;

    const foundLower = new Set<string>();
    const matches = rows.map((r) => {
      foundLower.add(r.indicator_value_lower);
      return JSON.parse(r.flat_json) as Record<string, unknown>;
    });

    // Preserve exact caller casing in unmatched!
    const unmatched = requested.filter((item) => !foundLower.has(item.toLowerCase()));

    return {
      case_id: this.caseId,
      matches,
      unmatched,
    };
  }

  public arkimeSessions(params: ArkimeSessionsParams): ArkimeSessionsResult {
    this.assertOpen();
    this.assertCaseParam(params.case_id);
    this.requireCapture();

    const length = coerceBoundedInt(params.length, 50, 1, MAX_RESULT, "invalid_query");
    const start = coerceBoundedInt(params.start, 0, 0, 10_000, "invalid_query");
    const fields = parseFieldList(params.fields, ARKIME_DEFAULT_FIELDS, (f) =>
      ARKIME_SESSION_SET.has(f),
    );
    const compiled = compileArkimeExpression(params.expression);

    const whereSql = compiled.whereSql;
    const baseParams = compiled.params;

    const countRow = this.db
      .query(`SELECT COUNT(*) AS cnt FROM sessions s WHERE ${whereSql}`)
      .get(...baseParams) as { cnt: number };

    const rows = this.db
      .query(
        `SELECT s.arkime_json
         FROM sessions s
         WHERE ${whereSql}
         ORDER BY s.first_packet_ms ASC, s.session_id ASC
         LIMIT ? OFFSET ?`,
      )
      .all(...baseParams, length, start) as Array<{ arkime_json: string }>;

    const sessions = rows.map((r) =>
      flattenFields(JSON.parse(r.arkime_json) as Record<string, unknown>, fields),
    );

    return {
      case_id: this.caseId,
      recordsFiltered: countRow.cnt,
      returned: sessions.length,
      sessions,
    };
  }

  public arkimeUnique(params: ArkimeUniqueParams): ArkimeUniqueResult {
    this.assertOpen();
    this.assertCaseParam(params.case_id);
    this.requireCapture();

    const field = checkCleanText(params.field, 64, "invalid_query");
    if (!ARKIME_UNIQUE_FIELDS.has(field)) {
      throwDataPlaneError(400, "field_not_allowed", `Arkime unique field '${field}' is not allowed`);
    }

    const rawCounts = params.counts === undefined ? "1" : String(params.counts);
    if (rawCounts !== "0" && rawCounts !== "1") {
      throwDataPlaneError(400, "invalid_query", "counts must be 0 or 1");
    }
    const includeCounts = rawCounts === "1";

    const compiled = compileArkimeExpression(params.expression);
    const whereSql = compiled.whereSql;
    const baseParams = compiled.params;

    const rows = this.db
      .query(
        `SELECT sk.val_str AS val, COUNT(DISTINCT s.session_id) AS cnt
         FROM sessions s
         JOIN session_kv sk ON sk.session_id = s.session_id AND sk.field = ?
         WHERE ${whereSql}
         GROUP BY sk.val_str`,
      )
      .all(field, ...baseParams) as Array<{ val: string; cnt: number }>;

    if (includeCounts) {
      rows.sort((a, b) => b.cnt - a.cnt || (a.val < b.val ? -1 : a.val > b.val ? 1 : 0));
    } else {
      rows.sort((a, b) => (a.val < b.val ? -1 : a.val > b.val ? 1 : 0));
    }

    const truncated = rows.length > MAX_UNIQUE_VALUES;
    const sliced = rows.slice(0, MAX_UNIQUE_VALUES);
    const values = sliced.map((r) =>
      includeCounts ? { value: r.val, count: r.cnt } : { value: r.val },
    );

    return {
      case_id: this.caseId,
      field,
      returned: values.length,
      truncated,
      values,
    };
  }

  public packetFields(params: PacketFieldsParams): PacketFieldsResult {
    this.assertOpen();
    this.assertCaseParam(params.case_id);
    this.requireCapture();

    const length = coerceBoundedInt(params.length, 50, 1, MAX_RESULT, "invalid_query");
    const start = coerceBoundedInt(params.start, 0, 0, MAX_PACKET_START, "invalid_query");
    const requestedFields = parseFieldList(params.fields, PACKET_DEFAULT_FIELDS, (f) =>
      PACKET_ALLOWED_SET.has(f),
    );
    const columns = [
      ...PACKET_ALWAYS_FIELDS,
      ...requestedFields.filter((f) => !(PACKET_ALWAYS_FIELDS as readonly string[]).includes(f)),
    ];

    const compiledFilter = compilePacketDisplayFilter(params.filter);

    const dbRows = this.db
      .query(
        `SELECT p.row_json
         FROM packets p
         WHERE p.ts_ns >= ? AND p.ts_ns < ? AND (${compiledFilter.whereSql})
         ORDER BY p.frame_number ASC
         LIMIT ? OFFSET ?`,
      )
      .all(this.pack.startNs, this.pack.endNs, ...compiledFilter.params, length + 1, start) as Array<{ row_json: string }>;

    const rows: Array<Record<string, unknown>> = [];
    let byteBudget = 0;
    let truncated = false;
    const more = dbRows.length > length;

    for (const r of dbRows.slice(0, length)) {
      byteBudget += Buffer.byteLength(r.row_json, "utf8");
      if (byteBudget > MAX_BACKEND_BYTES) {
        truncated = true;
        break;
      }
      const parsed = JSON.parse(r.row_json) as Record<string, unknown>;
      const projected: Record<string, unknown> = {};
      for (const col of columns) {
        if (parsed[col] !== undefined && parsed[col] !== "") {
          projected[col] = parsed[col];
        }
      }
      rows.push(projected);
    }

    return {
      case_id: this.caseId,
      fields: columns,
      start,
      returned: rows.length,
      more: !truncated && more,
      truncated,
      rows,
    };
  }

  public huntLabQuery(params: HuntLabQueryParams): HuntLabQueryResult {
    this.assertOpen();
    this.assertCaseParam(params.case_id);

    const dataset = params.dataset;
    if (dataset === "case") {
      return this.getCaseInfo();
    }
    if (dataset !== "events" && dataset !== "network") {
      throwDataPlaneError(400, "invalid_dataset", `Unsupported dataset '${String(dataset)}'`);
    }

    const limit = coerceBoundedInt(params.limit, 50, 1, MAX_RESULT, "invalid_pagination");
    const offset = coerceBoundedInt(params.offset, 0, 0, 5_000, "invalid_pagination");
    const q = checkCleanText(params.q, 300, "invalid_query");
    const host = checkCleanText(params.host, 100, "invalid_query");

    if (dataset === "events") {
      const scoped = this.buildScopedEventWhere(q, host || undefined);
      const totalRow = this.db
        .query(`SELECT COUNT(*) AS cnt FROM events_hot e WHERE ${scoped.whereSql}`)
        .get(...scoped.params) as { cnt: number };

      const docRows = this.db
        .query(
          `SELECT e.doc_id
           FROM events_hot e
           WHERE ${scoped.whereSql}
           ORDER BY e.ts_ns ASC, e.event_id ASC
           LIMIT ? OFFSET ?`,
        )
        .all(...scoped.params, limit, offset) as Array<{ doc_id: number }>;

      const records = docRows.map((r) =>
        filterTopLevelFields(this.loadEventSourceDoc(r.doc_id), EVENT_FIELDS),
      );

      return {
        case_id: this.caseId,
        dataset: "events",
        total: totalRow.cnt,
        total_relation: "eq",
        offset,
        limit,
        returned: records.length,
        more: offset + records.length < totalRow.cnt,
        records,
        read_only: true,
      };
    }

    // dataset === "network"
    this.requireCapture();
    const netFilter = compileNetworkDatasetFilter(q, host);
    const whereSql = netFilter.whereSql;
    const sqlParams = netFilter.params;

    const totalRow = this.db
      .query(`SELECT COUNT(*) AS cnt FROM sessions s WHERE ${whereSql}`)
      .get(...sqlParams) as { cnt: number };

    const sessRows = this.db
      .query(
        `SELECT s.network_json
         FROM sessions s
         WHERE ${whereSql}
         ORDER BY s.first_packet_ms ASC, s.session_id ASC
         LIMIT ? OFFSET ?`,
      )
      .all(...sqlParams, limit, offset) as Array<{ network_json: string }>;

    const records = sessRows.map((r) => JSON.parse(r.network_json) as Record<string, unknown>);

    return {
      case_id: this.caseId,
      dataset: "network",
      total: totalRow.cnt,
      total_relation: "eq",
      offset,
      limit,
      returned: records.length,
      more: offset + records.length < totalRow.cnt,
      records,
      read_only: true,
    };
  }

  public renderWatchHtml(
    page: WatchPageId,
    params: { q?: string; host?: string; expression?: string; field?: string },
    consoleKey?: string,
    authorizeTool?: AuthorizeWatchTool,
  ): { status: 200 | 400; title: string; summary: string; returned: number; html: string } {
    authorizeTool?.(WATCH_PAGES[page].tool);
    const originBanner =
      this.dataOrigin === "synthetic"
        ? "Synthetic data only."
        : `${REAL_DATA_ORIGIN_LABELS[this.dataOrigin][0]} (${REAL_DATA_ORIGIN_LABELS[this.dataOrigin][1]}).`;
    try {
      let result: unknown;
      let title: string;
      let summary: string;
      let returned: number;
      if (page === "lab_console" || page === "kibana_discover") {
        const q = checkCleanText(params.q, 300, "invalid_query");
        const host = checkCleanText(params.host, 100, "invalid_query");
        const hostTerm = host ? `host.name:"${host.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"` : "";
        const query = hostTerm && q ? `(${q}) AND ${hostTerm}` : hostTerm || q;
        const res = this.elasticSearch({ q: query, size: 50 });
        result = res;
        title = page === "kibana_discover" ? `Discover — ${this.caseId} events` : "Hermes hunting lab";
        returned = res.returned;
        summary = `${returned} of ${res.total} events`;
      } else if (page === "arkime_sessions") {
        const res = this.arkimeSessions({ expression: params.expression ?? "", length: 50, start: 0 });
        result = res;
        title = `Arkime Sessions — ${this.caseId}`;
        returned = res.returned;
        summary = `${returned} of ${res.recordsFiltered} sessions`;
      } else {
        const field = params.field ?? "host.http";
        const res = this.arkimeUnique({ expression: params.expression ?? "", field, counts: 1 });
        result = res;
        title = `Arkime SPI View (${field}) — ${this.caseId}`;
        returned = res.returned;
        summary = `${returned} distinct values for ${field}`;
      }
      const form = page === "lab_console" || page === "kibana_discover"
        ? `<form action="${WATCH_PAGES[page].path}" method="get"><label for="q">Search</label>` +
          `<input id="q" name="q" size="60" value="${escapeHtml(String(sanitizeToolResult(params.q ?? "")))}">` +
          (consoleKey ? `<input type="hidden" name="key" value="${escapeHtml(consoleKey)}">` : "") +
          `<label for="host">Host</label><input id="host" name="host" value="${escapeHtml(String(sanitizeToolResult(params.host ?? "")))}">` +
          `<button>Search logs</button></form>`
        : "";
      const html =
        `<!doctype html><html><head><meta charset="utf-8"><title>${escapeHtml(title)}</title>` +
        `<style>body{font:15px system-ui;margin:24px}pre{white-space:pre-wrap;overflow-wrap:anywhere}form{display:flex;flex-wrap:wrap;gap:8px;align-items:center}input{max-width:100%;box-sizing:border-box}</style></head><body>` +
        `<h1>${escapeHtml(title)}</h1><p>${escapeHtml(originBanner)} Read-only.</p>` +
        form +
        `<p role="status"><strong>${escapeHtml(summary)}</strong></p>` +
        `<pre>${escapeHtml(fenceToolResult(result))}</pre></body></html>`;
      return { status: 200, title, summary, returned, html };
    } catch (err) {
      const code = extractDataPlaneError(err)?.errorCode ?? "invalid_query";
      const title = "Query refused";
      const summary = `Query refused: ${code}`;
      const html =
        `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title></head><body>` +
        `<p role="alert">${escapeHtml(summary)}</p></body></html>`;
      return { status: 400, title, summary, returned: 0, html };
    }
  }

  public async labBrowser(
    params: LabBrowserParams,
    authorizeTool?: AuthorizeWatchTool,
  ): Promise<LabBrowserResult> {
    this.assertOpen();
    this.assertCaseParam(params.case_id);

    if (!Object.prototype.hasOwnProperty.call(WATCH_PAGES, params.page)) {
      throwDataPlaneError(400, "invalid_arguments", `Invalid Watch page '${String(params.page)}'`);
    }

    const rendered = this.renderWatchHtml(params.page, params, undefined, authorizeTool);
    if (rendered.status !== 200) {
      const code = rendered.summary.replace(/^Query refused:\s*/, "");
      throwDataPlaneError(400, (code as "invalid_query") || "invalid_query", rendered.summary);
    }

    const srv = await this.ensureLocalHttpServer();
    const key = crypto.randomBytes(32).toString("hex");
    this.watchGrants.set(key, { page: params.page, authorizeTool });
    const url = new URL(WATCH_PAGES[params.page].path, srv.baseUrl);
    url.searchParams.set("key", key);
    for (const name of ["q", "host", "expression", "field"] as const) {
      if (params[name] !== undefined) {
        url.searchParams.set(name, params[name]);
      }
    }

    return {
      case_id: this.caseId,
      page: params.page,
      url: url.toString(),
      title: rendered.title,
      summary: rendered.summary,
      returned: rendered.returned,
      blocked_requests: 0,
      html_preview: rendered.html.slice(0, 4096),
    };
  }

  /**
   * Reads the records behind cited ids, with the same case scoping as {@link verifyCitations}
   * (events inside the window and host scope, frames inside the window). Ids that do not resolve,
   * or are malformed, are simply absent from the result. Records are raw case data: callers that
   * show them must scrub them.
   */
  public readCitedRecords(ids: readonly string[]): CitedRecord[] {
    this.assertOpen();
    const records: CitedRecord[] = [];
    const eventScope = this.buildScopedEventWhere(undefined);
    const evtQuery = this.db.query(
      `SELECT e.doc_id, e.ts_iso FROM events_hot e WHERE e.event_id = ? AND ${eventScope.whereSql} LIMIT 1`,
    );
    const iocQuery = this.db.query(
      "SELECT feed_name, indicator_value, flat_json FROM intel_items WHERE ioc_id = ? LIMIT 1",
    );
    const hasPackets =
      this.hasNetworkCapture &&
      this.db
        .query("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'packets'")
        .get() !== null;
    const frameQuery = hasPackets
      ? this.db.query(
          "SELECT CAST(ts_ns AS TEXT) AS ts_ns_str, ws_protocol, row_json FROM packets WHERE frame_number = ? AND ts_ns >= ? AND ts_ns < ? LIMIT 1",
        )
      : null;

    for (const id of [...new Set(ids)]) {
      if (/^evt-[A-Za-z0-9_-]{1,120}$/.test(id)) {
        const row = evtQuery.get(id, ...eventScope.params) as { doc_id: number; ts_iso: string } | null;
        if (!row) continue;
        const doc = this.loadEventSourceDoc(row.doc_id);
        const message = (doc as { message?: unknown }).message;
        const action = ((doc as { event?: { action?: unknown } }).event ?? {}).action;
        records.push({
          id,
          kind: "evt",
          timestamp_iso: row.ts_iso,
          title: typeof message === "string" ? message : typeof action === "string" ? action : id,
          record: doc,
        });
        continue;
      }
      const frameMatch = /^frame-0*([1-9][0-9]{0,9})$/.exec(id);
      if (frameMatch) {
        const row = frameQuery?.get(Number.parseInt(frameMatch[1]!, 10), this.pack.startNs, this.pack.endNs) as
          | { ts_ns_str: string; ws_protocol: string; row_json: string }
          | null
          | undefined;
        if (!row) continue;
        records.push({
          id,
          kind: "frame",
          timestamp_iso: new Date(epochMillisFromNs(BigInt(row.ts_ns_str))).toISOString(),
          title: `${row.ws_protocol} frame ${frameMatch[1]}`,
          record: JSON.parse(row.row_json) as Record<string, unknown>,
        });
        continue;
      }
      if (/^ioc-[A-Za-z0-9_-]{1,120}$/.test(id)) {
        const row = iocQuery.get(id) as { feed_name: string; indicator_value: string; flat_json: string } | null;
        if (!row) continue;
        records.push({
          id,
          kind: "ioc",
          timestamp_iso: null,
          title: `${row.feed_name}: ${row.indicator_value}`,
          record: JSON.parse(row.flat_json) as Record<string, unknown>,
        });
      }
    }
    return records;
  }

  public verifyCitations(citations: readonly string[]): CitationVerificationResult {
    this.assertOpen();

    const eventIds: string[] = [];
    const frameIds: string[] = [];
    const iocIds: string[] = [];
    const unresolved: string[] = [];
    const malformed: string[] = [];

    const eventScope = this.buildScopedEventWhere(undefined);
    const checkEvt = this.db.query(
      `SELECT 1 FROM events_hot e WHERE e.event_id = ? AND ${eventScope.whereSql} LIMIT 1`,
    );
    const checkIoc = this.db.query("SELECT 1 FROM intel_items WHERE ioc_id = ? LIMIT 1");
    const hasPacketsTable =
      this.hasNetworkCapture &&
      this.db
        .query("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'packets'")
        .get() !== null;
    const checkFrame = hasPacketsTable
      ? this.db.query("SELECT 1 FROM packets WHERE frame_number = ? AND ts_ns >= ? AND ts_ns < ? LIMIT 1")
      : null;

    const uniqueCitations = [...new Set(citations)];

    for (const raw of uniqueCitations) {
      if (/^evt-[A-Za-z0-9_-]{1,120}$/.test(raw)) {
        if (checkEvt.get(raw, ...eventScope.params)) {
          eventIds.push(raw);
        } else {
          unresolved.push(raw);
        }
      } else {
        const frameMatch = /^frame-0*([1-9][0-9]{0,9})$/.exec(raw);
        if (frameMatch) {
          const frameNum = Number.parseInt(frameMatch[1]!, 10);
          const canonicalFrame = `frame-${frameNum}`;
          if (checkFrame && checkFrame.get(frameNum, this.pack.startNs, this.pack.endNs)) {
            if (!frameIds.includes(canonicalFrame)) {
              frameIds.push(canonicalFrame);
            }
          } else {
            unresolved.push(raw);
          }
        } else if (/^ioc-[A-Za-z0-9_-]{1,120}$/.test(raw)) {
          if (checkIoc.get(raw)) {
            iocIds.push(raw);
          } else {
            unresolved.push(raw);
          }
        } else {
          malformed.push(raw);
        }
      }
    }

    return {
      allValid: unresolved.length === 0 && malformed.length === 0,
      checkedCount: uniqueCitations.length,
      resolved: { eventIds, frameIds, iocIds },
      unresolved,
      malformed,
    };
  }

  /**
   * Starts (or returns the already bound) loopback-only `127.0.0.1:<ephemeral>` read-only HTTP server
   * implementing DNS-rebinding `Host` guard (`403 host_not_allowed`), `X-Hunt-Lab-Secret` guard
   * (`401 caller_not_authorized`), `X-Hunt-Lab-Instance`, `405 read_only`, JSON routes, and Watch HTML views.
   */
  public async ensureLocalHttpServer(options?: {
    secret?: string;
    instanceId?: string;
  }): Promise<LocalDataPlaneHttpHandle> {
    this.assertOpen();
    if (this.localServer) {
      return this.localServer;
    }

    const secret = options?.secret ?? crypto.randomBytes(32).toString("hex");
    if (!/^[0-9a-f]{64}$/.test(secret)) {
      throw new Error("Lab secret must be 64 lowercase hex characters");
    }
    const instanceId = options?.instanceId ?? crypto.randomBytes(16).toString("hex");
    const secretBuf = Buffer.from(secret, "ascii");

    const activityRing: ActivityEntry[] = [];
    let activitySeq = 0;
    let boundPort = 0;

    const recordActivity = (entry: Omit<ActivityEntry, "seq" | "time">): void => {
      activitySeq += 1;
      activityRing.push({
        seq: activitySeq,
        time: new Date().toISOString(),
        ...entry,
      });
      if (activityRing.length > 500) {
        activityRing.shift();
      }
    };

    const sendResponse = (
      res: http.ServerResponse,
      status: number,
      payload: unknown,
      contentType = "application/json",
    ): void => {
      const bodyStr =
        contentType === "application/json" ? JSON.stringify(payload) : String(payload);
      const bodyBuf = Buffer.from(bodyStr, "utf8");
      res.writeHead(status, {
        "Content-Type": `${contentType}; charset=utf-8`,
        "Content-Length": String(bodyBuf.byteLength),
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Content-Security-Policy":
          "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'",
        "X-Hunt-Lab-Instance": instanceId,
      });
      res.end(bodyBuf);
    };

    const CONSOLE_PATHS = new Set<string>(["/", ...Object.values(WATCH_PAGES).map((page) => page.path)]);

    const server = http.createServer((req, res) => {
      try {
        // 1. Host header check FIRST (defeats DNS rebinding before testing secret or parsing URL!)
        const rawHosts = req.headersDistinct.host ?? (req.headers.host ? [req.headers.host] : []);
        const expectedHost = `127.0.0.1:${boundPort}`;
        if (rawHosts.length !== 1 || rawHosts[0] !== expectedHost) {
          sendResponse(res, 403, { error: "host_not_allowed" });
          return;
        }

        // Extract origin-form path/query safely WITHOUT calling `new URL()` yet
        const rawUrl = typeof req.url === "string" ? req.url : "";
        const isOriginForm =
          rawUrl.startsWith("/") && !rawUrl.startsWith("//") && !rawUrl.includes("#");
        const qIdx = rawUrl.indexOf("?");
        const rawPathname = isOriginForm ? (qIdx === -1 ? rawUrl : rawUrl.slice(0, qIdx)) : "";
        const rawQuery = isOriginForm && qIdx !== -1 ? rawUrl.slice(qIdx + 1) : "";
        const isConsolePath = CONSOLE_PATHS.has(rawPathname);

        // 2. Authenticate caller SECOND (operator secret OR page-bound Watch grant)
        const headerSecrets = req.headersDistinct["x-hunt-lab-secret"] ?? [];
        const candidate = headerSecrets.length === 1 ? Buffer.from(headerSecrets[0]!, "latin1") : null;
        const operatorAuthorized =
          candidate !== null &&
          candidate.byteLength === secretBuf.byteLength &&
          crypto.timingSafeEqual(candidate, secretBuf);
        const keys = isConsolePath ? new URLSearchParams(rawQuery).getAll("key") : [];
        const grant = keys.length === 1 ? this.watchGrants.get(keys[0]!) : undefined;
        if (
          !operatorAuthorized &&
          (headerSecrets.length > 0 || !grant || rawPathname !== WATCH_PAGES[grant.page].path)
        ) {
          sendResponse(res, 401, { error: "caller_not_authorized" });
          return;
        }

        // 3. Enforce GET-only read-only surface THIRD
        if (req.method !== "GET") {
          sendResponse(res, 405, { error: "read_only" });
          return;
        }

        // 4. Strictly validate origin-form request target (`/...`, rejecting `//authority`, schemes, and fragments)
        if (!isOriginForm) {
          sendResponse(res, 400, { error: "invalid_request" });
          return;
        }
        let parsedUrl: URL;
        try {
          parsedUrl = new URL(rawUrl, "http://127.0.0.1");
        } catch {
          sendResponse(res, 400, { error: "invalid_request" });
          return;
        }
        if (
          parsedUrl.origin !== "http://127.0.0.1" ||
          !parsedUrl.pathname.startsWith("/") ||
          parsedUrl.pathname.startsWith("//")
        ) {
          sendResponse(res, 400, { error: "invalid_request" });
          return;
        }

        const singleParams = (allowed: ReadonlySet<string>): Record<string, string> => {
          const out: Record<string, string> = {};
          for (const [k, v] of parsedUrl.searchParams.entries()) {
            if (!allowed.has(k) || Object.prototype.hasOwnProperty.call(out, k)) {
              throwDataPlaneError(400, "invalid_query", `Unknown or duplicate query parameter '${k}'`);
            }
            out[k] = v;
          }
          return out;
        };

        const pathname = parsedUrl.pathname;
        if (pathname === "/case") {
          if ([...parsedUrl.searchParams.keys()].length > 0) {
            throwDataPlaneError(400, "invalid_query", "No /case parameters supported");
          }
          sendResponse(res, 200, this.getCaseInfo());
          return;
        }

        if (pathname === "/health") {
          if ([...parsedUrl.searchParams.keys()].length > 0) {
            throwDataPlaneError(400, "invalid_query", "No /health parameters supported");
          }
          const ev = this.huntLabQuery({ dataset: "events", limit: 1 }) as Extract<
            HuntLabQueryResult,
            { total: number }
          >;
          const netCount = this.hasNetworkCapture
            ? (
                this.huntLabQuery({ dataset: "network", limit: 1 }) as Extract<
                  HuntLabQueryResult,
                  { total: number }
                >
              ).total
            : 0;
          const intelRow = this.db
            .query("SELECT COUNT(*) AS cnt FROM intel_items")
            .get() as { cnt: number };
          const ready = ev.total > 0 && (!this.hasNetworkCapture || netCount > 0);
          sendResponse(res, ready ? 200 : 503, {
            ready,
            case_id: this.caseId,
            event_count: ev.total,
            network_session_count: netCount,
            intel_count: intelRow.cnt,
            network_scope: "tag",
            arkime_viewer_ready: this.hasNetworkCapture,
            kibana_ready: true,
            read_only: true,
            instance_id: instanceId,
            ...(this.hasNetworkCapture ? {} : { network_capture: "none" }),
          });
          return;
        }

        if (pathname === "/activity") {
          const qp = singleParams(new Set(["after", "limit"]));
          const after = coerceBoundedInt(qp.after, 0, 0, 1_000_000_000, "invalid_query");
          const limit = coerceBoundedInt(qp.limit, 100, 1, 100, "invalid_query");
          const effAfter = after > activitySeq ? 0 : after;
          const pending = activityRing.filter((e) => e.seq > effAfter);
          const entries = pending.slice(0, limit);
          const next = entries.length > 0 ? entries[entries.length - 1]!.seq : effAfter;
          sendResponse(res, 200, {
            case_id: this.caseId,
            next,
            more: pending.length > limit,
            entries,
          });
          return;
        }

        if (CONSOLE_PATHS.has(pathname)) {
          const consoleKey = parsedUrl.searchParams.get("key") ?? undefined;
          const page: WatchPageId =
            pathname === "/watch/kibana_discover"
              ? "kibana_discover"
              : pathname === "/watch/arkime_sessions"
                ? "arkime_sessions"
                : pathname === "/watch/arkime_spiview"
                  ? "arkime_spiview"
                  : "lab_console";
          const rendered = this.renderWatchHtml(
            page,
            {
              q: parsedUrl.searchParams.get("q") ?? undefined,
              host: parsedUrl.searchParams.get("host") ?? undefined,
              expression: parsedUrl.searchParams.get("expression") ?? undefined,
              field: parsedUrl.searchParams.get("field") ?? undefined,
            },
            consoleKey,
            operatorAuthorized ? undefined : grant!.authorizeTool,
          );
          sendResponse(res, rendered.status, rendered.html, "text/html");
          return;
        }

        const profileHdr = req.headers["x-hermes-profile"];
        const callerProfile = typeof profileHdr === "string" ? profileHdr : "unknown";

        if (pathname === "/es/search") {
          const qp = singleParams(new Set(["q", "size", "sort", "after", "fields"]));
          const out = this.elasticSearch(qp as unknown as ElasticSearchParams);
          recordActivity({
            profile: callerProfile,
            tool: "elastic_search",
            endpoint: pathname,
            params: qp,
            result_count: out.returned,
            total: out.total,
            error: null,
          });
          sendResponse(res, 200, out);
          return;
        }

        if (pathname === "/es/aggs") {
          const qp = singleParams(new Set(["q", "field", "size", "interval"]));
          if (!qp.field) throwDataPlaneError(400, "field_not_allowed", "Missing field");
          const out = this.elasticAggregate(qp as unknown as ElasticAggregateParams);
          recordActivity({
            profile: callerProfile,
            tool: "elastic_aggregate",
            endpoint: pathname,
            params: qp,
            result_count: out.buckets.length,
            total: out.total,
            error: null,
          });
          sendResponse(res, 200, out);
          return;
        }

        if (pathname === "/es/detect") {
          const qp = singleParams(new Set(["q", "name"]));
          const out = this.detectionTest({ q: qp.q ?? "", name: qp.name ?? "" });
          recordActivity({
            profile: callerProfile,
            tool: "detection_test",
            endpoint: pathname,
            params: qp,
            result_count: out.sample.length,
            total: out.total,
            error: null,
          });
          sendResponse(res, 200, out);
          return;
        }

        if (pathname === "/intel") {
          const qp = singleParams(new Set(["values"]));
          const out = this.intelLookup({ values: qp.values ?? "" });
          recordActivity({
            profile: callerProfile,
            tool: "intel_lookup",
            endpoint: pathname,
            params: qp,
            result_count: out.matches.length,
            total: null,
            error: null,
          });
          sendResponse(res, 200, out);
          return;
        }

        if (pathname === "/arkime/sessions") {
          const qp = singleParams(new Set(["expression", "length", "start", "fields"]));
          const out = this.arkimeSessions(qp as unknown as ArkimeSessionsParams);
          recordActivity({
            profile: callerProfile,
            tool: "arkime_sessions",
            endpoint: pathname,
            params: qp,
            result_count: out.returned,
            total: out.recordsFiltered,
            error: null,
          });
          sendResponse(res, 200, out);
          return;
        }

        if (pathname === "/arkime/unique") {
          const qp = singleParams(new Set(["expression", "field", "counts"]));
          if (!qp.field) throwDataPlaneError(400, "field_not_allowed", "Missing field");
          const out = this.arkimeUnique(qp as unknown as ArkimeUniqueParams);
          recordActivity({
            profile: callerProfile,
            tool: "arkime_unique",
            endpoint: pathname,
            params: qp,
            result_count: out.returned,
            total: null,
            error: null,
          });
          sendResponse(res, 200, out);
          return;
        }

        if (pathname === "/packets") {
          const qp = singleParams(new Set(["fields", "filter", "length", "start"]));
          const out = this.packetFields(qp as unknown as PacketFieldsParams);
          recordActivity({
            profile: callerProfile,
            tool: "packet_fields",
            endpoint: pathname,
            params: qp,
            result_count: out.returned,
            total: null,
            error: null,
          });
          sendResponse(res, 200, out);
          return;
        }

        if (pathname === "/events" || pathname === "/network") {
          const qp = singleParams(new Set(["q", "host", "limit", "offset"]));
          const ds = pathname === "/events" ? "events" : "network";
          const out = this.huntLabQuery({
            dataset: ds,
            q: qp.q,
            host: qp.host,
            limit: qp.limit,
            offset: qp.offset,
          }) as Extract<HuntLabQueryResult, { returned: number; total: number }>;
          recordActivity({
            profile: callerProfile,
            tool: "hunt_lab_query",
            endpoint: pathname,
            params: qp,
            result_count: out.returned,
            total: out.total,
            error: null,
          });
          sendResponse(res, 200, out);
          return;
        }

        sendResponse(res, 404, { error: "not_found" });
      } catch (err) {
        if (res.headersSent) {
          return;
        }
        const dpErr = extractDataPlaneError(err);
        if (dpErr) {
          if (dpErr.statusCode === 503) {
            sendResponse(res, 503, { error: dpErr.errorCode, partial_results: false });
          } else {
            // Mirror lab_server.py HTTP status codes (400 on query/filter/field errors)
            const httpCode =
              dpErr.statusCode === 401 || dpErr.statusCode === 403 || dpErr.statusCode === 405
                ? dpErr.statusCode
                : 400;
            sendResponse(res, httpCode, { error: dpErr.errorCode });
          }
          return;
        }
        sendResponse(res, 503, { error: "backend_not_ready", partial_results: false });
      }
    });

    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => {
        server.removeListener("error", reject);
        const addr = server.address();
        if (!addr || typeof addr === "string") {
          reject(new Error("Failed to bind ephemeral loopback port"));
          return;
        }
        boundPort = addr.port;
        resolve();
      });
    });

    const handle: LocalDataPlaneHttpHandle = {
      host: "127.0.0.1",
      port: boundPort,
      baseUrl: `http://127.0.0.1:${boundPort}`,
      instanceId,
      secret,
      close: () =>
        new Promise<void>((resolve) => {
          server.close(() => resolve());
        }),
    };
    this.localServer = handle;
    return handle;
  }

  public async close(): Promise<void> {
    if (this.closed) return;
    this.watchGrants.clear();
    this.closed = true;
    if (this.localServer) {
      const srv = this.localServer;
      this.localServer = null;
      await srv.close();
    }
    this.db.close();
  }
}
