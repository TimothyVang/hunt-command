import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
  compareByLengthThenLex,
  compareLexicographic,
  escapeRegExp,
  EVENT_ID_SOURCE,
  FRAME_ID_SOURCE,
  INTEL_ID_SOURCE,
  loadJsonText,
  names,
  normalizeFrameCitation,
  scoreReport,
  textOf,
  validateTruth,
  type ScenarioTruth,
  type ScoreReportResult,
} from "./scorer.ts";

export const ENTITY_FIELDS = [
  "host.name",
  "host.hostname",
  "user.name",
  "user.target.name",
  "process.name",
  "process.parent.name",
  "source.ip",
  "destination.ip",
  "client.ip",
  "server.ip",
  "dns.question.name",
  "url.domain",
  "destination.domain",
  "server.domain",
] as const;

export const GENERIC_VALUES: ReadonlySet<string> = new Set<string>([
  "system",
  "local service",
  "network service",
  "anonymous logon",
  "unknown",
  "localhost",
  "n/a",
  "none",
  "null",
  "127.0.0.1",
  "::1",
  "0.0.0.0",
]);

export const EVENT_CAP = 40 as const;
export const REASON_LIMIT = 300 as const;
export const VERDICTS = ["correct", "wrong", "unsupported"] as const;
export const ESTABLISHED = ["yes", "partly", "no"] as const;
export const SCORER_TO_REVIEW = {
  found: "yes",
  partial: "partly",
  missed: "no",
} as const;

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function roundTo4(value: number): number {
  return Math.round(value * 10_000) / 10_000;
}

export function sha256Hex(content: string | Uint8Array): string {
  return crypto.createHash("sha256").update(content).digest("hex");
}

export function sha256File(filePath: string): string {
  return sha256Hex(fs.readFileSync(filePath));
}

/**
 * `names`, plus a subdomain of a named domain: an event recording
 * `x.t.relay.test` does show `t.relay.test`.
 */
export function inEvent(text: string, value: string): boolean {
  if (names(text, value)) {
    return true;
  }
  const escaped = escapeRegExp(value.toLowerCase());
  const subRe = new RegExp(`[A-Za-z0-9-]\\.${escaped}(?![A-Za-z0-9_-]|\\.[A-Za-z0-9])`);
  return subRe.test(text);
}

/**
 * Every string at a dotted ECS path, whether nested (`{"host": {"name": ...}}`),
 * flattened (`{"host.name": ...}`), or mixed.
 */
export function fieldValues(record: unknown, dottedPath: string): string[] {
  const found: string[] = [];

  const walk = (node: unknown, rest: readonly string[]): void => {
    if (Array.isArray(node)) {
      for (const item of node) {
        walk(item, rest);
      }
      return;
    }
    if (rest.length === 0) {
      if (typeof node === "string" && node.length > 0) {
        found.push(node);
      }
      return;
    }
    if (isPlainRecord(node)) {
      for (let cut = 1; cut <= rest.length; cut++) {
        const key = rest.slice(0, cut).join(".");
        if (key in node) {
          walk(node[key], rest.slice(cut));
        }
      }
    }
  };

  walk(record, dottedPath.split("."));
  return found;
}

function extractBalancedJsonObjectEnd(text: string, start: number): number | null {
  if (text[start] !== "{") {
    return null;
  }
  let depth = 0;
  let inString = false;
  for (let i = start; i < text.length; i++) {
    const ch = text[i];
    if (inString) {
      if (ch === "\\") {
        i++;
        continue;
      }
      if (ch === '"') {
        inString = false;
      }
      continue;
    }
    if (ch === '"') {
      inString = true;
    } else if (ch === "{") {
      depth++;
    } else if (ch === "}") {
      depth--;
      if (depth === 0) {
        return i + 1;
      }
    }
  }
  return null;
}

/**
 * Extract the JSON handoff object containing a `claims` array from saved stage
 * output (which may have prose or markdown fences around it).
 */
export function readHandoff(text: string): Record<string, unknown> {
  const withoutBom = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  let start = withoutBom.indexOf("{");
  while (start >= 0) {
    const end = extractBalancedJsonObjectEnd(withoutBom, start);
    if (end !== null) {
      try {
        const parsed = loadJsonText(withoutBom.slice(start, end));
        if (isPlainRecord(parsed) && Array.isArray(parsed.claims)) {
          return parsed;
        }
      } catch {
        // Continue scanning for the next '{'
      }
    }
    start = withoutBom.indexOf("{", start + 1);
  }
  throw new Error("no JSON handoff with a claims list");
}

export function extractEventIds(text: string): string[] {
  const set = new Set<string>();
  for (const m of text.matchAll(new RegExp(EVENT_ID_SOURCE, "g"))) {
    set.add(m[0]);
  }
  return [...set].sort(compareLexicographic);
}

export function extractFrameIds(text: string): string[] {
  const set = new Set<string>();
  for (const m of text.matchAll(new RegExp(FRAME_ID_SOURCE, "gi"))) {
    if (m[1] !== undefined) {
      set.add(normalizeFrameCitation(m[1]));
    }
  }
  return [...set].sort(compareByLengthThenLex);
}

export function extractIntelIds(text: string): string[] {
  const set = new Set<string>();
  for (const m of text.matchAll(new RegExp(INTEL_ID_SOURCE, "g"))) {
    set.add(m[0]);
  }
  return [...set].sort(compareByLengthThenLex);
}

export function reportClaims(report: Record<string, unknown>): Record<string, unknown>[] {
  if (!Array.isArray(report.claims)) {
    return [];
  }
  return report.claims.filter(isPlainRecord);
}

export function claimEventIds(claim: unknown): string[] {
  return extractEventIds(textOf(claim));
}

export function claimFrameIds(claim: unknown): string[] {
  return extractFrameIds(textOf(claim));
}

export function claimIntelIds(claim: unknown): string[] {
  return extractIntelIds(textOf(claim));
}

export function reportCitedEventIds(report: Record<string, unknown>): Set<string> {
  const out = new Set<string>();
  for (const claim of reportClaims(report)) {
    for (const eid of claimEventIds(claim)) {
      out.add(eid);
    }
  }
  for (const eid of extractEventIds(textOf(report.limitations ?? []))) {
    out.add(eid);
  }
  return out;
}

export function keyEventIds(truth: ScenarioTruth): Set<string> {
  const out = new Set<string>();
  for (const fact of truth.facts) {
    for (const group of fact.evidence_event_groups) {
      for (const eid of group) {
        out.add(eid);
      }
    }
  }
  return out;
}

/**
 * Pure binary parser counting packet frames in classic libpcap (LE/BE, micro/nano)
 * and pcapng captures without invoking external binaries.
 */
export function countPcapFrames(input: Uint8Array | string): number {
  const bytes = typeof input === "string" ? fs.readFileSync(input) : input;
  if (bytes.byteLength < 24) {
    return 0;
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const magicBE = view.getUint32(0, false);

  // Classic libpcap
  if (
    magicBE === 0xa1b2c3d4 ||
    magicBE === 0xa1b23c4d ||
    magicBE === 0xd4c3b2a1 ||
    magicBE === 0x4d3cb2a1
  ) {
    const littleEndian = magicBE === 0xd4c3b2a1 || magicBE === 0x4d3cb2a1;
    let offset = 24;
    let count = 0;
    while (offset + 16 <= bytes.byteLength) {
      const inclLen = view.getUint32(offset + 8, littleEndian);
      if (offset + 16 + inclLen > bytes.byteLength) {
        break;
      }
      count++;
      offset += 16 + inclLen;
    }
    return count;
  }

  // pcapng Section Header Block (0x0A0D0D0A)
  if (magicBE === 0x0a0d0d0a) {
    let offset = 0;
    let littleEndian = true;
    let count = 0;
    while (offset + 12 <= bytes.byteLength) {
      const rawTypeBE = view.getUint32(offset, false);
      if (rawTypeBE === 0x0a0d0d0a) {
        if (offset + 12 > bytes.byteLength) {
          break;
        }
        const byteOrderMagic = view.getUint32(offset + 8, false);
        if (byteOrderMagic === 0x1a2b3c4d) {
          littleEndian = false;
        } else if (byteOrderMagic === 0x4d3c2b1a) {
          littleEndian = true;
        } else {
          break;
        }
      }
      const blockType = view.getUint32(offset, littleEndian);
      const blockTotalLen = view.getUint32(offset + 4, littleEndian);
      if (blockTotalLen < 12 || offset + blockTotalLen > bytes.byteLength) {
        break;
      }
      // Enhanced Packet (6), Simple Packet (3), Obsolete Packet (2)
      if (blockType === 0x00000006 || blockType === 0x00000003 || blockType === 0x00000002) {
        count++;
      }
      const aligned = (blockTotalLen + 3) & ~3;
      offset += aligned;
    }
    return count;
  }

  throw new Error("Unsupported PCAP magic header");
}

function readIntelIdsFromJsonl(intelPath: string): Set<string> {
  const ids = new Set<string>();
  const raw = fs.readFileSync(intelPath, "utf8");
  const withoutBom = raw.charCodeAt(0) === 0xfeff ? raw.slice(1) : raw;
  for (const line of withoutBom.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) {
      continue;
    }
    const doc = JSON.parse(trimmed) as Record<string, unknown>;
    if (typeof doc.id === "string" && doc.id.length > 0) {
      ids.add(doc.id);
    }
  }
  return ids;
}

export interface CaseEventsOptions {
  readonly wanted?: Iterable<string>;
  readonly intelPath?: string | null;
  readonly validIntelIds?: Iterable<string>;
  readonly pcapPath?: string | null;
  readonly maxFrameNumber?: number;
  readonly validFrameIds?: Iterable<string>;
  readonly autoDiscoverSiblings?: boolean;
}

export interface CaseEventsSummary {
  readonly path: string;
  readonly sha256: string;
  readonly events: number;
  readonly events_without_id: number;
  readonly duplicate_ids: string[];
  readonly vocabulary_size: number;
  readonly frame_count: number;
  readonly intel_count: number;
}

export class CaseEvents {
  public readonly path: string;
  public readonly ids: Set<string>;
  public readonly frameIds: Set<string>;
  public readonly intelIds: Set<string>;
  public readonly records: Map<string, Record<string, unknown>>;
  private readonly texts: Map<string, string>;
  public readonly duplicates: string[];
  public readonly without_id: number;
  public readonly count: number;
  public readonly sha256: string;
  public readonly vocabulary: string[];

  private constructor(init: {
    path: string;
    ids: Set<string>;
    frameIds: Set<string>;
    intelIds: Set<string>;
    records: Map<string, Record<string, unknown>>;
    duplicates: string[];
    withoutId: number;
    count: number;
    sha256: string;
    vocabulary: string[];
  }) {
    this.path = init.path;
    this.ids = init.ids;
    this.frameIds = init.frameIds;
    this.intelIds = init.intelIds;
    this.records = init.records;
    this.texts = new Map<string, string>();
    this.duplicates = init.duplicates;
    this.without_id = init.withoutId;
    this.count = init.count;
    this.sha256 = init.sha256;
    this.vocabulary = init.vocabulary;
  }

  public static fromFile(eventsPath: string, options: CaseEventsOptions = {}): CaseEvents {
    const rawBytes = fs.readFileSync(eventsPath);
    const digestHex = sha256Hex(rawBytes);
    const rawText = rawBytes.toString("utf8");
    const withoutBom = rawText.charCodeAt(0) === 0xfeff ? rawText.slice(1) : rawText;

    const wantedSet = options.wanted !== undefined ? new Set<string>(options.wanted) : null;
    const ids = new Set<string>();
    const records = new Map<string, Record<string, unknown>>();
    const duplicates: string[] = [];
    let withoutId = 0;
    let count = 0;
    const vocabSet = new Set<string>();

    const lines = withoutBom.split(/\r?\n/);
    for (let idx = 0; idx < lines.length; idx++) {
      const line = lines[idx]!;
      if (!line.trim()) {
        continue;
      }
      let record: unknown;
      try {
        record = JSON.parse(line);
      } catch (err) {
        throw new Error(`${eventsPath}:${idx + 1}: not JSON (${String(err)})`);
      }
      if (!isPlainRecord(record)) {
        throw new Error(`${eventsPath}:${idx + 1}: event line must be a JSON object`);
      }
      count++;
      const eids = fieldValues(record, "event.id");
      if (eids.length === 0) {
        withoutId++;
        continue;
      }
      const eid = eids[0]!;
      if (ids.has(eid)) {
        duplicates.push(eid);
      }
      ids.add(eid);
      if (wantedSet === null || wantedSet.has(eid)) {
        records.set(eid, record);
      }
      for (const field of ENTITY_FIELDS) {
        for (const rawVal of fieldValues(record, field)) {
          const val = rawVal.trim().toLowerCase();
          if (val.length >= 3 && !GENERIC_VALUES.has(val)) {
            vocabSet.add(val);
          }
        }
      }
    }

    const autoSiblings = options.autoDiscoverSiblings !== false;
    const parentDir = path.dirname(eventsPath);

    let intelIds: Set<string>;
    if (options.validIntelIds !== undefined) {
      intelIds = new Set<string>(options.validIntelIds);
    } else if (options.intelPath) {
      intelIds = readIntelIdsFromJsonl(options.intelPath);
    } else if (autoSiblings && fs.existsSync(path.join(parentDir, "intel.jsonl"))) {
      intelIds = readIntelIdsFromJsonl(path.join(parentDir, "intel.jsonl"));
    } else {
      intelIds = new Set<string>();
    }

    let frameIds: Set<string>;
    if (options.validFrameIds !== undefined) {
      frameIds = new Set<string>();
      for (const f of options.validFrameIds) {
        const m = /^frame-(\d+)$/i.exec(f.trim());
        frameIds.add(m && m[1] !== undefined ? normalizeFrameCitation(m[1]) : f.trim());
      }
    } else if (options.maxFrameNumber !== undefined) {
      frameIds = new Set<string>();
      for (let n = 1; n <= options.maxFrameNumber; n++) {
        frameIds.add(`frame-${n}`);
      }
    } else if (options.pcapPath) {
      const nFrames = countPcapFrames(options.pcapPath);
      frameIds = new Set<string>();
      for (let n = 1; n <= nFrames; n++) {
        frameIds.add(`frame-${n}`);
      }
    } else if (autoSiblings) {
      frameIds = CaseEvents.discoverSiblingPcapFrames(parentDir);
    } else {
      frameIds = new Set<string>();
    }

    return new CaseEvents({
      path: eventsPath,
      ids,
      frameIds,
      intelIds,
      records,
      duplicates,
      withoutId,
      count,
      sha256: digestHex,
      vocabulary: [...vocabSet].sort(compareLexicographic),
    });
  }

  private static discoverSiblingPcapFrames(evidenceDir: string): Set<string> {
    const candidates = [
      path.join(evidenceDir, "traffic.pcap"),
      path.join(evidenceDir, "traffic.pcapng"),
      path.join(evidenceDir, "capture.pcap"),
      path.join(evidenceDir, "capture.pcapng"),
    ];
    const caseJsonCandidates = [
      path.join(evidenceDir, "case.json"),
      path.join(path.dirname(evidenceDir), "case.json"),
    ];
    for (const cj of caseJsonCandidates) {
      if (fs.existsSync(cj)) {
        try {
          const meta = JSON.parse(fs.readFileSync(cj, "utf8")) as Record<string, unknown>;
          if (typeof meta.pcap_relpath === "string" && meta.pcap_relpath.length > 0) {
            candidates.unshift(path.resolve(path.dirname(cj), meta.pcap_relpath));
          }
        } catch {
          // Ignore unreadable sibling case.json during optional discovery
        }
      }
    }

    for (const candidate of candidates) {
      if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
        const totalFrames = countPcapFrames(candidate);
        const set = new Set<string>();
        for (let n = 1; n <= totalFrames; n++) {
          set.add(`frame-${n}`);
        }
        return set;
      }
    }
    return new Set<string>();
  }

  public static fromRecords(
    recordsInput: readonly Record<string, unknown>[],
    options: Omit<CaseEventsOptions, "autoDiscoverSiblings"> & { readonly label?: string } = {},
  ): CaseEvents {
    const serialized = recordsInput.map((r) => JSON.stringify(r)).join("\n");
    const wantedSet = options.wanted !== undefined ? new Set<string>(options.wanted) : null;
    const ids = new Set<string>();
    const records = new Map<string, Record<string, unknown>>();
    const duplicates: string[] = [];
    let withoutId = 0;
    const vocabSet = new Set<string>();

    for (const record of recordsInput) {
      const eids = fieldValues(record, "event.id");
      if (eids.length === 0) {
        withoutId++;
        continue;
      }
      const eid = eids[0]!;
      if (ids.has(eid)) {
        duplicates.push(eid);
      }
      ids.add(eid);
      if (wantedSet === null || wantedSet.has(eid)) {
        records.set(eid, record);
      }
      for (const field of ENTITY_FIELDS) {
        for (const rawVal of fieldValues(record, field)) {
          const val = rawVal.trim().toLowerCase();
          if (val.length >= 3 && !GENERIC_VALUES.has(val)) {
            vocabSet.add(val);
          }
        }
      }
    }

    const intelIds = new Set<string>(options.validIntelIds ?? []);
    if (options.intelPath) {
      for (const id of readIntelIdsFromJsonl(options.intelPath)) {
        intelIds.add(id);
      }
    }

    const frameIds = new Set<string>();
    if (options.validFrameIds !== undefined) {
      for (const f of options.validFrameIds) {
        const m = /^frame-(\d+)$/i.exec(f.trim());
        frameIds.add(m && m[1] !== undefined ? normalizeFrameCitation(m[1]) : f.trim());
      }
    } else if (options.maxFrameNumber !== undefined) {
      for (let n = 1; n <= options.maxFrameNumber; n++) {
        frameIds.add(`frame-${n}`);
      }
    } else if (options.pcapPath) {
      const total = countPcapFrames(options.pcapPath);
      for (let n = 1; n <= total; n++) {
        frameIds.add(`frame-${n}`);
      }
    }

    return new CaseEvents({
      path: options.label ?? "<in-memory>",
      ids,
      frameIds,
      intelIds,
      records,
      duplicates,
      withoutId,
      count: recordsInput.length,
      sha256: sha256Hex(serialized),
      vocabulary: [...vocabSet].sort(compareLexicographic),
    });
  }

  public text(eid: string): string {
    const cached = this.texts.get(eid);
    if (cached !== undefined) {
      return cached;
    }
    const record = this.records.get(eid);
    if (!record) {
      return "";
    }
    const computed = textOf(record).toLowerCase();
    this.texts.set(eid, computed);
    return computed;
  }

  public namedIn(value: string, eids: readonly string[]): boolean {
    return eids.some((eid) => this.records.has(eid) && inEvent(this.text(eid), value));
  }

  public summary(): CaseEventsSummary {
    return {
      path: this.path,
      sha256: this.sha256,
      events: this.count,
      events_without_id: this.without_id,
      duplicate_ids: [...new Set(this.duplicates)].sort(compareLexicographic),
      vocabulary_size: this.vocabulary.length,
      frame_count: this.frameIds.size,
      intel_count: this.intelIds.size,
    };
  }
}

export type ClaimSupportStatus = "supported" | "unsupported" | "uncited";

export interface ClaimSupportDetail {
  claim_id: unknown;
  kind: unknown;
  status: ClaimSupportStatus;
  cited_ids: string[];
  missing_ids: string[];
  cited_frame_ids: string[];
  missing_frame_ids: string[];
  cited_intel_ids: string[];
  missing_intel_ids: string[];
  grounded_ids: string[];
  ungrounded_ids: string[];
  citation_precision: number | null;
  entities_named: string[];
  entities_not_in_cited_events: string[];
}

export function claimSupport(
  claim: Record<string, unknown>,
  events: CaseEvents,
): ClaimSupportDetail {
  const cited = claimEventIds(claim);
  const present = cited.filter((eid) => events.ids.has(eid));
  const missing = cited.filter((eid) => !events.ids.has(eid));

  const citedFrames = claimFrameIds(claim);
  const missingFrames = citedFrames.filter((fid) => !events.frameIds.has(fid));

  const citedIntels = claimIntelIds(claim);
  const missingIntels = citedIntels.filter((iid) => !events.intelIds.has(iid));

  const statement = textOf(claim.statement ?? "").toLowerCase();
  const named = events.vocabulary.filter(
    (value) => statement.includes(value) && names(statement, value),
  );
  const absent = named.filter((value) => !events.namedIn(value, present));
  const grounded = present.filter(
    (eid) =>
      events.records.has(eid) && named.some((value) => inEvent(events.text(eid), value)),
  );
  const groundedSet = new Set<string>(grounded);
  const ungrounded = present.filter((eid) => !groundedSet.has(eid));
  const precision = cited.length > 0 ? roundTo4(grounded.length / cited.length) : null;

  const hasAnyCitations =
    cited.length > 0 || citedFrames.length > 0 || citedIntels.length > 0;
  const hasAnyMissing =
    missing.length > 0 || missingFrames.length > 0 || missingIntels.length > 0;

  const supported =
    cited.length > 0 &&
    named.length > 0 &&
    grounded.length > 0 &&
    !hasAnyMissing &&
    absent.length === 0;

  const status: ClaimSupportStatus = !hasAnyCitations
    ? "uncited"
    : supported
      ? "supported"
      : "unsupported";

  return {
    claim_id: claim.claim_id ?? null,
    kind: claim.kind ?? null,
    status,
    cited_ids: cited,
    missing_ids: missing,
    cited_frame_ids: citedFrames,
    missing_frame_ids: missingFrames,
    cited_intel_ids: citedIntels,
    missing_intel_ids: missingIntels,
    grounded_ids: grounded,
    ungrounded_ids: ungrounded,
    citation_precision: precision,
    entities_named: named,
    entities_not_in_cited_events: absent,
  };
}

export interface KeyConsistencyItem {
  fact_id: string;
  kind: string;
  groups: number;
  event_ids: number;
  missing_event_ids: string[];
  entities_absent: string[];
  consistent: boolean;
}

export function keyConsistency(truth: ScenarioTruth, events: CaseEvents): KeyConsistencyItem[] {
  validateTruth(truth);
  return truth.facts.map((fact) => {
    const eidSet = new Set<string>();
    for (const group of fact.evidence_event_groups) {
      for (const eid of group) {
        eidSet.add(eid);
      }
    }
    const eids = [...eidSet].sort(compareLexicographic);
    const missing = eids.filter((eid) => !events.ids.has(eid));

    const entitySet = new Set<string>();
    for (const values of Object.values(fact.entities ?? {})) {
      if (Array.isArray(values)) {
        for (const val of values) {
          entitySet.add(String(val));
        }
      }
    }
    const entities = [...entitySet].sort(compareLexicographic);
    const absent = entities.filter((value) => !events.namedIn(value, eids));

    return {
      fact_id: fact.fact_id,
      kind: fact.kind,
      groups: fact.evidence_event_groups.length,
      event_ids: eids.length,
      missing_event_ids: missing,
      entities_absent: absent,
      consistent: missing.length === 0 && absent.length === 0,
    };
  });
}

export type FactScorerStatus = "found" | "partial" | "missed";

export function scorerStatuses(
  truth: ScenarioTruth,
  report: Record<string, unknown>,
): { scored: ScoreReportResult; statuses: Record<string, FactScorerStatus> } {
  const scored = scoreReport(truth, report);
  const statuses: Record<string, FactScorerStatus> = {};
  for (const detail of scored.facts) {
    statuses[detail.fact_id] = detail.found
      ? "found"
      : detail.cited_groups.length > 0
        ? "partial"
        : "missed";
  }
  return { scored, statuses };
}

export interface ClaimsGroundingCheckResult {
  claims: number;
  cited_ids: string[];
  missing_ids: string[];
  cited_frame_ids: string[];
  missing_frame_ids: string[];
  cited_intel_ids: string[];
  missing_intel_ids: string[];
  limitation_ids: string[];
  limitation_missing_ids: string[];
  limitation_frame_ids: string[];
  limitation_missing_frame_ids: string[];
  limitation_intel_ids: string[];
  limitation_missing_intel_ids: string[];
  missing_citation_total: number;
  g2_1_pass: boolean;
  citation_support: {
    supported: number;
    unsupported: number;
    uncited: number;
    entity_free_cited: number;
    supported_share: number | null;
    citation_precision: number | null;
    mean_claim_precision: number | null;
    claims: ClaimSupportDetail[];
  };
}

/**
 * Key-free G2.1 citation existence across `evt-*`, `frame-*`, and `ioc-*` in
 * BOTH `claims` AND `limitations`, plus entity grounding and citation precision.
 */
export function checkClaimsGrounding(
  report: Record<string, unknown>,
  events: CaseEvents,
): ClaimsGroundingCheckResult {
  const claims = reportClaims(report);
  const support = claims.map((claim) => claimSupport(claim, events));

  const citedEvtSet = new Set<string>();
  const citedFrameSet = new Set<string>();
  const citedIntelSet = new Set<string>();
  for (const item of support) {
    for (const id of item.cited_ids) citedEvtSet.add(id);
    for (const id of item.cited_frame_ids) citedFrameSet.add(id);
    for (const id of item.cited_intel_ids) citedIntelSet.add(id);
  }

  const citedIdsList = [...citedEvtSet].sort(compareLexicographic);
  const missingIdsList = citedIdsList.filter((eid) => !events.ids.has(eid));

  const citedFrameIdsList = [...citedFrameSet].sort(compareByLengthThenLex);
  const missingFrameIdsList = citedFrameIdsList.filter((fid) => !events.frameIds.has(fid));

  const citedIntelIdsList = [...citedIntelSet].sort(compareByLengthThenLex);
  const missingIntelIdsList = citedIntelIdsList.filter((iid) => !events.intelIds.has(iid));

  const limText = textOf(report.limitations ?? []);
  const limitationIds = extractEventIds(limText);
  const limitationMissingIds = limitationIds.filter((eid) => !events.ids.has(eid));

  const limitationFrameIds = extractFrameIds(limText);
  const limitationMissingFrameIds = limitationFrameIds.filter(
    (fid) => !events.frameIds.has(fid),
  );

  const limitationIntelIds = extractIntelIds(limText);
  const limitationMissingIntelIds = limitationIntelIds.filter(
    (iid) => !events.intelIds.has(iid),
  );

  const missingTotal =
    missingIdsList.length +
    missingFrameIdsList.length +
    missingIntelIdsList.length +
    limitationMissingIds.length +
    limitationMissingFrameIds.length +
    limitationMissingIntelIds.length;

  let supportedCount = 0;
  let unsupportedCount = 0;
  let uncitedCount = 0;
  let entityFreeCited = 0;
  let totalCitations = 0;
  let groundedCitations = 0;
  const precisions: number[] = [];

  for (const item of support) {
    if (item.status === "supported") supportedCount++;
    else if (item.status === "unsupported") unsupportedCount++;
    else uncitedCount++;

    if (item.cited_ids.length > 0 && item.entities_named.length === 0) {
      entityFreeCited++;
    }
    totalCitations += item.cited_ids.length;
    groundedCitations += item.grounded_ids.length;
    if (item.citation_precision !== null) {
      precisions.push(item.citation_precision);
    }
  }

  return {
    claims: claims.length,
    cited_ids: citedIdsList,
    missing_ids: missingIdsList,
    cited_frame_ids: citedFrameIdsList,
    missing_frame_ids: missingFrameIdsList,
    cited_intel_ids: citedIntelIdsList,
    missing_intel_ids: missingIntelIdsList,
    limitation_ids: limitationIds,
    limitation_missing_ids: limitationMissingIds,
    limitation_frame_ids: limitationFrameIds,
    limitation_missing_frame_ids: limitationMissingFrameIds,
    limitation_intel_ids: limitationIntelIds,
    limitation_missing_intel_ids: limitationMissingIntelIds,
    missing_citation_total: missingTotal,
    g2_1_pass: missingTotal === 0,
    citation_support: {
      supported: supportedCount,
      unsupported: unsupportedCount,
      uncited: uncitedCount,
      entity_free_cited: entityFreeCited,
      supported_share: claims.length > 0 ? roundTo4(supportedCount / claims.length) : null,
      citation_precision:
        totalCitations > 0 ? roundTo4(groundedCitations / totalCitations) : null,
      mean_claim_precision:
        precisions.length > 0
          ? roundTo4(precisions.reduce((a, b) => a + b, 0) / precisions.length)
          : null,
      claims: support,
    },
  };
}

export interface CheckedReportWithScorer extends ClaimsGroundingCheckResult {
  scorer: {
    found: number;
    total: number;
    partial: number;
    misattributed_decoys: ScoreReportResult["misattributed_decoys"];
    facts: Array<{
      fact_id: string;
      kind: string;
      status: FactScorerStatus;
      cited_groups: number[];
      missing_groups: number[];
      entities_named: string[];
    }>;
  };
}

export function checkReport(
  report: Record<string, unknown>,
  truth: ScenarioTruth,
  events: CaseEvents,
): CheckedReportWithScorer {
  const checked = checkClaimsGrounding(report, events);
  const { scored, statuses } = scorerStatuses(truth, report);
  const partialCount = Object.values(statuses).filter((s) => s === "partial").length;

  return {
    ...checked,
    scorer: {
      found: scored.found,
      total: scored.total,
      partial: partialCount,
      misattributed_decoys: scored.misattributed_decoys,
      facts: scored.facts.map((detail) => ({
        fact_id: detail.fact_id,
        kind: detail.kind,
        status: statuses[detail.fact_id]!,
        cited_groups: detail.cited_groups,
        missing_groups: detail.missing_groups,
        entities_named: detail.entities_named,
      })),
    },
  };
}

export interface G21GoalSummary {
  goal: string;
  reports: number;
  reports_checked: number;
  reports_with_missing: number;
  cited_ids: number;
  cited_frame_ids: number;
  cited_intel_ids: number;
  missing_ids: number;
  pass: boolean;
}

export interface G22GoalSummary {
  goal: string;
  cases: number;
  cases_checked: number;
  facts: number;
  consistent: number;
  inconsistent: string[];
  pass: boolean;
}

export interface ReviewReportsResult {
  schema_version: 1;
  events: CaseEventsSummary;
  goals: {
    "G2.1": G21GoalSummary;
    "G2.2"?: G22GoalSummary;
  };
  g2_1_pass: boolean;
  reports: Array<
    (ClaimsGroundingCheckResult | CheckedReportWithScorer) & {
      report?: string;
      report_sha256?: string;
    }
  >;
}

/**
 * Evaluate one or more reports (parsed objects, raw handoff strings, or file paths)
 * against `CaseEvents` and optional `ScenarioTruth`, enforcing `g2_1_pass` (`0`
 * missing `evt-*`, `frame-*`, and `ioc-*` across BOTH `claims` and `limitations`).
 */
export function reviewReports(params: {
  readonly reports: ReadonlyArray<string | Record<string, unknown>>;
  readonly reportIsFilePath?: boolean;
  readonly events: CaseEvents;
  readonly truth?: ScenarioTruth;
}): ReviewReportsResult {
  if (params.reports.length === 0) {
    throw new Error("reviewReports requires at least one report");
  }

  const checkedList: ReviewReportsResult["reports"] = [];

  for (const item of params.reports) {
    let reportObj: Record<string, unknown>;
    let reportLabel: string | undefined;
    let reportDigest: string | undefined;

    if (typeof item === "string") {
      if (params.reportIsFilePath) {
        const rawBytes = fs.readFileSync(item);
        reportLabel = item;
        reportDigest = sha256Hex(rawBytes);
        reportObj = readHandoff(rawBytes.toString("utf8"));
      } else {
        reportDigest = sha256Hex(item);
        reportObj = readHandoff(item);
      }
    } else {
      reportObj = item;
    }

    const base =
      params.truth !== undefined
        ? checkReport(reportObj, params.truth, params.events)
        : checkClaimsGrounding(reportObj, params.events);

    checkedList.push({
      ...(reportLabel !== undefined ? { report: reportLabel } : {}),
      ...(reportDigest !== undefined ? { report_sha256: reportDigest } : {}),
      ...base,
    });
  }

  const reportsWithMissing = checkedList.filter((r) => !r.g2_1_pass).length;
  const totalCitedEvts = checkedList.reduce(
    (acc, r) => acc + r.cited_ids.length + r.limitation_ids.length,
    0,
  );
  const totalCitedFrames = checkedList.reduce(
    (acc, r) => acc + r.cited_frame_ids.length + r.limitation_frame_ids.length,
    0,
  );
  const totalCitedIntels = checkedList.reduce(
    (acc, r) => acc + r.cited_intel_ids.length + r.limitation_intel_ids.length,
    0,
  );
  const totalMissing = checkedList.reduce((acc, r) => acc + r.missing_citation_total, 0);
  const allPass = checkedList.length > 0 && checkedList.every((r) => r.g2_1_pass);

  const goals: ReviewReportsResult["goals"] = {
    "G2.1": {
      goal: "No invented citations: every cited evt-*, frame-*, and ioc-* ID exists across claims and limitations",
      reports: checkedList.length,
      reports_checked: checkedList.length,
      reports_with_missing: reportsWithMissing,
      cited_ids: totalCitedEvts,
      cited_frame_ids: totalCitedFrames,
      cited_intel_ids: totalCitedIntels,
      missing_ids: totalMissing,
      pass: allPass,
    },
  };

  if (params.truth !== undefined) {
    const facts = keyConsistency(params.truth, params.events);
    const consistentCount = facts.filter((f) => f.consistent).length;
    goals["G2.2"] = {
      goal: "Keys are internally consistent: every key event exists and every key entity is in its events",
      cases: 1,
      cases_checked: 1,
      facts: facts.length,
      consistent: consistentCount,
      inconsistent: facts.filter((f) => !f.consistent).map((f) => f.fact_id),
      pass: facts.length > 0 && consistentCount === facts.length,
    };
  }

  return {
    schema_version: 1,
    events: params.events.summary(),
    goals,
    g2_1_pass: allPass,
    reports: checkedList,
  };
}
