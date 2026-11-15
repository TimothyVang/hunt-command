import {
  RECONCILE_GATE,
  extractInlineCitations,
  scrubSecretValue,
  type Handoff,
  type ProfileId,
} from "@hunt-command/shared";
import type { CitationVerificationReceipt, CitedEvidenceRecord, HuntDataPlanePort } from "./ports.ts";
import { sanitizeUntrustedText, truncateUtf8Safe } from "./scrubber-and-fence.ts";
import type { DispatchReceiptRow, PersistedHuntRun } from "./state-store.ts";
import { profileForRunStep } from "./transcript.ts";
import { assertDataPlaneBindsRun } from "./wave-engine.ts";

export const GATE_CONTEXT_MAX_EVIDENCE = 500;
export const GATE_CONTEXT_MAX_FIELDS = 64;
export const GATE_CONTEXT_MAX_VALUE_BYTES = 1024;

export type GateContextFieldValue = string | number | boolean | string[];

export interface GateContextEvidence {
  readonly id: string;
  readonly kind: "evt" | "frame" | "ioc";
  /** `unchecked` only on a citation reconcile gate whose source is still down. */
  readonly status: "verified" | "unresolved" | "out_of_scope" | "ambiguous" | "unchecked";
  readonly timestamp_iso: string | null;
  readonly title: string;
  readonly fields: Record<string, GateContextFieldValue>;
}

export interface GateContextReconcileReceipt {
  readonly execution_id: string;
  readonly session_id: string;
  readonly input_id: string;
  readonly step_id: string;
  readonly profile: ProfileId;
  readonly reserved_at: string;
  readonly reason_code: "previous_dispatch_unknown";
}

export interface GateContext {
  readonly run_id: string;
  readonly case_id: string;
  readonly gate: "scope" | "incident" | "reconcile";
  readonly payload_sha256: string;
  readonly scope?: { readonly scope_text: string };
  readonly incident?: GateCitedEvidence;
  readonly reconcile?: GateContextReconcile;
}

/** Tagged by `reason_code`: why the step became unknown decides what the operator must see. */
export type GateContextReconcile =
  | {
      readonly reason_code: "previous_dispatch_unknown";
      readonly receipts: GateContextReconcileReceipt[];
    }
  | {
      readonly reason_code: "citation_source_unavailable";
      /** Source kinds that could not be read while building this context (statuses are `unchecked`). */
      readonly unavailable_sources: Array<"events" | "packets" | "intel">;
    } & GateCitedEvidence;

/**
 * Complete statuses for every distinct cited id (`cited`, capped at 20,000 or the context fails
 * closed), plus the first page of records; `hunt.gateEvidencePage` returns the rest.
 */
export interface GateCitedEvidence {
  readonly citation_receipt: CitationVerificationReceipt;
  readonly cited: GateCitedStatus[];
  readonly evidence: GateContextEvidence[];
  readonly evidence_total: number;
  readonly evidence_next_cursor: string | null;
}

export type GateContextErrorCode = "no_open_gate" | "gate_context_unavailable" | "stale_cursor" | "invalid_arguments";

export class GateContextError extends Error {
  constructor(
    public readonly errorCode: GateContextErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "GateContextError";
  }
}

/** Scrubbed, control-stripped display text, capped to `maxBytes` UTF-8 bytes. */
function clean(text: string, maxBytes = GATE_CONTEXT_MAX_VALUE_BYTES): string {
  return truncateUtf8Safe(sanitizeUntrustedText(text), maxBytes).text;
}

/** Flattens a scrubbed record to at most 64 dotted fields of display-safe values. */
export function flattenEvidenceFields(record: Record<string, unknown>): Record<string, GateContextFieldValue> {
  const out: Record<string, GateContextFieldValue> = {};
  let count = 0;
  const visit = (value: unknown, key: string, depth: number): void => {
    if (count >= GATE_CONTEXT_MAX_FIELDS) return;
    if (value === null || value === undefined) return;
    if (typeof value === "number") {
      if (Number.isFinite(value)) {
        out[key] = value;
        count++;
      }
      return;
    }
    if (typeof value === "boolean") {
      out[key] = value;
      count++;
      return;
    }
    if (typeof value === "string") {
      out[key] = clean(value);
      count++;
      return;
    }
    if (Array.isArray(value)) {
      if (value.every((v) => typeof v === "string" || typeof v === "number" || typeof v === "boolean")) {
        // A string[] whose joined size stays within the per-value cap.
        const items: string[] = [];
        let bytes = 0;
        for (const v of value) {
          const item = clean(String(v));
          bytes += Buffer.byteLength(item, "utf8");
          if (bytes > GATE_CONTEXT_MAX_VALUE_BYTES) break;
          items.push(item);
        }
        out[key] = items;
      } else {
        out[key] = clean(JSON.stringify(value));
      }
      count++;
      return;
    }
    if (typeof value === "object") {
      if (depth >= 8) {
        out[key] = clean(JSON.stringify(value));
        count++;
        return;
      }
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
        visit(v, key ? `${key}.${k}` : k, depth + 1);
      }
      return;
    }
  };
  visit(scrubSecretValue(record), "", 0);
  return out;
}

function citedIds(handoffs: readonly Handoff[]): string[] {
  const ids = new Set<string>();
  for (const h of handoffs) {
    for (const text of [...h.claims.map((c) => c.statement), ...h.limitations]) {
      const cited = extractInlineCitations(text);
      for (const id of [...cited.event_ids, ...cited.frame_ids, ...cited.ioc_ids]) ids.add(id);
    }
  }
  return [...ids].sort();
}

function kindOf(id: string): "evt" | "frame" | "ioc" {
  return id.startsWith("evt-") ? "evt" : id.startsWith("frame-") ? "frame" : "ioc";
}


type Resolver = (caseId: string) => Promise<HuntDataPlanePort> | HuntDataPlanePort;

/** Kind of case source behind a citation kind, as reported in `unavailable_sources`. */
const SOURCE_OF_KIND = { evt: "events", frame: "packets", ioc: "intel" } as const;
export type EvidenceSourceKind = (typeof SOURCE_OF_KIND)[keyof typeof SOURCE_OF_KIND];

async function readRecords(run: PersistedHuntRun, ids: readonly string[], resolve?: Resolver) {
  if (!resolve) throw new Error("no data plane resolver is configured");
  const dataPlane = await resolve(run.case_id);
  assertDataPlaneBindsRun(run, dataPlane);
  if (!dataPlane.readCitedRecords) throw new Error("the case data plane cannot read cited records");
  return dataPlane.readCitedRecords(ids);
}

/** One evidence entry per id: receipt status first, then whether the case holds the record. */
function toEvidence(
  ids: readonly string[],
  records: readonly CitedEvidenceRecord[],
  receipt: CitationVerificationReceipt,
): GateContextEvidence[] {
  const byId = new Map(records.filter((r) => ids.includes(r.id)).map((r) => [r.id, r]));
  const missing = new Set([...receipt.missing_event_ids, ...receipt.missing_frame_ids, ...receipt.missing_ioc_ids]);
  const outOfScope = new Set(receipt.out_of_scope_ids);
  const ambiguous = new Set(receipt.ambiguous_ids);
  return ids.map((id): GateContextEvidence => {
    const rec = byId.get(id);
    const status: GateContextEvidence["status"] = outOfScope.has(id)
      ? "out_of_scope"
      : ambiguous.has(id)
        ? "ambiguous"
        : missing.has(id) || !rec
          ? "unresolved"
          : "verified";
    if (status !== "verified" || !rec) {
      return { id, kind: kindOf(id), status, timestamp_iso: null, title: "", fields: {} };
    }
    return {
      id,
      kind: rec.kind,
      status,
      timestamp_iso: rec.timestamp_iso,
      title: clean(rec.title),
      fields: flattenEvidenceFields(rec.record),
    };
  });
}

function unavailable(run: PersistedHuntRun, what: string, err?: unknown): GateContextError {
  const why = err === undefined ? "" : `: ${err instanceof Error ? err.message : String(err)}`;
  return new GateContextError("gate_context_unavailable", `${what} for hunt '${run.run_id}' is unavailable${why}`);
}

/** Reloadable, case-bound evidence for the incident and reviewed handoffs of a run. */
export async function buildRunEvidence(params: {
  readonly run: PersistedHuntRun;
  readonly resolveDataPlane?: Resolver;
}): Promise<{
  run_id: string;
  case_id: string;
  citation_receipt: CitationVerificationReceipt;
  evidence: GateContextEvidence[];
  evidence_truncated: boolean;
}> {
  const { run } = params;
  const receipt = run.citation_receipt;
  if (!receipt || !run.results["incident"]?.handoff) throw unavailable(run, "The incident handoff and citation receipt");
  if (receipt.case_id !== run.case_id || receipt.source_status !== "ok") {
    throw unavailable(run, "The incident citation verification");
  }
  const handoffs = [run.results["incident"].handoff, ...Object.values(run.reviewed_handoffs)];
  const allIds = citedIds(handoffs);
  const ids = allIds.slice(0, GATE_CONTEXT_MAX_EVIDENCE);
  let records: CitedEvidenceRecord[];
  try {
    records = await readRecords(run, ids, params.resolveDataPlane);
  } catch (err) {
    throw unavailable(run, "Cited evidence", err);
  }
  return {
    run_id: run.run_id,
    case_id: run.case_id,
    citation_receipt: scrubSecretValue(receipt),
    evidence: toEvidence(ids, records, receipt),
    evidence_truncated: allIds.length > ids.length,
  };
}

/** Every distinct cited id gets a status; above this the context fails closed instead of truncating. */
export const GATE_CONTEXT_MAX_CITED = 20_000;
/** Records returned inline by `hunt.gateContext`; the rest come from `hunt.gateEvidencePage`. */
export const GATE_CONTEXT_FIRST_PAGE = 200;
export const GATE_EVIDENCE_PAGE_MAX = 500;

export interface GateCitedStatus {
  readonly id: string;
  readonly kind: "evt" | "frame" | "ioc";
  readonly status: GateContextEvidence["status"];
}

export interface GateEvidencePage {
  readonly run_id: string;
  readonly gate: "incident" | "reconcile";
  readonly payload_sha256: string;
  readonly evidence: GateContextEvidence[];
  readonly evidence_total: number;
  readonly evidence_next_cursor: string | null;
}

/** The cited ids a gate decides on, with the receipt that gate was opened on. */
interface GateCitations {
  readonly kind: "incident" | "reconcile";
  readonly ids: string[];
  readonly receipt: CitationVerificationReceipt;
  /** Citation reconcile tolerates a source that is still down (statuses become `unchecked`). */
  readonly tolerateUnavailable: boolean;
}

function gateCitations(run: PersistedHuntRun): GateCitations | null {
  const gate = run.open_gate!;
  if (gate.gate === "incident") {
    const receipt = run.citation_receipt;
    const handoff = run.results["incident"]?.handoff;
    if (!receipt || !handoff) throw unavailable(run, "The incident handoff and citation receipt");
    if (receipt.case_id !== run.case_id || receipt.source_status !== "ok") {
      throw unavailable(run, "The incident citation verification");
    }
    return {
      kind: "incident",
      ids: citedIds([handoff, ...Object.values(run.reviewed_handoffs)]),
      receipt,
      tolerateUnavailable: false,
    };
  }
  if (gate.gate === RECONCILE_GATE) {
    const result = gate.unknown_step_id ? run.results[gate.unknown_step_id] : undefined;
    if ((gate.reason_code ?? result?.reason_code) !== "citation_source_unavailable") return null;
    if (!result?.unverified_handoff || !result.citation_receipt) {
      throw unavailable(run, `The unverified handoff and receipt of step '${String(gate.unknown_step_id)}'`);
    }
    return {
      kind: "reconcile",
      ids: citedIds([result.unverified_handoff]),
      receipt: result.citation_receipt,
      tolerateUnavailable: true,
    };
  }
  return null;
}

async function bindPlane(run: PersistedHuntRun, resolve?: Resolver): Promise<HuntDataPlanePort> {
  if (!resolve) throw new Error("no data plane resolver is configured");
  const dataPlane = await resolve(run.case_id);
  assertDataPlaneBindsRun(run, dataPlane);
  return dataPlane;
}

/**
 * Status of each id: the gate receipt's failures first (out of scope, ambiguous, missing), then a
 * fresh existence check against the run's own case. `plane === null` means the source is down.
 * Per-id and deterministic, so a page's statuses equal the same ids' entries in `cited`.
 */
async function statusesFor(
  run: PersistedHuntRun,
  ids: readonly string[],
  receipt: CitationVerificationReceipt,
  plane: HuntDataPlanePort | null,
): Promise<GateCitedStatus[]> {
  if (plane === null) {
    return ids.map((id) => ({ id, kind: kindOf(id), status: "unchecked" as const }));
  }
  const fresh = await plane.verifyCitations({
    case_id: run.case_id,
    event_ids: ids.filter((id) => kindOf(id) === "evt"),
    frame_ids: ids.filter((id) => kindOf(id) === "frame"),
    ioc_ids: ids.filter((id) => kindOf(id) === "ioc"),
  });
  if (fresh.source_status !== "ok") {
    throw new Error(fresh.diagnostic ?? "citation source unavailable");
  }
  const outOfScope = new Set([...receipt.out_of_scope_ids, ...fresh.out_of_scope_ids]);
  const ambiguous = new Set([...receipt.ambiguous_ids, ...fresh.ambiguous_ids]);
  const missing = new Set([
    ...receipt.missing_event_ids, ...receipt.missing_frame_ids, ...receipt.missing_ioc_ids,
    ...fresh.missing_event_ids, ...fresh.missing_frame_ids, ...fresh.missing_ioc_ids,
  ]);
  return ids.map((id) => ({
    id,
    kind: kindOf(id),
    status: outOfScope.has(id) ? "out_of_scope" : ambiguous.has(id) ? "ambiguous" : missing.has(id) ? "unresolved" : "verified",
  }));
}

/** Evidence entries for a slice of statuses: verified ids carry their scrubbed, capped record. */
async function recordsFor(statuses: readonly GateCitedStatus[], plane: HuntDataPlanePort | null): Promise<GateContextEvidence[]> {
  const verified = statuses.filter((s) => s.status === "verified").map((s) => s.id);
  let records: CitedEvidenceRecord[] = [];
  if (verified.length > 0) {
    if (!plane?.readCitedRecords) throw new Error("the case data plane cannot read cited records");
    records = await plane.readCitedRecords(verified);
  }
  const byId = new Map(records.map((r) => [r.id, r]));
  return statuses.map((s): GateContextEvidence => {
    const rec = s.status === "verified" ? byId.get(s.id) : undefined;
    if (!rec) return { id: s.id, kind: s.kind, status: s.status, timestamp_iso: null, title: "", fields: {} };
    return {
      id: s.id,
      kind: rec.kind,
      status: s.status,
      timestamp_iso: rec.timestamp_iso,
      title: clean(rec.title),
      fields: flattenEvidenceFields(rec.record),
    };
  });
}

interface CursorBody {
  readonly v: 1;
  readonly run_id: string;
  readonly gate: string;
  readonly payload_sha256: string;
  readonly offset: number;
}

function encodeCursor(body: CursorBody): string {
  return `gev1.${Buffer.from(JSON.stringify(body), "utf8").toString("base64url")}`;
}

function decodeCursor(cursor: string): CursorBody {
  const bad = () => new GateContextError("invalid_arguments", "Malformed evidence cursor");
  if (!cursor.startsWith("gev1.") || cursor.length > 2048) throw bad();
  let body: unknown;
  try {
    body = JSON.parse(Buffer.from(cursor.slice(5), "base64url").toString("utf8"));
  } catch {
    throw bad();
  }
  const b = body as Partial<CursorBody>;
  if (
    b === null || typeof b !== "object" || b.v !== 1 || typeof b.run_id !== "string" ||
    typeof b.gate !== "string" || typeof b.payload_sha256 !== "string" ||
    !Number.isInteger(b.offset) || (b.offset as number) < 0
  ) {
    throw bad();
  }
  return b as CursorBody;
}

/** Statuses of every cited id plus the first record page, shared by incident and citation reconcile. */
async function citedContext(run: PersistedHuntRun, c: GateCitations, resolve?: Resolver) {
  if (c.ids.length > GATE_CONTEXT_MAX_CITED) {
    throw unavailable(
      run,
      `The gate cites ${c.ids.length} distinct records, more than the ${GATE_CONTEXT_MAX_CITED} the daemon will verify for review; the context`,
    );
  }
  let plane: HuntDataPlanePort | null;
  let cited: GateCitedStatus[];
  try {
    plane = await bindPlane(run, resolve);
    cited = await statusesFor(run, c.ids, c.receipt, plane);
  } catch (err) {
    if (!c.tolerateUnavailable) throw unavailable(run, "Cited evidence", err);
    plane = null;
    cited = await statusesFor(run, c.ids, c.receipt, null);
  }
  const first = cited.slice(0, GATE_CONTEXT_FIRST_PAGE);
  let evidence: GateContextEvidence[];
  try {
    evidence = await recordsFor(first, plane);
  } catch (err) {
    throw unavailable(run, "Cited evidence", err);
  }
  const gate = run.open_gate!;
  return {
    citation_receipt: scrubSecretValue(c.receipt),
    cited,
    evidence,
    evidence_total: cited.length,
    evidence_next_cursor:
      first.length < cited.length
        ? encodeCursor({ v: 1, run_id: run.run_id, gate: gate.gate, payload_sha256: gate.payload_sha256, offset: first.length })
        : null,
    unavailable_sources:
      plane === null ? [...new Set(c.ids.map((id) => SOURCE_OF_KIND[kindOf(id)]))].sort() : [],
  };
}

/**
 * Read-only decision context for a run's open gate. Never mutates run or gate state; reads the
 * run's own durable state and, for incident and citation reconcile gates, its own case's records.
 */
export async function buildGateContext(params: {
  readonly run: PersistedHuntRun;
  readonly receipts: readonly DispatchReceiptRow[];
  readonly resolveDataPlane?: Resolver;
}): Promise<GateContext> {
  const { run } = params;
  const gate = run.open_gate;
  if (run.status !== "awaiting_gate" || !gate) {
    throw new GateContextError("no_open_gate", `Hunt '${run.run_id}' has no open gate`);
  }
  const base = { run_id: run.run_id, case_id: run.case_id, payload_sha256: gate.payload_sha256 };

  if (gate.gate === "scope") {
    return { ...base, gate: "scope", scope: { scope_text: clean(run.config.scopeText, 64 * 1024) } };
  }

  const citations = gateCitations(run);
  if (citations) {
    const ctx = await citedContext(run, citations, params.resolveDataPlane);
    const page = {
      citation_receipt: ctx.citation_receipt,
      cited: ctx.cited,
      evidence: ctx.evidence,
      evidence_total: ctx.evidence_total,
      evidence_next_cursor: ctx.evidence_next_cursor,
    };
    if (citations.kind === "incident") return { ...base, gate: "incident", incident: page };
    return {
      ...base,
      gate: "reconcile",
      reconcile: {
        reason_code: "citation_source_unavailable",
        unavailable_sources: ctx.unavailable_sources as EvidenceSourceKind[],
        ...page,
      },
    };
  }

  if (gate.gate === RECONCILE_GATE) {
    const stepId = gate.unknown_step_id;
    const receipts = params.receipts
      .filter((r) => r.run_id === run.run_id && r.step_id === stepId && r.status === "previous_dispatch_unknown")
      .map((r): GateContextReconcileReceipt => {
        const profile = profileForRunStep(run, r.step_id);
        if (!profile) throw unavailable(run, `Step '${r.step_id}'`);
        return {
          execution_id: r.execution_id,
          session_id: r.session_id,
          input_id: r.input_id,
          step_id: r.step_id,
          profile,
          reserved_at: r.reserved_at,
          reason_code: "previous_dispatch_unknown",
        };
      });
    if (receipts.length === 0) {
      throw unavailable(run, `The reconcile context (${gate.reason_code ?? "unknown"})`);
    }
    return { ...base, gate: "reconcile", reconcile: { reason_code: "previous_dispatch_unknown", receipts } };
  }

  throw new GateContextError("gate_context_unavailable", `Gate '${gate.gate}' has no decision context`);
}

/**
 * The next records for the run's CURRENT open gate. The cursor is bound to the run, the gate and
 * its payload digest: another run's cursor is refused, and a cursor from a gate that has since
 * changed is `stale_cursor`. Read-only.
 */
export async function buildGateEvidencePage(params: {
  readonly run: PersistedHuntRun;
  readonly cursor: string;
  readonly limit: number;
  readonly resolveDataPlane?: Resolver;
}): Promise<GateEvidencePage> {
  const { run } = params;
  const body = decodeCursor(params.cursor);
  if (body.run_id !== run.run_id) {
    throw new GateContextError("invalid_arguments", `Evidence cursor belongs to another hunt, not '${run.run_id}'`);
  }
  const gate = run.open_gate;
  if (run.status !== "awaiting_gate" || !gate) {
    throw new GateContextError("no_open_gate", `Hunt '${run.run_id}' has no open gate`);
  }
  if (body.gate !== gate.gate || body.payload_sha256 !== gate.payload_sha256) {
    throw new GateContextError("stale_cursor", `Evidence cursor is for a gate that is no longer open on '${run.run_id}'`);
  }
  const citations = gateCitations(run);
  if (!citations) {
    throw new GateContextError("gate_context_unavailable", `Gate '${gate.gate}' has no cited evidence`);
  }
  if (citations.ids.length > GATE_CONTEXT_MAX_CITED) {
    throw unavailable(run, "Cited evidence over the review cap");
  }
  if (body.offset > citations.ids.length) {
    throw new GateContextError("invalid_arguments", "Evidence cursor is past the end of the cited records");
  }
  const sliceIds = citations.ids.slice(body.offset, body.offset + params.limit);
  let evidence: GateContextEvidence[];
  try {
    let plane: HuntDataPlanePort | null;
    let statuses: GateCitedStatus[];
    try {
      plane = await bindPlane(run, params.resolveDataPlane);
      statuses = await statusesFor(run, sliceIds, citations.receipt, plane);
    } catch (err) {
      if (!citations.tolerateUnavailable) throw err;
      plane = null;
      statuses = await statusesFor(run, sliceIds, citations.receipt, null);
    }
    evidence = await recordsFor(statuses, plane);
  } catch (err) {
    throw unavailable(run, "Cited evidence", err);
  }
  const end = body.offset + sliceIds.length;
  return {
    run_id: run.run_id,
    gate: citations.kind,
    payload_sha256: gate.payload_sha256,
    evidence,
    evidence_total: citations.ids.length,
    evidence_next_cursor:
      end < citations.ids.length ? encodeCursor({ ...body, offset: end }) : null,
  };
}
