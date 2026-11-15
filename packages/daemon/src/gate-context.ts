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
  readonly status: "verified" | "unresolved" | "out_of_scope" | "ambiguous";
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
  readonly incident?: {
    readonly citation_receipt: CitationVerificationReceipt;
    readonly evidence: GateContextEvidence[];
    readonly evidence_truncated: boolean;
  };
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
      readonly citation_receipt: CitationVerificationReceipt;
      /** Source kinds that could not be read while building this context (then evidence is []). */
      readonly unavailable_sources: Array<"events" | "packets" | "intel">;
      readonly evidence: GateContextEvidence[];
      readonly evidence_truncated: boolean;
    };

export type GateContextErrorCode = "no_open_gate" | "gate_context_unavailable";

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

  if (gate.gate === RECONCILE_GATE) {
    const stepId = gate.unknown_step_id;
    const result = stepId ? run.results[stepId] : undefined;
    const reason = gate.reason_code ?? result?.reason_code;

    if (reason === "citation_source_unavailable") {
      const handoff = result?.unverified_handoff;
      const receipt = result?.citation_receipt;
      if (!handoff || !receipt) {
        throw unavailable(run, `The unverified handoff and receipt of step '${String(stepId)}'`);
      }
      const allIds = citedIds([handoff]);
      const ids = allIds.slice(0, GATE_CONTEXT_MAX_EVIDENCE);
      // The source may still be down: then no id can be checked and every cited kind is reported.
      let checkedIds: string[] = ids;
      let records: CitedEvidenceRecord[] = [];
      let unavailableSources: EvidenceSourceKind[] = [];
      try {
        records = await readRecords(run, ids, params.resolveDataPlane);
      } catch {
        checkedIds = [];
        unavailableSources = [...new Set(ids.map((id) => SOURCE_OF_KIND[kindOf(id)]))].sort();
      }
      return {
        ...base,
        gate: "reconcile",
        reconcile: {
          reason_code: "citation_source_unavailable",
          citation_receipt: scrubSecretValue(receipt),
          unavailable_sources: unavailableSources,
          evidence: toEvidence(checkedIds, records, receipt),
          evidence_truncated: allIds.length > ids.length,
        },
      };
    }

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
      throw unavailable(run, `The reconcile context (${reason ?? "unknown"})`);
    }
    return { ...base, gate: "reconcile", reconcile: { reason_code: "previous_dispatch_unknown", receipts } };
  }

  if (gate.gate !== "incident") {
    throw new GateContextError("gate_context_unavailable", `Gate '${gate.gate}' has no decision context`);
  }
  const receipt = run.citation_receipt;
  if (!receipt) throw unavailable(run, "The incident citation receipt");
  const handoffs = [
    ...(run.results["incident"]?.handoff ? [run.results["incident"].handoff] : []),
    ...Object.values(run.reviewed_handoffs),
  ];
  const allIds = citedIds(handoffs);
  const ids = allIds.slice(0, GATE_CONTEXT_MAX_EVIDENCE);
  let records: CitedEvidenceRecord[];
  try {
    records = await readRecords(run, ids, params.resolveDataPlane);
  } catch (err) {
    throw unavailable(run, "Cited evidence", err);
  }
  return {
    ...base,
    gate: "incident",
    incident: {
      citation_receipt: scrubSecretValue(receipt),
      evidence: toEvidence(ids, records, receipt),
      evidence_truncated: allIds.length > ids.length,
    },
  };
}
