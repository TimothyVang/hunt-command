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
  readonly reconcile?: { readonly receipts: GateContextReconcileReceipt[] };
}

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

/**
 * Read-only decision context for a run's open gate. Never mutates run or gate state; reads the
 * run's own durable state and, for an incident gate, the records of the run's own case.
 */
export async function buildGateContext(params: {
  readonly run: PersistedHuntRun;
  readonly receipts: readonly DispatchReceiptRow[];
  readonly resolveDataPlane?: (caseId: string) => Promise<HuntDataPlanePort> | HuntDataPlanePort;
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
    const receipts = params.receipts
      .filter(
        (r) =>
          r.run_id === run.run_id &&
          r.step_id === gate.unknown_step_id &&
          r.status === "previous_dispatch_unknown",
      )
      .map((r): GateContextReconcileReceipt => {
        const profile = profileForRunStep(run, r.step_id);
        if (!profile) {
          throw new GateContextError("gate_context_unavailable", `Step '${r.step_id}' is not in hunt '${run.run_id}'`);
        }
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
      throw new GateContextError(
        "gate_context_unavailable",
        `Reconcile gate on hunt '${run.run_id}' (${gate.reason_code ?? "unknown"}) has no previous_dispatch_unknown receipt`,
      );
    }
    return { ...base, gate: "reconcile", reconcile: { receipts } };
  }

  if (gate.gate !== "incident") {
    throw new GateContextError("gate_context_unavailable", `Gate '${gate.gate}' has no decision context`);
  }
  const receipt = run.citation_receipt;
  if (!receipt) {
    throw new GateContextError("gate_context_unavailable", `Incident gate on hunt '${run.run_id}' has no citation receipt`);
  }
  const handoffs = [
    ...(run.results["incident"]?.handoff ? [run.results["incident"].handoff] : []),
    ...Object.values(run.reviewed_handoffs),
  ];
  const allIds = citedIds(handoffs);
  const ids = allIds.slice(0, GATE_CONTEXT_MAX_EVIDENCE);

  let records: CitedEvidenceRecord[];
  try {
    if (!params.resolveDataPlane) throw new Error("no data plane resolver is configured");
    const dataPlane = await params.resolveDataPlane(run.case_id);
    assertDataPlaneBindsRun(run, dataPlane);
    if (!dataPlane.readCitedRecords) throw new Error("the case data plane cannot read cited records");
    records = await dataPlane.readCitedRecords(ids);
  } catch (err) {
    throw new GateContextError(
      "gate_context_unavailable",
      `Cited evidence for hunt '${run.run_id}' is unavailable: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  const byId = new Map(records.filter((r) => ids.includes(r.id)).map((r) => [r.id, r]));
  const missing = new Set([...receipt.missing_event_ids, ...receipt.missing_frame_ids, ...receipt.missing_ioc_ids]);
  const outOfScope = new Set(receipt.out_of_scope_ids);
  const ambiguous = new Set(receipt.ambiguous_ids);

  const evidence = ids.map((id): GateContextEvidence => {
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

  return {
    ...base,
    gate: "incident",
    incident: {
      citation_receipt: scrubSecretValue(receipt),
      evidence,
      evidence_truncated: allIds.length > ids.length,
    },
  };
}
