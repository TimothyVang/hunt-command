/**
 * Projects the daemon's `hunt.gateContext` and `hunt.inspectTranscriptPage` results into workbench types.
 *
 * Contract agreed with packages/daemon (fix-desktop <-> fix-daemon, PR #5 F4/F8). Every result is
 * validated here; anything missing, mismatched or failed becomes `activeGate.contextError`, which
 * `missingGateContextReason` turns into a disabled Approve button (fail closed). Rejecting stays possible.
 */
import { z } from "zod";
import {
  extractInlineCitations,
  ProfileIdSchema,
  type Handoff,
  type ProfileId,
} from "@hunt-command/shared";
import type {
  ActiveGatePrompt,
  CitationStatusEntry,
  CitationVerificationReceipt,
  DissectorEventRow,
  EvidenceRecordDetail,
  TranscriptPageSlice,
} from "../shared/workbench-types.ts";

const FieldValueSchema = z.union([z.string(), z.number(), z.boolean(), z.array(z.string())]);

const DaemonCitationReceiptSchema = z
  .object({
    verified: z.boolean(),
    case_id: z.string(),
    total_checked: z.number().int().nonnegative(),
    missing_event_ids: z.array(z.string()),
    missing_frame_ids: z.array(z.string()),
    missing_ioc_ids: z.array(z.string()),
    ambiguous_ids: z.array(z.string()),
    out_of_scope_ids: z.array(z.string()),
    source_status: z.enum(["ok", "unavailable"]),
    diagnostic: z.string().optional(),
  })
  .passthrough();

const EvidenceSchema = z
  .object({
    id: z.string().min(1).max(256),
    kind: z.enum(["evt", "frame", "ioc"]),
    status: z.enum(["verified", "unresolved", "out_of_scope", "ambiguous"]),
    timestamp_iso: z.string().nullable(),
    title: z.string().max(4096),
    fields: z.record(FieldValueSchema),
  })
  .strict();

export const GateContextResultSchema = z
  .object({
    run_id: z.string().min(1),
    case_id: z.string().min(1),
    gate: z.enum(["scope", "incident", "reconcile"]),
    payload_sha256: z.string().regex(/^[a-f0-9]{64}$/i),
    scope: z.object({ scope_text: z.string().min(1) }).strict().optional(),
    incident: z
      .object({
        citation_receipt: DaemonCitationReceiptSchema,
        evidence: z.array(EvidenceSchema).max(500),
        evidence_truncated: z.boolean(),
      })
      .strict()
      .optional(),
    // Tagged on reason_code: a crash left a dispatch's outcome unknown, or the citation source was
    // unreachable while verifying citations. Both are approvable once their context is shown.
    reconcile: z
      .discriminatedUnion("reason_code", [
        z
          .object({
            reason_code: z.literal("previous_dispatch_unknown"),
            receipts: z
              .array(
                z
                  .object({
                    execution_id: z.string().min(1),
                    session_id: z.string().min(1),
                    input_id: z.string().min(1),
                    step_id: z.string().min(1),
                    profile: ProfileIdSchema,
                    reserved_at: z.string().min(1),
                    reason_code: z.literal("previous_dispatch_unknown"),
                  })
                  .strict(),
              )
              .min(1),
          })
          .strict(),
        z
          .object({
            reason_code: z.literal("citation_source_unavailable"),
            citation_receipt: DaemonCitationReceiptSchema,
            unavailable_sources: z.array(z.string()),
            evidence: z.array(EvidenceSchema).max(500),
            evidence_truncated: z.boolean().optional(),
          })
          .strict(),
      ])
      .optional(),
  })
  .strict();

export type GateContextResult = z.infer<typeof GateContextResultSchema>;

export const LiveTranscriptPageSchema = z
  .object({
    run_id: z.string().min(1),
    step_id: z.string().min(1),
    profile: ProfileIdSchema,
    byte_offset: z.number().int().nonnegative(),
    byte_length: z.number().int().nonnegative(),
    total_bytes: z.number().int().nonnegative(),
    has_more: z.boolean(),
    next_byte_offset: z.number().int().nonnegative(),
    fence_nonce: z.string().regex(/^[0-9a-f]{32}$/),
    content: z.string(),
  })
  .strict();

/**
 * Removes the daemon's per-call untrusted-output fence. The page must be wrapped in exactly
 * `<untrusted_tool_result_<nonce>>` + newline ... newline + `</untrusted_tool_result_<nonce>>`; anything
 * else is refused. The inner text is still untrusted model output and is rendered as inert text only.
 */
export function unwrapFencedPage(content: string, nonce: string): string {
  const open = `<untrusted_tool_result_${nonce}>\n`;
  const close = `\n</untrusted_tool_result_${nonce}>`;
  if (!content.startsWith(open) || !content.endsWith(close) || content.length < open.length + close.length) {
    throw new Error("Transcript page is not wrapped in the expected untrusted-output fence.");
  }
  return content.slice(open.length, content.length - close.length);
}

export function projectTranscriptPage(raw: unknown, huntId: string, stepId: string): TranscriptPageSlice {
  const page = LiveTranscriptPageSchema.parse(raw);
  if (page.run_id !== huntId || page.step_id !== stepId) {
    throw new Error(`Daemon returned a transcript page for ${page.run_id}/${page.step_id}, not ${huntId}/${stepId}.`);
  }
  const content = unwrapFencedPage(page.content, page.fence_nonce);
  return {
    huntId: page.run_id,
    stepId: page.step_id,
    profile: page.profile,
    byteOffset: page.byte_offset,
    byteLength: page.byte_length,
    totalBytes: page.total_bytes,
    hasMore: page.has_more,
    nextByteOffset: page.next_byte_offset,
    content,
  };
}

export interface OpenGateInfo {
  readonly gate: "scope" | "incident" | "reconcile";
  readonly payload_sha256: string;
  readonly opened_at: string;
  readonly expires_at: string;
}

export interface LiveGateProjection {
  activeGate: ActiveGatePrompt;
  /** Receipt for the claims pane (empty entries when there is no incident context). */
  citationReceipt: CitationVerificationReceipt | null;
  evidenceCatalog: Record<string, EvidenceRecordDetail>;
  events: DissectorEventRow[];
  /** Per-citation status, for claim rows' inline citation chips. */
  citationStatus: ReadonlyMap<string, "verified" | "unresolved" | "out_of_scope">;
}

function fieldText(fields: Record<string, unknown>, ...keys: string[]): string {
  for (const key of keys) {
    const v = fields[key];
    if (typeof v === "string") return v;
    if (typeof v === "number" || typeof v === "boolean") return String(v);
    if (Array.isArray(v)) return v.join(", ");
  }
  return "";
}

/** Citation ids referenced by each claim / limitation of the reviewed handoffs. */
function citedReferences(handoffs: readonly Handoff[]) {
  const refs = new Map<string, { kind: "evt" | "frame" | "ioc"; referencedIn: CitationStatusEntry["referencedIn"][number][]; claimIds: Set<string> }>();
  const add = (text: string, sourceKind: "claim" | "limitation", sourceId: string, stepId: string, claimId?: string) => {
    const ex = extractInlineCitations(text);
    const items = [
      ...ex.event_ids.map((id) => ({ id, kind: "evt" as const })),
      ...ex.frame_ids.map((id) => ({ id, kind: "frame" as const })),
      ...ex.ioc_ids.map((id) => ({ id, kind: "ioc" as const })),
    ];
    for (const item of items) {
      let entry = refs.get(item.id);
      if (!entry) {
        entry = { kind: item.kind, referencedIn: [], claimIds: new Set() };
        refs.set(item.id, entry);
      }
      if (!entry.referencedIn.some((r) => r.sourceKind === sourceKind && r.sourceId === sourceId)) {
        entry.referencedIn.push({ sourceKind, sourceId, stepId });
      }
      if (claimId) entry.claimIds.add(claimId);
    }
  };
  for (const h of handoffs) {
    for (const c of h.claims) add(c.statement, "claim", c.claim_id, h.step_id, c.claim_id);
    h.limitations.forEach((text, i) => add(text, "limitation", `${h.step_id}:limitation-${i + 1}`, h.step_id));
  }
  return refs;
}

/**
 * Builds the active gate prompt (and incident evidence) from `hunt.status`'s open gate plus the
 * `hunt.gateContext` result. `rawContext` is the RPC result, or the Error the RPC failed with. Scope
 * gates use `statusScopeText` (hunt.status `config.scopeText`, the text the scope digest covers).
 */
export function projectLiveGate(
  runId: string,
  openGate: OpenGateInfo,
  handoffs: readonly Handoff[],
  rawContext: unknown,
  statusScopeText?: string,
): LiveGateProjection {
  const base: ActiveGatePrompt = {
    gate: openGate.gate,
    huntId: runId,
    openedAtIso: openGate.opened_at,
    expiresAtIso: openGate.expires_at,
    payloadSha256: openGate.payload_sha256,
  };
  const fail = (reason: string): LiveGateProjection => ({
    activeGate: { ...base, contextError: reason },
    citationReceipt: null,
    evidenceCatalog: {},
    events: [],
    citationStatus: new Map(),
  });

  if (openGate.gate === "scope") {
    const text = statusScopeText?.trim() ? statusScopeText : undefined;
    if (!text) return fail("hunt.status has no scope text for the open scope gate");
    return { activeGate: { ...base, scopeText: text }, citationReceipt: null, evidenceCatalog: {}, events: [], citationStatus: new Map() };
  }

  if (rawContext instanceof Error) {
    return fail(`hunt.gateContext failed: ${rawContext.message}`);
  }
  const parsed = GateContextResultSchema.safeParse(rawContext);
  if (!parsed.success) {
    return fail(`hunt.gateContext returned an invalid result: ${parsed.error.issues[0]?.message ?? "schema mismatch"}`);
  }
  const ctx = parsed.data;
  if (ctx.run_id !== runId) return fail(`gate context is for run '${ctx.run_id}', not '${runId}'`);
  if (ctx.gate !== openGate.gate) return fail(`gate context is for the '${ctx.gate}' gate, but '${openGate.gate}' is open`);
  if (ctx.payload_sha256.toLowerCase() !== openGate.payload_sha256.toLowerCase()) {
    return fail("gate context digest does not match the open gate (stale or mismatched context)");
  }

  if (ctx.gate === "reconcile") {
    const reconcile = ctx.reconcile;
    if (!reconcile) return fail("reconcile gate context is missing");
    if (reconcile.reason_code === "previous_dispatch_unknown") {
      const [receipt, ...rest] = reconcile.receipts;
      return {
        activeGate: {
          ...base,
          reconcileContext: {
            executionId: receipt!.execution_id,
            sessionId: receipt!.session_id,
            inputId: receipt!.input_id,
            stepId: receipt!.step_id,
            profile: receipt!.profile as ProfileId,
            reservedAtIso: receipt!.reserved_at,
            reasonCode: "previous_dispatch_unknown",
            ...(rest.length > 0 ? { additionalReceiptCount: rest.length } : {}),
          },
        },
        citationReceipt: null,
        evidenceCatalog: {},
        events: [],
        citationStatus: new Map(),
      };
    }
    // citation_source_unavailable: the reason itself is the context; show what could and could not be checked.
    const projected = projectEvidence(handoffs, reconcile.evidence, reconcile.evidence_truncated ?? false, reconcile.citation_receipt.verified);
    if (projected.uncovered) {
      return fail(`gate context does not cover cited ids: ${projected.uncovered.slice(0, 5).join(", ")}`);
    }
    return {
      activeGate: {
        ...base,
        reconcileContext: {
          reasonCode: "citation_source_unavailable",
          unavailableSources: reconcile.unavailable_sources,
          citationReceipt: projected.receipt,
        },
      },
      citationReceipt: projected.receipt,
      evidenceCatalog: projected.evidenceCatalog,
      events: projected.events,
      citationStatus: projected.status,
    };
  }

  const incident = ctx.incident;
  if (!incident) return fail("incident gate context has no citation receipt or evidence");
  if (incident.citation_receipt.source_status !== "ok") {
    return fail(`citation backend unavailable: ${incident.citation_receipt.diagnostic ?? "source_status=unavailable"}`);
  }
  const projected = projectEvidence(handoffs, incident.evidence, incident.evidence_truncated, incident.citation_receipt.verified);
  if (projected.uncovered) {
    return fail(`gate context does not cover cited ids: ${projected.uncovered.slice(0, 5).join(", ")}`);
  }
  const { receipt, evidenceCatalog, events, status } = projected;
  const claims = handoffs.flatMap((h) => h.claims);
  const reviews = handoffs.flatMap((h) => h.reviews);
  return {
    activeGate: {
      ...base,
      incidentSummary: {
        citationReceipt: receipt,
        observedCount: claims.filter((c) => c.kind === "observed").length,
        findingCount: claims.filter((c) => c.kind === "finding").length,
        inferenceCount: claims.filter((c) => c.kind === "inference").length,
        hypothesisCount: claims.filter((c) => c.kind === "hypothesis").length,
        limitationCount: handoffs.reduce((n, h) => n + h.limitations.length, 0),
        purpleVerdictCounts: {
          review_ready: reviews.filter((r) => r.disposition === "review_ready").length,
          needs_validation: reviews.filter((r) => r.disposition === "needs_validation").length,
          needs_revision: reviews.filter((r) => r.disposition === "needs_revision").length,
        },
      },
    },
    citationReceipt: receipt,
    evidenceCatalog,
    events,
    citationStatus: status,
  };
}

/** Citation receipt, evidence catalog and Dissector events from the daemon's evidence entries. */
function projectEvidence(
  handoffs: readonly Handoff[],
  evidence: z.infer<typeof EvidenceSchema>[],
  truncated: boolean,
  receiptVerified: boolean,
):
  | { uncovered: string[] }
  | {
      uncovered?: undefined;
      receipt: CitationVerificationReceipt;
      evidenceCatalog: Record<string, EvidenceRecordDetail>;
      events: DissectorEventRow[];
      status: Map<string, "verified" | "unresolved" | "out_of_scope">;
    } {
  const refs = citedReferences(handoffs);
  const byId = new Map(evidence.map((e) => [e.id, e]));
  if (!truncated) {
    const uncovered = [...refs.keys()].filter((id) => !byId.has(id));
    if (uncovered.length > 0) {
      return { uncovered };
    }
  }

  const status = new Map<string, "verified" | "unresolved" | "out_of_scope">();
  const entries: CitationStatusEntry[] = [];
  const evidenceCatalog: Record<string, EvidenceRecordDetail> = {};
  const events: DissectorEventRow[] = [];
  let verified = 0;
  let unresolved = 0;
  let outOfScope = 0;
  for (const ev of [...evidence].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))) {
    const s = ev.status === "ambiguous" ? "unresolved" : ev.status;
    status.set(ev.id, s);
    if (s === "verified") verified++;
    else if (s === "out_of_scope") outOfScope++;
    else unresolved++;
    const ref = refs.get(ev.id);
    entries.push({
      citationId: ev.id,
      kind: ev.kind,
      status: s,
      referencedIn: ref?.referencedIn ?? [],
      ...(ev.timestamp_iso ? { timestampIso: ev.timestamp_iso } : {}),
      ...(ev.title ? { summary: ev.title } : {}),
    });
    evidenceCatalog[ev.id] = {
      id: ev.id,
      kind: ev.kind,
      verified: s === "verified",
      ...(ev.timestamp_iso ? { timestampIso: ev.timestamp_iso } : {}),
      title: ev.title || ev.id,
      fields: ev.fields,
      citingClaimIds: [...(ref?.claimIds ?? [])],
      linkedEntityIds: [],
    };
    if (ev.kind === "evt" && s === "verified") {
      const ts = ev.timestamp_iso ?? fieldText(ev.fields, "@timestamp");
      const tsMs = Date.parse(ts);
      events.push({
        eventId: ev.id,
        timestampIso: ts,
        timestampMs: Number.isNaN(tsMs) ? 0 : tsMs,
        hostName: fieldText(ev.fields, "host.name", "host.hostname"),
        category: fieldText(ev.fields, "event.category"),
        action: fieldText(ev.fields, "event.action"),
        userName: fieldText(ev.fields, "user.name"),
        processName: fieldText(ev.fields, "process.name"),
        commandLine: fieldText(ev.fields, "process.command_line"),
        sourceIp: fieldText(ev.fields, "source.ip"),
        destinationIp: fieldText(ev.fields, "destination.ip"),
        message: fieldText(ev.fields, "message") || ev.title,
        entityIds: [],
      });
    }
  }
  const receipt: CitationVerificationReceipt = {
    totalCited: entries.length,
    verifiedCount: verified,
    unresolvedCount: unresolved,
    outOfScopeCount: outOfScope,
    allVerified: receiptVerified && unresolved === 0 && outOfScope === 0,
    entries,
  };
  return { receipt, evidenceCatalog, events: events.sort((a, b) => a.timestampMs - b.timestampMs), status };
}
