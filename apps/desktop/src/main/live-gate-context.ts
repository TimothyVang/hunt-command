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
  HUNT_WAVES,
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

const CitedStatusSchema = z.enum(["verified", "unresolved", "out_of_scope", "ambiguous", "unchecked"]);

/** Every distinct cited id with its status: complete, so approval coverage never depends on record pages. */
export const MAX_CITED_IDS = 20_000;
const CitedSchema = z
  .object({ id: z.string().min(1).max(256), kind: z.enum(["evt", "frame", "ioc"]), status: CitedStatusSchema })
  .strict();

/** Records arrive in pages of at most this many on hunt.gateContext; hunt.gateEvidencePage returns more. */
export const FIRST_EVIDENCE_PAGE_MAX = 200;
export const EVIDENCE_PAGE_LIMIT = 200;
/** Page size for reading the rest of a completed run's records (the daemon's maximum). */
export const RUN_EVIDENCE_PAGE_LIMIT = 500;

/**
 * The step a reconcile gate decides, resolved by the daemon exactly as planGateTransition does (F17).
 * Required on the wire; if it does not match the step the gate is about, the card cannot say what
 * Approve does, so approval is disabled.
 */
const AffectedStepSchema = z
  .object({
    step_id: z.string().min(1),
    profile: ProfileIdSchema,
    wave: z.enum(HUNT_WAVES),
    optional: z.boolean(),
    approve_transition: z.enum(["reconcile_drop", "reconcile_halt"]),
    reject_reason_code: z.literal("reconcile_rejected"),
  })
  .strict();

function projectAffectedStep(raw: z.infer<typeof AffectedStepSchema> | undefined, expectedStepId?: string) {
  if (!raw) return undefined;
  if (expectedStepId !== undefined && raw.step_id !== expectedStepId) return undefined;
  if ((raw.approve_transition === "reconcile_drop") !== raw.optional) return undefined;
  return {
    stepId: raw.step_id,
    profile: raw.profile as ProfileId,
    wave: raw.wave,
    optional: raw.optional,
    approveTransition: raw.approve_transition,
  };
}

const EvidenceSchema = z
  .object({
    id: z.string().min(1).max(256),
    kind: z.enum(["evt", "frame", "ioc"]),
    status: CitedStatusSchema,
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
        cited: z.array(CitedSchema).max(MAX_CITED_IDS),
        evidence: z.array(EvidenceSchema).max(FIRST_EVIDENCE_PAGE_MAX),
        evidence_total: z.number().int().nonnegative(),
        evidence_next_cursor: z.string().min(1).nullable(),
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
            affected_step: AffectedStepSchema,
          })
          .strict(),
        z
          .object({
            reason_code: z.literal("citation_source_unavailable"),
            citation_receipt: DaemonCitationReceiptSchema,
            unavailable_sources: z.array(z.enum(["events", "packets", "intel"])),
            cited: z.array(CitedSchema).max(MAX_CITED_IDS),
            evidence: z.array(EvidenceSchema).max(FIRST_EVIDENCE_PAGE_MAX),
            evidence_total: z.number().int().nonnegative(),
            evidence_next_cursor: z.string().min(1).nullable(),
            affected_step: AffectedStepSchema,
          })
          .strict(),
      ])
      .optional(),
  })
  .strict();

export type GateContextResult = z.infer<typeof GateContextResultSchema>;

/** Completed-run evidence (hunt.evidence): the same complete `cited` statuses and paged records as a gate. */
const LiveEvidenceResultSchema = z.object({
  run_id: z.string().min(1),
  case_id: z.string().min(1),
  citation_receipt: DaemonCitationReceiptSchema,
  cited: z.array(CitedSchema.extend({ status: z.enum(["verified", "unresolved", "out_of_scope", "ambiguous"]) })).max(MAX_CITED_IDS),
  evidence: z.array(EvidenceSchema.extend({ status: z.enum(["verified", "unresolved", "out_of_scope", "ambiguous"]) })).max(FIRST_EVIDENCE_PAGE_MAX),
  evidence_total: z.number().int().nonnegative(),
  evidence_next_cursor: z.string().min(1).nullable(),
}).strict();

export const GateEvidencePageSchema = z
  .object({
    run_id: z.string().min(1),
    gate: z.enum(["incident", "reconcile"]),
    payload_sha256: z.string().regex(/^[a-f0-9]{64}$/i),
    evidence: z.array(EvidenceSchema).max(500),
    evidence_total: z.number().int().nonnegative(),
    evidence_next_cursor: z.string().min(1).nullable(),
  })
  .strict();

/** One hunt.evidencePage result: further records of a completed run, in `cited` order. */
const RunEvidencePageSchema = z
  .object({
    run_id: z.string().min(1),
    evidence: z.array(EvidenceSchema).max(RUN_EVIDENCE_PAGE_LIMIT),
    evidence_total: z.number().int().nonnegative(),
    evidence_next_cursor: z.string().min(1).nullable(),
  })
  .strict();

export type CitedEntry = z.infer<typeof CitedSchema>;
export type EvidenceEntry = z.infer<typeof EvidenceSchema>;

/** Main-process paging state for a gate's cited records (the cursor never reaches the renderer). */
export interface GateEvidencePaging {
  readonly runId: string;
  readonly gate: "incident" | "reconcile";
  readonly payloadSha256: string;
  readonly cited: readonly CitedEntry[];
  loaded: number;
  nextCursor: string | null;
}

/**
 * Checks that `evidence` is exactly the next slice of `cited` starting at `offset` (same ids, kinds and
 * statuses, in order). Returns an error message, or null when it is a faithful continuation.
 */
function checkEvidenceSlice(cited: readonly CitedEntry[], offset: number, evidence: readonly EvidenceEntry[]): string | null {
  if (offset + evidence.length > cited.length) return "evidence page runs past the cited list";
  for (let i = 0; i < evidence.length; i++) {
    const c = cited[offset + i]!;
    const e = evidence[i]!;
    if (c.id !== e.id || c.kind !== e.kind || c.status !== e.status) {
      return `evidence record ${e.id} does not match cited entry ${offset + i} (${c.id})`;
    }
  }
  return null;
}

/**
 * Validates one hunt.gateEvidencePage result against the paging state and returns its records. Throws on
 * any mismatch (other run, gate or digest, out-of-order or altered records), so a page is never merged
 * unless it continues the complete `cited` list exactly.
 */
export function projectEvidencePage(raw: unknown, paging: GateEvidencePaging): { records: EvidenceEntry[]; nextCursor: string | null } {
  const page = GateEvidencePageSchema.parse(raw);
  if (page.run_id !== paging.runId || page.gate !== paging.gate || page.payload_sha256.toLowerCase() !== paging.payloadSha256.toLowerCase()) {
    throw new Error("Evidence page is for a different run, gate or gate digest; refresh the gate.");
  }
  if (page.evidence_total !== paging.cited.length) throw new Error("Evidence page total does not match the cited list.");
  const err = checkEvidenceSlice(paging.cited, paging.loaded, page.evidence);
  if (err) throw new Error(`Evidence page rejected: ${err}.`);
  if (page.evidence.length === 0 && page.evidence_next_cursor !== null) throw new Error("Evidence page is empty but claims more pages.");
  if (page.evidence_next_cursor === null && paging.loaded + page.evidence.length !== paging.cited.length) {
    throw new Error("Evidence pages ended before every cited record was returned.");
  }
  return { records: page.evidence, nextCursor: page.evidence_next_cursor };
}

/** Projects additional records into catalog entries and Dissector events (statuses come from `cited`). */
export function projectEvidenceRecords(handoffs: readonly Handoff[], records: readonly EvidenceEntry[]): {
  evidenceCatalog: Record<string, EvidenceRecordDetail>;
  events: DissectorEventRow[];
} {
  const refs = citedReferences(handoffs);
  const evidenceCatalog: Record<string, EvidenceRecordDetail> = {};
  const events: DissectorEventRow[] = [];
  for (const ev of records) addRecord(ev, refs.get(ev.id), evidenceCatalog, events);
  return { evidenceCatalog, events };
}

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
  /** Main-process-only state for loading further record pages (never sent to the renderer). */
  pagingState?: GateEvidencePaging;
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
 * `hunt.gateContext` result. `rawContext` is the RPC result, or the Error the RPC failed with.
 * Scope gates show both the operator's original text and the generated handoff.
 */
export function projectLiveGate(
  runId: string,
  openGate: OpenGateInfo,
  handoffs: readonly Handoff[],
  rawContext: unknown,
  statusScopeText?: string,
  reconcileHandoff?: Handoff,
): LiveGateProjection {
  const base: ActiveGatePrompt = {
    gate: openGate.gate,
    huntId: runId,
    openedAtIso: openGate.opened_at,
    expiresAtIso: openGate.expires_at,
    payloadSha256: openGate.payload_sha256,
  };
  const incidentHandoff = openGate.gate === "incident" ? handoffs.find((h) => h.step_id === "incident") : undefined;
  if (incidentHandoff) base.incidentHandoff = incidentHandoff;
  const fail = (reason: string): LiveGateProjection => ({
    activeGate: { ...base, contextError: reason },
    citationReceipt: null,
    evidenceCatalog: {},
    events: [],
    citationStatus: new Map(),
  });

  if (openGate.gate === "scope") {
    const text = statusScopeText?.trim() ? statusScopeText : undefined;
    const scopeHandoff = handoffs.find((h) => h.step_id === "scope");
    if (!text) return fail("hunt.status has no scope text for the open scope gate");
    if (!scopeHandoff) return fail("The scope handoff is unavailable or invalid.");
    return { activeGate: { ...base, scopeText: text, scopeHandoff }, citationReceipt: null, evidenceCatalog: {}, events: [], citationStatus: new Map() };
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
            ...(() => {
              const affected = projectAffectedStep(reconcile.affected_step, receipt!.step_id);
              return affected ? { affectedStep: affected } : {};
            })(),
          },
        },
        citationReceipt: null,
        evidenceCatalog: {},
        events: [],
        citationStatus: new Map(),
      };
    }
    // citation_source_unavailable: the reason itself is the context; show what could and could not be checked.
    if (!reconcileHandoff) return fail("The unverified handoff for the affected step is unavailable.");
    if (reconcileHandoff.case_id !== ctx.case_id || reconcile.citation_receipt.case_id !== ctx.case_id) {
      return fail("Reconcile handoff or citation receipt is for a different case.");
    }
    const projected = projectCitedEvidence([reconcileHandoff], reconcile, reconcile.citation_receipt.verified);
    if (projected.error !== undefined) return fail(projected.error);
    return {
      activeGate: {
        ...base,
        evidencePaging: projected.paging,
        reconcileContext: {
          reasonCode: "citation_source_unavailable",
          unavailableSources: reconcile.unavailable_sources,
          citationReceipt: projected.receipt,
          ...(() => {
            const affected = projectAffectedStep(reconcile.affected_step, reconcileHandoff.step_id);
            return affected ? { affectedStep: affected } : {};
          })(),
        },
      },
      citationReceipt: projected.receipt,
      evidenceCatalog: projected.evidenceCatalog,
      events: projected.events,
      citationStatus: projected.status,
      pagingState: {
        runId, gate: "reconcile", payloadSha256: ctx.payload_sha256, cited: reconcile.cited,
        loaded: reconcile.evidence.length, nextCursor: reconcile.evidence_next_cursor,
      },
    };
  }

  const incident = ctx.incident;
  if (!incidentHandoff) return fail("The incident handoff is unavailable.");
  if (!incident) return fail("incident gate context has no citation receipt or evidence");
  if (incident.citation_receipt.source_status !== "ok") {
    return fail(`citation backend unavailable: ${incident.citation_receipt.diagnostic ?? "source_status=unavailable"}`);
  }
  if (incident.citation_receipt.case_id !== ctx.case_id || handoffs.some((h) => h.case_id !== ctx.case_id)) {
    return fail("Incident handoff or citation receipt is for a different case.");
  }
  if (incident.cited.some((c) => c.status === "unchecked")) {
    return fail("Incident context reports unchecked citations; the citation source must be readable for this gate.");
  }
  const projected = projectCitedEvidence(handoffs, incident, incident.citation_receipt.verified);
  if (projected.error !== undefined) return fail(projected.error);
  const { receipt, evidenceCatalog, events, status } = projected;
  const claims = handoffs.flatMap((h) => h.claims);
  const reviews = handoffs.flatMap((h) => h.reviews);
  return {
    activeGate: {
      ...base,
      evidencePaging: projected.paging,
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
    pagingState: {
      runId, gate: "incident", payloadSha256: ctx.payload_sha256, cited: incident.cited,
      loaded: incident.evidence.length, nextCursor: incident.evidence_next_cursor,
    },
  };
}

export type LiveEvidenceProjection = Pick<LiveGateProjection, "citationReceipt" | "evidenceCatalog" | "events" | "citationStatus">;

/**
 * Projects completed-run evidence only when its identity and full citation coverage are intact.
 * A completed run has no "Load more": `fetchPage` (hunt.evidencePage) is called until every cited record
 * is loaded. Each page must continue the complete `cited` list exactly; any failed or mismatched page
 * yields null, so a partial record list is never shown as the run's evidence.
 */
export async function projectLiveEvidence(
  runId: string,
  caseId: string,
  handoffs: readonly Handoff[],
  raw: unknown,
  fetchPage: (cursor: string) => Promise<unknown>,
): Promise<LiveEvidenceProjection | null> {
  const parsed = LiveEvidenceResultSchema.safeParse(raw);
  if (!parsed.success) return null;
  const data = parsed.data;
  if (data.run_id !== runId || data.case_id !== caseId || data.citation_receipt.case_id !== caseId ||
      data.citation_receipt.source_status !== "ok") return null;
  if (handoffs.some((h) => h.case_id !== caseId)) return null;
  if (data.evidence_total !== data.cited.length || checkEvidenceSlice(data.cited, 0, data.evidence)) return null;
  const records: EvidenceEntry[] = [...data.evidence];
  let cursor = data.evidence_next_cursor;
  while (cursor !== null) {
    let page: z.infer<typeof RunEvidencePageSchema>;
    try {
      const result = RunEvidencePageSchema.safeParse(await fetchPage(cursor));
      if (!result.success) return null;
      page = result.data;
    } catch {
      return null;
    }
    // A page with a cursor still open must add records, so the loop ends within `cited.length` records.
    if (page.run_id !== runId || page.evidence_total !== data.cited.length || page.evidence.length === 0 ||
        checkEvidenceSlice(data.cited, records.length, page.evidence)) return null;
    records.push(...page.evidence);
    cursor = page.evidence_next_cursor;
  }
  const projected = projectCitedEvidence(
    handoffs,
    { cited: data.cited, evidence: records, evidence_total: data.evidence_total, evidence_next_cursor: null },
    data.citation_receipt.verified,
  );
  if (projected.error !== undefined) return null;
  return {
    citationReceipt: projected.receipt,
    evidenceCatalog: projected.evidenceCatalog,
    events: projected.events,
    citationStatus: projected.status,
  };
}

type CitedRef = { kind: "evt" | "frame" | "ioc"; referencedIn: CitationStatusEntry["referencedIn"][number][]; claimIds: Set<string> };

/** A daemon status as the receipt reports it: `ambiguous` and `unchecked` cannot count as verified. */
function receiptStatus(status: CitedEntry["status"]): "verified" | "unresolved" | "out_of_scope" {
  return status === "verified" || status === "out_of_scope" ? status : "unresolved";
}

/** Adds one daemon record to the evidence catalog (and, for a verified event, the Dissector events). */
function addRecord(
  ev: EvidenceEntry,
  ref: CitedRef | undefined,
  evidenceCatalog: Record<string, EvidenceRecordDetail>,
  events: DissectorEventRow[],
): void {
  const s = receiptStatus(ev.status);
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

/**
 * Gate evidence (F18): the receipt and approval coverage come from `cited`, which lists EVERY cited id with
 * its status in one response; `evidence` is only the first page of records. Returns `error` when the
 * handoffs cite an id `cited` does not list, `cited` repeats an id, the totals disagree, or the record page
 * is not exactly the first slice of `cited`.
 */
function projectCitedEvidence(
  handoffs: readonly Handoff[],
  block: { cited: CitedEntry[]; evidence: EvidenceEntry[]; evidence_total: number; evidence_next_cursor: string | null },
  receiptVerified: boolean,
):
  | { error: string }
  | {
      error?: undefined;
      receipt: CitationVerificationReceipt;
      evidenceCatalog: Record<string, EvidenceRecordDetail>;
      events: DissectorEventRow[];
      status: Map<string, "verified" | "unresolved" | "out_of_scope">;
      paging: { loaded: number; total: number; hasMore: boolean };
    } {
  const { cited, evidence } = block;
  if (block.evidence_total !== cited.length) {
    return { error: `evidence_total ${block.evidence_total} does not match ${cited.length} cited ids` };
  }
  const byId = new Map(cited.map((c) => [c.id, c]));
  if (byId.size !== cited.length) return { error: "the cited list repeats an id" };
  const sliceErr = checkEvidenceSlice(cited, 0, evidence);
  if (sliceErr) return { error: sliceErr };
  if (block.evidence_next_cursor === null && evidence.length !== cited.length) {
    return { error: "record pages end before every cited record was returned" };
  }
  const refs = citedReferences(handoffs);
  const uncovered = [...refs].filter(([id, ref]) => byId.get(id)?.kind !== ref.kind).map(([id]) => id);
  if (uncovered.length > 0) {
    return { error: `gate context does not cover cited ids: ${uncovered.slice(0, 5).join(", ")}` };
  }
  // The reverse also holds: a record nobody cited is not this gate's evidence and must not be shown as such.
  const uncited = cited.filter((c) => !refs.has(c.id)).map((c) => c.id);
  if (uncited.length > 0) {
    return { error: `gate context lists ids that no handoff cites: ${uncited.slice(0, 5).join(", ")}` };
  }

  const records = new Map(evidence.map((e) => [e.id, e]));
  const status = new Map<string, "verified" | "unresolved" | "out_of_scope">();
  const entries: CitationStatusEntry[] = [];
  let verified = 0;
  let unresolved = 0;
  let outOfScope = 0;
  for (const c of cited) {
    const st = receiptStatus(c.status);
    status.set(c.id, st);
    if (st === "verified") verified++;
    else if (st === "out_of_scope") outOfScope++;
    else unresolved++;
    const rec = records.get(c.id);
    entries.push({
      citationId: c.id,
      kind: c.kind,
      status: st,
      referencedIn: refs.get(c.id)?.referencedIn ?? [],
      ...(rec?.timestamp_iso ? { timestampIso: rec.timestamp_iso } : {}),
      ...(rec?.title ? { summary: rec.title } : {}),
    });
  }
  const { evidenceCatalog, events } = projectEvidenceRecords(handoffs, evidence);
  return {
    receipt: {
      totalCited: cited.length,
      verifiedCount: verified,
      unresolvedCount: unresolved,
      outOfScopeCount: outOfScope,
      allVerified: receiptVerified && unresolved === 0 && outOfScope === 0,
      entries,
    },
    evidenceCatalog,
    events: events.sort((a, b) => a.timestampMs - b.timestampMs),
    status,
    paging: { loaded: evidence.length, total: cited.length, hasMore: block.evidence_next_cursor !== null },
  };
}
