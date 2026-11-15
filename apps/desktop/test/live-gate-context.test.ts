import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { resolveRuntimeDir } from "@hunt-command/shared";
import {
  createCaseDirDataPlaneResolver,
  DurableStateStore,
  GateAuthority,
  HuntDaemonRpcServer,
  HuntWaveEngine,
  InMemoryTelemetrySink,
  type ModelRunnerPort,
  type ModelTurnRequest,
  type StepTurnResult,
} from "../../../packages/daemon/src/index.ts";
import type { HuntDaemonSidecar } from "../src/main/daemon/daemon-sidecar.ts";
import { projectLiveGate, projectTranscriptPage } from "../src/main/live-gate-context.ts";
import { WorkbenchService, type WorkbenchServiceDeps } from "../src/main/workbench-service.ts";
import { transcriptViewFor } from "../src/renderer/src/lib/transcript-view.ts";
import { missingGateContextReason, validateGateSubmission } from "../src/shared/gate-validation.ts";
import type { ActiveGatePrompt } from "../src/shared/workbench-types.ts";

const DIGEST = "a".repeat(64);
const OPEN = { gate: "incident" as const, payload_sha256: DIGEST, opened_at: "2026-11-14T10:00:00Z", expires_at: "2099-01-01T00:00:00Z" };
const EVT = "evt-0000000000000001";
const HANDOFFS = [
  {
    schema_version: 1, case_id: "c1", step_id: "incident", profile: "framework-coordinator",
    claims: [{ claim_id: "incident:c1", kind: "finding", statement: `Beacon seen in ${EVT}.`, evidence_ids: [EVT], entity_ids: [], contradicts: [] }],
    reviews: [{ review_id: "r1", claim_ids: ["incident:c1"], disposition: "review_ready", rationale: "ok" }],
    disposition: "review_ready", limitations: ["No packet capture."], requested_decisions: [],
  },
] as unknown as Parameters<typeof projectLiveGate>[2];

type Rec = { id: string; kind: string; status: string; timestamp_iso: string | null; title: string; fields: Record<string, unknown> };

/** F18 wire shape: `cited` lists every id with its status; `evidence` is the first page of records. */
function paged(records: Rec[], extra: Partial<{ cited: unknown[]; evidence: Rec[]; evidence_total: number; evidence_next_cursor: string | null }> = {}) {
  return {
    cited: records.map((r) => ({ id: r.id, kind: r.kind, status: r.status })),
    evidence: records,
    evidence_total: records.length,
    evidence_next_cursor: null,
    ...extra,
  };
}

const AFFECTED_OPTIONAL = {
  step_id: "incident", profile: "framework-coordinator", wave: "incident", optional: true,
  approve_transition: "reconcile_drop", reject_reason_code: "reconcile_rejected",
};

function incidentContext(overrides: Record<string, unknown> = {}) {
  return {
    run_id: "run-1", case_id: "c1", gate: "incident", payload_sha256: DIGEST,
    incident: {
      citation_receipt: {
        verified: true, checked_at: "2026-11-14T10:00:00Z", case_id: "c1", total_checked: 1,
        missing_event_ids: [], missing_frame_ids: [], missing_ioc_ids: [], ambiguous_ids: [], out_of_scope_ids: [],
        source_status: "ok",
      },
      ...paged([{
        id: EVT, kind: "evt", status: "verified", timestamp_iso: "2026-11-14T10:01:00Z",
        title: "Process executed.", fields: { "host.name": "wks-01", "process.name": "beacon.exe", message: "Process executed." },
      }]),
    },
    ...overrides,
  };
}

const draft = (action: "approve" | "reject") => ({
  operatorName: "analyst", rbacRole: "lead_hunter" as const, checkNote: "Checked the cited record.", payloadSha256: DIGEST, action,
});

describe("F4: gate approval requires the gate's decision context", () => {
  test("approve is refused for incident/reconcile/scope gates with no context or a context error; reject is allowed", () => {
    const bare = (gate: ActiveGatePrompt["gate"]): ActiveGatePrompt => ({
      gate, huntId: "run-1", openedAtIso: OPEN.opened_at, expiresAtIso: OPEN.expires_at, payloadSha256: DIGEST,
    });
    for (const gate of ["incident", "reconcile", "scope"] as const) {
      expect(missingGateContextReason(bare(gate))).not.toBeNull();
      const approve = validateGateSubmission(bare(gate), draft("approve"));
      expect(approve.valid).toBe(false);
      expect(validateGateSubmission(bare(gate), draft("reject")).valid).toBe(true);
    }
    const errored = { ...bare("scope"), scopeText: "x", contextError: "boom" };
    expect(validateGateSubmission(errored, draft("approve")).errors.join(" ")).toContain("boom");
  });

  test("incident context from the daemon fills the summary, citation entries, evidence catalog and events", () => {
    const p = projectLiveGate("run-1", OPEN, HANDOFFS, incidentContext());
    expect(p.activeGate.contextError).toBeUndefined();
    const summary = p.activeGate.incidentSummary!;
    expect(summary.findingCount).toBe(1);
    expect(summary.limitationCount).toBe(1);
    expect(summary.purpleVerdictCounts.review_ready).toBe(1);
    expect(summary.citationReceipt.allVerified).toBe(true);
    expect(summary.citationReceipt.entries).toEqual([
      expect.objectContaining({ citationId: EVT, status: "verified", summary: "Process executed." }),
    ]);
    expect(summary.citationReceipt.entries[0]!.referencedIn).toEqual([{ sourceKind: "claim", sourceId: "incident:c1", stepId: "incident" }]);
    expect(p.evidenceCatalog[EVT]?.fields["host.name"]).toBe("wks-01");
    expect(p.evidenceCatalog[EVT]?.citingClaimIds).toEqual(["incident:c1"]);
    expect(p.events.map((e) => [e.eventId, e.hostName, e.processName])).toEqual([[EVT, "wks-01", "beacon.exe"]]);
    expect(missingGateContextReason(p.activeGate)).toBeNull();
  });

  test("an incomplete or inconsistent cited list is never presented as complete or approvable", () => {
    const inc = incidentContext().incident;
    const bad: Array<[string, unknown]> = [
      ["cited omits a cited id", { ...inc, cited: [], evidence: [], evidence_total: 0 }],
      ["total disagrees", { ...inc, evidence_total: 2 }],
      ["record status differs from cited", { ...inc, evidence: [{ ...inc.evidence[0]!, status: "unresolved" }] }],
      ["pages end early", { ...inc, evidence: [], evidence_next_cursor: null }],
      ["repeated id", { ...inc, cited: [...inc.cited, ...inc.cited], evidence_total: 2 }],
      ["legacy truncated shape", { citation_receipt: inc.citation_receipt, evidence: inc.evidence, evidence_truncated: true }],
    ];
    for (const [label, incident] of bad) {
      const p = projectLiveGate("run-1", OPEN, HANDOFFS, incidentContext({ incident }));
      expect([label, typeof p.activeGate.contextError]).toEqual([label, "string"]);
      expect(p.activeGate.incidentSummary).toBeUndefined();
      expect(p.citationReceipt).toBeNull();
      expect(p.activeGate.incidentHandoff?.claims[0]?.statement).toContain("Beacon seen");
      expect(validateGateSubmission(p.activeGate, draft("approve")).valid).toBe(false);
      expect(validateGateSubmission(p.activeGate, draft("reject")).valid).toBe(true);
    }
  });

  test("unchecked statuses on an incident gate fail closed (only a citation reconcile may carry them)", () => {
    const inc = incidentContext().incident;
    const unchecked = { ...inc.evidence[0]!, status: "unchecked", timestamp_iso: null, title: "", fields: {} };
    const p = projectLiveGate("run-1", OPEN, HANDOFFS, incidentContext({ incident: { ...inc, ...paged([unchecked]) } }));
    expect(p.activeGate.contextError).toContain("unchecked");
    expect(validateGateSubmission(p.activeGate, draft("approve")).valid).toBe(false);
  });

  test("an absent incident handoff cannot be approved", () => {
    const p = projectLiveGate("run-1", OPEN, [], incidentContext());
    expect(p.activeGate.contextError).toContain("incident handoff");
    expect(validateGateSubmission(p.activeGate, draft("approve")).valid).toBe(false);
  });

  test("unresolved citations keep approve blocked by the citation rule", () => {
    const ctx = incidentContext();
    (ctx.incident as { evidence: Array<{ status: string }> }).evidence[0]!.status = "unresolved";
    (ctx.incident as { cited: Array<{ status: string }> }).cited[0]!.status = "unresolved";
    (ctx.incident as { citation_receipt: { verified: boolean } }).citation_receipt.verified = false;
    const p = projectLiveGate("run-1", OPEN, HANDOFFS, ctx);
    expect(p.activeGate.incidentSummary!.citationReceipt.allVerified).toBe(false);
    expect(validateGateSubmission(p.activeGate, draft("approve")).valid).toBe(false);
  });

  test("every failure mode fails closed with a contextError", () => {
    const cases: Array<[string, unknown]> = [
      ["rpc error", new Error("method_not_found: Unknown RPC method 'hunt.gateContext'")],
      ["schema", { run_id: "run-1" }],
      ["digest mismatch", incidentContext({ payload_sha256: "b".repeat(64) })],
      ["other run", incidentContext({ run_id: "run-2" })],
      ["other gate", { ...incidentContext(), gate: "reconcile", incident: undefined, reconcile: { reason_code: "previous_dispatch_unknown", receipts: [{ execution_id: "e", session_id: "s", input_id: "i", step_id: "x", profile: "framework-coordinator", reserved_at: "t", reason_code: "previous_dispatch_unknown" }] } }],
      ["no incident block", { run_id: "run-1", case_id: "c1", gate: "incident", payload_sha256: DIGEST }],
      ["uncovered citation", incidentContext({ incident: { ...incidentContext().incident, ...paged([]) } })],
      ["backend unavailable", incidentContext({ incident: { ...incidentContext().incident, citation_receipt: { ...incidentContext().incident.citation_receipt, source_status: "unavailable" } } })],
    ];
    for (const [label, raw] of cases) {
      const p = projectLiveGate("run-1", OPEN, HANDOFFS, raw);
      expect([label, typeof p.activeGate.contextError]).toEqual([label, "string"]);
      expect(p.activeGate.incidentSummary).toBeUndefined();
      expect(validateGateSubmission(p.activeGate, draft("approve")).valid).toBe(false);
    }
  });

  test("reconcile context fills the dispatch receipt", () => {
    const open = { ...OPEN, gate: "reconcile" as const };
    const p = projectLiveGate("run-1", open, HANDOFFS, {
      run_id: "run-1", case_id: "c1", gate: "reconcile", payload_sha256: DIGEST,
      reconcile: { reason_code: "previous_dispatch_unknown",
        affected_step: { step_id: "analysis", profile: "framework-coordinator", wave: "analysis", optional: false, approve_transition: "reconcile_halt", reject_reason_code: "reconcile_rejected" },
        receipts: [{ execution_id: "exec-1", session_id: "sess-1", input_id: "in-1", step_id: "analysis", profile: "framework-coordinator", reserved_at: "2026-11-14T10:00:05Z", reason_code: "previous_dispatch_unknown" }] },
    });
    expect(p.activeGate.reconcileContext).toEqual({
      executionId: "exec-1", sessionId: "sess-1", inputId: "in-1", stepId: "analysis",
      profile: "framework-coordinator", reservedAtIso: "2026-11-14T10:00:05Z", reasonCode: "previous_dispatch_unknown",
      affectedStep: { stepId: "analysis", profile: "framework-coordinator", wave: "analysis", optional: false, approveTransition: "reconcile_halt" },
    });
    expect(missingGateContextReason(p.activeGate)).toBeNull();
  });

  test("a citation_source_unavailable reconcile gate shows its reason and evidence and stays approvable", () => {
    const open = { ...OPEN, gate: "reconcile" as const };
    const inc = incidentContext().incident;
    const p = projectLiveGate("run-1", open, HANDOFFS, {
      run_id: "run-1", case_id: "c1", gate: "reconcile", payload_sha256: DIGEST,
      reconcile: {
        reason_code: "citation_source_unavailable",
        citation_receipt: { ...inc.citation_receipt, verified: false, source_status: "unavailable" },
        unavailable_sources: ["events"],
        ...paged([{ ...inc.evidence[0]!, status: "unchecked", timestamp_iso: null, title: "", fields: {} }]),
        affected_step: AFFECTED_OPTIONAL,
      },
    }, undefined, HANDOFFS[0]);
    expect(p.activeGate.contextError).toBeUndefined();
    const rc = p.activeGate.reconcileContext!;
    expect(rc.reasonCode).toBe("citation_source_unavailable");
    if (rc.reasonCode !== "citation_source_unavailable") throw new Error("narrowing");
    expect(rc.unavailableSources).toEqual(["events"]);
    expect(rc.citationReceipt.entries.map((e) => [e.citationId, e.status])).toEqual([[EVT, "unresolved"]]);
    expect(rc.affectedStep).toEqual({ stepId: "incident", profile: "framework-coordinator", wave: "incident", optional: true, approveTransition: "reconcile_drop" });
    expect(missingGateContextReason(p.activeGate)).toBeNull();
    expect(validateGateSubmission(p.activeGate, draft("approve")).valid).toBe(true);
  });

  test("F17: a citation reconcile without an identifiable affected step cannot be approved", () => {
    const inc = incidentContext().incident;
    const ctx = (affected_step?: unknown) => ({
      run_id: "run-1", case_id: "c1", gate: "reconcile", payload_sha256: DIGEST,
      reconcile: {
        reason_code: "citation_source_unavailable",
        citation_receipt: { ...inc.citation_receipt, verified: false, source_status: "unavailable" },
        unavailable_sources: ["events"],
        ...paged([{ ...inc.evidence[0]!, status: "unchecked", timestamp_iso: null, title: "", fields: {} }]),
        ...(affected_step ? { affected_step } : {}),
      },
    });
    // Missing affected_step: the context itself is invalid (fail closed).
    const missing = projectLiveGate("run-1", { ...OPEN, gate: "reconcile" }, HANDOFFS, ctx(undefined), undefined, HANDOFFS[0]);
    expect(missing.activeGate.contextError).toBeDefined();
    expect(validateGateSubmission(missing.activeGate, draft("approve")).valid).toBe(false);
    expect(validateGateSubmission(missing.activeGate, draft("reject")).valid).toBe(true);
    // Present but for another step, or inconsistent (optional with a halt transition): step not identified.
    for (const affected of [{ ...AFFECTED_OPTIONAL, step_id: "other-step" }, { ...AFFECTED_OPTIONAL, approve_transition: "reconcile_halt" }]) {
      const p = projectLiveGate("run-1", { ...OPEN, gate: "reconcile" }, HANDOFFS, ctx(affected), undefined, HANDOFFS[0]);
      expect(p.activeGate.contextError).toBeUndefined();
      expect(String(missingGateContextReason(p.activeGate))).toContain("could not be identified");
      expect(validateGateSubmission(p.activeGate, draft("approve")).valid).toBe(false);
      expect(validateGateSubmission(p.activeGate, draft("reject")).valid).toBe(true);
    }
  });

  test("F17: a dispatch reconcile whose affected step does not match or contradicts itself cannot be approved", () => {
    const receipt = { execution_id: "exec-1", session_id: "sess-1", input_id: "in-1", step_id: "analysis", profile: "framework-coordinator", reserved_at: "2026-11-14T10:00:05Z", reason_code: "previous_dispatch_unknown" };
    const required = { step_id: "analysis", profile: "framework-coordinator", wave: "analysis", optional: false, approve_transition: "reconcile_halt", reject_reason_code: "reconcile_rejected" };
    for (const affected_step of [
      { ...required, step_id: "other-step" },
      { ...required, optional: true },
      { ...required, approve_transition: "reconcile_drop" },
    ]) {
      const p = projectLiveGate("run-1", { ...OPEN, gate: "reconcile" }, HANDOFFS, {
        run_id: "run-1", case_id: "c1", gate: "reconcile", payload_sha256: DIGEST,
        reconcile: { reason_code: "previous_dispatch_unknown", affected_step, receipts: [receipt] },
      });
      expect(p.activeGate.reconcileContext?.affectedStep).toBeUndefined();
      expect(String(missingGateContextReason(p.activeGate))).toContain("could not be identified");
      expect(validateGateSubmission(p.activeGate, draft("approve")).valid).toBe(false);
      expect(validateGateSubmission(p.activeGate, draft("reject")).valid).toBe(true);
    }
  });

  test("a record that no handoff cites is not shown as the gate's evidence", () => {
    const inc = incidentContext().incident;
    const stray = { ...inc.evidence[0]!, id: "evt-0000000000000777" };
    const p = projectLiveGate("run-1", OPEN, HANDOFFS, incidentContext({ incident: { ...inc, ...paged([...inc.evidence, stray]) } }));
    expect(p.activeGate.contextError).toContain("no handoff cites");
    expect(p.evidenceCatalog).toEqual({});
    expect(validateGateSubmission(p.activeGate, draft("approve")).valid).toBe(false);
    expect(validateGateSubmission(p.activeGate, draft("reject")).valid).toBe(true);
  });

  test("an outage projects only affected cited IDs as unresolved without inventing evidence", () => {
    const failed = {
      ...HANDOFFS[0]!,
      claims: [{ ...HANDOFFS[0]!.claims[0]!, statement: `Process ${EVT} and packet frame-42.` }],
      limitations: ["Intel ioc-00123 could not be checked."],
    };
    const inc = incidentContext().incident;
    const context = {
      run_id: "run-1", case_id: "c1", gate: "reconcile", payload_sha256: DIGEST,
      reconcile: {
        reason_code: "citation_source_unavailable",
        citation_receipt: { ...inc.citation_receipt, verified: false, source_status: "unavailable" },
        unavailable_sources: ["events", "packets", "intel"],
        ...paged([
          { id: EVT, kind: "evt", status: "unchecked", timestamp_iso: null, title: "", fields: {} },
          { id: "frame-42", kind: "frame", status: "unchecked", timestamp_iso: null, title: "", fields: {} },
          { id: "ioc-00123", kind: "ioc", status: "unchecked", timestamp_iso: null, title: "", fields: {} },
        ]),
        affected_step: AFFECTED_OPTIONAL,
      },
    };
    const open = { ...OPEN, gate: "reconcile" as const };
    const p = projectLiveGate("run-1", open, [], context, undefined, failed);
    expect(p.activeGate.contextError).toBeUndefined();
    expect(p.citationReceipt).toMatchObject({ totalCited: 3, verifiedCount: 0, unresolvedCount: 3, allVerified: false });
    expect(p.citationReceipt?.entries).toEqual([
      { citationId: EVT, kind: "evt", status: "unresolved", referencedIn: [{ sourceKind: "claim", sourceId: "incident:c1", stepId: "incident" }] },
      { citationId: "frame-42", kind: "frame", status: "unresolved", referencedIn: [{ sourceKind: "claim", sourceId: "incident:c1", stepId: "incident" }] },
      { citationId: "ioc-00123", kind: "ioc", status: "unresolved", referencedIn: [{ sourceKind: "limitation", sourceId: "incident:limitation-1", stepId: "incident" }] },
    ]);
    expect([...p.citationStatus.values()]).toEqual(["unresolved", "unresolved", "unresolved"]);
    expect(Object.values(p.evidenceCatalog).every((r) => !r.verified && Object.keys(r.fields).length === 0)).toBe(true);
    expect(p.events).toEqual([]);
    expect(validateGateSubmission(p.activeGate, draft("approve")).valid).toBe(true);

    const partial = projectLiveGate("run-1", open, [], {
      ...context,
      reconcile: {
        ...context.reconcile,
        unavailable_sources: ["packets", "intel"],
        ...paged([
          inc.evidence[0]!,
          { id: "frame-42", kind: "frame", status: "unchecked", timestamp_iso: null, title: "", fields: {} },
          { id: "ioc-00123", kind: "ioc", status: "unchecked", timestamp_iso: null, title: "", fields: {} },
        ]),
      },
    }, undefined, failed);
    expect(partial.activeGate.contextError).toBeUndefined();
    expect(partial.citationReceipt).toMatchObject({ verifiedCount: 1, unresolvedCount: 2, allVerified: false });
    expect(partial.evidenceCatalog[EVT]?.fields["host.name"]).toBe("wks-01");
    expect(Object.values(partial.evidenceCatalog).filter((r) => r.verified).map((r) => r.id)).toEqual([EVT]);
    expect(partial.events.map((event) => event.eventId)).toEqual([EVT]);

    const cases = [
      { ...context.reconcile, unavailable_sources: ["unrelated"] },
      { ...context.reconcile, evidence_truncated: true },
      { ...context.reconcile, cited: context.reconcile.cited.slice(1), evidence: context.reconcile.evidence.slice(1), evidence_total: 2 },
      { ...context.reconcile, evidence_total: 4 },
      { ...context.reconcile, citation_receipt: { ...context.reconcile.citation_receipt, case_id: "other-case" } },
      { ...context.reconcile, ...paged([{ ...inc.evidence[0]!, kind: "ioc" }, ...context.reconcile.evidence.slice(1)]) },
    ];
    for (const reconcile of cases) {
      const rejected = projectLiveGate("run-1", open, [], { ...context, reconcile }, undefined, failed);
      expect(rejected.activeGate.contextError).toBeDefined();
      expect(rejected.citationReceipt).toBeNull();
      expect(validateGateSubmission(rejected.activeGate, draft("approve")).valid).toBe(false);
      expect(validateGateSubmission(rejected.activeGate, draft("reject")).valid).toBe(true);
    }
  });

  test("reconcile evidence covers only the failed step, not earlier reviewed handoffs", () => {
    const failed = HANDOFFS[0]!;
    const earlier = {
      ...failed,
      step_id: "scope",
      claims: [{ ...failed.claims[0]!, claim_id: "scope:c1", statement: "Earlier evt-0000000000000099." }],
    };
    const inc = incidentContext().incident;
    const ctx = { run_id: "run-1", case_id: "c1", gate: "reconcile", payload_sha256: DIGEST,
      reconcile: { reason_code: "citation_source_unavailable", citation_receipt: inc.citation_receipt,
        unavailable_sources: [], ...paged(inc.evidence as Rec[]), affected_step: AFFECTED_OPTIONAL } };
    const p = projectLiveGate("run-1", { ...OPEN, gate: "reconcile" }, [earlier], ctx, undefined, failed);
    expect(p.activeGate.contextError).toBeUndefined();
    expect(p.citationReceipt?.entries.map((entry) => entry.citationId)).toEqual([EVT]);
    expect(validateGateSubmission(p.activeGate, draft("approve")).valid).toBe(true);
    const missing = projectLiveGate("run-1", { ...OPEN, gate: "reconcile" }, [earlier], ctx);
    expect(validateGateSubmission(missing.activeGate, draft("approve")).valid).toBe(false);
  });

  test("scope approval requires the generated scope handoff, not just the operator text", () => {
    const open = { ...OPEN, gate: "scope" as const };
    const missing = projectLiveGate("run-1", open, [], null, "Investigate the host.");
    expect(validateGateSubmission(missing.activeGate, draft("approve")).valid).toBe(false);
    const scope = { ...HANDOFFS[0]!, step_id: "scope", limitations: ["Limited collection."] };
    const ready = projectLiveGate("run-1", open, [scope], null, "Investigate the host.");
    expect(ready.activeGate.scopeHandoff).toEqual(scope);
    expect(validateGateSubmission(ready.activeGate, draft("approve")).valid).toBe(true);
  });

  test("an unparseable reconcile context (no receipts) fails closed", () => {
    const p = projectLiveGate("run-1", { ...OPEN, gate: "reconcile" }, HANDOFFS, {
      run_id: "run-1", case_id: "c1", gate: "reconcile", payload_sha256: DIGEST,
      reconcile: { reason_code: "previous_dispatch_unknown", receipts: [] },
    });
    expect(p.activeGate.contextError).toBeDefined();
    expect(validateGateSubmission(p.activeGate, draft("approve")).valid).toBe(false);
  });
});

describe("F8: live transcript pages", () => {
  test("daemon page is validated and mapped; mismatched or failed pages become an error view", () => {
    const nonce = "0123456789abcdef0123456789abcdef";
    const fenced = (t: string, n = nonce) => `<untrusted_tool_result_${n}>
${t}
</untrusted_tool_result_${n}>`;
    const raw = { run_id: "run-1", step_id: "incident", profile: "framework-coordinator", byte_offset: 0, byte_length: 5, total_bytes: 9, has_more: true, next_byte_offset: 5, fence_nonce: nonce, content: fenced("hello") };
    const page = projectTranscriptPage(raw, "run-1", "incident");
    expect(page).toEqual({ huntId: "run-1", stepId: "incident", profile: "framework-coordinator", byteOffset: 0, byteLength: 5, totalBytes: 9, hasMore: true, nextByteOffset: 5, content: "hello" });
    expect(projectTranscriptPage({ ...raw, content: fenced(""), byte_length: 0, has_more: false }, "run-1", "incident").content).toBe("");
    // Wrong nonce, missing fence, or unfenced text is refused rather than rendered.
    expect(() => projectTranscriptPage({ ...raw, content: fenced("hello", "f".repeat(32)) }, "run-1", "incident")).toThrow(/fence/);
    expect(() => projectTranscriptPage({ ...raw, content: "hello" }, "run-1", "incident")).toThrow(/fence/);
    expect(() => projectTranscriptPage({ ...raw, step_id: "other" }, "run-1", "incident")).toThrow();
    expect(() => projectTranscriptPage({ ...raw, extra: 1 }, "run-1", "incident")).toThrow();

    const req = { huntId: "run-1", stepId: "incident", byteOffset: 0 };
    expect(transcriptViewFor(req, { ok: true, data: page })).toEqual({ kind: "page", page });
    expect(transcriptViewFor(req, { ok: false, error: { code: "IPC_HANDLER_ERROR", message: "method_not_found" } })).toEqual({ kind: "error", message: "method_not_found" });
    expect(transcriptViewFor({ ...req, stepId: "analysis" }, { ok: true, data: page }).kind).toBe("error");
    // The daemon may snap an offset forward to a UTF-8 boundary (at most 3 bytes).
    expect(transcriptViewFor({ ...req, byteOffset: 0 }, { ok: true, data: { ...page, byteOffset: 2 } }).kind).toBe("page");
    expect(transcriptViewFor({ ...req, byteOffset: 0 }, { ok: true, data: { ...page, byteOffset: 9 } }).kind).toBe("error");
  });
});

/** In-process daemon (real engine, store, gates, RPC server) behind a sidecar-shaped adapter. */
/** `gateContext` may override hunt.gateContext; returning `undefined` uses the real daemon RPC. */
async function liveHarness(
  gateContext: (params: Record<string, unknown>, store: DurableStateStore) => unknown,
  citedRecordsUnavailable = false,
  incidentCitation = false,
  extraEventIds: readonly string[] = [],
) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "hc-live-gate-"));
  const caseId = "gate-case";
  const caseDir = path.join(root, "cases", caseId);
  fs.mkdirSync(caseDir, { recursive: true });
  fs.writeFileSync(path.join(caseDir, "case.json"), JSON.stringify({
    case_id: caseId, question: "Which host ran the process?", data_origin: "synthetic",
    time_range_utc: { start_inclusive: "2026-11-14T10:00:00Z", end_exclusive: "2026-11-14T11:00:00Z" },
  }));
  fs.writeFileSync(path.join(caseDir, "events.jsonl"), [
    { "@timestamp": "2026-11-14T10:01:00Z", event: { id: "evt-1", code: "1" }, host: { name: "gate-host" }, message: "Process executed." },
    ...extraEventIds.map((id, i) => ({
      "@timestamp": `2026-11-14T10:${String(2 + Math.floor(i / 60)).padStart(2, "0")}:${String(i % 60).padStart(2, "0")}Z`,
      event: { id, code: "1" }, host: { name: `bulk-host-${i % 7}` }, message: `Bulk record ${i}.`,
    })),
  ].map((e) => JSON.stringify(e)).join("\n") + "\n");
  const resolver = createCaseDirDataPlaneResolver({ casesDir: path.join(root, "cases"), cacheDir: path.join(root, "cache") });
  const store = new DurableStateStore(path.join(root, "state.sqlite"));
  const gates = new GateAuthority({ stateStore: store, decisionsDir: path.join(root, "decisions") });
  const runner: ModelRunnerPort = {
    getPinnedModelForRole: () => ({ provider: "anthropic", model: "stub", fallback_providers: [] }),
    preflightWave: async () => {},
    runTurn: async (req: ModelTurnRequest): Promise<StepTurnResult> => ({
      status: "completed",
      output_text: JSON.stringify({
        schema_version: 1, case_id: req.caseId, step_id: req.stepId, profile: req.profile,
        claims: [{ claim_id: `${req.stepId}:c1`, kind: "observed", statement: req.stepId === "incident" ? (incidentCitation ? "Incident process finding in evt-1." : "Incident-specific process finding.") : "The process was observed.", evidence_ids: ["events.jsonl"], entity_ids: [], contradicts: [] }],
        reviews: [], disposition: "review_ready", limitations: req.stepId === "incident" ? ["Incident-specific collection limitation."] : [], requested_decisions: [],
      }),
      usage: { input_tokens: 1, output_tokens: 1, cache_read_tokens: 0, cache_write_tokens: 0, total_tokens: 2, turns: 1, provider: "anthropic", model: "stub", billing_mode: "oauth_subscription", actual_billed_usd: 0, shadow_api_usd: 0, cache_savings_usd: 0 },
    }),
  };
  const engine = new HuntWaveEngine({ stateStore: store, gateAuthority: gates, modelRunner: runner, telemetry: new InMemoryTelemetrySink(), resolveDataPlane: resolver.resolve });
  const outage = { on: false };
  const rpcResolver = citedRecordsUnavailable
    ? async (caseId: string) => {
        const plane = await resolver.resolve(caseId);
        return new Proxy(plane, {
          get(target, key) {
            // Source down, as the daemon detects it: verification reports the source unavailable and
            // record reads fail.
            if (key === "readCitedRecords") return async () => { throw new Error("citation source unavailable"); };
            if (key === "verifyCitations" && outage.on) {
              return async (r: { case_id: string }) => ({
                verified: false, checked_at: new Date().toISOString(), case_id: r.case_id, total_checked: 0,
                missing_event_ids: [], missing_frame_ids: [], missing_ioc_ids: [], ambiguous_ids: [], out_of_scope_ids: [],
                source_status: "unavailable", diagnostic: "citation source unavailable",
              });
            }
            const value = Reflect.get(target, key, target);
            return typeof value === "function" ? value.bind(target) : value;
          },
        });
      }
    : resolver.resolve;
  const replies = new Map<number, { result?: unknown; error?: { message: string; error_code?: string } }>();
  const rpc = new HuntDaemonRpcServer({
    engine, resolveDataPlane: rpcResolver,
    writeLine: (line) => {
      const msg = JSON.parse(line) as { id?: number; result?: unknown; error?: { message: string; error_code?: string } };
      if (typeof msg.id === "number") replies.set(msg.id, msg);
    },
  });
  const calls: string[] = [];
  const recorded: Array<[string, Record<string, unknown> | undefined]> = [];
  let seq = 0;
  const sidecar = {
    isLiveReady: true,
    health: () => ({ status: "ready" }),
    request: async (method: string, params?: Record<string, unknown>) => {
      calls.push(method);
      recorded.push([method, params]);
      if (method === "hunt.gateContext") {
        const override = gateContext(params ?? {}, store);
        if (override !== undefined) return override;
      }
      const id = ++seq;
      await rpc.handleLine(JSON.stringify({ jsonrpc: "2.0", id, method, ...(params ? { params } : {}) }));
      const reply = replies.get(id);
      if (!reply) throw new Error(`no reply to ${method}`);
      if (reply.error) throw new Error(reply.error.error_code ? `${reply.error.error_code}: ${reply.error.message}` : reply.error.message);
      return reply.result;
    },
  } as unknown as HuntDaemonSidecar;
  const runtimePaths = resolveRuntimeDir(path.join(root, "runtime"), { repoRoot: path.resolve(import.meta.dir, "../../..") });
  const service = new WorkbenchService({ runtimePaths, sidecar, vault: {} as WorkbenchServiceDeps["vault"] });
  const close = async () => {
    store.close();
    await resolver.close();
    fs.rmSync(root, { recursive: true, force: true });
  };
  return { service, runtimePaths, sidecar, store, gates, calls, recorded, outage, caseId, close };
}

async function toIncidentGate(h: Awaited<ReturnType<typeof liveHarness>>) {
  const started = await h.service.startRun({ caseId: h.caseId, dataOrigin: "synthetic", scope: "Investigate the process.", followUps: 0, maxTotalTokens: 100_000 });
  expect(started.activeGate?.gate).toBe("scope");
  expect(started.activeGate?.scopeText).toBe("Investigate the process.");
  expect(started.activeGate?.scopeHandoff?.step_id).toBe("scope");
  expect(started.handoffs.filter((handoff) => handoff.step_id === "scope")).toHaveLength(1);
  expect(started.claims.some((claim) => claim.stepId === "scope")).toBe(true);
  const atIncident = await h.service.submitGateDecision({
    huntId: started.huntId, gate: "scope", action: "approve", operatorName: "x", rbacRole: "incident_commander",
    checkNote: "Reviewed the scope.", payloadSha256: started.activeGate!.payloadSha256,
    operatorToken: h.gates.sessionAuthority.issueToken("real-analyst", "analyst"),
  });
  expect(atIncident.activeGate?.gate).toBe("incident");
  return atIncident;
}

describe("F4 end to end through WorkbenchService and the real daemon engine", () => {
  test("real daemon source outage projects the failed step and permits safe reconciliation", async () => {
    const h = await liveHarness(() => undefined, true);
    try {
      const started = await h.service.startRun({ caseId: h.caseId, dataOrigin: "synthetic", scope: "Investigate the process.", followUps: 0, maxTotalTokens: 100_000 });
      const run = h.store.getRun(started.huntId)!;
      const source = run.results.scope!.handoff!;
      const prior = { ...source, claims: [{ ...source.claims[0]!, statement: "Earlier evt-0000000000000099." }] };
      const failed = { ...source, step_id: "analysis", claims: [{ ...source.claims[0]!, claim_id: "analysis:c1", statement: `Failed step ${EVT}.` }] };
      run.reviewed_handoffs.scope = prior;
      run.results.analysis = { ...run.results.scope!, step_id: "analysis", status: "unknown",
        reason_code: "citation_source_unavailable", unverified_handoff: failed,
        citation_receipt: { ...incidentContext().incident.citation_receipt, case_id: run.case_id, verified: false, source_status: "unavailable" } };
      run.open_gate = { ...run.open_gate!, gate: "reconcile", reason_code: "citation_source_unavailable", unknown_step_id: "analysis" };
      h.store.saveRun(run);
      h.outage.on = true;
      const context = await h.sidecar.request("hunt.gateContext", { run_id: run.run_id }) as {
        reconcile: { unavailable_sources: string[]; cited: Array<{ id: string; status: string }>; evidence: Array<{ id: string; status: string }>; affected_step?: unknown };
      };
      expect(context.reconcile.unavailable_sources).toEqual(["events"]);
      expect(context.reconcile.cited.map((c) => [c.id, c.status])).toEqual([[EVT, "unchecked"]]);
      expect(context.reconcile.evidence.map((c) => [c.id, c.status])).toEqual([[EVT, "unchecked"]]);
      const snapshot = await h.service.getWorkbenchState({ huntId: run.run_id });
      expect(snapshot.activeGate?.contextError).toBeUndefined();
      expect(snapshot.activeGate?.reconcileContext?.reasonCode).toBe("citation_source_unavailable");
      expect(snapshot.citationReceipt.entries.map((entry) => entry.citationId)).toEqual([EVT]);
      expect(snapshot.citationReceipt.entries[0]?.status).toBe("unresolved");
      expect(snapshot.citationReceipt.allVerified).toBe(false);
      expect(snapshot.activeGate?.reconcileContext?.reasonCode === "citation_source_unavailable" &&
        snapshot.activeGate.reconcileContext.unavailableSources).toEqual(["events"]);
      const decide = (action: "approve" | "reject") => h.service.submitGateDecision({
        huntId: run.run_id, gate: "reconcile", action, operatorName: "x", rbacRole: "incident_commander",
        checkNote: "Reviewed the unavailable source.", payloadSha256: snapshot.activeGate!.payloadSha256,
        operatorToken: h.gates.sessionAuthority.issueToken("real-analyst", "analyst"),
      });
      const rc = snapshot.activeGate?.reconcileContext;
      if (rc?.reasonCode !== "citation_source_unavailable") throw new Error("expected a citation reconcile");
      // The daemon names the affected step (F17): analysis is required, so approval halts the run.
      expect(rc.affectedStep).toEqual({ stepId: "analysis", profile: rc.affectedStep!.profile, wave: rc.affectedStep!.wave, optional: false, approveTransition: "reconcile_halt" });
      expect(missingGateContextReason(snapshot.activeGate!)).toBeNull();
      await decide("approve");
      const reconciled = h.store.getRun(run.run_id)!;
      expect(reconciled.decisions.at(-1)?.action).toBe("approve");
      expect(reconciled.status).toBe("failed");
      expect(reconciled.reason_code).toBe("reconciled_halt_required_step");
    } finally {
      await h.close();
    }
  });
  test("the incident gate shows the real daemon's hunt.gateContext and can be approved", async () => {
    const h = await liveHarness(() => undefined);
    try {
      const snap = await toIncidentGate(h);
      expect(snap.activeGate?.contextError).toBeUndefined();
      expect(snap.activeGate?.incidentSummary?.observedCount).toBeGreaterThan(0);
      expect(snap.handoffs.filter((h) => h.step_id === "incident")).toHaveLength(1);
      expect(snap.claims.find((c) => c.stepId === "incident")?.claim.statement).toBe("Incident-specific process finding.");
      expect(snap.limitations.find((l) => l.stepId === "incident")?.text).toBe("Incident-specific collection limitation.");
      expect(snap.activeGate?.incidentHandoff?.limitations).toEqual(["Incident-specific collection limitation."]);
      expect(h.calls).toContain("hunt.gateContext");
      const done = await h.service.submitGateDecision({
        huntId: snap.huntId, gate: "incident", action: "approve", operatorName: "x", rbacRole: "incident_commander",
        checkNote: "Checked the incident claims.", payloadSha256: snap.activeGate!.payloadSha256,
        operatorToken: h.gates.sessionAuthority.issueToken("real-analyst", "analyst"),
      });
      expect(done.gateHistory.map((d) => d.gate)).toEqual(["scope", "incident"]);
      expect(done.handoffs.filter((h) => h.step_id === "incident")).toHaveLength(1);
    } finally {
      await h.close();
    }
  });
  test("completed incident evidence survives approval and a fresh WorkbenchService", async () => {
    const h = await liveHarness(() => undefined, false, true);
    try {
      const incident = await toIncidentGate(h);
      expect(incident.activeGate?.incidentSummary?.citationReceipt.allVerified).toBe(true);
      const completed = await h.service.submitGateDecision({
        huntId: incident.huntId, gate: "incident", action: "approve", operatorName: "x", rbacRole: "incident_commander",
        checkNote: "Checked the cited process event.", payloadSha256: incident.activeGate!.payloadSha256,
        operatorToken: h.gates.sessionAuthority.issueToken("real-analyst", "analyst"),
      });
      const reopenedService = new WorkbenchService({
        runtimePaths: h.runtimePaths, sidecar: h.sidecar, vault: {} as WorkbenchServiceDeps["vault"],
      });
      const reopened = await reopenedService.getWorkbenchState({ huntId: incident.huntId });
      for (const snapshot of [completed, reopened]) {
        expect(snapshot.activeGate).toBeNull();
        expect(snapshot.citationReceipt.allVerified).toBe(true);
        expect(snapshot.citationReceipt.entries).toEqual([
          expect.objectContaining({ citationId: "evt-1", kind: "evt", status: "verified" }),
        ]);
        expect(snapshot.evidenceCatalog["evt-1"]).toMatchObject({
          id: "evt-1", kind: "evt", verified: true, fields: { "host.name": "gate-host" },
        });
        expect(snapshot.events).toEqual([
          expect.objectContaining({ eventId: "evt-1", hostName: "gate-host", message: "Process executed." }),
        ]);
      }
      expect(h.calls).toContain("hunt.evidence");
    } finally {
      await h.close();
    }
  });

  test("a truncated context cannot be approved through the service, but can be rejected", async () => {
    const h = await liveHarness((params, store) => {
      const run = store.getRun(String(params.run_id))!;
      return incidentContext({ run_id: run.run_id, case_id: run.case_id, payload_sha256: run.open_gate!.payload_sha256,
        incident: { ...incidentContext().incident, evidence_truncated: true } });
    });
    try {
      const snap = await toIncidentGate(h);
      expect(snap.activeGate?.contextError).toContain("truncated");
      expect(snap.citationReceipt.allVerified).toBe(false);
      const decide = (action: "approve" | "reject") => h.service.submitGateDecision({
        huntId: snap.huntId, gate: "incident", action, operatorName: "x", rbacRole: "incident_commander",
        checkNote: "Checked context.", payloadSha256: snap.activeGate!.payloadSha256,
        operatorToken: h.gates.sessionAuthority.issueToken("real-analyst", "analyst"),
      });
      const before = h.calls.filter((c) => c === "hunt.decideGate").length;
      await expect(decide("approve")).rejects.toThrow(/truncated/);
      expect(h.calls.filter((c) => c === "hunt.decideGate")).toHaveLength(before);
      await decide("reject");
      expect(h.store.getRun(snap.huntId)!.decisions.at(-1)?.action).toBe("reject");
    } finally {
      await h.close();
    }
  });

  /** A real-daemon incident gate whose handoff cites 1,200 ids that all exist in the case. */
  async function bulkIncidentGate() {
    const ids = Array.from({ length: 1_200 }, (_, i) => `evt-b${String(i).padStart(4, "0")}`);
    const h = await liveHarness(() => undefined, false, false, ids);
    const snap = await toIncidentGate(h);
    const run = h.store.getRun(snap.huntId)!;
    const result = run.results["incident"]!;
    // 6 claims of 200 ids (each statement <= 2,048 bytes, the handoff <= 16 KiB), written to the store
    // because a stub model turn is not needed to prove paging.
    const base = result.handoff!.claims[0]!;
    const claims = Array.from({ length: 6 }, (_, c) => ({
      ...base, claim_id: `incident:bulk${c}`, statement: ids.slice(c * 200, c * 200 + 200).join(" "),
    }));
    run.results["incident"] = { ...result, handoff: { ...result.handoff!, claims } };
    h.store.saveRun(run);
    return { h, ids, huntId: snap.huntId };
  }

  test("F18: 1,200 cited ids are approvable from complete statuses with a partial record list; a stale cursor is an error", async () => {
    const { h, huntId } = await bulkIncidentGate();
    try {
      const atGate = await h.service.getWorkbenchState({ huntId });
      const gate = atGate.activeGate!;
      expect(gate.contextError).toBeUndefined();
      const receipt = gate.incidentSummary!.citationReceipt;
      expect([receipt.totalCited, receipt.verifiedCount, receipt.allVerified]).toEqual([1_200, 1_200, true]);
      expect(gate.evidencePaging).toEqual({ loaded: 200, total: 1_200, hasMore: true });
      expect(Object.keys(atGate.evidenceCatalog)).toHaveLength(200);
      // Approval coverage comes from the complete statuses, not from how many records are loaded.
      expect(missingGateContextReason(gate)).toBeNull();
      expect(validateGateSubmission(gate, { ...draft("approve"), payloadSha256: gate.payloadSha256 }).valid).toBe(true);

      const once = await h.service.loadMoreGateEvidence({ huntId });
      expect(once.activeGate!.evidencePaging).toEqual({ loaded: 400, total: 1_200, hasMore: true });
      // A refresh with the same gate keeps the pages already loaded.
      const refreshed = await h.service.getWorkbenchState({ huntId });
      expect(refreshed.activeGate!.evidencePaging!.loaded).toBe(400);
      expect(Object.keys(refreshed.evidenceCatalog)).toHaveLength(400);

      // Stale cursor: the gate digest changes in the daemon while the desktop holds a cursor. Loading more fails
      // with an explanation and merges nothing.
      const real = h.store.getRun(huntId)!.open_gate!.payload_sha256;
      const moved = h.store.getRun(huntId)!;
      moved.open_gate = { ...moved.open_gate!, payload_sha256: "d".repeat(64) };
      h.store.saveRun(moved);
      await expect(h.service.loadMoreGateEvidence({ huntId })).rejects.toThrow(/changed since its evidence was loaded/);
      const restored = h.store.getRun(huntId)!;
      restored.open_gate = { ...restored.open_gate!, payload_sha256: real };
      h.store.saveRun(restored);
      const back = await h.service.getWorkbenchState({ huntId });
      expect(back.activeGate!.evidencePaging).toEqual({ loaded: 400, total: 1_200, hasMore: true });

      // Approve through the real daemon with 400 of 1,200 records loaded and every status complete.
      const done = await h.service.submitGateDecision({
        huntId, gate: "incident", action: "approve", operatorName: "x", rbacRole: "incident_commander",
        checkNote: "Checked every cited status.", payloadSha256: back.activeGate!.payloadSha256,
        operatorToken: h.gates.sessionAuthority.issueToken("real-analyst", "analyst"),
      });
      expect(done.gateHistory.map((d) => `${d.gate}:${d.action}`)).toEqual(["scope:approve", "incident:approve"]);
      expect(h.store.getRun(huntId)!.status).toBe("completed");

      // The completed run has no Load more: every one of its 1,200 records is read through hunt.evidencePage.
      expect(Object.keys(done.evidenceCatalog)).toHaveLength(1_200);
      expect(done.events).toHaveLength(1_200);
      expect([done.citationReceipt.totalCited, done.citationReceipt.allVerified]).toEqual([1_200, true]);
      expect(h.calls.filter((c) => c === "hunt.evidencePage")).toHaveLength(2);

      // A page that fails, or that does not continue the cited list, leaves no evidence rather than a partial list.
      const realRequest = h.sidecar.request.bind(h.sidecar);
      for (const tamper of [
        async () => { throw new Error("evidence_unavailable"); },
        async (params: Record<string, unknown>) => {
          const page = await realRequest("hunt.evidencePage", params) as { evidence: Array<{ id: string }> };
          return { ...page, evidence: page.evidence.slice(1) };
        },
      ]) {
        (h.sidecar as { request: unknown }).request = (method: string, params?: Record<string, unknown>) =>
          method === "hunt.evidencePage" ? tamper(params ?? {}) : realRequest(method, params);
        const broken = await h.service.getWorkbenchState({ huntId });
        expect(broken.evidenceCatalog).toEqual({});
        expect(broken.events).toEqual([]);
        expect(broken.citationReceipt.allVerified).toBe(false);
      }
    } finally {
      await h.close();
    }
  }, 120_000);

  test("a delayed workbench refresh cannot restore a decided gate", async () => {
    const h = await liveHarness(() => undefined);
    const refreshReady = Promise.withResolvers<void>();
    const releaseRefresh = Promise.withResolvers<void>();
    try {
      const snapshot = await toIncidentGate(h);
      const original = h.sidecar.request.bind(h.sidecar);
      let pause = true;
      Object.assign(h.sidecar, { request: async (method: string, params?: Record<string, unknown>) => {
        const result = await original(method, params);
        if (method === "case.metadata" && pause) {
          pause = false;
          refreshReady.resolve();
          await releaseRefresh.promise;
        }
        return result;
      } });
      const refreshing = h.service.getWorkbenchState({ huntId: snapshot.huntId });
      await refreshReady.promise;
      const decided = await h.service.submitGateDecision({
        huntId: snapshot.huntId, gate: "incident", action: "approve", operatorName: "x", rbacRole: "incident_commander",
        checkNote: "Checked the evidence.", payloadSha256: snapshot.activeGate!.payloadSha256,
        operatorToken: h.gates.sessionAuthority.issueToken("real-analyst", "analyst"),
      });
      expect(decided.runStatus).toBe("completed");
      expect(decided.activeGate).toBeNull();
      releaseRefresh.resolve();
      const late = await refreshing;
      expect(late.runStatus).toBe("completed");
      expect(late.activeGate).toBeNull();
      expect(late.gateHistory.map((decision) => decision.gate)).toEqual(["scope", "incident"]);
    } finally {
      releaseRefresh.resolve();
      await h.close();
    }
  });

  test("a delayed evidence page cannot restore a decided gate", async () => {
    const { h, huntId } = await bulkIncidentGate();
    const pageReady = Promise.withResolvers<void>();
    const releasePage = Promise.withResolvers<void>();
    try {
      const snapshot = await h.service.getWorkbenchState({ huntId });
      const original = h.sidecar.request.bind(h.sidecar);
      Object.assign(h.sidecar, { request: async (method: string, params?: Record<string, unknown>) => {
        const result = await original(method, params);
        if (method === "hunt.gateEvidencePage") {
          pageReady.resolve();
          await releasePage.promise;
        }
        return result;
      } });
      const loading = h.service.loadMoreGateEvidence({ huntId });
      await pageReady.promise;
      const decided = await h.service.submitGateDecision({
        huntId, gate: "incident", action: "approve", operatorName: "x", rbacRole: "incident_commander",
        checkNote: "Checked the evidence.", payloadSha256: snapshot.activeGate!.payloadSha256,
        operatorToken: h.gates.sessionAuthority.issueToken("real-analyst", "analyst"),
      });
      expect(decided.activeGate).toBeNull();
      releasePage.resolve();
      await expect(loading).rejects.toThrow(/changed|stale/i);
      const after = await h.service.getWorkbenchState({ huntId });
      expect(after.runStatus).toBe("completed");
      expect(after.activeGate).toBeNull();
    } finally {
      releasePage.resolve();
      await h.close();
    }
  }, 120_000);

  test("a page is rejected while an already-applied gate decision response is pending", async () => {
    const { h, huntId } = await bulkIncidentGate();
    const pageReady = Promise.withResolvers<void>();
    const decisionReady = Promise.withResolvers<void>();
    const releasePage = Promise.withResolvers<void>();
    const releaseDecision = Promise.withResolvers<void>();
    try {
      const snapshot = await h.service.getWorkbenchState({ huntId });
      const original = h.sidecar.request.bind(h.sidecar);
      Object.assign(h.sidecar, { request: async (method: string, params?: Record<string, unknown>) => {
        const result = await original(method, params);
        if (method === "hunt.gateEvidencePage") {
          pageReady.resolve();
          await releasePage.promise;
        } else if (method === "hunt.decideGate") {
          decisionReady.resolve();
          await releaseDecision.promise;
        }
        return result;
      } });
      const loading = h.service.loadMoreGateEvidence({ huntId }).then(() => null, (error: unknown) => error);
      await pageReady.promise;
      const deciding = h.service.submitGateDecision({
        huntId, gate: "incident", action: "approve", operatorName: "x", rbacRole: "incident_commander",
        checkNote: "Checked the evidence.", payloadSha256: snapshot.activeGate!.payloadSha256,
        operatorToken: h.gates.sessionAuthority.issueToken("real-analyst", "analyst"),
      });
      await decisionReady.promise;
      releasePage.resolve();
      expect(await loading).toBeInstanceOf(Error);
      releaseDecision.resolve();
      expect((await deciding).activeGate).toBeNull();
    } finally {
      releasePage.resolve();
      releaseDecision.resolve();
      await h.close();
    }
  }, 120_000);

  test("F18: Load more pages every one of 1,200 records in cited order and a refresh keeps them", async () => {
    const { h, ids, huntId } = await bulkIncidentGate();
    try {
      let view = await h.service.getWorkbenchState({ huntId });
      const seen: number[] = [view.activeGate!.evidencePaging!.loaded];
      for (let page = 0; page < 10 && view.activeGate!.evidencePaging!.hasMore; page++) {
        view = await h.service.loadMoreGateEvidence({ huntId });
        seen.push(view.activeGate!.evidencePaging!.loaded);
      }
      expect(seen).toEqual([200, 400, 600, 800, 1_000, 1_200]);
      expect(view.activeGate!.evidencePaging).toEqual({ loaded: 1_200, total: 1_200, hasMore: false });
      expect(Object.keys(view.evidenceCatalog).sort()).toEqual([...ids].sort());
      expect(view.evidenceCatalog[ids[1_199]!]?.fields["host.name"]).toBe(`bulk-host-${1_199 % 7}`);
      const kept = await h.service.getWorkbenchState({ huntId });
      expect(kept.activeGate!.evidencePaging).toEqual({ loaded: 1_200, total: 1_200, hasMore: false });
      expect(Object.keys(kept.evidenceCatalog)).toHaveLength(1_200);
    } finally {
      await h.close();
    }
  }, 120_000);

  test("when the gate context cannot be loaded, approve never reaches the daemon; reject still does", async () => {
    const h = await liveHarness(() => {
      throw new Error("method_not_found: Unknown RPC method 'hunt.gateContext'");
    });
    try {
      const snap = await toIncidentGate(h);
      expect(snap.activeGate?.contextError).toContain("method_not_found");
      const decide = (action: "approve" | "reject") => h.service.submitGateDecision({
        huntId: snap.huntId, gate: "incident", action, operatorName: "x", rbacRole: "incident_commander",
        checkNote: "Tried to approve blind.", payloadSha256: snap.activeGate!.payloadSha256,
        operatorToken: h.gates.sessionAuthority.issueToken("real-analyst", "analyst"),
      });
      const before = h.calls.filter((c) => c === "hunt.decideGate").length;
      await expect(decide("approve")).rejects.toThrow(/approval is disabled/);
      expect(h.calls.filter((c) => c === "hunt.decideGate").length).toBe(before);
      expect(h.store.getRun(snap.huntId)!.decisions.map((d) => d.gate)).toEqual(["scope"]);
      await decide("reject");
      expect(h.store.getRun(snap.huntId)!.decisions.map((d) => [d.gate, d.action])).toEqual([["scope", "approve"], ["incident", "reject"]]);
    } finally {
      await h.close();
    }
  });

  test("live transcript inspection pages through the daemon's hunt.inspectTranscriptPage", async () => {
    const h = await liveHarness(() => undefined);
    try {
      const started = await h.service.startRun({ caseId: h.caseId, dataOrigin: "synthetic", scope: "Investigate the process.", followUps: 0, maxTotalTokens: 100_000 });
      const stepId = Object.keys(h.store.getRun(started.huntId)!.results)[0]!;
      const first = await h.service.inspectTranscriptPage({ huntId: started.huntId, stepId, byteOffset: 0, byteLimit: 600 });
      expect(h.recorded.find(([m]) => m === "hunt.inspectTranscriptPage")?.[1]).toEqual({
        run_id: started.huntId, step_id: stepId, byte_offset: 0, byte_limit: 600,
      });
      expect(first.content.length).toBeGreaterThan(0);
      expect(first.content).not.toContain("untrusted_tool_result_");
      expect(first.totalBytes).toBeGreaterThan(first.byteLength);
      expect(first.hasMore).toBe(true);
      const second = await h.service.inspectTranscriptPage({ huntId: started.huntId, stepId, byteOffset: first.nextByteOffset!, byteLimit: 600 });
      expect(second.byteOffset).toBe(first.nextByteOffset!);
      await expect(h.service.inspectTranscriptPage({ huntId: started.huntId, stepId: "no-such-step", byteOffset: 0, byteLimit: 600 })).rejects.toThrow(/step_not_found/);
    } finally {
      await h.close();
    }
  });

});
