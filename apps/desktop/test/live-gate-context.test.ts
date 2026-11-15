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

function incidentContext(overrides: Record<string, unknown> = {}) {
  return {
    run_id: "run-1", case_id: "c1", gate: "incident", payload_sha256: DIGEST,
    incident: {
      citation_receipt: {
        verified: true, checked_at: "2026-11-14T10:00:00Z", case_id: "c1", total_checked: 1,
        missing_event_ids: [], missing_frame_ids: [], missing_ioc_ids: [], ambiguous_ids: [], out_of_scope_ids: [],
        source_status: "ok",
      },
      evidence: [{
        id: EVT, kind: "evt", status: "verified", timestamp_iso: "2026-11-14T10:01:00Z",
        title: "Process executed.", fields: { "host.name": "wks-01", "process.name": "beacon.exe", message: "Process executed." },
      }],
      evidence_truncated: false,
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

  test("truncated incident evidence is never presented as complete or approvable", () => {
    const ctx = incidentContext();
    ctx.incident.evidence_truncated = true;
    const p = projectLiveGate("run-1", OPEN, HANDOFFS, ctx);
    expect(p.activeGate.contextError).toContain("truncated");
    expect(p.activeGate.incidentSummary).toBeUndefined();
    expect(p.citationReceipt).toBeNull();
    expect(p.activeGate.incidentHandoff?.claims[0]?.statement).toContain("Beacon seen");
    expect(validateGateSubmission(p.activeGate, draft("approve")).valid).toBe(false);
    expect(validateGateSubmission(p.activeGate, draft("reject")).valid).toBe(true);
  });

  test("truncated reconcile evidence also blocks approval", () => {
    const inc = incidentContext().incident;
    const p = projectLiveGate("run-1", { ...OPEN, gate: "reconcile" }, HANDOFFS, {
      run_id: "run-1", case_id: "c1", gate: "reconcile", payload_sha256: DIGEST,
      reconcile: { reason_code: "citation_source_unavailable", citation_receipt: inc.citation_receipt,
        unavailable_sources: [], evidence: inc.evidence, evidence_truncated: true },
    });
    expect(p.activeGate.contextError).toContain("truncated");
    expect(validateGateSubmission(p.activeGate, draft("approve")).valid).toBe(false);
    expect(validateGateSubmission(p.activeGate, draft("reject")).valid).toBe(true);
  });

  test("an absent incident handoff cannot be approved", () => {
    const p = projectLiveGate("run-1", OPEN, [], incidentContext());
    expect(p.activeGate.contextError).toContain("incident handoff");
    expect(validateGateSubmission(p.activeGate, draft("approve")).valid).toBe(false);
  });

  test("unresolved citations keep approve blocked by the citation rule", () => {
    const ctx = incidentContext();
    (ctx.incident as { evidence: Array<{ status: string }> }).evidence[0]!.status = "unresolved";
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
      ["uncovered citation", incidentContext({ incident: { ...incidentContext().incident, evidence: [] } })],
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
      reconcile: { reason_code: "previous_dispatch_unknown", receipts: [{ execution_id: "exec-1", session_id: "sess-1", input_id: "in-1", step_id: "analysis", profile: "framework-coordinator", reserved_at: "2026-11-14T10:00:05Z", reason_code: "previous_dispatch_unknown" }] },
    });
    expect(p.activeGate.reconcileContext).toEqual({
      executionId: "exec-1", sessionId: "sess-1", inputId: "in-1", stepId: "analysis",
      profile: "framework-coordinator", reservedAtIso: "2026-11-14T10:00:05Z", reasonCode: "previous_dispatch_unknown",
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
        evidence: [{ ...inc.evidence[0]!, status: "unresolved", timestamp_iso: null, title: "", fields: {} }],
        evidence_truncated: false,
      },
    }, undefined, HANDOFFS[0]);
    expect(p.activeGate.contextError).toBeUndefined();
    const rc = p.activeGate.reconcileContext!;
    expect(rc.reasonCode).toBe("citation_source_unavailable");
    if (rc.reasonCode !== "citation_source_unavailable") throw new Error("narrowing");
    expect(rc.unavailableSources).toEqual(["events"]);
    expect(rc.citationReceipt.entries.map((e) => [e.citationId, e.status])).toEqual([[EVT, "unresolved"]]);
    expect(missingGateContextReason(p.activeGate)).toBeNull();
    expect(validateGateSubmission(p.activeGate, draft("approve")).valid).toBe(true);
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
        evidence: [], evidence_truncated: false,
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
    expect(p.evidenceCatalog).toEqual({});
    expect(p.events).toEqual([]);
    expect(validateGateSubmission(p.activeGate, draft("approve")).valid).toBe(true);

    const partial = projectLiveGate("run-1", open, [], {
      ...context,
      reconcile: { ...context.reconcile, unavailable_sources: ["packets", "intel"], evidence: inc.evidence },
    }, undefined, failed);
    expect(partial.activeGate.contextError).toBeUndefined();
    expect(partial.citationReceipt).toMatchObject({ verifiedCount: 1, unresolvedCount: 2, allVerified: false });
    expect(partial.evidenceCatalog[EVT]?.fields["host.name"]).toBe("wks-01");
    expect(Object.keys(partial.evidenceCatalog)).toEqual([EVT]);
    expect(partial.events.map((event) => event.eventId)).toEqual([EVT]);

    const cases = [
      { ...context.reconcile, unavailable_sources: ["events", "packets"] },
      { ...context.reconcile, unavailable_sources: [] },
      { ...context.reconcile, unavailable_sources: ["unrelated"] },
      { ...context.reconcile, evidence_truncated: true },
      { ...context.reconcile, evidence_truncated: undefined },
      { ...context.reconcile, citation_receipt: { ...context.reconcile.citation_receipt, case_id: "other-case" } },
      { ...context.reconcile, evidence: [{ ...inc.evidence[0]!, kind: "ioc" }] },
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
        unavailable_sources: [], evidence: inc.evidence, evidence_truncated: false } };
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
) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "hc-live-gate-"));
  const caseId = "gate-case";
  const caseDir = path.join(root, "cases", caseId);
  fs.mkdirSync(caseDir, { recursive: true });
  fs.writeFileSync(path.join(caseDir, "case.json"), JSON.stringify({
    case_id: caseId, question: "Which host ran the process?", data_origin: "synthetic",
    time_range_utc: { start_inclusive: "2026-11-14T10:00:00Z", end_exclusive: "2026-11-14T11:00:00Z" },
  }));
  fs.writeFileSync(path.join(caseDir, "events.jsonl"), `${JSON.stringify({
    "@timestamp": "2026-11-14T10:01:00Z", event: { id: "evt-1", code: "1" }, host: { name: "gate-host" }, message: "Process executed.",
  })}\n`);
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
  const rpcResolver = citedRecordsUnavailable
    ? async (caseId: string) => {
        const plane = await resolver.resolve(caseId);
        return new Proxy(plane, {
          get(target, key) {
            if (key === "readCitedRecords") return async () => { throw new Error("citation source unavailable"); };
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
  return { service, runtimePaths, sidecar, store, gates, calls, recorded, caseId, close };
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
      const context = await h.sidecar.request("hunt.gateContext", { run_id: run.run_id }) as {
        reconcile: { unavailable_sources: string[]; evidence: unknown[]; evidence_truncated: boolean };
      };
      expect(context.reconcile.unavailable_sources).toEqual(["events"]);
      expect(context.reconcile.evidence).toEqual([]);
      expect(context.reconcile.evidence_truncated).toBe(false);
      const snapshot = await h.service.getWorkbenchState({ huntId: run.run_id });
      expect(snapshot.activeGate?.contextError).toBeUndefined();
      expect(snapshot.activeGate?.reconcileContext?.reasonCode).toBe("citation_source_unavailable");
      expect(snapshot.citationReceipt.entries.map((entry) => entry.citationId)).toEqual([EVT]);
      expect(snapshot.citationReceipt.entries[0]?.status).toBe("unresolved");
      expect(snapshot.citationReceipt.allVerified).toBe(false);
      expect(snapshot.activeGate?.reconcileContext?.reasonCode === "citation_source_unavailable" &&
        snapshot.activeGate.reconcileContext.unavailableSources).toEqual(["events"]);
      expect(missingGateContextReason(snapshot.activeGate!)).toBeNull();
      await h.service.submitGateDecision({
        huntId: run.run_id, gate: "reconcile", action: "approve", operatorName: "x", rbacRole: "incident_commander",
        checkNote: "Reviewed the unavailable source.", payloadSha256: snapshot.activeGate!.payloadSha256,
        operatorToken: h.gates.sessionAuthority.issueToken("real-analyst", "analyst"),
      });
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

  test("direct desktop RPC cannot bypass the truncated evidence gate", async () => {
    const h = await liveHarness(() => undefined);
    try {
      const snap = await toIncidentGate(h);
      const run = h.store.getRun(snap.huntId)!;
      const result = run.results["incident"]!;
      const ids = Array.from({ length: 501 }, (_, i) => `evt-${i.toString(16).padStart(16, "0")}`);
      run.results["incident"] = { ...result, handoff: { ...result.handoff!, limitations: [ids.join(" ")] } };
      h.store.saveRun(run);
      const input = { hunt_id: snap.huntId, gate: "incident", via: "desktop", payload_sha256: snap.activeGate!.payloadSha256,
        check_note: "Reviewed evidence.", operator_token: h.gates.sessionAuthority.issueToken("real-analyst", "analyst") };
      await expect(h.sidecar.request("hunt.decideGate", { ...input, action: "approve" })).rejects.toThrow(/truncated/);
      expect(h.store.getRun(snap.huntId)!.decisions.map((d) => d.gate)).toEqual(["scope"]);
      await h.sidecar.request("hunt.decideGate", { ...input, action: "reject" });
      expect(h.store.getRun(snap.huntId)!.decisions.at(-1)?.action).toBe("reject");
    } finally {
      await h.close();
    }
  });


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
