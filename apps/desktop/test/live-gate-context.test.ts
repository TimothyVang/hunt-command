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
      ["other gate", { ...incidentContext(), gate: "reconcile", incident: undefined, reconcile: { receipts: [{ execution_id: "e", session_id: "s", input_id: "i", step_id: "x", profile: "framework-coordinator", reserved_at: "t", reason_code: "previous_dispatch_unknown" }] } }],
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
      reconcile: { receipts: [{ execution_id: "exec-1", session_id: "sess-1", input_id: "in-1", step_id: "analysis", profile: "framework-coordinator", reserved_at: "2026-11-14T10:00:05Z", reason_code: "previous_dispatch_unknown" }] },
    });
    expect(p.activeGate.reconcileContext).toEqual({
      executionId: "exec-1", sessionId: "sess-1", inputId: "in-1", stepId: "analysis",
      profile: "framework-coordinator", reservedAtIso: "2026-11-14T10:00:05Z", reasonCode: "previous_dispatch_unknown",
    });
    expect(missingGateContextReason(p.activeGate)).toBeNull();
  });
});

describe("F8: live transcript pages", () => {
  test("daemon page is validated and mapped; mismatched or failed pages become an error view", () => {
    const raw = { run_id: "run-1", step_id: "incident", profile: "framework-coordinator", byte_offset: 0, byte_length: 5, total_bytes: 9, has_more: true, content: "hello" };
    const page = projectTranscriptPage(raw, "run-1", "incident");
    expect(page).toEqual({ huntId: "run-1", stepId: "incident", profile: "framework-coordinator", byteOffset: 0, byteLength: 5, totalBytes: 9, hasMore: true, content: "hello" });
    expect(() => projectTranscriptPage({ ...raw, step_id: "other" }, "run-1", "incident")).toThrow();
    expect(() => projectTranscriptPage({ ...raw, extra: 1 }, "run-1", "incident")).toThrow();

    const req = { huntId: "run-1", stepId: "incident", byteOffset: 0 };
    expect(transcriptViewFor(req, { ok: true, data: page })).toEqual({ kind: "page", page });
    expect(transcriptViewFor(req, { ok: false, error: { code: "IPC_HANDLER_ERROR", message: "method_not_found" } })).toEqual({ kind: "error", message: "method_not_found" });
    expect(transcriptViewFor({ ...req, stepId: "analysis" }, { ok: true, data: page }).kind).toBe("error");
  });
});

/** In-process daemon (real engine, store, gates, RPC server) behind a sidecar-shaped adapter. */
async function liveHarness(gateContext: (params: Record<string, unknown>, store: DurableStateStore) => unknown) {
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
        claims: [{ claim_id: `${req.stepId}:c1`, kind: "observed", statement: "The process was observed.", evidence_ids: ["events.jsonl"], entity_ids: [], contradicts: [] }],
        reviews: [], disposition: "review_ready", limitations: [], requested_decisions: [],
      }),
      usage: { input_tokens: 1, output_tokens: 1, cache_read_tokens: 0, cache_write_tokens: 0, total_tokens: 2, turns: 1, provider: "anthropic", model: "stub", billing_mode: "oauth_subscription", actual_billed_usd: 0, shadow_api_usd: 0, cache_savings_usd: 0 },
    }),
  };
  const engine = new HuntWaveEngine({ stateStore: store, gateAuthority: gates, modelRunner: runner, telemetry: new InMemoryTelemetrySink(), resolveDataPlane: resolver.resolve });
  const replies = new Map<number, { result?: unknown; error?: { message: string; error_code?: string } }>();
  const rpc = new HuntDaemonRpcServer({
    engine, resolveDataPlane: resolver.resolve,
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
      if (method === "hunt.gateContext") return gateContext(params ?? {}, store);
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
  return { service, store, gates, calls, recorded, caseId, close };
}

async function toIncidentGate(h: Awaited<ReturnType<typeof liveHarness>>) {
  const started = await h.service.startRun({ caseId: h.caseId, dataOrigin: "synthetic", scope: "Investigate the process.", followUps: 0, maxTotalTokens: 100_000 });
  expect(started.activeGate?.gate).toBe("scope");
  expect(started.activeGate?.scopeText).toBe("Investigate the process.");
  const atIncident = await h.service.submitGateDecision({
    huntId: started.huntId, gate: "scope", action: "approve", operatorName: "x", rbacRole: "incident_commander",
    checkNote: "Reviewed the scope.", payloadSha256: started.activeGate!.payloadSha256,
    operatorToken: h.gates.sessionAuthority.issueToken("real-analyst", "analyst"),
  });
  expect(atIncident.activeGate?.gate).toBe("incident");
  return atIncident;
}

describe("F4 end to end through WorkbenchService and the real daemon engine", () => {
  test("the incident gate shows daemon-supplied context and can be approved", async () => {
    const h = await liveHarness((params, store) => {
      const run = store.getRun(String(params.run_id))!;
      return {
        run_id: run.run_id, case_id: run.case_id, gate: run.open_gate!.gate, payload_sha256: run.open_gate!.payload_sha256,
        incident: {
          citation_receipt: { verified: true, checked_at: "t", case_id: run.case_id, total_checked: 0, missing_event_ids: [], missing_frame_ids: [], missing_ioc_ids: [], ambiguous_ids: [], out_of_scope_ids: [], source_status: "ok" },
          evidence: [], evidence_truncated: false,
        },
      };
    });
    try {
      const snap = await toIncidentGate(h);
      expect(snap.activeGate?.contextError).toBeUndefined();
      expect(snap.activeGate?.incidentSummary?.observedCount).toBeGreaterThan(0);
      expect(h.calls).toContain("hunt.gateContext");
      const done = await h.service.submitGateDecision({
        huntId: snap.huntId, gate: "incident", action: "approve", operatorName: "x", rbacRole: "incident_commander",
        checkNote: "Checked the incident claims.", payloadSha256: snap.activeGate!.payloadSha256,
        operatorToken: h.gates.sessionAuthority.issueToken("real-analyst", "analyst"),
      });
      expect(done.gateHistory.map((d) => d.gate)).toEqual(["scope", "incident"]);
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

  test("live transcript inspection calls hunt.inspectTranscriptPage and surfaces a daemon failure", async () => {
    const h = await liveHarness(() => null);
    try {
      const started = await h.service.startRun({ caseId: h.caseId, dataOrigin: "synthetic", scope: "Investigate the process.", followUps: 0, maxTotalTokens: 100_000 });
      // This daemon build has no such method: the error propagates (the pane renders it); nothing is invented.
      await expect(
        h.service.inspectTranscriptPage({ huntId: started.huntId, stepId: "scope", byteOffset: 0, byteLimit: 4096 }),
      ).rejects.toThrow(/method_not_found|Unknown RPC method/);
      expect(h.recorded.find(([m]) => m === "hunt.inspectTranscriptPage")?.[1]).toEqual({
        run_id: started.huntId, step_id: "scope", byte_offset: 0, byte_limit: 4096,
      });
    } finally {
      await h.close();
    }
  });
});
