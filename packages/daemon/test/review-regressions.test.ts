import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { resolveRuntimeDir, type CaseMetadata, type Handoff, type ProfileId } from "@hunt-command/shared";
import {
  DurableStateStore,
  GateAuthority,
  GateDecisionError,
  HuntDaemonRpcServer,
  HuntWaveEngine,
  acquireRuntimeLock,
  createHuntDaemonRuntime,
  executeDriveGates,
  runHuntCli,
  runtimeLockPath,
  type HuntDataPlanePort,
  type ModelRunnerPort,
  type ModelTurnRequest,
  type PersistedHuntRun,
  type StepTurnResult,
} from "../src/index.ts";

const tempDirs: string[] = [];
function makeTmpDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hunt-review-regress-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop()!;
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {}
  }
});

function makeHandoff(caseId: string, stepId: string, profile: ProfileId): Handoff {
  return {
    schema_version: 1,
    case_id: caseId,
    step_id: stepId,
    profile,
    claims: [
      {
        claim_id: `${stepId}:c1`,
        kind: stepId === "incident" ? "finding" : "observed",
        statement: "Synthetic regression claim citing evt-1.",
        evidence_ids: ["elastic-logs"],
        entity_ids: [],
        contradicts: [],
      },
    ],
    reviews: [],
    disposition: "review_ready",
    limitations: [],
    requested_decisions: [],
  };
}

function makeDataPlane(opts?: { failCapabilitiesOnce?: boolean; caseId?: string }): HuntDataPlanePort {
  const meta: CaseMetadata = {
    case_id: opts?.caseId ?? "case-regress-01",
    title: "Review regression case",
    data_origin: "synthetic",
    synthetic_only: true,
    time_window: { start_iso: "2026-11-01T00:00:00Z", end_iso: "2026-11-01T01:00:00Z" },
    sources: ["elastic-logs"],
  };
  let failNext = opts?.failCapabilitiesOnce ?? false;
  return {
    caseMetadata: meta,
    capabilities: () => {
      if (failNext) {
        failNext = false;
        throw new Error("synthetic data plane outage");
      }
      return { hasNetworkCapture: false, hasIntelSource: false, sources: meta.sources };
    },
    executeTool: async () => ({}),
    verifyCitations: async (req) => ({
      verified: true,
      checked_at: new Date().toISOString(),
      case_id: req.case_id,
      total_checked: req.event_ids.length,
      missing_event_ids: [],
      missing_frame_ids: [],
      missing_ioc_ids: [],
      ambiguous_ids: [],
      out_of_scope_ids: [],
      source_status: "ok",
    }),
  };
}

function makeRunner(gate?: Promise<void>): ModelRunnerPort {
  return {
    getPinnedModelForRole: () => ({
      provider: "anthropic",
      model: "claude-sonnet-4-6",
      fallback_providers: [],
    }),
    preflightWave: async () => {},
    runTurn: async (req: ModelTurnRequest): Promise<StepTurnResult> => {
      if (gate) await gate;
      return {
        status: "completed",
        output_text: JSON.stringify(makeHandoff(req.caseId, req.stepId, req.profile)),
        usage: {
          input_tokens: 100,
          output_tokens: 50,
          cache_read_tokens: 0,
          cache_write_tokens: 0,
          total_tokens: 150,
          turns: 1,
          provider: "anthropic",
          model: "claude-sonnet-4-6",
          billing_mode: "oauth_subscription",
          actual_billed_usd: 0,
          shadow_api_usd: 0.001,
          cache_savings_usd: 0,
        },
      };
    },
  };
}

function makeEngine(
  dbPath: string,
  decisionsDir: string,
  opts?: { resolveDataPlane?: (caseId: string) => HuntDataPlanePort; runnerGate?: Promise<void> },
) {
  const store = new DurableStateStore(dbPath);
  const gates = new GateAuthority({ stateStore: store, decisionsDir });
  const engine = new HuntWaveEngine({
    stateStore: store,
    gateAuthority: gates,
    modelRunner: makeRunner(opts?.runnerGate),
    resolveDataPlane: opts?.resolveDataPlane,
  });
  return { store, gates, engine };
}

function seedRunningRunWithReservedReceipt(store: DurableStateStore, runId: string): void {
  const now = new Date().toISOString();
  store.saveRun({
    run_id: runId,
    case_id: "case-regress-01",
    data_origin: "synthetic",
    synthetic_only: true,
    wave: "analysis",
    wave_index: 2,
    status: "running",
    reason_code: null,
    step_states: { scope: "done", evidence: "done", analysis: "working" },
    results: {},
    handoff_rejections: [],
    reviewed_handoffs: {},
    delegated_ledger: [],
    open_gate: null,
    decisions: [],
    token_ledger: {
      max_total_tokens: 100_000,
      consumed_total_tokens: 0,
      results_tokens: 0,
      rejections_tokens: 0,
      delegated_tokens: 0,
      actual_billed_usd: 0,
      shadow_api_usd: 0,
      cache_savings_usd: 0,
    },
    citation_receipt: null,
    snapshot: null,
    config: { scopeText: "Regression scope.", followUps: 0, maxTotalTokens: 100_000 },
    created_at: now,
    updated_at: now,
  });
  const reserved = store.reserveReceipt({
    executionId: `${runId}:analysis`,
    runId,
    stepId: "analysis",
    sessionId: `${runId}:analysis`,
    inputId: "in-1",
    fingerprint: "fp-1",
  });
  expect(reserved.action).toBe("proceed");
}

function captureIo() {
  const out: string[] = [];
  const err: string[] = [];
  return {
    out,
    err,
    io: { writeStdout: (t: string) => void out.push(t), writeStderr: (t: string) => void err.push(t) },
  };
}

async function* linesOf(...lines: string[]): AsyncIterable<string> {
  for (const l of lines) yield `${l}\n`;
}

describe("Review regressions (slice 2)", () => {
  // Finding 1
  test("read-only CLI commands never run crash recovery; only the single-instance serve does", async () => {
    const runtimeDir = makeTmpDir();
    const paths = resolveRuntimeDir(runtimeDir);
    const seedStore = new DurableStateStore(paths.daemonStateDbPath);
    seedRunningRunWithReservedReceipt(seedStore, "hunt-live-01");
    seedStore.close();

    // A second process running `hunt status` / `hunt gates status` must not touch in-flight state.
    const c1 = captureIo();
    expect(await runHuntCli(["status", "--hunt-id", "hunt-live-01", "--runtime-dir", runtimeDir], c1.io)).toBe(0);
    const c2 = captureIo();
    expect(
      await runHuntCli(["gates", "status", "--hunt-id", "hunt-live-01", "--runtime-dir", runtimeDir], c2.io),
    ).toBe(0);
    const ctx = createHuntDaemonRuntime({ runtimeDir });
    expect(ctx.recoveredRuns.length).toBe(0);
    expect(ctx.stateStore.listReceiptsForRun("hunt-live-01")[0]!.status).toBe("reserved");
    expect(ctx.stateStore.getRun("hunt-live-01")!.status).toBe("running");
    ctx.stateStore.close();

    // While a live daemon holds the runtime lock: serve and mutating commands are refused.
    const lockPath = runtimeLockPath(paths.stateDir);
    const live = acquireRuntimeLock(lockPath);
    const c3 = captureIo();
    expect(
      await runHuntCli(["serve", "--runtime-dir", runtimeDir], c3.io, {
        resolveDataPlane: () => makeDataPlane(),
        stdin: linesOf(),
      }),
    ).toBe(1);
    expect(c3.err.join("")).toContain("held by live pid");
    const c4 = captureIo();
    expect(await runHuntCli(["cancel", "--hunt-id", "hunt-live-01", "--runtime-dir", runtimeDir], c4.io)).toBe(1);
    const check = new DurableStateStore(paths.daemonStateDbPath);
    expect(check.getRun("hunt-live-01")!.status).toBe("running");
    expect(check.listReceiptsForRun("hunt-live-01")[0]!.status).toBe("reserved");
    check.close();
    live.release();

    // A stale lock from a dead pid is reclaimed; serve then recovers and removes its lock on exit.
    fs.writeFileSync(lockPath, JSON.stringify({ pid: 2_147_483_000, acquired_at: "2026-01-01T00:00:00Z" }));
    const c5 = captureIo();
    expect(
      await runHuntCli(["serve", "--runtime-dir", runtimeDir], c5.io, {
        resolveDataPlane: () => makeDataPlane(),
        stdin: linesOf(),
      }),
    ).toBe(0);
    expect(fs.existsSync(lockPath)).toBe(false);
    const after = new DurableStateStore(paths.daemonStateDbPath);
    expect(after.getRun("hunt-live-01")!.status).toBe("awaiting_gate");
    expect(after.getRun("hunt-live-01")!.open_gate?.gate).toBe("reconcile");
    expect(after.listReceiptsForRun("hunt-live-01")[0]!.status).toBe("previous_dispatch_unknown");
    after.close();
  });

  // Finding 1 (RPC)
  test("RPC hunt.recover is rejected while hunts are actively executing", async () => {
    const tmp = makeTmpDir();
    const release = Promise.withResolvers<void>();
    const { store, engine } = makeEngine(path.join(tmp, "s.sqlite"), path.join(tmp, "dec"), {
      runnerGate: release.promise,
    });
    const dp = makeDataPlane();
    const rpc = new HuntDaemonRpcServer({ engine, resolveDataPlane: () => dp, writeLine: () => {} });

    const pending = engine.startHunt({ runId: "hunt-active-01", scopeText: "Active scope.", dataPlane: dp, followUps: 0 });
    await Bun.sleep(10);
    expect(engine.getActiveHuntCount()).toBe(1);
    const resp = await rpc.handleLine(JSON.stringify({ jsonrpc: "2.0", id: "r1", method: "hunt.recover" }));
    expect(resp.error?.message).toContain("recover_refused_active_hunts");
    expect(() => engine.recoverInFlightRunsOnStartup()).toThrow(/recover_refused_active_hunts/);

    release.resolve();
    await pending;
    store.close();
  });

  // Finding 2
  test("gate approval with no resolvable data plane fails WITHOUT recording or burning the decision", async () => {
    const tmp = makeTmpDir();
    const dbPath = path.join(tmp, "s.sqlite");
    const decisionsDir = path.join(tmp, "dec");
    const first = makeEngine(dbPath, decisionsDir);
    const parked = await first.engine.startHunt({
      runId: "hunt-dp-01",
      scopeText: "Scope for data plane regression.",
      dataPlane: makeDataPlane(),
      followUps: 0,
    });
    expect(parked.open_gate?.gate).toBe("scope");
    const secretCarrier = first.gates.sessionAuthority;
    first.store.close();

    // "Restarted" engine (no in-memory data plane, no resolver), same token authority
    const store2 = new DurableStateStore(dbPath);
    const gates2 = new GateAuthority({ stateStore: store2, decisionsDir, sessionAuthority: secretCarrier });
    const engine2 = new HuntWaveEngine({ stateStore: store2, gateAuthority: gates2, modelRunner: makeRunner() });
    const token = secretCarrier.issueToken("alice", "analyst");
    const decision = {
      decisionId: "dec-dp-regress-1",
      huntId: "hunt-dp-01",
      gate: "scope",
      action: "approve" as const,
      via: "cli" as const,
      operatorToken: token,
      payloadSha256: parked.open_gate!.payload_sha256,
      checkNote: "Scope verified.",
    };
    await expect(engine2.submitGateDecision(decision)).rejects.toThrow(/decision NOT recorded/);
    const untouched = store2.getRun("hunt-dp-01")!;
    expect(untouched.status).toBe("awaiting_gate");
    expect(untouched.open_gate?.gate).toBe("scope");
    expect(untouched.decisions.length).toBe(0);
    expect(fs.existsSync(gates2.decisionsLogPath)).toBe(false);
    store2.close();

    // With a resolveDataPlane factory, the SAME decision_id is still usable and resumes the run.
    const store3 = new DurableStateStore(dbPath);
    const gates3 = new GateAuthority({ stateStore: store3, decisionsDir, sessionAuthority: secretCarrier });
    const resolved: string[] = [];
    const engine3 = new HuntWaveEngine({
      stateStore: store3,
      gateAuthority: gates3,
      modelRunner: makeRunner(),
      resolveDataPlane: (caseId) => {
        resolved.push(caseId);
        return makeDataPlane();
      },
    });
    const advanced = await engine3.submitGateDecision(decision);
    expect(resolved).toEqual(["case-regress-01"]);
    expect(advanced.open_gate?.gate).toBe("incident");
    store3.close();
  });

  // Finding 2 (orphaned runs)
  test("a committed approval whose resumption failed is left resumable and continues via RPC hunt.resume", async () => {
    const tmp = makeTmpDir();
    const { store, gates, engine } = makeEngine(path.join(tmp, "s.sqlite"), path.join(tmp, "dec"));
    const parked = await engine.startHunt({
      runId: "hunt-orphan-01",
      scopeText: "Orphan scope.",
      dataPlane: makeDataPlane(),
      followUps: 0,
    });
    await expect(
      engine.submitGateDecision(
        {
          huntId: "hunt-orphan-01",
          gate: "scope",
          action: "approve",
          via: "cli",
          operatorToken: gates.sessionAuthority.issueToken("alice", "analyst"),
          payloadSha256: parked.open_gate!.payload_sha256,
          checkNote: "Approved.",
        },
        makeDataPlane({ failCapabilitiesOnce: true }),
      ),
    ).rejects.toThrow(/outage/);
    expect(store.getRun("hunt-orphan-01")!.status).toBe("running");
    expect(engine.listResumableRuns().map((r) => r.run_id)).toEqual(["hunt-orphan-01"]);

    const rpc = new HuntDaemonRpcServer({ engine, resolveDataPlane: () => makeDataPlane(), writeLine: () => {} });
    const resp = await rpc.handleLine(
      JSON.stringify({ jsonrpc: "2.0", id: "res1", method: "hunt.resume", params: { run_id: "hunt-orphan-01" } }),
    );
    expect((resp.result as PersistedHuntRun).open_gate?.gate).toBe("incident");
    store.close();
  });

  // F3 follow-up: a resolved data plane must serve the run's own case before anything changes.
  test("gate resume, hunt.resume and data-plane registration refuse a plane for another case", async () => {
    const tmp = makeTmpDir();
    const dbPath = path.join(tmp, "s.sqlite");
    const decisionsDir = path.join(tmp, "dec");
    const first = makeEngine(dbPath, decisionsDir);
    const parked = await first.engine.startHunt({
      runId: "hunt-bind-01",
      scopeText: "Binding scope.",
      dataPlane: makeDataPlane(),
      followUps: 0,
    });
    expect(parked.open_gate?.gate).toBe("scope");
    first.store.close();

    // A restarted daemon whose resolver returns a different case for this run's case_id.
    const wrong = makeEngine(dbPath, decisionsDir, { resolveDataPlane: () => makeDataPlane({ caseId: "case-other-99" }) });
    const before = wrong.store.getRun("hunt-bind-01")!;
    const rpc = new HuntDaemonRpcServer({ engine: wrong.engine, writeLine: () => {} });
    const decide = (operatorToken: string) => ({
      jsonrpc: "2.0",
      id: "d1",
      method: "hunt.decideGate",
      params: {
        decision_id: "dec-bind-01",
        hunt_id: "hunt-bind-01",
        gate: "scope",
        action: "approve",
        operator_token: operatorToken,
        payload_sha256: parked.open_gate!.payload_sha256,
        check_note: "Approved.",
      },
    });
    const refused = await rpc.handleLine(
      JSON.stringify(decide(wrong.gates.sessionAuthority.issueToken("alice", "analyst"))),
    );
    expect(refused.error?.error_code).toBe("case_mismatch");
    expect(wrong.store.getRun("hunt-bind-01")).toEqual(before);

    const resumeRefused = await rpc.handleLine(
      JSON.stringify({ jsonrpc: "2.0", id: "r1", method: "hunt.resume", params: { run_id: "hunt-bind-01" } }),
    );
    expect(resumeRefused.error?.error_code).toBe("case_mismatch");
    expect(() => wrong.engine.registerDataPlaneForRun("hunt-bind-01", makeDataPlane({ caseId: "case-other-99" }))).toThrow(
      /case-other-99/,
    );
    expect(wrong.store.getRun("hunt-bind-01")).toEqual(before);
    wrong.store.close();

    // The decision id was not burned: the same decision succeeds once the right case resolves.
    const right = makeEngine(dbPath, decisionsDir, { resolveDataPlane: () => makeDataPlane() });
    const accepted = await new HuntDaemonRpcServer({ engine: right.engine, writeLine: () => {} }).handleLine(
      JSON.stringify(decide(right.gates.sessionAuthority.issueToken("alice", "analyst"))),
    );
    expect(accepted.error).toBeUndefined();
    expect((accepted.result as PersistedHuntRun).decisions.map((d) => d.decision_id)).toContain("dec-bind-01");
    right.store.close();
  });

  // Finding 3
  test("serve wires an injected data-plane factory into hunt.start", async () => {
    const runtimeDir = makeTmpDir();
    const requested: string[] = [];
    const c2 = captureIo();
    const code = await runHuntCli(["serve", "--runtime-dir", runtimeDir], c2.io, {
      resolveDataPlane: (caseId) => {
        requested.push(caseId);
        // Invalid case metadata makes startHunt fail closed BEFORE any model turn.
        return { ...makeDataPlane(), caseMetadata: {} as CaseMetadata };
      },
      stdin: linesOf(
        JSON.stringify({
          jsonrpc: "2.0",
          id: "s1",
          method: "hunt.start",
          params: { case_id: "case-wired-01", scope: "Wiring check." },
        }),
      ),
    });
    expect(code).toBe(0);
    expect(requested).toEqual(["case-wired-01"]);
    const resp = JSON.parse(c2.out.join("").trim().split("\n").pop()!) as {
      error: { error_code: string; message: string };
    };
    expect(resp.error.message).not.toContain("No resolveDataPlane factory");
    expect(resp.error.error_code).toBe("case_origin_mismatch");
  });

  // Finding 4
  test("RPC cannot mint tokens, and gate decisions require a verified token (caller principal/role ignored)", async () => {
    const tmp = makeTmpDir();
    const dp = makeDataPlane();
    const { store, gates, engine } = makeEngine(path.join(tmp, "s.sqlite"), path.join(tmp, "dec"), {
      resolveDataPlane: () => dp,
    });
    const lines: string[] = [];
    const rpc = new HuntDaemonRpcServer({ engine, writeLine: (l) => lines.push(l) });
    const call = (method: string, params?: Record<string, unknown>) =>
      rpc.handleLine(JSON.stringify({ jsonrpc: "2.0", id: method, method, params }));

    const mint = await call("daemon.issueOperatorToken", { principal: "mallory", rbac_role: "admin" });
    expect(mint.error?.error_code).toBe("method_not_found");

    const started = await call("hunt.start", { run_id: "hunt-auth-01", case_id: dp.caseMetadata.case_id, scope: "Auth scope.", follow_ups: 0 });
    const digest = (started.result as PersistedHuntRun).open_gate!.payload_sha256;

    const bare = await call("hunt.decideGate", {
      hunt_id: "hunt-auth-01",
      gate: "scope",
      action: "approve",
      via: "cli",
      authenticated_principal: "mallory",
      rbac_role: "admin",
      payload_sha256: digest,
      check_note: "forged",
    });
    expect(bare.error?.error_code).toBe("invalid_operator_token");

    const slackSpoof = await call("hunt.decideGate", {
      hunt_id: "hunt-auth-01",
      gate: "scope",
      action: "approve",
      via: "slack",
      authenticated_principal: "slack:U0SPOOF",
      rbac_role: "admin",
      payload_sha256: digest,
      check_note: "forged",
    });
    expect(slackSpoof.error?.error_code).toBe("automated_channel_forbidden");

    const driveBare = await call("driveGates.run", {
      action: "approve",
      huntId: "hunt-auth-01",
      operator: "mallory",
      rbacRole: "admin",
      checkNote: "forged",
    });
    expect(driveBare.error?.error_code).toBe("invalid_operator_token");
    expect(store.getRun("hunt-auth-01")!.decisions.length).toBe(0);

    const ok = await call("hunt.decideGate", {
      hunt_id: "hunt-auth-01",
      gate: "scope",
      action: "approve",
      via: "desktop",
      operator_token: gates.sessionAuthority.issueToken("alice", "analyst"),
      authenticated_principal: "mallory",
      rbac_role: "admin",
      payload_sha256: digest,
      check_note: "Verified scope.",
    });
    const decided = ok.result as PersistedHuntRun;
    expect(decided.decisions[0]!.decided_by).toBe("alice");
    expect(decided.decisions[0]!.rbac_role).toBe("analyst");
    store.close();
  });

  // Finding 4 (CLI token issuance from the runtime-dir secret)
  test("CLI-issued operator tokens verify across processes sharing the runtime dir", async () => {
    const runtimeDir = makeTmpDir();
    const c1 = captureIo();
    expect(
      await runHuntCli(["token", "--principal", "cli-alice", "--role", "analyst", "--runtime-dir", runtimeDir], c1.io),
    ).toBe(0);
    const token = c1.out.join("").trim();
    const ctx = createHuntDaemonRuntime({ runtimeDir });
    expect(ctx.gateAuthority.sessionAuthority.verifyToken(token).principal).toBe("cli-alice");
    ctx.stateStore.close();
  });

  // Finding 5
  test("gate decisions are one atomic transaction: no double decide, no burned id on failure", async () => {
    const tmp = makeTmpDir();
    const dbPath = path.join(tmp, "s.sqlite");
    const decisionsDir = path.join(tmp, "dec");
    const a = makeEngine(dbPath, decisionsDir);
    const parked = await a.engine.startHunt({
      runId: "hunt-race-01",
      scopeText: "Race scope.",
      dataPlane: makeDataPlane(),
      followUps: 0,
    });
    const openGate = parked.open_gate!;

    // A failing transition rolls back the whole transaction: the decision_id stays usable.
    const decisionFor = (id: string) => ({
      decision_id: id,
      hunt_id: "hunt-race-01",
      gate: "scope",
      action: "reject" as const,
      via: "cli" as const,
      decided_by: "alice",
      rbac_role: "analyst",
      payload_sha256: openGate.payload_sha256,
      decided_at: new Date().toISOString(),
      expires_at: openGate.expires_at,
      note: "n",
    });
    expect(() =>
      a.store.commitGateDecision({
        decision: decisionFor("dec-race-1"),
        expectedOpenGate: openGate,
        mutate: () => {
          throw new Error("synthetic failure mid-transition");
        },
      }),
    ).toThrow(/synthetic failure/);
    expect(a.store.getRun("hunt-race-01")!.open_gate?.gate).toBe("scope");

    // Second "process" on the same SQLite file
    const storeB = new DurableStateStore(dbPath);
    const first = a.store.commitGateDecision({
      decision: decisionFor("dec-race-1"),
      expectedOpenGate: openGate,
      mutate: (r) => {
        r.status = "failed";
      },
    });
    expect(first.outcome).toBe("committed");
    const second = storeB.commitGateDecision({
      decision: decisionFor("dec-race-2"),
      expectedOpenGate: openGate,
      mutate: (r) => {
        r.status = "running";
      },
    });
    expect(second.outcome).toBe("gate_not_open");
    const final = storeB.getRun("hunt-race-01")!;
    expect(final.decisions.map((d) => d.decision_id)).toEqual(["dec-race-1"]);
    expect(final.status).toBe("failed");
    storeB.close();
    a.store.close();
  });

  test("two engines on one database cannot both decide the same gate through submitGateDecision", async () => {
    const tmp = makeTmpDir();
    const dbPath = path.join(tmp, "s.sqlite");
    const decisionsDir = path.join(tmp, "dec");
    const a = makeEngine(dbPath, decisionsDir);
    const parked = await a.engine.startHunt({
      runId: "hunt-race-02",
      scopeText: "Race scope 2.",
      dataPlane: makeDataPlane(),
      followUps: 0,
    });
    const storeB = new DurableStateStore(dbPath);
    const gatesB = new GateAuthority({ stateStore: storeB, decisionsDir, sessionAuthority: a.gates.sessionAuthority });
    const engineB = new HuntWaveEngine({ stateStore: storeB, gateAuthority: gatesB, modelRunner: makeRunner() });
    const input = (id: string) => ({
      decisionId: id,
      huntId: "hunt-race-02",
      gate: "scope",
      action: "reject" as const,
      via: "cli" as const,
      operatorToken: a.gates.sessionAuthority.issueToken("alice", "analyst"),
      payloadSha256: parked.open_gate!.payload_sha256,
      checkNote: "Rejecting.",
    });
    const results = await Promise.allSettled([
      a.engine.submitGateDecision(input("dec-r2-a")),
      engineB.submitGateDecision(input("dec-r2-b")),
    ]);
    expect(results.filter((r) => r.status === "fulfilled").length).toBe(1);
    const rejected = results.find((r) => r.status === "rejected") as PromiseRejectedResult;
    expect(rejected.reason).toBeInstanceOf(Error);
    expect(storeB.getRun("hunt-race-02")!.decisions.length).toBe(1);
    const logLines = fs.readFileSync(a.gates.decisionsLogPath, "utf8").trim().split("\n");
    expect(logLines.length).toBe(1);
    storeB.close();
    a.store.close();
  });

  test("executeDriveGates rejects approvals without an operator token", async () => {
    const tmp = makeTmpDir();
    const { store, engine } = makeEngine(path.join(tmp, "s.sqlite"), path.join(tmp, "dec"));
    await engine.startHunt({ runId: "hunt-dg-01", scopeText: "DG scope.", dataPlane: makeDataPlane(), followUps: 0 });
    await expect(
      executeDriveGates(engine, { action: "deny", huntId: "hunt-dg-01", checkNote: "no token" }),
    ).rejects.toBeInstanceOf(GateDecisionError);
    expect(store.getRun("hunt-dg-01")!.status).toBe("awaiting_gate");
    store.close();
  });
});
