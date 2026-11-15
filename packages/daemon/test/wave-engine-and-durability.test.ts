import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import {
  DataPlaneAccessError,
  MAX_CONCURRENT_HUNTS,
  RECONCILE_GATE,
  type CaseMetadata,
  type Handoff,
  type ProfileId,
} from "@hunt-command/shared";
import {
  DurableStateStore,
  GateAuthority,
  HuntWaveEngine,
  InMemoryTelemetrySink,
  RoleCapabilityAuthority,
  buildSessionCustomTools,
  type HuntDataPlanePort,
  type ModelRunnerPort,
  type ModelTurnRequest,
  type RoleModelPin,
  type StepTokenUsage,
  type StepTurnResult,
} from "../src/index.ts";

const tempDirs: string[] = [];
function makeTmpDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hunt-wave-test-"));
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

function makeUsage(tokens = 200, model = "claude-sonnet-4-6"): StepTokenUsage {
  return {
    input_tokens: Math.floor(tokens * 0.7),
    output_tokens: tokens - Math.floor(tokens * 0.7),
    cache_read_tokens: 50,
    cache_write_tokens: 0,
    total_tokens: tokens,
    turns: 1,
    provider: "anthropic",
    model,
    billing_mode: "oauth_subscription",
    actual_billed_usd: 0,
    shadow_api_usd: 0.001,
    cache_savings_usd: 0.0001,
  };
}

function makeValidHandoff(
  caseId: string,
  stepId: string,
  profile: ProfileId,
  claimCount = 2,
  reviewTargets: string[] = [],
): Handoff {
  return {
    schema_version: 1,
    case_id: caseId,
    step_id: stepId,
    profile,
    claims: Array.from({ length: claimCount }, (_, idx) => ({
      claim_id: `${stepId}:c${idx + 1}`,
      kind: stepId === "incident" ? "finding" : "observed",
      statement: `Evidence-backed finding #${idx + 1} from ${stepId} citing evt-101 and frame-7.`,
      evidence_ids: ["elastic-logs"],
      entity_ids: [],
      contradicts: [],
    })),
    reviews:
      profile === "framework-reviewer" && reviewTargets.length > 0
        ? [
            {
              review_id: `${stepId}:r1`,
              claim_ids: reviewTargets,
              disposition: "review_ready",
              rationale: "Verified evt-101 and frame-7 against raw case logs.",
              evidence_ids: ["elastic-logs"],
            },
          ]
        : [],
    disposition: "review_ready",
    limitations: ["Bounded to 1h capture window around evt-101."],
    requested_decisions: [],
  };
}

function createCaseDataPlane(options?: {
  caseId?: string;
  syntheticOnly?: boolean;
  hasNetwork?: boolean;
  hasIntel?: boolean;
  validEvents?: string[];
}): HuntDataPlanePort {
  const syntheticOnly = options?.syntheticOnly ?? true;
  const meta: CaseMetadata = {
    case_id: options?.caseId ?? "case-8wave-01",
    title: "8-Wave Integration Case",
    data_origin: syntheticOnly ? "synthetic" : "work-export",
    synthetic_only: syntheticOnly,
    time_window: {
      start_iso: "2026-11-01T00:00:00Z",
      end_iso: "2026-11-01T02:00:00Z",
    },
    sources: ["elastic-logs"],
  };
  const validEvents = new Set(options?.validEvents ?? ["evt-101"]);

  return {
    caseMetadata: meta,
    capabilities: () => ({
      hasNetworkCapture: options?.hasNetwork ?? true,
      hasIntelSource: options?.hasIntel ?? true,
      sources: meta.sources,
    }),
    executeTool: async (_tok, toolName, params) => ({
      tool: toolName,
      params,
      records: [{ id: "evt-101" }],
    }),
    verifyCitations: async (req) => {
      const missingEvents = req.event_ids.filter((e) => !validEvents.has(e));
      const missingFrames = req.frame_ids.filter((f) => f !== "frame-7");
      return {
        verified:
          missingEvents.length === 0 && missingFrames.length === 0 && req.ioc_ids.length === 0,
        checked_at: new Date().toISOString(),
        case_id: req.case_id,
        total_checked: req.event_ids.length + req.frame_ids.length + req.ioc_ids.length,
        missing_event_ids: missingEvents,
        missing_frame_ids: missingFrames,
        missing_ioc_ids: [...req.ioc_ids],
        ambiguous_ids: [],
        out_of_scope_ids: [],
        source_status: "ok",
      };
    },
  };
}

class ProgrammableModelRunner implements ModelRunnerPort {
  public readonly promptsByExecutionId = new Map<string, string>();
  public preflightCalls: string[] = [];
  private readonly handler: (req: ModelTurnRequest, runner: ProgrammableModelRunner) => Promise<StepTurnResult>;

  constructor(
    handler: (req: ModelTurnRequest, runner: ProgrammableModelRunner) => Promise<StepTurnResult>,
  ) {
    this.handler = handler;
  }

  public getPinnedModelForRole(profile: ProfileId): RoleModelPin {
    return {
      provider: "anthropic",
      model:
        profile === "framework-coordinator" || profile === "framework-reviewer"
          ? "claude-opus-4-6"
          : "claude-sonnet-4-6",
      fallback_providers: [],
    };
  }

  public async preflightWave(providers: readonly string[], waveKey: string): Promise<void> {
    this.preflightCalls.push(`${waveKey}:${providers.join(",")}`);
  }

  public async runTurn(request: ModelTurnRequest): Promise<StepTurnResult> {
    this.promptsByExecutionId.set(request.executionId, request.userPromptBody);
    return this.handler(request, this);
  }
}

describe("8-Wave Hunt Engine, Merge Fallback, Capabilities, Durability & Budget", () => {
  test("executes complete 8-wave DAG with Gate 1, F09 capability drops, delegate_task, K=6 focus slicing, purple reviews, citation receipt & Gate 2", async () => {
    const tmp = makeTmpDir();
    const store = new DurableStateStore(path.join(tmp, "state", "hunt_daemon.sqlite"));
    const pragmas = store.getPragmaStatus();
    expect(pragmas.journalMode).toBe("wal");
    expect(pragmas.synchronous).toBe(2); // FULL = 2 in SQLite

    const gates = new GateAuthority({
      stateStore: store,
      decisionsDir: path.join(tmp, "decisions"),
    });
    const telemetry = new InMemoryTelemetrySink();
    const capAuth = new RoleCapabilityAuthority();

    const runner = new ProgrammableModelRunner(async (req, self) => {
      if (req.isDelegatedChild) {
        return {
          status: "completed",
          output_text: "Specialist checked process tree around evt-101; confirmed powershell child.",
          usage: makeUsage(120),
        };
      }

      if (req.stepId === "analysis") {
        // Exercise real `delegate_task` tool inside Wave 3 coordinator!
        const tools = buildSessionCustomTools({
          runId: req.runId,
          caseId: req.caseId,
          stepId: req.stepId,
          wave: req.wave,
          profile: req.profile,
          syntheticOnly: req.syntheticOnly,
          dataOrigin: req.dataOrigin,
          capabilityAuthority: capAuth,
          dataPlane: req.dataPlane,
          telemetry: req.telemetry,
          modelRunner: self,
          delegateContext: req.delegateContext,
        });
        const delTool = tools.find((t) => t.name === "delegate_task")!;
        const delOut = await delTool.execute(
          "del-1",
          {
            specialist_profile: "framework-researcher",
            question: "Verify powershell parent PID in evt-101",
          } as never,
          undefined,
          {} as never,
        );
        expect(delOut.isError).toBeUndefined();

        // Emit 2 claims so follow-1 & follow-2 execute while follow-3..6 auto-drop with `no_focus_claim` (0 tokens)!
        return {
          status: "completed",
          output_text: JSON.stringify(makeValidHandoff(req.caseId, "analysis", req.profile, 2)),
          usage: makeUsage(300, "claude-opus-4-6"),
        };
      }

      if (req.stepId === "purple") {
        return {
          status: "completed",
          output_text: JSON.stringify(
            makeValidHandoff(req.caseId, "purple", "framework-reviewer", 1, ["merge:c1", "detection:c1"]),
          ),
          usage: makeUsage(250, "claude-opus-4-6"),
        };
      }

      return {
        status: "completed",
        output_text: JSON.stringify(makeValidHandoff(req.caseId, req.stepId, req.profile, 2)),
        usage: makeUsage(200),
      };
    });

    const engine = new HuntWaveEngine({
      stateStore: store,
      gateAuthority: gates,
      modelRunner: runner,
      telemetry,
    });

    // Case has NO network capture and NO intel source -> `network` & `intel` drop cleanly with 0 tokens!
    const dp = createCaseDataPlane({ hasNetwork: false, hasIntel: false });

    const afterWave1 = await engine.startHunt({
      runId: "hunt-full-01",
      scopeText: "Investigate suspicious workstation activity around evt-101.",
      dataPlane: dp,
      followUps: 6,
      maxTotalTokens: 50_000,
    });

    expect(afterWave1.status).toBe("awaiting_gate");
    expect(afterWave1.open_gate?.gate).toBe("scope");

    // Approve Gate 1 (`scope`) -> drives Waves 2..8 up to Gate 2 (`incident`)!
    const afterWave8 = await engine.submitGateDecision({
      huntId: "hunt-full-01",
      gate: "scope",
      action: "approve",
      via: "cli",
      operatorToken: gates.sessionAuthority.issueToken("analyst-alice", "analyst"),
      payloadSha256: afterWave1.open_gate!.payload_sha256,
      checkNote: "Reviewed scope boundaries and time window.",
    });

    expect(afterWave8.status).toBe("awaiting_gate");
    expect(afterWave8.open_gate?.gate).toBe("incident");
    expect(afterWave8.open_gate?.check_note_cleared).toBe(true);
    expect(afterWave8.citation_receipt?.verified).toBe(true);

    // Verify F09 capability gating (0 tokens, exact reason codes)
    expect(afterWave8.results["network"]?.status).toBe("dropped");
    expect(afterWave8.results["network"]?.reason_code).toBe("no_network_capture");
    expect(afterWave8.results["network"]?.attempts).toBe(0);
    expect(afterWave8.results["intel"]?.status).toBe("dropped");
    expect(afterWave8.results["intel"]?.reason_code).toBe("no_intel_source");

    // Verify Wave 4 focus slicing: follow-1 got ONLY analysis:c1, follow-2 got ONLY analysis:c2, follow-3..6 dropped (`no_focus_claim`)
    const f1Prompt = runner.promptsByExecutionId.get("hunt-full-01:follow-1")!;
    expect(f1Prompt).toContain("analysis:c1");
    expect(f1Prompt).not.toContain("analysis:c2");
    expect(afterWave8.results["follow-3"]?.status).toBe("dropped");
    expect(afterWave8.results["follow-3"]?.reason_code).toBe("no_focus_claim");
    expect(afterWave8.results["follow-6"]?.reason_code).toBe("no_focus_claim");

    // Verify delegated specialist usage is counted in token_ledger
    expect(afterWave8.delegated_ledger.length).toBe(1);
    expect(afterWave8.token_ledger.delegated_tokens).toBe(120);
    expect(afterWave8.token_ledger.actual_billed_usd).toBe(0);
    expect(afterWave8.token_ledger.shadow_api_usd).toBeGreaterThan(0);

    // Approve Gate 2 (`incident`) -> `completed`!
    const finished = await engine.submitGateDecision({
      huntId: "hunt-full-01",
      gate: "incident",
      action: "approve",
      via: "desktop",
      operatorToken: gates.sessionAuthority.issueToken("lead-bob", "reviewer"),
      payloadSha256: afterWave8.open_gate!.payload_sha256,
      checkNote: "Confirmed all inline evt-101 and frame-7 citations match case store.",
    });

    expect(finished.status).toBe("completed");
    expect(finished.decisions.length).toBe(2);
    store.close();
  });

  test("activates _MERGE_FALLBACK_PATCH round-robin claim rank injection when merge drops on cyber refusal", async () => {
    const tmp = makeTmpDir();
    const store = new DurableStateStore(path.join(tmp, "state", "runs.sqlite"));
    const gates = new GateAuthority({ stateStore: store, decisionsDir: path.join(tmp, "dec") });

    const runner = new ProgrammableModelRunner(async (req) => {
      if (req.stepId === "merge") {
        // Honest cyber refusal on merge -> optional merge drops, triggering _MERGE_FALLBACK_PATCH!
        return {
          status: "refused",
          reason_code: "cyber_refusal",
          output_text: "",
          usage: makeUsage(80, "claude-opus-4-6"),
          refusal: {
            refused: true,
            finish_reason: "content_filter",
            category: "cyber",
            diagnostic: "Refusal(category=cyber)",
          },
        };
      }
      if (req.stepId === "purple") {
        // Purple reviews round-robin fallback claims from follow-1 & follow-2!
        return {
          status: "completed",
          output_text: JSON.stringify(
            makeValidHandoff(req.caseId, "purple", "framework-reviewer", 1, [
              "follow-1:c1",
              "follow-2:c1",
            ]),
          ),
          usage: makeUsage(150, "claude-opus-4-6"),
        };
      }
      return {
        status: "completed",
        output_text: JSON.stringify(makeValidHandoff(req.caseId, req.stepId, req.profile, 2)),
        usage: makeUsage(150),
      };
    });

    const engine = new HuntWaveEngine({
      stateStore: store,
      gateAuthority: gates,
      modelRunner: runner,
    });
    const dp = createCaseDataPlane();

    const w1 = await engine.startHunt({
      runId: "hunt-fallback-01",
      scopeText: "Check lateral movement.",
      dataPlane: dp,
      followUps: 2,
    });
    const w8 = await engine.submitGateDecision({
      huntId: "hunt-fallback-01",
      gate: "scope",
      action: "approve",
      via: "cli",
      operatorToken: gates.sessionAuthority.issueToken("op-1", "admin"),
      payloadSha256: w1.open_gate!.payload_sha256,
      checkNote: "Scope approved.",
    });

    expect(w8.status).toBe("awaiting_gate");
    expect(w8.results["merge"]?.status).toBe("dropped");
    expect(w8.results["merge"]?.reason_code).toBe("cyber_refusal");

    // Detection prompt received round-robin claims by rank: follow-1:c1, follow-2:c1, THEN follow-1:c2, follow-2:c2!
    const detPrompt = runner.promptsByExecutionId.get("hunt-fallback-01:detection")!;
    const idxF1C1 = detPrompt.indexOf("follow-1:c1");
    const idxF2C1 = detPrompt.indexOf("follow-2:c1");
    const idxF1C2 = detPrompt.indexOf("follow-1:c2");
    const idxF2C2 = detPrompt.indexOf("follow-2:c2");
    expect(idxF1C1).toBeGreaterThan(-1);
    expect(idxF2C1).toBeGreaterThan(idxF1C1);
    expect(idxF1C2).toBeGreaterThan(idxF2C1);
    expect(idxF2C2).toBeGreaterThan(idxF1C2);

    store.close();
  });

  test("enforces 1 :retry cap, sums handoff_rejections into max_total_tokens, and fails closed on missing integer total_tokens", async () => {
    const tmp = makeTmpDir();
    const store = new DurableStateStore(path.join(tmp, "state", "runs.sqlite"));
    const gates = new GateAuthority({ stateStore: store, decisionsDir: path.join(tmp, "dec") });

    let scopeAttempts = 0;
    const runner = new ProgrammableModelRunner(async (req) => {
      if (req.stepId === "scope") {
        scopeAttempts += 1;
        if (scopeAttempts === 1) {
          // Attempt 1 emits invalid JSON -> moved to handoff_rejections[] (400 tokens)
          return {
            status: "completed",
            output_text: '{"broken_json": true}',
            usage: makeUsage(400, "claude-opus-4-6"),
          };
        }
        // Attempt 2 (:retry) succeeds (400 tokens -> total 800 tokens)
        return {
          status: "completed",
          output_text: JSON.stringify(makeValidHandoff(req.caseId, "scope", req.profile, 1)),
          usage: makeUsage(400, "claude-opus-4-6"),
        };
      }
      // Missing usage (`undefined`) on Wave 2 -> must fail closed as `token_cap_exceeded`!
      return {
        status: "completed",
        output_text: JSON.stringify(makeValidHandoff(req.caseId, req.stepId, req.profile, 1)),
        usage: undefined,
      };
    });

    const engine = new HuntWaveEngine({
      stateStore: store,
      gateAuthority: gates,
      modelRunner: runner,
    });
    const dp = createCaseDataPlane({ hasNetwork: false, hasIntel: false });

    const w1 = await engine.startHunt({
      runId: "hunt-retry-budget",
      scopeText: "Retry and token accounting test.",
      dataPlane: dp,
      maxTotalTokens: 5_000,
    });
    expect(w1.handoff_rejections.length).toBe(1);
    expect(w1.token_ledger.rejections_tokens).toBe(400);
    expect(w1.token_ledger.results_tokens).toBe(400);
    expect(w1.token_ledger.consumed_total_tokens).toBe(800);

    const afterMissingUsage = await engine.submitGateDecision({
      huntId: "hunt-retry-budget",
      gate: "scope",
      action: "approve",
      via: "cli",
      operatorToken: gates.sessionAuthority.issueToken("op-1", "analyst"),
      payloadSha256: w1.open_gate!.payload_sha256,
      checkNote: "Proceed to Wave 2.",
    });

    expect(afterMissingUsage.status).toBe("failed");
    expect(afterMissingUsage.reason_code).toBe("token_cap_exceeded");
    store.close();
  });

  test("ReceiptStore crash recovery marks reserved in-flight turns previous_dispatch_unknown and opens human reconcile gate (never auto-reruns)", async () => {
    const tmp = makeTmpDir();
    const dbPath = path.join(tmp, "state", "crash_recovery.sqlite");
    const decisionsDir = path.join(tmp, "decisions");

    // Simulate a daemon crash right after ReceiptStore.reserveReceipt() BEFORE finalizeReceipt()!
    const store1 = new DurableStateStore(dbPath);
    const now = new Date().toISOString();
    store1.saveRun({
      run_id: "hunt-crash-01",
      case_id: "case-8wave-01",
      data_origin: "work-export",
      synthetic_only: false,
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
        consumed_total_tokens: 500,
        results_tokens: 500,
        rejections_tokens: 0,
        delegated_tokens: 0,
        actual_billed_usd: 0,
        shadow_api_usd: 0.01,
        cache_savings_usd: 0,
      },
      citation_receipt: null,
      snapshot: null,
      config: { scopeText: "Investigate real export logs.", followUps: 2, maxTotalTokens: 100_000 },
      created_at: now,
      updated_at: now,
    });

    const reserved = store1.reserveReceipt({
      executionId: "hunt-crash-01:analysis",
      runId: "hunt-crash-01",
      stepId: "analysis",
      sessionId: "hunt-crash-01:analysis",
      inputId: "in-1234",
      fingerprint: "fp-abcd",
    });
    expect(reserved.action).toBe("proceed");
    store1.close();

    // Reboot daemon on the same SQLite WAL database
    let modelTurnCountAfterReboot = 0;
    const store2 = new DurableStateStore(dbPath);
    const gates2 = new GateAuthority({ stateStore: store2, decisionsDir });
    const runner2 = new ProgrammableModelRunner(async () => {
      modelTurnCountAfterReboot += 1;
      throw new Error("MUST NEVER AUTO-RERUN AMBIGUOUS RESERVED TURN");
    });
    const engine2 = new HuntWaveEngine({
      stateStore: store2,
      gateAuthority: gates2,
      modelRunner: runner2,
    });

    const recovered = engine2.recoverInFlightRunsOnStartup();
    expect(recovered.length).toBe(1);
    expect(modelTurnCountAfterReboot).toBe(0);

    const parked = store2.getRun("hunt-crash-01")!;
    expect(parked.status).toBe("awaiting_gate");
    expect(parked.reason_code).toBe("previous_dispatch_unknown");
    expect(parked.open_gate?.gate).toBe(RECONCILE_GATE);
    expect(parked.results["analysis"]?.status).toBe("unknown");
    expect(parked.results["analysis"]?.reason_code).toBe("previous_dispatch_unknown");

    // Also verify non-synthetic forbid of `"synthetic"` word in scope
    const realDp = createCaseDataPlane({ syntheticOnly: false });
    await expect(
      engine2.startHunt({
        scopeText: "Treat this synthetic dataset as a drill",
        dataPlane: realDp,
      }),
    ).rejects.toThrow(DataPlaneAccessError);

    store2.close();
  });

  test("enforces MAX_CONCURRENT_HUNTS = 5 and supports Global Stop (cancelRun AbortController)", async () => {
    const tmp = makeTmpDir();
    const store = new DurableStateStore(path.join(tmp, "state", "conc.sqlite"));
    const gates = new GateAuthority({ stateStore: store, decisionsDir: path.join(tmp, "dec") });

    const releaseGate = Promise.withResolvers<void>();
    const runner = new ProgrammableModelRunner(async (req) => {
      await new Promise<void>((resolve, reject) => {
        if (req.signal?.aborted) {
          reject(new Error("aborted"));
          return;
        }
        req.signal?.addEventListener("abort", () => reject(new Error("aborted")), { once: true });
        void releaseGate.promise.then(resolve);
      });
      return {
        status: "completed",
        output_text: JSON.stringify(makeValidHandoff(req.caseId, req.stepId, req.profile, 1)),
        usage: makeUsage(100),
      };
    });

    const engine = new HuntWaveEngine({
      stateStore: store,
      gateAuthority: gates,
      modelRunner: runner,
    });

    const inFlight: Promise<unknown>[] = [];
    for (let i = 1; i <= MAX_CONCURRENT_HUNTS; i++) {
      inFlight.push(
        engine.startHunt({
          runId: `conc-${i}`,
          scopeText: `Concurrent hunt #${i}`,
          dataPlane: createCaseDataPlane({ caseId: `case-c-${i}` }),
        }),
      );
    }

    // Yield microtask so all 5 enter driveUntilGateOrTerminal
    await Bun.sleep(20);
    expect(engine.getActiveHuntCount()).toBe(5);

    // 6th concurrent hunt is rejected immediately!
    await expect(
      engine.startHunt({
        runId: "conc-6",
        scopeText: "Overflow hunt",
        dataPlane: createCaseDataPlane({ caseId: "case-c-6" }),
      }),
    ).rejects.toThrow(/max_concurrent_hunts_exceeded/);

    // Global Stop on conc-1 aborts it immediately while others finish when released!
    const cancelled = engine.cancelRun("conc-1", "operator_emergency_stop");
    expect(cancelled.status).toBe("cancelled");
    expect(cancelled.reason_code).toBe("operator_emergency_stop");

    releaseGate.resolve();
    await Promise.allSettled(inFlight);
    store.close();
  });
});
