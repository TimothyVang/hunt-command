import crypto from "node:crypto";
import {
  CaseMetadataSchema,
  DEFAULT_FOLLOW_UPS,
  DataPlaneAccessError,
  HUNT_WAVES,
  MAX_CONCURRENT_HUNTS,
  MAX_FOLLOW_UPS,
  MAX_PROMPT_BYTES,
  RECONCILE_GATE,
  formatRealDataOriginText,
  getAllowedToolsForStep,
  type Claim,
  type Handoff,
  type HuntWave,
  type ProfileId,
} from "@hunt-command/shared";
import { GateAuthority, GateDecisionError, type SubmitGateDecisionInput } from "./gates.ts";
import { SHARED_CACHE_HEADER, validateNonSyntheticGuidanceText } from "./omp-pool.ts";
import {
  FINAL_HANDOFF_BYTES,
  OntologyValidationError,
  RETRY_NOTICE_RESERVE_BYTES,
  WHOLE_CHECK_RETRY_SUFFIX,
  buildHandoffInstructions,
  computeTypedOutputCaps,
  disclosedTargetBytes,
  selectSnapshot,
  validateHandoff,
  verifyHandoffCitations,
  type StepCapDescriptor,
} from "./ontology-validator.ts";
import {
  NoopTelemetrySink,
  type CaseCapabilities,
  type HuntDataPlanePort,
  type ModelRunnerPort,
  type StepTokenUsage,
  type TelemetrySinkPort,
} from "./ports.ts";
import {
  computeDispatchFingerprint,
  type DurableStateStore,
  type PersistedHuntRun,
  type StepResultRecord,
  type TokenLedgerSummary,
} from "./state-store.ts";

export interface WaveStepSpec {
  readonly stepId: string;
  readonly wave: HuntWave;
  readonly waveIndex: number;
  readonly stageKey: string;
  readonly profile: ProfileId;
  readonly optional: boolean;
  readonly maxTurns: number;
  readonly dependsOn: readonly string[];
  readonly focus?: readonly [sourceStepId: string, claimIndex: number] | null;
  readonly capabilityRequirement?: "network_capture" | "intel_source" | null;
}

export interface BuildEightWaveGraphOptions {
  readonly followUps?: number;
  readonly optionalOverrides?: Partial<Record<string, boolean>>;
}

/**
 * Builds the exact 8-Wave Hunt DAG (`HUNT_WAVES`):
 * 1. `scope` (`framework-coordinator`, required, `maxTurns=8`, `delegate_task` DISABLED) + Human Gate 1
 * 2. `investigation`: `evidence`, `hypotheses`, `network`, `intel` (parallel, optional, `maxTurns=6`, capability-gated)
 * 3. `analysis` (`framework-coordinator`, required, `delegate_task` <= 3)
 * 4. `follow_up`: `follow-1..K` (`K=6` default `0..12`, optional, `focus=("analysis", i-1)`)
 * 5. `merge` (`framework-coordinator`, optional, + `_MERGE_FALLBACK_PATCH` round-robin claim rank injection)
 * 6. `detection` (`framework-builder`, optional)
 * 7. `purple` (`framework-reviewer`, optional — ONLY role allowed to emit `reviews[]`)
 * 8. `incident` (`framework-coordinator`, required) + Citation Verification Receipt + Human Gate 2
 */
export function buildEightWaveGraph(options?: BuildEightWaveGraphOptions): WaveStepSpec[][] {
  const followUps = options?.followUps ?? DEFAULT_FOLLOW_UPS;
  if (!Number.isInteger(followUps) || followUps < 0 || followUps > MAX_FOLLOW_UPS) {
    throw new RangeError(
      `followUps must be an integer within 0..${MAX_FOLLOW_UPS}, got ${followUps}`,
    );
  }
  const overrides = options?.optionalOverrides ?? {};
  const resolveOpt = (stepId: string, defaultOptional: boolean): boolean =>
    overrides[stepId] !== undefined ? Boolean(overrides[stepId]) : defaultOptional;

  const wave1: WaveStepSpec[] = [
    {
      stepId: "scope",
      wave: "scope",
      waveIndex: 0,
      stageKey: "scope",
      profile: "framework-coordinator",
      optional: resolveOpt("scope", false),
      maxTurns: 8,
      dependsOn: [],
    },
  ];

  const wave2: WaveStepSpec[] = [
    {
      stepId: "evidence",
      wave: "investigation",
      waveIndex: 1,
      stageKey: "evidence",
      profile: "framework-researcher",
      optional: resolveOpt("evidence", true),
      maxTurns: 6,
      dependsOn: ["scope"],
    },
    {
      stepId: "hypotheses",
      wave: "investigation",
      waveIndex: 1,
      stageKey: "hypotheses",
      profile: "framework-builder",
      optional: resolveOpt("hypotheses", true),
      maxTurns: 6,
      dependsOn: ["scope"],
    },
    {
      stepId: "network",
      wave: "investigation",
      waveIndex: 1,
      stageKey: "network",
      profile: "framework-network-analyst",
      optional: resolveOpt("network", true),
      maxTurns: 6,
      dependsOn: ["scope"],
      capabilityRequirement: "network_capture",
    },
    {
      stepId: "intel",
      wave: "investigation",
      waveIndex: 1,
      stageKey: "intel",
      profile: "framework-librarian",
      optional: resolveOpt("intel", true),
      maxTurns: 6,
      dependsOn: ["scope"],
      capabilityRequirement: "intel_source",
    },
  ];

  const wave3: WaveStepSpec[] = [
    {
      stepId: "analysis",
      wave: "analysis",
      waveIndex: 2,
      stageKey: "analysis",
      profile: "framework-coordinator",
      optional: resolveOpt("analysis", false),
      maxTurns: 10,
      dependsOn: ["evidence", "hypotheses", "network", "intel"],
    },
  ];

  const followStepIds: string[] = [];
  const wave4: WaveStepSpec[] = [];
  for (let i = 1; i <= followUps; i++) {
    const id = `follow-${i}`;
    followStepIds.push(id);
    wave4.push({
      stepId: id,
      wave: "follow_up",
      waveIndex: 3,
      stageKey: "follow",
      profile: "framework-researcher",
      optional: resolveOpt(id, true),
      maxTurns: 8,
      dependsOn: ["analysis"],
      focus: ["analysis", i - 1] as const,
    });
  }

  const mergeDeps = followStepIds.length > 0 ? followStepIds : ["analysis"];
  const wave5: WaveStepSpec[] = [
    {
      stepId: "merge",
      wave: "merge",
      waveIndex: 4,
      stageKey: "merge",
      profile: "framework-coordinator",
      optional: resolveOpt("merge", true),
      maxTurns: 8,
      dependsOn: mergeDeps,
    },
  ];

  const wave6: WaveStepSpec[] = [
    {
      stepId: "detection",
      wave: "detection",
      waveIndex: 5,
      stageKey: "detection",
      profile: "framework-builder",
      optional: resolveOpt("detection", true),
      maxTurns: 8,
      dependsOn: ["merge"],
    },
  ];

  const wave7: WaveStepSpec[] = [
    {
      stepId: "purple",
      wave: "purple",
      waveIndex: 6,
      stageKey: "purple",
      profile: "framework-reviewer",
      optional: resolveOpt("purple", true),
      maxTurns: 8,
      dependsOn: ["merge", "detection"],
    },
  ];

  const wave8: WaveStepSpec[] = [
    {
      stepId: "incident",
      wave: "incident",
      waveIndex: 7,
      stageKey: "incident",
      profile: "framework-coordinator",
      optional: resolveOpt("incident", false),
      maxTurns: 10,
      dependsOn: ["merge", "detection", "purple"],
    },
  ];

  return [wave1, wave2, wave3, wave4, wave5, wave6, wave7, wave8];
}

export interface MergeFallbackInjection {
  readonly active: boolean;
  readonly includedClaims: Claim[];
  readonly totalClaims: number;
  readonly omittedCount: number;
  readonly renderedSection: string;
  readonly syntheticPredecessorHandoffs: Handoff[];
}

/**
 * Port of `workflows.py:_MERGE_FALLBACK_PATCH`:
 * When `merge` drops (e.g., `cyber_refusal`, validation cap, or all follow-ups dropped),
 * interleaves surviving `follow-1..K` claims round-robin by claim rank (or `analysis` claims
 * if no follow-up survived) up to `budgetBytes`, appending:
 * `"Not shown (prompt limit): X of Y claims."` when truncated!
 */
export function buildMergeFallbackInjection(params: {
  caseId: string;
  followStepIds: readonly string[];
  survivingHandoffs: Readonly<Record<string, Handoff>>;
  budgetBytes: number;
}): MergeFallbackInjection {
  const sourceHandoffs: Handoff[] = [];
  for (const fid of params.followStepIds) {
    const h = params.survivingHandoffs[fid];
    if (h && h.claims.length > 0) {
      sourceHandoffs.push(h);
    }
  }
  if (sourceHandoffs.length === 0) {
    const analysisHandoff = params.survivingHandoffs["analysis"];
    if (analysisHandoff && analysisHandoff.claims.length > 0) {
      sourceHandoffs.push(analysisHandoff);
    }
  }

  // Round-robin interleave by claim rank (rank 0 across all surviving follow-ups, then rank 1, ...)
  const rankedClaims: Array<{ sourceStepId: string; claim: Claim }> = [];
  const maxRank = sourceHandoffs.reduce((acc, h) => Math.max(acc, h.claims.length), 0);
  for (let rank = 0; rank < maxRank; rank++) {
    for (const h of sourceHandoffs) {
      const claim = h.claims[rank];
      if (claim) {
        rankedClaims.push({ sourceStepId: h.step_id, claim });
      }
    }
  }

  const totalClaims = rankedClaims.length;
  if (totalClaims === 0) {
    return {
      active: true,
      includedClaims: [],
      totalClaims: 0,
      omittedCount: 0,
      renderedSection: "## Merge Fallback Claims\nNo surviving follow-up claims available.",
      syntheticPredecessorHandoffs: [],
    };
  }

  const header = "## Merge Fallback Claims (Round-Robin by Rank)\n";
  const reserveForDisclosure = 80;
  const maxContentBytes = Math.max(128, params.budgetBytes - Buffer.byteLength(header, "utf8") - reserveForDisclosure);

  const included: Claim[] = [];
  const lines: string[] = [];
  let usedBytes = 0;

  for (const entry of rankedClaims) {
    const line = `- [${entry.sourceStepId}] ${JSON.stringify(entry.claim)}`;
    const lineBytes = Buffer.byteLength(`${line}\n`, "utf8");
    if (usedBytes + lineBytes > maxContentBytes && included.length > 0) {
      break;
    }
    if (usedBytes + lineBytes > maxContentBytes && included.length === 0) {
      // Even first claim exceeds tight budget -> omit all and disclose
      break;
    }
    included.push(entry.claim);
    lines.push(line);
    usedBytes += lineBytes;
  }

  const omittedCount = totalClaims - included.length;
  if (omittedCount > 0) {
    lines.push(`Not shown (prompt limit): ${omittedCount} of ${totalClaims} claims.`);
  }

  const syntheticHandoff: Handoff | undefined =
    included.length > 0
      ? {
          schema_version: 1,
          case_id: params.caseId,
          step_id: "merge-fallback",
          profile: "framework-researcher",
          claims: included.slice(0, 16),
          reviews: [],
          disposition: "needs_validation",
          limitations:
            omittedCount > 0
              ? [`Not shown (prompt limit): ${omittedCount} of ${totalClaims} claims.`]
              : [],
          requested_decisions: [],
        }
      : undefined;

  return {
    active: true,
    includedClaims: included,
    totalClaims,
    omittedCount,
    renderedSection: `${header}${lines.join("\n")}`,
    syntheticPredecessorHandoffs: syntheticHandoff ? [syntheticHandoff] : [],
  };
}

class TokenBudgetExceededError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TokenBudgetExceededError";
  }
}

function assertValidIntegerTotalTokens(
  usage: StepTokenUsage | undefined,
  contextLabel: string,
): number {
  if (
    !usage ||
    typeof usage.total_tokens !== "number" ||
    !Number.isInteger(usage.total_tokens) ||
    usage.total_tokens < 0
  ) {
    throw new TokenBudgetExceededError(
      `Fail-closed token accounting: ${contextLabel} is missing integer total_tokens`,
    );
  }
  return usage.total_tokens;
}

/**
 * Sums `results + handoff_rejections + delegated_ledger`.
 * Fails closed (`TokenBudgetExceededError` -> `token_cap_exceeded`) if ANY completed/dispatched
 * turn lacks an integer `total_tokens`!
 */
export function computeRunTokenLedger(
  run: Pick<
    PersistedHuntRun,
    "results" | "handoff_rejections" | "delegated_ledger" | "config"
  >,
): TokenLedgerSummary {
  let resultsTokens = 0;
  let rejectionsTokens = 0;
  let delegatedTokens = 0;
  let actualBilledUsd = 0;
  let shadowApiUsd = 0;
  let cacheSavingsUsd = 0;

  for (const res of Object.values(run.results)) {
    if (res.attempts <= 0) {
      // Capability-gated (`no_network_capture`, `no_intel_source`, `no_focus_claim`) 0-token step
      continue;
    }
    if (res.status === "unknown" || res.status === "cancelled") {
      if (res.usage) {
        const tok = assertValidIntegerTotalTokens(res.usage, `step '${res.step_id}'`);
        resultsTokens += tok;
        actualBilledUsd += res.usage.actual_billed_usd;
        shadowApiUsd += res.usage.shadow_api_usd;
        cacheSavingsUsd += res.usage.cache_savings_usd;
      }
      continue;
    }
    const tok = assertValidIntegerTotalTokens(res.usage, `step '${res.step_id}'`);
    resultsTokens += tok;
    actualBilledUsd += res.usage!.actual_billed_usd;
    shadowApiUsd += res.usage!.shadow_api_usd;
    cacheSavingsUsd += res.usage!.cache_savings_usd;
  }

  for (const rej of run.handoff_rejections) {
    const tok = assertValidIntegerTotalTokens(
      rej.usage,
      `handoff_rejection '${rej.execution_id}'`,
    );
    rejectionsTokens += tok;
    actualBilledUsd += rej.usage!.actual_billed_usd;
    shadowApiUsd += rej.usage!.shadow_api_usd;
    cacheSavingsUsd += rej.usage!.cache_savings_usd;
  }

  for (const del of run.delegated_ledger) {
    if (del.status === "cancelled" && !del.usage) {
      continue;
    }
    const tok = assertValidIntegerTotalTokens(
      del.usage,
      `delegate_task '${del.delegate_id}'`,
    );
    delegatedTokens += tok;
    actualBilledUsd += del.usage!.actual_billed_usd;
    shadowApiUsd += del.usage!.shadow_api_usd;
    cacheSavingsUsd += del.usage!.cache_savings_usd;
  }

  const round = (n: number) => Math.round(n * 1e8) / 1e8;

  return {
    max_total_tokens: run.config.maxTotalTokens,
    consumed_total_tokens: resultsTokens + rejectionsTokens + delegatedTokens,
    results_tokens: resultsTokens,
    rejections_tokens: rejectionsTokens,
    delegated_tokens: delegatedTokens,
    actual_billed_usd: round(actualBilledUsd),
    shadow_api_usd: round(shadowApiUsd),
    cache_savings_usd: round(cacheSavingsUsd),
  };
}

export interface StartHuntInput {
  readonly runId?: string;
  readonly scopeText: string;
  readonly dataPlane: HuntDataPlanePort;
  readonly followUps?: number;
  readonly maxTotalTokens?: number;
  readonly stageGuidance?: Partial<Record<string, string>>;
  readonly optionalOverrides?: Partial<Record<string, boolean>>;
  readonly snapshots?: Record<string, unknown>;
  readonly gateTtlMs?: number;
}

export interface HuntWaveEngineOptions {
  readonly stateStore: DurableStateStore;
  readonly gateAuthority: GateAuthority;
  readonly modelRunner: ModelRunnerPort;
  readonly telemetry?: TelemetrySinkPort;
  readonly maxConcurrentHunts?: number;
  /** Factory used to (re)bind a case data plane when a gate decision resumes a run. */
  readonly resolveDataPlane?: DataPlaneResolver;
}

export type DataPlaneResolver = (
  caseId: string,
) => Promise<HuntDataPlanePort> | HuntDataPlanePort;

export class HuntWaveEngine {
  public readonly stateStore: DurableStateStore;
  public readonly gateAuthority: GateAuthority;
  public readonly modelRunner: ModelRunnerPort;
  public readonly telemetry: TelemetrySinkPort;
  public readonly maxConcurrentHunts: number;
  public readonly resolveDataPlane?: DataPlaneResolver;

  private readonly activeControllers = new Map<string, AbortController>();
  private readonly dataPlanesByRun = new Map<string, HuntDataPlanePort>();

  constructor(options: HuntWaveEngineOptions) {
    this.stateStore = options.stateStore;
    this.gateAuthority = options.gateAuthority;
    this.modelRunner = options.modelRunner;
    this.telemetry = options.telemetry ?? new NoopTelemetrySink();
    this.maxConcurrentHunts = options.maxConcurrentHunts ?? MAX_CONCURRENT_HUNTS;
    this.resolveDataPlane = options.resolveDataPlane;
  }

  public registerDataPlaneForRun(runId: string, dataPlane: HuntDataPlanePort): void {
    this.dataPlanesByRun.set(runId, dataPlane);
  }

  public getActiveHuntCount(): number {
    return this.activeControllers.size;
  }

  /**
   * Startup crash recovery (`F02` / `ReceiptStore`):
   * Inspects all runs caught in `status === 'running'` when the daemon previously exited:
   * - Parked `awaiting_gate` runs remain parked without re-running completed waves.
   * - Any `running` run with an in-flight `reserved` or `previous_dispatch_unknown` receipt
   *   marks that step `unknown` (`reason_code = 'previous_dispatch_unknown'`) and opens a
   *   human `reconcile` gate — NEVER auto-rerunning!
   */
  public recoverInFlightRunsOnStartup(): PersistedHuntRun[] {
    if (this.activeControllers.size > 0) {
      throw new Error(
        `recover_refused_active_hunts: ${this.activeControllers.size} hunt(s) are actively executing; recovery only runs at daemon startup`,
      );
    }
    const runningRuns = this.stateStore.listRuns("running");
    const recovered: PersistedHuntRun[] = [];

    for (const run of runningRuns) {
      const receipts = this.stateStore.listReceiptsForRun(run.run_id);
      const ambiguous = receipts.find(
        (r) => r.status === "reserved" || r.status === "previous_dispatch_unknown",
      );

      if (ambiguous) {
        this.stateStore.finalizeReceipt({
          executionId: ambiguous.execution_id,
          status: "previous_dispatch_unknown",
          reasonCode: "previous_dispatch_unknown",
          diagnostic:
            "Daemon restarted while dispatch receipt was reserved in-flight; human reconcile required",
        });

        run.step_states[ambiguous.step_id] = "awaiting_review";
        run.results[ambiguous.step_id] = {
          step_id: ambiguous.step_id,
          wave: run.wave,
          profile: "framework-coordinator",
          status: "unknown",
          reason_code: "previous_dispatch_unknown",
          attempts: 1,
          diagnostic: "Ambiguous in-flight dispatch recovered on startup",
          finished_at: new Date().toISOString(),
        };
        const { openGate } = this.gateAuthority.openGate({
          huntId: run.run_id,
          caseId: run.case_id,
          wave: run.wave,
          gate: RECONCILE_GATE,
          statusEnum: "previous_dispatch_unknown",
          gatedPayload: {
            run_id: run.run_id,
            step_id: ambiguous.step_id,
            execution_id: ambiguous.execution_id,
            reason_code: "previous_dispatch_unknown",
          },
          syntheticOnly: run.synthetic_only,
          dataOrigin: run.data_origin,
          reasonCode: "previous_dispatch_unknown",
          unknownStepId: ambiguous.step_id,
          ttlMs: run.config.gateTtlMs,
        });
        run.open_gate = openGate;
        run.status = "awaiting_gate";
        run.reason_code = "previous_dispatch_unknown";
        this.stateStore.saveRun(run);
        recovered.push(run);
      }
    }

    return recovered;
  }

  /**
   * Global Stop (`F08`): immediately aborts all in-flight sessions & tools for `runId`
   * and persists `status = 'cancelled'`.
   */
  public cancelRun(runId: string, reason = "global_stop"): PersistedHuntRun {
    const controller = this.activeControllers.get(runId);
    if (controller) {
      controller.abort(new Error(reason));
    }
    const run = this.stateStore.getRun(runId);
    if (!run) {
      throw new Error(`Unknown hunt run_id '${runId}'`);
    }
    if (run.status === "completed" || run.status === "failed" || run.status === "cancelled") {
      return run;
    }

    if (run.open_gate) {
      this.gateAuthority.removeReviewArtifacts(run.open_gate);
      run.open_gate = null;
    }
    for (const [stepId, st] of Object.entries(run.step_states)) {
      if (st === "working" || st === "awaiting_approval" || st === "awaiting_review") {
        run.step_states[stepId] = "stopped";
      }
    }
    run.status = "cancelled";
    run.reason_code = reason;
    this.stateStore.saveRun(run);
    this.telemetry.emit(runId, "hunt.cancelled", { reason });
    return run;
  }

  public async startHunt(input: StartHuntInput): Promise<PersistedHuntRun> {
    if (this.activeControllers.size >= this.maxConcurrentHunts) {
      throw new Error(
        `max_concurrent_hunts_exceeded: limit is ${this.maxConcurrentHunts} concurrent hunts`,
      );
    }

    const metaParsed = CaseMetadataSchema.safeParse(input.dataPlane.caseMetadata);
    if (!metaParsed.success) {
      const first = metaParsed.error.issues[0];
      throw new DataPlaneAccessError(
        400,
        "case_origin_mismatch",
        `Invalid case metadata (${first?.path.join(".") || "root"}): ${first?.message ?? "invalid"}`,
      );
    }
    const caseMeta = metaParsed.data;
    const scopeText = input.scopeText.trim();
    if (!scopeText) {
      throw new Error("scopeText must be non-empty");
    }

    // Forbid `"synthetic"` in scope or stageGuidance when !synthetic_only
    validateNonSyntheticGuidanceText(scopeText, "scope", caseMeta.synthetic_only);
    if (input.stageGuidance) {
      for (const [stage, g] of Object.entries(input.stageGuidance)) {
        validateNonSyntheticGuidanceText(
          g,
          `stage_guidance.${stage}`,
          caseMeta.synthetic_only,
        );
      }
    }

    const followUps = input.followUps ?? DEFAULT_FOLLOW_UPS;
    const maxTotalTokens = input.maxTotalTokens ?? 500_000;
    if (!Number.isInteger(maxTotalTokens) || maxTotalTokens <= 0) {
      throw new RangeError("maxTotalTokens must be a positive integer");
    }

    const { snapshot } = selectSnapshot(input.snapshots, caseMeta.case_id);
    const waves = buildEightWaveGraph({
      followUps,
      optionalOverrides: input.optionalOverrides,
    });

    const stepStates: Record<string, PersistedHuntRun["step_states"][string]> = {};
    for (const waveSteps of waves) {
      for (const s of waveSteps) {
        stepStates[s.stepId] = "not_reached";
      }
    }

    const runId = input.runId?.trim() || `hunt-${crypto.randomUUID()}`;
    if (this.stateStore.getRun(runId)) {
      throw new Error(`Hunt run_id '${runId}' already exists`);
    }
    const now = new Date().toISOString();

    const run: PersistedHuntRun = {
      run_id: runId,
      case_id: caseMeta.case_id,
      data_origin: caseMeta.data_origin,
      synthetic_only: caseMeta.synthetic_only,
      wave: "scope",
      wave_index: 0,
      status: "running",
      reason_code: null,
      step_states: stepStates,
      results: {},
      handoff_rejections: [],
      reviewed_handoffs: {},
      delegated_ledger: [],
      open_gate: null,
      decisions: [],
      token_ledger: {
        max_total_tokens: maxTotalTokens,
        consumed_total_tokens: 0,
        results_tokens: 0,
        rejections_tokens: 0,
        delegated_tokens: 0,
        actual_billed_usd: 0,
        shadow_api_usd: 0,
        cache_savings_usd: 0,
      },
      citation_receipt: null,
      snapshot,
      config: {
        scopeText,
        followUps,
        maxTotalTokens,
        stageGuidance: input.stageGuidance,
        optionalOverrides: input.optionalOverrides,
        gateTtlMs: input.gateTtlMs,
      },
      created_at: now,
      updated_at: now,
    };

    this.stateStore.saveRun(run);
    this.dataPlanesByRun.set(runId, input.dataPlane);
    this.telemetry.emit(runId, "hunt.started", {
      case_id: run.case_id,
      data_origin: run.data_origin,
      synthetic_only: run.synthetic_only,
      follow_ups: followUps,
      max_total_tokens: maxTotalTokens,
    });

    return this.driveUntilGateOrTerminal(runId, input.dataPlane);
  }

  /**
   * Submits an authenticated human (or non-human intermediate) gate decision and
   * automatically advances execution if approved!
   *
   * Ordering is fail-closed: validate (pure) -> resolve the data plane when the decision
   * would resume execution -> ONE atomic SQLite commit (gate-open check + unique decision +
   * run transition) -> audit log append -> resume. Nothing is mutated if validation or
   * data-plane resolution fails.
   */
  public async submitGateDecision(
    input: SubmitGateDecisionInput,
    dataPlaneOverride?: HuntDataPlanePort,
  ): Promise<PersistedHuntRun> {
    const snapshot = this.stateStore.getRun(input.huntId);
    if (!snapshot) {
      throw new Error(`Unknown hunt run_id '${input.huntId}'`);
    }
    if (snapshot.status !== "awaiting_gate" || !snapshot.open_gate) {
      throw new Error(`Hunt '${input.huntId}' is not currently awaiting a gate decision`);
    }
    if (this.activeControllers.has(snapshot.run_id)) {
      throw new Error(`Hunt '${snapshot.run_id}' is already actively executing`);
    }

    const activeGate = snapshot.open_gate;
    const { decision, auditRecord } = this.gateAuthority.validateDecision(activeGate, input);
    const transition = this.planGateTransition(snapshot, activeGate, decision.action);

    let dp: HuntDataPlanePort | undefined;
    if (transition.resume) {
      dp =
        dataPlaneOverride ??
        this.dataPlanesByRun.get(snapshot.run_id) ??
        (this.resolveDataPlane ? await this.resolveDataPlane(snapshot.case_id) : undefined);
      if (!dp) {
        throw new Error(
          `Hunt '${snapshot.run_id}' cannot resume after gate '${activeGate.gate}': no HuntDataPlanePort is bound or resolvable (decision NOT recorded)`,
        );
      }
    }

    const committed = this.stateStore.commitGateDecision({
      decision,
      expectedOpenGate: activeGate,
      mutate: (run) => transition.apply(run),
    });
    if (committed.outcome === "decision_id_replayed") {
      throw new GateDecisionError(
        "decision_id_replayed",
        `Replay blocked: decision_id '${decision.decision_id}' has already been consumed`,
      );
    }
    if (committed.outcome !== "committed") {
      throw new GateDecisionError(
        "gate_not_open",
        `Gate '${activeGate.gate}' on hunt '${snapshot.run_id}' is no longer open (already decided or changed)`,
      );
    }
    const run = committed.run;

    this.gateAuthority.finalizeCommittedDecision(activeGate, auditRecord);
    this.telemetry.onGateDecision?.(decision);

    if (transition.kind === "reject") {
      this.telemetry.emit(run.run_id, "hunt.failed", { reason_code: run.reason_code });
      return run;
    }
    if (transition.kind === "incident") {
      this.stateStore.checkpointWal();
      this.telemetry.checkpoint?.();
      this.telemetry.emit(run.run_id, "hunt.completed", {
        total_tokens: run.token_ledger.consumed_total_tokens,
        actual_billed_usd: run.token_ledger.actual_billed_usd,
        shadow_api_usd: run.token_ledger.shadow_api_usd,
      });
      return run;
    }
    if (!transition.resume || !dp) {
      return run;
    }

    this.dataPlanesByRun.set(run.run_id, dp);
    return this.driveUntilGateOrTerminal(run.run_id, dp);
  }

  /** Deterministically plans the run transition for a gate decision (no side effects). */
  private planGateTransition(
    run: PersistedHuntRun,
    activeGate: NonNullable<PersistedHuntRun["open_gate"]>,
    action: "approve" | "reject",
  ): {
    kind: "reject" | "scope" | "incident" | "reconcile_drop" | "reconcile_halt" | "advance";
    resume: boolean;
    apply: (run: PersistedHuntRun) => void;
  } {
    if (action === "reject") {
      return {
        kind: "reject",
        resume: false,
        apply: (r) => {
          r.status = "failed";
          r.reason_code =
            activeGate.gate === RECONCILE_GATE
              ? "reconcile_rejected"
              : `gate_${activeGate.gate}_rejected`;
          for (const [sid, st] of Object.entries(r.step_states)) {
            if (st === "awaiting_review" || st === "awaiting_approval") {
              r.step_states[sid] = "stopped";
            }
          }
        },
      };
    }

    if (activeGate.gate === "scope") {
      return {
        kind: "scope",
        resume: true,
        apply: (r) => {
          const scopeRes = r.results["scope"];
          if (scopeRes?.handoff) {
            r.reviewed_handoffs["scope"] = scopeRes.handoff;
          }
          r.step_states["scope"] = "done";
          r.wave_index = 1;
          r.wave = HUNT_WAVES[1]!;
          r.status = "running";
          r.reason_code = null;
        },
      };
    }

    if (activeGate.gate === "incident") {
      return {
        kind: "incident",
        resume: false,
        apply: (r) => {
          const incRes = r.results["incident"];
          if (incRes?.handoff) {
            r.reviewed_handoffs["incident"] = incRes.handoff;
          }
          r.step_states["incident"] = "done";
          r.status = "completed";
          r.reason_code = null;
        },
      };
    }

    if (activeGate.gate === RECONCILE_GATE) {
      // Human operator explicitly reconciled an unknown step
      const unknownStepId = activeGate.unknown_step_id;
      const waves = buildEightWaveGraph({
        followUps: run.config.followUps,
        optionalOverrides: run.config.optionalOverrides,
      });
      const spec = waves.flat().find((s) => s.stepId === unknownStepId);
      if (unknownStepId && spec?.optional) {
        return {
          kind: "reconcile_drop",
          resume: true,
          apply: (r) => {
            r.step_states[unknownStepId] = "dropped";
            r.results[unknownStepId] = {
              step_id: unknownStepId,
              wave: spec.wave,
              profile: spec.profile,
              status: "dropped",
              reason_code: "reconciled_drop",
              attempts: 0,
              finished_at: new Date().toISOString(),
            };
            r.status = "running";
            r.reason_code = null;
          },
        };
      }
      // Required step was unknown and cannot materialize a verified typed handoff without re-running
      return {
        kind: "reconcile_halt",
        resume: false,
        apply: (r) => {
          r.status = "failed";
          r.reason_code = "reconciled_halt_required_step";
        },
      };
    }

    return {
      kind: "advance",
      resume: true,
      apply: (r) => {
        r.status = "running";
        r.reason_code = null;
      },
    };
  }

  /**
   * Lists runs left `status === "running"` with no live controller in this process (e.g. a
   * crash between waves, or a committed approval whose resumption failed). They are safe to
   * continue with `resumeParkedRun`, because ambiguous in-flight dispatches were already parked
   * behind a `reconcile` gate by `recoverInFlightRunsOnStartup()`.
   */
  public listResumableRuns(): PersistedHuntRun[] {
    return this.stateStore
      .listRuns("running")
      .filter((r) => !this.activeControllers.has(r.run_id));
  }

  public async resumeParkedRun(
    runId: string,
    dataPlane: HuntDataPlanePort,
  ): Promise<PersistedHuntRun> {
    this.dataPlanesByRun.set(runId, dataPlane);
    const run = this.stateStore.getRun(runId);
    if (!run) {
      throw new Error(`Unknown hunt run_id '${runId}'`);
    }
    if (run.status !== "running") {
      return run;
    }
    return this.driveUntilGateOrTerminal(runId, dataPlane);
  }

  private refreshAndEnforceBudget(run: PersistedHuntRun, preDispatch: boolean): boolean {
    try {
      const ledger = computeRunTokenLedger(run);
      run.token_ledger = ledger;
      const breached = preDispatch
        ? ledger.consumed_total_tokens >= ledger.max_total_tokens
        : ledger.consumed_total_tokens > ledger.max_total_tokens;
      if (breached) {
        run.status = "failed";
        run.reason_code = "token_cap_exceeded";
        this.stateStore.saveRun(run);
        this.telemetry.emit(run.run_id, "hunt.failed", {
          reason_code: "token_cap_exceeded",
          consumed_total_tokens: ledger.consumed_total_tokens,
          max_total_tokens: ledger.max_total_tokens,
        });
        return false;
      }
      return true;
    } catch (err) {
      if (err instanceof TokenBudgetExceededError) {
        run.status = "failed";
        run.reason_code = "token_cap_exceeded";
        this.stateStore.saveRun(run);
        this.telemetry.emit(run.run_id, "hunt.failed", {
          reason_code: "token_cap_exceeded",
          diagnostic: err.message,
        });
        return false;
      }
      throw err;
    }
  }

  private async driveUntilGateOrTerminal(
    runId: string,
    dataPlane: HuntDataPlanePort,
  ): Promise<PersistedHuntRun> {
    if (this.activeControllers.has(runId)) {
      throw new Error(`Hunt '${runId}' is already actively executing`);
    }
    if (this.activeControllers.size >= this.maxConcurrentHunts) {
      throw new Error(
        `max_concurrent_hunts_exceeded: limit is ${this.maxConcurrentHunts} concurrent hunts`,
      );
    }

    const controller = new AbortController();
    this.activeControllers.set(runId, controller);

    try {
      let run = this.stateStore.getRun(runId)!;
      const waves = buildEightWaveGraph({
        followUps: run.config.followUps,
        optionalOverrides: run.config.optionalOverrides,
      });
      const snapshotJson = run.snapshot ? JSON.stringify(run.snapshot) : "";
      const snapshotBytes = Buffer.byteLength(snapshotJson, "utf8");

      const capDescriptors: StepCapDescriptor[] = waves.flat().map((s) => ({
        stepId: s.stepId,
        profile: s.profile,
        dependsOn: s.dependsOn,
        focus: s.focus,
        basePromptOverheadBytes: 6_144,
      }));
      const typedOutputCaps = computeTypedOutputCaps(capDescriptors, snapshotBytes);
      const capabilities = await dataPlane.capabilities();

      while (run.wave_index < waves.length && run.status === "running") {
        if (controller.signal.aborted) {
          return this.cancelRun(runId, "global_stop");
        }

        const waveSteps = waves[run.wave_index]!;
        const currentWave = HUNT_WAVES[run.wave_index]!;
        run.wave = currentWave;
        this.stateStore.saveRun(run);

        if (waveSteps.length === 0) {
          // e.g. Wave 4 when followUps === 0
          run.wave_index += 1;
          this.stateStore.saveRun(run);
          continue;
        }

        // Pre-dispatch budget check
        if (!this.refreshAndEnforceBudget(run, true)) {
          return run;
        }

        this.telemetry.emit(runId, "wave.started", {
          wave: currentWave,
          wave_index: run.wave_index,
          steps: waveSteps.map((s) => s.stepId),
        });

        // Pre-flight OAuth credentials ONCE per unique provider before parallel wave dispatch
        const providersInWave = waveSteps.map(
          (s) => this.modelRunner.getPinnedModelForRole(s.profile).provider,
        );
        try {
          await this.modelRunner.preflightWave(
            providersInWave,
            `${runId}:wave-${run.wave_index + 1}`,
            controller.signal,
          );
          if (controller.signal.aborted) return this.cancelRun(runId, "global_stop");
        } catch (err) {
          if (controller.signal.aborted) return this.cancelRun(runId, "global_stop");
          run.status = "failed";
          run.reason_code = "oauth_preflight_failed";
          this.stateStore.saveRun(run);
          this.telemetry.emit(runId, "hunt.failed", {
            reason_code: "oauth_preflight_failed",
            diagnostic: err instanceof Error ? err.message : String(err),
          });
          return run;
        }

        // Execute all steps in this wave concurrently via Promise.all (e.g. Wave 2 4-way, Wave 4 K=6)
        const pendingWaveSteps = waveSteps.filter((s) => {
          const existing = run.results[s.stepId];
          return !existing || (existing.status !== "done" && existing.status !== "dropped");
        });

        await Promise.all(
          pendingWaveSteps.map((spec) =>
            this.executeSingleStep({
              run,
              spec,
              allWaves: waves,
              capabilities,
              dataPlane,
              typedOutputCaps,
              snapshotJson,
              signal: controller.signal,
            }),
          ),
        );

        // Reload or inspect run state after parallel wave completion
        const latestAfterWave = this.stateStore.getRun(runId)!;
        if (latestAfterWave.status === "cancelled") {
          return latestAfterWave;
        }
        run = latestAfterWave;

        // Post-wave token cap check (fails closed if any completed step lacked integer total_tokens!)
        if (!this.refreshAndEnforceBudget(run, false)) {
          return run;
        }
        this.stateStore.saveRun(run);

        // Check if any step in the wave hit `unknown` (`previous_dispatch_unknown` / `citation_source_unavailable`)
        const unknownStep = waveSteps.find((s) => run.results[s.stepId]?.status === "unknown");
        if (unknownStep) {
          const unkRec = run.results[unknownStep.stepId]!;
          run.step_states[unknownStep.stepId] = "awaiting_review";
          const { openGate } = this.gateAuthority.openGate({
            huntId: run.run_id,
            caseId: run.case_id,
            wave: currentWave,
            gate: RECONCILE_GATE,
            statusEnum: unkRec.reason_code ?? "previous_dispatch_unknown",
            gatedPayload: {
              run_id: run.run_id,
              step_id: unknownStep.stepId,
              reason_code: unkRec.reason_code ?? "previous_dispatch_unknown",
              diagnostic: unkRec.diagnostic ?? "",
            },
            syntheticOnly: run.synthetic_only,
            dataOrigin: run.data_origin,
            reasonCode: unkRec.reason_code ?? "previous_dispatch_unknown",
            unknownStepId: unknownStep.stepId,
            ttlMs: run.config.gateTtlMs,
          });
          run.open_gate = openGate;
          run.status = "awaiting_gate";
          run.reason_code = unkRec.reason_code ?? "previous_dispatch_unknown";
          this.stateStore.saveRun(run);
          this.telemetry.emit(runId, "gate.opened", {
            gate: RECONCILE_GATE,
            wave: currentWave,
            payload_sha256: openGate.payload_sha256,
          });
          return run;
        }

        // Check if any REQUIRED step failed in this wave
        const failedRequired = waveSteps.find(
          (s) => !s.optional && run.results[s.stepId]?.status !== "done",
        );
        if (failedRequired) {
          const failRec = run.results[failedRequired.stepId];
          run.status = "failed";
          run.reason_code = failRec?.reason_code ?? "required_step_failed";
          this.stateStore.saveRun(run);
          this.telemetry.emit(runId, "hunt.failed", {
            step_id: failedRequired.stepId,
            reason_code: run.reason_code,
          });
          return run;
        }

        // Wave 2 special invariant: halt (`no_surviving_dependency`) ONLY if all 4 Wave 2 hunters dropped!
        if (currentWave === "investigation") {
          const survivingWave2 = waveSteps.filter(
            (s) => run.results[s.stepId]?.status === "done",
          );
          if (survivingWave2.length === 0) {
            run.status = "failed";
            run.reason_code = "no_surviving_dependency";
            this.stateStore.saveRun(run);
            this.telemetry.emit(runId, "hunt.failed", {
              wave: currentWave,
              reason_code: "no_surviving_dependency",
            });
            return run;
          }
        }

        // Human Gate 1 (`scope`)
        if (currentWave === "scope") {
          const scopeHandoff = run.results["scope"]?.handoff;
          if (!scopeHandoff) {
            run.status = "failed";
            run.reason_code = "missing_scope_handoff";
            this.stateStore.saveRun(run);
            return run;
          }
          run.step_states["scope"] = "awaiting_review";
          const { openGate } = this.gateAuthority.openGate({
            huntId: run.run_id,
            caseId: run.case_id,
            wave: "scope",
            gate: "scope",
            statusEnum: "awaiting_human_scope_approval",
            gatedPayload: {
              run_id: run.run_id,
              gate: "scope",
              handoff: scopeHandoff,
            },
            syntheticOnly: run.synthetic_only,
            dataOrigin: run.data_origin,
            handoff: scopeHandoff,
            ttlMs: run.config.gateTtlMs,
          });
          run.open_gate = openGate;
          run.status = "awaiting_gate";
          this.stateStore.saveRun(run);
          this.telemetry.emit(runId, "gate.opened", {
            gate: "scope",
            wave: "scope",
            payload_sha256: openGate.payload_sha256,
          });
          return run;
        }

        // Human Gate 2 (`incident`) — already citation-verified inside executeSingleStep!
        if (currentWave === "incident") {
          const incidentHandoff = run.results["incident"]?.handoff;
          if (!incidentHandoff || !run.citation_receipt?.verified) {
            run.status = "failed";
            run.reason_code = "citation_verification_failed";
            this.stateStore.saveRun(run);
            return run;
          }
          run.step_states["incident"] = "awaiting_review";
          const { openGate } = this.gateAuthority.openGate({
            huntId: run.run_id,
            caseId: run.case_id,
            wave: "incident",
            gate: "incident",
            statusEnum: "awaiting_human_incident_approval",
            gatedPayload: {
              run_id: run.run_id,
              gate: "incident",
              handoff: incidentHandoff,
              citation_receipt: run.citation_receipt,
            },
            syntheticOnly: run.synthetic_only,
            dataOrigin: run.data_origin,
            handoff: incidentHandoff,
            ttlMs: run.config.gateTtlMs,
          });
          run.open_gate = openGate;
          run.status = "awaiting_gate";
          this.stateStore.saveRun(run);
          this.telemetry.emit(runId, "gate.opened", {
            gate: "incident",
            wave: "incident",
            payload_sha256: openGate.payload_sha256,
          });
          return run;
        }

        // Advance to next wave
        run.wave_index += 1;
        if (run.wave_index < HUNT_WAVES.length) {
          run.wave = HUNT_WAVES[run.wave_index]!;
        }
        this.stateStore.saveRun(run);
      }

      return run;
    } catch (err) {
      if (controller.signal.aborted) return this.cancelRun(runId, "global_stop");
      throw err;
    } finally {
      this.activeControllers.delete(runId);
    }
  }

  private resolveStepPredecessorsAndPrompt(params: {
    run: PersistedHuntRun;
    spec: WaveStepSpec;
    allWaves: WaveStepSpec[][];
    snapshotJson: string;
    stepHardCap: number;
    targetBytes: number;
    suppliedSourceIds: readonly string[];
  }):
    | {
        readonly kind: "drop";
        readonly reasonCode: string;
      }
    | {
        readonly kind: "ready";
        readonly promptBody: string;
        readonly predecessors: Handoff[];
        readonly ancestorClaims: Claim[];
      } {
    const { run, spec } = params;

    // Build surviving handoff map across completed steps
    const survivingHandoffs: Record<string, Handoff> = { ...run.reviewed_handoffs };
    for (const [sid, res] of Object.entries(run.results)) {
      if (res.status === "done" && res.handoff) {
        survivingHandoffs[sid] = res.handoff;
      }
    }

    // 1. Wave 4 single-claim `focus = ("analysis", claimIndex)` slicing
    let focusedClaimBlock = "";
    if (spec.focus) {
      const [sourceStepId, claimIdx] = spec.focus;
      const sourceHandoff = survivingHandoffs[sourceStepId];
      if (!sourceHandoff) {
        return { kind: "drop", reasonCode: "no_surviving_dependency" };
      }
      const targetClaim = sourceHandoff.claims[claimIdx];
      if (!targetClaim) {
        return { kind: "drop", reasonCode: "no_focus_claim" };
      }
      const singleClaimHandoff: Handoff = {
        ...sourceHandoff,
        claims: [targetClaim],
      };
      focusedClaimBlock = [
        `## Focused Claim Slice (${sourceStepId} claim #${claimIdx + 1})`,
        JSON.stringify(targetClaim),
      ].join("\n");

      const promptBody = this.composeStepPromptText({
        run,
        spec,
        snapshotJson: params.snapshotJson,
        predecessorSection: focusedClaimBlock,
        stepHardCap: params.stepHardCap,
        targetBytes: params.targetBytes,
        suppliedSourceIds: params.suppliedSourceIds,
      });

      return {
        kind: "ready",
        promptBody,
        predecessors: [singleClaimHandoff],
        ancestorClaims: [],
      };
    }

    // 2. Standard predecessor resolution (+ `_MERGE_FALLBACK_PATCH` when `merge` dropped!)
    const predecessors: Handoff[] = [];
    const ancestorClaims: Claim[] = [];
    const predecessorBlocks: string[] = [];

    const mergeResult = run.results["merge"];
    const mergeDropped =
      spec.dependsOn.includes("merge") &&
      (!survivingHandoffs["merge"] || mergeResult?.status === "dropped");

    for (const depId of spec.dependsOn) {
      if (depId === "merge" && mergeDropped) {
        continue;
      }
      const h = survivingHandoffs[depId];
      if (h) {
        predecessors.push(h);
        predecessorBlocks.push(`### Predecessor Handoff: ${depId} (${h.profile})\n${JSON.stringify(h)}`);
        // If predecessor is `purple` (`framework-reviewer`), carry forward its reviewed predecessor claims as `ancestorClaims`!
        if (h.profile === "framework-reviewer") {
          const purpleSpec = params.allWaves.flat().find((s) => s.stepId === depId);
          for (const purpleDep of purpleSpec?.dependsOn ?? []) {
            const anc = survivingHandoffs[purpleDep];
            if (anc && anc.profile !== "framework-reviewer") {
              ancestorClaims.push(...anc.claims);
            }
          }
        }
      }
    }

    if (mergeDropped) {
      const followIds = (params.allWaves[3] ?? []).map((s) => s.stepId);
      const otherBlocksBytes = Buffer.byteLength(predecessorBlocks.join("\n\n"), "utf8");
      const snapshotBytes = Buffer.byteLength(params.snapshotJson, "utf8");
      const fallbackBudget = Math.max(
        512,
        MAX_PROMPT_BYTES -
          8_192 -
          snapshotBytes -
          otherBlocksBytes -
          RETRY_NOTICE_RESERVE_BYTES,
      );
      const fallback = buildMergeFallbackInjection({
        caseId: run.case_id,
        followStepIds: followIds,
        survivingHandoffs,
        budgetBytes: fallbackBudget,
      });
      predecessorBlocks.unshift(fallback.renderedSection);
      predecessors.unshift(...fallback.syntheticPredecessorHandoffs);
      if (spec.stepId === "incident") {
        ancestorClaims.push(...fallback.includedClaims);
      }
    }

    if (spec.dependsOn.length > 0 && predecessors.length === 0) {
      return { kind: "drop", reasonCode: "no_surviving_dependency" };
    }

    const promptBody = this.composeStepPromptText({
      run,
      spec,
      snapshotJson: params.snapshotJson,
      predecessorSection: predecessorBlocks.join("\n\n"),
      stepHardCap: params.stepHardCap,
      targetBytes: params.targetBytes,
      suppliedSourceIds: params.suppliedSourceIds,
    });

    return {
      kind: "ready",
      promptBody,
      predecessors,
      ancestorClaims,
    };
  }

  private composeStepPromptText(params: {
    run: PersistedHuntRun;
    spec: WaveStepSpec;
    snapshotJson: string;
    predecessorSection: string;
    stepHardCap: number;
    targetBytes: number;
    suppliedSourceIds: readonly string[];
  }): string {
    const { run, spec } = params;
    const originLine = run.synthetic_only
      ? "Data Origin: synthetic lab telemetry (synthetic_only=true)."
      : `Data Origin: ${formatRealDataOriginText(run.data_origin as Exclude<typeof run.data_origin, "synthetic">)} (synthetic_only=false).`;

    const sections: string[] = [
      SHARED_CACHE_HEADER.trimEnd(),
      `## Investigation Context`,
      `Hunt ID: ${run.run_id}`,
      `Case ID: ${run.case_id}`,
      `Wave: ${spec.wave} | Step: ${spec.stepId} | Profile: ${spec.profile}`,
      originLine,
      "",
      `## Approved Investigation Scope`,
      run.config.scopeText,
    ];

    if (params.snapshotJson) {
      sections.push("", "## Case Ontology Snapshot", params.snapshotJson);
    }

    if (params.predecessorSection) {
      sections.push("", "## Upstream Stage Inputs", params.predecessorSection);
    }

    sections.push(
      "",
      buildHandoffInstructions({
        caseId: run.case_id,
        stepId: spec.stepId,
        profile: spec.profile,
        suppliedSourceIds: params.suppliedSourceIds,
        hasSnapshot: Boolean(run.snapshot),
        targetBytes: params.targetBytes,
        hardCapBytes: params.stepHardCap,
      }),
    );

    const full = sections.join("\n");
    const totalBytes = Buffer.byteLength(full, "utf8");
    if (totalBytes > MAX_PROMPT_BYTES) {
      throw new OntologyValidationError(
        `Assembled prompt for step '${spec.stepId}' exceeds MAX_PROMPT_BYTES (${totalBytes} > ${MAX_PROMPT_BYTES})`,
      );
    }
    return full;
  }

  private async executeSingleStep(params: {
    run: PersistedHuntRun;
    spec: WaveStepSpec;
    allWaves: WaveStepSpec[][];
    capabilities: CaseCapabilities;
    dataPlane: HuntDataPlanePort;
    typedOutputCaps: Map<string, number>;
    snapshotJson: string;
    signal: AbortSignal;
  }): Promise<void> {
    const { run, spec, capabilities, dataPlane } = params;

    // 1. Capability gating (`F09`): skip network / intel cleanly with 0 tokens when case lacks them
    if (spec.capabilityRequirement === "network_capture" && !capabilities.hasNetworkCapture) {
      run.step_states[spec.stepId] = "dropped";
      run.results[spec.stepId] = {
        step_id: spec.stepId,
        wave: spec.wave,
        profile: spec.profile,
        status: "dropped",
        reason_code: "no_network_capture",
        attempts: 0,
        finished_at: new Date().toISOString(),
      };
      this.stateStore.saveRun(run);
      this.telemetry.emit(run.run_id, "step.dropped", {
        step_id: spec.stepId,
        reason_code: "no_network_capture",
      });
      return;
    }

    if (spec.capabilityRequirement === "intel_source" && !capabilities.hasIntelSource) {
      run.step_states[spec.stepId] = "dropped";
      run.results[spec.stepId] = {
        step_id: spec.stepId,
        wave: spec.wave,
        profile: spec.profile,
        status: "dropped",
        reason_code: "no_intel_source",
        attempts: 0,
        finished_at: new Date().toISOString(),
      };
      this.stateStore.saveRun(run);
      this.telemetry.emit(run.run_id, "step.dropped", {
        step_id: spec.stepId,
        reason_code: "no_intel_source",
      });
      return;
    }

    const stepHardCap =
      params.typedOutputCaps.get(spec.stepId) ??
      (spec.stepId === "incident" ? FINAL_HANDOFF_BYTES : 16_384);
    const hasTools = getAllowedToolsForStep(spec.profile, spec.stepId).length > 0;
    const isForwardedStep = spec.stepId !== "incident";
    const initialTargetBytes = disclosedTargetBytes(stepHardCap, isForwardedStep, hasTools);
    const suppliedSourceIds = dataPlane.caseMetadata.sources;

    const resolved = this.resolveStepPredecessorsAndPrompt({
      run,
      spec,
      allWaves: params.allWaves,
      snapshotJson: params.snapshotJson,
      stepHardCap,
      targetBytes: initialTargetBytes,
      suppliedSourceIds,
    });

    if (resolved.kind === "drop") {
      run.step_states[spec.stepId] = spec.optional ? "dropped" : "stopped";
      run.results[spec.stepId] = {
        step_id: spec.stepId,
        wave: spec.wave,
        profile: spec.profile,
        status: spec.optional ? "dropped" : "failed",
        reason_code: resolved.reasonCode,
        attempts: 0,
        finished_at: new Date().toISOString(),
      };
      this.stateStore.saveRun(run);
      this.telemetry.emit(run.run_id, "step.dropped", {
        step_id: spec.stepId,
        reason_code: resolved.reasonCode,
      });
      return;
    }

    run.step_states[spec.stepId] = "working";
    this.stateStore.saveRun(run);

    const stageGuidance =
      run.config.stageGuidance?.[spec.stepId] ?? run.config.stageGuidance?.[spec.stageKey];

    // At most 2 attempts total: attempt 1 (`${runId}:${stepId}`) + at most 1 `:retry` (`${runId}:${stepId}:retry`)
    let currentPromptBody = resolved.promptBody;
    let combinedUsage: StepTokenUsage | undefined;

    for (let attempt = 1; attempt <= 2; attempt++) {
      if (params.signal.aborted) {
        run.step_states[spec.stepId] = "stopped";
        run.results[spec.stepId] = {
          step_id: spec.stepId,
          wave: spec.wave,
          profile: spec.profile,
          status: "cancelled",
          reason_code: "cancelled",
          attempts: attempt - 1,
          usage: combinedUsage,
          finished_at: new Date().toISOString(),
        };
        this.stateStore.saveRun(run);
        return;
      }

      const executionId =
        attempt === 1 ? `${run.run_id}:${spec.stepId}` : `${run.run_id}:${spec.stepId}:retry`;
      const fingerprint = computeDispatchFingerprint({
        runId: run.run_id,
        stepId: spec.stepId,
        profile: spec.profile,
        prompt: currentPromptBody,
      });

      const reservation = this.stateStore.reserveReceipt({
        executionId,
        runId: run.run_id,
        stepId: spec.stepId,
        sessionId: executionId,
        inputId: `in-${fingerprint.slice(0, 16)}`,
        fingerprint,
      });

      if (reservation.action === "unknown") {
        run.step_states[spec.stepId] = "awaiting_review";
        run.results[spec.stepId] = {
          step_id: spec.stepId,
          wave: spec.wave,
          profile: spec.profile,
          status: "unknown",
          reason_code: "previous_dispatch_unknown",
          attempts: attempt,
          diagnostic: reservation.receipt.diagnostic ?? "Previous dispatch receipt is unknown",
          finished_at: new Date().toISOString(),
        };
        this.stateStore.saveRun(run);
        return;
      }

      if (reservation.action === "conflict") {
        run.step_states[spec.stepId] = "stopped";
        run.results[spec.stepId] = {
          step_id: spec.stepId,
          wave: spec.wave,
          profile: spec.profile,
          status: "failed",
          reason_code: "fingerprint_conflict",
          attempts: attempt,
          diagnostic: "Dispatch receipt fingerprint mismatch",
          finished_at: new Date().toISOString(),
        };
        this.stateStore.saveRun(run);
        return;
      }

      let turnOutputText: string;
      let turnUsage: StepTokenUsage | undefined;
      let turnStatus: "completed" | "failed" | "refused" | "cancelled" | "unknown";
      let turnReasonCode: string | undefined;
      let turnDiagnostic: string | undefined;
      let turnRefusal: StepResultRecord["refusal"];

      if (reservation.action === "replay_completed") {
        turnOutputText = reservation.receipt.output_text ?? "";
        turnUsage = reservation.receipt.usage ?? undefined;
        turnStatus = "completed";
      } else {
        const turnResult = await this.modelRunner.runTurn({
          executionId,
          runId: run.run_id,
          caseId: run.case_id,
          stepId: spec.stepId,
          wave: spec.wave,
          profile: spec.profile,
          syntheticOnly: run.synthetic_only,
          dataOrigin: run.data_origin,
          userPromptBody: currentPromptBody,
          stageGuidance,
          maxTurns: spec.maxTurns,
          dataPlane,
          telemetry: this.telemetry,
          delegateContext: {
            checkBudgetBeforeDelegate: () => {
              const ledger = computeRunTokenLedger(run);
              if (ledger.consumed_total_tokens >= ledger.max_total_tokens) {
                throw new Error("token_cap_exceeded prior to delegate_task");
              }
            },
            onDelegatedUsage: (record) => {
              run.delegated_ledger.push(record);
              this.stateStore.saveRun(run);
            },
          },
          signal: params.signal,
        });

        turnOutputText = turnResult.output_text;
        turnUsage = turnResult.usage;
        turnStatus = turnResult.status;
        turnReasonCode = turnResult.reason_code;
        turnDiagnostic = turnResult.diagnostic;
        turnRefusal = turnResult.refusal;

        this.stateStore.finalizeReceipt({
          executionId,
          status:
            turnStatus === "completed"
              ? "completed"
              : turnStatus === "unknown"
                ? "previous_dispatch_unknown"
                : "failed",
          reasonCode: turnReasonCode ?? null,
          outputText: turnOutputText,
          usage: turnUsage ?? null,
          refusal: turnRefusal ?? null,
          diagnostic: turnDiagnostic ?? null,
        });
      }
      if (params.signal.aborted) return;

      if (turnStatus === "cancelled") {
        run.step_states[spec.stepId] = "stopped";
        run.results[spec.stepId] = {
          step_id: spec.stepId,
          wave: spec.wave,
          profile: spec.profile,
          status: "cancelled",
          reason_code: "cancelled",
          attempts: attempt,
          usage: turnUsage,
          diagnostic: turnDiagnostic,
          finished_at: new Date().toISOString(),
        };
        this.stateStore.saveRun(run);
        return;
      }

      // Cyber refusal NEVER retries, rewords, or swaps models!
      if (turnStatus === "refused") {
        run.step_states[spec.stepId] = spec.optional ? "dropped" : "stopped";
        run.results[spec.stepId] = {
          step_id: spec.stepId,
          wave: spec.wave,
          profile: spec.profile,
          status: spec.optional ? "dropped" : "failed",
          reason_code: "cyber_refusal",
          attempts: attempt,
          usage: turnUsage,
          refusal: turnRefusal,
          diagnostic: turnDiagnostic,
          finished_at: new Date().toISOString(),
        };
        this.stateStore.saveRun(run);
        return;
      }

      if (turnStatus !== "completed") {
        run.step_states[spec.stepId] = spec.optional ? "dropped" : "stopped";
        run.results[spec.stepId] = {
          step_id: spec.stepId,
          wave: spec.wave,
          profile: spec.profile,
          status:
            turnStatus === "unknown"
              ? "unknown"
              : spec.optional
                ? "dropped"
                : "failed",
          reason_code: turnReasonCode ?? "step_execution_failed",
          attempts: attempt,
          usage: turnUsage,
          diagnostic: turnDiagnostic,
          finished_at: new Date().toISOString(),
        };
        this.stateStore.saveRun(run);
        return;
      }

      // Validate typed JSON handoff + strict ontology rules
      try {
        const validated = validateHandoff(turnOutputText, {
          caseId: run.case_id,
          stepId: spec.stepId,
          profile: spec.profile,
          snapshot: run.snapshot,
          predecessors: resolved.predecessors,
          ancestorClaims: resolved.ancestorClaims,
          suppliedSourceIds,
          handoffLimitBytes: stepHardCap,
        });

        // Host-side inline citation verification (`evt-*`, `frame-*`, `ioc-*`) on `incident` (and all stages!)
        const citationCheck = await verifyHandoffCitations(
          validated.handoff,
          dataPlane,
          params.signal,
        );
        this.telemetry.onCitationVerified?.(run.run_id, spec.stepId, citationCheck.receipt);

        if (citationCheck.status === "unknown") {
          run.step_states[spec.stepId] = "awaiting_review";
          run.results[spec.stepId] = {
            step_id: spec.stepId,
            wave: spec.wave,
            profile: spec.profile,
            status: "unknown",
            reason_code: "citation_source_unavailable",
            attempts: attempt,
            usage: turnUsage,
            diagnostic: citationCheck.errorMessage,
            finished_at: new Date().toISOString(),
          };
          this.stateStore.saveRun(run);
          return;
        }

        if (citationCheck.status === "failed") {
          throw new OntologyValidationError(
            citationCheck.errorMessage ?? "Citation verification failed",
          );
        }

        if (spec.stepId === "incident") {
          run.citation_receipt = citationCheck.receipt;
        }

        run.step_states[spec.stepId] =
          spec.stepId === "scope" || spec.stepId === "incident" ? "awaiting_review" : "done";
        run.results[spec.stepId] = {
          step_id: spec.stepId,
          wave: spec.wave,
          profile: spec.profile,
          status: "done",
          attempts: attempt,
          handoff: validated.handoff,
          canonical_json: validated.canonicalJson,
          usage: turnUsage,
          finished_at: new Date().toISOString(),
        };
        this.stateStore.saveRun(run);
        this.telemetry.emit(run.run_id, "step.completed", {
          step_id: spec.stepId,
          wave: spec.wave,
          attempts: attempt,
          claims: validated.handoff.claims.length,
        });
        return;
      } catch (validationErr) {
        const isOversize =
          validationErr instanceof OntologyValidationError && validationErr.isOversize;
        const diag =
          validationErr instanceof Error ? validationErr.message : String(validationErr);
        const reasonCode = diag.includes("citation verification failed")
          ? "citation_verification_failed"
          : isOversize
            ? "handoff_oversize"
            : "invalid_handoff";

        if (attempt === 1) {
          // Move Attempt 1 to `handoff_rejections[]` (retaining full token usage for budget accounting!)
          run.handoff_rejections.push({
            step_id: spec.stepId,
            execution_id: executionId,
            attempt: 1,
            reason_code: reasonCode,
            diagnostic: diag,
            raw_bytes: Buffer.byteLength(turnOutputText, "utf8"),
            usage: turnUsage,
            rejected_at: new Date().toISOString(),
          });
          this.stateStore.saveRun(run);

          // Check budget before dispatching `:retry`!
          try {
            const postRejLedger = computeRunTokenLedger(run);
            run.token_ledger = postRejLedger;
            if (postRejLedger.consumed_total_tokens >= postRejLedger.max_total_tokens) {
              run.step_states[spec.stepId] = "stopped";
              run.results[spec.stepId] = {
                step_id: spec.stepId,
                wave: spec.wave,
                profile: spec.profile,
                status: "failed",
                reason_code: "token_cap_exceeded",
                attempts: 1,
                usage: undefined,
                diagnostic: "Token budget reached after Attempt 1 handoff rejection",
                finished_at: new Date().toISOString(),
              };
              this.stateStore.saveRun(run);
              return;
            }
          } catch {
            run.step_states[spec.stepId] = "stopped";
            run.results[spec.stepId] = {
              step_id: spec.stepId,
              wave: spec.wave,
              profile: spec.profile,
              status: "failed",
              reason_code: "token_cap_exceeded",
              attempts: 1,
              diagnostic: "Missing integer total_tokens on rejected handoff attempt",
              finished_at: new Date().toISOString(),
            };
            this.stateStore.saveRun(run);
            return;
          }

          if (isOversize) {
            const halfCapTarget = Math.max(512, Math.floor(stepHardCap / 2));
            const retryResolved = this.resolveStepPredecessorsAndPrompt({
              run,
              spec,
              allWaves: params.allWaves,
              snapshotJson: params.snapshotJson,
              stepHardCap,
              targetBytes: halfCapTarget,
              suppliedSourceIds,
            });
            currentPromptBody =
              retryResolved.kind === "ready"
                ? `${retryResolved.promptBody}\n\nRETRY NOTICE: Your previous handoff exceeded the ${stepHardCap}B ceiling. Compress strictly below ${halfCapTarget} UTF-8 bytes!`
                : currentPromptBody;
          } else {
            currentPromptBody = `${resolved.promptBody}${WHOLE_CHECK_RETRY_SUFFIX}\nValidation error to fix: ${diag}`;
          }
          continue;
        }

        // Attempt 2 (`:retry`) also failed -> drop if optional, fail if required!
        run.step_states[spec.stepId] = spec.optional ? "dropped" : "stopped";
        run.results[spec.stepId] = {
          step_id: spec.stepId,
          wave: spec.wave,
          profile: spec.profile,
          status: spec.optional ? "dropped" : "failed",
          reason_code: reasonCode,
          attempts: attempt,
          usage: turnUsage,
          diagnostic: diag,
          finished_at: new Date().toISOString(),
        };
        this.stateStore.saveRun(run);
        return;
      }
    }
  }
}
