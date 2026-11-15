import {
  resolveEgressCardMode,
  type AuthenticatedGateDecision,
  type BillingMode,
  type CaseMetadata,
  type DataOrigin,
  type DataPlaneToolName,
  type EgressCardMode,
  type Handoff,
  type HuntToolName,
  type HuntWave,
  type ModelRefusalReport,
  type ProfileId,
} from "@hunt-command/shared";

/**
 * Cryptographically signed, closure-bound capability token for a single `(runId, stepId, profile)`.
 * Never serialized into tool schemas or accepted from model arguments.
 */
export interface RoleCapabilityToken {
  readonly runId: string;
  readonly stepId: string;
  readonly profile: ProfileId;
  readonly signatureHex: string;
}

export interface CaseCapabilities {
  readonly hasNetworkCapture: boolean;
  readonly hasIntelSource: boolean;
  readonly eventCount?: number;
  readonly sources: readonly string[];
}

export interface CitationVerificationRequest {
  readonly case_id: string;
  readonly event_ids: readonly string[];
  readonly frame_ids: readonly string[];
  readonly ioc_ids: readonly string[];
}

export interface CitationVerificationReceipt {
  readonly verified: boolean;
  readonly checked_at: string;
  readonly case_id: string;
  readonly total_checked: number;
  readonly missing_event_ids: string[];
  readonly missing_frame_ids: string[];
  readonly missing_ioc_ids: string[];
  readonly ambiguous_ids: string[];
  readonly out_of_scope_ids: string[];
  readonly source_status: "ok" | "unavailable";
  readonly diagnostic?: string;
}

export interface HuntDataPlanePort {
  readonly caseMetadata: CaseMetadata;
  capabilities(): Promise<CaseCapabilities> | CaseCapabilities;
  executeTool(
    capabilityToken: RoleCapabilityToken,
    toolName: DataPlaneToolName,
    params: Record<string, unknown>,
    signal?: AbortSignal,
  ): Promise<unknown>;
  verifyCitations(
    request: CitationVerificationRequest,
    signal?: AbortSignal,
  ): Promise<CitationVerificationReceipt>;
  /** Optional: the case-scoped records behind cited ids, for operator review (raw; caller scrubs). */
  readCitedRecords?(ids: readonly string[], signal?: AbortSignal): Promise<CitedEvidenceRecord[]>;
  close?(): Promise<void> | void;
}

export interface CitedEvidenceRecord {
  readonly id: string;
  readonly kind: "evt" | "frame" | "ioc";
  readonly timestamp_iso: string | null;
  readonly title: string;
  readonly record: Record<string, unknown>;
}

export interface StepTokenUsage {
  readonly input_tokens: number;
  readonly output_tokens: number;
  readonly cache_read_tokens: number;
  readonly cache_write_tokens: number;
  readonly total_tokens: number;
  readonly turns: number;
  readonly provider: string;
  readonly model: string;
  readonly billing_mode: BillingMode;
  readonly actual_billed_usd: number;
  readonly shadow_api_usd: number;
  readonly cache_savings_usd: number;
}

export type StepTurnStatus = "completed" | "failed" | "refused" | "cancelled" | "unknown";

export interface StepTurnResult {
  readonly status: StepTurnStatus;
  readonly reason_code?: string;
  readonly output_text: string;
  readonly usage?: StepTokenUsage;
  readonly refusal?: ModelRefusalReport;
  readonly diagnostic?: string;
}

export interface DelegateTaskContext {
  readonly onDelegatedUsage: (record: DelegatedStepRecord) => void;
  readonly checkBudgetBeforeDelegate: () => void;
}

export interface DelegatedStepRecord {
  readonly delegate_id: string;
  readonly parent_step_id: string;
  readonly specialist_profile: ProfileId;
  readonly question: string;
  readonly status: StepTurnStatus;
  readonly reason_code?: string;
  readonly usage?: StepTokenUsage;
  readonly created_at: string;
}

export interface ModelTurnRequest {
  readonly executionId: string;
  readonly runId: string;
  readonly caseId: string;
  readonly stepId: string;
  readonly wave: HuntWave;
  readonly profile: ProfileId;
  readonly syntheticOnly: boolean;
  readonly dataOrigin: DataOrigin;
  readonly userPromptBody: string;
  readonly stageGuidance?: string;
  readonly maxTurns: number;
  readonly isDelegatedChild?: boolean;
  readonly allowedToolsOverride?: readonly HuntToolName[];
  readonly dataPlane: HuntDataPlanePort;
  readonly telemetry: TelemetrySinkPort;
  readonly delegateContext?: DelegateTaskContext;
  readonly signal?: AbortSignal;
}

export interface ModelRunnerPort {
  preflightWave(providers: readonly string[], waveSessionKey: string, signal?: AbortSignal): Promise<void>;
  runTurn(request: ModelTurnRequest): Promise<StepTurnResult>;
  getPinnedModelForRole(profile: ProfileId): RoleModelPin;
}

export interface RoleModelPin {
  readonly provider: string;
  readonly model: string;
  readonly fallback_providers: readonly [];
}

export interface SanitizedGateCardPayload {
  readonly mode: EgressCardMode;
  readonly hunt_uuid: string;
  readonly wave: HuntWave;
  readonly gate_kind: string;
  readonly status_enum: string;
  readonly opened_at_utc: string;
  readonly reason_code: string | null;
  readonly payload_sha256: string;
  readonly expires_at_utc: string;
  readonly synthetic_summary?: {
    readonly case_id: string;
    readonly disposition?: string;
    readonly claim_count?: number;
    readonly limitation_count?: number;
  };
}

export interface GateCardInput {
  readonly huntId: string;
  readonly caseId: string;
  readonly wave: HuntWave;
  readonly gateKind: string;
  readonly statusEnum: string;
  readonly openedAtUtc: string;
  readonly expiresAtUtc: string;
  readonly payloadSha256: string;
  readonly reasonCode?: string | null;
  readonly syntheticOnly: boolean;
  readonly handoff?: Handoff | null;
}

export interface EgressGuardPort {
  sanitizeGateCard(input: GateCardInput): SanitizedGateCardPayload;
}

const ALLOWED_NON_SYNTHETIC_CARD_KEYS = new Set([
  "mode",
  "hunt_uuid",
  "wave",
  "gate_kind",
  "status_enum",
  "opened_at_utc",
  "reason_code",
  "payload_sha256",
  "expires_at_utc",
]);

/**
 * Rule 4 Egress Guard: when `syntheticOnly === false`, strips ALL case/telemetry/claim
 * content and enforces the strict ID-and-status allowlist on outbound notifications/cards.
 */
export class StrictEgressGuard implements EgressGuardPort {
  public sanitizeGateCard(input: GateCardInput): SanitizedGateCardPayload {
    const mode = resolveEgressCardMode(input.syntheticOnly);
    const base: SanitizedGateCardPayload = {
      mode,
      hunt_uuid: input.huntId,
      wave: input.wave,
      gate_kind: input.gateKind,
      status_enum: input.statusEnum,
      opened_at_utc: input.openedAtUtc,
      reason_code: input.reasonCode ?? null,
      payload_sha256: input.payloadSha256,
      expires_at_utc: input.expiresAtUtc,
    };

    if (!input.syntheticOnly) {
      for (const key of Object.keys(base)) {
        if (!ALLOWED_NON_SYNTHETIC_CARD_KEYS.has(key)) {
          throw new Error(`EgressGuard violation: forbidden non-synthetic key '${key}'`);
        }
      }
      return Object.freeze(base);
    }

    if (input.handoff) {
      return Object.freeze({
        ...base,
        synthetic_summary: Object.freeze({
          case_id: input.caseId,
          disposition: input.handoff.disposition,
          claim_count: input.handoff.claims.length,
          limitation_count: input.handoff.limitations.length,
        }),
      });
    }

    return Object.freeze(base);
  }
}

export interface DaemonTelemetryEvent {
  readonly runId: string;
  readonly seq: number;
  readonly ts: string;
  readonly type: string;
  readonly payload: Record<string, unknown>;
}

export interface TelemetrySinkPort {
  emit(runId: string, type: string, payload: Record<string, unknown>): void;
  onToolCall?(event: {
    runId: string;
    stepId: string;
    profile: ProfileId;
    toolName: HuntToolName;
    durationMs: number;
    isError: boolean;
    errorCode?: string;
    fencedBytes: number;
  }): void;
  onSafetyRefusal?(event: {
    runId: string;
    stepId: string;
    profile: ProfileId;
    provider: string;
    model: string;
    report: ModelRefusalReport;
  }): void;
  onGateDecision?(decision: AuthenticatedGateDecision): void;
  onCitationVerified?(runId: string, stepId: string, receipt: CitationVerificationReceipt): void;
  checkpoint?(): void;
}

export class NoopTelemetrySink implements TelemetrySinkPort {
  public emit(_runId: string, _type: string, _payload: Record<string, unknown>): void {}
}

export class InMemoryTelemetrySink implements TelemetrySinkPort {
  public readonly events: DaemonTelemetryEvent[] = [];
  public readonly toolCalls: Array<{
    runId: string;
    stepId: string;
    profile: ProfileId;
    toolName: HuntToolName;
    durationMs: number;
    isError: boolean;
    errorCode?: string;
    fencedBytes: number;
  }> = [];
  public readonly refusals: Array<{
    runId: string;
    stepId: string;
    profile: ProfileId;
    provider: string;
    model: string;
    report: ModelRefusalReport;
  }> = [];
  public readonly gateDecisions: AuthenticatedGateDecision[] = [];
  public readonly citationReceipts: Array<{
    runId: string;
    stepId: string;
    receipt: CitationVerificationReceipt;
  }> = [];
  private seqCounter = 0;
  private readonly listeners = new Set<(ev: DaemonTelemetryEvent) => void>();

  public subscribe(listener: (ev: DaemonTelemetryEvent) => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  public emit(runId: string, type: string, payload: Record<string, unknown>): void {
    const event: DaemonTelemetryEvent = {
      runId,
      seq: ++this.seqCounter,
      ts: new Date().toISOString(),
      type,
      payload,
    };
    this.events.push(event);
    for (const listener of this.listeners) {
      listener(event);
    }
  }

  public onToolCall(event: {
    runId: string;
    stepId: string;
    profile: ProfileId;
    toolName: HuntToolName;
    durationMs: number;
    isError: boolean;
    errorCode?: string;
    fencedBytes: number;
  }): void {
    this.toolCalls.push(event);
    this.emit(event.runId, "tool.call", { ...event });
  }

  public onSafetyRefusal(event: {
    runId: string;
    stepId: string;
    profile: ProfileId;
    provider: string;
    model: string;
    report: ModelRefusalReport;
  }): void {
    this.refusals.push(event);
    this.emit(event.runId, "hunt.safety.refusal", {
      step_id: event.stepId,
      profile: event.profile,
      provider: event.provider,
      model: event.model,
      "hunt.safety.category": event.report.category ?? "cyber",
      finish_reason: event.report.finish_reason ?? "content_filter",
      diagnostic: event.report.diagnostic ?? "",
    });
  }

  public onGateDecision(decision: AuthenticatedGateDecision): void {
    this.gateDecisions.push(decision);
    this.emit(decision.hunt_id, "gate.decided", {
      decision_id: decision.decision_id,
      gate: decision.gate,
      action: decision.action,
      via: decision.via,
      decided_by: decision.decided_by,
      rbac_role: decision.rbac_role,
      payload_sha256: decision.payload_sha256,
    });
  }

  public onCitationVerified(runId: string, stepId: string, receipt: CitationVerificationReceipt): void {
    this.citationReceipts.push({ runId, stepId, receipt });
    this.emit(runId, "citations.verified", {
      step_id: stepId,
      verified: receipt.verified,
      total_checked: receipt.total_checked,
      source_status: receipt.source_status,
    });
  }

  public checkpoint(): void {}
}
