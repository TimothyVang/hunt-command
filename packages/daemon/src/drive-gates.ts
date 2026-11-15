import { requiresHumanDecision } from "@hunt-command/shared";
import { GateDecisionError, type RbacRole } from "./gates.ts";
import type { PersistedHuntRun } from "./state-store.ts";
import type { HuntWaveEngine } from "./wave-engine.ts";

export interface DriveGatesCommandInput {
  readonly action: "status" | "approve" | "reject" | "deny";
  readonly huntId: string;
  readonly gate?: string;
  readonly operator?: string;
  readonly rbacRole?: RbacRole;
  readonly operatorToken?: string;
  readonly checkNote?: string;
  readonly payloadSha256?: string;
  readonly decisionId?: string;
  /**
   * Non-prod delegated mode: ONLY allowed for intermediate non-human wave gates,
   * NEVER allowed for `scope`, `incident`, or `reconcile` in production!
   */
  readonly automated?: boolean;
  readonly delegatedBy?: string;
  readonly delegationReason?: string;
}

export interface DriveGatesCommandResult {
  readonly ok: boolean;
  readonly hunt_id: string;
  readonly status: string;
  readonly wave: string;
  readonly open_gate: PersistedHuntRun["open_gate"];
  readonly decisions_count: number;
  readonly error_code?: string;
  readonly message?: string;
}

/**
 * Programmatic and CLI `drive_gates` controller (`ADR 0002` / `operator/drive_gates.py` port):
 * Supports `status`, `approve`, and `reject`/`deny`.
 * Enforces that human gates (`scope`, `incident`, `reconcile`) NEVER run under `automated`
 * (or `delegatedBy` in production).
 */
export async function executeDriveGates(
  engine: HuntWaveEngine,
  input: DriveGatesCommandInput,
): Promise<DriveGatesCommandResult> {
  const run = engine.stateStore.getRun(input.huntId);
  if (!run) {
    return {
      ok: false,
      hunt_id: input.huntId,
      status: "not_found",
      wave: "scope",
      open_gate: null,
      decisions_count: 0,
      error_code: "hunt_not_found",
      message: `Unknown hunt '${input.huntId}'`,
    };
  }

  if (input.action === "status") {
    return {
      ok: true,
      hunt_id: run.run_id,
      status: run.status,
      wave: run.wave,
      open_gate: run.open_gate,
      decisions_count: run.decisions.length,
    };
  }

  if (!run.open_gate) {
    return {
      ok: false,
      hunt_id: run.run_id,
      status: run.status,
      wave: run.wave,
      open_gate: null,
      decisions_count: run.decisions.length,
      error_code: "gate_not_open",
      message: `Hunt '${run.run_id}' has no open gate (status='${run.status}')`,
    };
  }

  const targetGate = input.gate ?? run.open_gate.gate;
  const normalizedAction = input.action === "approve" ? "approve" : "reject";
  const isHuman = requiresHumanDecision(targetGate);

  if (input.automated && isHuman) {
    throw new GateDecisionError(
      "automated_channel_forbidden",
      `drive_gates automated mode is forbidden on human gate '${targetGate}'`,
    );
  }

  if (input.delegatedBy) {
    if (!input.delegationReason?.trim()) {
      throw new GateDecisionError(
        "invalid_gate_decision",
        "delegationReason is required when delegatedBy is set",
      );
    }
    if (isHuman && engine.gateAuthority.productionMode) {
      throw new GateDecisionError(
        "automated_channel_forbidden",
        `Delegated automated mode cannot be used on human gate '${targetGate}' in production`,
      );
    }
  }

  const updated = await engine.submitGateDecision({
    decisionId: input.decisionId,
    huntId: run.run_id,
    gate: targetGate,
    action: normalizedAction,
    via: input.automated ? "automated" : "cli",
    authenticatedPrincipal: input.operator ?? input.delegatedBy,
    rbacRole: input.rbacRole ?? "analyst",
    operatorToken: input.operatorToken,
    payloadSha256: input.payloadSha256 ?? run.open_gate.payload_sha256,
    checkNote: input.checkNote,
    delegatedBy: input.delegatedBy,
    delegationReason: input.delegationReason,
  });

  return {
    ok: true,
    hunt_id: updated.run_id,
    status: updated.status,
    wave: updated.wave,
    open_gate: updated.open_gate,
    decisions_count: updated.decisions.length,
  };
}
