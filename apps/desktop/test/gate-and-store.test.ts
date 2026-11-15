import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, test } from "bun:test";
import { resolveRuntimeDir } from "@hunt-command/shared";
import { HuntDaemonSidecar } from "../src/main/daemon/daemon-sidecar.ts";
import { createLogger } from "../src/main/logger.ts";
import { SecretVault } from "../src/main/secret-vault.ts";
import { WorkbenchService } from "../src/main/workbench-service.ts";
import { WorkbenchStore } from "../src/renderer/src/state/workbench-store.ts";
import { buildFixtureWorkbenchSnapshot } from "../src/shared/fixture-workbench.ts";
import { validateGateSubmission } from "../src/shared/gate-validation.ts";

describe("Tamper-Evident Human Gate Cards & <16ms Cross-Pane Store (#189 Deliverable 2)", () => {
  test("Gate 2 Incident hard-blocks Approve when any inline citation in claims or limitations is unresolved", () => {
    const cleanSnap = buildFixtureWorkbenchSnapshot({
      openGate: "incident",
      injectUnresolvedCitation: false,
    });
    expect(cleanSnap.citationReceipt.allVerified).toBe(true);

    const unresolvedSnap = buildFixtureWorkbenchSnapshot({
      openGate: "incident",
      injectUnresolvedCitation: true,
    });
    expect(unresolvedSnap.citationReceipt.allVerified).toBe(false);
    expect(unresolvedSnap.citationReceipt.unresolvedCount).toBe(1);

    const gate = unresolvedSnap.activeGate!;
    const approveOutcome = validateGateSubmission(gate, {
      operatorName: "analyst.kim",
      rbacRole: "incident_commander",
      checkNote: "Checked all claims; attempting to approve despite evt-9999999999999999.",
      payloadSha256: gate.payloadSha256,
      action: "approve",
    });
    expect(approveOutcome.valid).toBe(false);
    expect(approveOutcome.errors.join(" ")).toMatch(/Gate 2 Incident approval blocked/);

    // Reject MUST remain allowed so the operator can reject a hallucinated incident report!
    const rejectOutcome = validateGateSubmission(gate, {
      operatorName: "analyst.kim",
      rbacRole: "incident_commander",
      checkNote: "Rejecting due to unresolved evt-9999999999999999 citation.",
      payloadSha256: gate.payloadSha256,
      action: "reject",
    });
    expect(rejectOutcome.valid).toBe(true);
  });

  test("WorkbenchStore clears 'What did you check?' note between Gate 1 (Scope) and Gate 2 (Incident)", () => {
    const scopeSnap = buildFixtureWorkbenchSnapshot({
      huntId: "hunt-gate-seq",
      openGate: "scope",
    });
    const store = new WorkbenchStore(scopeSnap);

    store.updateActiveGateDraft({
      operatorName: "analyst.patel",
      rbacRole: "lead_hunter",
      checkNote: "Checked scope time bounds and synthetic data_origin.",
    });
    expect(store.getActiveGateDraft().checkNote).toBe(
      "Checked scope time bounds and synthetic data_origin.",
    );

    // Transition to Gate 2 Incident -> checkNote MUST be cleared to ""!
    const incidentSnap = buildFixtureWorkbenchSnapshot({
      huntId: "hunt-gate-seq",
      openGate: "incident",
    });
    store.setWorkbenchSnapshot(incidentSnap);

    const gate2Draft = store.getActiveGateDraft();
    expect(gate2Draft.operatorName).toBe("analyst.patel");
    expect(gate2Draft.checkNote).toBe("");
  });

  test("WorkbenchStore cross-highlights timeline, graph, and raw record in <16ms", () => {
    const snap = buildFixtureWorkbenchSnapshot({ openGate: "incident" });
    const store = new WorkbenchStore(snap);

    const elapsedMs = store.selectProvenanceBadge("frame-188");
    expect(elapsedMs).toBeLessThan(16);

    const state = store.getState();
    expect(state.selectedCitationId).toBe("frame-188");
    expect(state.selectedEvidenceId).toBe("frame-188");
    expect(state.dissectorTab).toBe("packets");
    expect(state.selectedClaimId).toBe("network:c1");
    expect(state.selectedEntityId).toBe("host:wks-fin-07");
  });

  test("WorkbenchService persists authenticated Gate 1 -> Gate 2 decisions to decisions.jsonl and supports Global Stop", async () => {
    const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hunt-wb-svc-"));
    try {
      const repoRoot = path.resolve(import.meta.dir, "../../..");
      const runtimePaths = resolveRuntimeDir(path.join(tmpRoot, "runtime"), { repoRoot });
      const log = createLogger(path.join(tmpRoot, "logs"));
      const sidecar = new HuntDaemonSidecar({
        resolveLaunch: () => ({
          available: false,
          command: "",
          args: [],
          piNativesDir: null,
          source: "unavailable",
        }),
        runtimeRootDir: runtimePaths.rootDir,
        log,
      });
      sidecar.start();

      const vault = new SecretVault(path.join(tmpRoot, "vault"), {
        isEncryptionAvailable: () => true,
        encryptString: (s) => Buffer.from(s, "utf8"),
        decryptString: (b) => b.toString("utf8"),
      });

      const svc = new WorkbenchService({ runtimePaths, sidecar, vault });
      const scopeState = await svc.getWorkbenchState({ huntId: "hunt-20261115-scope-work" });
      expect(scopeState.activeGate?.gate).toBe("scope");

      // Stale SHA-256 digest must be rejected
      await expect(
        svc.submitGateDecision({
          huntId: scopeState.huntId,
          gate: "scope",
          action: "approve",
          operatorName: "analyst.lee",
          rbacRole: "soc_lead",
          checkNote: "Checked work-export scope.",
          payloadSha256: "0".repeat(64),
        }),
      ).rejects.toThrow(/SHA-256/);

      // Valid Gate 1 approval advances to Gate 2 and appends to decisions.jsonl
      const afterScope = await svc.submitGateDecision({
        huntId: scopeState.huntId,
        gate: "scope",
        action: "approve",
        operatorName: "analyst.lee\u202E",
        rbacRole: "soc_lead",
        checkNote: "Checked work-export host bounds and Rule 4 notice.",
        payloadSha256: scopeState.activeGate!.payloadSha256,
      });
      expect(afterScope.activeGate?.gate).toBe("incident");
      expect(fs.existsSync(runtimePaths.decisionsLogPath)).toBe(true);
      const decisionLine = JSON.parse(
        fs.readFileSync(runtimePaths.decisionsLogPath, "utf8").trim(),
      ) as { decided_by: string; via: string; gate: string };
      expect(decisionLine.decided_by).toBe("analyst.lee");
      expect(decisionLine.via).toBe("desktop");
      expect(decisionLine.gate).toBe("scope");

      // Global Stop halts the run immediately
      const stopped = await svc.globalStop({
        huntId: scopeState.huntId,
        reason: "operator_global_stop",
      });
      expect(stopped.runStatus).toBe("stopped");
      expect(stopped.activeGate).toBeNull();
    } finally {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    }
  });
});
