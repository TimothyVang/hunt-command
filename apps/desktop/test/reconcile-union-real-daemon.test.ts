import { afterAll, describe, expect, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { Handoff, ProfileId } from "@hunt-command/shared";
import {
  createCaseDirDataPlaneResolver,
  runHuntCli,
  type HuntDataPlanePort,
  type ModelRunnerPort,
  type ModelTurnRequest,
  type PersistedHuntRun,
  type StepTurnResult,
} from "../../../packages/daemon/src/index.ts";
import { projectLiveGate } from "../src/main/live-gate-context.ts";
import { missingGateContextReason, validateGateSubmission } from "../src/shared/gate-validation.ts";

/**
 * The daemon's real `serve` opens a citation_source_unavailable reconcile gate (the citation source reports
 * itself unavailable), and the desktop projection must render that context and keep the gate approvable,
 * whether the source is back (records readable) or still down.
 */
const CASE_ID = "desk-csu-001";
const dirs: string[] = [];
const tmp = (p: string) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), p));
  dirs.push(d);
  return d;
};
afterAll(() => {
  for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
});

const casesDir = tmp("desk-csu-cases-");
fs.mkdirSync(path.join(casesDir, CASE_ID));
fs.writeFileSync(path.join(casesDir, CASE_ID, "case.json"), JSON.stringify({
  case_id: CASE_ID, question: "Which host ran it?", data_origin: "synthetic",
  time_range_utc: { start_inclusive: "2026-11-14T10:00:00Z", end_exclusive: "2026-11-14T11:00:00Z" },
}));
fs.writeFileSync(path.join(casesDir, CASE_ID, "events.jsonl"), [
  { "@timestamp": "2026-11-14T10:01:00Z", event: { id: "evt-dc-1", code: "1" }, host: { name: "desk-host-01" }, message: "Process start." },
  { "@timestamp": "2026-11-14T10:02:00Z", event: { id: "evt-dc-2", code: "2" }, host: { name: "desk-host-02" }, message: "Beacon." },
].map((e) => JSON.stringify(e)).join("\n") + "\n");

const handoff = (stepId: string, profile: ProfileId): Handoff => ({
  schema_version: 1, case_id: CASE_ID, step_id: stepId, profile,
  claims: [{ claim_id: `${stepId}:c1`, kind: "observed", statement: "Start (evt-dc-1) then beacon (evt-dc-2).", evidence_ids: ["events.jsonl"], entity_ids: [], contradicts: [] }],
  reviews: [], disposition: "review_ready", limitations: [], requested_decisions: [],
} as unknown as Handoff);

const runner: ModelRunnerPort = {
  getPinnedModelForRole: () => ({ provider: "stub", model: "stub", fallback_providers: [] }),
  preflightWave: async () => {},
  runTurn: async (req: ModelTurnRequest): Promise<StepTurnResult> => ({
    status: "completed",
    output_text: JSON.stringify(handoff(req.stepId, req.profile)),
    usage: { input_tokens: 1, output_tokens: 1, cache_read_tokens: 0, cache_write_tokens: 0, total_tokens: 2, turns: 1, provider: "stub", model: "stub", billing_mode: "oauth_subscription", actual_billed_usd: 0, shadow_api_usd: 0, cache_savings_usd: 0 },
  }),
};

async function* linesOf(...lines: string[]): AsyncGenerator<string> {
  for (const l of lines) yield `${l}\n`;
}
const rpc = (id: string, method: string, params: unknown) => JSON.stringify({ jsonrpc: "2.0", id, method, params });

async function serve(runtimeDir: string, plane: HuntDataPlanePort, ...lines: string[]) {
  const out: string[] = [];
  const code = await runHuntCli(["serve", "--runtime-dir", runtimeDir], { writeStdout: (t) => void out.push(t), writeStderr: () => {} }, {
    modelRunner: runner, resolveDataPlane: () => plane, stdin: linesOf(...lines),
  });
  expect(code).toBe(0);
  return out.join("").trim().split("\n").map((l) => JSON.parse(l) as { id?: string; result?: any; error?: unknown }).filter((l) => l.id);
}

describe("desktop renders the daemon's real citation_source_unavailable reconcile context", () => {
  for (const readable of [true, false]) {
    test(`source ${readable ? "back" : "still down"}`, async () => {
      const resolver = createCaseDirDataPlaneResolver({ casesDir, cacheDir: tmp("desk-csu-cache-") });
      const real = await resolver.resolve(CASE_ID);
      let sourceBack = false;
      const plane: HuntDataPlanePort = {
        caseMetadata: real.caseMetadata,
        capabilities: () => real.capabilities(),
        executeTool: (...a) => real.executeTool(...a),
        // The source is down while the gate opens; for the context it is back (real verification) or still down.
        verifyCitations: async (r) => sourceBack ? real.verifyCitations(r) : ({
          verified: false, checked_at: new Date().toISOString(), case_id: r.case_id, total_checked: 0,
          missing_event_ids: [], missing_frame_ids: [], missing_ioc_ids: [], ambiguous_ids: [], out_of_scope_ids: [],
          source_status: "unavailable", diagnostic: "events index offline",
        }),
        readCitedRecords: readable ? (ids, signal) => real.readCitedRecords!(ids, signal) : async () => { throw new Error("events index offline"); },
      };
      try {
        const runtimeDir = tmp("desk-csu-rt-");
        const [started] = await serve(runtimeDir, plane, rpc("s", "hunt.start", { run_id: "hunt-dcsu", case_id: CASE_ID, scope: "Scope.", follow_ups: 0 }));
        const run = started!.result as PersistedHuntRun;
        expect(run.open_gate?.gate).toBe("reconcile");
        sourceBack = readable;
        const [ctx] = await serve(runtimeDir, plane, rpc("g", "hunt.gateContext", { run_id: "hunt-dcsu" }));
        expect(ctx!.error).toBeUndefined();

        // hunt.status types `gate` as string; the service narrows it with zod, here we assert it.
        const openGate = { ...run.open_gate!, gate: run.open_gate!.gate as "reconcile" };
        // The workbench passes the affected step's unverified handoff, as WorkbenchService does.
        const unknownStepId = run.open_gate?.unknown_step_id;
        const reconcileHandoff = unknownStepId
          ? (run.results[unknownStepId]?.unverified_handoff as Parameters<typeof projectLiveGate>[5])
          : undefined;
        expect(reconcileHandoff?.step_id).toBe(unknownStepId);
        const p = projectLiveGate(
          run.run_id,
          openGate,
          Object.values(run.reviewed_handoffs),
          ctx!.result,
          run.config.scopeText,
          reconcileHandoff,
        );
        expect(p.activeGate.contextError).toBeUndefined();
        const rc = p.activeGate.reconcileContext!;
        expect(rc.reasonCode).toBe("citation_source_unavailable");
        if (rc.reasonCode !== "citation_source_unavailable") throw new Error("narrowing");
        if (readable) {
          expect(rc.unavailableSources).toEqual([]);
          expect(rc.citationReceipt.entries.map((e) => [e.citationId, e.status])).toEqual([["evt-dc-1", "verified"], ["evt-dc-2", "verified"]]);
          expect(p.evidenceCatalog["evt-dc-1"]?.fields["host.name"]).toBe("desk-host-01");
        } else {
          expect(rc.unavailableSources).toEqual(["events"]);
        }
        const approve = validateGateSubmission(p.activeGate, {
          operatorName: "a", rbacRole: "lead_hunter", checkNote: "Checked the source status.", payloadSha256: run.open_gate!.payload_sha256, action: "approve",
        });
        if (rc.affectedStep) {
          // F17: the daemon named the step, so the card can state the outcome and approval is allowed.
          expect(rc.affectedStep.stepId).toBe(String(unknownStepId));
          expect(missingGateContextReason(p.activeGate)).toBeNull();
          expect(approve.valid).toBe(true);
        } else {
          // F17: without the daemon's affected_step the outcome cannot be stated, so approval stays disabled.
          expect(String(missingGateContextReason(p.activeGate))).toContain("could not be identified");
          expect(approve.valid).toBe(false);
        }
      } finally {
        await resolver.close();
      }
    }, 60_000);
  }
});
