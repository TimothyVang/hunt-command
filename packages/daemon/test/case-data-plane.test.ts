import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import type { ProfileId } from "@hunt-command/shared";
import { EmbeddedHuntDataPlane } from "@hunt-command/data-plane";
import {
  CaseDataPlanePort,
  DurableStateStore,
  GateAuthority,
  HuntWaveEngine,
  RoleCapabilityAuthority,
  createCaseDirDataPlaneResolver,
  runHuntCli,
  type ModelRunnerPort,
  type ModelTurnRequest,
  type PersistedHuntRun,
  type RoleModelPin,
  type StepTurnResult,
} from "../src/index.ts";

const CASE_ID = "port-case-001";
const EVENT_IDS = ["evt-port-1", "evt-port-2", "evt-port-3"];
const tempDirs: string[] = [];
let casesDir: string;

function makeTmpDir(prefix: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

beforeAll(() => {
  // Synthetic case pack in the OS temp dir (never inside the Git checkout).
  casesDir = makeTmpDir("hunt-port-cases-");
  const caseDir = path.join(casesDir, CASE_ID);
  fs.mkdirSync(caseDir);
  fs.writeFileSync(
    path.join(caseDir, "case.json"),
    JSON.stringify({
      case_id: CASE_ID,
      question: "Which synthetic host ran the scripted process?",
      data_origin: "synthetic",
      time_range_utc: { start_inclusive: "2026-11-14T10:00:00Z", end_exclusive: "2026-11-14T11:00:00Z" },
    }),
  );
  fs.writeFileSync(
    path.join(caseDir, "events.jsonl"),
    EVENT_IDS.map((id, i) =>
      JSON.stringify({
        "@timestamp": `2026-11-14T10:0${i + 1}:00Z`,
        event: { id, code: String(i + 1) },
        host: { name: `workstation-0${i + 1}` },
        message: `synthetic event ${i + 1}`,
      }),
    ).join("\n") + "\n",
  );
});

afterAll(() => {
  for (const dir of tempDirs) fs.rmSync(dir, { recursive: true, force: true });
});

function captureIo() {
  const out: string[] = [];
  const err: string[] = [];
  return { out, err, io: { writeStdout: (t: string) => void out.push(t), writeStderr: (t: string) => void err.push(t) } };
}

async function* linesOf(...lines: string[]): AsyncGenerator<string> {
  for (const line of lines) yield `${line}\n`;
}

/** Model runner that searches the bound case once, then stops the step (no model call). */
class SearchOnceRunner implements ModelRunnerPort {
  public readonly seen: Array<{ caseId: string; sources: readonly string[]; total: number }> = [];
  readonly #authority = new RoleCapabilityAuthority();

  public getPinnedModelForRole(_profile: ProfileId): RoleModelPin {
    return { provider: "stub", model: "stub-model", fallback_providers: [] };
  }

  public async preflightWave(): Promise<void> {}

  public async runTurn(request: ModelTurnRequest): Promise<StepTurnResult> {
    const token = this.#authority.mint(request.runId, request.stepId, request.profile);
    const result = (await request.dataPlane.executeTool(token, "elastic_search", { q: "" })) as { total: number };
    this.seen.push({ caseId: request.caseId, sources: request.dataPlane.caseMetadata.sources, total: result.total });
    return { status: "failed", reason_code: "stub_stop", output_text: "", diagnostic: "stub runner stops here" };
  }
}

describe("default serve data plane", () => {
  test("serve with no injected factory resolves <cases-dir>/<caseId> and runs hunt.start against it", async () => {
    const runtimeDir = makeTmpDir("hunt-port-rt-");
    const runner = new SearchOnceRunner();
    const c = captureIo();
    const code = await runHuntCli(["serve", "--runtime-dir", runtimeDir, "--cases-dir", casesDir], c.io, {
      modelRunner: runner,
      stdin: linesOf(
        JSON.stringify({ jsonrpc: "2.0", id: "s1", method: "hunt.start", params: { case_id: CASE_ID, scope: "Synthetic scope." } }),
        JSON.stringify({ jsonrpc: "2.0", id: "s2", method: "hunt.start", params: { case_id: "missing-case", scope: "x" } }),
      ),
    });
    expect(code).toBe(0);
    const responses = c.out
      .join("")
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l) as { id?: string; result?: PersistedHuntRun; error?: { error_code: string } });
    const started = responses.find((r) => r.id === "s1")!;
    expect(started.error).toBeUndefined();
    expect(started.result!.case_id).toBe(CASE_ID);
    expect(started.result!.data_origin).toBe("synthetic");
    expect(runner.seen[0]).toEqual({ caseId: CASE_ID, sources: ["events.jsonl"], total: EVENT_IDS.length });
    expect(responses.find((r) => r.id === "s2")!.error!.error_code).toBe("not_found");
  });

  test("defaults the cases dir to <runtimeDir>/cases", async () => {
    const runtimeDir = makeTmpDir("hunt-port-rt-");
    fs.cpSync(path.join(casesDir, CASE_ID), path.join(runtimeDir, "cases", CASE_ID), { recursive: true });
    const runner = new SearchOnceRunner();
    const c = captureIo();
    expect(
      await runHuntCli(["serve", "--runtime-dir", runtimeDir], c.io, {
        modelRunner: runner,
        stdin: linesOf(
          JSON.stringify({ jsonrpc: "2.0", id: "s1", method: "hunt.start", params: { case_id: CASE_ID, scope: "Synthetic scope." } }),
        ),
      }),
    ).toBe(0);
    expect(runner.seen[0]?.total).toBe(EVENT_IDS.length);
  });

  test("refuses case ids that could escape the cases dir", async () => {
    const resolver = createCaseDirDataPlaneResolver({ casesDir, cacheDir: makeTmpDir("hunt-port-cache-") });
    try {
      for (const bad of ["../etc", "..", "a/b", "UPPER-case"]) {
        await expect(Promise.resolve().then(() => resolver.resolve(bad))).rejects.toMatchObject({
          errorCode: "explicit_case_id_required",
        });
      }
    } finally {
      await resolver.close();
    }
  });

  test("rejects a case pack whose identity differs from the requested directory and retries after repair", async () => {
    const root = makeTmpDir("hunt-port-mismatch-");
    const requested = "requested-case";
    const caseDir = path.join(root, requested);
    fs.cpSync(path.join(casesDir, CASE_ID), caseDir, { recursive: true });
    const resolver = createCaseDirDataPlaneResolver({ casesDir: root, cacheDir: makeTmpDir("hunt-port-cache-") });
    try {
      for (let i = 0; i < 2; i++) {
        await expect(Promise.resolve().then(() => resolver.resolve(requested))).rejects.toMatchObject({
          errorCode: "case_mismatch",
        });
      }
      const caseJson = path.join(caseDir, "case.json");
      const metadata = JSON.parse(fs.readFileSync(caseJson, "utf8"));
      fs.writeFileSync(caseJson, JSON.stringify({ ...metadata, case_id: requested }));
      const port = await resolver.resolve(requested);
      expect(port.caseMetadata.case_id).toBe(requested);
    } finally {
      await resolver.close();
    }
  });

  test("gate resume rejects a replaced case pack without recording the decision", async () => {
    const root = makeTmpDir("hunt-port-resume-");
    const caseDir = path.join(root, CASE_ID);
    fs.cpSync(path.join(casesDir, CASE_ID), caseDir, { recursive: true });
    const cacheDir = makeTmpDir("hunt-port-cache-");
    const dbPath = path.join(root, "state.sqlite");
    const decisionsDir = path.join(root, "decisions");
    const runner: ModelRunnerPort = {
      getPinnedModelForRole: () => ({ provider: "stub", model: "stub-model", fallback_providers: [] }),
      preflightWave: async () => {},
      runTurn: async (req) => ({
        status: "completed",
        output_text: JSON.stringify({
          schema_version: 1,
          case_id: req.caseId,
          step_id: req.stepId,
          profile: req.profile,
          claims: [{
            claim_id: `${req.stepId}:c1`,
            kind: "observed",
            statement: "Synthetic event observed.",
            evidence_ids: ["events.jsonl"],
            entity_ids: [],
            contradicts: [],
          }],
          reviews: [],
          disposition: "review_ready",
          limitations: [],
          requested_decisions: [],
        }),
        usage: {
          input_tokens: 100,
          output_tokens: 50,
          cache_read_tokens: 0,
          cache_write_tokens: 0,
          total_tokens: 150,
          turns: 1,
          provider: "stub",
          model: "stub-model",
          billing_mode: "oauth_subscription",
          actual_billed_usd: 0,
          shadow_api_usd: 0,
          cache_savings_usd: 0,
        },
      }),
    };
    const firstResolver = createCaseDirDataPlaneResolver({ casesDir: root, cacheDir });
    const firstStore = new DurableStateStore(dbPath);
    const firstGates = new GateAuthority({ stateStore: firstStore, decisionsDir });
    const firstEngine = new HuntWaveEngine({ stateStore: firstStore, gateAuthority: firstGates, modelRunner: runner });
    let parked: PersistedHuntRun;
    try {
      parked = await firstEngine.startHunt({
        runId: "hunt-case-mismatch",
        scopeText: "Synthetic scope.",
        dataPlane: await firstResolver.resolve(CASE_ID),
        followUps: 0,
      });
      expect(parked.open_gate?.gate).toBe("scope");
    } finally {
      firstStore.close();
      await firstResolver.close();
    }
    const sessionAuthority = firstGates.sessionAuthority;

    const caseJson = path.join(caseDir, "case.json");
    const metadata = JSON.parse(fs.readFileSync(caseJson, "utf8"));
    fs.writeFileSync(caseJson, JSON.stringify({ ...metadata, case_id: "different-case" }));
    const resolver = createCaseDirDataPlaneResolver({ casesDir: root, cacheDir });
    const store = new DurableStateStore(dbPath);
    const gates = new GateAuthority({ stateStore: store, decisionsDir, sessionAuthority });
    const engine = new HuntWaveEngine({ stateStore: store, gateAuthority: gates, modelRunner: runner, resolveDataPlane: resolver.resolve });
    try {
      await expect(engine.submitGateDecision({
        decisionId: "decision-case-mismatch",
        huntId: "hunt-case-mismatch",
        gate: "scope",
        action: "approve",
        via: "cli",
        operatorToken: sessionAuthority.issueToken("alice", "analyst"),
        payloadSha256: parked.open_gate!.payload_sha256,
        checkNote: "Scope verified.",
      })).rejects.toMatchObject({ errorCode: "case_mismatch" });
      const untouched = store.getRun("hunt-case-mismatch")!;
      expect(untouched.status).toBe("awaiting_gate");
      expect(untouched.open_gate?.gate).toBe("scope");
      expect(untouched.decisions).toHaveLength(0);
      expect(fs.existsSync(gates.decisionsLogPath)).toBe(false);
    } finally {
      store.close();
      await resolver.close();
    }
  });
});

describe("CaseDataPlanePort", () => {
  let dp: EmbeddedHuntDataPlane;
  let port: CaseDataPlanePort;
  const authority = new RoleCapabilityAuthority();

  beforeAll(async () => {
    dp = await EmbeddedHuntDataPlane.open(path.join(casesDir, CASE_ID), { cacheDir: makeTmpDir("hunt-port-cache-") });
    port = new CaseDataPlanePort(dp, dp.describeCase());
  });
  afterAll(async () => {
    await port.close();
  });

  test("describes the case with the shared CaseMetadata contract", async () => {
    expect(port.caseMetadata).toEqual({
      case_id: CASE_ID,
      title: "Which synthetic host ran the scripted process?",
      data_origin: "synthetic",
      synthetic_only: true,
      time_window: { start_iso: "2026-11-14T10:00:00Z", end_iso: "2026-11-14T11:00:00Z" },
      sources: ["events.jsonl"],
    });
    expect(await port.capabilities()).toEqual({
      hasNetworkCapture: false,
      hasIntelSource: false,
      eventCount: EVENT_IDS.length,
      sources: ["events.jsonl"],
    });
  });

  test("executes data-plane tools and rejects another case's id", async () => {
    const token = authority.mint("run-1", "evidence", "framework-researcher");
    const hits = (await port.executeTool(token, "elastic_search", { q: "host.name:workstation-*" })) as { total: number };
    expect(hits.total).toBe(EVENT_IDS.length);
    await expect(port.executeTool(token, "elastic_search", { case_id: "other-case", q: "" })).rejects.toMatchObject({
      errorCode: "case_mismatch",
    });
  });

  test("checks Watch page tools against the calling role", async () => {
    const researcher = authority.mint("run-1", "evidence", "framework-researcher");
    await expect(port.executeTool(researcher, "lab_browser", { page: "arkime_sessions" })).rejects.toThrow(/does not own tool/);
  });

  test("verifies citations into a receipt that names the missing ids", async () => {
    const ok = await port.verifyCitations({ case_id: CASE_ID, event_ids: EVENT_IDS, frame_ids: [], ioc_ids: [] });
    expect(ok).toMatchObject({ verified: true, total_checked: 3, missing_event_ids: [], source_status: "ok" });

    const bad = await port.verifyCitations({
      case_id: CASE_ID,
      event_ids: ["evt-port-1", "evt-port-404"],
      frame_ids: ["frame-7"],
      ioc_ids: ["ioc-none"],
    });
    expect(bad).toMatchObject({
      verified: false,
      missing_event_ids: ["evt-port-404"],
      missing_frame_ids: ["frame-7"],
      missing_ioc_ids: ["ioc-none"],
      source_status: "ok",
    });

    const foreign = await port.verifyCitations({ case_id: "other-case", event_ids: ["evt-port-1"], frame_ids: [], ioc_ids: [] });
    expect(foreign).toMatchObject({ verified: false, out_of_scope_ids: ["evt-port-1"] });
  });
});
