import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import type { Handoff, ProfileId } from "@hunt-command/shared";
import {
  GATE_CONTEXT_MAX_EVIDENCE,
  GateContextError,
  buildGateContext,
  runHuntCli,
  type CitationVerificationReceipt,
  type HuntDataPlanePort,
  type ModelRunnerPort,
  type ModelTurnRequest,
  type PersistedHuntRun,
  type StepTurnResult,
} from "../src/index.ts";

const CASE_ID = "gate-ctx-001";
const LEAK = "GATECTXLEAK";
const tempDirs: string[] = [];
let casesDir: string;
let runtimeDir: string;

function makeTmpDir(prefix: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

afterAll(() => {
  for (const dir of tempDirs) fs.rmSync(dir, { recursive: true, force: true });
});

const wideEvent: Record<string, unknown> = {};
for (let i = 0; i < 100; i++) wideEvent[`f${String(i).padStart(3, "0")}`] = `v${i}`;

beforeAll(() => {
  casesDir = makeTmpDir("hunt-gatectx-cases-");
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
  const events = [
    {
      "@timestamp": "2026-11-14T10:01:00Z",
      event: { id: "evt-gc-1", code: "1", action: "process-start" },
      host: { name: "workstation-01" },
      message: `powershell launched {"body":"{\\"password\\":\\"${LEAK}\\"}"}`,
      long: "x".repeat(5_000),
    },
    { "@timestamp": "2026-11-14T10:02:00Z", event: { id: "evt-gc-2", code: "2" }, host: { name: "workstation-02" }, ...wideEvent },
  ];
  fs.writeFileSync(path.join(caseDir, "events.jsonl"), events.map((e) => JSON.stringify(e)).join("\n") + "\n");
});

function handoff(stepId: string, profile: ProfileId): Handoff {
  return {
    schema_version: 1,
    case_id: CASE_ID,
    step_id: stepId,
    profile,
    claims: [
      {
        claim_id: `${stepId}:c1`,
        kind: stepId === "incident" ? "finding" : "observed",
        statement: "Process start on workstation-01 (evt-gc-1) and a follow-up on workstation-02 (evt-gc-2).",
        evidence_ids: ["events.jsonl"],
        entity_ids: [],
        contradicts: [],
      },
    ],
    reviews: [],
    disposition: "review_ready",
    limitations: stepId === "incident" ? ["Coverage after 10:05 is absent; see evt-gc-2."] : [],
    requested_decisions: [],
  };
}

const runner: ModelRunnerPort = {
  getPinnedModelForRole: () => ({ provider: "stub", model: "stub-model", fallback_providers: [] }),
  preflightWave: async () => {},
  runTurn: async (req: ModelTurnRequest): Promise<StepTurnResult> => ({
    status: "completed",
    output_text: JSON.stringify(handoff(req.stepId, req.profile)),
    usage: {
      input_tokens: 100, output_tokens: 50, cache_read_tokens: 0, cache_write_tokens: 0, total_tokens: 150, turns: 1,
      provider: "stub", model: "stub-model", billing_mode: "oauth_subscription",
      actual_billed_usd: 0, shadow_api_usd: 0, cache_savings_usd: 0,
    },
  }),
};

async function* linesOf(...lines: string[]): AsyncGenerator<string> {
  for (const line of lines) yield `${line}\n`;
}

type RpcLine = { id?: string; result?: any; error?: { code: number; error_code: string; message: string } };

async function serve(lines: string[], withRunner = false): Promise<RpcLine[]> {
  const out: string[] = [];
  const code = await runHuntCli(
    ["serve", "--runtime-dir", runtimeDir, "--cases-dir", casesDir],
    { writeStdout: (t) => void out.push(t), writeStderr: () => {} },
    { ...(withRunner ? { modelRunner: runner } : {}), stdin: linesOf(...lines) },
  );
  expect(code).toBe(0);
  return out.join("").trim().split("\n").map((l) => JSON.parse(l) as RpcLine).filter((l) => l.id !== undefined);
}

const rpc = (id: string, method: string, params: unknown) => JSON.stringify({ jsonrpc: "2.0", id, method, params });

describe("hunt.gateContext over serve with the default case data plane", () => {
  let scopeSha = "";
  let incidentSha = "";

  test("scope gate: scope text and the open gate's digest", async () => {
    runtimeDir = makeTmpDir("hunt-gatectx-rt-");
    const [started] = await serve(
      [rpc("s", "hunt.start", { run_id: "hunt-gc-1", case_id: CASE_ID, scope: `Scope the host Authorization: Bearer ${LEAK}abc` , follow_ups: 0 })],
      true,
    );
    expect(started!.error).toBeUndefined();
    scopeSha = (started!.result as PersistedHuntRun).open_gate!.payload_sha256;
    const [ctx] = await serve([rpc("g", "hunt.gateContext", { run_id: "hunt-gc-1" })]);
    expect(ctx!.error).toBeUndefined();
    expect(ctx!.result).toMatchObject({ run_id: "hunt-gc-1", case_id: CASE_ID, gate: "scope", payload_sha256: scopeSha });
    expect(ctx!.result.scope.scope_text).toContain("Scope the host");
    expect(ctx!.result.scope.scope_text).not.toContain(LEAK);
    expect(ctx!.result.incident).toBeUndefined();
  });

  test("incident gate: receipt, verified evidence with scrubbed and capped fields, sorted ids", async () => {
    const token = (await (async () => {
      const out: string[] = [];
      await runHuntCli(["token", "--principal", "alice", "--role", "analyst", "--runtime-dir", runtimeDir], {
        writeStdout: (t) => void out.push(t),
        writeStderr: () => {},
      });
      return out.join("").trim();
    })());
    const [decided] = await serve(
      [rpc("d", "hunt.decideGate", { hunt_id: "hunt-gc-1", gate: "scope", action: "approve", operator_token: token, payload_sha256: scopeSha, check_note: "Approved scope." })],
      true,
    );
    expect(decided!.error).toBeUndefined();
    const parked = decided!.result as PersistedHuntRun;
    expect(parked.open_gate?.gate).toBe("incident");
    incidentSha = parked.open_gate!.payload_sha256;

    const [ctx] = await serve([rpc("g", "hunt.gateContext", { run_id: "hunt-gc-1" })]);
    expect(ctx!.error).toBeUndefined();
    const result = ctx!.result;
    expect(result).toMatchObject({ gate: "incident", payload_sha256: incidentSha });
    expect(result.scope).toBeUndefined();
    expect(result.incident.citation_receipt).toEqual(parked.citation_receipt as CitationVerificationReceipt);
    expect(result.incident.evidence_truncated).toBe(false);
    expect(result.incident.evidence.map((e: { id: string }) => e.id)).toEqual(["evt-gc-1", "evt-gc-2"]);
    const [e1, e2] = result.incident.evidence;
    expect(e1).toMatchObject({ kind: "evt", status: "verified", timestamp_iso: "2026-11-14T10:01:00Z" });
    expect(e1.fields["host.name"]).toBe("workstation-01");
    expect(Buffer.byteLength(e1.fields.long, "utf8")).toBeLessThanOrEqual(1024);
    expect(JSON.stringify(result)).not.toContain(LEAK);
    expect(Object.keys(e2.fields).length).toBeLessThanOrEqual(64);
  });

  test("errors: unknown run, no open gate, bad params; and the real serve binary answers", async () => {
    const out = await serve([
      rpc("u", "hunt.gateContext", { run_id: "hunt-missing" }),
      rpc("b", "hunt.gateContext", { run_id: "hunt-gc-1", extra: true }),
    ]);
    const byId = new Map(out.map((l) => [l.id, l]));
    expect(byId.get("u")!.error!.error_code).toBe("hunt_not_found");
    expect(byId.get("b")!.error!.error_code).toBe("invalid_arguments");

    const proc = Bun.spawn(
      [process.execPath, path.join(import.meta.dir, "..", "src", "cli.ts"), "serve", "--runtime-dir", runtimeDir, "--cases-dir", casesDir],
      { stdin: "pipe", stdout: "pipe", stderr: "pipe", windowsHide: true },
    );
    proc.stdin.write(`${rpc("cli", "hunt.gateContext", { run_id: "hunt-gc-1" })}\n`);
    await proc.stdin.end();
    const stdout = await new Response(proc.stdout).text();
    expect(await proc.exited).toBe(0);
    const line = stdout.trim().split("\n").map((l) => JSON.parse(l) as RpcLine).find((l) => l.id === "cli")!;
    expect(line.result).toMatchObject({ run_id: "hunt-gc-1", gate: "incident", payload_sha256: incidentSha });
    expect(line.result.incident.evidence).toHaveLength(2);
  }, 60_000);
});

describe("buildGateContext", () => {
  const receipt: CitationVerificationReceipt = {
    verified: false,
    checked_at: "2026-11-14T10:30:00Z",
    case_id: "case-x",
    total_checked: 4,
    missing_event_ids: ["evt-missing"],
    missing_frame_ids: [],
    missing_ioc_ids: [],
    ambiguous_ids: ["ioc-77"],
    out_of_scope_ids: ["frame-9"],
    source_status: "ok",
  };
  const baseRun = (over: Partial<PersistedHuntRun>): PersistedHuntRun =>
    ({
      run_id: "hunt-x",
      case_id: "case-x",
      data_origin: "synthetic",
      synthetic_only: true,
      status: "awaiting_gate",
      step_states: { scope: "done", incident: "awaiting_review" },
      results: {},
      reviewed_handoffs: {},
      handoff_rejections: [],
      citation_receipt: receipt,
      config: { scopeText: "s", followUps: 0, maxTotalTokens: 1000 },
      open_gate: { gate: "incident", wave: "incident", requires_human: true, payload_sha256: "ab".repeat(32), opened_at: "t", expires_at: "t", check_note_cleared: true },
      ...over,
    }) as unknown as PersistedHuntRun;
  const statement = (ids: string[]) => ({
    claim_id: "c", kind: "finding", statement: `Saw ${ids.join(", ")}.`, evidence_ids: [], entity_ids: [], contradicts: [],
  });
  const withCited = (ids: string[]) =>
    baseRun({ results: { incident: { handoff: { claims: [statement(ids)], limitations: [] } } } as never });
  const plane = (records: string[]): HuntDataPlanePort =>
    ({
      caseMetadata: { case_id: "case-x", data_origin: "synthetic" },
      readCitedRecords: async (ids: readonly string[]) =>
        ids.filter((id) => records.includes(id)).map((id) => ({ id, kind: "evt", timestamp_iso: null, title: id, record: { a: 1 } })),
    }) as unknown as HuntDataPlanePort;

  test("maps receipt statuses and blanks non-verified evidence", async () => {
    const ctx = await buildGateContext({
      run: withCited(["evt-ok", "evt-missing", "frame-9", "ioc-77", "evt-gone"]),
      receipts: [],
      resolveDataPlane: () => plane(["evt-ok", "frame-9", "ioc-77"]),
    });
    const status = Object.fromEntries(ctx.incident!.evidence.map((e) => [e.id, e.status]));
    expect(status).toEqual({
      "evt-gone": "unresolved",
      "evt-missing": "unresolved",
      "evt-ok": "verified",
      "frame-9": "out_of_scope",
      "ioc-77": "ambiguous",
    });
    expect(ctx.incident!.evidence.find((e) => e.id === "frame-9")).toMatchObject({ kind: "frame", title: "", fields: {}, timestamp_iso: null });
  });

  test("caps evidence at 500 ids and says so", async () => {
    const ids = Array.from({ length: GATE_CONTEXT_MAX_EVIDENCE + 20 }, (_, i) => `evt-${String(i).padStart(4, "0")}`);
    const ctx = await buildGateContext({ run: withCited(ids), receipts: [], resolveDataPlane: () => plane(ids) });
    expect(ctx.incident!.evidence).toHaveLength(GATE_CONTEXT_MAX_EVIDENCE);
    expect(ctx.incident!.evidence_truncated).toBe(true);
  });

  test("fails closed: no open gate, wrong-case plane, unreadable plane, reconcile without receipts", async () => {
    const codeOf = async (p: Promise<unknown>) => {
      try {
        await p;
        return "ok";
      } catch (err) {
        return err instanceof GateContextError ? err.errorCode : "other";
      }
    };
    expect(await codeOf(buildGateContext({ run: baseRun({ status: "running", open_gate: null }), receipts: [] }))).toBe("no_open_gate");
    const otherCase = { ...plane([]), caseMetadata: { case_id: "case-y", data_origin: "synthetic" } } as unknown as HuntDataPlanePort;
    expect(await codeOf(buildGateContext({ run: withCited(["evt-ok"]), receipts: [], resolveDataPlane: () => otherCase }))).toBe(
      "gate_context_unavailable",
    );
    const noReader = { caseMetadata: { case_id: "case-x", data_origin: "synthetic" } } as unknown as HuntDataPlanePort;
    expect(await codeOf(buildGateContext({ run: withCited(["evt-ok"]), receipts: [], resolveDataPlane: () => noReader }))).toBe(
      "gate_context_unavailable",
    );
    const reconcileRun = baseRun({
      open_gate: { gate: "reconcile", wave: "analysis", requires_human: true, payload_sha256: "cd".repeat(32), opened_at: "t", expires_at: "t", check_note_cleared: true, unknown_step_id: "scope", reason_code: "previous_dispatch_unknown" } as never,
    });
    expect(await codeOf(buildGateContext({ run: reconcileRun, receipts: [] }))).toBe("gate_context_unavailable");
    const ctx = await buildGateContext({
      run: reconcileRun,
      receipts: [
        { execution_id: "hunt-x:scope", run_id: "hunt-x", step_id: "scope", session_id: "s1", input_id: "i1", fingerprint: "f", status: "previous_dispatch_unknown", reason_code: "previous_dispatch_unknown", output_text: null, usage: null, refusal: null, diagnostic: null, reserved_at: "2026-11-14T10:00:00Z", finished_at: null },
        { execution_id: "hunt-other:scope", run_id: "hunt-other", step_id: "scope", session_id: "s2", input_id: "i2", fingerprint: "f", status: "previous_dispatch_unknown", reason_code: "previous_dispatch_unknown", output_text: null, usage: null, refusal: null, diagnostic: null, reserved_at: "2026-11-14T10:00:00Z", finished_at: null },
      ],
    });
    expect(ctx.reconcile).toEqual({ reason_code: "previous_dispatch_unknown", receipts: [
      { execution_id: "hunt-x:scope", session_id: "s1", input_id: "i1", step_id: "scope", profile: "framework-coordinator", reserved_at: "2026-11-14T10:00:00Z", reason_code: "previous_dispatch_unknown" },
    ] });
  });
});

describe("hunt.gateContext on a citation_source_unavailable reconcile gate", () => {
  /** The real case data plane, except that citation verification reports its source unavailable. */
  async function flakyPlane(readable: boolean): Promise<{ plane: HuntDataPlanePort; close: () => Promise<void> }> {
    const { createCaseDirDataPlaneResolver } = await import("../src/index.ts");
    const resolver = createCaseDirDataPlaneResolver({ casesDir, cacheDir: makeTmpDir("hunt-gatectx-cache-") });
    const real = await resolver.resolve(CASE_ID);
    const plane: HuntDataPlanePort = {
      caseMetadata: real.caseMetadata,
      capabilities: () => real.capabilities(),
      executeTool: (...a) => real.executeTool(...a),
      verifyCitations: async (r) => ({
        verified: false,
        checked_at: new Date().toISOString(),
        case_id: r.case_id,
        total_checked: 0,
        missing_event_ids: [],
        missing_frame_ids: [],
        missing_ioc_ids: [],
        ambiguous_ids: [],
        out_of_scope_ids: [],
        source_status: "unavailable",
        diagnostic: `events index offline password=${LEAK}`,
      }),
      readCitedRecords: readable
        ? (ids, signal) => real.readCitedRecords!(ids, signal)
        : async () => {
            throw new Error("events index offline");
          },
    };
    return { plane, close: () => resolver.close() };
  }

  for (const readable of [true, false]) {
    test(`opens the gate through serve and returns its context (source ${readable ? "back" : "still down"})`, async () => {
      runtimeDir = makeTmpDir("hunt-gatectx-csu-rt-");
      const { plane, close } = await flakyPlane(readable);
      try {
      const out: string[] = [];
      const code = await runHuntCli(
        ["serve", "--runtime-dir", runtimeDir],
        { writeStdout: (t) => void out.push(t), writeStderr: () => {} },
        {
          modelRunner: runner,
          resolveDataPlane: () => plane,
          stdin: linesOf(rpc("s", "hunt.start", { run_id: "hunt-csu", case_id: CASE_ID, scope: "Scope.", follow_ups: 0 })),
        },
      );
      expect(code).toBe(0);
      const started = out.join("").trim().split("\n").map((l) => JSON.parse(l) as RpcLine).find((l) => l.id === "s")!;
      const parked = started.result as PersistedHuntRun;
      expect(parked.open_gate).toMatchObject({ gate: "reconcile", reason_code: "citation_source_unavailable", unknown_step_id: "scope" });

      const ctxOut: string[] = [];
      await runHuntCli(
        ["serve", "--runtime-dir", runtimeDir],
        { writeStdout: (t) => void ctxOut.push(t), writeStderr: () => {} },
        { resolveDataPlane: () => plane, stdin: linesOf(rpc("g", "hunt.gateContext", { run_id: "hunt-csu" })) },
      );
      const ctx = ctxOut.join("").trim().split("\n").map((l) => JSON.parse(l) as RpcLine).find((l) => l.id === "g")!;
      expect(ctx.error).toBeUndefined();
      expect(ctx.result).toMatchObject({ gate: "reconcile", payload_sha256: parked.open_gate!.payload_sha256 });
      const reconcile = ctx.result.reconcile;
      expect(reconcile.reason_code).toBe("citation_source_unavailable");
      expect(reconcile.citation_receipt).toMatchObject({ source_status: "unavailable" });
      expect(JSON.stringify(ctx.result)).not.toContain(LEAK);
      expect(reconcile.evidence_truncated).toBe(false);
      if (readable) {
        expect(reconcile.unavailable_sources).toEqual([]);
        expect(reconcile.evidence.map((e: { id: string; status: string }) => [e.id, e.status])).toEqual([
          ["evt-gc-1", "verified"],
          ["evt-gc-2", "verified"],
        ]);
        expect(reconcile.evidence[0].fields["host.name"]).toBe("workstation-01");
      } else {
        expect(reconcile.unavailable_sources).toEqual(["events"]);
        expect(reconcile.evidence).toEqual([]);
      }
      } finally {
        await close();
      }
    });
  }
});
