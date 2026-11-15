import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import type { Handoff, ProfileId } from "@hunt-command/shared";
import {
  GATE_CONTEXT_FIRST_PAGE,
  GATE_CONTEXT_MAX_CITED,
  GateContextError,
  buildGateContext,
  buildGateEvidencePage,
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
    expect(result.incident.cited).toEqual([
      { id: "evt-gc-1", kind: "evt", status: "verified" },
      { id: "evt-gc-2", kind: "evt", status: "verified" },
    ]);
    expect(result.incident).toMatchObject({ evidence_total: 2, evidence_next_cursor: null });
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
  test("approved incident evidence reloads from its case after daemon restart and fails closed if unavailable", async () => {
    const tokenOutput: string[] = [];
    await runHuntCli(["token", "--principal", "alice", "--role", "analyst", "--runtime-dir", runtimeDir], {
      writeStdout: (text) => void tokenOutput.push(text), writeStderr: () => {},
    });
    const [approved] = await serve([rpc("approve", "hunt.decideGate", {
      hunt_id: "hunt-gc-1", gate: "incident", action: "approve", operator_token: tokenOutput.join("").trim(),
      payload_sha256: incidentSha, check_note: "Reviewed incident evidence.",
    })], true);
    expect(approved!.error).toBeUndefined();
    expect((approved!.result as PersistedHuntRun).open_gate).toBeNull();
    const responses = await serve([
      rpc("e", "hunt.evidence", { run_id: "hunt-gc-1" }),
      rpc("bad", "hunt.evidence", { run_id: "hunt-gc-1", case_id: "other" }),
      rpc("unknown", "hunt.evidence", { run_id: "unknown" }),
    ]);
    const reloaded = responses.find((response) => response.id === "e");
    const bad = responses.find((response) => response.id === "bad");
    const unknown = responses.find((response) => response.id === "unknown");
    expect(reloaded!.error).toBeUndefined();
    expect(reloaded!.result).toMatchObject({ run_id: "hunt-gc-1", case_id: CASE_ID, evidence_truncated: false });
    expect(reloaded!.result.evidence.map((e: { status: string }) => e.status)).toEqual(["verified", "verified"]);
    expect(JSON.stringify(reloaded!.result)).not.toContain(LEAK);
    expect(Object.keys(reloaded!.result.evidence[1].fields).length).toBeLessThanOrEqual(64);
    expect(bad!.error!.error_code).toBe("invalid_arguments");
    expect(unknown!.error!.error_code).toBe("hunt_not_found");

    const caseDir = path.join(casesDir, CASE_ID);
    const moved = `${caseDir}-offline`;
    fs.renameSync(caseDir, moved);
    try {
      const [offline] = await serve([rpc("offline", "hunt.evidence", { run_id: "hunt-gc-1" })]);
      expect(offline!.error!.error_code).toBe("evidence_unavailable");
      expect(offline!.result).toBeUndefined();
    } finally {
      fs.renameSync(moved, caseDir);
    }
  });
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
  const verifyAgainst = (records: readonly string[]) => async (r: { case_id: string; event_ids: readonly string[]; frame_ids: readonly string[]; ioc_ids: readonly string[] }) => {
    const known = new Set(records);
    const miss = (ids: readonly string[]) => ids.filter((id) => !known.has(id));
    return {
      verified: true, checked_at: "t", case_id: r.case_id, total_checked: 0,
      missing_event_ids: miss(r.event_ids), missing_frame_ids: miss(r.frame_ids), missing_ioc_ids: miss(r.ioc_ids),
      ambiguous_ids: [], out_of_scope_ids: [], source_status: "ok" as const,
    };
  };
  const plane = (records: string[]): HuntDataPlanePort =>
    ({
      caseMetadata: { case_id: "case-x", data_origin: "synthetic" },
      verifyCitations: verifyAgainst(records),
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

  test("1,200 cited ids: cited is complete and pages reassemble every record exactly once", async () => {
    const ids = Array.from({ length: 1_200 }, (_, i) => `evt-${String(i).padStart(5, "0")}`);
    const present = ids.filter((_, i) => i % 7 !== 0);
    const run = withCited(ids);
    const ctx = await buildGateContext({ run, receipts: [], resolveDataPlane: () => plane(present) });
    const inc = ctx.incident!;
    expect(inc.cited.map((c) => c.id)).toEqual(ids);
    expect(inc.cited.filter((c) => c.status === "verified").map((c) => c.id)).toEqual(present);
    expect(inc.cited.filter((c) => c.status === "unresolved")).toHaveLength(ids.length - present.length);
    expect(inc.evidence).toHaveLength(GATE_CONTEXT_FIRST_PAGE);
    expect(inc.evidence_total).toBe(1_200);
    const seen = [...inc.evidence];
    let cursor = inc.evidence_next_cursor;
    let pages = 0;
    while (cursor) {
      const page = await buildGateEvidencePage({ run, cursor, limit: 333, resolveDataPlane: () => plane(present) });
      expect(page).toMatchObject({ run_id: "hunt-x", gate: "incident", payload_sha256: run.open_gate!.payload_sha256, evidence_total: 1_200 });
      expect(page.evidence.length).toBeLessThanOrEqual(333);
      seen.push(...page.evidence);
      cursor = page.evidence_next_cursor;
      pages++;
    }
    expect(pages).toBe(Math.ceil((1_200 - GATE_CONTEXT_FIRST_PAGE) / 333));
    expect(seen.map((e) => e.id)).toEqual(ids);
    // Each page's statuses agree with `cited`, and verified records carry their fields.
    expect(seen.map((e) => e.status)).toEqual(inc.cited.map((c) => c.status));
    expect(seen.filter((e) => e.status === "verified").every((e) => e.fields.a === 1)).toBe(true);
  });

  test("evidence cursors are bound to the run, the gate and its digest", async () => {
    const ids = Array.from({ length: 300 }, (_, i) => `evt-${String(i).padStart(5, "0")}`);
    const run = withCited(ids);
    const ctx = await buildGateContext({ run, receipts: [], resolveDataPlane: () => plane(ids) });
    const cursor = ctx.incident!.evidence_next_cursor!;
    const codeOf = async (p: Promise<unknown>) => p.then(() => "ok", (err) => (err instanceof GateContextError ? err.errorCode : "other"));
    const page = (r: PersistedHuntRun, c: string) => buildGateEvidencePage({ run: r, cursor: c, limit: 50, resolveDataPlane: () => plane(ids) });

    expect(await codeOf(page(run, cursor))).toBe("ok");
    expect(await codeOf(page({ ...run, run_id: "hunt-other" }, cursor))).toBe("invalid_arguments");
    expect(await codeOf(page({ ...run, open_gate: { ...run.open_gate!, payload_sha256: "ef".repeat(32) } }, cursor))).toBe("stale_cursor");
    expect(await codeOf(page({ ...run, open_gate: { ...run.open_gate!, gate: "scope" } }, cursor))).toBe("stale_cursor");
    expect(await codeOf(page({ ...run, status: "running", open_gate: null }, cursor))).toBe("no_open_gate");
    expect(await codeOf(page(run, "gev1.not-json"))).toBe("invalid_arguments");
    expect(await codeOf(page(run, "something-else"))).toBe("invalid_arguments");
  });

  test("more than 20,000 cited ids fails closed instead of truncating", async () => {
    const ids = Array.from({ length: GATE_CONTEXT_MAX_CITED + 1 }, (_, i) => `evt-${String(i).padStart(6, "0")}`);
    let error: unknown;
    try {
      await buildGateContext({ run: withCited(ids), receipts: [], resolveDataPlane: () => plane(ids) });
    } catch (err) {
      error = err;
    }
    expect(error).toBeInstanceOf(GateContextError);
    expect((error as GateContextError).errorCode).toBe("gate_context_unavailable");
    expect((error as Error).message).toContain("20000");
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
    const noReader = { caseMetadata: { case_id: "case-x", data_origin: "synthetic" }, verifyCitations: verifyAgainst(["evt-ok"]) } as unknown as HuntDataPlanePort;
    expect(await codeOf(buildGateContext({ run: withCited(["evt-ok"]), receipts: [], resolveDataPlane: () => noReader }))).toBe(
      "gate_context_unavailable",
    );
    const reconcileRun = baseRun({
      open_gate: { gate: "reconcile", wave: "analysis", requires_human: true, payload_sha256: "cd".repeat(32), opened_at: "t", expires_at: "t", check_note_cleared: true, unknown_step_id: "scope", reason_code: "previous_dispatch_unknown" } as never,
    });
    expect(await codeOf(buildGateContext({ run: reconcileRun, receipts: [] }))).toBe("gate_context_unavailable");
    // The affected step must be identifiable in the run's own graph.
    const noStep = baseRun({ open_gate: { ...reconcileRun.open_gate!, unknown_step_id: undefined } });
    const ghostStep = baseRun({ open_gate: { ...reconcileRun.open_gate!, unknown_step_id: "follow-9" } });
    const pdu = [{ execution_id: "hunt-x:follow-9", run_id: "hunt-x", step_id: "follow-9", session_id: "s", input_id: "i", fingerprint: "f", status: "previous_dispatch_unknown" as const, reason_code: "previous_dispatch_unknown", output_text: null, usage: null, refusal: null, diagnostic: null, reserved_at: "t", finished_at: null }];
    expect(await codeOf(buildGateContext({ run: noStep, receipts: pdu }))).toBe("gate_context_unavailable");
    expect(await codeOf(buildGateContext({ run: ghostStep, receipts: pdu }))).toBe("gate_context_unavailable");
    const ctx = await buildGateContext({
      run: reconcileRun,
      receipts: [
        { execution_id: "hunt-x:scope", run_id: "hunt-x", step_id: "scope", session_id: "s1", input_id: "i1", fingerprint: "f", status: "previous_dispatch_unknown", reason_code: "previous_dispatch_unknown", output_text: null, usage: null, refusal: null, diagnostic: null, reserved_at: "2026-11-14T10:00:00Z", finished_at: null },
        { execution_id: "hunt-other:scope", run_id: "hunt-other", step_id: "scope", session_id: "s2", input_id: "i2", fingerprint: "f", status: "previous_dispatch_unknown", reason_code: "previous_dispatch_unknown", output_text: null, usage: null, refusal: null, diagnostic: null, reserved_at: "2026-11-14T10:00:00Z", finished_at: null },
      ],
    });
    expect(ctx.reconcile).toEqual({ reason_code: "previous_dispatch_unknown",
      affected_step: { step_id: "scope", profile: "framework-coordinator", wave: "scope", optional: false, approve_transition: "reconcile_halt", reject_reason_code: "reconcile_rejected" },
      receipts: [
      { execution_id: "hunt-x:scope", session_id: "s1", input_id: "i1", step_id: "scope", profile: "framework-coordinator", reserved_at: "2026-11-14T10:00:00Z", reason_code: "previous_dispatch_unknown" },
    ] });
  });
});

describe("hunt.gateContext on a citation_source_unavailable reconcile gate", () => {
  /** The real case data plane, except that citation verification reports its source unavailable. */
  async function flakyPlane(
    readable: boolean,
    healthyVerifyCalls = 0,
  ): Promise<{ plane: HuntDataPlanePort; close: () => Promise<void>; recover: () => void }> {
    let recovered = false;
    let verifyCalls = 0;
    const { createCaseDirDataPlaneResolver } = await import("../src/index.ts");
    const resolver = createCaseDirDataPlaneResolver({ casesDir, cacheDir: makeTmpDir("hunt-gatectx-cache-") });
    const real = await resolver.resolve(CASE_ID);
    const plane: HuntDataPlanePort = {
      caseMetadata: real.caseMetadata,
      capabilities: () => real.capabilities(),
      executeTool: (...a) => real.executeTool(...a),
      verifyCitations: async (r) => (recovered || ++verifyCalls <= healthyVerifyCalls) ? real.verifyCitations(r) : ({
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
    return { plane, close: () => resolver.close(), recover: () => { recovered = readable; } };
  }

  for (const readable of [true, false]) {
    test(`opens the gate through serve and returns its context (source ${readable ? "back" : "still down"})`, async () => {
      runtimeDir = makeTmpDir("hunt-gatectx-csu-rt-");
      const { plane, close, recover } = await flakyPlane(readable);
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

      recover();
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
      expect(reconcile).toMatchObject({ evidence_total: 2, evidence_next_cursor: null });
      const status = readable ? "verified" : "unchecked";
      expect(reconcile.cited).toEqual([
        { id: "evt-gc-1", kind: "evt", status },
        { id: "evt-gc-2", kind: "evt", status },
      ]);
      expect(reconcile.evidence.map((e: { id: string; status: string }) => [e.id, e.status])).toEqual([
        ["evt-gc-1", status],
        ["evt-gc-2", status],
      ]);
      if (readable) {
        expect(reconcile.unavailable_sources).toEqual([]);
        expect(reconcile.evidence[0].fields["host.name"]).toBe("workstation-01");
      } else {
        expect(reconcile.unavailable_sources).toEqual(["events"]);
        expect(reconcile.evidence[0]).toMatchObject({ title: "", fields: {}, timestamp_iso: null });
      }
      // Required step: the card says Approve halts the hunt, and the engine agrees.
      expect(reconcile.affected_step).toEqual({
        step_id: "scope",
        profile: "framework-coordinator",
        wave: "scope",
        optional: false,
        approve_transition: "reconcile_halt",
        reject_reason_code: "reconcile_rejected",
      });
      if (readable) {
        const approved = await approveThroughServe(runtimeDir, plane, "hunt-csu", "reconcile", parked.open_gate!.payload_sha256);
        expect(approved).toMatchObject({ status: "failed", reason_code: "reconciled_halt_required_step" });
      }
      } finally {
        await close();
      }
    });
  }

  test("an optional step's reconcile gate says Approve drops it, and the engine drops it", async () => {
    runtimeDir = makeTmpDir("hunt-gatectx-opt-rt-");
    // Scope's verification succeeds; the evidence step's verification finds its source down.
    const { plane, close } = await flakyPlane(false, 1);
    try {
      const out: string[] = [];
      await runHuntCli(
        ["serve", "--runtime-dir", runtimeDir],
        { writeStdout: (t) => void out.push(t), writeStderr: () => {} },
        {
          modelRunner: runner,
          resolveDataPlane: () => plane,
          stdin: linesOf(rpc("s", "hunt.start", { run_id: "hunt-opt", case_id: CASE_ID, scope: "Scope.", follow_ups: 0 })),
        },
      );
      const started = out.join("").trim().split("\n").map((l) => JSON.parse(l) as RpcLine).find((l) => l.id === "s")!;
      const scopeGate = (started.result as PersistedHuntRun).open_gate!;
      expect(scopeGate.gate).toBe("scope");
      const parked = await approveThroughServe(runtimeDir, plane, "hunt-opt", "scope", scopeGate.payload_sha256);
      expect(parked.open_gate).toMatchObject({ gate: "reconcile", reason_code: "citation_source_unavailable", unknown_step_id: "evidence" });

      const ctxOut: string[] = [];
      await runHuntCli(
        ["serve", "--runtime-dir", runtimeDir],
        { writeStdout: (t) => void ctxOut.push(t), writeStderr: () => {} },
        { resolveDataPlane: () => plane, stdin: linesOf(rpc("g", "hunt.gateContext", { run_id: "hunt-opt" })) },
      );
      const ctx = ctxOut.join("").trim().split("\n").map((l) => JSON.parse(l) as RpcLine).find((l) => l.id === "g")!;
      expect(ctx.error).toBeUndefined();
      expect(ctx.result.reconcile.affected_step).toEqual({
        step_id: "evidence",
        profile: "framework-researcher",
        wave: "investigation",
        optional: true,
        approve_transition: "reconcile_drop",
        reject_reason_code: "reconcile_rejected",
      });

      const after = await approveThroughServe(runtimeDir, plane, "hunt-opt", "reconcile", parked.open_gate!.payload_sha256);
      expect(after.step_states.evidence).toBe("dropped");
      expect(after.results.evidence).toMatchObject({ status: "dropped", reason_code: "reconciled_drop" });
      expect(after.status).not.toBe("failed");
    } finally {
      await close();
    }
  });
});

async function approveThroughServe(
  rt: string,
  plane: HuntDataPlanePort,
  runId: string,
  gate: string,
  payloadSha256: string,
): Promise<PersistedHuntRun> {
  const tokenOut: string[] = [];
  await runHuntCli(["token", "--principal", "alice", "--role", "analyst", "--runtime-dir", rt], {
    writeStdout: (t) => void tokenOut.push(t),
    writeStderr: () => {},
  });
  const out: string[] = [];
  await runHuntCli(
    ["serve", "--runtime-dir", rt],
    { writeStdout: (t) => void out.push(t), writeStderr: () => {} },
    {
      modelRunner: runner,
      resolveDataPlane: () => plane,
      stdin: linesOf(rpc("d", "hunt.decideGate", {
        hunt_id: runId, gate, action: "approve", operator_token: tokenOut.join("").trim(),
        payload_sha256: payloadSha256, check_note: "Reviewed the gate context.",
      })),
    },
  );
  const line = out.join("").trim().split("\n").map((l) => JSON.parse(l) as RpcLine).find((l) => l.id === "d")!;
  expect(line.error).toBeUndefined();
  return line.result as PersistedHuntRun;
}

describe("paged incident evidence over the real serve binary", () => {
  const PAGE_CASE = "gate-page-001";
  const N = 250;
  const ids = Array.from({ length: N }, (_, i) => `evt-p${String(i).padStart(4, "0")}`);

  test("gateContext returns all statuses and a cursor; hunt.gateEvidencePage returns the rest", async () => {
    const pageCases = makeTmpDir("hunt-gatepage-cases-");
    const caseDir = path.join(pageCases, PAGE_CASE);
    fs.mkdirSync(caseDir);
    fs.writeFileSync(
      path.join(caseDir, "case.json"),
      JSON.stringify({
        case_id: PAGE_CASE,
        question: "Paged evidence case.",
        data_origin: "synthetic",
        time_range_utc: { start_inclusive: "2026-11-14T10:00:00Z", end_exclusive: "2026-11-14T11:00:00Z" },
      }),
    );
    fs.writeFileSync(
      path.join(caseDir, "events.jsonl"),
      ids.map((id, i) => JSON.stringify({
        "@timestamp": `2026-11-14T10:${String(Math.floor(i / 60)).padStart(2, "0")}:${String(i % 60).padStart(2, "0")}Z`,
        event: { id, code: "1" },
        host: { name: `workstation-${i}` },
        message: `event ${i}`,
      })).join("\n") + "\n",
    );
    const chunk = (xs: string[], n: number) => Array.from({ length: Math.ceil(xs.length / n) }, (_, i) => xs.slice(i * n, i * n + n));
    const pageRunner: ModelRunnerPort = {
      ...runner,
      runTurn: async (req) => {
        const claims = req.stepId === "incident"
          ? chunk(ids, 150).map((part, i) => ({
              claim_id: `incident:c${i}`, kind: "finding" as const, statement: `Cited ${part.join(", ")}.`,
              evidence_ids: ["events.jsonl"], entity_ids: [], contradicts: [],
            }))
          : [{ claim_id: `${req.stepId}:c1`, kind: "observed" as const, statement: `Saw ${ids[0]}.`, evidence_ids: ["events.jsonl"], entity_ids: [], contradicts: [] }];
        const h: Handoff = { ...handoff(req.stepId, req.profile), case_id: PAGE_CASE, claims, limitations: [] };
        const res = await runner.runTurn(req);
        return { ...res, output_text: JSON.stringify(h) };
      },
    };
    const rt = makeTmpDir("hunt-gatepage-rt-");
    const serveRt = async (lines: string[], withRunner: boolean) => {
      const out: string[] = [];
      await runHuntCli(
        ["serve", "--runtime-dir", rt, "--cases-dir", pageCases],
        { writeStdout: (t) => void out.push(t), writeStderr: () => {} },
        { ...(withRunner ? { modelRunner: pageRunner } : {}), stdin: linesOf(...lines) },
      );
      return out.join("").trim().split("\n").map((l) => JSON.parse(l) as RpcLine).filter((l) => l.id !== undefined);
    };
    const [started] = await serveRt([rpc("s", "hunt.start", { run_id: "hunt-page", case_id: PAGE_CASE, scope: "Paged scope.", follow_ups: 0 })], true);
    expect(started!.error).toBeUndefined();
    const tokenOut: string[] = [];
    await runHuntCli(["token", "--principal", "alice", "--role", "analyst", "--runtime-dir", rt], {
      writeStdout: (t) => void tokenOut.push(t), writeStderr: () => {},
    });
    const [decided] = await serveRt([rpc("d", "hunt.decideGate", {
      hunt_id: "hunt-page", gate: "scope", action: "approve", operator_token: tokenOut.join("").trim(),
      payload_sha256: (started!.result as PersistedHuntRun).open_gate!.payload_sha256, check_note: "Approved.",
    })], true);
    expect((decided!.result as PersistedHuntRun).open_gate?.gate).toBe("incident");

    const binary = async (line: string): Promise<RpcLine> => {
      const proc = Bun.spawn(
        [process.execPath, path.join(import.meta.dir, "..", "src", "cli.ts"), "serve", "--runtime-dir", rt, "--cases-dir", pageCases],
        { stdin: "pipe", stdout: "pipe", stderr: "pipe", windowsHide: true },
      );
      proc.stdin.write(`${line}\n`);
      await proc.stdin.end();
      const stdout = await new Response(proc.stdout).text();
      expect(await proc.exited).toBe(0);
      return stdout.trim().split("\n").map((l) => JSON.parse(l) as RpcLine).find((l) => l.id === "b")!;
    };
    const ctx = await binary(rpc("b", "hunt.gateContext", { run_id: "hunt-page" }));
    expect(ctx.error).toBeUndefined();
    const inc = ctx.result.incident;
    expect(inc.cited.map((c: { id: string }) => c.id)).toEqual(ids);
    expect(inc.cited.every((c: { status: string }) => c.status === "verified")).toBe(true);
    expect(inc.evidence).toHaveLength(GATE_CONTEXT_FIRST_PAGE);
    expect(inc.evidence_total).toBe(N);
    expect(typeof inc.evidence_next_cursor).toBe("string");

    const page = await binary(rpc("b", "hunt.gateEvidencePage", { run_id: "hunt-page", cursor: inc.evidence_next_cursor, limit: 500 }));
    expect(page.error).toBeUndefined();
    expect(page.result).toMatchObject({ run_id: "hunt-page", gate: "incident", evidence_total: N, evidence_next_cursor: null });
    expect([...inc.evidence, ...page.result.evidence].map((e: { id: string }) => e.id)).toEqual(ids);
    expect(page.result.evidence.at(-1).fields["host.name"]).toBe(`workstation-${N - 1}`);

    const foreign = await binary(rpc("b", "hunt.gateEvidencePage", { run_id: "hunt-gc-1", cursor: inc.evidence_next_cursor, limit: 10 }));
    expect(foreign.error!.error_code).toBe("hunt_not_found");
    const bad = await binary(rpc("b", "hunt.gateEvidencePage", { run_id: "hunt-page", cursor: inc.evidence_next_cursor, limit: 501 }));
    expect(bad.error!.error_code).toBe("invalid_arguments");
  }, 120_000);
});
