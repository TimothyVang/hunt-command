import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import type { CaseMetadata, Handoff, ProfileId } from "@hunt-command/shared";
import {
  DurableStateStore,
  GateAuthority,
  GateDecisionError,
  HuntDaemonRpcServer,
  HuntWaveEngine,
  InMemoryTelemetrySink,
  LineSplitter,
  NON_SYNTHETIC_MODAL_WARNING_TEXT,
  SlackSocketModeBridge,
  buildBotSanitizedEnv,
  executeDriveGates,
  verifyActionNonceConstantTime,
  type HuntDataPlanePort,
  type ModelRunnerPort,
  type ModelTurnRequest,
  type SlackApiTransport,
  type StepTurnResult,
} from "../src/index.ts";

const tempDirs: string[] = [];
function makeTmpDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hunt-gates-rpc-test-"));
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

function makeSimpleHandoff(caseId: string, stepId: string, profile: ProfileId): Handoff {
  return {
    schema_version: 1,
    case_id: caseId,
    step_id: stepId,
    profile,
    claims: [
      {
        claim_id: `${stepId}:c1`,
        kind: stepId === "incident" ? "finding" : "observed",
        statement: `Sensitive internal host CORP-DC099 and user svc_backup_secret in evt-500.`,
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

function makeTestDataPlane(syntheticOnly: boolean): HuntDataPlanePort {
  const meta: CaseMetadata = {
    case_id: syntheticOnly ? "case-syn-99" : "case-real-work-99",
    title: "Gate & Slack Security Test",
    data_origin: syntheticOnly ? "synthetic" : "work-connected",
    synthetic_only: syntheticOnly,
    time_window: {
      start_iso: "2026-11-01T00:00:00Z",
      end_iso: "2026-11-01T01:00:00Z",
    },
    sources: ["elastic-logs"],
  };
  return {
    caseMetadata: meta,
    capabilities: () => ({ hasNetworkCapture: false, hasIntelSource: false, sources: meta.sources }),
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

function makeStaticRunner(): ModelRunnerPort {
  return {
    getPinnedModelForRole: () => ({
      provider: "anthropic",
      model: "claude-sonnet-4-6",
      fallback_providers: [],
    }),
    preflightWave: async () => {},
    runTurn: async (req: ModelTurnRequest): Promise<StepTurnResult> => ({
      status: "completed",
      output_text: JSON.stringify(makeSimpleHandoff(req.caseId, req.stepId, req.profile)),
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
    }),
  };
}

describe("Governed Human Gates, EgressGuard, Slack Socket Mode & NDJSON RPC", () => {
  test("enforces RBAC, SHA-256 digest binding, expiry, automated rejection, replay prevention, and atomic decisions.jsonl", () => {
    const tmp = makeTmpDir();
    const store = new DurableStateStore(path.join(tmp, "state.sqlite"));
    const gates = new GateAuthority({
      stateStore: store,
      decisionsDir: path.join(tmp, "decisions"),
      productionMode: true,
    });

    const handoff = makeSimpleHandoff("case-real-work-99", "scope", "framework-coordinator");
    const { openGate, reviewEnvelope } = gates.openGate({
      huntId: "hunt-sec-1",
      caseId: "case-real-work-99",
      wave: "scope",
      gate: "scope",
      statusEnum: "awaiting_human_scope_approval",
      gatedPayload: { handoff },
      syntheticOnly: false,
      dataOrigin: "work-connected",
      handoff,
      nowMs: 1_000_000,
      ttlMs: 60_000,
    });

    // Rule 4 EgressGuard: non-synthetic review card NEVER contains case_id, claims, or hostnames!
    const serializedCard = JSON.stringify(reviewEnvelope.card);
    expect(reviewEnvelope.card.mode).toBe("id_and_status_only");
    expect(serializedCard).not.toContain("CORP-DC099");
    expect(serializedCard).not.toContain("svc_backup_secret");
    expect(serializedCard).not.toContain("case-real-work-99");

    // 1. Rejects `via === 'automated'` on human gate
    expect(() =>
      gates.validateAndRecordDecision(openGate, {
        huntId: "hunt-sec-1",
        gate: "scope",
        action: "approve",
        via: "automated",
        operatorToken: gates.sessionAuthority.issueToken("ci-bot", "admin"),
        payloadSha256: openGate.payload_sha256,
        checkNote: "auto",
        nowMs: 1_010_000,
      }),
    ).toThrow(/rejects via='automated'/);

    // 2. Rejects `viewer` RBAC role
    const viewerToken = gates.sessionAuthority.issueToken("bob-viewer", "viewer");
    expect(() =>
      gates.validateAndRecordDecision(openGate, {
        huntId: "hunt-sec-1",
        gate: "scope",
        action: "approve",
        via: "desktop",
        operatorToken: viewerToken,
        payloadSha256: openGate.payload_sha256,
        checkNote: "Looks good",
        nowMs: 1_010_000,
      }),
    ).toThrow(/not authorized/);

    // 3. Rejects mismatched SHA-256 digest
    const analystToken = gates.sessionAuthority.issueToken("alice-analyst", "analyst");
    expect(() =>
      gates.validateAndRecordDecision(openGate, {
        huntId: "hunt-sec-1",
        gate: "scope",
        action: "approve",
        via: "desktop",
        operatorToken: analystToken,
        payloadSha256: "0".repeat(64),
        checkNote: "Checked scope",
        nowMs: 1_010_000,
      }),
    ).toThrow(/payload_sha256 mismatch/);

    // 4. Rejects expired gate
    expect(() =>
      gates.validateAndRecordDecision(openGate, {
        huntId: "hunt-sec-1",
        gate: "scope",
        action: "approve",
        via: "desktop",
        operatorToken: analystToken,
        payloadSha256: openGate.payload_sha256,
        checkNote: "Checked scope",
        nowMs: 2_000_000,
      }),
    ).toThrow(/expired/);

    // 5. Rejects empty check_note on human gate
    expect(() =>
      gates.validateAndRecordDecision(openGate, {
        huntId: "hunt-sec-1",
        gate: "scope",
        action: "approve",
        via: "desktop",
        operatorToken: analystToken,
        payloadSha256: openGate.payload_sha256,
        checkNote: "   ",
        nowMs: 1_010_000,
      }),
    ).toThrow(/check_note/);

    // 6. Valid decision succeeds, writes decisions.jsonl with note_sha256, and blocks replay!
    const valid = gates.validateAndRecordDecision(openGate, {
      decisionId: "dec-unique-001",
      huntId: "hunt-sec-1",
      gate: "scope",
      action: "approve",
      via: "desktop",
      operatorToken: analystToken,
      payloadSha256: openGate.payload_sha256,
      checkNote: "Verified scope targets and read-only Elastic time bounds.",
      nowMs: 1_010_000,
    });
    expect(valid.decision.decided_by).toBe("alice-analyst");
    expect(valid.auditRecord.note_sha256).toMatch(/^[0-9a-f]{64}$/);

    // Replay of `dec-unique-001` on a subsequent gate is blocked!
    const { openGate: gate2 } = gates.openGate({
      huntId: "hunt-sec-1",
      caseId: "case-real-work-99",
      wave: "incident",
      gate: "incident",
      statusEnum: "awaiting_human_incident_approval",
      gatedPayload: { incident: true },
      syntheticOnly: false,
      dataOrigin: "work-connected",
      nowMs: 1_020_000,
      ttlMs: 60_000,
    });
    expect(() =>
      gates.validateAndRecordDecision(gate2, {
        decisionId: "dec-unique-001",
        huntId: "hunt-sec-1",
        gate: "incident",
        action: "approve",
        via: "desktop",
        operatorToken: analystToken,
        payloadSha256: gate2.payload_sha256,
        checkNote: "Second gate note",
        nowMs: 1_025_000,
      }),
    ).toThrow(/Replay blocked/);

    const logLines = fs
      .readFileSync(gates.decisionsLogPath, "utf8")
      .trim()
      .split("\n");
    expect(logLines.length).toBe(1);
    const parsedLog = JSON.parse(logLines[0]!) as { authenticated_principal: string; note_sha256: string };
    expect(parsedLog.authenticated_principal).toBe("alice-analyst");
    expect(parsedLog.note_sha256).toBe(valid.auditRecord.note_sha256!);

    store.close();
  });

  test("SlackSocketModeBridge enforces env stripping, claimed->pending recovery, allowlist, timingSafeEqual nonce & 2-step red-warning modal", async () => {
    const tmp = makeTmpDir();
    const store = new DurableStateStore(path.join(tmp, "state.sqlite"));
    const gates = new GateAuthority({
      stateStore: store,
      decisionsDir: path.join(tmp, "decisions"),
    });
    const engine = new HuntWaveEngine({
      stateStore: store,
      gateAuthority: gates,
      modelRunner: makeStaticRunner(),
    });

    // Verify bot environment sanitizer strips SLACK_* and API keys
    // health: allow FORBIDDEN_TOKEN -- synthetic test fixture
    const sanitizedEnv = buildBotSanitizedEnv({
      PATH: "/usr/bin",
      // health: allow FORBIDDEN_TOKEN -- synthetic test fixture
      SLACK_BOT_TOKEN: "xoxb-synthetic-test-0001",
      // health: allow FORBIDDEN_TOKEN -- synthetic test fixture
      SLACK_APP_TOKEN: "xapp-synthetic-test-0001",
      // health: allow FORBIDDEN_TOKEN -- synthetic test fixture
      ANTHROPIC_API_KEY: "sk-ant-synthetic-test-0001",
    });
    expect(sanitizedEnv.SLACK_BOT_TOKEN).toBeUndefined();
    expect(sanitizedEnv.SLACK_APP_TOKEN).toBeUndefined();
    expect(sanitizedEnv.ANTHROPIC_API_KEY).toBeUndefined();
    expect(sanitizedEnv.PATH).toBe("/usr/bin");

    // Constant-time nonce check helper
    const n1 = "abcdef0123456789abcdef0123456789";
    expect(verifyActionNonceConstantTime(n1, n1)).toBe(true);
    expect(verifyActionNonceConstantTime(n1, "0000000123456789abcdef0123456789")).toBe(false);

    // Start a non-synthetic hunt (`work-connected`) so Gate 1 opens and writes `pending/*__review.json`
    const dp = makeTestDataPlane(false);
    const parked = await engine.startHunt({
      runId: "hunt-slack-01",
      scopeText: "Check privileged authentication anomalies.",
      dataPlane: dp,
      followUps: 0,
    });
    expect(parked.open_gate?.gate).toBe("scope");

    // Simulate crash recovery: move pending file into claimed/, then verify recoverClaimedToPending() restores it!
    const pendingFilesBefore = fs.readdirSync(gates.pendingDir);
    expect(pendingFilesBefore.length).toBe(1);
    fs.renameSync(
      path.join(gates.pendingDir, pendingFilesBefore[0]!),
      path.join(gates.claimedDir, pendingFilesBefore[0]!),
    );

    const postedMessages: Array<{ channel: string; text: string; blocks: Record<string, unknown>[] }> = [];
    const openedModals: Array<{ trigger_id: string; view: Record<string, unknown> }> = [];
    const updatedMessages: Array<{ channel: string; ts: string; text: string }> = [];

    const mockSlackTransport: SlackApiTransport = {
      openSocketUrl: async () => "wss://wss-primary.slack.com/link/?ticket=test",
      postMessage: async (msg) => {
        postedMessages.push(msg);
        return { ts: "1700000000.000100", channel: msg.channel };
      },
      openModal: async (modal) => {
        openedModals.push(modal);
      },
      updateMessage: async (upd) => {
        updatedMessages.push(upd);
      },
    };

    const bridge = new SlackSocketModeBridge({
      pendingDir: gates.pendingDir,
      claimedDir: gates.claimedDir,
      channelId: "C0123456789",
      allowedUserIds: ["U01ALLOW99"],
      userRoles: { U01ALLOW99: "analyst" },
      transport: mockSlackTransport,
      onGateDecision: (dec) => engine.submitGateDecision(dec, dp),
    });

    expect(bridge.recoverClaimedToPending()).toBe(1);
    expect(await bridge.pollAndPublishPendingReviews()).toBe(1);
    expect(postedMessages.length).toBe(1);

    // Non-synthetic Slack card contains ZERO sensitive telemetry strings!
    const cardJson = JSON.stringify(postedMessages[0]!.blocks);
    expect(cardJson).not.toContain("CORP-DC099");
    expect(cardJson).not.toContain("svc_backup_secret");

    const actionsBlock = postedMessages[0]!.blocks.find((b) => b.type === "actions") as {
      elements: Array<{ action_id: string; value: string }>;
    };
    const approveBtnValue = actionsBlock.elements[0]!.value;

    // Unauthorized Slack user is blocked!
    await expect(
      bridge.handleBlockAction({
        user: { id: "U99INTRUDER" },
        trigger_id: "trig-bad",
        actions: [{ action_id: "hunt_gate_approve", value: approveBtnValue }],
      }),
    ).rejects.toThrow(/not in allowlisted/);

    // Forged nonce is blocked!
    const forgedValue = JSON.stringify({
      ...(JSON.parse(approveBtnValue) as Record<string, unknown>),
      nonce: "ffffffffffffffffffffffffffffffff",
    });
    await expect(
      bridge.handleBlockAction({
        user: { id: "U01ALLOW99" },
        trigger_id: "trig-forged",
        actions: [{ action_id: "hunt_gate_approve", value: forgedValue }],
      }),
    ).rejects.toThrow(/nonce mismatch/);

    // Step 1: Allowlisted operator clicks Approve -> opens modal with RED non-synthetic warning!
    await bridge.handleBlockAction({
      user: { id: "U01ALLOW99" },
      trigger_id: "trig-ok",
      actions: [{ action_id: "hunt_gate_approve", value: approveBtnValue }],
    });
    expect(openedModals.length).toBe(1);
    const modalJson = JSON.stringify(openedModals[0]!.view);
    expect(modalJson).toContain(NON_SYNTHETIC_MODAL_WARNING_TEXT);

    // Step 2: Operator submits `"What did you check?"` modal -> advances hunt from Gate 1 (`scope`) to Gate 2 (`incident`)!
    await bridge.handleViewSubmission({
      user: { id: "U01ALLOW99" },
      view: {
        callback_id: "hunt_gate_check_note_modal",
        private_metadata: (openedModals[0]!.view.private_metadata as string),
        state: {
          values: {
            check_note_block: {
              check_note_input: {
                value: "Reviewed scope boundaries locally in Desktop; approved Wave 2 launch.",
              },
            },
          },
        },
      },
    });

    expect(updatedMessages.length).toBe(1);
    expect(updatedMessages[0]!.text).toContain("APPROVED");
    const advanced = store.getRun("hunt-slack-01")!;
    expect(advanced.open_gate?.gate).toBe("incident");

    store.close();
  });

  test("Stdio NDJSON LineSplitter, HuntDaemonRpcServer & drive_gates CLI round-trip cleanly", async () => {
    const splitter = new LineSplitter(128);
    const part1 = Buffer.from('{"jsonrpc":"2.0","id":1,', "utf8");
    const part2 = Buffer.from('"method":"daemon.ping"}\r\n', "utf8");
    expect(splitter.push(part1)).toEqual([]);
    expect(splitter.push(part2)).toEqual(['{"jsonrpc":"2.0","id":1,"method":"daemon.ping"}']);
    expect(() => splitter.push("x".repeat(200))).toThrow(/maxLineBytes/);

    const tmp = makeTmpDir();
    const store = new DurableStateStore(path.join(tmp, "rpc.sqlite"));
    const gates = new GateAuthority({
      stateStore: store,
      decisionsDir: path.join(tmp, "decisions"),
    });
    const telemetry = new InMemoryTelemetrySink();
    const engine = new HuntWaveEngine({
      stateStore: store,
      gateAuthority: gates,
      modelRunner: makeStaticRunner(),
      telemetry,
    });

    const outboundLines: string[] = [];
    const dp = makeTestDataPlane(true);
    const rpc = new HuntDaemonRpcServer({
      engine,
      resolveDataPlane: () => dp,
      writeLine: (line) => outboundLines.push(line),
    });
    const unsub = telemetry.subscribe((ev) => rpc.emitTelemetryEvent(ev));

    await rpc.handleChunk('{"jsonrpc":"2.0","id":"p1","method":"daemon.ping"}\n');
    const pingResp = JSON.parse(outboundLines[0]!) as { result: { ok: boolean } };
    expect(pingResp.result.ok).toBe(true);

    outboundLines.length = 0;
    await rpc.handleChunk(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: "s1",
        method: "hunt.start",
        params: {
          run_id: "hunt-rpc-01",
          case_id: "case-syn-99",
          scope: "Synthetic RPC test",
          follow_ups: 0,
        },
      })}\n`,
    );

    // Verify streaming `hunt.event` notifications AND final `RpcResponse` were emitted as valid NDJSON!
    const frames = outboundLines.map((l) => JSON.parse(l.trim()) as Record<string, unknown>);
    expect(frames.some((f) => f.method === "hunt.event")).toBe(true);
    const startResp = frames.find((f) => f.id === "s1") as {
      result: { status: string; open_gate: { gate: string; payload_sha256: string } };
    };
    expect(startResp.result.status).toBe("awaiting_gate");
    expect(startResp.result.open_gate.gate).toBe("scope");

    // Verify `executeDriveGates` blocks automated mode on `scope` and succeeds with authenticated operator + note!
    await expect(
      executeDriveGates(engine, {
        action: "approve",
        huntId: "hunt-rpc-01",
        automated: true,
        operatorToken: gates.sessionAuthority.issueToken("ci", "admin"),
      }),
    ).rejects.toThrow(/forbidden/);

    const gateApprove = await executeDriveGates(engine, {
      action: "approve",
      huntId: "hunt-rpc-01",
      operatorToken: gates.sessionAuthority.issueToken("cli-alice", "analyst"),
      checkNote: "Approved scope via drive_gates.",
    });
    expect(gateApprove.ok).toBe(true);
    expect(gateApprove.open_gate?.gate).toBe("incident");

    unsub();
    store.close();
  });
});
