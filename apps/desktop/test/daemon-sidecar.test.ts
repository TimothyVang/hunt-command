import { describe, expect, test } from "bun:test";
import { EventEmitter } from "node:events";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import { resolveRuntimeDir } from "@hunt-command/shared";
import {
  createCaseDirDataPlaneResolver,
  DurableStateStore,
  GateAuthority,
  HuntDaemonRpcServer,
  HuntWaveEngine,
  InMemoryTelemetrySink,
  type ModelRunnerPort,
  type ModelTurnRequest,
  type StepTurnResult,
} from "../../../packages/daemon/src/index.ts";
import {
  type DaemonProcess,
  HuntDaemonSidecar,
  type SpawnDaemonFn,
} from "../src/main/daemon/daemon-sidecar.ts";
import { resolveDaemonLaunch, resolvePiNativesDir } from "../src/main/daemon/resolve-daemon.ts";
import type { Logger } from "../src/main/logger.ts";
import { WorkbenchService, type WorkbenchServiceDeps } from "../src/main/workbench-service.ts";

const silentLog: Logger = {
  debug() {},
  info() {},
  warn() {},
  error() {},
  child() {
    return silentLog;
  },
} as unknown as Logger;

interface FakeChild extends Omit<DaemonProcess, "stdout" | "stderr"> {
  stdout: PassThrough;
  stderr: PassThrough;
  exitWith(code: number): void;
  stdinLines: string[];
}

/** A fake `hunt-daemon` child: `behaviour` decides how it reacts to each NDJSON request line. */
function fakeChild(behaviour: (line: string, child: FakeChild) => void): FakeChild {
  const events = new EventEmitter();
  const stdin = new PassThrough();
  const stdout = new PassThrough();
  const stderr = new PassThrough();
  let exited = false;
  const child = {
    stdin,
    stdout,
    stderr,
    pid: 4242,
    stdinLines: [] as string[],
    kill: () => {
      child.exitWith(1);
      return true;
    },
    once: (event: string, listener: (...args: unknown[]) => void) => events.once(event, listener),
    exitWith: (code: number) => {
      if (exited) return;
      exited = true;
      setTimeout(() => events.emit("exit", code, null), 0);
    },
  } as unknown as FakeChild;
  let buf = "";
  stdin.on("data", (chunk: Buffer) => {
    buf += chunk.toString("utf8");
    let nl = buf.indexOf("\n");
    while (nl >= 0) {
      const line = buf.slice(0, nl);
      buf = buf.slice(nl + 1);
      child.stdinLines.push(line);
      behaviour(line, child);
      nl = buf.indexOf("\n");
    }
  });
  return child;
}

function waitFor(predicate: () => boolean, timeoutMs = 3_000): Promise<void> {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const tick = () => {
      if (predicate()) return resolve();
      if (Date.now() - started > timeoutMs) return reject(new Error("waitFor timed out"));
      setTimeout(tick, 10);
    };
    tick();
  });
}

const launch = () => ({
  available: true,
  command: "hunt-daemon",
  args: ["serve", "--runtime-dir", "C:/rt"],
  piNativesDir: null,
  source: "packaged_exe" as const,
});

describe("hunt-daemon sidecar", () => {
  test("a daemon that exits before answering daemon.ping fails once and does not restart-loop", async () => {
    let spawns = 0;
    const spawn: SpawnDaemonFn = () => {
      spawns += 1;
      const child = fakeChild(() => {});
      setTimeout(() => {
        child.stderr.write("Unknown command '--rpc'\n");
        child.exitWith(2);
      }, 5);
      return child;
    };
    const sidecar = new HuntDaemonSidecar({ resolveLaunch: launch, runtimeRootDir: "C:/rt", log: silentLog, spawn });
    sidecar.start();
    expect(sidecar.health().status).toBe("starting");
    await waitFor(() => sidecar.health().status === "failed");
    // The old policy restarted after 500ms; wait well past that and the first backoff steps.
    await new Promise((r) => setTimeout(r, 1_800));
    expect(spawns).toBe(1);
    const health = sidecar.health();
    expect(health.status).toBe("failed");
    expect(health.restarts).toBe(0);
    expect(health.lastError).toContain("exited (code=2");
    expect(health.lastError).toContain("Unknown command '--rpc'");
    expect(sidecar.isLiveReady).toBe(false);
    await sidecar.stop();
  });

  test("reports ready only after daemon.ping is answered, and restarts a daemon that crashed while serving", async () => {
    let spawns = 0;
    const children: FakeChild[] = [];
    const spawn: SpawnDaemonFn = () => {
      spawns += 1;
      const child = fakeChild((line, self) => {
        const req = JSON.parse(line) as { id: number; method: string };
        if (req.method === "daemon.ping") {
          self.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id: req.id, result: { ok: true } })}\n`);
        }
      });
      children.push(child);
      return child;
    };
    const sidecar = new HuntDaemonSidecar({ resolveLaunch: launch, runtimeRootDir: "C:/rt", log: silentLog, spawn });
    sidecar.start();
    await waitFor(() => sidecar.health().status === "ready");
    expect(children[0]!.stdinLines.map((l) => JSON.parse(l).method)).toEqual(["daemon.ping"]);
    expect(sidecar.isLiveReady).toBe(true);

    children[0]!.exitWith(137);
    await waitFor(() => sidecar.health().status === "restarting");
    await waitFor(() => spawns === 2 && sidecar.health().status === "ready", 4_000);
    expect(sidecar.health().restarts).toBe(1);
    await sidecar.stop();
  });

  test("a daemon that never answers daemon.ping is failed and killed, not left 'ready'", async () => {
    let killed = 0;
    const spawn: SpawnDaemonFn = () => {
      const child = fakeChild(() => {});
      const kill = child.kill.bind(child);
      (child as { kill: () => boolean }).kill = () => {
        killed += 1;
        return kill();
      };
      return child;
    };
    const sidecar = new HuntDaemonSidecar({
      resolveLaunch: launch,
      runtimeRootDir: "C:/rt",
      log: silentLog,
      spawn,
      readyTimeoutMs: 100,
    });
    sidecar.start();
    await waitFor(() => sidecar.health().status === "failed");
    expect(sidecar.health().lastError).toContain("did not answer daemon.ping");
    expect(killed).toBe(1);
    await sidecar.stop();
  });
});

test("live workbench uses the real daemon for metadata, authenticated gates, and stop", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "hc-live-workbench-"));
  const caseId = "integration-case";
  const caseDir = path.join(root, "cases", caseId);
  fs.mkdirSync(caseDir, { recursive: true });
  fs.writeFileSync(path.join(caseDir, "case.json"), JSON.stringify({
    case_id: caseId,
    question: "Which host ran the process?",
    data_origin: "synthetic",
    time_range_utc: { start_inclusive: "2026-11-14T10:00:00Z", end_exclusive: "2026-11-14T11:00:00Z" },
  }));
  fs.writeFileSync(path.join(caseDir, "events.jsonl"), JSON.stringify({
    "@timestamp": "2026-11-14T10:01:00Z", event: { id: "evt-1", code: "1" },
    host: { name: "integration-host" }, message: "Process executed.",
  }) + "\n");

  const resolver = createCaseDirDataPlaneResolver({ casesDir: path.join(root, "cases"), cacheDir: path.join(root, "cache") });
  const store = new DurableStateStore(path.join(root, "state.sqlite"));
  const gates = new GateAuthority({ stateStore: store, decisionsDir: path.join(root, "decisions") });
  const telemetry = new InMemoryTelemetrySink();
  const runner: ModelRunnerPort = {
    getPinnedModelForRole: () => ({ provider: "anthropic", model: "test-model", fallback_providers: [] }),
    preflightWave: async () => {},
    runTurn: async (req: ModelTurnRequest): Promise<StepTurnResult> => ({
      status: "completed",
      output_text: JSON.stringify({
        schema_version: 1, case_id: req.caseId, step_id: req.stepId, profile: req.profile,
        claims: [{
          claim_id: `${req.stepId}:c1`, kind: req.stepId === "incident" ? "finding" : "observed",
          statement: "The process was observed.", evidence_ids: ["events.jsonl"],
          entity_ids: [], contradicts: [],
        }],
        reviews: [], disposition: "review_ready", limitations: [], requested_decisions: [],
      }),
      usage: {
        input_tokens: 100, output_tokens: 50, cache_read_tokens: 0, cache_write_tokens: 0,
        total_tokens: 150, turns: 1, provider: "anthropic", model: "test-model",
        billing_mode: "oauth_subscription", actual_billed_usd: 0, shadow_api_usd: 0.001, cache_savings_usd: 0,
      },
    }),
  };
  const engine = new HuntWaveEngine({ stateStore: store, gateAuthority: gates, modelRunner: runner, telemetry, resolveDataPlane: resolver.resolve });
  let child!: FakeChild;
  const pending: Promise<unknown>[] = [];
  const rpc = new HuntDaemonRpcServer({
    engine,
    resolveDataPlane: resolver.resolve,
    writeLine: (line) => child.stdout.write(line),
  });
  const unsubscribe = telemetry.subscribe((event) => rpc.emitTelemetryEvent(event));
  const sidecar = new HuntDaemonSidecar({
    resolveLaunch: launch, runtimeRootDir: root, log: silentLog,
    spawn: () => {
      child = fakeChild((line) => { pending.push(rpc.handleLine(line)); });
      return child;
    },
  });
  try {
    sidecar.start();
    await waitFor(() => sidecar.isLiveReady);
    const runtimePaths = resolveRuntimeDir(path.join(root, "runtime"), { repoRoot: path.resolve(import.meta.dir, "../../..") });
    const service = new WorkbenchService({ runtimePaths, sidecar, vault: {} as WorkbenchServiceDeps["vault"] });
    const started = await service.startRun({
      caseId, dataOrigin: "synthetic", scope: "Investigate the process.", followUps: 0, maxTotalTokens: 100_000,
    });
    expect(started.provenanceMode).toBe("live_daemon");
    expect(started.caseMetadata).toEqual((await resolver.resolve(caseId)).caseMetadata);
    expect(started.runStatus).toBe("awaiting_human_gate");
    expect(started.activeGate?.gate).toBe("scope");
    expect(started.activeGate?.payloadSha256).toBe(store.getRun(started.huntId)!.open_gate!.payload_sha256);

    const decision = {
      huntId: started.huntId, gate: "scope", action: "approve", operatorName: "forged-name",
      rbacRole: "incident_commander", checkNote: "Reviewed the scope.",
      payloadSha256: started.activeGate!.payloadSha256,
    };
    await expect(service.submitGateDecision({ ...decision, operatorToken: "invalid-token" })).rejects.toThrow();
    expect(store.getRun(started.huntId)!.decisions).toHaveLength(0);
    const approved = await service.submitGateDecision({
      ...decision, operatorToken: gates.sessionAuthority.issueToken("real-analyst", "analyst"),
    });
    expect(approved.activeGate?.gate).toBe("incident");
    expect(approved.gateHistory[0]?.decided_by).toBe("real-analyst");
    expect(approved.gateHistory[0]?.rbac_role).toBe("analyst");
    const stopped = await service.globalStop({ huntId: started.huntId, reason: "operator_global_stop" });
    expect(stopped.runStatus).toBe("stopped");
    expect(stopped.activeGate).toBeNull();
    expect(store.getRun(started.huntId)!.status).toBe("cancelled");
    expect((await service.getWorkbenchState({ huntId: started.huntId })).runStatus).toBe("stopped");
  } finally {
    await sidecar.stop();
    await Promise.allSettled(pending);
    unsubscribe();
    store.close();
    await resolver.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

describe("resolveDaemonLaunch", () => {
  test("launches `serve --runtime-dir <dir>` (never `--rpc`) for workspace bun and packaged exe", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hc-resolve-"));
    try {
      const cli = path.join(root, "packages", "daemon", "src", "cli.ts");
      fs.mkdirSync(path.dirname(cli), { recursive: true });
      fs.writeFileSync(cli, "");
      const runtimeDir = path.join(root, "rt");
      const ws = resolveDaemonLaunch({
        isPackaged: false,
        repoRoot: root,
        runtimeDir,
        casesDir: path.join(root, "cases"),
        findBun: () => "C:/bun/bun.exe",
      });
      expect(ws.source).toBe("workspace_bun");
      expect(ws.args).toEqual(["run", cli, "serve", "--runtime-dir", runtimeDir, "--cases-dir", path.join(root, "cases")]);

      const resources = path.join(root, "resources");
      const exe = path.join(resources, "hunt-daemon", process.platform === "win32" ? "hunt-daemon.exe" : "hunt-daemon");
      fs.mkdirSync(path.dirname(exe), { recursive: true });
      fs.writeFileSync(exe, "");
      const packaged = resolveDaemonLaunch({ isPackaged: true, resourcesPath: resources, repoRoot: root, runtimeDir });
      expect(packaged.source).toBe("packaged_exe");
      expect(packaged.args).toEqual(["serve", "--runtime-dir", runtimeDir]);
      expect([...ws.args, ...packaged.args]).not.toContain("--rpc");
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  test("resolvePiNativesDir finds the addon in bun's isolated node_modules/.bun layout", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hc-natives-"));
    try {
      expect(resolvePiNativesDir({ isPackaged: false, repoRoot: root })).toBeNull();
      const pkgDir = path.join(
        root,
        "node_modules",
        ".bun",
        "@oh-my-pi+pi-natives-win32-x64@18.20.0",
        "node_modules",
        "@oh-my-pi",
        "pi-natives-win32-x64",
      );
      fs.mkdirSync(pkgDir, { recursive: true });
      fs.writeFileSync(path.join(pkgDir, "pi_natives.win32-x64-baseline.node"), "");
      expect(resolvePiNativesDir({ isPackaged: false, repoRoot: root })).toBe(pkgDir);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});
