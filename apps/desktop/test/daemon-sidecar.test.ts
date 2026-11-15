import { describe, expect, test } from "bun:test";
import { EventEmitter } from "node:events";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import {
  type DaemonProcess,
  HuntDaemonSidecar,
  type SpawnDaemonFn,
} from "../src/main/daemon/daemon-sidecar.ts";
import { resolveDaemonLaunch, resolvePiNativesDir } from "../src/main/daemon/resolve-daemon.ts";
import type { Logger } from "../src/main/logger.ts";

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
