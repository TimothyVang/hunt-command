/**
 * Adapted from omp-desktop/app/src/main/sidecar/sidecar-manager.ts
 * Copyright (c) omp-desktop contributors (MIT License — see root THIRD-PARTY-NOTICES.md).
 * Modified for Hunt Command v2:
 * - Spawns ONE persistent Bun `hunt-daemon` sidecar (`windowsHide: true`, `PI_NATIVES_DIR`,
 *   stripped paid API keys) speaking JSON-RPC 2.0 (`RpcRequestSchema` / `RpcResponseSchema` /
 *   `RpcEventNotificationSchema`) over stdio NDJSON.
 * - Relays streaming `hunt.event` notifications through the 33ms `EventBatcher`.
 * - Reports `ready` only after the child answers `daemon.ping`. A child that exits (or stays silent)
 *   before its first ping is a deterministic startup failure (bad arguments, missing data plane, held
 *   runtime lock): the sidecar goes `failed` with the daemon's stderr and does NOT restart-loop.
 *   Only a daemon that was serving and then died is restarted with exponential backoff.
 */
import { type ChildProcessWithoutNullStreams, spawn } from "node:child_process";
import {
  RpcEventNotificationSchema,
  RpcResponseSchema,
  type RpcEventNotification,
  type RpcRequest,
} from "@hunt-command/shared";
import type { DaemonHealthStatus } from "../../shared/ipc.ts";
import type { Logger } from "../logger.ts";
import { LineSplitter } from "./framing.ts";
import { buildDaemonChildEnv, type ResolvedDaemonLaunch } from "./resolve-daemon.ts";

export type DaemonProcess = Pick<
  ChildProcessWithoutNullStreams,
  "stdin" | "stdout" | "stderr" | "pid" | "kill"
> & {
  once(event: "exit", listener: (code: number | null, signal: NodeJS.Signals | null) => void): unknown;
  once(event: "error", listener: (error: Error) => void): unknown;
};

export type SpawnDaemonFn = (
  command: string,
  args: string[],
  cwd: string,
  env: NodeJS.ProcessEnv,
) => DaemonProcess;

const defaultSpawnDaemon: SpawnDaemonFn = (command, args, cwd, env) =>
  spawn(command, args, {
    cwd,
    env,
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
    shell: false,
  });

interface PendingRpcCall {
  resolve: (value: unknown) => void;
  reject: (err: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

export interface HuntDaemonSidecarOptions {
  resolveLaunch: () => ResolvedDaemonLaunch;
  runtimeRootDir: string;
  log: Logger;
  spawn?: SpawnDaemonFn;
  onEvent?: (notification: RpcEventNotification["params"]) => void;
  onStatusChanged?: (status: DaemonHealthStatus) => void;
  rpcTimeoutMs?: number;
  /** How long a freshly spawned daemon may take to answer `daemon.ping` (default 30s). */
  readyTimeoutMs?: number;
}

const STDERR_TAIL_LINES = 6;

export class HuntDaemonSidecar {
  readonly #opts: HuntDaemonSidecarOptions;
  readonly #spawn: SpawnDaemonFn;
  readonly #log: Logger;
  readonly #pending = new Map<string | number, PendingRpcCall>();
  #child: DaemonProcess | null = null;
  #status: DaemonHealthStatus["status"] = "starting";
  #restarts = 0;
  #restartTimes: number[] = [];
  #restartTimer: ReturnType<typeof setTimeout> | undefined;
  #piNativesDir: string | null = null;
  #lastError: string | null = null;
  #closing = false;
  #reqSeq = 0;
  #generation = 0;
  #readyGeneration = -1;
  #stderrTail: string[] = [];

  constructor(options: HuntDaemonSidecarOptions) {
    this.#opts = options;
    this.#spawn = options.spawn ?? defaultSpawnDaemon;
    this.#log = options.log.child("hunt-daemon");
  }

  health(): DaemonHealthStatus {
    return {
      status: this.#status,
      pid: this.#child?.pid ?? null,
      restarts: this.#restarts,
      runtimeRootDir: this.#opts.runtimeRootDir,
      piNativesDir: this.#piNativesDir,
      lastError: this.#lastError,
    };
  }

  get isLiveReady(): boolean {
    return this.#status === "ready" && this.#child !== null;
  }

  start(): DaemonHealthStatus {
    this.#closing = false;
    const launch = this.#opts.resolveLaunch();
    this.#piNativesDir = launch.piNativesDir;

    if (!launch.available) {
      this.#status = "standby_fixture";
      this.#lastError = launch.reason ?? null;
      this.#log.info(`Daemon in standby fixture mode: ${launch.reason ?? "unavailable"}`);
      this.#emitStatus();
      return this.health();
    }

    const gen = ++this.#generation;
    const env = buildDaemonChildEnv(process.env, this.#opts.runtimeRootDir, launch.piNativesDir);
    this.#stderrTail = [];

    try {
      const child = this.#spawn(launch.command, launch.args, this.#opts.runtimeRootDir, env);
      this.#child = child;
      this.#status = "starting";
      this.#lastError = null;
      this.#log.info(
        `Spawned hunt-daemon pid=${child.pid ?? "?"} (${launch.source}) args=${JSON.stringify(launch.args)}`,
      );
      this.#wireChild(child, gen);
      this.#emitStatus();
      void this.#awaitReady(child, gen);
    } catch (err) {
      this.#status = "failed";
      this.#lastError = err instanceof Error ? err.message : String(err);
      this.#log.error(`Failed to spawn hunt-daemon: ${this.#lastError}`);
      this.#emitStatus();
    }

    return this.health();
  }

  async restart(): Promise<DaemonHealthStatus> {
    clearTimeout(this.#restartTimer);
    await this.stop();
    this.#restartTimes = [];
    this.#status = "restarting";
    this.#emitStatus();
    return this.start();
  }

  async stop(): Promise<void> {
    this.#closing = true;
    clearTimeout(this.#restartTimer);
    this.#generation += 1;
    this.#rejectAllPending(new Error("hunt-daemon stopping"));
    const child = this.#child;
    this.#child = null;
    if (!child) {
      return;
    }
    await new Promise<void>((resolve) => {
      let settled = false;
      const done = () => {
        if (!settled) {
          settled = true;
          resolve();
        }
      };
      child.once("exit", done);
      try {
        child.stdin.end();
      } catch {
        // Ignore broken pipe.
      }
      const killTimer = setTimeout(() => {
        try {
          child.kill();
        } catch {
          // Ignore already exited.
        }
        done();
      }, 2_500);
      child.once("exit", () => clearTimeout(killTimer));
    });
  }

  request<T = unknown>(method: string, params?: Record<string, unknown>): Promise<T> {
    const child = this.#child;
    if (!child || this.#status !== "ready") {
      return Promise.reject(new Error(`hunt-daemon is not ready (status=${this.#status})`));
    }
    return this.#send<T>(child, method, params, this.#opts.rpcTimeoutMs ?? 30_000);
  }

  async #awaitReady(child: DaemonProcess, gen: number): Promise<void> {
    const timeoutMs = this.#opts.readyTimeoutMs ?? 30_000;
    try {
      await this.#send(child, "daemon.ping", undefined, timeoutMs);
    } catch (err) {
      if (gen !== this.#generation || this.#closing) return;
      // Still running but not answering: a startup failure, not a crash worth restarting.
      this.#generation += 1;
      this.#child = null;
      this.#failStartup(`did not answer daemon.ping (${err instanceof Error ? err.message : String(err)})`);
      try {
        child.kill();
      } catch {
        // Already gone.
      }
      return;
    }
    if (gen !== this.#generation || this.#closing) return;
    this.#readyGeneration = gen;
    this.#status = "ready";
    this.#lastError = null;
    this.#log.info(`hunt-daemon pid=${child.pid ?? "?"} answered daemon.ping; serving`);
    this.#emitStatus();
  }

  #failStartup(reason: string): void {
    const stderr = this.#stderrTail.join(" | ");
    this.#status = "failed";
    this.#lastError = `startup failed: ${reason}${stderr ? `; stderr: ${stderr}` : ""}`;
    this.#rejectAllPending(new Error(`hunt-daemon ${this.#lastError}`));
    this.#log.error(`hunt-daemon ${this.#lastError} (not restarting; use daemon:restart after fixing)`);
    this.#emitStatus();
  }

  #send<T>(
    child: DaemonProcess,
    method: string,
    params: Record<string, unknown> | undefined,
    timeoutMs: number,
  ): Promise<T> {
    const id = ++this.#reqSeq;
    const frame: RpcRequest = {
      jsonrpc: "2.0",
      id,
      method,
      ...(params ? { params } : {}),
    };

    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(new Error(`RPC request '${method}' timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      this.#pending.set(id, {
        resolve: resolve as (value: unknown) => void,
        reject,
        timer,
      });

      try {
        child.stdin.write(`${JSON.stringify(frame)}\n`, "utf8");
      } catch (err) {
        clearTimeout(timer);
        this.#pending.delete(id);
        reject(err instanceof Error ? err : new Error(String(err)));
      }
    });
  }

  #wireChild(child: DaemonProcess, gen: number): void {
    const splitter = new LineSplitter(
      (lineBuf) => {
        if (gen !== this.#generation) return;
        this.#handleLine(lineBuf.toString("utf8"));
      },
      (bytes) => {
        this.#log.warn(`Discarded oversized NDJSON frame from hunt-daemon (${bytes} bytes)`);
      },
    );

    child.stdout.on("data", (chunk: Buffer) => splitter.push(chunk));
    child.stdout.once("end", () => splitter.end());
    child.stderr.on("data", (chunk: Buffer) => {
      const text = chunk.toString("utf8").trim();
      if (text.length > 0) {
        this.#log.warn(`stderr: ${text.slice(0, 300)}`);
        if (gen === this.#generation) {
          for (const line of text.split(/\r?\n/)) {
            if (line.trim().length === 0) continue;
            this.#stderrTail.push(line.trim().slice(0, 300));
          }
          this.#stderrTail = this.#stderrTail.slice(-STDERR_TAIL_LINES);
        }
      }
    });

    child.once("error", (err) => this.#handleExit(gen, `process error: ${err.message}`));
    child.once("exit", (code, signal) =>
      this.#handleExit(gen, `exited (code=${code ?? "null"}, signal=${signal ?? "none"})`),
    );
  }

  #handleLine(line: string): void {
    const trimmed = line.trim();
    if (trimmed.length === 0) return;

    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      this.#log.warn("Invalid JSON line from hunt-daemon");
      return;
    }

    const eventCheck = RpcEventNotificationSchema.safeParse(parsed);
    if (eventCheck.success) {
      this.#opts.onEvent?.(eventCheck.data.params);
      return;
    }

    const respCheck = RpcResponseSchema.safeParse(parsed);
    if (respCheck.success) {
      const resp = respCheck.data;
      const pending = this.#pending.get(resp.id);
      if (!pending) return;
      clearTimeout(pending.timer);
      this.#pending.delete(resp.id);
      if (resp.error) {
        pending.reject(
          new Error(
            resp.error.error_code
              ? `${resp.error.error_code}: ${resp.error.message}`
              : resp.error.message,
          ),
        );
      } else {
        pending.resolve(resp.result);
      }
    }
  }

  #handleExit(gen: number, reason: string): void {
    if (gen !== this.#generation || this.#closing) {
      return;
    }
    this.#generation += 1;
    this.#child = null;

    if (this.#readyGeneration !== gen) {
      // Never served: deterministic startup failure. Surface it instead of restart-looping.
      this.#failStartup(`${reason} before answering daemon.ping`);
      return;
    }

    this.#lastError = reason;
    this.#rejectAllPending(new Error(`hunt-daemon ${reason}`));

    const now = Date.now();
    this.#restartTimes = this.#restartTimes.filter((t) => now - t < 120_000);
    if (this.#restartTimes.length >= 5) {
      this.#status = "failed";
      this.#lastError = `${reason} (exceeded max 5 restarts in 120s)`;
      this.#emitStatus();
      return;
    }

    const delayMs = Math.min(8_000, 500 * 2 ** this.#restartTimes.length);
    this.#restartTimes.push(now);
    this.#restarts += 1;
    this.#status = "restarting";
    this.#emitStatus();

    this.#restartTimer = setTimeout(() => {
      if (!this.#closing) {
        this.start();
      }
    }, delayMs);
  }

  #rejectAllPending(err: Error): void {
    for (const [, p] of this.#pending) {
      clearTimeout(p.timer);
      p.reject(err);
    }
    this.#pending.clear();
  }

  #emitStatus(): void {
    this.#opts.onStatusChanged?.(this.health());
  }
}
