#!/usr/bin/env bun
import path from "node:path";
import { resolveRuntimeDir } from "@hunt-command/shared";
import { executeDriveGates } from "./drive-gates.ts";
import {
  GateAuthority,
  OperatorSessionAuthority,
  RBAC_ROLES,
  loadOrCreateOperatorSessionSecret,
  type RbacRole,
} from "./gates.ts";
import { OmpHunterPool } from "./omp-pool.ts";
import { createCaseDirDataPlaneResolver } from "./case-data-plane.ts";
import { InMemoryTelemetrySink, type ModelRunnerPort } from "./ports.ts";
import { HuntDaemonRpcServer } from "./rpc-server.ts";
import { acquireRuntimeLock, RuntimeLockHeldError, type RuntimeLockHandle } from "./runtime-lock.ts";
import { DurableStateStore } from "./state-store.ts";
import { HuntWaveEngine, type DataPlaneResolver } from "./wave-engine.ts";

export interface CreateDaemonContextOptions {
  readonly runtimeDir?: string;
  readonly subscriptionOnly?: boolean;
  readonly productionMode?: boolean;
  readonly resolveDataPlane?: DataPlaneResolver;
  /** Model runner for hunt steps (defaults to the subscription-only `OmpHunterPool`). */
  readonly modelRunner?: ModelRunnerPort;
  /**
   * Reconcile interrupted in-flight runs from a prior daemon crash. ONLY the single-instance
   * `serve` process (holding the runtime lock) may set this; read-only commands never do.
   */
  readonly recoverOnStartup?: boolean;
}

export const RUNTIME_LOCK_FILE = "hunt-daemon.lock";
export const OPERATOR_SESSION_SECRET_FILE = "operator-session.secret";

export function runtimeLockPath(stateDir: string): string {
  return path.join(stateDir, RUNTIME_LOCK_FILE);
}

export function createHuntDaemonRuntime(options?: CreateDaemonContextOptions) {
  const paths = resolveRuntimeDir(options?.runtimeDir);
  const stateStore = new DurableStateStore(paths.daemonStateDbPath);
  const gateAuthority = new GateAuthority({
    stateStore,
    decisionsDir: paths.decisionsDir,
    decisionsLogPath: paths.decisionsLogPath,
    productionMode: options?.productionMode ?? true,
    // Shared across processes on this runtime dir so locally issued operator tokens verify.
    sessionAuthority: new OperatorSessionAuthority(
      loadOrCreateOperatorSessionSecret(path.join(paths.stateDir, OPERATOR_SESSION_SECRET_FILE)),
    ),
  });
  const telemetry = new InMemoryTelemetrySink();
  const modelRunner =
    options?.modelRunner ??
    new OmpHunterPool({
      subscriptionOnly: options?.subscriptionOnly ?? true,
    });
  const engine = new HuntWaveEngine({
    stateStore,
    gateAuthority,
    modelRunner,
    telemetry,
    resolveDataPlane: options?.resolveDataPlane,
  });

  const recoveredRuns = options?.recoverOnStartup ? engine.recoverInFlightRunsOnStartup() : [];

  return {
    paths,
    stateStore,
    gateAuthority,
    telemetry,
    modelRunner,
    engine,
    recoveredRuns,
  };
}

export interface RunHuntCliOptions {
  /**
   * Case data-plane factory for `serve` (`hunt.start`, `hunt.resume`, gate resumption).
   * Defaults to the embedded data plane over `--cases-dir` (default `<runtimeDir>/cases`),
   * opening `<casesDir>/<caseId>`.
   */
  readonly resolveDataPlane?: DataPlaneResolver;
  /** Model runner for `serve` (defaults to the subscription-only `OmpHunterPool`). */
  readonly modelRunner?: ModelRunnerPort;
  /** Input stream for `serve` (defaults to `process.stdin`). */
  readonly stdin?: AsyncIterable<Uint8Array | Buffer | string>;
}

function parseCliFlags(args: readonly string[]): Record<string, string | boolean> {
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < args.length; i++) {
    const token = args[i]!;
    if (!token.startsWith("--")) continue;
    const key = token.slice(2);
    const next = args[i + 1];
    if (next !== undefined && !next.startsWith("--")) {
      flags[key] = next;
      i += 1;
    } else {
      flags[key] = true;
    }
  }
  return flags;
}

export interface HuntCliIo {
  writeStdout: (text: string) => void;
  writeStderr: (text: string) => void;
}

/** One stderr line for a refused or failed command; the stack only with `HUNT_DEBUG=1`. */
export function formatCliError(err: unknown): string {
  if (!(err instanceof Error)) {
    return `hunt: ${String(err)}`;
  }
  const code = (err as { code?: unknown; errorCode?: unknown }).errorCode ?? (err as { code?: unknown }).code;
  const firstLine = err.message.split(/\r?\n/, 1)[0] ?? "";
  return `hunt: ${typeof code === "string" ? `${code}: ` : ""}${firstLine}`;
}

/**
 * CLI entry point. Every refusal (unknown hunt, runtime dir inside a Git tree, rejected gate
 * decision, ...) is reported as one stderr line and a non-zero exit code, never a stack trace.
 */
export async function runHuntCli(
  argv: readonly string[],
  io: HuntCliIo = {
    writeStdout: (t) => process.stdout.write(t),
    writeStderr: (t) => process.stderr.write(t),
  },
  options: RunHuntCliOptions = {},
): Promise<number> {
  try {
    return await runHuntCommand(argv, io, options);
  } catch (err) {
    io.writeStderr(`${formatCliError(err)}\n`);
    if (process.env.HUNT_DEBUG === "1" && err instanceof Error && err.stack) {
      io.writeStderr(`${err.stack}\n`);
    }
    return 1;
  }
}

async function runHuntCommand(
  argv: readonly string[],
  io: HuntCliIo,
  options: RunHuntCliOptions,
): Promise<number> {
  const subcommand = argv[0] ?? "help";
  const flags = parseCliFlags(argv.slice(1));
  const runtimeDir = typeof flags["runtime-dir"] === "string" ? flags["runtime-dir"] : undefined;

  if (subcommand === "help" || subcommand === "--help" || subcommand === "-h") {
    io.writeStdout(
      [
        "Hunt Command Daemon CLI (@hunt-command/daemon)",
        "Usage:",
        "  hunt-daemon serve [--runtime-dir <dir>] [--cases-dir <dir>]",
        "  hunt status --hunt-id <id> [--runtime-dir <dir>]",
        "  hunt cancel --hunt-id <id> [--reason <text>] [--runtime-dir <dir>]",
        "  hunt token --principal <id> --role <admin|analyst|reviewer|viewer> [--ttl-hours <n>] [--runtime-dir <dir>]",
        "  hunt gates <status|approve|deny> --hunt-id <id> [--gate <name>] --token <operator-token> [--note <text>] [--digest <sha256>] [--runtime-dir <dir>]",
        "",
        "cancel and gates approve/deny refuse to run while hunt-daemon serves the same runtime dir.",
        "",
      ].join("\n"),
    );
    return 0;
  }

  if (subcommand === "serve") {
    return serveDaemon(runtimeDir, flags, io, options);
  }

  const gateAction = subcommand === "gates" ? argv[1] : undefined;
  const mutates = subcommand === "cancel" || (subcommand === "gates" && gateAction !== "status");

  // Mutating commands take the same exclusive runtime lock as `serve`, so they can never
  // race a live daemon's in-flight state. Read-only commands never take it and never mutate.
  let lock: RuntimeLockHandle | null = null;
  if (mutates) {
    try {
      lock = acquireRuntimeLock(runtimeLockPath(resolveRuntimeDir(runtimeDir).stateDir));
    } catch (err) {
      if (err instanceof RuntimeLockHeldError) {
        io.writeStderr(
          `${err.message}\nhunt-daemon is serving this runtime dir; send this action through its RPC instead.\n`,
        );
        return 1;
      }
      throw err;
    }
  }

  let ctx: ReturnType<typeof createHuntDaemonRuntime>;
  try {
    ctx = createHuntDaemonRuntime({
      runtimeDir,
      productionMode: flags["non-prod"] !== true,
      resolveDataPlane: options.resolveDataPlane,
    });
  } catch (err) {
    lock?.release();
    throw err;
  }

  try {
    if (subcommand === "status") {
      const huntId = typeof flags["hunt-id"] === "string" ? flags["hunt-id"] : "";
      if (!huntId) {
        io.writeStderr("Missing required --hunt-id <id>\n");
        return 2;
      }
      const run = ctx.stateStore.getRun(huntId);
      if (!run) {
        io.writeStderr(`Unknown hunt '${huntId}'\n`);
        return 1;
      }
      io.writeStdout(`${JSON.stringify(run, null, 2)}\n`);
      return 0;
    }

    if (subcommand === "cancel") {
      const huntId = typeof flags["hunt-id"] === "string" ? flags["hunt-id"] : "";
      if (!huntId) {
        io.writeStderr("Missing required --hunt-id <id>\n");
        return 2;
      }
      const reason = typeof flags["reason"] === "string" ? flags["reason"] : "global_stop";
      const cancelled = ctx.engine.cancelRun(huntId, reason);
      io.writeStdout(`${JSON.stringify(cancelled, null, 2)}\n`);
      return 0;
    }

    if (subcommand === "token") {
      const principal = typeof flags["principal"] === "string" ? flags["principal"] : "";
      const role = typeof flags["role"] === "string" ? flags["role"] : "";
      if (!principal.trim() || !(RBAC_ROLES as readonly string[]).includes(role)) {
        io.writeStderr(
          `Usage: hunt token --principal <id> --role <${RBAC_ROLES.join("|")}> [--ttl-hours <n>]\n`,
        );
        return 2;
      }
      const ttlHours = typeof flags["ttl-hours"] === "string" ? Number(flags["ttl-hours"]) : 12;
      if (!Number.isFinite(ttlHours) || ttlHours <= 0 || ttlHours > 24) {
        io.writeStderr("--ttl-hours must be in (0, 24]\n");
        return 2;
      }
      const token = ctx.gateAuthority.sessionAuthority.issueToken(
        principal,
        role as RbacRole,
        Math.round(ttlHours * 60 * 60 * 1000),
      );
      io.writeStdout(`${token}\n`);
      return 0;
    }

    if (subcommand === "gates") {
      const actionRaw = gateAction;
      if (
        actionRaw !== "status" &&
        actionRaw !== "approve" &&
        actionRaw !== "reject" &&
        actionRaw !== "deny"
      ) {
        io.writeStderr("Usage: hunt gates <status|approve|reject|deny> --hunt-id <id> ...\n");
        return 2;
      }
      const gateFlags = parseCliFlags(argv.slice(2));
      const huntId = typeof gateFlags["hunt-id"] === "string" ? gateFlags["hunt-id"] : "";
      if (!huntId) {
        io.writeStderr("Missing required --hunt-id <id>\n");
        return 2;
      }
      const res = await executeDriveGates(ctx.engine, {
        action: actionRaw,
        huntId,
        gate: typeof gateFlags["gate"] === "string" ? gateFlags["gate"] : undefined,
        operatorToken: typeof gateFlags["token"] === "string" ? gateFlags["token"] : undefined,
        checkNote: typeof gateFlags["note"] === "string" ? gateFlags["note"] : undefined,
        payloadSha256: typeof gateFlags["digest"] === "string" ? gateFlags["digest"] : undefined,
        automated: gateFlags["automated"] === true,
        delegatedBy:
          typeof gateFlags["delegated-by"] === "string" ? gateFlags["delegated-by"] : undefined,
        delegationReason:
          typeof gateFlags["reason"] === "string" ? gateFlags["reason"] : undefined,
      });
      io.writeStdout(`${JSON.stringify(res, null, 2)}\n`);
      return res.ok ? 0 : 1;
    }

    io.writeStderr(`Unknown command '${subcommand}'\n`);
    return 2;
  } finally {
    ctx.stateStore.close();
    lock?.release();
  }
}

async function serveDaemon(
  runtimeDir: string | undefined,
  flags: Record<string, string | boolean>,
  io: { writeStdout: (text: string) => void; writeStderr: (text: string) => void },
  options: RunHuntCliOptions,
): Promise<number> {
  if (flags["cases-dir"] === true) {
    io.writeStderr("hunt-daemon serve: --cases-dir requires a directory\n");
    return 2;
  }
  const paths = resolveRuntimeDir(runtimeDir);

  let lock: RuntimeLockHandle;
  try {
    lock = acquireRuntimeLock(runtimeLockPath(paths.stateDir));
  } catch (err) {
    if (err instanceof RuntimeLockHeldError) {
      io.writeStderr(`hunt-daemon serve: ${err.message}\n`);
      return 1;
    }
    throw err;
  }
  const releaseOnExit = () => lock.release();
  process.once("exit", releaseOnExit);

  const defaultResolver = options.resolveDataPlane
    ? null
    : createCaseDirDataPlaneResolver({
        casesDir: typeof flags["cases-dir"] === "string" ? flags["cases-dir"] : paths.casesDir,
        cacheDir: path.join(paths.rootDir, "case-cache"),
      });
  const resolveDataPlane = options.resolveDataPlane ?? defaultResolver!.resolve;

  try {
    // Only the lock-holding serve process reconciles interrupted in-flight runs.
    const ctx = createHuntDaemonRuntime({
      runtimeDir,
      productionMode: flags["non-prod"] !== true,
      resolveDataPlane,
      modelRunner: options.modelRunner,
      recoverOnStartup: true,
    });
    const resumable = ctx.engine.listResumableRuns();
    if (ctx.recoveredRuns.length > 0 || resumable.length > 0) {
      io.writeStderr(
        `hunt-daemon serve: ${ctx.recoveredRuns.length} run(s) parked behind a reconcile gate; ` +
          `${resumable.length} run(s) resumable via hunt.resume: ${resumable.map((r) => r.run_id).join(", ")}\n`,
      );
    }
    const rpc = new HuntDaemonRpcServer({
      engine: ctx.engine,
      resolveDataPlane,
      writeLine: (line) => io.writeStdout(line),
    });
    const unsub = ctx.telemetry.subscribe((ev) => rpc.emitTelemetryEvent(ev));
    const pending = new Set<Promise<void>>();
    let dispatchError: unknown;
    try {
      try {
        for await (const chunk of options.stdin ?? process.stdin) {
          const task = rpc.handleChunk(chunk as Buffer).catch((err: unknown) => {
            dispatchError ??= err;
          });
          pending.add(task);
          void task.then(() => pending.delete(task));
        }
      } finally {
        await Promise.all(pending);
      }
      if (dispatchError) throw dispatchError;
    } finally {
      unsub();
      ctx.stateStore.close();
    }
    return 0;
  } finally {
    await defaultResolver?.close();
    process.removeListener("exit", releaseOnExit);
    lock.release();
  }
}

if (import.meta.main) {
  const code = await runHuntCli(process.argv.slice(2));
  process.exit(code);
}
