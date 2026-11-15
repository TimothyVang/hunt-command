#!/usr/bin/env bun
import { resolveRuntimeDir } from "@hunt-command/shared";
import { executeDriveGates } from "./drive-gates.ts";
import { GateAuthority, type RbacRole } from "./gates.ts";
import { OmpHunterPool } from "./omp-pool.ts";
import { InMemoryTelemetrySink, type HuntDataPlanePort } from "./ports.ts";
import { HuntDaemonRpcServer } from "./rpc-server.ts";
import { DurableStateStore } from "./state-store.ts";
import { HuntWaveEngine } from "./wave-engine.ts";

export interface CreateDaemonContextOptions {
  readonly runtimeDir?: string;
  readonly subscriptionOnly?: boolean;
  readonly productionMode?: boolean;
  readonly resolveDataPlane?: (caseId: string) => Promise<HuntDataPlanePort> | HuntDataPlanePort;
}

export function createHuntDaemonRuntime(options?: CreateDaemonContextOptions) {
  const paths = resolveRuntimeDir(options?.runtimeDir);
  const stateStore = new DurableStateStore(paths.daemonStateDbPath);
  const gateAuthority = new GateAuthority({
    stateStore,
    decisionsDir: paths.decisionsDir,
    decisionsLogPath: paths.decisionsLogPath,
    productionMode: options?.productionMode ?? true,
  });
  const telemetry = new InMemoryTelemetrySink();
  const modelRunner = new OmpHunterPool({
    subscriptionOnly: options?.subscriptionOnly ?? true,
  });
  const engine = new HuntWaveEngine({
    stateStore,
    gateAuthority,
    modelRunner,
    telemetry,
  });

  // Automatically reconcile any interrupted in-flight runs from prior daemon crashes
  const recoveredRuns = engine.recoverInFlightRunsOnStartup();

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

export async function runHuntCli(
  argv: readonly string[],
  io: {
    writeStdout: (text: string) => void;
    writeStderr: (text: string) => void;
  } = {
    writeStdout: (t) => process.stdout.write(t),
    writeStderr: (t) => process.stderr.write(t),
  },
): Promise<number> {
  const subcommand = argv[0] ?? "help";
  const flags = parseCliFlags(argv.slice(1));
  const runtimeDir = typeof flags["runtime-dir"] === "string" ? flags["runtime-dir"] : undefined;

  if (subcommand === "help" || subcommand === "--help" || subcommand === "-h") {
    io.writeStdout(
      [
        "Hunt Command Daemon CLI (@hunt-command/daemon)",
        "Usage:",
        "  hunt-daemon serve [--runtime-dir <dir>]",
        "  hunt status --hunt-id <id> [--runtime-dir <dir>]",
        "  hunt cancel --hunt-id <id> [--reason <text>] [--runtime-dir <dir>]",
        "  hunt gates <status|approve|deny> --hunt-id <id> [--gate <name>] [--operator <id>] [--role <admin|analyst|reviewer>] [--note <text>] [--digest <sha256>] [--runtime-dir <dir>]",
        "",
      ].join("\n"),
    );
    return 0;
  }

  const ctx = createHuntDaemonRuntime({
    runtimeDir,
    productionMode: flags["non-prod"] !== true,
  });

  try {
    if (subcommand === "serve") {
      const rpc = new HuntDaemonRpcServer({
        engine: ctx.engine,
        writeLine: (line) => io.writeStdout(line),
      });
      const unsub = ctx.telemetry.subscribe((ev) => rpc.emitTelemetryEvent(ev));
      try {
        for await (const chunk of process.stdin) {
          await rpc.handleChunk(chunk as Buffer);
        }
      } finally {
        unsub();
      }
      return 0;
    }

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

    if (subcommand === "gates") {
      const actionRaw = argv[1];
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
        operator: typeof gateFlags["operator"] === "string" ? gateFlags["operator"] : undefined,
        rbacRole: (typeof gateFlags["role"] === "string"
          ? gateFlags["role"]
          : "analyst") as RbacRole,
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
    if (subcommand !== "serve") {
      ctx.stateStore.close();
    }
  }
}

if (import.meta.main) {
  const code = await runHuntCli(process.argv.slice(2));
  process.exit(code);
}
