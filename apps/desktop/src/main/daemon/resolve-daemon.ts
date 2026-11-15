import fs from "node:fs";
import path from "node:path";

export interface ResolvedDaemonLaunch {
  available: boolean;
  command: string;
  args: string[];
  piNativesDir: string | null;
  source: "packaged_exe" | "workspace_bun" | "unavailable";
  reason?: string;
}

const STRIPPED_PAID_API_KEY_ENVS = [
  "ANTHROPIC_API_KEY",
  "OPENAI_API_KEY",
  "CODEX_API_KEY",
  "GEMINI_API_KEY",
  "GOOGLE_API_KEY",
  "GOOGLE_GENAI_USE_VERTEXAI",
] as const;

/**
 * Strips paid API key environment variables so `hunt-daemon` runs strictly in `$0` OAuth
 * subscription mode (`#180` G2.2, Rule 5).
 */
export function buildDaemonChildEnv(
  baseEnv: NodeJS.ProcessEnv,
  runtimeRootDir: string,
  piNativesDir: string | null,
): NodeJS.ProcessEnv {
  const clean: NodeJS.ProcessEnv = { ...baseEnv };
  for (const key of STRIPPED_PAID_API_KEY_ENVS) {
    delete clean[key];
  }
  clean.HUNT_COMMAND_RUNTIME_DIR = runtimeRootDir;
  if (piNativesDir) {
    clean.PI_NATIVES_DIR = piNativesDir;
  }
  return clean;
}

export function resolvePiNativesDir(options: {
  isPackaged: boolean;
  resourcesPath?: string;
  repoRoot: string;
}): string | null {
  const candidates: string[] = [];
  if (options.isPackaged && options.resourcesPath) {
    candidates.push(path.join(options.resourcesPath, "hunt-daemon"));
  }
  candidates.push(
    path.join(options.repoRoot, "node_modules", "@oh-my-pi", "pi-natives-win32-x64"),
    path.join(options.repoRoot, "apps", "desktop", "build", "extra", "hunt-daemon"),
  );

  for (const dir of candidates) {
    const addon = path.join(dir, "pi_natives.win32-x64-baseline.node");
    if (fs.existsSync(addon)) {
      return dir;
    }
  }
  return null;
}

function findBunExecutable(): string | null {
  if (process.env.BUN_INSTALL) {
    const candidate = path.join(
      process.env.BUN_INSTALL,
      "bin",
      process.platform === "win32" ? "bun.exe" : "bun",
    );
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  const pathDirs = (process.env.PATH ?? "").split(path.delimiter).filter(Boolean);
  const binName = process.platform === "win32" ? "bun.exe" : "bun";
  for (const dir of pathDirs) {
    const full = path.join(dir, binName);
    if (fs.existsSync(full)) {
      return full;
    }
  }
  return null;
}

/**
 * Resolves the persistent `hunt-daemon` binary or workspace RPC entrypoint (`#180` G1.1 & G1.2).
 */
export function resolveDaemonLaunch(options: {
  isPackaged: boolean;
  resourcesPath?: string;
  repoRoot: string;
}): ResolvedDaemonLaunch {
  const piNativesDir = resolvePiNativesDir(options);

  if (options.isPackaged && options.resourcesPath) {
    const unpackedDir = path.join(options.resourcesPath, "hunt-daemon");
    const exePath = path.join(
      unpackedDir,
      process.platform === "win32" ? "hunt-daemon.exe" : "hunt-daemon",
    );
    if (fs.existsSync(exePath)) {
      return {
        available: true,
        command: exePath,
        args: ["--rpc"],
        piNativesDir: piNativesDir ?? unpackedDir,
        source: "packaged_exe",
      };
    }
  }

  const rpcCandidates = [
    path.join(options.repoRoot, "packages", "daemon", "src", "cli.ts"),
    path.join(options.repoRoot, "packages", "daemon", "src", "rpc-server.ts"),
  ];

  const foundEntry = rpcCandidates.find((p) => fs.existsSync(p));
  const bunBin = findBunExecutable();

  if (foundEntry && bunBin) {
    return {
      available: true,
      command: bunBin,
      args: ["run", foundEntry, "--rpc"],
      piNativesDir,
      source: "workspace_bun",
    };
  }

  return {
    available: false,
    command: "",
    args: [],
    piNativesDir,
    source: "unavailable",
    reason: foundEntry
      ? "Bun executable not found on PATH"
      : "Workspace packages/daemon RPC entrypoint not yet present (standby fixture mode)",
  };
}
