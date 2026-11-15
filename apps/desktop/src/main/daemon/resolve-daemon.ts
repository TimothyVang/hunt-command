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

const PI_NATIVES_ADDON = "pi_natives.win32-x64-baseline.node";
const PI_NATIVES_PACKAGE = "pi-natives-win32-x64";

/**
 * `@oh-my-pi/pi-natives-win32-x64` package directories under `nodeModulesDir`: the hoisted layout
 * (`node_modules/@oh-my-pi/<pkg>`) first, then Bun's isolated layout
 * (`node_modules/.bun/@oh-my-pi+<pkg>@<version>/node_modules/@oh-my-pi/<pkg>`, newest version first).
 */
export function piNativesPackageDirs(nodeModulesDir: string): string[] {
  const dirs = [path.join(nodeModulesDir, "@oh-my-pi", PI_NATIVES_PACKAGE)];
  const isolatedRoot = path.join(nodeModulesDir, ".bun");
  let entries: string[] = [];
  try {
    entries = fs.readdirSync(isolatedRoot);
  } catch {
    entries = [];
  }
  const prefix = `@oh-my-pi+${PI_NATIVES_PACKAGE}@`;
  const versions = entries
    .filter((name) => name.startsWith(prefix))
    .sort((a, b) => b.localeCompare(a, "en", { numeric: true }));
  for (const name of versions) {
    dirs.push(path.join(isolatedRoot, name, "node_modules", "@oh-my-pi", PI_NATIVES_PACKAGE));
  }
  return dirs;
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
    ...piNativesPackageDirs(path.join(options.repoRoot, "node_modules")),
    path.join(options.repoRoot, "apps", "desktop", "build", "extra", "hunt-daemon"),
  );

  for (const dir of candidates) {
    if (fs.existsSync(path.join(dir, PI_NATIVES_ADDON))) {
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
 * `hunt-daemon serve` arguments: the daemon speaks stdio NDJSON JSON-RPC on `serve` and keeps its state
 * in the same runtime directory the desktop resolved (never a `.git` tree).
 */
export function buildDaemonServeArgs(runtimeDir: string, casesDir?: string | null): string[] {
  const args = ["serve", "--runtime-dir", runtimeDir];
  if (casesDir) {
    args.push("--cases-dir", casesDir);
  }
  return args;
}

export interface ResolveDaemonLaunchOptions {
  isPackaged: boolean;
  resourcesPath?: string;
  repoRoot: string;
  /** Runtime root handed to `serve --runtime-dir`. */
  runtimeDir: string;
  /** Optional case directory handed to `serve --cases-dir`. */
  casesDir?: string | null;
  /** Override for locating `bun` (tests); defaults to `BUN_INSTALL` then `PATH`. */
  findBun?: () => string | null;
}

/**
 * Resolves the persistent `hunt-daemon` binary or workspace CLI entrypoint (`#180` G1.1 & G1.2),
 * launched as `serve --runtime-dir <dir> [--cases-dir <dir>]`.
 */
export function resolveDaemonLaunch(options: ResolveDaemonLaunchOptions): ResolvedDaemonLaunch {
  const piNativesDir = resolvePiNativesDir(options);
  const serveArgs = buildDaemonServeArgs(options.runtimeDir, options.casesDir);

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
        args: serveArgs,
        piNativesDir: piNativesDir ?? unpackedDir,
        source: "packaged_exe",
      };
    }
  }

  const cliEntry = path.join(options.repoRoot, "packages", "daemon", "src", "cli.ts");
  const foundEntry = fs.existsSync(cliEntry);
  const bunBin = (options.findBun ?? findBunExecutable)();

  if (foundEntry && bunBin) {
    return {
      available: true,
      command: bunBin,
      args: ["run", cliEntry, ...serveArgs],
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
      : "Workspace packages/daemon/src/cli.ts entrypoint not present (standby fixture mode)",
  };
}
