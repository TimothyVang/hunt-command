import fs from "node:fs";
import path from "node:path";

export class RuntimeFenceError extends Error {
  public readonly code = "RUNTIME_INSIDE_GIT_TREE" as const;
  public readonly candidatePath: string;
  public readonly gitMarkerPath: string;

  constructor(candidatePath: string, gitMarkerPath: string) {
    super(
      `Refusing runtime directory '${candidatePath}': located inside Git tree (${gitMarkerPath})`,
    );
    this.name = "RuntimeFenceError";
    this.candidatePath = candidatePath;
    this.gitMarkerPath = gitMarkerPath;
  }
}

export interface RuntimePaths {
  rootDir: string;
  casesDir: string;
  stateDir: string;
  daemonStateDbPath: string;
  telemetryDir: string;
  telemetryDbPath: string;
  blobsDir: string;
  decisionsDir: string;
  decisionsLogPath: string;
  exportsDir: string;
  filmsDir: string;
  operatorOnlyDir: string;
}

export interface ResolveRuntimeDirOptions {
  repoRoot?: string;
}

function canonicalizeWithExistingAncestor(targetPath: string): string {
  const resolved = path.resolve(targetPath);
  const trailingSegments: string[] = [];
  let current = resolved;

  while (!fs.existsSync(current)) {
    const parent = path.dirname(current);
    if (parent === current) {
      return resolved;
    }
    trailingSegments.unshift(path.basename(current));
    current = parent;
  }

  const realExisting = fs.realpathSync(current);
  return trailingSegments.length > 0
    ? path.join(realExisting, ...trailingSegments)
    : realExisting;
}

function normalizeForComparison(p: string): string {
  const normalized = path.resolve(p);
  return process.platform === "win32" ? normalized.toLowerCase() : normalized;
}

function isSameOrSubpath(childPath: string, parentPath: string): boolean {
  const childNorm = normalizeForComparison(childPath);
  const parentNorm = normalizeForComparison(parentPath);
  if (childNorm === parentNorm) {
    return true;
  }
  const rel = path.relative(parentNorm, childNorm);
  return rel !== "" && !rel.startsWith("..") && !path.isAbsolute(rel);
}

export function findEnclosingGitMarker(targetPath: string): string | null {
  let current = canonicalizeWithExistingAncestor(targetPath);

  while (true) {
    const gitEntry = path.join(current, ".git");
    if (fs.existsSync(gitEntry)) {
      return gitEntry;
    }
    const parent = path.dirname(current);
    if (parent === current) {
      return null;
    }
    current = parent;
  }
}

function computeDefaultRuntimeDir(repoRoot: string): string {
  const parentDir = path.dirname(repoRoot);
  if (path.basename(parentDir) === ".worktrees") {
    return path.resolve(parentDir, "..", "runtime");
  }
  return path.resolve(repoRoot, "../runtime");
}

export function resolveRuntimeDir(
  candidatePath?: string,
  options?: ResolveRuntimeDirOptions,
): RuntimePaths {
  const defaultRepoRoot = options?.repoRoot
    ? path.resolve(options.repoRoot)
    : path.resolve(import.meta.dir, "../../..");

  const rawTarget =
    candidatePath ??
    process.env.HUNT_COMMAND_RUNTIME_DIR ??
    computeDefaultRuntimeDir(defaultRepoRoot);

  const canonicalRoot = canonicalizeWithExistingAncestor(rawTarget);

  if (options?.repoRoot) {
    const canonicalRepoRoot = canonicalizeWithExistingAncestor(options.repoRoot);
    if (isSameOrSubpath(canonicalRoot, canonicalRepoRoot)) {
      throw new RuntimeFenceError(canonicalRoot, canonicalRepoRoot);
    }
  }

  const enclosingGit = findEnclosingGitMarker(canonicalRoot);
  if (enclosingGit !== null) {
    throw new RuntimeFenceError(canonicalRoot, enclosingGit);
  }

  const stateDir = path.join(canonicalRoot, "state");
  const telemetryDir = path.join(canonicalRoot, "telemetry");
  const decisionsDir = path.join(canonicalRoot, "operator-decisions");

  return {
    rootDir: canonicalRoot,
    casesDir: path.join(canonicalRoot, "cases"),
    stateDir,
    daemonStateDbPath: path.join(stateDir, "hunt_daemon.sqlite"),
    telemetryDir,
    telemetryDbPath: path.join(telemetryDir, "hunt_telemetry.sqlite"),
    blobsDir: path.join(telemetryDir, "blobs"),
    decisionsDir,
    decisionsLogPath: path.join(decisionsDir, "decisions.jsonl"),
    exportsDir: path.join(canonicalRoot, "exports"),
    filmsDir: path.join(canonicalRoot, "films"),
    operatorOnlyDir: path.join(canonicalRoot, "operator-only"),
  };
}
