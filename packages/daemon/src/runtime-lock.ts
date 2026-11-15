import fs from "node:fs";
import path from "node:path";

export class RuntimeLockHeldError extends Error {
  public readonly holderPid: number | null;

  constructor(lockPath: string, holderPid: number | null) {
    super(
      `hunt-daemon runtime lock '${lockPath}' is held by live pid ${holderPid ?? "unknown"}; ` +
        "only one process may serve or mutate this runtime dir at a time",
    );
    this.name = "RuntimeLockHeldError";
    this.holderPid = holderPid;
  }
}

export interface RuntimeLockHandle {
  readonly lockPath: string;
  release(): void;
}

function isPidAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    // EPERM: the process exists but belongs to someone else.
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

function readHolderPid(lockPath: string): number | null {
  try {
    const parsed = JSON.parse(fs.readFileSync(lockPath, "utf8")) as { pid?: unknown };
    return typeof parsed.pid === "number" ? parsed.pid : null;
  } catch {
    return null;
  }
}

/**
 * Exclusive, stale-pid-aware lockfile (`O_CREAT | O_EXCL`). A lock whose recorded pid is no
 * longer alive is reclaimed; a lock held by a live pid (including this process) is refused.
 */
export function acquireRuntimeLock(lockPath: string): RuntimeLockHandle {
  const resolved = path.resolve(lockPath);
  fs.mkdirSync(path.dirname(resolved), { recursive: true });

  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const fd = fs.openSync(resolved, "wx", 0o600);
      try {
        fs.writeSync(
          fd,
          JSON.stringify({ pid: process.pid, acquired_at: new Date().toISOString() }),
        );
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
      let released = false;
      return {
        lockPath: resolved,
        release: () => {
          if (released) return;
          released = true;
          if (readHolderPid(resolved) === process.pid) {
            try {
              fs.unlinkSync(resolved);
            } catch {}
          }
        },
      };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
      const holder = readHolderPid(resolved);
      if (holder !== null && isPidAlive(holder)) {
        throw new RuntimeLockHeldError(resolved, holder);
      }
      if (holder === null) {
        // A just-created lock may not have its pid written yet; never reclaim a fresh one.
        let ageMs = Number.POSITIVE_INFINITY;
        try {
          ageMs = Date.now() - fs.statSync(resolved).mtimeMs;
        } catch {}
        if (ageMs < 5_000) {
          throw new RuntimeLockHeldError(resolved, null);
        }
      }
      if (attempt > 0) {
        throw new RuntimeLockHeldError(resolved, holder);
      }
      // Stale lock (dead pid or unreadable): reclaim once.
      try {
        fs.unlinkSync(resolved);
      } catch {}
    }
  }
  throw new RuntimeLockHeldError(resolved, null);
}
