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

const FRESH_UNREADABLE_LOCK_MS = 5_000;
const STALE_RECLAIM_MUTEX_MS = 30_000;

/** Why a lock file may be reclaimed right now, or null when it must be left alone. */
function staleLockReason(lockPath: string): { holder: number | null } | null {
  const holder = readHolderPid(lockPath);
  if (holder !== null) {
    return isPidAlive(holder) ? null : { holder };
  }
  // A just-created lock may not have its pid written yet; never reclaim a fresh one.
  let ageMs = Number.POSITIVE_INFINITY;
  try {
    ageMs = Date.now() - fs.statSync(lockPath).mtimeMs;
  } catch {
    return null;
  }
  return ageMs < FRESH_UNREADABLE_LOCK_MS ? null : { holder: null };
}

/**
 * Takes the reclaim mutex (`<lock>.reclaim`, O_EXCL). Only its holder may delete a stale lock,
 * so two processes that both saw the same stale lock can't each delete and recreate it.
 * A mutex left by a crash mid-reclaim is moved aside atomically once it is old; one that
 * turns out to be fresh is linked back, so a live reclaimer is never displaced.
 */
function tryTakeReclaimMutex(mutexPath: string): boolean {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      fs.closeSync(fs.openSync(mutexPath, "wx", 0o600));
      return true;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST" || attempt > 0) return false;
    }
    const aside = `${mutexPath}.${process.pid}.${Date.now()}.stale`;
    try {
      fs.renameSync(mutexPath, aside);
    } catch {
      return false;
    }
    let ageMs = 0;
    try {
      ageMs = Date.now() - fs.statSync(aside).mtimeMs;
    } catch {}
    if (ageMs < STALE_RECLAIM_MUTEX_MS) {
      try {
        fs.linkSync(aside, mutexPath);
      } catch {}
      try {
        fs.unlinkSync(aside);
      } catch {}
      return false;
    }
    try {
      fs.unlinkSync(aside);
    } catch {}
  }
  return false;
}

/**
 * Exclusive, stale-pid-aware lockfile (`O_CREAT | O_EXCL`). A lock whose recorded pid is no
 * longer alive is reclaimed under a reclaim mutex; a lock held by a live pid (including this
 * process) is refused.
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
      if (attempt > 0 || staleLockReason(resolved) === null) {
        throw new RuntimeLockHeldError(resolved, readHolderPid(resolved));
      }
      const mutexPath = `${resolved}.reclaim`;
      if (!tryTakeReclaimMutex(mutexPath)) {
        throw new RuntimeLockHeldError(resolved, readHolderPid(resolved));
      }
      try {
        // Re-check under the mutex: while it is held, only this process can remove the lock,
        // so a lock that is still stale here is the same dead holder's file.
        if (staleLockReason(resolved) === null) {
          throw new RuntimeLockHeldError(resolved, readHolderPid(resolved));
        }
        try {
          fs.unlinkSync(resolved);
        } catch {}
      } finally {
        try {
          fs.unlinkSync(mutexPath);
        } catch {}
      }
    }
  }
  throw new RuntimeLockHeldError(resolved, null);
}
