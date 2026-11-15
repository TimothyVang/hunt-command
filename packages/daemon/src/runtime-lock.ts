import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";

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

/**
 * The runtime lock is stale but its reclaim mutex is still present after the retry window.
 * When the mutex's recorded owner is dead, a crash mid-reclaim left it behind; it is never
 * removed automatically, so the operator is told exactly which file to delete.
 */
export class RuntimeLockReclaimBlockedError extends RuntimeLockHeldError {
  public readonly mutexPath: string;
  public readonly mutexOwnerPid: number | null;

  constructor(lockPath: string, mutexPath: string, mutexOwnerPid: number | null, ownerAlive: boolean) {
    super(lockPath, null);
    this.message =
      ownerAlive
        ? `hunt-daemon runtime lock '${lockPath}' is stale and pid ${mutexOwnerPid} is reclaiming it; retry shortly`
        : `hunt-daemon runtime lock '${lockPath}' is stale, but its reclaim mutex '${mutexPath}' was left by ` +
            `${mutexOwnerPid === null ? "an unknown process" : `dead pid ${mutexOwnerPid}`}. ` +
            "Confirm no hunt-daemon or hunt CLI is running for this runtime dir, then delete that file and retry.";
    this.name = "RuntimeLockReclaimBlockedError";
    this.mutexPath = mutexPath;
    this.mutexOwnerPid = mutexOwnerPid;
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
const RECLAIM_RETRY_MS = 100;
const reclaimRetryWait = new Int32Array(new SharedArrayBuffer(4));

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
 * An ownerless or crashed reclaim mutex cannot be distinguished safely from a paused
 * owner. Never reclaim it automatically; an operator must first ensure all reclaimers
 * have stopped before removing an abandoned mutex.
 */
function tryTakeReclaimMutex(mutexPath: string): (() => void) | null {
  let fd: number;
  try {
    fd = fs.openSync(mutexPath, "wx", 0o600);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "EEXIST") return null;
    throw err;
  }
  const token = randomUUID();
  try {
    fs.writeSync(fd, JSON.stringify({ pid: process.pid, token }));
  } finally {
    fs.closeSync(fd);
  }
  return () => {
    try {
      const owner = JSON.parse(fs.readFileSync(mutexPath, "utf8")) as { token?: unknown };
      if (owner.token === token) fs.unlinkSync(mutexPath);
    } catch {}
  };
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
      const token = randomUUID();
      try {
        fs.writeSync(
          fd,
          JSON.stringify({ pid: process.pid, token, acquired_at: new Date().toISOString() }),
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
          try {
            const holder = JSON.parse(fs.readFileSync(resolved, "utf8")) as { token?: unknown };
            if (holder.token === token) fs.unlinkSync(resolved);
          } catch {}
        },
      };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
      if (attempt > 0 || staleLockReason(resolved) === null) {
        throw new RuntimeLockHeldError(resolved, readHolderPid(resolved));
      }
      const mutexPath = `${resolved}.reclaim`;
      let releaseMutex = tryTakeReclaimMutex(mutexPath);
      const retryUntil = Date.now() + RECLAIM_RETRY_MS;
      while (!releaseMutex && Date.now() < retryUntil) {
        Atomics.wait(reclaimRetryWait, 0, 0, 2);
        releaseMutex = tryTakeReclaimMutex(mutexPath);
      }
      if (!releaseMutex) {
        const mutexOwner = readHolderPid(mutexPath);
        throw new RuntimeLockReclaimBlockedError(
          resolved,
          mutexPath,
          mutexOwner,
          mutexOwner !== null && isPidAlive(mutexOwner),
        );
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
        releaseMutex();
      }
    }
  }
  throw new RuntimeLockHeldError(resolved, null);
}
