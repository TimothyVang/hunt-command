import { describe, expect, spyOn, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { acquireRuntimeLock, RuntimeLockHeldError } from "../src/runtime-lock.ts";

const LOCK_MODULE = path.resolve(import.meta.dir, "../src/runtime-lock.ts");

// Each child spins until a shared start time, tries the lock, and holds it briefly.
const CHILD = `
const { acquireRuntimeLock } = await import(process.argv[1]);
const [lockPath, startAt] = [process.argv[2], Number(process.argv[3])];
while (Date.now() < startAt) {}
try {
  const handle = acquireRuntimeLock(lockPath);
  const t0 = Date.now();
  await Bun.sleep(1_200);
  console.log(JSON.stringify({ acquired: true, t0, t1: Date.now() }));
  handle.release();
} catch {
  console.log(JSON.stringify({ acquired: false }));
}
`;

async function raceRound(lockPath: string, contenders: number) {
  const startAt = Date.now() + 1_000;
  const children = Array.from({ length: contenders }, () =>
    Bun.spawn([process.execPath, "-e", CHILD, LOCK_MODULE, lockPath, String(startAt)], {
      stdout: "pipe",
      stderr: "pipe",
      windowsHide: true,
    }),
  );
  const results = await Promise.all(
    children.map(async (child) => {
      const out = (await new Response(child.stdout).text()).trim();
      await child.exited;
      return JSON.parse(out) as { acquired: boolean; t0?: number; t1?: number };
    }),
  );
  return results.filter((r) => r.acquired);
}

describe("runtime lock under concurrent stale reclaim", () => {
  test("a contender cannot displace a paused reclaimer", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hunt-lock-arbitration-"));
    const lockPath = path.join(dir, "runtime.lock");
    const mutexPath = `${lockPath}.reclaim`;
    fs.writeFileSync(lockPath, JSON.stringify({ pid: 2_147_483_000 }));
    const originalUnlink = fs.unlinkSync;
    let nestedAttempted = false;
    const unlink = spyOn(fs, "unlinkSync").mockImplementation((target) => {
      if (String(target) === lockPath && !nestedAttempted) {
        nestedAttempted = true;
        const mutex = fs.readFileSync(mutexPath, "utf8");
        expect(() => acquireRuntimeLock(lockPath)).toThrow(RuntimeLockHeldError);
        expect(fs.readFileSync(mutexPath, "utf8")).toBe(mutex);
      }
      return originalUnlink(target);
    });
    try {
      const handle = acquireRuntimeLock(lockPath);
      expect(nestedAttempted).toBe(true);
      expect(() => acquireRuntimeLock(lockPath)).toThrow(RuntimeLockHeldError);
      handle.release();
    } finally {
      unlink.mockRestore();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test("legacy mutex files are never moved or removed, regardless of age", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hunt-lock-legacy-"));
    const lockPath = path.join(dir, "runtime.lock");
    const mutexPath = `${lockPath}.reclaim`;
    try {
      fs.writeFileSync(lockPath, JSON.stringify({ pid: 2_147_483_000 }));
      fs.writeFileSync(mutexPath, "legacy");
      for (const age of [0, 60_000]) {
        const time = new Date(Date.now() - age);
        fs.utimesSync(mutexPath, time, time);
        expect(() => acquireRuntimeLock(lockPath)).toThrow(RuntimeLockHeldError);
        expect(fs.readFileSync(mutexPath, "utf8")).toBe("legacy");
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test("release preserves a replacement lock", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hunt-lock-release-"));
    const lockPath = path.join(dir, "runtime.lock");
    try {
      fs.writeFileSync(lockPath, JSON.stringify({ pid: 2_147_483_000 }));
      const handle = acquireRuntimeLock(lockPath);
      fs.writeFileSync(lockPath, JSON.stringify({ pid: process.pid, token: "replacement" }));
      handle.release();
      expect(JSON.parse(fs.readFileSync(lockPath, "utf8")).token).toBe("replacement");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test(
    "exactly one of many processes reclaims a stale lock, with no overlapping holders",
    async () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hunt-lock-race-"));
      try {
        const stalePreps: Array<(lockPath: string) => void> = [
          (lp) => fs.writeFileSync(lp, JSON.stringify({ pid: 2_147_483_000, acquired_at: "x" })),
          (lp) => {
            fs.writeFileSync(lp, "garbage");
            const old = new Date(Date.now() - 60_000);
            fs.utimesSync(lp, old, old);
          },
        ];
        for (let round = 0; round < 10; round++) {
          const lockPath = path.join(dir, `round-${round}.lock`);
          stalePreps[round % stalePreps.length]!(lockPath);
          const holders = await raceRound(lockPath, 12);
          expect(holders.length, `round ${round} holders`).toBe(1);
        }
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    },
    180_000,
  );
});
