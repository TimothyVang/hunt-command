import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { runHuntCli } from "../src/index.ts";

const tempDirs: string[] = [];
afterEach(() => {
  while (tempDirs.length > 0) fs.rmSync(tempDirs.pop()!, { recursive: true, force: true });
});

function captureIo() {
  const out: string[] = [];
  const err: string[] = [];
  return { out, err, io: { writeStdout: (t: string) => void out.push(t), writeStderr: (t: string) => void err.push(t) } };
}

describe("hunt CLI refusals", () => {
  test("an unknown hunt on cancel is one stderr line and exit 1, not a stack trace", async () => {
    const runtimeDir = fs.mkdtempSync(path.join(os.tmpdir(), "hunt-cli-errors-"));
    tempDirs.push(runtimeDir);
    const c = captureIo();
    expect(await runHuntCli(["cancel", "--hunt-id", "hunt-missing", "--runtime-dir", runtimeDir], c.io)).toBe(1);
    const stderr = c.err.join("");
    expect(stderr.trimEnd().split("\n")).toHaveLength(1);
    expect(stderr).toContain("hunt-missing");
    expect(stderr).not.toMatch(/\n\s+at /);
  });

  test("a runtime dir inside a Git tree is refused with its code on one line", async () => {
    const c = captureIo();
    const insideGit = path.join(import.meta.dir, "..", "not-a-runtime-dir");
    expect(await runHuntCli(["status", "--hunt-id", "x", "--runtime-dir", insideGit], c.io)).toBe(1);
    const stderr = c.err.join("");
    expect(stderr.trimEnd().split("\n")).toHaveLength(1);
    expect(stderr).toContain("RUNTIME_INSIDE_GIT_TREE");
    expect(fs.existsSync(insideGit)).toBe(false);
  });
});
