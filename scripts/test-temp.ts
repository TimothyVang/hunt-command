// Preloaded by `bun test` (bunfig.toml). Sends every temp file a test creates to one folder inside the
// workspace temp directory, and removes that folder when the test process exits.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { resolveWorkspaceTempDir } from "../packages/shared/src/runtime-paths.ts";

const RUN_DIR_RE = /^test-(\d+)-/;
const STALE_AFTER_MS = 24 * 60 * 60 * 1000;
const base = resolveWorkspaceTempDir();

function isRunning(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    // EPERM means the process exists but belongs to someone else.
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

// A run cannot always remove its own folder: it may be killed, or a library may still hold a log file
// open at exit. The next run removes every folder whose process has ended.
for (const entry of fs.readdirSync(base, { withFileTypes: true })) {
  const match = entry.isDirectory() ? RUN_DIR_RE.exec(entry.name) : null;
  if (!match) continue;
  const leftover = path.join(base, entry.name);
  try {
    const ownerEnded = !isRunning(Number(match[1]));
    if (ownerEnded || Date.now() - fs.statSync(leftover).mtimeMs > STALE_AFTER_MS) {
      fs.rmSync(leftover, { recursive: true, force: true });
    }
  } catch {}
}

// Coach clean rooms must stay outside the workspace, so they keep the real system temp folder.
process.env.HUNT_COMMAND_CLEAN_ROOM_TEMP ??= os.tmpdir();

const runDir = fs.mkdtempSync(path.join(base, `test-${process.pid}-`));
for (const key of ["TEMP", "TMP", "TMPDIR", "HUNT_COMMAND_TEMP_DIR"]) {
  process.env[key] = runDir;
}
process.on("exit", () => {
  try {
    fs.rmSync(runDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  } catch {}
});
