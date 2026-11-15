/**
 * Hunt Command Workstation & Workbench Doctor (`verify-hunt-command`).
 *
 * Verifies:
 * 1. `bun >= 1.4.4`
 * 2. `ffmpeg.exe` dynamic resolution + `libass` (`ass` filter) availability
 * 3. `pi_natives.win32-x64-baseline.node` resolution
 * 4. `resolveRuntimeDir()` Git-fence enforcement
 * 5. `apps/desktop` main/preload/renderer build health + packaged CSP + zero `openExternal`
 */
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { resolveRuntimeDir, RuntimeFenceError } from "../../../../packages/shared/src/runtime-paths.ts";
import { resolvePiNativesDir } from "../../../../apps/desktop/src/main/daemon/resolve-daemon.ts";
import { resolveFfmpegBinary } from "../../../../apps/desktop/src/main/film/cfr-editor.ts";

export interface DoctorCheckResult {
  id: string;
  status: "pass" | "warn" | "fail";
  detail: string;
}

function parseSemver(raw: string): readonly [number, number, number] | null {
  const m = /(\d+)\.(\d+)\.(\d+)/.exec(raw.trim());
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}

function isAtLeast(
  actual: readonly [number, number, number],
  min: readonly [number, number, number],
): boolean {
  if (actual[0] !== min[0]) return actual[0] > min[0];
  if (actual[1] !== min[1]) return actual[1] > min[1];
  return actual[2] >= min[2];
}

function collectSourceFiles(dir: string): string[] {
  if (!fs.existsSync(dir)) return [];
  const results: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...collectSourceFiles(full));
    } else if (/\.[cm]?[jt]sx?$/.test(entry.name)) {
      results.push(full);
    }
  }
  return results;
}

export function runDoctorChecks(repoRoot: string): DoctorCheckResult[] {
  const checks: DoctorCheckResult[] = [];

  // 1. Bun >= 1.4.4
  const bunBin = process.platform === "win32" ? "bun.exe" : "bun";
  const bunRes = spawnSync(bunBin, ["--version"], {
    encoding: "utf8",
    windowsHide: true,
    timeout: 8_000,
  });
  const bunVerStr = (bunRes.stdout ?? "").trim();
  const bunSemver = parseSemver(bunVerStr);
  if (bunRes.status === 0 && bunSemver && isAtLeast(bunSemver, [1, 4, 4])) {
    checks.push({
      id: "bun_runtime",
      status: "pass",
      detail: `bun ${bunVerStr} (>= 1.4.4)`,
    });
  } else {
    checks.push({
      id: "bun_runtime",
      status: "fail",
      detail: `Expected bun >= 1.4.4, got '${bunVerStr || (bunRes.error?.message ?? "missing")}'`,
    });
  }

  // 2. FFmpeg + libass
  const ffmpeg = resolveFfmpegBinary();
  if (ffmpeg.available && ffmpeg.hasLibass && ffmpeg.ffmpegPath) {
    checks.push({
      id: "ffmpeg_libass",
      status: "pass",
      detail: `${ffmpeg.ffmpegPath} (source=${ffmpeg.source}, libass=true)`,
    });
  } else {
    checks.push({
      id: "ffmpeg_libass",
      status: "fail",
      detail: ffmpeg.available
        ? `ffmpeg found at ${ffmpeg.ffmpegPath ?? "?"}, but 'ass' (libass) filter is missing`
        : "ffmpeg.exe not found on PATH or %LOCALAPPDATA%/hermes/tools",
    });
  }

  // 3. pi_natives addon
  const piNativesDir = resolvePiNativesDir({ isPackaged: false, repoRoot });
  if (piNativesDir) {
    checks.push({
      id: "pi_natives_addon",
      status: "pass",
      detail: `Found pi_natives.win32-x64-baseline.node in ${piNativesDir}`,
    });
  } else {
    checks.push({
      id: "pi_natives_addon",
      status: "warn",
      detail:
        "pi_natives.win32-x64-baseline.node not yet installed in node_modules (expected until Slice 2 merges; stage-extra-resources ready)",
    });
  }

  // 4. Runtime Git-Fence
  try {
    const rt = resolveRuntimeDir(undefined, { repoRoot });
    let blockedInsideGit = false;
    try {
      resolveRuntimeDir(path.join(repoRoot, "apps", "desktop", "illegal-runtime"), { repoRoot });
    } catch (err) {
      blockedInsideGit = err instanceof RuntimeFenceError;
    }
    if (blockedInsideGit) {
      checks.push({
        id: "runtime_git_fence",
        status: "pass",
        detail: `Runtime resolves outside .git (${rt.rootDir}) and blocks in-repo paths`,
      });
    } else {
      checks.push({
        id: "runtime_git_fence",
        status: "fail",
        detail: "resolveRuntimeDir failed to reject an in-repo path",
      });
    }
  } catch (err) {
    checks.push({
      id: "runtime_git_fence",
      status: "fail",
      detail: err instanceof Error ? err.message : String(err),
    });
  }

  // 5. Source security scan (zero openExternal, zero dangerouslySetInnerHTML)
  const desktopSrcDir = path.join(repoRoot, "apps", "desktop", "src");
  const srcFiles = collectSourceFiles(desktopSrcDir);
  const violations: string[] = [];
  for (const file of srcFiles) {
    const lines = fs.readFileSync(file, "utf8").split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? "";
      const trimmed = line.trim();
      if (trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")) {
        continue;
      }
      if (/\bopenExternal(?:Safe)?\b/.test(line)) {
        violations.push(`${path.relative(repoRoot, file)}:${i + 1} references openExternal`);
      }
      if (/\bdangerouslySetInnerHTML\b/.test(line)) {
        violations.push(`${path.relative(repoRoot, file)}:${i + 1} references dangerouslySetInnerHTML`);
      }
    }
  }
  if (srcFiles.length > 0 && violations.length === 0) {
    checks.push({
      id: "desktop_zero_egress_source",
      status: "pass",
      detail: `Scanned ${srcFiles.length} desktop source files: zero openExternal & zero dangerouslySetInnerHTML`,
    });
  } else {
    checks.push({
      id: "desktop_zero_egress_source",
      status: "fail",
      detail: violations.join("; ") || "No desktop source files found",
    });
  }

  // 6. Electron-Vite Build Output + Packaged CSP
  const outMain = path.join(repoRoot, "apps", "desktop", "out", "main", "index.js");
  const outPreload = path.join(repoRoot, "apps", "desktop", "out", "preload", "index.cjs");
  const outRendererHtml = path.join(repoRoot, "apps", "desktop", "out", "renderer", "index.html");
  if (fs.existsSync(outMain) && fs.existsSync(outPreload) && fs.existsSync(outRendererHtml)) {
    const html = fs.readFileSync(outRendererHtml, "utf8");
    const hasConnectNone = html.includes("connect-src 'none'");
    const hasWorkerBlob = html.includes("worker-src 'self' blob:");
    if (hasConnectNone && hasWorkerBlob) {
      checks.push({
        id: "desktop_build_and_csp",
        status: "pass",
        detail:
          "out/{main/index.js,preload/index.cjs,renderer/index.html} built with connect-src 'none' & worker-src 'self' blob:",
      });
    } else {
      checks.push({
        id: "desktop_build_and_csp",
        status: "fail",
        detail: "out/renderer/index.html is missing connect-src 'none' or worker-src 'self' blob:",
      });
    }
  } else {
    checks.push({
      id: "desktop_build_and_csp",
      status: "warn",
      detail:
        "apps/desktop/out artifacts not yet built (run `bun run --cwd apps/desktop build` first)",
    });
  }

  return checks;
}

if (import.meta.main) {
  const scriptDir = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(scriptDir, "../../../..");
  const jsonMode = process.argv.includes("--json");
  const results = runDoctorChecks(repoRoot);
  const failed = results.filter((r) => r.status === "fail");

  if (jsonMode) {
    console.log(JSON.stringify({ ok: failed.length === 0, checks: results }, null, 2));
  } else {
    console.log("=== Hunt Command Workstation & Desktop Doctor ===");
    for (const r of results) {
      const tag = r.status === "pass" ? "[PASS]" : r.status === "warn" ? "[WARN]" : "[FAIL]";
      console.log(`${tag} ${r.id}: ${r.detail}`);
    }
  }

  if (failed.length > 0) {
    process.exit(1);
  }
}
