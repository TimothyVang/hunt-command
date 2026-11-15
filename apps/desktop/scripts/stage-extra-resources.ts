import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";

/**
 * Stages unpacked extraResources for electron-builder (`pack:hunt` / `package:win`):
 * - `pi_natives.win32-x64-baseline.node` (so PI_NATIVES_DIR resolves outside $bunfs / ASAR)
 * - `hunt-daemon` entrypoint metadata / compiled binary when built
 *
 * Output directory `apps/desktop/build/extra/hunt-daemon` is gitignored (`dist/`, `out/`, `build/`).
 */
const desktopDir = path.resolve(import.meta.dir, "..");
const repoRoot = path.resolve(desktopDir, "../..");
const stageDir = path.join(desktopDir, "build", "extra", "hunt-daemon");

fs.mkdirSync(stageDir, { recursive: true });

const require = createRequire(path.join(repoRoot, "package.json"));

function findPiNativesBinary(): string | null {
  const candidates: string[] = [];
  try {
    const pkgJsonPath = require.resolve("@oh-my-pi/pi-natives-win32-x64/package.json");
    const pkgDir = path.dirname(pkgJsonPath);
    candidates.push(path.join(pkgDir, "pi_natives.win32-x64-baseline.node"));
  } catch {
    // Try direct node_modules walk.
  }
  candidates.push(
    path.join(repoRoot, "node_modules", "@oh-my-pi", "pi-natives-win32-x64", "pi_natives.win32-x64-baseline.node"),
  );

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  return null;
}

const nativesSrc = findPiNativesBinary();
if (nativesSrc) {
  const dest = path.join(stageDir, "pi_natives.win32-x64-baseline.node");
  fs.copyFileSync(nativesSrc, dest);
  console.log(`[stage:resources] Staged ${path.basename(dest)} (${fs.statSync(dest).size} bytes)`);
} else {
  console.warn("[stage:resources] pi_natives.win32-x64-baseline.node not found on host; skipping native addon copy");
}

const daemonEntryCandidates = [
  path.join(repoRoot, "packages", "daemon", "dist", "hunt-daemon.exe"),
  path.join(repoRoot, "packages", "daemon", "src", "cli.ts"),
  path.join(repoRoot, "packages", "daemon", "src", "index.ts"),
];

const foundEntry = daemonEntryCandidates.find((p) => fs.existsSync(p));
if (foundEntry) {
  const dest = path.join(stageDir, path.basename(foundEntry));
  fs.copyFileSync(foundEntry, dest);
  console.log(`[stage:resources] Staged daemon entry ${path.basename(dest)}`);
}

fs.writeFileSync(
  path.join(stageDir, "manifest.json"),
  `${JSON.stringify(
    {
      appId: "com.huntcommand.desktop",
      stagedAt: new Date().toISOString(),
      piNativesFile: nativesSrc ? "pi_natives.win32-x64-baseline.node" : null,
      daemonEntry: foundEntry ? path.basename(foundEntry) : null,
    },
    null,
    2,
  )}\n`,
  "utf8",
);
