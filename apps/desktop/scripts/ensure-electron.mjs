/**
 * Adapted from omp-desktop/app/scripts/ensure-electron.mjs
 * Copyright (c) omp-desktop contributors (MIT License — see root THIRD-PARTY-NOTICES.md).
 * Modified for Hunt Command v2: enforces windowsHide: true on child_process tar extraction
 * and supports fast local sibling Electron dist hydration when offline/cached.
 */
import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";

const require = createRequire(import.meta.url);
const electronDir = dirname(require.resolve("electron/package.json"));
const { version } = JSON.parse(readFileSync(join(electronDir, "package.json"), "utf8"));

const platformPath = {
  win32: "electron.exe",
  darwin: "Electron.app/Contents/MacOS/Electron",
  linux: "electron",
}[process.platform];
if (!platformPath) {
  throw new Error(`Unsupported platform ${process.platform}`);
}

const distDir = join(electronDir, "dist");
const binary = join(distDir, platformPath);
const pathTxt = join(electronDir, "path.txt");

if (existsSync(binary) && existsSync(pathTxt)) {
  process.exit(0);
}

// Fast local cache check from sibling omp-desktop checkout if exact version matches.
const siblingElectronPkg = resolve(electronDir, "../../../../../omp-desktop/app/node_modules/electron/package.json");
if (existsSync(siblingElectronPkg)) {
  try {
    const siblingMeta = JSON.parse(readFileSync(siblingElectronPkg, "utf8"));
    const siblingDist = join(dirname(siblingElectronPkg), "dist");
    if (siblingMeta.version === version && existsSync(join(siblingDist, platformPath))) {
      mkdirSync(distDir, { recursive: true });
      cpSync(siblingDist, distDir, { recursive: true });
      writeFileSync(pathTxt, platformPath);
      console.log(`[ensure-electron] hydrated electron ${version} from local cache`);
      process.exit(0);
    }
  } catch {
    // Fall through to @electron/get download/cache extraction.
  }
}

const { downloadArtifact } = require(require.resolve("@electron/get", { paths: [electronDir] }));
const zipPath = await downloadArtifact({
  version,
  artifactName: "electron",
  platform: process.env.npm_config_platform || process.platform,
  arch: process.env.npm_config_arch || process.arch,
  checksums: JSON.parse(readFileSync(join(electronDir, "checksums.json"), "utf8")),
});
mkdirSync(distDir, { recursive: true });
execFileSync("tar", ["-xf", zipPath, "-C", distDir], { stdio: "inherit", windowsHide: true });
if (!existsSync(binary)) {
  throw new Error(`Electron binary missing after extraction: ${binary}`);
}
writeFileSync(pathTxt, platformPath);
console.log(`[ensure-electron] extracted electron ${version}`);
