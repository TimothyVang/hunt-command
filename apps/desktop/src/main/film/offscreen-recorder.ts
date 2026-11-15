/**
 * Windows 11 DWM-Proof Hidden Offscreen `1920x1080` 30fps Workbench Recorder (`#178` G3.1, `#189`).
 *
 * Captures real Chromium compositor frames from a dedicated hidden offscreen `BrowserWindow`
 * (`show: false`, `width: 1920`, `height: 1080`, `offscreen: true`, `backgroundThrottling: false`,
 * `deviceScaleFactor: 1`, `setFrameRate(30)`) via `webContents.on("paint")` — immune to Windows 11
 * DWM window occlusion, minimize, virtual-desktop switch, or DPI scaling.
 */
import fs from "node:fs";
import path from "node:path";
import { BrowserWindow } from "electron";
import { findEnclosingGitMarker, RuntimeFenceError } from "@hunt-command/shared";
import { hardenWindow, type TrustedRenderers } from "../security.ts";
import {
  cutCfrFilm,
  enforceRule4FilmGuard,
  FILM_FPS,
  FILM_HEIGHT,
  FILM_WIDTH,
  type CapturedFrameEntry,
  type FilmCaptionEvent,
  type FilmWaveChapterInput,
} from "./cfr-editor.ts";
import type { FilmExportResult } from "../../shared/ipc.ts";
import type { WorkbenchSnapshot } from "../../shared/workbench-types.ts";

export interface OffscreenRecordAndCutOptions {
  filmsRootDir: string;
  rendererUrl: string;
  preloadPath: string;
  trustedRenderers: TrustedRenderers;
  workbench: WorkbenchSnapshot;
  speed: number;
  captions: boolean;
  allowWorkFilm: boolean;
  captureHoldMs?: number;
  onProgress?: (phase: string, detail: string) => void;
}

export async function recordOffscreenWorkbenchAndCutFilm(
  options: OffscreenRecordAndCutOptions,
): Promise<FilmExportResult> {
  const enclosingGit = findEnclosingGitMarker(options.filmsRootDir);
  if (enclosingGit !== null) {
    throw new RuntimeFenceError(options.filmsRootDir, enclosingGit);
  }

  enforceRule4FilmGuard(options.workbench.caseMetadata, options.allowWorkFilm);

  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const safeHuntId = options.workbench.huntId.replace(/[^A-Za-z0-9_-]/g, "_");
  const filmDir = path.join(options.filmsRootDir, `${safeHuntId}-${stamp}`);
  const framesDir = path.join(filmDir, "frames");
  fs.mkdirSync(framesDir, { recursive: true });

  const indexJsonlPath = path.join(filmDir, "index.jsonl");
  const boardStateJsonlPath = path.join(filmDir, "board-state.jsonl");

  const win = new BrowserWindow({
    show: false,
    width: FILM_WIDTH,
    height: FILM_HEIGHT,
    useContentSize: true,
    frame: false,
    backgroundColor: "#090d16",
    webPreferences: {
      preload: options.preloadPath,
      offscreen: true,
      backgroundThrottling: false,
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false,
      webSecurity: true,
      spellcheck: false,
    },
  });

  options.trustedRenderers.add(win);
  hardenWindow(win, options.trustedRenderers);

  const capturedFrames: CapturedFrameEntry[] = [];
  let frameSeq = 0;
  let lastEpochSec = 0;

  const recordFrame = (jpegBuffer: Buffer) => {
    if (jpegBuffer.byteLength < 4_096) {
      return;
    }
    const rawNow = Date.now() / 1000;
    const monotonicSec = rawNow <= lastEpochSec ? lastEpochSec + 1 / FILM_FPS : rawNow;
    lastEpochSec = monotonicSec;

    frameSeq += 1;
    const fileName = `${String(frameSeq).padStart(6, "0")}.jpg`;
    const absPath = path.join(framesDir, fileName);
    fs.writeFileSync(absPath, jpegBuffer);
    capturedFrames.push({
      epochSec: Number(monotonicSec.toFixed(6)),
      imagePath: absPath,
    });

    const indexRow = {
      seq: frameSeq,
      t: Number(monotonicSec.toFixed(6)),
      rel_path: `frames/${fileName}`,
      width: FILM_WIDTH,
      height: FILM_HEIGHT,
      bytes: jpegBuffer.byteLength,
    };
    fs.appendFileSync(indexJsonlPath, `${JSON.stringify(indexRow)}\n`, "utf8");
  };

  let repaintTimer: ReturnType<typeof setInterval> | undefined;

  try {
    options.onProgress?.("offscreen_capture", "Starting 1920x1080@30fps offscreen compositor");
    win.webContents.setAudioMuted(true);
    win.webContents.setFrameRate(FILM_FPS);
    win.webContents.enableDeviceEmulation({
      screenPosition: "desktop",
      screenSize: { width: FILM_WIDTH, height: FILM_HEIGHT },
      viewPosition: { x: 0, y: 0 },
      deviceScaleFactor: 1,
      viewSize: { width: FILM_WIDTH, height: FILM_HEIGHT },
      scale: 1,
    });

    win.webContents.on("paint", (_event, _dirty, image) => {
      const size = image.getSize();
      const normalized =
        size.width === FILM_WIDTH && size.height === FILM_HEIGHT
          ? image
          : image.resize({ width: FILM_WIDTH, height: FILM_HEIGHT });
      recordFrame(normalized.toJPEG(88));
    });

    const targetUrl = new URL(options.rendererUrl);
    targetUrl.searchParams.set("film", "1");
    targetUrl.searchParams.set("huntId", options.workbench.huntId);

    await win.loadURL(targetUrl.toString());
    win.webContents.setZoomFactor(1);
    win.webContents.invalidate();

    repaintTimer = setInterval(() => {
      if (!win.isDestroyed() && !win.webContents.isDestroyed()) {
        win.webContents.invalidate();
      }
    }, 250);

    const holdMs = Math.max(1_200, options.captureHoldMs ?? 2_400);
    await new Promise((resolve) => setTimeout(resolve, holdMs));

    if (capturedFrames.length === 0 && !win.webContents.isDestroyed()) {
      const fallbackImg = await win.webContents.capturePage({
        x: 0,
        y: 0,
        width: FILM_WIDTH,
        height: FILM_HEIGHT,
      });
      recordFrame(fallbackImg.toJPEG(88));
    }

    const firstSec = capturedFrames[0]?.epochSec ?? Date.now() / 1000;
    const endSec = Math.max(firstSec + 1.0, capturedFrames[capturedFrames.length - 1]?.epochSec ?? firstSec + 1.0);

    const boardStateRow = {
      t: firstSec,
      steps: options.workbench.steps.map((s, index) => ({
        index,
        step_id: s.stepId,
        role: s.profile,
        wave: s.waveNumber,
        state: s.state,
        reason: s.reasonCode ?? "",
      })),
    };
    fs.writeFileSync(boardStateJsonlPath, `${JSON.stringify(boardStateRow)}\n`, "utf8");

    const distinctWaves = [...new Set(options.workbench.steps.map((s) => s.waveNumber))].sort(
      (a, b) => a - b,
    );
    const totalWaves = Math.max(1, distinctWaves.length);
    const spanSec = Math.max(1.0, endSec - firstSec);

    const chapters: FilmWaveChapterInput[] = distinctWaves.map((waveNum, idx) => {
      const waveSteps = options.workbench.steps.filter((s) => s.waveNumber === waveNum);
      const relStart = firstSec + (spanSec * idx) / totalWaves;
      const relEnd = firstSec + (spanSec * (idx + 1)) / totalWaves;
      const dropped = waveSteps
        .filter((s) => s.state === "dropped" || s.state === "stopped")
        .map((s) => `${s.stepId} (${s.state}: ${s.reasonCode ?? "halted"})`);
      return {
        waveNumber: waveNum,
        totalWaves,
        startedAtSec: relStart,
        endedAtSec: relEnd,
        stepIds: waveSteps.map((s) => s.stepId),
        roles: [...new Set(waveSteps.map((s) => s.profile))],
        ...(dropped.length > 0 ? { droppedOrStoppedSummary: dropped.join(", ") } : {}),
      };
    });

    const toolSpans = options.workbench.ganttSpans.filter(
      (sp) => sp.kind === "gen_ai.execute_tool" || sp.kind === "hunt.gate.decision",
    );
    const captionEvents: FilmCaptionEvent[] = toolSpans.map((sp, idx) => ({
      epochSec: firstSec + ((idx + 0.3) / Math.max(1, toolSpans.length)) * spanSec,
      text: `${sp.profile ?? "operator"} · ${sp.label}`,
    }));

    options.onProgress?.("ffmpeg_cut", "Encoding CFR 30fps video-full.mp4 (1x) & video.mp4 (5x)");
    return cutCfrFilm({
      outDir: filmDir,
      huntId: options.workbench.huntId,
      caseMetadata: options.workbench.caseMetadata,
      frames: capturedFrames,
      chapters,
      captionEvents,
      speed: options.speed,
      captions: options.captions,
      allowWorkFilm: options.allowWorkFilm,
    });
  } finally {
    if (repaintTimer) {
      clearInterval(repaintTimer);
    }
    if (!win.isDestroyed()) {
      win.destroy();
    }
  }
}
