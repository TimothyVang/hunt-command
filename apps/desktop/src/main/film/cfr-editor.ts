/**
 * Windows 11 DWM-Proof `1920x1080` CFR 30fps Filming & ASS Caption Pipeline (`#178` G3.2–G3.3, `#189`).
 *
 * TypeScript port & hardening of `operator/film/edit.py`:
 * - Enforces Rule 4 film guard: refuses `.mp4`/`.ass` export when `!caseMetadata.synthetic_only`
 *   unless `allowWorkFilm: true` (which burns a crimson `NON-SYNTHETIC — OPERATOR LOCAL ONLY` banner).
 * - Dynamically resolves `ffmpeg.exe` across `HUNT_COMMAND_FFMPEG_PATH`, `PATH`, and
 *   `%LOCALAPPDATA%/hermes/tools/ffmpeg-*-win32-x64/bin/ffmpeg.exe` (never hardcodes version `9.0.1`).
 * - Spawns `ffmpeg.exe` with `{ cwd: outDir, windowsHide: true }` using **strictly relative ASCII filenames**
 *   (`ass=filename=video.ass`, `concat-5x.ffconcat`, `concat-full.ffconcat`) so Windows `C\:` colons,
 *   apostrophes `'`, or brackets `[` in `outDir` NEVER crash FFmpeg's filtergraph or concat demuxer!
 * - Generates Margin-styled ASS v4+ subtitles (`PlayResX: 1920, PlayResY: 1080, WrapStyle: 2, Alignment=1,
 *   MarginL=620, MarginR=24, MarginV=18`) + `2.5s` Wave Chapter Cards (`CHAPTER_SECONDS = 2.5`) +
 *   CFR 30fps `-movflags +faststart` `video-full.mp4` (`1x`) and `video.mp4` (`5x`).
 */
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import {
  findEnclosingGitMarker,
  RuntimeFenceError,
  type CaseMetadata,
} from "@hunt-command/shared";
import { sanitizeSingleLine } from "../../shared/sanitize.ts";
import type { FilmExportResult } from "../../shared/ipc.ts";

export const FILM_WIDTH = 1920;
export const FILM_HEIGHT = 1080;
export const FILM_FPS = 30;
export const INTRO_SECONDS = 5.0;
export const OUTRO_SECONDS = 7.0;
export const CHAPTER_SECONDS = 2.5;
export const CAPTION_HOLD_SECONDS = 3.0;
export const MIN_CAPTION_SECONDS = 0.4;

export class Rule4FilmRefusedError extends Error {
  public readonly code = "RULE4_NON_SYNTHETIC_FILM_REFUSED" as const;
  public readonly dataOrigin: string;

  constructor(dataOrigin: string) {
    super(
      `Rule 4 Film Guard refused .mp4/.ass export for non-synthetic case (data_origin='${dataOrigin}'). Pass allowWorkFilm: true to render an operator-local watermarked cut.`,
    );
    this.name = "Rule4FilmRefusedError";
    this.dataOrigin = dataOrigin;
  }
}

export interface Rule4FilmDecision {
  allowed: true;
  burnNonSyntheticBanner: boolean;
  bannerText: string | null;
}

export function enforceRule4FilmGuard(
  caseMetadata: Pick<CaseMetadata, "data_origin" | "synthetic_only">,
  allowWorkFilm: boolean,
): Rule4FilmDecision {
  const isSynthetic = caseMetadata.synthetic_only && caseMetadata.data_origin === "synthetic";
  if (isSynthetic) {
    return {
      allowed: true,
      burnNonSyntheticBanner: false,
      bannerText: null,
    };
  }
  if (!allowWorkFilm) {
    throw new Rule4FilmRefusedError(caseMetadata.data_origin);
  }
  return {
    allowed: true,
    burnNonSyntheticBanner: true,
    bannerText: `NON-SYNTHETIC (${caseMetadata.data_origin.toUpperCase()}) — OPERATOR LOCAL ONLY`,
  };
}

export interface FfmpegResolution {
  available: boolean;
  ffmpegPath: string | null;
  ffprobePath: string | null;
  source: "env_override" | "path" | "hermes_localappdata" | "unavailable";
  hasLibass: boolean;
}

function listHermesToolFfmpegCandidates(env: NodeJS.ProcessEnv): string[] {
  const localAppData = env.LOCALAPPDATA;
  if (!localAppData) {
    return [];
  }
  const toolsDir = path.join(localAppData, "hermes", "tools");
  if (!fs.existsSync(toolsDir)) {
    return [];
  }
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(toolsDir, { withFileTypes: true });
  } catch {
    return [];
  }
  return entries
    .filter((d) => d.isDirectory() && /^ffmpeg-.*-win32-x64$/i.test(d.name))
    .map((d) => d.name)
    .sort((a, b) => b.localeCompare(a, undefined, { numeric: true }))
    .map((dirName) => path.join(toolsDir, dirName, "bin", "ffmpeg.exe"))
    .filter((candidate) => fs.existsSync(candidate));
}

function findExecutableOnPath(binaryName: string, env: NodeJS.ProcessEnv): string | null {
  const rawPath = env.PATH ?? env.Path ?? "";
  const dirs = rawPath.split(path.delimiter).filter((s) => s.length > 0);
  for (const dir of dirs) {
    const candidate = path.join(dir, binaryName);
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  return null;
}

export function resolveFfmpegBinary(env: NodeJS.ProcessEnv = process.env): FfmpegResolution {
  const binaryName = process.platform === "win32" ? "ffmpeg.exe" : "ffmpeg";
  const probeName = process.platform === "win32" ? "ffprobe.exe" : "ffprobe";

  const checkCandidate = (
    ffmpegPath: string,
    source: FfmpegResolution["source"],
  ): FfmpegResolution | null => {
    if (!fs.existsSync(ffmpegPath)) {
      return null;
    }
    const probeRes = spawnSync(ffmpegPath, ["-hide_banner", "-filters"], {
      encoding: "utf8",
      windowsHide: true,
      timeout: 10_000,
    });
    if (probeRes.error || probeRes.status !== 0) {
      return null;
    }
    const filtersOut = `${probeRes.stdout ?? ""}\n${probeRes.stderr ?? ""}`;
    const hasLibass = /\bass\b/.test(filtersOut);
    const siblingProbe = path.join(path.dirname(ffmpegPath), probeName);
    return {
      available: true,
      ffmpegPath,
      ffprobePath: fs.existsSync(siblingProbe) ? siblingProbe : findExecutableOnPath(probeName, env),
      source,
      hasLibass,
    };
  };

  if (env.HUNT_COMMAND_FFMPEG_PATH) {
    const found = checkCandidate(env.HUNT_COMMAND_FFMPEG_PATH, "env_override");
    if (found) return found;
  }

  const fromPath = findExecutableOnPath(binaryName, env);
  if (fromPath) {
    const found = checkCandidate(fromPath, "path");
    if (found) return found;
  }

  for (const candidate of listHermesToolFfmpegCandidates(env)) {
    const found = checkCandidate(candidate, "hermes_localappdata");
    if (found) return found;
  }

  return {
    available: false,
    ffmpegPath: null,
    ffprobePath: null,
    source: "unavailable",
    hasLibass: false,
  };
}

export interface CapturedFrameEntry {
  /** Capture epoch seconds (monotonic). */
  epochSec: number;
  /** Path to captured 1920x1080 JPEG frame. */
  imagePath: string;
}

export interface FilmWaveChapterInput {
  waveNumber: number;
  totalWaves: number;
  /** Epoch seconds when this wave started. */
  startedAtSec: number;
  /** Epoch seconds when this wave ended. */
  endedAtSec: number;
  stepIds: string[];
  roles: string[];
  droppedOrStoppedSummary?: string;
}

export interface FilmCaptionEvent {
  epochSec: number;
  text: string;
}

export interface AssCaptionDialogue {
  startSec: number;
  endSec: number;
  text: string;
}

export function escapeAssText(raw: string): string {
  return sanitizeSingleLine(raw)
    .replace(/\\/g, "\\\\")
    .replace(/\{/g, "\\{")
    .replace(/\}/g, "\\}");
}

export function formatAssTimestamp(seconds: number): string {
  const clamped = Math.max(0, seconds);
  const totalCentis = Math.round(clamped * 100);
  const cs = totalCentis % 100;
  const totalSecs = Math.floor(totalCentis / 100);
  const s = totalSecs % 60;
  const totalMins = Math.floor(totalSecs / 60);
  const m = totalMins % 60;
  const h = Math.floor(totalMins / 60);
  return `${h}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}.${String(cs).padStart(2, "0")}`;
}

export interface BuildAssOptions {
  totalDurationSec: number;
  speedLabel: string;
  speed: number;
  captions: readonly AssCaptionDialogue[];
  nonSyntheticBannerText?: string | null;
}

/**
 * Generates an ASS v4+ subtitle script with `PlayResX: 1920, PlayResY: 1080, WrapStyle: 2`
 * and Margin-styled `Caption` (`Alignment=1, MarginL=620, MarginR=24, MarginV=18`) — zero `\pos(...)`.
 */
export function buildAssSubtitles(options: BuildAssOptions): string {
  const speedColor = options.speed === 1 ? "&H005EC522" : "&H000B9EF5";
  const endStamp = formatAssTimestamp(Math.max(0.1, options.totalDurationSec));

  const lines: string[] = [
    "[Script Info]",
    "Title: Hunt Command Workbench Flight Film",
    "ScriptType: v4.00+",
    "PlayResX: 1920",
    "PlayResY: 1080",
    "WrapStyle: 2",
    "ScaledBorderAndShadow: yes",
    "",
    "[V4+ Styles]",
    "Format: Name, Fontname, Fontsize, PrimaryColour, SecondaryColour, OutlineColour, BackColour, Bold, Italic, Underline, StrikeOut, ScaleX, ScaleY, Spacing, Angle, BorderStyle, Outline, Shadow, Alignment, MarginL, MarginR, MarginV, Encoding",
    // Caption style: Alignment=1 (bottom-left), MarginL=620, MarginR=24, MarginV=18
    "Style: Caption,Segoe UI,26,&H00FFFFFF,&H000000FF,&H00141A24,&HC0080D14,0,0,0,0,100,100,0,0,1,2,0,1,620,24,18,1",
    // SpeedBadge style: Alignment=1 (bottom-left), MarginL=24, MarginR=1320, MarginV=18
    `Style: SpeedBadge,Segoe UI,28,${speedColor},&H000000FF,&H00141A24,&H00000000,-1,0,0,0,100,100,0,0,1,2,0,1,24,1320,18,1`,
    // Rule4Banner style: Alignment=8 (top-center), MarginL=24, MarginR=24, MarginV=10
    "Style: Rule4Banner,Segoe UI,26,&H00FFFFFF,&H000000FF,&H001B1B99,&HE01B1B99,-1,0,0,0,100,100,0,0,3,6,0,8,24,24,10,1",
    "",
    "[Events]",
    "Format: Layer, Start, End, Style, Name, MarginL, MarginR, MarginV, Effect, Text",
    `Dialogue: 1,0:00:00.00,${endStamp},SpeedBadge,,0,0,0,,${escapeAssText(options.speedLabel)}`,
  ];

  if (options.nonSyntheticBannerText) {
    lines.push(
      `Dialogue: 3,0:00:00.00,${endStamp},Rule4Banner,,0,0,0,,${escapeAssText(options.nonSyntheticBannerText)}`,
    );
  }

  for (const cap of options.captions) {
    if (cap.endSec <= cap.startSec) continue;
    lines.push(
      `Dialogue: 2,${formatAssTimestamp(cap.startSec)},${formatAssTimestamp(cap.endSec)},Caption,,0,0,0,,${escapeAssText(cap.text)}`,
    );
  }

  return `${lines.join("\n")}\n`;
}

function buildCardAssScript(lines: readonly string[], bannerText: string | null): string {
  const titleLine = escapeAssText(lines[0] ?? "Hunt Command");
  const bodyLines = lines
    .slice(1, 12)
    .map((l) => escapeAssText(l))
    .join("\\N");

  const events: string[] = [
    "[Script Info]",
    "ScriptType: v4.00+",
    "PlayResX: 1920",
    "PlayResY: 1080",
    "WrapStyle: 2",
    "ScaledBorderAndShadow: yes",
    "",
    "[V4+ Styles]",
    "Format: Name, Fontname, Fontsize, PrimaryColour, SecondaryColour, OutlineColour, BackColour, Bold, Italic, Underline, StrikeOut, ScaleX, ScaleY, Spacing, Angle, BorderStyle, Outline, Shadow, Alignment, MarginL, MarginR, MarginV, Encoding",
    "Style: CardTitle,Segoe UI,50,&H00FFFFFF,&H000000FF,&H0020120B,&H00000000,-1,0,0,0,100,100,0,0,1,2,0,8,80,80,320,1",
    "Style: CardBody,Segoe UI,32,&H00E1D5CB,&H000000FF,&H0020120B,&H00000000,0,0,0,0,100,100,0,0,1,2,0,8,100,100,420,1",
    "Style: Rule4Banner,Segoe UI,26,&H00FFFFFF,&H000000FF,&H001B1B99,&HE01B1B99,-1,0,0,0,100,100,0,0,3,6,0,8,24,24,10,1",
    "",
    "[Events]",
    "Format: Layer, Start, End, Style, Name, MarginL, MarginR, MarginV, Effect, Text",
    `Dialogue: 1,0:00:00.00,0:00:05.00,CardTitle,,0,0,0,,${titleLine}`,
  ];
  if (bodyLines.length > 0) {
    events.push(`Dialogue: 1,0:00:00.00,0:00:05.00,CardBody,,0,0,0,,${bodyLines}`);
  }
  if (bannerText) {
    events.push(`Dialogue: 2,0:00:00.00,0:00:05.00,Rule4Banner,,0,0,0,,${escapeAssText(bannerText)}`);
  }
  return `${events.join("\n")}\n`;
}

function runFfmpegInOutDir(ffmpegPath: string, outDir: string, args: string[]): void {
  const res = spawnSync(ffmpegPath, args, {
    cwd: outDir,
    encoding: "utf8",
    windowsHide: true,
    timeout: 180_000,
  });
  if (res.error) {
    throw new Error(`ffmpeg spawn failed: ${res.error.message}`);
  }
  if (res.status !== 0) {
    throw new Error(
      `ffmpeg exited with code ${String(res.status)}: ${(res.stderr ?? "").slice(-800)}`,
    );
  }
}

function renderCardJpeg(
  ffmpegPath: string,
  outDir: string,
  relAssFile: string,
  relJpegFile: string,
  lines: readonly string[],
  bannerText: string | null,
): void {
  fs.writeFileSync(path.join(outDir, relAssFile), buildCardAssScript(lines, bannerText), "utf8");
  const vfParts = [
    ...(bannerText ? ["drawbox=x=0:y=0:w=iw:h=48:color=0x991b1b@0.94:t=fill"] : []),
    `ass=filename=${relAssFile}`,
  ];
  runFfmpegInOutDir(ffmpegPath, outDir, [
    "-hide_banner",
    "-loglevel",
    "error",
    "-y",
    "-f",
    "lavfi",
    "-i",
    `color=c=0x0b1220:s=${FILM_WIDTH}x=${FILM_HEIGHT}:d=1`.replace("x=", "x"),
    "-frames:v",
    "1",
    "-vf",
    vfParts.join(","),
    "-pix_fmt",
    "yuvj420p",
    "-q:v",
    "2",
    relJpegFile,
  ]);
}

export function speedLabelText(speed: number): string {
  return speed === 1
    ? "Real time · every frame is real"
    : `${Number(speed.toFixed(2))}x speed · every frame is real`;
}

interface PlannedSegment {
  kind: "intro" | "chapter" | "board" | "outro";
  relJpeg?: string;
  boardStartSec?: number;
  boardEndSec?: number;
  outStartSec: number;
  outEndSec: number;
  waveNumber?: number;
  captions?: AssCaptionDialogue[];
}

function scheduleBoardFrames(
  relFrames: ReadonlyArray<{ relSec: number; relPath: string }>,
  segStart: number,
  segEnd: number,
): Array<{ relPath: string; holdSec: number }> {
  let idx = 0;
  for (let i = 0; i < relFrames.length; i++) {
    const f = relFrames[i];
    if (f && f.relSec <= segStart) {
      idx = i;
    } else {
      break;
    }
  }
  const initialFrame = relFrames[idx] ?? relFrames[0];
  if (!initialFrame) {
    return [];
  }

  const starts: Array<{ t: number; relPath: string }> = [
    { t: segStart, relPath: initialFrame.relPath },
  ];
  for (let i = idx + 1; i < relFrames.length; i++) {
    const f = relFrames[i];
    if (f && f.relSec > segStart && f.relSec < segEnd) {
      starts.push({ t: f.relSec, relPath: f.relPath });
    }
  }

  const scheduled: Array<{ relPath: string; holdSec: number }> = [];
  for (let k = 0; k < starts.length; k++) {
    const cur = starts[k];
    if (!cur) continue;
    const nxt = k + 1 < starts.length ? (starts[k + 1]?.t ?? segEnd) : segEnd;
    if (nxt > cur.t) {
      scheduled.push({ relPath: cur.relPath, holdSec: Number((nxt - cur.t).toFixed(6)) });
    }
  }
  return scheduled;
}

export interface CutCfrFilmOptions {
  outDir: string;
  huntId: string;
  caseMetadata: Pick<CaseMetadata, "case_id" | "title" | "data_origin" | "synthetic_only">;
  frames: readonly CapturedFrameEntry[];
  chapters: readonly FilmWaveChapterInput[];
  captionEvents?: readonly FilmCaptionEvent[];
  introLines?: readonly string[];
  outroLines?: readonly string[];
  speed?: number;
  captions?: boolean;
  allowWorkFilm?: boolean;
  ffmpegPath?: string;
}

/**
 * Renders a CFR 30fps `1920x1080` dual cut (`video-full.mp4` at 1x and `video.mp4` at `speed`x, default `5x`)
 * plus `video.ass`, `video-full.ass`, and `edit.json` inside `outDir` using strictly relative ASCII filenames.
 */
export function cutCfrFilm(options: CutCfrFilmOptions): FilmExportResult {
  const enclosingGit = findEnclosingGitMarker(options.outDir);
  if (enclosingGit !== null) {
    throw new RuntimeFenceError(options.outDir, enclosingGit);
  }

  const rule4 = enforceRule4FilmGuard(options.caseMetadata, options.allowWorkFilm === true);

  if (options.frames.length === 0) {
    throw new Error("cutCfrFilm requires at least one captured 1920x1080 board frame");
  }

  const resolvedFfmpeg = options.ffmpegPath
    ? { available: true, ffmpegPath: options.ffmpegPath, hasLibass: true }
    : resolveFfmpegBinary();
  if (!resolvedFfmpeg.available || !resolvedFfmpeg.ffmpegPath) {
    throw new Error("ffmpeg.exe with libass was not found on PATH or %LOCALAPPDATA%/hermes/tools");
  }
  if (!resolvedFfmpeg.hasLibass) {
    throw new Error(`ffmpeg binary '${resolvedFfmpeg.ffmpegPath}' lacks required 'ass' (libass) filter`);
  }
  const ffmpegPath = resolvedFfmpeg.ffmpegPath;

  const reviewedSpeed = Math.min(30, Math.max(2, options.speed ?? 5));
  const captionsEnabled = options.captions !== false;

  fs.mkdirSync(options.outDir, { recursive: true });
  const framesSubdir = path.join(options.outDir, "frames");
  fs.mkdirSync(framesSubdir, { recursive: true });
  const cardsSubdir = path.join(options.outDir, "cards");
  fs.mkdirSync(cardsSubdir, { recursive: true });

  // Stage frames under relative ASCII paths `frames/000001.jpg` inside `outDir` so `ffconcat` never
  // embeds `outDir` characters (`'`, `[`, spaces, or Windows drive letters).
  const sortedFrames = [...options.frames].sort((a, b) => a.epochSec - b.epochSec);
  const startEpochSec = sortedFrames[0]?.epochSec ?? 0;
  const lastFrameEpochSec = sortedFrames[sortedFrames.length - 1]?.epochSec ?? startEpochSec;
  const roundDurationSec = Math.max(1.0, Number((lastFrameEpochSec - startEpochSec + 1.0).toFixed(3)));

  const stagedRelFrames: Array<{ relSec: number; relPath: string }> = sortedFrames.map((entry, idx) => {
    const asciiName = `${String(idx + 1).padStart(6, "0")}.jpg`;
    const destAbs = path.join(framesSubdir, asciiName);
    const srcAbs = path.resolve(entry.imagePath);
    if (srcAbs.toLowerCase() !== destAbs.toLowerCase()) {
      fs.copyFileSync(srcAbs, destAbs);
    }
    return {
      relSec: Math.max(0, Number((entry.epochSec - startEpochSec).toFixed(3))),
      relPath: `frames/${asciiName}`,
    };
  });

  const defaultIntro = options.introLines ?? [
    "Hunt Command — 4-Pane DFIR Tactical Flight Recording",
    `Case ${options.caseMetadata.case_id} · Run ${options.huntId}`,
    `Data Origin: ${options.caseMetadata.data_origin} · Every frame is a real 1920x1080 capture`,
  ];
  const defaultOutro = options.outroLines ?? [
    `Hunt ${options.huntId} Complete · ${options.chapters.length} Waves Recorded`,
    `${stagedRelFrames.length} real offscreen 1920x1080 frames captured`,
    "Citations verified inline · Zero external network egress",
  ];

  renderCardJpeg(
    ffmpegPath,
    options.outDir,
    "cards/card-intro.ass",
    "cards/card-intro.jpg",
    defaultIntro,
    rule4.bannerText,
  );
  renderCardJpeg(
    ffmpegPath,
    options.outDir,
    "cards/card-outro.ass",
    "cards/card-outro.jpg",
    defaultOutro,
    rule4.bannerText,
  );

  const sortedChapters = [...options.chapters].sort((a, b) => a.startedAtSec - b.startedAtSec);
  const chapterCardRelPaths = new Map<number, string>();
  sortedChapters.forEach((ch, index) => {
    const relAss = `cards/card-ch-${String(index + 1).padStart(2, "0")}.ass`;
    const relJpg = `cards/card-ch-${String(index + 1).padStart(2, "0")}.jpg`;
    const durSec = Math.max(0, Math.round(ch.endedAtSec - ch.startedAtSec));
    const lines = [
      `Wave ${ch.waveNumber} of ${ch.totalWaves} · ${ch.stepIds.join(", ")}`,
      ch.roles.join(" · "),
      `Duration: ${durSec}s`,
      ...(ch.droppedOrStoppedSummary ? [ch.droppedOrStoppedSummary] : []),
    ];
    renderCardJpeg(ffmpegPath, options.outDir, relAss, relJpg, lines, rule4.bannerText);
    chapterCardRelPaths.set(index, relJpg);
  });

  const rawCaptionEvents = (options.captionEvents ?? [])
    .map((ev) => ({
      relSec: Number((ev.epochSec - startEpochSec).toFixed(3)),
      text: ev.text,
    }))
    .filter((ev) => ev.relSec >= 0 && ev.relSec <= roundDurationSec)
    .sort((a, b) => a.relSec - b.relSec);

  const renderCut = (
    speed: number,
    relConcatName: string,
    relAssName: string,
    relMp4Name: string,
  ): { outSeconds: number; segments: PlannedSegment[] } => {
    const holdReal = CAPTION_HOLD_SECONDS * speed;
    const realSpans: Array<{ s: number; e: number; text: string }> = [];
    if (captionsEnabled) {
      for (let i = 0; i < rawCaptionEvents.length; i++) {
        const cur = rawCaptionEvents[i];
        if (!cur) continue;
        const nextStart =
          i + 1 < rawCaptionEvents.length
            ? (rawCaptionEvents[i + 1]?.relSec ?? roundDurationSec)
            : roundDurationSec;
        const end = Math.min(cur.relSec + holdReal, nextStart, roundDurationSec);
        if (end > cur.relSec) {
          realSpans.push({ s: cur.relSec, e: end, text: cur.text });
        }
      }
    }

    const segments: PlannedSegment[] = [];
    let outCursor = 0;

    segments.push({
      kind: "intro",
      relJpeg: "cards/card-intro.jpg",
      outStartSec: 0,
      outEndSec: INTRO_SECONDS,
    });
    outCursor = INTRO_SECONDS;

    let boardCursor = 0;
    const clipCaptions = (segStart: number, segEnd: number, outBase: number): AssCaptionDialogue[] => {
      const dialogues: AssCaptionDialogue[] = [];
      for (const sp of realSpans) {
        const a = (Math.max(sp.s, segStart) - segStart) / speed;
        const b = (Math.min(sp.e, segEnd) - segStart) / speed;
        if (b - a >= MIN_CAPTION_SECONDS) {
          dialogues.push({
            startSec: Number((outBase + a).toFixed(3)),
            endSec: Number((outBase + b).toFixed(3)),
            text: sp.text,
          });
        }
      }
      return dialogues;
    };

    sortedChapters.forEach((ch, idx) => {
      const atRel = Math.min(
        roundDurationSec,
        Math.max(0, Number((ch.startedAtSec - startEpochSec).toFixed(3))),
      );
      if (atRel > boardCursor) {
        const outDur = (atRel - boardCursor) / speed;
        segments.push({
          kind: "board",
          boardStartSec: boardCursor,
          boardEndSec: atRel,
          outStartSec: Number(outCursor.toFixed(3)),
          outEndSec: Number((outCursor + outDur).toFixed(3)),
          captions: clipCaptions(boardCursor, atRel, outCursor),
        });
        outCursor += outDur;
        boardCursor = atRel;
      }

      segments.push({
        kind: "chapter",
        relJpeg: chapterCardRelPaths.get(idx) ?? "cards/card-intro.jpg",
        waveNumber: ch.waveNumber,
        outStartSec: Number(outCursor.toFixed(3)),
        outEndSec: Number((outCursor + CHAPTER_SECONDS).toFixed(3)),
      });
      outCursor += CHAPTER_SECONDS;
    });

    if (roundDurationSec > boardCursor) {
      const outDur = (roundDurationSec - boardCursor) / speed;
      segments.push({
        kind: "board",
        boardStartSec: boardCursor,
        boardEndSec: roundDurationSec,
        outStartSec: Number(outCursor.toFixed(3)),
        outEndSec: Number((outCursor + outDur).toFixed(3)),
        captions: clipCaptions(boardCursor, roundDurationSec, outCursor),
      });
      outCursor += outDur;
    }

    segments.push({
      kind: "outro",
      relJpeg: "cards/card-outro.jpg",
      outStartSec: Number(outCursor.toFixed(3)),
      outEndSec: Number((outCursor + OUTRO_SECONDS).toFixed(3)),
    });
    outCursor += OUTRO_SECONDS;

    const concatEntries: Array<{ relPath: string; durationSec: number }> = [];
    const allDialogues: AssCaptionDialogue[] = [];

    for (const seg of segments) {
      if (seg.kind === "intro" || seg.kind === "chapter" || seg.kind === "outro") {
        concatEntries.push({
          relPath: seg.relJpeg ?? "cards/card-intro.jpg",
          durationSec: seg.outEndSec - seg.outStartSec,
        });
      } else {
        const scheduled = scheduleBoardFrames(
          stagedRelFrames,
          seg.boardStartSec ?? 0,
          seg.boardEndSec ?? roundDurationSec,
        );
        for (const item of scheduled) {
          concatEntries.push({
            relPath: item.relPath,
            durationSec: item.holdSec / speed,
          });
        }
        if (seg.captions) {
          allDialogues.push(...seg.captions);
        }
      }
    }

    const totalSec = concatEntries.reduce((acc, e) => acc + e.durationSec, 0);
    const concatLines = ["ffconcat version 1.0"];
    for (const entry of concatEntries) {
      concatLines.push(`file '${entry.relPath}'`);
      concatLines.push(`duration ${entry.durationSec.toFixed(6)}`);
    }
    const lastEntry = concatEntries[concatEntries.length - 1];
    if (lastEntry) {
      concatLines.push(`file '${lastEntry.relPath}'`);
    }
    fs.writeFileSync(path.join(options.outDir, relConcatName), `${concatLines.join("\n")}\n`, "utf8");

    const assContent = buildAssSubtitles({
      totalDurationSec: totalSec,
      speed,
      speedLabel: speedLabelText(speed),
      captions: allDialogues,
      nonSyntheticBannerText: rule4.bannerText,
    });
    fs.writeFileSync(path.join(options.outDir, relAssName), assContent, "utf8");

    const vfChain = [
      `scale=${FILM_WIDTH}:${FILM_HEIGHT}:force_original_aspect_ratio=decrease`,
      `pad=${FILM_WIDTH}:${FILM_HEIGHT}:(ow-iw)/2:(oh-ih)/2:color=0x0b1220`,
      "setsar=1",
      `fps=${FILM_FPS}`,
      `trim=duration=${totalSec.toFixed(6)}`,
      "setpts=PTS-STARTPTS",
      "drawbox=x=0:y=ih-64:w=iw:h=64:color=black@0.82:t=fill",
      ...(rule4.burnNonSyntheticBanner
        ? ["drawbox=x=0:y=0:w=iw:h=48:color=0x991b1b@0.94:t=fill"]
        : []),
      `ass=filename=${relAssName}`,
      "scale=in_range=auto:out_range=tv",
      "format=yuv420p",
    ].join(",");

    runFfmpegInOutDir(ffmpegPath, options.outDir, [
      "-hide_banner",
      "-loglevel",
      "error",
      "-y",
      "-f",
      "concat",
      "-safe",
      "0",
      "-i",
      relConcatName,
      "-vf",
      vfChain,
      "-an",
      "-fps_mode",
      "cfr",
      "-r",
      String(FILM_FPS),
      "-c:v",
      "libx264",
      "-preset",
      "veryfast",
      "-crf",
      "20",
      "-g",
      String(FILM_FPS),
      "-keyint_min",
      String(FILM_FPS),
      "-sc_threshold",
      "0",
      "-color_range",
      "tv",
      "-pix_fmt",
      "yuv420p",
      "-movflags",
      "+faststart",
      relMp4Name,
    ]);

    return {
      outSeconds: Number(totalSec.toFixed(3)),
      segments,
    };
  };

  const fullCut = renderCut(1, "concat-full.ffconcat", "video-full.ass", "video-full.mp4");
  const reviewedCut = renderCut(reviewedSpeed, "concat-5x.ffconcat", "video.ass", "video.mp4");

  const editSummary = {
    schema_version: 1,
    hunt_id: options.huntId,
    case_id: options.caseMetadata.case_id,
    data_origin: options.caseMetadata.data_origin,
    non_synthetic_work_banner_burned: rule4.burnNonSyntheticBanner,
    resolution: `${FILM_WIDTH}x${FILM_HEIGHT}`,
    fps: FILM_FPS,
    video: "video.mp4",
    video_full: "video-full.mp4",
    ass: "video.ass",
    ass_full: "video-full.ass",
    speed: reviewedSpeed,
    board_frames: stagedRelFrames.length,
    round_seconds: roundDurationSec,
    out_seconds_reviewed: reviewedCut.outSeconds,
    out_seconds_full: fullCut.outSeconds,
    chapter_count: sortedChapters.length,
  };

  const editJsonPath = path.join(options.outDir, "edit.json");
  fs.writeFileSync(editJsonPath, `${JSON.stringify(editSummary, null, 2)}\n`, "utf8");

  return {
    filmDir: options.outDir,
    video5xPath: path.join(options.outDir, "video.mp4"),
    videoFull1xPath: path.join(options.outDir, "video-full.mp4"),
    assPath: path.join(options.outDir, "video.ass"),
    editJsonPath,
    frameCount: stagedRelFrames.length,
    nonSyntheticWorkBannerBurned: rule4.burnNonSyntheticBanner,
  };
}
