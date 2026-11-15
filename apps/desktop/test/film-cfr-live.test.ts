import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, test } from "bun:test";
import {
  buildAssSubtitles,
  CHAPTER_SECONDS,
  cutCfrFilm,
  enforceRule4FilmGuard,
  FILM_FPS,
  FILM_HEIGHT,
  FILM_WIDTH,
  resolveFfmpegBinary,
  Rule4FilmRefusedError,
} from "../src/main/film/cfr-editor.ts";

function generateTestBoardJpeg(ffmpegPath: string, outPath: string, hexColor: string): void {
  const res = spawnSync(
    ffmpegPath,
    [
      "-hide_banner",
      "-loglevel",
      "error",
      "-y",
      "-f",
      "lavfi",
      "-i",
      `color=c=${hexColor}:s=${FILM_WIDTH}x${FILM_HEIGHT}:d=1`,
      "-frames:v",
      "1",
      "-pix_fmt",
      "yuvj420p",
      "-q:v",
      "2",
      outPath,
    ],
    {
      encoding: "utf8",
      windowsHide: true,
      timeout: 30_000,
    },
  );
  if (res.status !== 0) {
    throw new Error(`Failed to synthesize test board JPEG: ${res.stderr ?? ""}`);
  }
}

const FILM_ENCODE_TEST_TIMEOUT_MS = 240_000;

describe("Offscreen 1920x1080 CFR 30fps Filming, ASS Margin Styling & Rule 4 Guard (#178 G3.1-G3.3)", () => {
  test("Rule 4 film guard refuses non-synthetic export unless allowWorkFilm=true (which burns crimson watermark)", () => {
    expect(() =>
      enforceRule4FilmGuard({ data_origin: "work-export", synthetic_only: false }, false),
    ).toThrow(Rule4FilmRefusedError);

    const watermarked = enforceRule4FilmGuard(
      { data_origin: "work-export", synthetic_only: false },
      true,
    );
    expect(watermarked.allowed).toBe(true);
    expect(watermarked.burnNonSyntheticBanner).toBe(true);
    expect(watermarked.bannerText).toContain("NON-SYNTHETIC (WORK-EXPORT) — OPERATOR LOCAL ONLY");

    const synthetic = enforceRule4FilmGuard(
      { data_origin: "synthetic", synthetic_only: true },
      false,
    );
    expect(synthetic.burnNonSyntheticBanner).toBe(false);
    expect(synthetic.bannerText).toBeNull();
  });

  test("buildAssSubtitles emits PlayRes 1920x1080, WrapStyle=2, and Margin-styled Alignment=1 captions with zero \\pos", () => {
    const ass = buildAssSubtitles({
      totalDurationSec: 18.5,
      speed: 5,
      speedLabel: "5x speed · every frame is real",
      captions: [
        {
          startSec: 5.0,
          endSec: 7.4,
          text: 'framework-researcher · elastic_search {attempt_override}\nline2',
        },
      ],
      nonSyntheticBannerText: "NON-SYNTHETIC (PUBLIC-DATASET) — OPERATOR LOCAL ONLY",
    });

    expect(ass).toContain("PlayResX: 1920");
    expect(ass).toContain("PlayResY: 1080");
    expect(ass).toContain("WrapStyle: 2");
    // Alignment=1, MarginL=620, MarginR=24, MarginV=18
    expect(ass).toContain(",1,620,24,18,1");
    expect(ass).not.toContain("\\pos(");
    // Brace injection in untrusted telemetry caption must be escaped
    expect(ass).toContain("\\{attempt_override\\}");
    expect(ass).toContain("Rule4Banner");
  });

  test("renders live CFR 30fps 1920x1080 video-full.mp4 (1x) + video.mp4 (5x) + video.ass via ffmpeg.exe in path with apostrophe & brackets", () => {
    const ffmpeg = resolveFfmpegBinary();
    expect(ffmpeg.available).toBe(true);
    expect(ffmpeg.hasLibass).toBe(true);
    expect(ffmpeg.ffmpegPath).not.toBeNull();

    // Intentionally include apostrophe `'` and brackets `[` in OS temp path to prove relative-cwd immunity!
    const trickyTmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hunt-film-O'Connor-[cfr]-"));
    try {
      const rawCapDir = path.join(trickyTmpRoot, "raw-capture");
      const outFilmDir = path.join(trickyTmpRoot, "cut-output");
      fs.mkdirSync(rawCapDir, { recursive: true });

      const f1 = path.join(rawCapDir, "board-1.jpg");
      const f2 = path.join(rawCapDir, "board-2.jpg");
      const f3 = path.join(rawCapDir, "board-3.jpg");
      generateTestBoardJpeg(ffmpeg.ffmpegPath!, f1, "0x0f172a");
      generateTestBoardJpeg(ffmpeg.ffmpegPath!, f2, "0x1e293b");
      generateTestBoardJpeg(ffmpeg.ffmpegPath!, f3, "0x0c4a6e");

      const t0 = 1_763_132_700;
      const result = cutCfrFilm({
        outDir: outFilmDir,
        huntId: "hunt-cfr-live-01",
        caseMetadata: {
          case_id: "northvale-lab-001",
          title: "Northvale Live FFmpeg CFR Verification",
          data_origin: "work-export",
          synthetic_only: false,
        },
        frames: [
          { epochSec: t0, imagePath: f1 },
          { epochSec: t0 + 2.0, imagePath: f2 },
          { epochSec: t0 + 4.0, imagePath: f3 },
        ],
        chapters: [
          {
            waveNumber: 1,
            totalWaves: 2,
            startedAtSec: t0,
            endedAtSec: t0 + 2.0,
            stepIds: ["scope"],
            roles: ["framework-coordinator"],
          },
          {
            waveNumber: 2,
            totalWaves: 2,
            startedAtSec: t0 + 2.0,
            endedAtSec: t0 + 5.0,
            stepIds: ["evidence", "network"],
            roles: ["framework-researcher", "framework-network-analyst"],
          },
        ],
        captionEvents: [
          {
            epochSec: t0 + 0.5,
            text: "framework-researcher · elastic_search process.name:UserSyncHelper.exe",
          },
          {
            epochSec: t0 + 2.5,
            text: "framework-network-analyst · packet_fields tls.handshake.ja4",
          },
        ],
        speed: 5,
        captions: true,
        allowWorkFilm: true,
      });

      expect(CHAPTER_SECONDS).toBe(2.5);
      expect(result.nonSyntheticWorkBannerBurned).toBe(true);
      expect(result.frameCount).toBe(3);
      expect(fs.existsSync(result.video5xPath)).toBe(true);
      expect(fs.existsSync(result.videoFull1xPath)).toBe(true);
      expect(fs.existsSync(result.assPath)).toBe(true);
      expect(fs.existsSync(result.editJsonPath)).toBe(true);

      const mp45xBytes = fs.readFileSync(result.video5xPath);
      const mp41xBytes = fs.readFileSync(result.videoFull1xPath);
      expect(mp45xBytes.byteLength).toBeGreaterThan(8_000);
      expect(mp41xBytes.byteLength).toBeGreaterThan(8_000);

      // Verify +faststart: 'moov' atom precedes 'mdat' atom in both MP4 files!
      const moovIdx5x = mp45xBytes.indexOf(Buffer.from("moov", "ascii"));
      const mdatIdx5x = mp45xBytes.indexOf(Buffer.from("mdat", "ascii"));
      expect(moovIdx5x).toBeGreaterThan(0);
      expect(mdatIdx5x).toBeGreaterThan(moovIdx5x);

      // Verify exact 1920x1080 & 30/1 CFR via ffprobe when present alongside ffmpeg
      if (ffmpeg.ffprobePath) {
        const probe = spawnSync(
          ffmpeg.ffprobePath,
          [
            "-v",
            "error",
            "-select_streams",
            "v:0",
            "-show_entries",
            "stream=codec_name,width,height,r_frame_rate,avg_frame_rate,pix_fmt",
            "-of",
            "json",
            result.video5xPath,
          ],
          {
            encoding: "utf8",
            windowsHide: true,
            timeout: 15_000,
          },
        );
        expect(probe.status).toBe(0);
        const parsed = JSON.parse(probe.stdout) as {
          streams: Array<{
            codec_name: string;
            width: number;
            height: number;
            r_frame_rate: string;
            avg_frame_rate: string;
            pix_fmt: string;
          }>;
        };
        const stream = parsed.streams[0];
        expect(stream?.codec_name).toBe("h264");
        expect(stream?.width).toBe(1920);
        expect(stream?.height).toBe(1080);
        expect(stream?.r_frame_rate).toBe("30/1");
        expect(stream?.pix_fmt).toBe("yuv420p");
      }
    } finally {
      fs.rmSync(trickyTmpRoot, { recursive: true, force: true });
    }
    // Real ffmpeg encodes (1x + 5x + probes) take ~4s on an idle machine; under CI or parallel load this far exceeds
    // bun's 5s default, which killed ffmpeg mid-encode. Bounded by the per-encode 180s spawn timeout.
  }, FILM_ENCODE_TEST_TIMEOUT_MS);
});
