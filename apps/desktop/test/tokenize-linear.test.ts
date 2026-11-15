import { describe, expect, test } from "bun:test";
import { type ForensicTextToken, tokenizeForensicText } from "../src/shared/sanitize.ts";

/**
 * The previous single-regex tokenizer, kept verbatim as an oracle. It is correct but quadratic on long
 * dotted runs, so it is only ever run on short fuzz inputs here.
 */
const ORACLE_RE = new RegExp(
  [
    "(\\b(?:evt-[A-Za-z0-9_-]+|frame-\\d+|ioc-\\d+)\\b)",
    "(\\b(?:https?|hxxps?|ftp|fxp|wss?|wxss?):\\/\\/[^\\s<>\"'`\\])]+)",
    "(\\b(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)(?::\\d{1,5})?\\b)",
    "(\\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+(?:com|net|org|io|dev|app|cloud|gov|mil|edu|info|biz|xyz|top|ru|cn|ir|kp|uk|de|fr|nl|co|me|ai|test|example|invalid|localhost|local|internal|corp|lan)\\b)",
  ].join("|"),
  "gi",
);

/** Token spans `[kind, text]` the oracle regex produces (before punctuation trimming / defanging). */
function oracleSpans(text: string): Array<[string, number, string]> {
  const out: Array<[string, number, string]> = [];
  ORACLE_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = ORACLE_RE.exec(text)) !== null) {
    const kind = m[1] !== undefined ? "cite" : m[2] !== undefined ? "url" : m[3] !== undefined ? "ipv4" : "domain";
    out.push([kind, m.index, m[0]]);
  }
  return out;
}

/** Rebuilds the same span view from tokenizer output (indicators and citations, in order). */
function spansOf(tokens: ForensicTextToken[]): string[] {
  return tokens
    .filter((t) => t.kind !== "text")
    .map((t) => (t.kind === "citation" ? `cite:${t.id}` : `${t.indicatorKind}:${t.raw}`));
}

function oracleTokenSpans(text: string): string[] {
  const trimmed: string[] = [];
  for (const [kind, , raw] of oracleSpans(text)) {
    if (kind === "cite") {
      if (/^(?:evt-[A-Za-z0-9_-]+|frame-\d+|ioc-\d+)$/.test(raw)) trimmed.push(`cite:${raw}`);
      continue;
    }
    let end = raw.length;
    while (end > 0) {
      const ch = raw[end - 1];
      if (ch === "." || ch === "," || ch === ";" || ch === ":" || ch === "!" || ch === "?") end--;
      else if (ch === ")" && !raw.slice(0, end).includes("(")) end--;
      else break;
    }
    if (end > 0) trimmed.push(`${kind}:${raw.slice(0, end)}`);
  }
  return trimmed;
}

/** Deterministic PRNG so failures reproduce. */
function rng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 2 ** 32;
  };
}

const ALPHABET = [
  "a", "b", "Z", "0", "1", "9", ".", ".", ".", "-", "-", "_", " ", ":", "/", "(", ")", ",",
  "com", "COM", "co", "local", "localhost", "example", "io", "info", "www.", "http://", "HTTPS://",
  "hxxp://", "evt-", "EVT-", "frame-", "ioc-", "1.2.3.4", "255.", "evil", "x".repeat(62), "y".repeat(64),
];

describe("tokenizeForensicText is linear and unchanged in behaviour", () => {
  test("matches the previous regex tokenizer on 20,000 random short inputs", () => {
    const next = rng(0x5eed);
    for (let i = 0; i < 20_000; i++) {
      let s = "";
      const parts = 1 + Math.floor(next() * 14);
      for (let p = 0; p < parts; p++) s += ALPHABET[Math.floor(next() * ALPHABET.length)];
      const got = spansOf(tokenizeForensicText(s));
      const want = oracleTokenSpans(s);
      if (JSON.stringify(got) !== JSON.stringify(want)) {
        throw new Error(`mismatch for ${JSON.stringify(s)}: got ${JSON.stringify(got)} want ${JSON.stringify(want)}`);
      }
    }
  });

  test("matches the previous tokenizer on hand-picked edge cases", () => {
    for (const s of [
      "c2.evil.com and 198.51.100.7:8080 and https://x.example/a?b",
      "a..evil.com",
      "-a.evil.com",
      "foo-bar.evil.co-op.org",
      "process.command_line.evil.com",
      "x_y.evil.com z.evt-abc.com evt-abc.evil.com",
      "1.2.3.4.example 1.2.3.4.5.com",
      `${"q".repeat(63)}.com ${"q".repeat(64)}.com a-${"q".repeat(64)}.com`,
      "evil.comm evil.com-x evil.local-host.lan",
      "WWW.EVIL.EXAMPLE/p Www.evil.example hTtP://Evil.Example/y",
      "(see evil.com).",
    ]) {
      expect(spansOf(tokenizeForensicText(s))).toEqual(oracleTokenSpans(s));
    }
  });

  const MB = 1024 * 1024;
  for (const unit of ["1.", "a.", "a-", "http://", "www.", "deadbeef", "0123456789abcdef.", "a.a-", "evt-", "a.com.", "a_.", "-."]) {
    test(
      `1 MB of ${JSON.stringify(unit)} repeated tokenizes in under 1 s`,
      () => {
        const input = unit.repeat(Math.ceil(MB / unit.length)).slice(0, MB);
        const t0 = performance.now();
        const tokens = tokenizeForensicText(input);
        const ms = performance.now() - t0;
        expect(tokens.length).toBeGreaterThan(0);
        expect(ms).toBeLessThan(1_000);
      },
      60_000,
    );
  }
});
