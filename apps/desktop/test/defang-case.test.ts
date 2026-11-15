import { describe, expect, test } from "bun:test";
import {
  renderDefangedMarkdownBlock,
  renderDefangedMarkdownInline,
  renderDefangedPlainText,
} from "../src/main/export/report-exporter.ts";
import { tokenizeForensicText } from "../src/shared/sanitize.ts";

const CASES = [
  "HTTPS://EVIL.EXAMPLE/Y",
  "Https://evil.example/y",
  "hTtP://Evil.Example/y",
  "EVIL.EXAMPLE",
  "WWW.EVIL.EXAMPLE/p",
  "Www.evil.example",
  "beacon at C2.EVIL.COM:443 then 198.51.100.7",
];

/** True when `text` still contains a live (un-defanged) scheme or dotted public hostname. */
function hasLiveIndicator(text: string): boolean {
  return /\b(?:https?|ftp|wss?):\/\//i.test(text) || /\b[a-z0-9-]+\.(?:example|com)\b/i.test(text);
}

describe("defanging is case-insensitive (markdown, plain text, print/PDF paths)", () => {
  for (const raw of CASES) {
    test(JSON.stringify(raw), () => {
      for (const rendered of [
        renderDefangedPlainText(raw),
        renderDefangedMarkdownInline(raw),
        renderDefangedMarkdownBlock(raw),
      ]) {
        expect(hasLiveIndicator(rendered)).toBe(false);
        expect(rendered).toContain("[.]");
      }
      const indicators = tokenizeForensicText(raw).filter((t) => t.kind === "indicator");
      expect(indicators.length).toBeGreaterThan(0);
    });
  }

  test("only lowercase evt-/frame-/ioc- ids are provenance citations", () => {
    expect(tokenizeForensicText("see evt-abc1 and frame-12")).toEqual([
      { kind: "text", text: "see " },
      { kind: "citation", id: "evt-abc1", citationKind: "evt" },
      { kind: "text", text: " and " },
      { kind: "citation", id: "frame-12", citationKind: "frame" },
    ]);
    expect(tokenizeForensicText("EVT-abc1").every((t) => t.kind === "text")).toBe(true);
  });
});
