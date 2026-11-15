import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, test } from "bun:test";
import { RuntimeFenceError } from "@hunt-command/shared";
import {
  AnswerKeyContaminationError,
  buildCustomerReportMarkdown,
  exportCustomerReport,
  renderDefangedMarkdownBlock,
  renderDefangedMarkdownInline,
} from "../src/main/export/report-exporter.ts";
import { buildFixtureWorkbenchSnapshot } from "../src/shared/fixture-workbench.ts";

describe("Customer Report Exporter (.md + .pdf + provenance JSON, F02/F22)", () => {
  test("exports defanged Markdown, printable PDF, and provenance JSON separating raw records from model prose", async () => {
    const tmpExportsDir = fs.mkdtempSync(path.join(os.tmpdir(), "hunt-report-export-"));
    try {
      const workbench = buildFixtureWorkbenchSnapshot({
        huntId: "hunt-export-01",
        dataOrigin: "synthetic",
        openGate: null,
      });

      const result = await exportCustomerReport({
        workbench,
        exportsRootDir: tmpExportsDir,
        exportedAtIso: "2026-11-15T01:30:00.000Z",
      });

      expect(fs.existsSync(result.markdownPath)).toBe(true);
      expect(fs.existsSync(result.pdfPath)).toBe(true);
      expect(fs.existsSync(result.provenanceJsonPath)).toBe(true);
      expect(result.reportSha256).toMatch(/^[a-f0-9]{64}$/);

      const md = fs.readFileSync(result.markdownPath, "utf8");
      // Live URLs and IPs in model prose and raw records must be defanged
      expect(md).toContain("hxxps://cdn-telemetry.northvale-sync[.]test/api/v2/checkin");
      expect(md).toContain("198.51.100[.]42");
      expect(md).not.toContain("https://cdn-telemetry.northvale-sync.test");

      // Strict epistemic separation + limitations + purple reviews + contradicts preserved
      expect(md).toContain("## 1. Observed Facts & Confirmed Findings (Model Analytical Prose)");
      expect(md).toContain("## 2. Analytical Inferences & Hypotheses (Model Analytical Prose)");
      expect(md).toContain("## 3. Adversarial Purple Reviews & Contradiction Ledger");
      expect(md).toContain("## 4. Telemetry Gaps & Analytical Limitations");
      expect(md).toContain("## 5. Immutable Raw Source Telemetry Records");
      expect(md).toContain("Contradicts**: `hypotheses:c1`");
      expect(md).toContain("purple:r1");
      expect(md).toContain("Sysmon EventID 7 image-load telemetry was not enabled");

      // Valid PDF header & EOF trailer
      const pdfHeader = fs.readFileSync(result.pdfPath).subarray(0, 8).toString("ascii");
      expect(pdfHeader).toContain("%PDF-1.4");

      const bundle = JSON.parse(fs.readFileSync(result.provenanceJsonPath, "utf8")) as Record<
        string,
        unknown
      >;
      expect(bundle.report_markdown_sha256).toBe(result.reportSha256);
      expect(bundle.immutable_raw_source_records).toBeDefined();
      expect(bundle.model_prose_handoffs).toBeDefined();
    } finally {
      fs.rmSync(tmpExportsDir, { recursive: true, force: true });
    }
  });

  test("refuses writing inside a Git repository and refuses answer-key contaminated payloads", async () => {
    const workbench = buildFixtureWorkbenchSnapshot();
    const illegalInRepoDir = path.resolve(import.meta.dir, "../illegal-exports");

    await expect(
      exportCustomerReport({
        workbench,
        exportsRootDir: illegalInRepoDir,
      }),
    ).rejects.toBeInstanceOf(RuntimeFenceError);

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "hunt-report-contaminated-"));
    try {
      const contaminated = {
        ...workbench,
        answer_key: { culprit: "wks-fin-07" },
      } as unknown as typeof workbench;

      await expect(
        exportCustomerReport({
          workbench: contaminated,
          exportsRootDir: tmpDir,
        }),
      ).rejects.toBeInstanceOf(AnswerKeyContaminationError);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test("Markdown report escapes untrusted text: no live images, links, HTML, forged sections, or code-span breakout", () => {
    // Raw HTML / image / link payloads render inert and protocol-relative hosts are defanged.
    const img = renderDefangedMarkdownInline("see <img src=//t.pw/b.png> now");
    expect(img).not.toMatch(/(^|[^\\])<img/);
    expect(img).toContain("\\<img src=//t\\[.\\]pw/b.png\\>");
    expect(img).not.toContain("t.pw");

    const link = renderDefangedMarkdownInline("click [x](//evil.pw/x)");
    expect(link).not.toMatch(/(^|[^\\])\]\(/);
    expect(link).not.toMatch(/(^|[^\\])\[x/);
    expect(link).not.toContain("evil.pw");

    const image = renderDefangedMarkdownInline("![](//a.xyz.pw/p)");
    expect(image).not.toMatch(/(^|[^\\])!\[/);
    expect(image).not.toMatch(/(^|[^\\])\]\(/);
    expect(image).not.toContain("a.xyz.pw");

    expect(renderDefangedMarkdownInline("visit www.t.pw today")).not.toContain("www.t.pw");
    expect(renderDefangedMarkdownInline("a `code` b *em* _u_ | pipe # hash ~s~")).toBe(
      "a \\`code\\` b \\*em\\* \\_u\\_ \\| pipe \\# hash \\~s\\~",
    );
    // Inline fields collapse newlines so they cannot open headings.
    expect(renderDefangedMarkdownInline("ok\n# Forged")).toBe("ok \\# Forged");
    // Citations stay readable but cannot pair with a forged link reference definition.
    expect(renderDefangedMarkdownInline("evt-a_b: //evil.pw/x")).toBe(
      "\\[evt-a\\_b\\]: //evil\\[.\\]pw/x",
    );

    // Multi-line statements: each line is escaped and cannot become a heading, list, rule, or code block.
    const block = renderDefangedMarkdownBlock(
      "first\n# Forged Section\n## 6. Fake\n- bullet\n+ plus\n1. ordered\n===\n    indented code\n> quote",
    );
    expect(block.split("\n")).toEqual([
      "first",
      "\\# Forged Section",
      "\\#\\# 6. Fake",
      "\\- bullet",
      "\\+ plus",
      "1\\. ordered",
      "\\===",
      "indented code",
      "\\> quote",
    ]);

    // End to end on the exported Markdown.
    const workbench = buildFixtureWorkbenchSnapshot({ huntId: "hunt-md-inject", openGate: null });
    const row = workbench.claims[0];
    if (!row) throw new Error("fixture has no claims");
    const hostileRow = row as unknown as {
      stepId: string;
      claim: { statement: string };
      inlineCitations: { id: string; status: string }[];
      reviews: { rationale: string }[];
    };
    hostileRow.stepId = "s1` <img src=//t.pw/a.png> `";
    hostileRow.claim.statement =
      "Benign start <img src=//t.pw/b.png> [x](//evil.pw/x) ![](//a.xyz.pw/p)\n## 6. Forged Section\n- forged bullet";
    const firstCitation = hostileRow.inlineCitations[0];
    if (firstCitation) {
      firstCitation.id = "evt-1` [x](//evil.pw/c)";
      firstCitation.status = "verified` <b>bold</b>";
    }
    const gate = workbench.gateHistory[0] as unknown as { payload_sha256: string; note: string };
    gate.payload_sha256 = "deadbeef` <img src=//t.pw/g.png>";
    gate.note = "approved\n# Forged Gate Section";
    const lim = workbench.limitations[0] as unknown as { stepId: string; text: string };
    lim.stepId = "s2] [x](//evil.pw/l)";
    lim.text = "gap\n## Forged Limitation";

    const md = buildCustomerReportMarkdown(workbench, "2026-11-15T01:30:00.000Z");
    expect(md).not.toMatch(/^#{1,6} (?:\\d+\. )?Forged/m);
    expect(md).not.toMatch(/^## 6\./m);
    expect(md).not.toMatch(/^- forged bullet/m);
    expect(md).toContain("\\#\\# 6. Forged Section");
    expect(md).toContain("`s1 <img src=//t.pw/a.png> `");
    expect(md).toContain("`evt-1 [x](//evil.pw/c)` (`verified <b>bold</b>`)");
    expect(md).toContain("SHA-256 _invalid digest withheld_");
    expect(md).not.toContain("deadbeef");
    expect(md).toContain("Note: approved \\# Forged Gate Section");
    expect(md).toContain("\\[s2\\] \\[x\\]\\(//evil\\[.\\]pw/l\\)");

    // Outside code spans, no live HTML, link, or image syntax survives.
    const outsideCode = md
      .replace(/^(`{3,})[^\n]*\n[\s\S]*?\n\1$/gm, "")
      .replace(/`[^`\n]*`/g, "");
    expect(outsideCode).not.toMatch(/(^|[^\\])<[A-Za-z/]/m);
    expect(outsideCode).not.toMatch(/(^|[^\\])\]\(/m);
    expect(outsideCode).not.toMatch(/(^|[^\\])!\[/m);
    expect(outsideCode).not.toContain("t.pw");
    expect(outsideCode).not.toContain("evil.pw");
    // Every code span is balanced on its line.
    for (const line of md.split("\n")) {
      if (/^`{3,}/.test(line)) continue;
      expect((line.match(/`/g) ?? []).length % 2).toBe(0);
    }
  });

  test("raw-record JSON fence outgrows any backtick run in record values", () => {
    const workbench = buildFixtureWorkbenchSnapshot({ huntId: "hunt-md-fence", openGate: null });
    const entry = workbench.citationReceipt.entries.find(
      (e) => workbench.evidenceCatalog[e.citationId] !== undefined,
    );
    if (!entry) throw new Error("fixture has no cited raw record");
    const record = workbench.evidenceCatalog[entry.citationId] as unknown as {
      fields: Record<string, unknown>;
    };
    record.fields.injected = "```\n# Escaped Fence Heading\n```";
    const md = buildCustomerReportMarkdown(workbench, "2026-11-15T01:30:00.000Z");
    expect(md).toContain("````json");
    expect(md).not.toMatch(/^# Escaped Fence Heading/m);
  });
});
