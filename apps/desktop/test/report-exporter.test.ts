import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, test } from "bun:test";
import { RuntimeFenceError } from "@hunt-command/shared";
import {
  AnswerKeyContaminationError,
  exportCustomerReport,
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
});
