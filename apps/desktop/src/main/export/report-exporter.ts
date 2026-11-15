/**
 * Customer Report Exporter (`F02` / `F22` / `#189` Deliverable 3).
 *
 * Security & Epistemic Invariants:
 * - Refuses to write inside any `.git` repository or worktree (`findEnclosingGitMarker`).
 * - Rejects any input object containing answer-key / operator-only fields (`truth`, `answer_key`,
 *   `ground_truth`, `scoring_rubric`, `operator_only`).
 * - Defangs all live URLs, IPv4s, and FQDNs (`hxxps://...`, `[.]`) and strips bidi/ANSI/control chars.
 * - Strictly separates Model Analytical Prose (`observed`/`finding` vs `hypothesis`/`inference`)
 *   from Adversarial Purple Reviews (`reviews[]`), Contradictions (`contradicts[]`), Analytical
 *   Limitations (`limitations[]`), and Immutable Raw Source Telemetry Records (`evt-*`, `frame-*`, `ioc-*`).
 * - Markdown-escapes every untrusted text segment (no live links, images, HTML, headings, or code-span
 *   breakout), collapses newlines in inline fields, and defangs protocol-relative `//host` and `www.` hosts.
 */
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
  findEnclosingGitMarker,
  PROFILE_DISPLAY_TITLES,
  RuntimeFenceError,
} from "@hunt-command/shared";
import {
  defangIndicator,
  sanitizeSingleLine,
  stripControlAndBidiChars,
  tokenizeForensicText,
} from "../../shared/sanitize.ts";
import type { ReportExportResult } from "../../shared/ipc.ts";
import type { WorkbenchSnapshot } from "../../shared/workbench-types.ts";

const FORBIDDEN_ANSWER_KEY_FIELDS = new Set([
  "truth",
  "truth_json",
  "answer_key",
  "answerkey",
  "ground_truth",
  "scoring_rubric",
  "operator_only",
  "expected_facts",
]);

export class AnswerKeyContaminationError extends Error {
  public readonly offendingKey: string;

  constructor(offendingKey: string) {
    super(
      `Refusing Customer Report export: forbidden answer-key field '${offendingKey}' detected in payload`,
    );
    this.name = "AnswerKeyContaminationError";
    this.offendingKey = offendingKey;
  }
}

export function assertNoAnswerKeyFields(value: unknown, seen = new Set<unknown>()): void {
  if (typeof value !== "object" || value === null) {
    return;
  }
  if (seen.has(value)) {
    return;
  }
  seen.add(value);

  if (Array.isArray(value)) {
    for (const item of value) {
      assertNoAnswerKeyFields(item, seen);
    }
    return;
  }

  for (const [key, child] of Object.entries(value)) {
    const normalized = key.toLowerCase();
    if (FORBIDDEN_ANSWER_KEY_FIELDS.has(normalized)) {
      throw new AnswerKeyContaminationError(key);
    }
    assertNoAnswerKeyFields(child, seen);
  }
}

export function renderDefangedPlainText(raw: string): string {
  const tokens = tokenizeForensicText(raw);
  return tokens
    .map((tok) => {
      if (tok.kind === "text") return tok.text;
      if (tok.kind === "citation") return `[${tok.id}]`;
      return tok.defanged;
    })
    .join("");
}

const MARKDOWN_SPECIAL_RE = /[\\`*_[\]()<>#|!~&]/g;
// `//host` (protocol-relative) and GFM `www.` autolink hosts that the TLD-bound tokenizer may miss.
const PROTOCOL_RELATIVE_HOST_RE = /(^|[^A-Za-z0-9:/])\/\/([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)/g;
const WWW_HOST_RE = /\bwww\./gi;

/** Backslash-escapes Markdown/HTML syntax in an untrusted text segment after defanging stray hosts. */
function escapeMarkdownText(text: string): string {
  return text
    .replace(
      PROTOCOL_RELATIVE_HOST_RE,
      (_m, lead: string, host: string) => `${lead}//${defangIndicator(host)}`,
    )
    .replace(WWW_HOST_RE, (m) => `${m.slice(0, 3)}[.]`)
    .replace(MARKDOWN_SPECIAL_RE, (ch) => `\\${ch}`);
}

/** Inline code span with backticks stripped so untrusted values cannot close the span. */
function mdCode(raw: string): string {
  return `\`${sanitizeSingleLine(raw).replace(/`+/g, "")}\``;
}

/** Defanged, Markdown-escaped rendering; citations and indicators become inert literal text / code spans. */
function renderDefangedMarkdown(cleaned: string): string {
  return tokenizeForensicText(cleaned)
    .map((tok) => {
      if (tok.kind === "text") return escapeMarkdownText(tok.text);
      if (tok.kind === "citation") return `\\[${escapeMarkdownText(tok.id)}\\]`;
      return mdCode(tok.defanged);
    })
    .join("");
}

/** Single-line Markdown field: newlines collapse to spaces so text cannot forge headings or sections. */
export function renderDefangedMarkdownInline(raw: string): string {
  return renderDefangedMarkdown(sanitizeSingleLine(raw));
}

/**
 * Multi-line Markdown paragraph: every line is escaped and stripped of leading indentation, and
 * line-start list / setext / ordered-list markers are escaped, so no line can open a new block.
 */
export function renderDefangedMarkdownBlock(raw: string): string {
  return stripControlAndBidiChars(raw)
    .split("\n")
    .map((line) => line.replace(/\t/g, " ").trim())
    .filter((line) => line.length > 0)
    .map((line) =>
      renderDefangedMarkdown(line)
        .replace(/^([-+=])/, "\\$1")
        .replace(/^(\d+)([.)])/, "$1\\$2"),
    )
    .join("\n");
}

const SHA256_HEX_RE = /^[a-f0-9]{64}$/;

/** Fenced code block whose fence is longer than any backtick run inside `body`. */
function mdFence(info: string, body: string): string[] {
  const longestRun = Math.max(0, ...[...body.matchAll(/`+/g)].map((m) => m[0].length));
  const fence = "`".repeat(Math.max(3, longestRun + 1));
  return [`${fence}${info}`, body, fence];
}

function escapeHtml(raw: string): string {
  return stripControlAndBidiChars(raw)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function renderDefangedHtmlInline(raw: string): string {
  const tokens = tokenizeForensicText(raw);
  return tokens
    .map((tok) => {
      if (tok.kind === "text") {
        return escapeHtml(tok.text);
      }
      if (tok.kind === "citation") {
        return `<code class="cite cite-${tok.citationKind}">${escapeHtml(tok.id)}</code>`;
      }
      return `<code class="ioc-defanged">${escapeHtml(tok.defanged)}</code>`;
    })
    .join("");
}

export function buildCustomerReportMarkdown(
  workbench: WorkbenchSnapshot,
  exportedAtIso: string,
): string {
  const { caseMetadata, citationReceipt, claims, limitations, snapshot, gateHistory } = workbench;
  const observedAndFindings = claims.filter(
    (c) => c.claim.kind === "observed" || c.claim.kind === "finding",
  );
  const hypothesesAndInferences = claims.filter(
    (c) => c.claim.kind === "hypothesis" || c.claim.kind === "inference",
  );
  const allReviews = workbench.handoffs.flatMap((h) => h.reviews);

  const lines: string[] = [];
  lines.push(
    `# Hunt Command DFIR Investigation Report — ${renderDefangedMarkdownInline(caseMetadata.case_id)}`,
  );
  lines.push("");
  lines.push(`- **Case Title**: ${renderDefangedMarkdownInline(caseMetadata.title)}`);
  lines.push(`- **Hunt Run ID**: ${mdCode(workbench.huntId)}`);
  lines.push(
    `- **Data Origin**: ${mdCode(caseMetadata.data_origin)} (${mdCode(`synthetic_only=${String(caseMetadata.synthetic_only)}`)})`,
  );
  lines.push(
    `- **Case Window (UTC)**: ${mdCode(caseMetadata.time_window.start_iso)} to ${mdCode(caseMetadata.time_window.end_iso)}`,
  );
  lines.push(`- **Exported At (UTC)**: ${mdCode(exportedAtIso)}`);
  lines.push(
    `- **Automated Citation Verification Receipt**: \`${citationReceipt.verifiedCount}/${citationReceipt.totalCited}\` resolved (\`${citationReceipt.unresolvedCount}\` unresolved, \`${citationReceipt.outOfScopeCount}\` out-of-scope)`,
  );
  lines.push("");
  lines.push("> **Epistemic Separation Notice**: Sections 1–4 contain structured model analytical");
  lines.push("> claims, adversarial purple-team reviews, contradictions, and telemetry limitations.");
  lines.push("> Section 5 contains immutable raw source records retrieved directly from the case store.");
  lines.push("> All network indicators are defanged (`hxxps://`, `[.]`) to prevent accidental activation.");
  lines.push("");

  lines.push("## 1. Observed Facts & Confirmed Findings (Model Analytical Prose)");
  lines.push("");
  if (observedAndFindings.length === 0) {
    lines.push("_No observed or confirmed finding claims recorded._");
  } else {
    for (const row of observedAndFindings) {
      const roleTitle = renderDefangedMarkdownInline(PROFILE_DISPLAY_TITLES[row.profile] ?? row.profile);
      lines.push(
        `### ${mdCode(row.claim.claim_id)} \\[${renderDefangedMarkdownInline(row.claim.kind.toUpperCase())}\\] — ${roleTitle} (${mdCode(row.stepId)})`,
      );
      lines.push("");
      lines.push(renderDefangedMarkdownBlock(row.claim.statement));
      lines.push("");
      lines.push(
        `- **Source Store IDs**: ${row.claim.evidence_ids.map((id) => mdCode(id)).join(", ")}`,
      );
      lines.push(
        `- **Inline Citations**: ${
          row.inlineCitations.length > 0
            ? row.inlineCitations.map((c) => `${mdCode(c.id)} (${mdCode(c.status)})`).join(", ")
            : "_None_"
        }`,
      );
      if (row.claim.entity_ids.length > 0) {
        lines.push(`- **Entities**: ${row.claim.entity_ids.map((e) => mdCode(e)).join(", ")}`);
      }
      if (row.claim.contradicts.length > 0) {
        lines.push(
          `- **Contradicts**: ${row.claim.contradicts.map((cid) => mdCode(cid)).join(", ")}`,
        );
      }
      if (row.reviews.length > 0) {
        for (const rev of row.reviews) {
          lines.push(
            `- **Purple Review (${mdCode(rev.review_id)} -> ${mdCode(rev.disposition)})**: ${renderDefangedMarkdownInline(rev.rationale)}`,
          );
        }
      }
      lines.push("");
    }
  }

  lines.push("## 2. Analytical Inferences & Hypotheses (Model Analytical Prose)");
  lines.push("");
  if (hypothesesAndInferences.length === 0) {
    lines.push("_No hypotheses or inferences recorded._");
  } else {
    for (const row of hypothesesAndInferences) {
      const roleTitle = renderDefangedMarkdownInline(PROFILE_DISPLAY_TITLES[row.profile] ?? row.profile);
      lines.push(
        `### ${mdCode(row.claim.claim_id)} \\[${renderDefangedMarkdownInline(row.claim.kind.toUpperCase())}\\] — ${roleTitle} (${mdCode(row.stepId)})`,
      );
      lines.push("");
      lines.push(renderDefangedMarkdownBlock(row.claim.statement));
      lines.push("");
      if (row.claim.contradicts.length > 0) {
        lines.push(
          `- **Contradicts**: ${row.claim.contradicts.map((cid) => mdCode(cid)).join(", ")}`,
        );
      }
      if (row.reviews.length > 0) {
        for (const rev of row.reviews) {
          lines.push(
            `- **Purple Review (${mdCode(rev.review_id)} -> ${mdCode(rev.disposition)})**: ${renderDefangedMarkdownInline(rev.rationale)}`,
          );
        }
      }
      lines.push("");
    }
  }

  lines.push("## 3. Adversarial Purple Reviews & Contradiction Ledger");
  lines.push("");
  if (allReviews.length === 0) {
    lines.push("_No adversarial purple reviews recorded._");
  } else {
    for (const rev of allReviews) {
      lines.push(
        `- **${mdCode(rev.review_id)}** (${mdCode(rev.disposition)}) covering ${rev.claim_ids.map((id) => mdCode(id)).join(", ")}: ${renderDefangedMarkdownInline(rev.rationale)}`,
      );
    }
  }
  lines.push("");

  lines.push("## 4. Telemetry Gaps & Analytical Limitations");
  lines.push("");
  if (limitations.length === 0) {
    lines.push("_No analytical limitations reported._");
  } else {
    for (const lim of limitations) {
      lines.push(
        `- **\\[${renderDefangedMarkdownInline(lim.stepId)} / ${renderDefangedMarkdownInline(PROFILE_DISPLAY_TITLES[lim.profile] ?? lim.profile)}\\]**: ${renderDefangedMarkdownInline(lim.text)}`,
      );
    }
  }
  lines.push("");

  if (gateHistory.length > 0) {
    lines.push("## 4b. Authenticated Human Gate Decisions");
    lines.push("");
    for (const gd of gateHistory) {
      lines.push(
        `- **Gate ${mdCode(gd.gate)}** -> ${mdCode(gd.action.toUpperCase())} by ${mdCode(gd.decided_by)} (${mdCode(gd.rbac_role)}, via ${mdCode(gd.via)}) at ${mdCode(gd.decided_at)} · SHA-256 ${SHA256_HEX_RE.test(gd.payload_sha256) ? mdCode(gd.payload_sha256) : "_invalid digest withheld_"}${gd.note ? ` · Note: ${renderDefangedMarkdownInline(gd.note)}` : ""}`,
      );
    }
    lines.push("");
  }

  lines.push("## 5. Immutable Raw Source Telemetry Records (Non-Prose Store Extract)");
  lines.push("");
  lines.push(
    `Entities in case graph: **${snapshot.entities.length}** · Relations: **${snapshot.relations.length}** · Cited raw records: **${citationReceipt.entries.length}**`,
  );
  lines.push("");

  for (const entry of citationReceipt.entries) {
    const record = workbench.evidenceCatalog[entry.citationId];
    lines.push(`### Raw Record ${mdCode(entry.citationId)} (${mdCode(entry.status)})`);
    lines.push("");
    if (!record) {
      lines.push("_Record not present in bounded case store._");
      lines.push("");
      continue;
    }
    const defangedFields: Record<string, unknown> = {};
    for (const [fieldKey, fieldVal] of Object.entries(record.fields)) {
      if (typeof fieldVal === "string") {
        defangedFields[fieldKey] = renderDefangedPlainText(fieldVal);
      } else if (Array.isArray(fieldVal)) {
        defangedFields[fieldKey] = fieldVal.map((item) =>
          typeof item === "string" ? renderDefangedPlainText(item) : item,
        );
      } else {
        defangedFields[fieldKey] = fieldVal;
      }
    }
    lines.push(...mdFence("json", JSON.stringify(defangedFields, null, 2)));
    lines.push("");
  }

  return `${lines.join("\n").trimEnd()}\n`;
}

export function buildCustomerReportPrintHtml(
  workbench: WorkbenchSnapshot,
  exportedAtIso: string,
): string {
  const { caseMetadata, citationReceipt, claims, limitations } = workbench;
  const allReviews = workbench.handoffs.flatMap((h) => h.reviews);

  const claimCardsHtml = claims
    .map((row) => {
      const contradictsHtml =
        row.claim.contradicts.length > 0
          ? `<div class="meta"><strong>Contradicts:</strong> ${row.claim.contradicts.map((c) => `<code>${escapeHtml(c)}</code>`).join(", ")}</div>`
          : "";
      const reviewsHtml = row.reviews
        .map(
          (r) =>
            `<div class="review"><strong>Purple ${escapeHtml(r.review_id)} (${escapeHtml(r.disposition)}):</strong> ${renderDefangedHtmlInline(r.rationale)}</div>`,
        )
        .join("");
      return `<section class="card">
        <div class="card-head">
          <span class="badge kind-${escapeHtml(row.claim.kind)}">${escapeHtml(row.claim.kind.toUpperCase())}</span>
          <code>${escapeHtml(row.claim.claim_id)}</code>
          <span class="role">${escapeHtml(PROFILE_DISPLAY_TITLES[row.profile])} (${escapeHtml(row.stepId)})</span>
        </div>
        <p class="statement">${renderDefangedHtmlInline(row.claim.statement)}</p>
        ${contradictsHtml}
        ${reviewsHtml}
      </section>`;
    })
    .join("\n");

  const limitationsHtml =
    limitations.length > 0
      ? `<ul>${limitations
          .map(
            (l) =>
              `<li><strong>[${escapeHtml(l.stepId)}]</strong> ${renderDefangedHtmlInline(l.text)}</li>`,
          )
          .join("")}</ul>`
      : "<p>No limitations recorded.</p>";

  const reviewsLedgerHtml =
    allReviews.length > 0
      ? `<ul>${allReviews
          .map(
            (r) =>
              `<li><code>${escapeHtml(r.review_id)}</code> (<strong>${escapeHtml(r.disposition)}</strong>) → ${r.claim_ids.map((id) => `<code>${escapeHtml(id)}</code>`).join(", ")}: ${renderDefangedHtmlInline(r.rationale)}</li>`,
          )
          .join("")}</ul>`
      : "<p>No purple reviews recorded.</p>";

  const rawRecordsHtml = citationReceipt.entries
    .map((entry) => {
      const rec = workbench.evidenceCatalog[entry.citationId];
      const safeJson = rec
        ? escapeHtml(
            JSON.stringify(
              Object.fromEntries(
                Object.entries(rec.fields).map(([k, v]) => [
                  k,
                  typeof v === "string" ? renderDefangedPlainText(v) : v,
                ]),
              ),
              null,
              2,
            ),
          )
        : "Record unresolved in case store";
      return `<div class="raw-record">
        <div class="raw-head"><code>${escapeHtml(entry.citationId)}</code> · status: <strong>${escapeHtml(entry.status)}</strong></div>
        <pre>${safeJson}</pre>
      </div>`;
    })
    .join("\n");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'" />
  <title>Hunt Command DFIR Report — ${escapeHtml(caseMetadata.case_id)}</title>
  <style>
    body { font-family: "Segoe UI", system-ui, sans-serif; color: #0f172a; margin: 28px; font-size: 12px; line-height: 1.5; font-variant-numeric: tabular-nums; }
    h1 { font-size: 20px; margin: 0 0 8px; border-bottom: 2px solid #0f172a; padding-bottom: 6px; }
    h2 { font-size: 14px; margin-top: 20px; border-bottom: 1px solid #cbd5e1; padding-bottom: 4px; text-transform: uppercase; letter-spacing: 0.04em; }
    code, pre { font-family: Consolas, "Cascadia Mono", monospace; font-size: 11px; }
    .summary-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 6px 18px; background: #f8fafc; border: 1px solid #cbd5e1; padding: 10px 12px; border-radius: 4px; }
    .notice { margin-top: 10px; padding: 8px 10px; background: #fffbeb; border-left: 4px solid #d97706; font-size: 11px; }
    .card { border: 1px solid #cbd5e1; border-radius: 4px; padding: 10px 12px; margin-bottom: 10px; break-inside: avoid; }
    .card-head { display: flex; gap: 8px; align-items: center; margin-bottom: 6px; }
    .badge { padding: 1px 6px; border-radius: 3px; font-weight: 700; font-size: 10px; }
    .kind-observed, .kind-finding { background: #dcfce7; color: #166534; }
    .kind-inference, .kind-hypothesis { background: #e0f2fe; color: #075985; }
    .ioc-defanged { background: #fef2f2; color: #991b1b; padding: 1px 4px; border-radius: 3px; }
    .cite { background: #eef2ff; color: #3730a3; padding: 1px 4px; border-radius: 3px; }
    .review, .meta { margin-top: 6px; font-size: 11px; color: #334155; }
    .raw-record { border: 1px solid #94a3b8; border-radius: 4px; padding: 8px 10px; margin-bottom: 10px; background: #f8fafc; break-inside: avoid; }
    pre { margin: 6px 0 0; white-space: pre-wrap; word-break: break-all; }
  </style>
</head>
<body>
  <h1>Hunt Command DFIR Report — ${escapeHtml(caseMetadata.case_id)}</h1>
  <div class="summary-grid">
    <div><strong>Title:</strong> ${renderDefangedHtmlInline(caseMetadata.title)}</div>
    <div><strong>Hunt ID:</strong> <code>${escapeHtml(workbench.huntId)}</code></div>
    <div><strong>Data Origin:</strong> <code>${escapeHtml(caseMetadata.data_origin)}</code> (synthetic_only=${String(caseMetadata.synthetic_only)})</div>
    <div><strong>Citations Verified:</strong> <code>${citationReceipt.verifiedCount}/${citationReceipt.totalCited}</code></div>
    <div><strong>Case Window:</strong> <code>${escapeHtml(caseMetadata.time_window.start_iso)}</code> → <code>${escapeHtml(caseMetadata.time_window.end_iso)}</code></div>
    <div><strong>Exported At:</strong> <code>${escapeHtml(exportedAtIso)}</code></div>
  </div>
  <div class="notice">
    <strong>Epistemic Separation:</strong> Model analytical claims and inferences below are strictly separated from the immutable Raw Source Telemetry Appendix. Indicators are defanged.
  </div>
  <h2>Model Analytical Claims (Observed, Findings, Hypotheses &amp; Inferences)</h2>
  ${claimCardsHtml}
  <h2>Adversarial Purple Reviews &amp; Contradictions</h2>
  ${reviewsLedgerHtml}
  <h2>Telemetry Gaps &amp; Analytical Limitations</h2>
  ${limitationsHtml}
  <h2>Immutable Raw Source Telemetry Appendix</h2>
  ${rawRecordsHtml}
</body>
</html>`;
}

/**
 * Generates a valid, self-contained printable PDF-1.4 document from plain lines when running
 * in headless CLI/unit-test environments without an active Electron Chromium instance.
 */
export function buildDeterministicFallbackPdf(title: string, markdownText: string): Uint8Array {
  const cleanLines = stripControlAndBidiChars(markdownText)
    .split("\n")
    .slice(0, 58)
    .map((line) =>
      line
        .replace(/[^\x20-\x7E]/g, "?")
        .slice(0, 96)
        .replace(/\\/g, "\\\\")
        .replace(/\(/g, "\\(")
        .replace(/\)/g, "\\)"),
    );

  const streamCommands = [
    "BT",
    "/F1 11 Tf",
    "42 752 Td",
    `(${title.replace(/[^\x20-\x7E]/g, "?").replace(/[()\\]/g, "")}) Tj`,
    "/F1 8.5 Tf",
    "0 -16 Td",
  ];
  for (const line of cleanLines) {
    streamCommands.push(`(${line}) Tj`);
    streamCommands.push("0 -11.5 Td");
  }
  streamCommands.push("ET");
  const contentStream = streamCommands.join("\n");

  const objects = [
    "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
    "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
    "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n",
    "4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>\nendobj\n",
    `5 0 obj\n<< /Length ${Buffer.byteLength(contentStream, "ascii")} >>\nstream\n${contentStream}\nendstream\nendobj\n`,
  ];

  let pdf = "%PDF-1.4\n";
  const offsets: number[] = [0];
  for (const obj of objects) {
    offsets.push(Buffer.byteLength(pdf, "ascii"));
    pdf += obj;
  }
  const xrefOffset = Buffer.byteLength(pdf, "ascii");
  pdf += `xref\n0 ${objects.length + 1}\n`;
  pdf += "0000000000 65535 f \n";
  for (let i = 1; i < offsets.length; i++) {
    pdf += `${String(offsets[i] ?? 0).padStart(10, "0")} 00000 n \n`;
  }
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF\n`;
  return new Uint8Array(Buffer.from(pdf, "ascii"));
}

export interface ExportCustomerReportOptions {
  workbench: WorkbenchSnapshot;
  exportsRootDir: string;
  exportedAtIso?: string;
  pdfRenderer?: (printHtml: string, fallbackMarkdown: string) => Promise<Uint8Array>;
}

export async function exportCustomerReport(
  options: ExportCustomerReportOptions,
): Promise<ReportExportResult> {
  const enclosingGit = findEnclosingGitMarker(options.exportsRootDir);
  if (enclosingGit !== null) {
    throw new RuntimeFenceError(options.exportsRootDir, enclosingGit);
  }

  assertNoAnswerKeyFields(options.workbench);

  const exportedAtIso = options.exportedAtIso ?? new Date().toISOString();
  const safeStamp = exportedAtIso.replace(/[:.]/g, "-");
  const safeHuntId = options.workbench.huntId.replace(/[^A-Za-z0-9_-]/g, "_");
  const exportDir = path.join(options.exportsRootDir, `${safeHuntId}-${safeStamp}`);
  fs.mkdirSync(exportDir, { recursive: true });

  const markdown = buildCustomerReportMarkdown(options.workbench, exportedAtIso);
  const reportSha256 = createHash("sha256").update(markdown, "utf8").digest("hex");

  const markdownPath = path.join(exportDir, "report.md");
  fs.writeFileSync(markdownPath, markdown, "utf8");

  const printHtml = buildCustomerReportPrintHtml(options.workbench, exportedAtIso);
  const pdfBytes = options.pdfRenderer
    ? await options.pdfRenderer(printHtml, markdown)
    : buildDeterministicFallbackPdf(
        `Hunt Command Report - ${options.workbench.caseMetadata.case_id}`,
        markdown,
      );

  const pdfPath = path.join(exportDir, "report.pdf");
  fs.writeFileSync(pdfPath, pdfBytes);

  const provenanceBundle = {
    schema_version: 1,
    exported_at_iso: exportedAtIso,
    report_markdown_sha256: reportSha256,
    hunt_id: options.workbench.huntId,
    case_metadata: options.workbench.caseMetadata,
    citation_verification_receipt: options.workbench.citationReceipt,
    gate_decisions: options.workbench.gateHistory,
    model_prose_handoffs: options.workbench.handoffs.map((h) => ({
      step_id: h.step_id,
      profile: h.profile,
      disposition: h.disposition,
      claims: h.claims.map((c) => ({
        ...c,
        statement_defanged: renderDefangedPlainText(c.statement),
      })),
      reviews: h.reviews.map((r) => ({
        ...r,
        rationale_defanged: renderDefangedPlainText(r.rationale),
      })),
      limitations: h.limitations.map((l) => renderDefangedPlainText(l)),
    })),
    ontology_snapshot: options.workbench.snapshot,
    immutable_raw_source_records: Object.fromEntries(
      options.workbench.citationReceipt.entries.map((entry) => [
        entry.citationId,
        options.workbench.evidenceCatalog[entry.citationId] ?? null,
      ]),
    ),
  };

  assertNoAnswerKeyFields(provenanceBundle);
  const provenanceJsonPath = path.join(exportDir, "provenance-bundle.json");
  fs.writeFileSync(provenanceJsonPath, `${JSON.stringify(provenanceBundle, null, 2)}\n`, "utf8");

  return {
    exportDir,
    markdownPath,
    pdfPath,
    provenanceJsonPath,
    reportSha256,
  };
}
