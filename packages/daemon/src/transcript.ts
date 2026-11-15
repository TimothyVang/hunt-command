import { scrubSecretValue, type ProfileId } from "@hunt-command/shared";
import { sanitizeUntrustedText, wrapSanitizedInFence } from "./scrubber-and-fence.ts";
import type { DispatchReceiptRow, PersistedHuntRun } from "./state-store.ts";
import { buildEightWaveGraph } from "./wave-engine.ts";

export const TRANSCRIPT_PAGE_MIN_BYTES = 1;
export const TRANSCRIPT_PAGE_MAX_BYTES = 65_536;
export const TRANSCRIPT_PAGE_DEFAULT_BYTES = 16_384;

export interface TranscriptPage {
  readonly run_id: string;
  readonly step_id: string;
  readonly profile: ProfileId;
  /** Offsets and sizes are UTF-8 bytes of the sanitized transcript, excluding the fence tags. */
  readonly byte_offset: number;
  readonly byte_length: number;
  readonly total_bytes: number;
  readonly next_byte_offset: number;
  readonly has_more: boolean;
  /** The page wrapped in `<untrusted_tool_result_${fence_nonce}>` ... `</...>`. */
  readonly content: string;
  readonly fence_nonce: string;
}


/** The profile that owns `stepId` in this run's own step graph, or null if the run has no such step. */
export function profileForRunStep(run: PersistedHuntRun, stepId: string): ProfileId | null {
  if (!Object.hasOwn(run.step_states, stepId)) {
    return null;
  }
  const graph = buildEightWaveGraph({
    followUps: run.config.followUps,
    optionalOverrides: run.config.optionalOverrides,
  });
  for (const wave of graph) {
    for (const spec of wave) {
      if (spec.stepId === stepId) return spec.profile;
    }
  }
  return run.results[stepId]?.profile ?? null;
}

function field(value: unknown): string {
  if (value === undefined || value === null) return "";
  return typeof value === "string" ? value : JSON.stringify(value);
}

/**
 * Renders one step's transcript from durable state: header, every dispatch attempt (status,
 * usage, refusal, diagnostic, model output), handoff rejections and the accepted handoff.
 * Values are credential-scrubbed structurally here; the whole text is sanitized by the caller.
 * Pure: the same state always renders the same text, so byte offsets are stable across pages.
 */
export function renderStepTranscript(
  run: PersistedHuntRun,
  receipts: readonly DispatchReceiptRow[],
  stepId: string,
  profile: ProfileId,
): string {
  const s = (v: unknown) => field(scrubSecretValue(v));
  const result = run.results[stepId];
  const lines: string[] = [
    "=== Hunt Command step transcript ===",
    `hunt_id: ${run.run_id}`,
    `case_id: ${run.case_id}`,
    `step_id: ${stepId}`,
    `profile: ${profile}`,
    `state: ${run.step_states[stepId]}`,
    `result: ${result ? `${result.status}${result.reason_code ? ` (${result.reason_code})` : ""}` : "none"}`,
    "",
  ];

  const stepReceipts = receipts.filter((r) => r.run_id === run.run_id && r.step_id === stepId);
  stepReceipts.forEach((r, index) => {
    lines.push(
      `--- attempt ${index + 1} execution=${r.execution_id} status=${r.status}` +
        `${r.reason_code ? ` reason=${r.reason_code}` : ""} reserved=${r.reserved_at}` +
        `${r.finished_at ? ` finished=${r.finished_at}` : ""} ---`,
    );
    if (r.usage) {
      lines.push(
        `usage: model=${s(r.usage.model)} input=${r.usage.input_tokens} output=${r.usage.output_tokens}` +
          ` cache_read=${r.usage.cache_read_tokens} cache_write=${r.usage.cache_write_tokens} turns=${r.usage.turns}`,
      );
    }
    if (r.refusal) lines.push(`refusal: ${s(r.refusal)}`);
    if (r.diagnostic) lines.push(`diagnostic: ${s(r.diagnostic)}`);
    if (r.output_text) lines.push("output:", s(r.output_text));
    lines.push("");
  });

  for (const rej of run.handoff_rejections.filter((x) => x.step_id === stepId)) {
    lines.push(
      `--- handoff rejected attempt=${rej.attempt} reason=${rej.reason_code} at=${rej.rejected_at} ---`,
      s(rej.diagnostic),
      "",
    );
  }

  if (result?.handoff) {
    lines.push("--- accepted handoff ---", s(result.handoff), "");
  }
  return lines.join("\n");
}

function utf8Boundary(buf: Buffer, offset: number): number {
  let at = Math.min(offset, buf.byteLength);
  while (at < buf.byteLength && (buf[at]! & 0xc0) === 0x80) at++;
  return at;
}

/** Slices the sanitized transcript on UTF-8 boundaries and fences the page. */
export function pageTranscript(params: {
  readonly runId: string;
  readonly stepId: string;
  readonly profile: ProfileId;
  readonly transcript: string;
  readonly byteOffset: number;
  readonly byteLimit: number;
}): TranscriptPage {
  const buf = Buffer.from(sanitizeUntrustedText(params.transcript), "utf8");
  const start = utf8Boundary(buf, params.byteOffset);
  let end = Math.min(start + params.byteLimit, buf.byteLength);
  if (end < buf.byteLength) {
    // Step back to the lead byte so a code point is never split across pages.
    while (end > start && (buf[end]! & 0xc0) === 0x80) end--;
  }
  const page = buf.subarray(start, end).toString("utf8");
  const fenced = wrapSanitizedInFence(page);
  return {
    run_id: params.runId,
    step_id: params.stepId,
    profile: params.profile,
    byte_offset: start,
    byte_length: end - start,
    total_bytes: buf.byteLength,
    next_byte_offset: end,
    has_more: end < buf.byteLength,
    content: fenced.wrappedText,
    fence_nonce: fenced.nonce128,
  };
}
