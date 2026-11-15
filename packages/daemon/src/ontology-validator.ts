import {
  CLAIM_KINDS,
  DISPOSITIONS,
  HandoffSchema,
  MAX_HANDOFF_BYTES,
  MAX_PREDECESSORS,
  MAX_PROMPT_BYTES,
  MAX_SNAPSHOT_BYTES,
  SnapshotSchema,
  extractInlineCitations,
  type Claim,
  type Handoff,
  type ProfileId,
  type Snapshot,
} from "@hunt-command/shared";
import type { CitationVerificationReceipt, HuntDataPlanePort } from "./ports.ts";

export const FINAL_HANDOFF_BYTES = 32_768;
export const RETRY_NOTICE_RESERVE_BYTES = 2_048;

export const WHOLE_CHECK_RETRY_SUFFIX =
  "\n\nIMPORTANT: Your previous handoff failed strict ontology validation. " +
  "Check ALL claims, evidence_ids (use supplied source_ids only, never evt-*/frame-*/ioc-*), " +
  "entity_ids, contradicts, reviews, and UTF-8 byte limits, then emit ONLY one valid JSON handoff object.";

export class OntologyValidationError extends Error {
  public readonly isOversize: boolean;
  public readonly actualBytes?: number;
  public readonly limitBytes?: number;

  constructor(
    message: string,
    options?: { isOversize?: boolean; actualBytes?: number; limitBytes?: number },
  ) {
    super(message);
    this.name = "OntologyValidationError";
    this.isOversize = options?.isOversize ?? false;
    this.actualBytes = options?.actualBytes;
    this.limitBytes = options?.limitBytes;
  }
}

function isJsonWhitespace(code: number): boolean {
  return code === 0x20 || code === 0x09 || code === 0x0a || code === 0x0d;
}

function readJsonStringToken(text: string, startQuoteIndex: number): { value: string; nextIndex: number } {
  let i = startQuoteIndex + 1;
  while (i < text.length) {
    const ch = text.charCodeAt(i);
    if (ch < 0x20) {
      throw new OntologyValidationError("Unescaped control character in JSON string");
    }
    if (ch === 0x5c /* \\ */) {
      i += 1;
      if (i >= text.length) {
        throw new OntologyValidationError("Unterminated escape sequence in JSON string");
      }
      const esc = text.charCodeAt(i);
      if (esc === 0x75 /* u */) {
        if (i + 4 >= text.length) {
          throw new OntologyValidationError("Incomplete \\uXXXX escape in JSON string");
        }
        const hex = text.slice(i + 1, i + 5);
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) {
          throw new OntologyValidationError(`Invalid Unicode escape \\u${hex} in JSON string`);
        }
        i += 5;
        continue;
      }
      i += 1;
      continue;
    }
    if (ch === 0x22 /* " */) {
      const rawLiteral = text.slice(startQuoteIndex, i + 1);
      let decoded: string;
      try {
        decoded = JSON.parse(rawLiteral) as string;
      } catch (err) {
        throw new OntologyValidationError(
          `Invalid JSON string literal: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
      return { value: decoded, nextIndex: i + 1 };
    }
    i += 1;
  }
  throw new OntologyValidationError("Unterminated JSON string literal");
}

/**
 * Strict deterministic JSON parser that rejects:
 * 1. Duplicate keys at any object nesting depth (even across `\uXXXX` escape aliases!)
 * 2. Bare `NaN`, `Infinity`, or `-Infinity` tokens
 * 3. Malformed JSON syntax
 */
export function parseStrictUniqueJson(rawText: string): unknown {
  type Frame =
    | { kind: "object"; keys: Set<string>; expectingKey: boolean; afterColon: boolean }
    | { kind: "array" };

  const stack: Frame[] = [];
  let i = 0;
  const len = rawText.length;

  while (i < len) {
    const code = rawText.charCodeAt(i);
    if (isJsonWhitespace(code)) {
      i += 1;
      continue;
    }

    // Check explicit NaN / Infinity / -Infinity tokens before JSON.parse
    if (
      rawText.startsWith("NaN", i) ||
      rawText.startsWith("Infinity", i) ||
      rawText.startsWith("-Infinity", i)
    ) {
      throw new OntologyValidationError(
        "Non-finite number literal (NaN/Infinity) is prohibited in handoff/snapshot JSON",
      );
    }

    const top = stack[stack.length - 1];

    if (code === 0x7b /* { */) {
      if (top?.kind === "object" && top.expectingKey) {
        throw new OntologyValidationError("Unexpected '{' where object key string was expected");
      }
      if (top?.kind === "object") {
        top.afterColon = false;
      }
      stack.push({ kind: "object", keys: new Set<string>(), expectingKey: true, afterColon: false });
      i += 1;
      continue;
    }

    if (code === 0x7d /* } */) {
      if (!top || top.kind !== "object") {
        throw new OntologyValidationError("Unexpected '}' outside JSON object");
      }
      stack.pop();
      i += 1;
      continue;
    }

    if (code === 0x5b /* [ */) {
      if (top?.kind === "object" && top.expectingKey) {
        throw new OntologyValidationError("Unexpected '[' where object key string was expected");
      }
      if (top?.kind === "object") {
        top.afterColon = false;
      }
      stack.push({ kind: "array" });
      i += 1;
      continue;
    }

    if (code === 0x5d /* ] */) {
      if (!top || top.kind !== "array") {
        throw new OntologyValidationError("Unexpected ']' outside JSON array");
      }
      stack.pop();
      i += 1;
      continue;
    }

    if (code === 0x3a /* : */) {
      if (!top || top.kind !== "object" || top.expectingKey || top.afterColon) {
        throw new OntologyValidationError("Unexpected ':' in JSON stream");
      }
      top.afterColon = true;
      i += 1;
      continue;
    }

    if (code === 0x2c /* , */) {
      if (!top) {
        throw new OntologyValidationError("Unexpected top-level ',' in JSON stream");
      }
      if (top.kind === "object") {
        if (top.expectingKey || top.afterColon) {
          throw new OntologyValidationError("Unexpected ',' in JSON object");
        }
        top.expectingKey = true;
      }
      i += 1;
      continue;
    }

    if (code === 0x22 /* " */) {
      const { value, nextIndex } = readJsonStringToken(rawText, i);
      if (top?.kind === "object" && top.expectingKey) {
        if (top.keys.has(value)) {
          throw new OntologyValidationError(`Duplicate JSON object key '${value}' is prohibited`);
        }
        top.keys.add(value);
        top.expectingKey = false;
        top.afterColon = false;
      } else if (top?.kind === "object") {
        top.afterColon = false;
      }
      i = nextIndex;
      continue;
    }

    // Primitive literal (number, true, false, null)
    if (top?.kind === "object" && top.expectingKey) {
      throw new OntologyValidationError("Expected double-quoted property name in JSON object");
    }
    if (top?.kind === "object") {
      top.afterColon = false;
    }
    while (
      i < len &&
      !isJsonWhitespace(rawText.charCodeAt(i)) &&
      rawText[i] !== "," &&
      rawText[i] !== "}" &&
      rawText[i] !== "]" &&
      rawText[i] !== ":"
    ) {
      i += 1;
    }
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawText);
  } catch (err) {
    throw new OntologyValidationError(
      `Malformed JSON: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  assertFiniteRecursive(parsed);
  return parsed;
}

function assertFiniteRecursive(val: unknown): void {
  if (typeof val === "number") {
    if (!Number.isFinite(val)) {
      throw new OntologyValidationError("Non-finite number in parsed JSON");
    }
    return;
  }
  if (Array.isArray(val)) {
    for (const item of val) {
      assertFiniteRecursive(item);
    }
    return;
  }
  if (val !== null && typeof val === "object") {
    for (const v of Object.values(val)) {
      assertFiniteRecursive(v);
    }
  }
}

const FENCED_JSON_RE = /```(?:json)?\s*\r?\n([\s\S]*?)\r?\n```/gi;

/**
 * Port of `workflows.py:_extract_single_handoff`:
 * Accepts either a standalone JSON object OR prose followed by a single terminal fenced ```json block
 * with zero trailing prose after the closing fence.
 */
export function extractSingleHandoffJson(rawOutput: string): string {
  const trimmed = rawOutput.trim();
  if (!trimmed) {
    throw new OntologyValidationError("Empty model output; expected typed JSON handoff object");
  }

  if (trimmed.startsWith("{")) {
    const parsed = parseStrictUniqueJson(trimmed);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new OntologyValidationError("Top-level handoff JSON must be an object");
    }
    return trimmed;
  }

  const matches = [...trimmed.matchAll(FENCED_JSON_RE)];
  if (matches.length === 0) {
    throw new OntologyValidationError(
      "Model output must be a raw JSON handoff object or end with a ```json fenced handoff block",
    );
  }

  const lastMatch = matches[matches.length - 1]!;
  const endOfLastFence = (lastMatch.index ?? 0) + lastMatch[0].length;
  const trailing = trimmed.slice(endOfLastFence).trim();
  if (trailing.length > 0) {
    throw new OntologyValidationError(
      "Trailing text after closing ``` fence is prohibited; JSON handoff block must be final",
    );
  }

  const candidate = (lastMatch[1] ?? "").trim();
  const parsed = parseStrictUniqueJson(candidate);
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new OntologyValidationError("Fenced handoff JSON must be a single JSON object");
  }
  return candidate;
}

export function validateSnapshot(raw: string | Record<string, unknown>, caseId: string): Snapshot {
  let obj: unknown;
  if (typeof raw === "string") {
    const byteLen = Buffer.byteLength(raw, "utf8");
    if (byteLen > MAX_SNAPSHOT_BYTES) {
      throw new OntologyValidationError(
        `Snapshot exceeds ${MAX_SNAPSHOT_BYTES} UTF-8 bytes (${byteLen} bytes)`,
        { isOversize: true, actualBytes: byteLen, limitBytes: MAX_SNAPSHOT_BYTES },
      );
    }
    obj = parseStrictUniqueJson(raw);
  } else {
    const serialized = JSON.stringify(raw);
    const byteLen = Buffer.byteLength(serialized, "utf8");
    if (byteLen > MAX_SNAPSHOT_BYTES) {
      throw new OntologyValidationError(
        `Snapshot exceeds ${MAX_SNAPSHOT_BYTES} UTF-8 bytes (${byteLen} bytes)`,
        { isOversize: true, actualBytes: byteLen, limitBytes: MAX_SNAPSHOT_BYTES },
      );
    }
    assertFiniteRecursive(raw);
    obj = raw;
  }

  const result = SnapshotSchema.safeParse(obj);
  if (!result.success) {
    const first = result.error.issues[0];
    throw new OntologyValidationError(
      `Invalid snapshot (${first?.path.join(".") || "root"}): ${first?.message ?? "schema error"}`,
    );
  }

  if (result.data.case_id !== caseId) {
    throw new OntologyValidationError(
      `Snapshot case_id '${result.data.case_id}' does not match expected '${caseId}'`,
    );
  }

  return result.data;
}

export function selectSnapshot(
  snapshots: Record<string, unknown> | undefined,
  caseId: string,
): { snapshot: Snapshot | null; serialized: string } {
  if (!snapshots || !(caseId in snapshots)) {
    return { snapshot: null, serialized: "" };
  }
  const entry = snapshots[caseId];
  if (entry === undefined || entry === null) {
    return { snapshot: null, serialized: "" };
  }
  if (typeof entry !== "string" && (typeof entry !== "object" || Array.isArray(entry))) {
    throw new OntologyValidationError(`Snapshot for case '${caseId}' must be JSON text or object`);
  }
  const validated = validateSnapshot(entry as string | Record<string, unknown>, caseId);
  const canonical = JSON.stringify(validated);
  const byteLen = Buffer.byteLength(canonical, "utf8");
  if (byteLen > MAX_SNAPSHOT_BYTES) {
    throw new OntologyValidationError(
      `Canonical snapshot exceeds ${MAX_SNAPSHOT_BYTES} UTF-8 bytes (${byteLen} bytes)`,
      { isOversize: true, actualBytes: byteLen, limitBytes: MAX_SNAPSHOT_BYTES },
    );
  }
  return { snapshot: validated, serialized: canonical };
}

export interface ValidateHandoffOptions {
  readonly caseId: string;
  readonly stepId: string;
  readonly profile: ProfileId;
  readonly snapshot?: Snapshot | null;
  readonly predecessors?: readonly Handoff[];
  readonly ancestorClaims?: readonly Claim[];
  readonly suppliedSourceIds?: readonly string[];
  readonly handoffLimitBytes?: number;
}

/**
 * Exact 1-for-1 port of `ontology.py:validate_handoff` + strict JSON duplicate-key / NaN rejection.
 */
export function validateHandoff(
  raw: string | Record<string, unknown>,
  options: ValidateHandoffOptions,
): { handoff: Handoff; canonicalJson: string; rawBytes: number } {
  const limitBytes = options.handoffLimitBytes ?? MAX_HANDOFF_BYTES;
  const predecessors = options.predecessors ?? [];
  const ancestorClaims = options.ancestorClaims ?? [];

  if (predecessors.length > MAX_PREDECESSORS) {
    throw new OntologyValidationError(
      `Step '${options.stepId}' exceeds MAX_PREDECESSORS (${predecessors.length} > ${MAX_PREDECESSORS})`,
    );
  }

  let parsedObj: unknown;
  let rawBytes: number;

  if (typeof raw === "string") {
    const extracted = extractSingleHandoffJson(raw);
    rawBytes = Buffer.byteLength(extracted, "utf8");
    if (rawBytes > limitBytes) {
      throw new OntologyValidationError(
        `Handoff exceeds ${limitBytes} UTF-8 bytes (got ${rawBytes} bytes)`,
        { isOversize: true, actualBytes: rawBytes, limitBytes },
      );
    }
    parsedObj = parseStrictUniqueJson(extracted);
  } else {
    const serialized = JSON.stringify(raw);
    rawBytes = Buffer.byteLength(serialized, "utf8");
    if (rawBytes > limitBytes) {
      throw new OntologyValidationError(
        `Handoff exceeds ${limitBytes} UTF-8 bytes (got ${rawBytes} bytes)`,
        { isOversize: true, actualBytes: rawBytes, limitBytes },
      );
    }
    assertFiniteRecursive(raw);
    parsedObj = raw;
  }

  const parsed = HandoffSchema.safeParse(parsedObj);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    const loc = issue?.path.join(".") || "handoff";
    throw new OntologyValidationError(
      `Invalid handoff at '${loc}': ${issue?.message ?? "schema mismatch"}`,
    );
  }

  const handoff = parsed.data;
  if (handoff.case_id !== options.caseId) {
    throw new OntologyValidationError(
      `Handoff case_id '${handoff.case_id}' does not match run case_id '${options.caseId}'`,
    );
  }
  if (handoff.step_id !== options.stepId) {
    throw new OntologyValidationError(
      `Handoff step_id '${handoff.step_id}' does not match current step_id '${options.stepId}'`,
    );
  }
  if (handoff.profile !== options.profile) {
    throw new OntologyValidationError(
      `Handoff profile '${handoff.profile}' does not match assigned profile '${options.profile}'`,
    );
  }

  // Enforce snapshot entity resolution when a case snapshot is present
  if (options.snapshot) {
    const knownEntities = new Set(options.snapshot.entities.map((e) => e.entity_id));
    for (const claim of handoff.claims) {
      for (const entityId of claim.entity_ids) {
        if (!knownEntities.has(entityId)) {
          throw new OntologyValidationError(
            `Claim '${claim.claim_id}' references unknown snapshot entity_id '${entityId}'`,
          );
        }
      }
    }
  }

  // Enforce supplied source_ids allowlist when case metadata specifies non-empty sources
  if (options.suppliedSourceIds && options.suppliedSourceIds.length > 0) {
    const allowedSources = new Set(options.suppliedSourceIds);
    for (const claim of handoff.claims) {
      for (const sourceId of claim.evidence_ids) {
        if (!allowedSources.has(sourceId)) {
          throw new OntologyValidationError(
            `Claim '${claim.claim_id}' evidence_id '${sourceId}' is not in case sources [${options.suppliedSourceIds.join(", ")}]`,
          );
        }
      }
    }
    for (const review of handoff.reviews) {
      for (const sourceId of review.evidence_ids) {
        if (!allowedSources.has(sourceId)) {
          throw new OntologyValidationError(
            `Review '${review.review_id}' evidence_id '${sourceId}' is not in case sources [${options.suppliedSourceIds.join(", ")}]`,
          );
        }
      }
    }
  }

  // Build claim scopes for contradicts[] and reviews[]
  const ownClaimIds = new Set(handoff.claims.map((c) => c.claim_id));
  const predecessorClaimIds = new Set<string>();
  const nonReviewerPredecessorClaimIds = new Set<string>();

  for (const pred of predecessors) {
    for (const c of pred.claims) {
      predecessorClaimIds.add(c.claim_id);
      if (pred.profile !== "framework-reviewer") {
        nonReviewerPredecessorClaimIds.add(c.claim_id);
      }
    }
  }

  const ancestorClaimIds = new Set(ancestorClaims.map((c) => c.claim_id));

  for (const claim of handoff.claims) {
    for (const targetId of claim.contradicts) {
      if (targetId === claim.claim_id) {
        throw new OntologyValidationError(`Claim '${claim.claim_id}' cannot contradict itself`);
      }
      if (
        !ownClaimIds.has(targetId) &&
        !predecessorClaimIds.has(targetId) &&
        !ancestorClaimIds.has(targetId)
      ) {
        throw new OntologyValidationError(
          `Claim '${claim.claim_id}' contradicts unknown claim_id '${targetId}' (must be in own claims, direct predecessors, or reviewed ancestor claims)`,
        );
      }
    }
  }

  if (handoff.profile !== "framework-reviewer" && handoff.reviews.length > 0) {
    throw new OntologyValidationError(
      `Profile '${handoff.profile}' is not permitted to emit reviews[]; only 'framework-reviewer' may supply reviews`,
    );
  }

  for (const review of handoff.reviews) {
    for (const targetClaimId of review.claim_ids) {
      if (!nonReviewerPredecessorClaimIds.has(targetClaimId)) {
        throw new OntologyValidationError(
          `Review '${review.review_id}' targets '${targetClaimId}', which is not a surviving non-reviewer predecessor claim`,
        );
      }
    }
  }

  const canonicalJson = JSON.stringify(handoff);
  const canonicalBytes = Buffer.byteLength(canonicalJson, "utf8");
  if (canonicalBytes > limitBytes) {
    throw new OntologyValidationError(
      `Canonical handoff exceeds ${limitBytes} UTF-8 bytes (${canonicalBytes} bytes)`,
      { isOversize: true, actualBytes: canonicalBytes, limitBytes },
    );
  }

  return { handoff, canonicalJson, rawBytes: canonicalBytes };
}

/**
 * Port of `workflows.py:_disclosed_target`:
 * Tool-driven forwarded steps get a 55% soft target (`Math.floor(cap * 11 / 20)`);
 * terminal `incident` (where `cap === FINAL_HANDOFF_BYTES` and `!tighter`) gets 80% (`Math.floor(cap * 4 / 5)`);
 * retry attempts pass `Math.floor(cap / 2)` directly.
 */
export function disclosedTargetBytes(
  capBytes: number,
  tighterForwardedStep: boolean,
  toolDriven: boolean,
): number {
  if (tighterForwardedStep && toolDriven) {
    return Math.floor((capBytes * 11) / 20);
  }
  if (toolDriven) {
    return Math.floor((capBytes * 4) / 5);
  }
  return capBytes;
}

export interface StepCapDescriptor {
  readonly stepId: string;
  readonly profile: ProfileId;
  readonly dependsOn: readonly string[];
  readonly focus?: readonly [sourceStepId: string, claimIndex: number] | null;
  readonly basePromptOverheadBytes: number;
}

/**
 * Port of `workflows.py:_typed_output_caps`:
 * Dynamically bounds each step's typed handoff cap so every downstream step can fit
 * all of its surviving predecessors + snapshot + retry notice within `MAX_PROMPT_BYTES` (`65_536 B`).
 */
export function computeTypedOutputCaps(
  steps: readonly StepCapDescriptor[],
  snapshotBytes = 0,
): Map<string, number> {
  const downstreamConsumers = new Map<string, StepCapDescriptor[]>();
  for (const step of steps) {
    for (const dep of step.dependsOn) {
      const arr = downstreamConsumers.get(dep) ?? [];
      arr.push(step);
      downstreamConsumers.set(dep, arr);
    }
  }

  const caps = new Map<string, number>();
  for (const step of steps) {
    const consumers = downstreamConsumers.get(step.stepId) ?? [];
    if (consumers.length === 0) {
      // Terminal step (e.g., Wave 8 `incident`)
      caps.set(step.stepId, FINAL_HANDOFF_BYTES);
      continue;
    }

    let stepCap = MAX_HANDOFF_BYTES;
    for (const consumer of consumers) {
      // If consumer only takes a single `focus` claim slice, MAX_HANDOFF_BYTES already fits
      if (consumer.focus && consumer.focus[0] === step.stepId) {
        continue;
      }
      const depCount = Math.max(1, consumer.dependsOn.length);
      const perDepFraming = depCount * 256;
      const available =
        MAX_PROMPT_BYTES -
        consumer.basePromptOverheadBytes -
        snapshotBytes -
        RETRY_NOTICE_RESERVE_BYTES -
        perDepFraming;
      const perDepBudget = Math.floor(available / depCount);
      if (perDepBudget < 1024) {
        throw new OntologyValidationError(
          `Prompt budget exhausted for consumer '${consumer.stepId}': per-predecessor cap ${perDepBudget}B < 1024B`,
        );
      }
      stepCap = Math.min(stepCap, perDepBudget);
    }
    caps.set(step.stepId, stepCap);
  }

  return caps;
}

export interface HandoffInstructionsParams {
  readonly caseId: string;
  readonly stepId: string;
  readonly profile: ProfileId;
  readonly suppliedSourceIds: readonly string[];
  readonly hasSnapshot: boolean;
  readonly targetBytes: number;
  readonly hardCapBytes: number;
}

export function buildHandoffInstructions(params: HandoffInstructionsParams): string {
  const claimsRule =
    params.profile === "framework-reviewer"
      ? `Emit up to 16 reviews[] (review_id starting with "${params.stepId}:") evaluating non-reviewer predecessor claims, and optional claims[].`
      : `Emit claims[] (1..16 items as warranted, each claim_id starting with "${params.stepId}:") and reviews: [] (MUST be empty for '${params.profile}').`;

  const sourceHint =
    params.suppliedSourceIds.length > 0
      ? `Valid source_id values for evidence_ids: [${params.suppliedSourceIds.join(", ")}].`
      : `Use supplied case source_id values in evidence_ids.`;

  const entityHint = params.hasSnapshot
    ? "entity_ids must reference entity_id values present in the case snapshot."
    : "entity_ids may be [] when no snapshot is attached.";

  return [
    "## Required Typed JSON Handoff Contract",
    `Respond with ONLY a single strict JSON object (no duplicate keys, no NaN/Infinity, no trailing prose):`,
    `- schema_version: 1`,
    `- case_id: "${params.caseId}"`,
    `- step_id: "${params.stepId}"`,
    `- profile: "${params.profile}"`,
    `- ${claimsRule}`,
    `- Claim kinds: ${CLAIM_KINDS.join(" | ")}; dispositions: ${DISPOSITIONS.join(" | ")}.`,
    `- ${sourceHint} NEVER put raw evt-*, frame-*, or ioc-* record IDs in evidence_ids; cite evt-*/frame-*/ioc-* inline inside claim.statement or limitations text!`,
    `- ${entityHint}`,
    `- limitations & requested_decisions: concise strings (<= 300 chars each, max 16).`,
    `- Target size <= ${params.targetBytes} UTF-8 bytes (hard ceiling ${params.hardCapBytes} UTF-8 bytes).`,
  ].join("\n");
}

export interface CitationCheckOutcome {
  readonly status: "verified" | "failed" | "unknown";
  readonly receipt: CitationVerificationReceipt;
  readonly errorMessage?: string;
}

/**
 * Extracts inline `evt-*`, `frame-*`, and `ioc-*` citations across ALL claims,
 * limitations, requested_decisions, and review rationales, then verifies every
 * cited record against `HuntDataPlanePort.verifyCitations`.
 */
export async function verifyHandoffCitations(
  handoff: Handoff,
  dataPlane: HuntDataPlanePort,
  signal?: AbortSignal,
): Promise<CitationCheckOutcome> {
  const eventIds = new Set<string>();
  const frameIds = new Set<string>();
  const iocIds = new Set<string>();

  const textsToScan: string[] = [
    ...handoff.claims.map((c) => c.statement),
    ...handoff.limitations,
    ...handoff.requested_decisions,
    ...handoff.reviews.map((r) => r.rationale),
  ];

  for (const text of textsToScan) {
    const extracted = extractInlineCitations(text);
    for (const id of extracted.event_ids) eventIds.add(id);
    for (const id of extracted.frame_ids) frameIds.add(id);
    for (const id of extracted.ioc_ids) iocIds.add(id);
  }

  const receipt = await dataPlane.verifyCitations(
    {
      case_id: handoff.case_id,
      event_ids: [...eventIds].sort(),
      frame_ids: [...frameIds].sort(),
      ioc_ids: [...iocIds].sort(),
    },
    signal,
  );

  if (receipt.source_status === "unavailable") {
    return {
      status: "unknown",
      receipt,
      errorMessage:
        receipt.diagnostic ?? "Citation verification backend unavailable (fail-closed unknown)",
    };
  }

  const hasFailures =
    !receipt.verified ||
    receipt.missing_event_ids.length > 0 ||
    receipt.missing_frame_ids.length > 0 ||
    receipt.missing_ioc_ids.length > 0 ||
    receipt.ambiguous_ids.length > 0 ||
    receipt.out_of_scope_ids.length > 0;

  if (hasFailures) {
    const parts: string[] = [];
    if (receipt.missing_event_ids.length > 0) {
      parts.push(`missing events=[${receipt.missing_event_ids.join(", ")}]`);
    }
    if (receipt.missing_frame_ids.length > 0) {
      parts.push(`missing frames=[${receipt.missing_frame_ids.join(", ")}]`);
    }
    if (receipt.missing_ioc_ids.length > 0) {
      parts.push(`missing iocs=[${receipt.missing_ioc_ids.join(", ")}]`);
    }
    if (receipt.ambiguous_ids.length > 0) {
      parts.push(`ambiguous=[${receipt.ambiguous_ids.join(", ")}]`);
    }
    if (receipt.out_of_scope_ids.length > 0) {
      parts.push(`out_of_scope=[${receipt.out_of_scope_ids.join(", ")}]`);
    }
    return {
      status: "failed",
      receipt,
      errorMessage: `Host citation verification failed: ${parts.join("; ") || receipt.diagnostic || "unverified inline citations"}`,
    };
  }

  return { status: "verified", receipt };
}
