import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { STAGE_IDS, type StageId } from "@hunt-command/shared";
import {
  assertEmptyOutsideRepoAndRuntimeDir,
  assertSubscriptionOnlyEnv,
  CLEAN_ROOM_TOOL_ABORT_EXIT_CODE,
  CleanRoomToolViolationError,
  CleanRoomViolationError,
  isApiKeyEnvName,
  type CleanRoomRole,
  type CleanRoomWorkerTurnRequest,
  type CleanRoomWorkerTurnResult,
  type CleanRoomWorkerWireFrame,
} from "./clean-room-worker.ts";
import {
  checkReport,
  type CaseEvents,
  type CheckedReportWithScorer,
} from "./review-reports.ts";
import {
  citedIds,
  loadJsonText,
  names,
  scoreReport,
  validateTruth,
  type ScenarioTruth,
  type ScoreReportResult,
} from "./scorer.ts";

export const COACH_EVAL_EVENT_TYPE = "hunt.coach.eval" as const;
export const MAX_PLAYBOOK_STAGE_GUIDANCE_BYTES = 600 as const;
export const MAX_PLAYBOOK_FOLLOW_UPS = 12 as const;
export const MAX_PLAYBOOK_SKILL_NOTES = 5 as const;
export const MAX_PLAYBOOK_SKILL_NOTE_CHARS = 280 as const;
export const DEFAULT_MIN_FOUND_GAIN = 1.0 as const;

export const GUIDANCE_STAGES: readonly StageId[] = STAGE_IDS;
const GUIDANCE_STAGE_SET: ReadonlySet<string> = new Set(GUIDANCE_STAGES);

/**
 * Strict positive file allowlist for Track 2 (`code_pr`) proposals.
 * Replaces upstream's leaky `_PROTECTED_FILES` denylist: ONLY mutable prompt,
 * stage-guidance, persona, and heuristic defaults may ever be touched by Coach.
 * Any touch to `packages/coach/**`, `scripts/**`, `packages/shared/**`,
 * `packages/telemetry/**`, `packages/data-plane/**`, `apps/**`, gate auth,
 * ontology validators, `package.json`, `TRACKED-FILES.txt`, or `*.test.ts` is
 * unconditionally rejected.
 */
export const ALLOWED_COACH_MUTATION_FILES = [
  "packages/daemon/src/prompts/stage-guidance.ts",
  "packages/daemon/src/prompts/personas.ts",
  "packages/daemon/src/prompts/heuristics.ts",
  "packages/daemon/src/prompts/playbook-defaults.json",
] as const;

export type AllowedCoachMutationFile = (typeof ALLOWED_COACH_MUTATION_FILES)[number];

const ALLOWED_COACH_MUTATION_SET: ReadonlySet<string> = new Set(
  ALLOWED_COACH_MUTATION_FILES,
);

export const DIAGNOSTIC_REASON_CODES = [
  "NONE",
  "GROUNDING_MISSING_CITATION",
  "DECOY_MISATTRIBUTED",
  "SCHEMA_INVALID",
  "STEP_HALTED",
  "TOOL_TIMEOUT",
  "TOOL_ERROR",
  "BATCH_LIMIT_EXCEEDED",
  "QUERY_REJECTED",
  "PASS2_BELOW_MARGIN",
  "G2_1_UNGROUNDED_ID",
  "PANEL_REJECTED",
  "PROPOSAL_BOUNDS_EXCEEDED",
  "ALLOWLIST_REJECTED",
  "UNKNOWN_REASON",
] as const;

export type DiagnosticReasonCode = (typeof DIAGNOSTIC_REASON_CODES)[number];

const DIAGNOSTIC_REASON_SET: ReadonlySet<string> = new Set(DIAGNOSTIC_REASON_CODES);

/**
 * Closed-set technical vocabulary exempt from `events.vocabulary` >=4-char
 * leak rejection so generic protocol/stage identifiers in diagnostics do not
 * false-positive when an event happens to mention `"network"` or `"https"`.
 */
export const SAFE_TECH_WORDS: ReadonlySet<string> = new Set([
  "elastic",
  "arkime",
  "zeek",
  "suricata",
  "sysmon",
  "windows",
  "linux",
  "http",
  "https",
  "tls",
  "quic",
  "icmp",
  "kerberos",
  "ldap",
  "ldaps",
  "ntlm",
  "smb",
  "rdp",
  "ssh",
  "winrm",
  "powershell",
  "cmd",
  "process",
  "parent",
  "network",
  "auth",
  "authentication",
  "logon",
  "file",
  "registry",
  "scheduled",
  "service",
  "session",
  "event",
  "events",
  "claim",
  "claims",
  "review",
  "reviews",
  "limitation",
  "limitations",
  "handoff",
  "snapshot",
  "scope",
  "evidence",
  "hypotheses",
  "intel",
  "analysis",
  "follow",
  "merge",
  "detection",
  "purple",
  "incident",
  "playbook",
  "code_pr",
  "promoted",
  "reverted_probe",
  "reverted_pass2",
  "reverted_panel",
  "rejected_validation",
  "true",
  "false",
  "null",
  "none",
  "host",
  "user",
  "source",
  "destination",
  "client",
  "server",
  "domain",
  "port",
  "bytes",
  "packets",
  "query",
  "status",
  "action",
  "result",
  "count",
  "total",
  "mean",
  "round",
  "stage",
  "track",
]);

export type CoachSubcommand = "judge" | "propose" | "stage-pr" | "promote";

export class HoldoutSealedError extends Error {
  public readonly reasons: readonly string[];
  public readonly subcommand: CoachSubcommand;

  public constructor(subcommand: CoachSubcommand, reasons: readonly string[]) {
    super(
      `Sealed holdout access refused for '${subcommand}': case triggered holdout guard [${reasons.join(", ")}]`,
    );
    this.name = "HoldoutSealedError";
    this.subcommand = subcommand;
    this.reasons = [...reasons];
  }
}

export class PacketLeakError extends Error {
  public readonly path: string;
  public readonly rule: string;

  public constructor(fieldPath: string, rule: string, detail: string) {
    super(`CleanDiagnosticsPacket leak blocked at '${fieldPath}' [${rule}]: ${detail}`);
    this.name = "PacketLeakError";
    this.path = fieldPath;
    this.rule = rule;
  }
}

export class ProposalValidationError extends Error {
  public readonly code: string;

  public constructor(code: string, message: string) {
    super(message);
    this.name = "ProposalValidationError";
    this.code = code;
  }
}

export class CoachAllowlistError extends ProposalValidationError {
  public readonly forbiddenPath: string;

  public constructor(forbiddenPath: string, reason?: string) {
    super(
      "allowlist_rejected",
      `Track 2 code_pr path '${forbiddenPath}' is outside ALLOWED_COACH_MUTATION_FILES${reason ? ` (${reason})` : ""}`,
    );
    this.name = "CoachAllowlistError";
    this.forbiddenPath = forbiddenPath;
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function roundTo4(value: number): number {
  return Math.round(value * 10_000) / 10_000;
}

// ============================================================================
// 1. Clean-Room Out-of-Process Child Spawner
// ============================================================================

export function buildCleanRoomChildEnv(
  baseEnv: Readonly<Record<string, string | undefined>> = process.env,
  options?: { allowTestSimulation?: boolean },
): Record<string, string> {
  const clean: Record<string, string> = {};
  for (const [key, val] of Object.entries(baseEnv)) {
    if (val === undefined) {
      continue;
    }
    if (isApiKeyEnvName(key)) {
      continue;
    }
    if (key.toUpperCase() === "HUNT_COACH_ALLOW_TEST_SIM") {
      continue;
    }
    clean[key] = val;
  }
  clean.NO_COLOR = "1";
  if (options?.allowTestSimulation === true) {
    clean.HUNT_COACH_ALLOW_TEST_SIM = "1";
  }
  assertSubscriptionOnlyEnv(clean);
  return clean;
}

export function createEmptyCleanRoomTempDir(options?: {
  repoRoot?: string;
  baseTempRoot?: string;
  prefix?: string;
}): string {
  const baseRoot = options?.baseTempRoot ?? os.tmpdir();
  const prefix = options?.prefix ?? "hunt-coach-clean-";
  const created = fs.mkdtempSync(path.join(baseRoot, prefix));
  try {
    assertEmptyOutsideRepoAndRuntimeDir(created, { repoRoot: options?.repoRoot });
    return created;
  } catch (err) {
    fs.rmSync(created, { recursive: true, force: true });
    throw err;
  }
}

export interface SpawnZeroToolCleanRoomOptions {
  readonly repoRoot?: string;
  readonly baseTempRoot?: string;
  readonly env?: Readonly<Record<string, string | undefined>>;
  readonly workerScriptPath?: string;
  readonly timeoutMs?: number;
  readonly allowTestSimulation?: boolean;
  readonly simulateToolStart?: {
    readonly toolName: string;
    readonly toolCallId?: string;
  };
  readonly mockResponseText?: string;
  readonly onDirectoryInspected?: (info: {
    readonly emptyTmpDir: string;
    readonly entriesBefore: readonly string[];
    readonly entriesAfter: readonly string[];
  }) => void;
}

export async function spawnZeroToolCleanRoomTurn(
  params: {
    readonly role: CleanRoomRole;
    readonly systemPrompt: string;
    readonly prompt: string;
    readonly modelPattern?: string;
  },
  options?: SpawnZeroToolCleanRoomOptions,
): Promise<CleanRoomWorkerTurnResult> {
  const workerPath =
    options?.workerScriptPath ??
    path.resolve(import.meta.dir, "clean-room-worker.ts");

  const emptyTmpDir = createEmptyCleanRoomTempDir({
    repoRoot: options?.repoRoot,
    baseTempRoot: options?.baseTempRoot,
    prefix: `hunt-coach-${params.role}-`,
  });

  const entriesBefore = fs.readdirSync(emptyTmpDir);
  if (entriesBefore.length !== 0) {
    fs.rmSync(emptyTmpDir, { recursive: true, force: true });
    throw new CleanRoomViolationError(
      "non_empty_clean_room_cwd",
      `Fresh clean-room directory '${emptyTmpDir}' was not empty before spawn`,
    );
  }

  const cleanEnv = buildCleanRoomChildEnv(options?.env ?? process.env, {
    allowTestSimulation: options?.allowTestSimulation,
  });

  const payload: CleanRoomWorkerTurnRequest = {
    role: params.role,
    emptyTmpDir,
    repoRoot: options?.repoRoot,
    systemPrompt: params.systemPrompt,
    prompt: params.prompt,
    modelPattern: params.modelPattern,
    deadlineMs: options?.timeoutMs,
    simulateToolStart: options?.simulateToolStart,
    mockResponseText: options?.mockResponseText,
  };

  let entriesAfter: string[] = [];
  let postTurnDirViolation: CleanRoomViolationError | null = null;

  try {
    const child = Bun.spawn([process.execPath, workerPath], {
      cwd: emptyTmpDir,
      env: cleanEnv,
      stdin: "pipe",
      stdout: "pipe",
      stderr: "pipe",
      windowsHide: true,
    });

    const timeoutMs = options?.timeoutMs ?? 120_000;
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      try {
        child.kill();
      } catch {
        // Ignore kill race if child already exited.
      }
    }, timeoutMs);

    try {
      child.stdin.write(JSON.stringify(payload));
      child.stdin.end();

      const wireState: {
        detectedToolViolation: CleanRoomToolViolationError | null;
        workerResult: CleanRoomWorkerTurnResult | null;
        workerErrorFrame: { code: string; message: string } | null;
      } = {
        detectedToolViolation: null,
        workerResult: null,
        workerErrorFrame: null,
      };

      const stderrPromise = new Response(child.stderr).text();
      const reader = child.stdout.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      const processLine = (rawLine: string): void => {
        const trimmed = rawLine.trim();
        if (trimmed.length === 0) {
          return;
        }
        let frame: CleanRoomWorkerWireFrame;
        try {
          frame = JSON.parse(trimmed) as CleanRoomWorkerWireFrame;
        } catch {
          return;
        }

        if (frame.type === "tool_execution_start") {
          if (wireState.detectedToolViolation === null) {
            wireState.detectedToolViolation = new CleanRoomToolViolationError(
              frame.toolName,
              frame.toolCallId,
            );
          }
          try {
            child.kill();
          } catch {
            // Child may have already aborted.
          }
          return;
        }
        if (frame.type === "result") {
          wireState.workerResult = frame.result;
          return;
        }
        if (frame.type === "error") {
          wireState.workerErrorFrame = { code: frame.code, message: frame.message };
        }
      };

      while (true) {
        const { value, done } = await reader.read();
        if (done) {
          break;
        }
        buffer += decoder.decode(value, { stream: true });
        let newlineIdx = buffer.indexOf("\n");
        while (newlineIdx !== -1) {
          const line = buffer.slice(0, newlineIdx);
          buffer = buffer.slice(newlineIdx + 1);
          processLine(line);
          if (wireState.detectedToolViolation !== null) {
            break;
          }
          newlineIdx = buffer.indexOf("\n");
        }
        if (wireState.detectedToolViolation !== null) {
          break;
        }
      }
      buffer += decoder.decode();
      if (buffer.trim().length > 0 && wireState.detectedToolViolation === null) {
        for (const rem of buffer.split("\n")) {
          processLine(rem);
        }
      }

      const [exitCode, stderrText] = await Promise.all([child.exited, stderrPromise]);

      if (wireState.detectedToolViolation !== null) {
        throw wireState.detectedToolViolation;
      }
      if (exitCode === CLEAN_ROOM_TOOL_ABORT_EXIT_CODE) {
        const msg =
          wireState.workerErrorFrame?.message ??
          "Child clean-room worker exited with tool-violation code";
        throw new CleanRoomToolViolationError("aborted_child_tool", msg);
      }
      if (timedOut) {
        throw new CleanRoomViolationError(
          "clean_room_worker_timeout",
          `Clean-room ${params.role} worker timed out after ${timeoutMs}ms`,
        );
      }
      if (wireState.workerErrorFrame !== null) {
        throw new CleanRoomViolationError(
          wireState.workerErrorFrame.code,
          wireState.workerErrorFrame.message,
        );
      }
      if (exitCode !== 0 || wireState.workerResult === null) {
        throw new CleanRoomViolationError(
          "clean_room_worker_failed",
          `Clean-room ${params.role} worker failed (exit ${exitCode}): ${stderrText.trim()}`,
        );
      }

      entriesAfter = fs.existsSync(emptyTmpDir) ? fs.readdirSync(emptyTmpDir) : [];
      if (entriesAfter.length !== 0) {
        postTurnDirViolation = new CleanRoomViolationError(
          "non_empty_clean_room_cwd",
          `Clean-room ${params.role} worker left ${entriesAfter.length} unexpected file(s) in temp directory`,
        );
        throw postTurnDirViolation;
      }

      return wireState.workerResult;
    } finally {
      clearTimeout(timer);
    }
  } finally {
    if (fs.existsSync(emptyTmpDir)) {
      if (entriesAfter.length === 0) {
        entriesAfter = fs.readdirSync(emptyTmpDir);
      }
      options?.onDirectoryInspected?.({
        emptyTmpDir,
        entriesBefore,
        entriesAfter,
      });
      fs.rmSync(emptyTmpDir, { recursive: true, force: true });
    }
  }
}

// ============================================================================
// 2. Sealed Holdout Detector & Clean Git Tree Gate
// ============================================================================

export interface HoldoutInspectionInput {
  readonly caseMeta?: Record<string, unknown> | null;
  readonly truth?: ScenarioTruth | Record<string, unknown> | null;
  readonly eventsVocab?: Iterable<string>;
}

const DEDALE_TOKEN_RE = /\bdedale\b/i;
const REAL_WIN_CASE_RE = /\breal-win-[a-z0-9_-]*\b/i;
const STORY_B_TOKEN_RE = /\bstory[-_]b(?:[-_]holdout)?\b/i;
const TALVERIN_ENV_PHRASE_RE = /of\s+the\s+talverin\s+environment/i;
const TALVERIN_DOMAIN_RE = /\btalverin\.example\b/i;
const PORTAL_PROBING_SLUG = "attack.recon.portal-path-probing";

function collectAllStringsFromJson(value: unknown, out: string[]): void {
  if (typeof value === "string") {
    out.push(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      collectAllStringsFromJson(item, out);
    }
    return;
  }
  if (isPlainObject(value)) {
    for (const [k, v] of Object.entries(value)) {
      out.push(k);
      collectAllStringsFromJson(v, out);
    }
  }
}

/**
 * Detects whether a case belongs to any sealed holdout family:
 * - `story === 'b'` (or `story_b_holdout`)
 * - `'of the Talverin environment'` / `'talverin.example'`
 * - `'attack.recon.portal-path-probing'`
 * - `data_origin === 'public-dataset'`
 * - `'DEDALE'` / `'real-win-*'`
 */
export function detectHoldoutReasons(input: HoldoutInspectionInput): string[] {
  const reasons = new Set<string>();

  const checkStoryAndOrigin = (obj: Record<string, unknown> | null | undefined): void => {
    if (!obj) {
      return;
    }
    const story = obj.story;
    if (typeof story === "string" && story.trim().toLowerCase() === "b") {
      reasons.add("story==='b'");
    }
    const dataOrigin = obj.data_origin;
    if (
      typeof dataOrigin === "string" &&
      dataOrigin.trim().toLowerCase() === "public-dataset"
    ) {
      reasons.add("data_origin==='public-dataset'");
    }
    const source = obj.source;
    if (typeof source === "string" && DEDALE_TOKEN_RE.test(source)) {
      reasons.add("DEDALE");
    }
  };

  checkStoryAndOrigin(input.caseMeta ?? undefined);
  checkStoryAndOrigin(
    input.truth ? (input.truth as unknown as Record<string, unknown>) : undefined,
  );

  const stringsToScan: string[] = [];
  if (input.caseMeta) {
    collectAllStringsFromJson(input.caseMeta, stringsToScan);
  }
  if (input.truth) {
    collectAllStringsFromJson(input.truth, stringsToScan);
  }
  if (input.eventsVocab) {
    for (const token of input.eventsVocab) {
      stringsToScan.push(token);
    }
  }

  for (const s of stringsToScan) {
    const lower = s.toLowerCase();
    if (STORY_B_TOKEN_RE.test(s)) {
      reasons.add("story==='b'");
    }
    if (TALVERIN_ENV_PHRASE_RE.test(s) || TALVERIN_DOMAIN_RE.test(s) || /\btalverin\b/i.test(s)) {
      reasons.add("talverin.example");
    }
    if (lower.includes(PORTAL_PROBING_SLUG)) {
      reasons.add("attack.recon.portal-path-probing");
    }
    if (lower === "public-dataset") {
      reasons.add("data_origin==='public-dataset'");
    }
    if (DEDALE_TOKEN_RE.test(s) || REAL_WIN_CASE_RE.test(s)) {
      reasons.add("DEDALE");
    }
  }

  return [...reasons].sort();
}

export function enforceHoldoutPolicy(
  subcommand: CoachSubcommand,
  holdoutReasons: readonly string[],
  options?: { sealedEval?: boolean },
): void {
  if (holdoutReasons.length === 0) {
    return;
  }

  // Training / mutation commands are UNCONDITIONALLY forbidden on sealed holdouts.
  if (
    subcommand === "propose" ||
    subcommand === "stage-pr" ||
    subcommand === "promote"
  ) {
    throw new HoldoutSealedError(subcommand, holdoutReasons);
  }

  // One-way read-only `judge` is gated behind explicit `sealedEval: true`.
  if (options?.sealedEval !== true) {
    throw new HoldoutSealedError(subcommand, holdoutReasons);
  }
}

/**
 * Fail-closed variant for the mutation paths (`propose` / `stage-pr` / `promote`):
 * holdout provenance MUST be supplied explicitly. A missing or malformed
 * `holdoutReasons` is refused rather than treated as "no holdout".
 */
export function requireHoldoutClearance(
  subcommand: CoachSubcommand,
  holdoutReasons: readonly string[] | undefined,
): void {
  if (
    !Array.isArray(holdoutReasons) ||
    holdoutReasons.some((r) => typeof r !== "string")
  ) {
    throw new CleanRoomViolationError(
      "holdout_provenance_missing",
      `'${subcommand}' refused: holdoutReasons must be supplied explicitly (fail closed)`,
    );
  }
  enforceHoldoutPolicy(subcommand, holdoutReasons);
}

export function assertCleanGitTree(repoRoot: string): void {
  const res = spawnSync("git", ["status", "--porcelain"], {
    cwd: repoRoot,
    encoding: "utf8",
    windowsHide: true,
  });

  if (res.status !== 0) {
    throw new CleanRoomViolationError(
      "git_status_failed",
      `Failed to verify clean git tree in '${repoRoot}': ${(res.stderr || res.stdout || "").trim()}`,
    );
  }

  const dirty = (res.stdout ?? "").trim();
  if (dirty.length > 0) {
    const preview = dirty.split(/\r?\n/).slice(0, 5).join("; ");
    throw new CleanRoomViolationError(
      "dirty_git_tree",
      `Refusing evaluation on dirty git working tree in '${repoRoot}': ${preview}`,
    );
  }
}

// ============================================================================
// 3. Scrubbed Numeric/Enum-Only Diagnostic Packet & Leak Firewall
// ============================================================================

export function classifyReasonCode(rawReason: string | null | undefined): DiagnosticReasonCode {
  if (!rawReason || rawReason.trim().length === 0) {
    return "NONE";
  }
  const trimmed = rawReason.trim();
  if (DIAGNOSTIC_REASON_SET.has(trimmed)) {
    return trimmed as DiagnosticReasonCode;
  }

  const lower = trimmed.toLowerCase();
  if (lower.includes("g2_1") || lower.includes("missing_event") || lower.includes("missing_frame") || lower.includes("missing_intel") || lower.includes("ungrounded")) {
    return "G2_1_UNGROUNDED_ID";
  }
  if (lower.includes("citation") || lower.includes("evidence_id")) {
    return "GROUNDING_MISSING_CITATION";
  }
  if (lower.includes("decoy") || lower.includes("misattribut")) {
    return "DECOY_MISATTRIBUTED";
  }
  if (lower.includes("allowlist")) {
    return "ALLOWLIST_REJECTED";
  }
  if (lower.includes("bound") || lower.includes("brief") || lower.includes("follow_up") || lower.includes("skill_note")) {
    return "PROPOSAL_BOUNDS_EXCEEDED";
  }
  if (lower.includes("panel") || lower.includes("verifier")) {
    return "PANEL_REJECTED";
  }
  if (lower.includes("pass2") || lower.includes("margin") || lower.includes("gain")) {
    return "PASS2_BELOW_MARGIN";
  }
  if (lower.includes("schema") || lower.includes("zod") || lower.includes("json")) {
    return "SCHEMA_INVALID";
  }
  if (lower.includes("halt") || lower.includes("stop")) {
    return "STEP_HALTED";
  }
  if (lower.includes("timeout") || lower.includes("timed out")) {
    return "TOOL_TIMEOUT";
  }
  if (lower.includes("batch")) {
    return "BATCH_LIMIT_EXCEEDED";
  }
  if (lower.includes("wildcard") || lower.includes("field_not_allowed") || lower.includes("invalid_query") || lower.includes("query")) {
    return "QUERY_REJECTED";
  }
  if (lower.includes("tool")) {
    return "TOOL_ERROR";
  }
  return "UNKNOWN_REASON";
}

export interface BuildForbiddenSetOptions {
  readonly truth?: ScenarioTruth | ReadonlyArray<ScenarioTruth>;
  readonly caseIds?: Iterable<string>;
  readonly eventsVocab?: Iterable<string>;
  readonly extraForbidden?: Iterable<string>;
}

export function buildForbiddenSet(options?: BuildForbiddenSetOptions): Set<string> {
  const forbidden = new Set<string>();
  if (!options) {
    return forbidden;
  }

  const truths: readonly ScenarioTruth[] = options.truth
    ? Array.isArray(options.truth)
      ? options.truth
      : [options.truth as ScenarioTruth]
    : [];

  for (const truth of truths) {
    if (typeof truth.case_id === "string" && truth.case_id.trim().length > 0) {
      forbidden.add(truth.case_id.trim().toLowerCase());
    }
    for (const fact of truth.facts) {
      forbidden.add(fact.fact_id.toLowerCase());
      for (const vals of Object.values(fact.entities)) {
        for (const entityVal of vals) {
          const norm = entityVal.trim().toLowerCase();
          if (norm.length >= 2 && !SAFE_TECH_WORDS.has(norm)) {
            forbidden.add(norm);
          }
        }
      }
      for (const grp of fact.evidence_event_groups) {
        for (const id of grp) {
          forbidden.add(id.toLowerCase());
        }
      }
      for (const grp of fact.evidence_frame_groups ?? []) {
        for (const id of grp) {
          forbidden.add(`frame-${id}`.toLowerCase());
        }
      }
      for (const grp of fact.evidence_intel_groups ?? []) {
        for (const id of grp) {
          forbidden.add(id.toLowerCase());
        }
      }
    }
  }

  if (options.caseIds) {
    for (const cid of options.caseIds) {
      const norm = cid.trim().toLowerCase();
      if (norm.length > 0) {
        forbidden.add(norm);
      }
    }
  }

  if (options.eventsVocab) {
    for (const rawWord of options.eventsVocab) {
      for (const token of rawWord.split(/[^A-Za-z0-9_.-]+/)) {
        const norm = token.trim().toLowerCase();
        if (norm.length >= 4 && !SAFE_TECH_WORDS.has(norm) && !/^\d+$/.test(norm)) {
          forbidden.add(norm);
        }
      }
    }
  }

  if (options.extraForbidden) {
    for (const item of options.extraForbidden) {
      const norm = item.trim().toLowerCase();
      if (norm.length > 0) {
        forbidden.add(norm);
      }
    }
  }

  return forbidden;
}

const SINGLE_TOKEN_ENUM_LEAF_RE = /^[A-Za-z0-9_.:-]{1,64}$/;
const FACT_SLUG_RE = /\b(?:attack|decoy|benign|coverage)\.[a-z0-9_-]+(?:\.[a-z0-9_-]+)*\b/i;
const RAW_EVT_ID_RE = /\bevt-[a-z0-9_-]+\b/i;
const RAW_FRAME_ID_RE = /\bframe-\d+\b/i;
const RAW_IOC_ID_RE = /\bioc-\d+\b/i;
const CASE_ID_LEAK_RE =
  /\b(?:story[-_]?[ab](?:[-_][a-z0-9_-]+)?|team-(?:easy|med|hard)-\d+|solo-[a-z]+-\d+|real-win-[a-z0-9_-]*|case[-_]\d+)\b/i;
const IPV4_LEAK_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
const IPV6_LEAK_RE = /\b(?:[0-9a-f]{1,4}:){2,}[0-9a-f:]{1,24}\b/i;
const SYNTH_DOMAIN_LEAK_RE =
  /\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:example|test|invalid|local|internal|corp|lan|home)\b/i;
const HEX_HASH_LEAK_RE = /\b(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})\b/i;
const SEALED_KEYWORD_LEAK_RE =
  /(?:northvale|talverin|dedale|truth\.json|operator-only|story_b_holdout)/i;

// Global copies used ONLY for `.replace` so every occurrence is redacted. The
// non-global originals above stay in use for `.test` (no `lastIndex` state).
const toGlobal = (re: RegExp): RegExp => new RegExp(re.source, `${re.flags}g`);
const SCRUB_RULES: ReadonlyArray<readonly [RegExp, string]> = [
  [toGlobal(FACT_SLUG_RE), "[REDACTED_FACT]"],
  [toGlobal(RAW_EVT_ID_RE), "[REDACTED_EVT]"],
  [toGlobal(RAW_FRAME_ID_RE), "[REDACTED_FRAME]"],
  [toGlobal(RAW_IOC_ID_RE), "[REDACTED_IOC]"],
  [toGlobal(CASE_ID_LEAK_RE), "[REDACTED_CASE]"],
  [toGlobal(SYNTH_DOMAIN_LEAK_RE), "[REDACTED_DOMAIN]"],
  [toGlobal(IPV4_LEAK_RE), "[REDACTED_IP]"],
  [toGlobal(IPV6_LEAK_RE), "[REDACTED_IP]"],
  [toGlobal(HEX_HASH_LEAK_RE), "[REDACTED_HASH]"],
  [toGlobal(SEALED_KEYWORD_LEAK_RE), "[REDACTED_SEALED]"],
];

export function scrubText(
  raw: string,
  forbidden?: ReadonlySet<string>,
): string {
  let out = raw;
  for (const [re, replacement] of SCRUB_RULES) {
    out = out.replace(re, replacement);
  }

  if (forbidden && forbidden.size > 0) {
    for (const term of forbidden) {
      if (term.length >= 3 && names(out, term)) {
        const escaped = term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        out = out.replace(new RegExp(escaped, "gi"), "[REDACTED_VOCAB]");
      }
    }
  }
  return out;
}

export interface AssertCleanPacketOptions extends BuildForbiddenSetOptions {
  readonly forbidden?: ReadonlySet<string>;
}

/**
 * Fail closed when the case-specific leak guard is missing or empty: without
 * truth / case ids / vocab / forbidden terms the packet check only covers the
 * generic patterns, so the packet must not reach a clean-room model.
 */
export function requireLeakGuard(
  where: string,
  leakGuard: AssertCleanPacketOptions | undefined,
): AssertCleanPacketOptions {
  const hasAny =
    isPlainObject(leakGuard) &&
    (leakGuard.truth !== undefined ||
      leakGuard.caseIds !== undefined ||
      leakGuard.eventsVocab !== undefined ||
      leakGuard.extraForbidden !== undefined ||
      leakGuard.forbidden !== undefined);
  if (!hasAny) {
    throw new CleanRoomViolationError(
      "leak_guard_missing",
      `'${where}' refused: a non-empty leakGuard is required (fail closed)`,
    );
  }
  return leakGuard as AssertCleanPacketOptions;
}

function inspectCleanStringToken(
  token: string,
  fieldPath: string,
  forbidden: ReadonlySet<string>,
): void {
  // 1. Structural anti-prompt-injection rule (#178 G1.1):
  // Every string in the diagnostics packet MUST be a compact single-token enum/identifier,
  // never whitespace-bearing prose, log lines, or natural-language sentences.
  if (!SINGLE_TOKEN_ENUM_LEAF_RE.test(token)) {
    throw new PacketLeakError(
      fieldPath,
      "NON_ENUM_PROSE_OR_INJECTION",
      `String value '${token.slice(0, 48)}' contains whitespace, control chars, or exceeds 64-char enum token grammar`,
    );
  }

  if (FACT_SLUG_RE.test(token)) {
    throw new PacketLeakError(fieldPath, "FACT_SLUG", `Fact slug leaked: '${token}'`);
  }
  if (RAW_EVT_ID_RE.test(token)) {
    throw new PacketLeakError(fieldPath, "EVT_ID", `Event ID leaked: '${token}'`);
  }
  if (RAW_FRAME_ID_RE.test(token)) {
    throw new PacketLeakError(fieldPath, "FRAME_ID", `Frame ID leaked: '${token}'`);
  }
  if (RAW_IOC_ID_RE.test(token)) {
    throw new PacketLeakError(fieldPath, "IOC_ID", `IOC ID leaked: '${token}'`);
  }
  if (CASE_ID_LEAK_RE.test(token)) {
    throw new PacketLeakError(fieldPath, "CASE_ID", `Case ID leaked: '${token}'`);
  }
  if (IPV4_LEAK_RE.test(token) || IPV6_LEAK_RE.test(token)) {
    throw new PacketLeakError(fieldPath, "IP_ADDRESS", `IP address leaked: '${token}'`);
  }
  if (SYNTH_DOMAIN_LEAK_RE.test(token)) {
    throw new PacketLeakError(fieldPath, "SYNTH_DOMAIN", `Domain leaked: '${token}'`);
  }
  if (HEX_HASH_LEAK_RE.test(token)) {
    throw new PacketLeakError(fieldPath, "HEX_HASH", `Hex hash leaked: '${token}'`);
  }
  if (SEALED_KEYWORD_LEAK_RE.test(token)) {
    throw new PacketLeakError(
      fieldPath,
      "SEALED_KEYWORD",
      `Sealed keyword leaked: '${token}'`,
    );
  }

  const lower = token.toLowerCase();
  if (forbidden.has(lower)) {
    throw new PacketLeakError(
      fieldPath,
      "FORBIDDEN_VOCAB",
      `Forbidden entity/vocab token leaked: '${token}'`,
    );
  }

  for (const term of forbidden) {
    if (term.length >= 3 && (lower === term || names(lower, term))) {
      throw new PacketLeakError(
        fieldPath,
        "FORBIDDEN_VOCAB",
        `Forbidden entity/vocab '${term}' matched inside '${token}'`,
      );
    }
  }
}

export function assertCleanPacket(
  packet: unknown,
  options?: AssertCleanPacketOptions,
): void {
  if (!isPlainObject(packet)) {
    throw new PacketLeakError("$", "INVALID_ROOT", "Diagnostics packet must be a plain object");
  }

  const combinedForbidden = new Set<string>(options?.forbidden ?? []);
  for (const extra of buildForbiddenSet(options)) {
    combinedForbidden.add(extra);
  }

  const walk = (node: unknown, currentPath: string): void => {
    if (node === null || typeof node === "boolean") {
      return;
    }
    if (typeof node === "number") {
      if (!Number.isFinite(node)) {
        throw new PacketLeakError(
          currentPath,
          "NON_FINITE_NUMBER",
          `Non-finite number '${String(node)}' in diagnostics packet`,
        );
      }
      return;
    }
    if (typeof node === "string") {
      inspectCleanStringToken(node, currentPath, combinedForbidden);
      return;
    }
    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i++) {
        walk(node[i], `${currentPath}[${i}]`);
      }
      return;
    }
    if (isPlainObject(node)) {
      for (const [k, v] of Object.entries(node)) {
        inspectCleanStringToken(k, `${currentPath}.<key:${k}>`, combinedForbidden);
        walk(v, `${currentPath}.${k}`);
      }
      return;
    }
    throw new PacketLeakError(
      currentPath,
      "UNSUPPORTED_TYPE",
      `Unsupported value type '${typeof node}' in diagnostics packet`,
    );
  };

  walk(packet, "$");
}

export interface StageCitationFunnelEntry {
  readonly claims_emitted: number;
  readonly cited_ids_emitted: number;
  readonly cited_ids_retained_in_incident: number;
}

export interface DiagnosticsRoundSummary {
  readonly round_index: number;
  readonly found_mean: number;
  readonly attack_found_mean: number;
  readonly misattributed_decoys: number;
  readonly citation_precision_mean: number;
  readonly g2_1_pass: boolean;
}

export type RevertOutcomeCode =
  | "promoted"
  | "reverted_probe"
  | "reverted_pass2"
  | "reverted_panel"
  | "rejected_validation";

export interface DiagnosticsRevertEntry {
  readonly attempt_index: number;
  readonly track: "playbook" | "code_pr";
  readonly outcome: RevertOutcomeCode;
  readonly reason_code: DiagnosticReasonCode;
  readonly probe_delta_found: number;
}

export interface CleanDiagnosticsPacket {
  readonly schema_version: 1;
  readonly case_count: number;
  readonly round_count: number;
  readonly aggregates: {
    readonly mean_found: number;
    readonly mean_attack_found: number;
    readonly mean_coverage_found: number;
    readonly misattributed_decoys_total: number;
    readonly mean_citation_precision: number;
    readonly g2_1_pass: boolean;
    readonly g2_1_pass_rate: number;
    readonly steps_halted_total: number;
  };
  readonly reason_code_counts: Partial<Record<DiagnosticReasonCode, number>>;
  readonly stage_citation_funnel: Record<string, StageCitationFunnelEntry>;
  readonly rounds: readonly DiagnosticsRoundSummary[];
  readonly revert_ledger: readonly DiagnosticsRevertEntry[];
  /** Holdout provenance: only packets built from non-sealed, non-holdout evaluations exist. */
  readonly provenance: {
    readonly holdout_checked: true;
    readonly sealed: false;
    readonly holdout_reason_count: 0;
  };
}

/** Refuses packets without clean holdout provenance (e.g. hand-built or tampered). */
export function assertPacketHoldoutProvenance(
  subcommand: CoachSubcommand,
  packet: CleanDiagnosticsPacket,
): void {
  const prov: unknown = isPlainObject(packet)
    ? (packet as { provenance?: unknown }).provenance
    : undefined;
  if (
    !isPlainObject(prov) ||
    prov.holdout_checked !== true ||
    prov.sealed !== false ||
    prov.holdout_reason_count !== 0
  ) {
    throw new CleanRoomViolationError(
      "packet_holdout_provenance_missing",
      `'${subcommand}' refused: diagnostics packet lacks clean holdout provenance (fail closed)`,
    );
  }
}

function extractAllComparableCitations(text: string): Set<string> {
  return citedIds(text);
}

export function buildCitationFunnel(
  stepHandoffs: ReadonlyArray<{
    readonly stage: StageId;
    readonly handoff: Record<string, unknown>;
  }>,
  incidentReport: Record<string, unknown>,
): Record<string, StageCitationFunnelEntry> {
  const incidentText = JSON.stringify(incidentReport);
  const incidentCitations = extractAllComparableCitations(incidentText);

  const funnel: Record<string, StageCitationFunnelEntry> = {};
  for (const item of stepHandoffs) {
    if (!GUIDANCE_STAGE_SET.has(item.stage)) {
      continue;
    }
    const claims = Array.isArray(item.handoff.claims) ? item.handoff.claims : [];
    const stepCitations = extractAllComparableCitations(JSON.stringify(item.handoff));
    let retained = 0;
    for (const id of stepCitations) {
      if (incidentCitations.has(id)) {
        retained += 1;
      }
    }
    const prev = funnel[item.stage];
    funnel[item.stage] = {
      claims_emitted: (prev?.claims_emitted ?? 0) + claims.length,
      cited_ids_emitted: (prev?.cited_ids_emitted ?? 0) + stepCitations.size,
      cited_ids_retained_in_incident:
        (prev?.cited_ids_retained_in_incident ?? 0) + retained,
    };
  }
  return funnel;
}

export interface CaseJudgeEvaluation {
  readonly score: ScoreReportResult;
  readonly review: CheckedReportWithScorer;
  readonly haltedSteps?: number;
  readonly rawReasons?: readonly string[];
  /** Holdout reasons detected for this case at judge time (stamped by `judgeCaseBatch`). */
  readonly holdoutReasons: readonly string[];
  /** True when the case was judged under `sealedEval: true`. */
  readonly sealed: boolean;
}

export interface BuildDiagnosticsPacketInput {
  readonly rounds: ReadonlyArray<ReadonlyArray<CaseJudgeEvaluation>>;
  readonly stageCitationFunnel?: Record<string, StageCitationFunnelEntry>;
  readonly revertHistory?: ReadonlyArray<{
    readonly track: "playbook" | "code_pr";
    readonly outcome: RevertOutcomeCode;
    readonly reason?: string;
    readonly probeDeltaFound?: number;
  }>;
  readonly leakGuard: AssertCleanPacketOptions;
}

export function buildDiagnosticsPacket(
  input: BuildDiagnosticsPacketInput,
): CleanDiagnosticsPacket {
  if (input.rounds.length === 0) {
    throw new Error("buildDiagnosticsPacket requires at least one round");
  }
  const leakGuard = requireLeakGuard("buildDiagnosticsPacket", input.leakGuard);

  // Fail closed on holdout provenance: every evaluation must carry the stamp from
  // `judgeCaseBatch`, and none may come from a sealed or holdout case.
  const sealedReasons = new Set<string>();
  for (const evals of input.rounds) {
    for (const ev of evals) {
      if (!Array.isArray(ev.holdoutReasons) || typeof ev.sealed !== "boolean") {
        throw new CleanRoomViolationError(
          "evaluation_holdout_provenance_missing",
          "buildDiagnosticsPacket refused: evaluation lacks holdout provenance (fail closed)",
        );
      }
      for (const r of ev.holdoutReasons) {
        sealedReasons.add(r);
      }
      if (ev.sealed) {
        sealedReasons.add("sealed_eval");
      }
    }
  }
  if (sealedReasons.size > 0) {
    throw new HoldoutSealedError("propose", [...sealedReasons].sort());
  }

  const reasonCounts: Partial<Record<DiagnosticReasonCode, number>> = {};
  const bumpReason = (code: DiagnosticReasonCode, delta = 1): void => {
    if (code === "NONE") {
      return;
    }
    reasonCounts[code] = (reasonCounts[code] ?? 0) + delta;
  };

  const roundSummaries: DiagnosticsRoundSummary[] = [];
  let totalCaseEvals = 0;
  let sumFound = 0;
  let sumAttackFound = 0;
  let sumCoverageFound = 0;
  let totalMisattributedDecoys = 0;
  let sumPrecision = 0;
  let g2PassCount = 0;
  let stepsHaltedTotal = 0;
  let maxCasesInRound = 0;

  for (let rIdx = 0; rIdx < input.rounds.length; rIdx++) {
    const evals = input.rounds[rIdx]!;
    if (evals.length === 0) {
      throw new Error(`Round ${rIdx} in buildDiagnosticsPacket cannot be empty`);
    }
    maxCasesInRound = Math.max(maxCasesInRound, evals.length);

    let rFound = 0;
    let rAttack = 0;
    let rDecoys = 0;
    let rPrec = 0;
    let rAllG2 = true;

    for (const ev of evals) {
      totalCaseEvals += 1;
      const foundCount = ev.score.found;
      const attackFound = ev.score.by_kind.attack?.found ?? 0;
      const coverageFound = ev.score.by_kind.coverage?.found ?? 0;
      const decoys = ev.score.misattributed_decoys.length;
      const prec = ev.review.citation_support.citation_precision ?? 1.0;
      const g2 = ev.review.g2_1_pass;

      sumFound += foundCount;
      sumAttackFound += attackFound;
      sumCoverageFound += coverageFound;
      totalMisattributedDecoys += decoys;
      sumPrecision += prec;
      if (g2) {
        g2PassCount += 1;
      } else {
        rAllG2 = false;
        bumpReason("G2_1_UNGROUNDED_ID");
      }
      if (decoys > 0) {
        bumpReason("DECOY_MISATTRIBUTED", decoys);
      }
      const halted = ev.haltedSteps ?? 0;
      stepsHaltedTotal += halted;
      if (halted > 0) {
        bumpReason("STEP_HALTED", halted);
      }
      for (const rawR of ev.rawReasons ?? []) {
        bumpReason(classifyReasonCode(rawR));
      }

      rFound += foundCount;
      rAttack += attackFound;
      rDecoys += decoys;
      rPrec += prec;
    }

    roundSummaries.push({
      round_index: rIdx,
      found_mean: roundTo4(rFound / evals.length),
      attack_found_mean: roundTo4(rAttack / evals.length),
      misattributed_decoys: rDecoys,
      citation_precision_mean: roundTo4(rPrec / evals.length),
      g2_1_pass: rAllG2,
    });
  }

  const sanitizedFunnel: Record<string, StageCitationFunnelEntry> = {};
  for (const [stageKey, stats] of Object.entries(input.stageCitationFunnel ?? {})) {
    if (GUIDANCE_STAGE_SET.has(stageKey)) {
      sanitizedFunnel[stageKey] = {
        claims_emitted: Math.max(0, Math.trunc(stats.claims_emitted)),
        cited_ids_emitted: Math.max(0, Math.trunc(stats.cited_ids_emitted)),
        cited_ids_retained_in_incident: Math.max(
          0,
          Math.trunc(stats.cited_ids_retained_in_incident),
        ),
      };
    }
  }

  const revertLedger: DiagnosticsRevertEntry[] = (input.revertHistory ?? []).map(
    (entry, idx) => ({
      attempt_index: idx,
      track: entry.track,
      outcome: entry.outcome,
      reason_code: classifyReasonCode(entry.reason),
      probe_delta_found: roundTo4(entry.probeDeltaFound ?? 0),
    }),
  );

  const packet: CleanDiagnosticsPacket = {
    schema_version: 1,
    case_count: maxCasesInRound,
    round_count: input.rounds.length,
    aggregates: {
      mean_found: roundTo4(sumFound / totalCaseEvals),
      mean_attack_found: roundTo4(sumAttackFound / totalCaseEvals),
      mean_coverage_found: roundTo4(sumCoverageFound / totalCaseEvals),
      misattributed_decoys_total: totalMisattributedDecoys,
      mean_citation_precision: roundTo4(sumPrecision / totalCaseEvals),
      g2_1_pass: g2PassCount === totalCaseEvals,
      g2_1_pass_rate: roundTo4(g2PassCount / totalCaseEvals),
      steps_halted_total: stepsHaltedTotal,
    },
    reason_code_counts: reasonCounts,
    stage_citation_funnel: sanitizedFunnel,
    rounds: roundSummaries,
    revert_ledger: revertLedger,
    provenance: {
      holdout_checked: true,
      sealed: false,
      holdout_reason_count: 0,
    },
  };

  assertCleanPacket(packet, leakGuard);
  return packet;
}

// ============================================================================
// 4. Track 1 (`playbook`) Bounds & Track 2 (`code_pr`) Positive File Allowlist
// ============================================================================

export interface PlaybookProposal {
  readonly track: "playbook";
  readonly rationale?: string;
  readonly brief?: string;
  readonly stage_guidance: Partial<Record<StageId, string>>;
  readonly follow_ups: number;
  readonly skill_notes: readonly string[];
}

export interface CodePrProposal {
  readonly track: "code_pr";
  readonly title: string;
  readonly rationale?: string;
  readonly files: readonly AllowedCoachMutationFile[];
  readonly unified_diff: string;
}

export type CoachProposal = PlaybookProposal | CodePrProposal;

export function validateCoachMutationPath(rawPath: string): AllowedCoachMutationFile {
  if (typeof rawPath !== "string" || rawPath.trim().length === 0) {
    throw new CoachAllowlistError(String(rawPath), "empty file path");
  }
  if (rawPath.includes("\0") || rawPath.includes("\\")) {
    throw new CoachAllowlistError(rawPath, "backslashes or null bytes forbidden");
  }
  const trimmed = rawPath.trim();
  if (trimmed.startsWith("/") || /^[A-Za-z]:/.test(trimmed)) {
    throw new CoachAllowlistError(trimmed, "absolute paths forbidden");
  }

  const segments = trimmed.split("/");
  for (const seg of segments) {
    if (seg.length === 0 || seg === "." || seg === "..") {
      throw new CoachAllowlistError(trimmed, "dot or traversal segment forbidden");
    }
  }

  const normalized = segments.join("/");
  if (!ALLOWED_COACH_MUTATION_SET.has(normalized)) {
    throw new CoachAllowlistError(normalized);
  }
  return normalized as AllowedCoachMutationFile;
}

function stripDiffPrefix(headerPath: string): string {
  const withoutTab = headerPath.split("\t")[0]!.trim();
  const unquoted =
    withoutTab.startsWith('"') && withoutTab.endsWith('"')
      ? withoutTab.slice(1, -1)
      : withoutTab;
  if (unquoted.startsWith("a/") || unquoted.startsWith("b/")) {
    return unquoted.slice(2);
  }
  return unquoted;
}

const REGULAR_FILE_MODES: ReadonlySet<string> = new Set(["100644", "100755"]);
const INDEX_LINE_MODE_RE = /^index [0-9a-f]+\.\.[0-9a-f]+ (\d+)\s*$/i;

/**
 * Track 2 diffs may only edit regular files: mode changes (`old mode` / `new mode`)
 * are refused outright, and any created/deleted/indexed mode other than
 * 100644/100755 (e.g. symlink 120000, gitlink 160000) is refused.
 */
function assertRegularFileModeLine(line: string): void {
  if (line.startsWith("old mode ") || line.startsWith("new mode ")) {
    throw new ProposalValidationError(
      "file_mode_change_forbidden",
      `Track 2 code_pr unified_diff must not change file modes: '${line}'`,
    );
  }
  let mode: string | undefined;
  if (line.startsWith("new file mode ")) {
    mode = line.slice("new file mode ".length).trim();
  } else if (line.startsWith("deleted file mode ")) {
    mode = line.slice("deleted file mode ".length).trim();
  } else {
    mode = INDEX_LINE_MODE_RE.exec(line)?.[1];
  }
  if (mode !== undefined && !REGULAR_FILE_MODES.has(mode)) {
    throw new ProposalValidationError(
      "non_regular_file_mode_forbidden",
      `Track 2 code_pr unified_diff may only touch regular files (100644/100755): '${line}'`,
    );
  }
}

export function extractUnifiedDiffPaths(
  unifiedDiff: string,
): AllowedCoachMutationFile[] {
  if (typeof unifiedDiff !== "string" || unifiedDiff.trim().length === 0) {
    throw new ProposalValidationError(
      "empty_unified_diff",
      "Track 2 code_pr unified_diff must be non-empty",
    );
  }

  if (
    /^GIT binary patch$/m.test(unifiedDiff) ||
    /^Binary files .+ differ$/m.test(unifiedDiff)
  ) {
    throw new ProposalValidationError(
      "binary_diff_forbidden",
      "Track 2 code_pr unified_diff must not contain binary patches",
    );
  }

  const touched = new Set<AllowedCoachMutationFile>();
  const lines = unifiedDiff.replace(/\r\n/g, "\n").split("\n");
  let sawHunk = false;

  for (const line of lines) {
    assertRegularFileModeLine(line);
    if (line.startsWith("@@ ")) {
      sawHunk = true;
      continue;
    }
    if (line.startsWith("diff --git ")) {
      const rest = line.slice("diff --git ".length).trim();
      const parts = rest.split(/\s+/);
      if (parts.length !== 2) {
        throw new ProposalValidationError(
          "malformed_diff_header",
          `Malformed diff --git header: '${line}'`,
        );
      }
      const left = stripDiffPrefix(parts[0]!);
      const right = stripDiffPrefix(parts[1]!);
      if (left !== "/dev/null") {
        touched.add(validateCoachMutationPath(left));
      }
      if (right !== "/dev/null") {
        touched.add(validateCoachMutationPath(right));
      }
      continue;
    }
    if (line.startsWith("--- ")) {
      const raw = line.slice(4).trim();
      if (raw !== "/dev/null") {
        touched.add(validateCoachMutationPath(stripDiffPrefix(raw)));
      }
      continue;
    }
    if (line.startsWith("+++ ")) {
      const raw = line.slice(4).trim();
      if (raw !== "/dev/null") {
        touched.add(validateCoachMutationPath(stripDiffPrefix(raw)));
      }
      continue;
    }
    if (
      line.startsWith("rename from ") ||
      line.startsWith("rename to ") ||
      line.startsWith("copy from ") ||
      line.startsWith("copy to ")
    ) {
      const raw = line.replace(/^(?:rename|copy) (?:from|to) /, "").trim();
      touched.add(validateCoachMutationPath(raw));
    }
  }

  if (touched.size === 0 || !sawHunk) {
    throw new ProposalValidationError(
      "invalid_unified_diff",
      "Track 2 code_pr unified_diff must contain valid file headers and at least one @@ hunk",
    );
  }

  return [...touched].sort();
}

const HARDCODED_EVIDENCE_OR_HOLDOUT_IN_PROPOSAL_RE =
  /(?:\bevt-\d{4,}\b|\bframe-\d+\b|\bioc-\d{4,}\b|\b(?:attack|decoy|benign|coverage)\.[a-z0-9_-]+\.[a-z0-9_-]+|northvale|talverin|dedale|story_b_holdout|truth\.json|operator-only)/i;

export interface ValidateProposalOptions {
  readonly frozenBrief?: string;
}

export function validateProposal(
  rawProposal: unknown,
  options?: ValidateProposalOptions,
): CoachProposal {
  if (!isPlainObject(rawProposal)) {
    throw new ProposalValidationError(
      "invalid_proposal_object",
      "Coach proposal must be a plain JSON object",
    );
  }

  const track = rawProposal.track;
  if (track !== "playbook" && track !== "code_pr") {
    throw new ProposalValidationError(
      "invalid_proposal_track",
      `Proposal track must be 'playbook' or 'code_pr', got '${String(track)}'`,
    );
  }

  if (track === "playbook") {
    // `brief` is frozen in Track 1: reject any attempt to supply or mutate `brief`
    // unless it is byte-for-byte identical to `options.frozenBrief`.
    if ("brief" in rawProposal && rawProposal.brief !== undefined) {
      if (
        options?.frozenBrief === undefined ||
        rawProposal.brief !== options.frozenBrief
      ) {
        throw new ProposalValidationError(
          "frozen_brief_mutation",
          "Track 1 playbook proposals may never mutate the frozen hunt brief",
        );
      }
    }

    if (!isPlainObject(rawProposal.stage_guidance)) {
      throw new ProposalValidationError(
        "invalid_stage_guidance",
        "Track 1 playbook proposal requires a plain 'stage_guidance' object",
      );
    }

    const validatedGuidance: Partial<Record<StageId, string>> = {};
    for (const [stageKey, val] of Object.entries(rawProposal.stage_guidance)) {
      if (!GUIDANCE_STAGE_SET.has(stageKey)) {
        throw new ProposalValidationError(
          "unknown_guidance_stage",
          `Unknown stage '${stageKey}' in stage_guidance`,
        );
      }
      if (typeof val !== "string") {
        throw new ProposalValidationError(
          "invalid_stage_guidance_value",
          `stage_guidance['${stageKey}'] must be a string`,
        );
      }
      const byteLen = Buffer.byteLength(val, "utf8");
      if (byteLen > MAX_PLAYBOOK_STAGE_GUIDANCE_BYTES) {
        throw new ProposalValidationError(
          "stage_guidance_exceeds_max_bytes",
          `stage_guidance['${stageKey}'] is ${byteLen} bytes (max ${MAX_PLAYBOOK_STAGE_GUIDANCE_BYTES} B)`,
        );
      }
      if (HARDCODED_EVIDENCE_OR_HOLDOUT_IN_PROPOSAL_RE.test(val)) {
        throw new ProposalValidationError(
          "hardcoded_case_artifact_in_guidance",
          `stage_guidance['${stageKey}'] contains forbidden case-specific citation/slug/holdout token`,
        );
      }
      validatedGuidance[stageKey as StageId] = val;
    }

    const followUps = rawProposal.follow_ups;
    if (
      typeof followUps !== "number" ||
      !Number.isInteger(followUps) ||
      followUps < 0 ||
      followUps > MAX_PLAYBOOK_FOLLOW_UPS
    ) {
      throw new ProposalValidationError(
        "follow_ups_out_of_bounds",
        `Track 1 follow_ups must be an integer in 0..${MAX_PLAYBOOK_FOLLOW_UPS}, got '${String(followUps)}'`,
      );
    }

    const skillNotes = rawProposal.skill_notes;
    if (!Array.isArray(skillNotes) || skillNotes.length > MAX_PLAYBOOK_SKILL_NOTES) {
      throw new ProposalValidationError(
        "skill_notes_count_exceeded",
        `Track 1 skill_notes must be an array of 0..${MAX_PLAYBOOK_SKILL_NOTES} strings`,
      );
    }

    const validatedNotes: string[] = [];
    for (let i = 0; i < skillNotes.length; i++) {
      const note = skillNotes[i];
      if (typeof note !== "string" || note.trim().length === 0) {
        throw new ProposalValidationError(
          "invalid_skill_note",
          `skill_notes[${i}] must be a non-empty string`,
        );
      }
      if (note.length > MAX_PLAYBOOK_SKILL_NOTE_CHARS) {
        throw new ProposalValidationError(
          "skill_note_too_long",
          `skill_notes[${i}] is ${note.length} chars (max ${MAX_PLAYBOOK_SKILL_NOTE_CHARS})`,
        );
      }
      if (HARDCODED_EVIDENCE_OR_HOLDOUT_IN_PROPOSAL_RE.test(note)) {
        throw new ProposalValidationError(
          "hardcoded_case_artifact_in_skill_note",
          `skill_notes[${i}] contains forbidden case-specific citation/slug/holdout token`,
        );
      }
      validatedNotes.push(note);
    }

    return {
      track: "playbook",
      ...(typeof rawProposal.rationale === "string"
        ? { rationale: rawProposal.rationale.slice(0, 1000) }
        : {}),
      ...(typeof rawProposal.brief === "string" ? { brief: rawProposal.brief } : {}),
      stage_guidance: validatedGuidance,
      follow_ups: followUps,
      skill_notes: validatedNotes,
    };
  }

  // Track 2: `code_pr`
  if (typeof rawProposal.title !== "string" || rawProposal.title.trim().length === 0) {
    throw new ProposalValidationError(
      "invalid_code_pr_title",
      "Track 2 code_pr proposal requires a non-empty 'title'",
    );
  }
  if (typeof rawProposal.unified_diff !== "string") {
    throw new ProposalValidationError(
      "invalid_code_pr_diff",
      "Track 2 code_pr proposal requires a string 'unified_diff'",
    );
  }
  if (HARDCODED_EVIDENCE_OR_HOLDOUT_IN_PROPOSAL_RE.test(rawProposal.unified_diff)) {
    throw new ProposalValidationError(
      "hardcoded_case_artifact_in_diff",
      "Track 2 unified_diff contains forbidden case-specific citation/slug/holdout token",
    );
  }

  const diffFiles = extractUnifiedDiffPaths(rawProposal.unified_diff);

  let declaredFiles: AllowedCoachMutationFile[] = diffFiles;
  if (rawProposal.files !== undefined) {
    if (!Array.isArray(rawProposal.files) || rawProposal.files.length === 0) {
      throw new ProposalValidationError(
        "invalid_code_pr_files",
        "Track 2 'files' must be a non-empty array of allowlisted paths",
      );
    }
    const checked = rawProposal.files.map((f) => {
      if (typeof f !== "string") {
        throw new CoachAllowlistError(String(f), "non-string path");
      }
      return validateCoachMutationPath(f);
    });
    const declaredSet = new Set(checked);
    if (
      declaredSet.size !== diffFiles.length ||
      diffFiles.some((df) => !declaredSet.has(df))
    ) {
      throw new ProposalValidationError(
        "code_pr_files_diff_mismatch",
        `Declared files [${[...declaredSet].sort().join(", ")}] do not match unified_diff paths [${diffFiles.join(", ")}]`,
      );
    }
    declaredFiles = [...declaredSet].sort();
  }

  return {
    track: "code_pr",
    title: rawProposal.title.trim(),
    ...(typeof rawProposal.rationale === "string"
      ? { rationale: rawProposal.rationale.slice(0, 1000) }
      : {}),
    files: declaredFiles,
    unified_diff: rawProposal.unified_diff,
  };
}

function isSymlinkPath(abs: string): boolean {
  try {
    return fs.lstatSync(abs).isSymbolicLink();
  } catch {
    return false;
  }
}

const DRAFT_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,47}$/;

export interface StagedCodePrDraft {
  readonly draftId: string;
  readonly branchName: string;
  readonly worktreePath: string;
  readonly touchedFiles: readonly AllowedCoachMutationFile[];
  cleanup(): void;
}

export function stageCodePrDraft(options: {
  readonly repoRoot: string;
  readonly draftId: string;
  readonly proposal: CodePrProposal;
  readonly baseRef?: string;
  readonly holdoutReasons: readonly string[];
}): StagedCodePrDraft {
  requireHoldoutClearance("stage-pr", options.holdoutReasons);

  if (!DRAFT_ID_RE.test(options.draftId)) {
    throw new ProposalValidationError(
      "invalid_draft_id",
      `Invalid draftId '${options.draftId}'`,
    );
  }

  const validated = validateProposal(options.proposal) as CodePrProposal;
  const repoRoot = path.resolve(options.repoRoot);
  const worktreesRoot = path.join(repoRoot, ".worktrees");
  fs.mkdirSync(worktreesRoot, { recursive: true });

  const worktreePath = path.join(worktreesRoot, `coach-draft-${options.draftId}`);
  const branchName = `coach/draft-${options.draftId}`;
  const baseRef = options.baseRef ?? "HEAD";

  if (fs.existsSync(worktreePath)) {
    spawnSync("git", ["worktree", "remove", "--force", worktreePath], {
      cwd: repoRoot,
      encoding: "utf8",
      windowsHide: true,
    });
    if (fs.existsSync(worktreePath)) {
      fs.rmSync(worktreePath, { recursive: true, force: true });
    }
  }

  const addRes = spawnSync(
    "git",
    ["worktree", "add", "-B", branchName, worktreePath, baseRef],
    {
      cwd: repoRoot,
      encoding: "utf8",
      windowsHide: true,
    },
  );
  if (addRes.status !== 0) {
    throw new CleanRoomViolationError(
      "git_worktree_add_failed",
      `git worktree add failed: ${(addRes.stderr || addRes.stdout || "").trim()}`,
    );
  }

  const cleanup = (): void => {
    spawnSync("git", ["worktree", "remove", "--force", worktreePath], {
      cwd: repoRoot,
      encoding: "utf8",
      windowsHide: true,
    });
    spawnSync("git", ["branch", "-D", branchName], {
      cwd: repoRoot,
      encoding: "utf8",
      windowsHide: true,
    });
    if (fs.existsSync(worktreePath)) {
      fs.rmSync(worktreePath, { recursive: true, force: true });
    }
  };

  try {
    for (const relFile of validated.files) {
      const parentDir = path.dirname(path.join(worktreePath, relFile));
      fs.mkdirSync(parentDir, { recursive: true });
    }

    const normalizedPatch = validated.unified_diff.endsWith("\n")
      ? validated.unified_diff
      : `${validated.unified_diff}\n`;

    const applyRes = spawnSync("git", ["apply", "--whitespace=nowarn", "-"], {
      cwd: worktreePath,
      input: normalizedPatch,
      encoding: "utf8",
      windowsHide: true,
    });
    if (applyRes.status !== 0) {
      throw new ProposalValidationError(
        "git_apply_failed",
        `git apply failed in draft worktree: ${(applyRes.stderr || applyRes.stdout || "").trim()}`,
      );
    }

    const statusRes = spawnSync("git", ["status", "--porcelain", "-uall"], {
      cwd: worktreePath,
      encoding: "utf8",
      windowsHide: true,
    });
    if (statusRes.status !== 0) {
      throw new CleanRoomViolationError(
        "git_status_failed",
        `git status failed in draft worktree: ${(statusRes.stderr || statusRes.stdout || "").trim()}`,
      );
    }

    const observedPaths: AllowedCoachMutationFile[] = [];
    for (const rawLine of (statusRes.stdout ?? "").split(/\r?\n/)) {
      if (rawLine.trim().length === 0) {
        continue;
      }
      const pathPart = rawLine.slice(3).trim();
      const arrowParts = pathPart.includes(" -> ")
        ? pathPart.split(" -> ")
        : [pathPart];
      for (const p of arrowParts) {
        const unquoted =
          p.startsWith('"') && p.endsWith('"') ? p.slice(1, -1) : p;
        observedPaths.push(validateCoachMutationPath(unquoted));
      }
    }

    const uniqueObserved = [...new Set(observedPaths)].sort();
    for (const rel of uniqueObserved) {
      const abs = path.join(worktreePath, rel);
      if (!fs.existsSync(abs) && !isSymlinkPath(abs)) {
        continue; // deleted by the diff
      }
      if (!fs.lstatSync(abs).isFile()) {
        throw new ProposalValidationError(
          "non_regular_file_in_draft",
          `Track 2 draft produced a non-regular file (symlink/dir) at '${rel}'`,
        );
      }
    }
    if (uniqueObserved.length === 0) {
      throw new ProposalValidationError(
        "noop_code_pr_diff",
        "Track 2 unified_diff produced zero modified allowlisted files in draft worktree",
      );
    }

    return {
      draftId: options.draftId,
      branchName,
      worktreePath,
      touchedFiles: uniqueObserved,
      cleanup,
    };
  } catch (err) {
    cleanup();
    throw err;
  }
}

// ============================================================================
// 5. Trusted Host Judge, Clean-Room Proposer & 3-Stage Promotion Pipeline
// ============================================================================

export interface JudgeCaseInput {
  readonly caseId: string;
  readonly caseMeta?: Record<string, unknown> | null;
  readonly truth: ScenarioTruth;
  readonly report: Record<string, unknown>;
  readonly caseEvents: CaseEvents;
  readonly haltedSteps?: number;
  readonly rawReasons?: readonly string[];
}

export interface JudgeBatchResult {
  readonly evaluations: readonly CaseJudgeEvaluation[];
  readonly holdoutReasons: readonly string[];
  readonly summary: RoundEvalMetrics;
}

export interface RoundEvalMetrics {
  readonly round_index: number;
  readonly case_count: number;
  readonly mean_found: number;
  readonly mean_attack_found: number;
  readonly misattributed_decoys_total: number;
  readonly mean_citation_precision: number;
  readonly all_g2_1_pass: boolean;
}

export function summarizeCaseEvaluations(
  evaluations: readonly CaseJudgeEvaluation[],
  roundIndex = 0,
): RoundEvalMetrics {
  if (evaluations.length === 0) {
    throw new Error("summarizeCaseEvaluations requires >= 1 case evaluation");
  }
  let sumFound = 0;
  let sumAttack = 0;
  let totalDecoys = 0;
  let sumPrecision = 0;
  let allG2 = true;

  for (const ev of evaluations) {
    sumFound += ev.score.found;
    sumAttack += ev.score.by_kind.attack?.found ?? 0;
    totalDecoys += ev.score.misattributed_decoys.length;
    sumPrecision += ev.review.citation_support.citation_precision ?? 1.0;
    if (!ev.review.g2_1_pass) {
      allG2 = false;
    }
  }

  return {
    round_index: roundIndex,
    case_count: evaluations.length,
    mean_found: roundTo4(sumFound / evaluations.length),
    mean_attack_found: roundTo4(sumAttack / evaluations.length),
    misattributed_decoys_total: totalDecoys,
    mean_citation_precision: roundTo4(sumPrecision / evaluations.length),
    all_g2_1_pass: allG2,
  };
}

export function judgeCaseBatch(
  cases: readonly JudgeCaseInput[],
  options?: {
    readonly repoRoot?: string;
    readonly requireCleanGit?: boolean;
    readonly subcommand?: CoachSubcommand;
    readonly sealedEval?: boolean;
  },
): JudgeBatchResult {
  if (cases.length === 0) {
    throw new Error("judgeCaseBatch requires at least one case");
  }

  if (options?.requireCleanGit && options.repoRoot) {
    assertCleanGitTree(options.repoRoot);
  }

  const allReasons = new Set<string>();
  const perCaseReasons: string[][] = [];
  for (const c of cases) {
    validateTruth(c.truth);
    const reasons = detectHoldoutReasons({
      caseMeta: { ...(c.caseMeta ?? {}), case_id: c.caseId },
      truth: c.truth,
      eventsVocab: c.caseEvents.vocabulary,
    });
    perCaseReasons.push(reasons);
    for (const r of reasons) {
      allReasons.add(r);
    }
  }

  const holdoutReasons = [...allReasons].sort();
  enforceHoldoutPolicy(options?.subcommand ?? "judge", holdoutReasons, {
    sealedEval: options?.sealedEval,
  });

  const sealed = options?.sealedEval === true;
  const evaluations: CaseJudgeEvaluation[] = cases.map((c, idx) => {
    const score = scoreReport(c.truth, c.report);
    const review = checkReport(c.report, c.truth, c.caseEvents);
    return {
      score,
      review,
      haltedSteps: c.haltedSteps ?? 0,
      rawReasons: c.rawReasons ?? [],
      holdoutReasons: perCaseReasons[idx] ?? [],
      sealed,
    };
  });

  return {
    evaluations,
    holdoutReasons,
    summary: summarizeCaseEvaluations(evaluations, 0),
  };
}

export const CLEAN_ROOM_PROPOSER_SYSTEM_PROMPT = [
  "You are the Hunt Command Clean-Room Coach Proposer running with ZERO tools in an isolated empty directory.",
  "You receive ONLY scrubbed numeric/enum aggregate diagnostics across synthetic Story A training cases.",
  "Never ask for tools, files, shell commands, or case logs. Output ONLY a single valid JSON object matching either Track 1 ('playbook') or Track 2 ('code_pr').",
  `Track 1 ('playbook'): {"track":"playbook","stage_guidance":{...},"follow_ups":0..12,"skill_notes":[...]} (stage_guidance <= 600 UTF-8 bytes per stage; never include 'brief'; <= 5 skill_notes of <= 280 chars).`,
  `Track 2 ('code_pr'): {"track":"code_pr","title":"...","files":[...],"unified_diff":"..."} touching ONLY ALLOWED_COACH_MUTATION_FILES: ${ALLOWED_COACH_MUTATION_FILES.join(", ")}.`,
].join("\n");

export const CLEAN_ROOM_VERIFIER_SYSTEM_PROMPTS: Readonly<
  Record<Exclude<CleanRoomRole, "proposer">, string>
> = {
  "verifier-1": [
    "You are Clean-Room Verifier 1 (Bounds, Schema & Positive-Allowlist Auditor) running with ZERO tools.",
    "Inspect the scrubbed diagnostics packet, promotion round metrics, and candidate proposal.",
    "Reject if Track 1 exceeds bounds or mutates brief, or if Track 2 touches any file outside ALLOWED_COACH_MUTATION_FILES.",
    'Respond ONLY with JSON: {"approve": boolean, "reason_code": string}.',
  ].join("\n"),
  "verifier-2": [
    "You are Clean-Room Verifier 2 (Pass^2 Stability, Decoy Non-Blame & G2.1 Grounding Auditor) running with ZERO tools.",
    "Verify that probe and BOTH pass^2 rounds achieved >= +1.0 found gain over baseline, zero decoy regression, and 100% g2_1_pass.",
    'Respond ONLY with JSON: {"approve": boolean, "reason_code": string}.',
  ].join("\n"),
  "verifier-3": [
    "You are Clean-Room Verifier 3 (Anti-Overfitting & Holdout-Safety Auditor) running with ZERO tools.",
    "Reject any proposal that hardcodes case-specific IOCs, IPs, domains, event/frame IDs, fact slugs, or weakens verification.",
    'Respond ONLY with JSON: {"approve": boolean, "reason_code": string}.',
  ].join("\n"),
};

export type CleanRoomTurnRunner = (params: {
  readonly role: CleanRoomRole;
  readonly systemPrompt: string;
  readonly prompt: string;
  readonly modelPattern?: string;
}) => Promise<CleanRoomWorkerTurnResult>;

export async function proposeCleanRoom(options: {
  readonly packet: CleanDiagnosticsPacket;
  readonly holdoutReasons: readonly string[];
  readonly leakGuard: AssertCleanPacketOptions;
  readonly frozenBrief?: string;
  readonly trackPreference?: "playbook" | "code_pr";
  readonly modelPattern?: string;
  readonly repoRoot?: string;
  readonly turnRunner?: CleanRoomTurnRunner;
  readonly spawnOptions?: SpawnZeroToolCleanRoomOptions;
}): Promise<{
  readonly proposal: CoachProposal;
  readonly turnResult: CleanRoomWorkerTurnResult;
}> {
  requireHoldoutClearance("propose", options.holdoutReasons);
  assertPacketHoldoutProvenance("propose", options.packet);
  assertCleanPacket(options.packet, requireLeakGuard("propose", options.leakGuard));

  const userPrompt = JSON.stringify({
    requested_track: options.trackPreference ?? "playbook",
    allowed_code_pr_files: ALLOWED_COACH_MUTATION_FILES,
    diagnostics_packet: options.packet,
  });

  const runner: CleanRoomTurnRunner =
    options.turnRunner ??
    ((turnParams) =>
      spawnZeroToolCleanRoomTurn(turnParams, {
        ...options.spawnOptions,
        repoRoot: options.repoRoot ?? options.spawnOptions?.repoRoot,
      }));

  const turnResult = await runner({
    role: "proposer",
    systemPrompt: CLEAN_ROOM_PROPOSER_SYSTEM_PROMPT,
    prompt: userPrompt,
    modelPattern: options.modelPattern,
  });

  const parsed = loadJsonText(turnResult.text);
  const proposal = validateProposal(parsed, {
    frozenBrief: options.frozenBrief,
  });

  return { proposal, turnResult };
}

export interface VerifierPanelVerdict {
  readonly verifier_role: Exclude<CleanRoomRole, "proposer">;
  readonly approve: boolean;
  readonly reason_code: DiagnosticReasonCode;
  readonly model: string;
}

export interface VerifierPanelResult {
  readonly unanimous: boolean;
  readonly approvals: number;
  readonly verdicts: readonly VerifierPanelVerdict[];
}

const PROPOSAL_SUSPICIOUS_HARDCODED_RE =
  /(?:\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:example|test|invalid|local|internal|corp)\b|\b[0-9a-f]{32,64}\b)/i;

function deterministicSafetyAudit(params: {
  readonly proposal: CoachProposal;
  readonly baseline: RoundEvalMetrics;
  readonly probe: RoundEvalMetrics;
  readonly pass2: readonly [RoundEvalMetrics, RoundEvalMetrics];
  readonly minFoundGain: number;
  readonly frozenBrief?: string;
}): { ok: boolean; reasonCode: DiagnosticReasonCode } {
  try {
    validateProposal(params.proposal, { frozenBrief: params.frozenBrief });
  } catch (err) {
    if (err instanceof CoachAllowlistError) {
      return { ok: false, reasonCode: "ALLOWLIST_REJECTED" };
    }
    return { ok: false, reasonCode: "PROPOSAL_BOUNDS_EXCEEDED" };
  }

  const serializedProposal = JSON.stringify(params.proposal);
  if (PROPOSAL_SUSPICIOUS_HARDCODED_RE.test(serializedProposal)) {
    return { ok: false, reasonCode: "PANEL_REJECTED" };
  }

  const allRounds = [params.probe, params.pass2[0], params.pass2[1]];
  for (const r of allRounds) {
    if (!r.all_g2_1_pass) {
      return { ok: false, reasonCode: "G2_1_UNGROUNDED_ID" };
    }
    if (r.misattributed_decoys_total > params.baseline.misattributed_decoys_total) {
      return { ok: false, reasonCode: "DECOY_MISATTRIBUTED" };
    }
    if (r.mean_found + 1e-9 < params.baseline.mean_found + params.minFoundGain) {
      return { ok: false, reasonCode: "PASS2_BELOW_MARGIN" };
    }
  }

  return { ok: true, reasonCode: "NONE" };
}

export async function runCleanRoomThreeVerifierPanel(options: {
  readonly packet: CleanDiagnosticsPacket;
  readonly proposal: CoachProposal;
  readonly baseline: RoundEvalMetrics;
  readonly probe: RoundEvalMetrics;
  readonly pass2: readonly [RoundEvalMetrics, RoundEvalMetrics];
  readonly minFoundGain?: number;
  readonly frozenBrief?: string;
  readonly leakGuard: AssertCleanPacketOptions;
  readonly modelPattern?: string;
  readonly repoRoot?: string;
  readonly turnRunner?: CleanRoomTurnRunner;
  readonly spawnOptions?: SpawnZeroToolCleanRoomOptions;
}): Promise<VerifierPanelResult> {
  assertPacketHoldoutProvenance("promote", options.packet);
  assertCleanPacket(options.packet, requireLeakGuard("verifier-panel", options.leakGuard));
  const minFoundGain = options.minFoundGain ?? DEFAULT_MIN_FOUND_GAIN;

  const hardAudit = deterministicSafetyAudit({
    proposal: options.proposal,
    baseline: options.baseline,
    probe: options.probe,
    pass2: options.pass2,
    minFoundGain,
    frozenBrief: options.frozenBrief,
  });

  const runner: CleanRoomTurnRunner =
    options.turnRunner ??
    ((turnParams) =>
      spawnZeroToolCleanRoomTurn(turnParams, {
        ...options.spawnOptions,
        repoRoot: options.repoRoot ?? options.spawnOptions?.repoRoot,
      }));

  const verifierRoles: ReadonlyArray<Exclude<CleanRoomRole, "proposer">> = [
    "verifier-1",
    "verifier-2",
    "verifier-3",
  ];

  const panelPromptPayload = JSON.stringify({
    diagnostics_packet: options.packet,
    baseline: options.baseline,
    probe: options.probe,
    pass2: options.pass2,
    min_found_gain: minFoundGain,
    candidate_proposal: options.proposal,
  });

  const turns = await Promise.all(
    verifierRoles.map(async (role): Promise<VerifierPanelVerdict> => {
      const turnRes = await runner({
        role,
        systemPrompt: CLEAN_ROOM_VERIFIER_SYSTEM_PROMPTS[role],
        prompt: panelPromptPayload,
        modelPattern: options.modelPattern,
      });

      let parsedVerdict: unknown;
      try {
        parsedVerdict = loadJsonText(turnRes.text);
      } catch {
        return {
          verifier_role: role,
          approve: false,
          reason_code: "SCHEMA_INVALID",
          model: turnRes.model,
        };
      }

      if (!isPlainObject(parsedVerdict) || typeof parsedVerdict.approve !== "boolean") {
        return {
          verifier_role: role,
          approve: false,
          reason_code: "SCHEMA_INVALID",
          model: turnRes.model,
        };
      }

      const rawReason =
        typeof parsedVerdict.reason_code === "string"
          ? parsedVerdict.reason_code
          : typeof parsedVerdict.reason === "string"
            ? parsedVerdict.reason
            : undefined;

      // Deterministic safety audit overrides any LLM false-approve.
      const finalApprove = hardAudit.ok && parsedVerdict.approve === true;
      const reasonCode = !hardAudit.ok
        ? hardAudit.reasonCode
        : finalApprove
          ? "NONE"
          : classifyReasonCode(rawReason ?? "PANEL_REJECTED");

      return {
        verifier_role: role,
        approve: finalApprove,
        reason_code: reasonCode,
        model: turnRes.model,
      };
    }),
  );

  const approvals = turns.filter((v) => v.approve).length;
  return {
    unanimous: turns.length === 3 && approvals === 3,
    approvals,
    verdicts: turns,
  };
}

export type PromotionStopStage =
  | "validation"
  | "probe"
  | "pass2"
  | "panel"
  | "promoted";

export interface CoachEvalTelemetryRecord {
  readonly event_type: typeof COACH_EVAL_EVENT_TYPE;
  readonly schema_version: 1;
  readonly eval_id: string;
  readonly ts: string;
  readonly track: "playbook" | "code_pr";
  readonly promoted: boolean;
  readonly stopped_at_stage: PromotionStopStage;
  readonly reason_code: DiagnosticReasonCode;
  readonly baseline: {
    readonly mean_found: number;
    readonly misattributed_decoys: number;
    readonly all_g2_1_pass: boolean;
  };
  readonly probe?: RoundEvalMetrics;
  readonly pass2?: readonly [RoundEvalMetrics, RoundEvalMetrics];
  readonly verifier_panel?: VerifierPanelResult;
}

export interface CoachLedgerEntry {
  readonly eval_id: string;
  readonly ts: string;
  readonly track: "playbook" | "code_pr";
  readonly outcome: RevertOutcomeCode;
  readonly stopped_at_stage: PromotionStopStage;
  readonly reason_code: DiagnosticReasonCode;
  readonly baseline_mean_found: number;
  readonly probe_mean_found: number | null;
  readonly probe_delta_found: number;
  readonly pass2_mean_founds: readonly [number, number] | null;
  readonly verifier_approvals: number | null;
}

export interface CoachLedgerFile {
  readonly schema_version: 1;
  readonly entries: readonly CoachLedgerEntry[];
}

export function readCoachLedger(ledgerPath: string): CoachLedgerFile {
  if (!fs.existsSync(ledgerPath)) {
    return { schema_version: 1, entries: [] };
  }
  const parsed = loadJsonText(fs.readFileSync(ledgerPath, "utf8"));
  if (!isPlainObject(parsed) || !Array.isArray(parsed.entries)) {
    throw new Error(`Invalid coach ledger file at '${ledgerPath}'`);
  }
  return parsed as unknown as CoachLedgerFile;
}

function appendCoachLedgerEntry(ledgerPath: string, entry: CoachLedgerEntry): void {
  const existing = readCoachLedger(ledgerPath);
  const updated: CoachLedgerFile = {
    schema_version: 1,
    entries: [...existing.entries, entry],
  };
  fs.mkdirSync(path.dirname(ledgerPath), { recursive: true });
  fs.writeFileSync(ledgerPath, `${JSON.stringify(updated, null, 2)}\n`, "utf8");
}

function appendTelemetryJsonl(
  jsonlPath: string,
  record: CoachEvalTelemetryRecord,
): void {
  fs.mkdirSync(path.dirname(jsonlPath), { recursive: true });
  fs.appendFileSync(jsonlPath, `${JSON.stringify(record)}\n`, "utf8");
}

function checkRoundGate(
  round: RoundEvalMetrics,
  baseline: RoundEvalMetrics,
  minFoundGain: number,
): { pass: boolean; reasonCode: DiagnosticReasonCode } {
  if (!round.all_g2_1_pass) {
    return { pass: false, reasonCode: "G2_1_UNGROUNDED_ID" };
  }
  if (round.misattributed_decoys_total > baseline.misattributed_decoys_total) {
    return { pass: false, reasonCode: "DECOY_MISATTRIBUTED" };
  }
  if (round.mean_found + 1e-9 < baseline.mean_found + minFoundGain) {
    return { pass: false, reasonCode: "PASS2_BELOW_MARGIN" };
  }
  return { pass: true, reasonCode: "NONE" };
}

export interface RunPromotionPipelineOptions {
  readonly evalId?: string;
  readonly packet: CleanDiagnosticsPacket;
  readonly rawProposal: unknown;
  readonly baseline: RoundEvalMetrics;
  readonly minFoundGain?: number;
  readonly frozenBrief?: string;
  readonly holdoutReasons: readonly string[];
  readonly leakGuard: AssertCleanPacketOptions;
  readonly repoRoot?: string;
  readonly requireCleanGit?: boolean;
  readonly evaluateRound: (params: {
    readonly stage: "probe" | "pass2";
    readonly roundIndex: number;
    readonly proposal: CoachProposal;
  }) => Promise<RoundEvalMetrics>;
  readonly verifierTurnRunner?: CleanRoomTurnRunner;
  readonly spawnOptions?: SpawnZeroToolCleanRoomOptions;
  readonly modelPattern?: string;
  readonly ledgerPath?: string;
  readonly telemetryJsonlPath?: string;
  readonly onTelemetry?: (
    record: CoachEvalTelemetryRecord,
  ) => void | Promise<void>;
}

export interface PromotionPipelineResult {
  readonly promoted: boolean;
  readonly stopped_at_stage: PromotionStopStage;
  readonly reason_code: DiagnosticReasonCode;
  readonly proposal?: CoachProposal;
  readonly probe?: RoundEvalMetrics;
  readonly pass2?: readonly [RoundEvalMetrics, RoundEvalMetrics];
  readonly verifier_panel?: VerifierPanelResult;
  readonly telemetry: CoachEvalTelemetryRecord;
}

/**
 * Executes the 3-stage Clean-Room Coach promotion gate:
 *   1. `1-round probe` (`found >= baseline + 1.0`, `decoys <= baseline`, `all_g2_1_pass === true`)
 *   2. `2-round pass^2` (`found >= baseline + 1.0` on BOTH rounds, `decoys <= baseline`, `all_g2_1_pass === true`)
 *   3. Unanimous `3-verifier` zero-tool clean-room panel (`3/3` approvals)
 * Persists `ledger.json` and emits `hunt.coach.eval` telemetry on every outcome.
 */
export async function runPromotionPipeline(
  options: RunPromotionPipelineOptions,
): Promise<PromotionPipelineResult> {
  requireHoldoutClearance("promote", options.holdoutReasons);
  if (options.requireCleanGit && options.repoRoot) {
    assertCleanGitTree(options.repoRoot);
  }
  assertPacketHoldoutProvenance("promote", options.packet);
  assertCleanPacket(options.packet, requireLeakGuard("promote", options.leakGuard));

  const evalId = options.evalId ?? `coach-eval-${crypto.randomUUID()}`;
  const ts = new Date().toISOString();
  const minFoundGain = options.minFoundGain ?? DEFAULT_MIN_FOUND_GAIN;

  const finalize = async (params: {
    track: "playbook" | "code_pr";
    promoted: boolean;
    stoppedAt: PromotionStopStage;
    outcome: RevertOutcomeCode;
    reasonCode: DiagnosticReasonCode;
    proposal?: CoachProposal;
    probe?: RoundEvalMetrics;
    pass2?: readonly [RoundEvalMetrics, RoundEvalMetrics];
    panel?: VerifierPanelResult;
  }): Promise<PromotionPipelineResult> => {
    const telemetry: CoachEvalTelemetryRecord = {
      event_type: COACH_EVAL_EVENT_TYPE,
      schema_version: 1,
      eval_id: evalId,
      ts,
      track: params.track,
      promoted: params.promoted,
      stopped_at_stage: params.stoppedAt,
      reason_code: params.reasonCode,
      baseline: {
        mean_found: options.baseline.mean_found,
        misattributed_decoys: options.baseline.misattributed_decoys_total,
        all_g2_1_pass: options.baseline.all_g2_1_pass,
      },
      ...(params.probe ? { probe: params.probe } : {}),
      ...(params.pass2 ? { pass2: params.pass2 } : {}),
      ...(params.panel ? { verifier_panel: params.panel } : {}),
    };

    if (options.ledgerPath) {
      appendCoachLedgerEntry(options.ledgerPath, {
        eval_id: evalId,
        ts,
        track: params.track,
        outcome: params.outcome,
        stopped_at_stage: params.stoppedAt,
        reason_code: params.reasonCode,
        baseline_mean_found: options.baseline.mean_found,
        probe_mean_found: params.probe ? params.probe.mean_found : null,
        probe_delta_found: params.probe
          ? roundTo4(params.probe.mean_found - options.baseline.mean_found)
          : 0,
        pass2_mean_founds: params.pass2
          ? [params.pass2[0].mean_found, params.pass2[1].mean_found]
          : null,
        verifier_approvals: params.panel ? params.panel.approvals : null,
      });
    }

    if (options.telemetryJsonlPath) {
      appendTelemetryJsonl(options.telemetryJsonlPath, telemetry);
    }
    if (options.onTelemetry) {
      await options.onTelemetry(telemetry);
    }

    return {
      promoted: params.promoted,
      stopped_at_stage: params.stoppedAt,
      reason_code: params.reasonCode,
      ...(params.proposal ? { proposal: params.proposal } : {}),
      ...(params.probe ? { probe: params.probe } : {}),
      ...(params.pass2 ? { pass2: params.pass2 } : {}),
      ...(params.panel ? { verifier_panel: params.panel } : {}),
      telemetry,
    };
  };

  const guessedTrack: "playbook" | "code_pr" =
    isPlainObject(options.rawProposal) && options.rawProposal.track === "code_pr"
      ? "code_pr"
      : "playbook";

  let proposal: CoachProposal;
  try {
    proposal = validateProposal(options.rawProposal, {
      frozenBrief: options.frozenBrief,
    });
  } catch (err) {
    const reasonCode: DiagnosticReasonCode =
      err instanceof CoachAllowlistError
        ? "ALLOWLIST_REJECTED"
        : "PROPOSAL_BOUNDS_EXCEEDED";
    return finalize({
      track: guessedTrack,
      promoted: false,
      stoppedAt: "validation",
      outcome: "rejected_validation",
      reasonCode,
    });
  }

  // Stage 1: 1-round probe
  const probeMetrics = await options.evaluateRound({
    stage: "probe",
    roundIndex: 0,
    proposal,
  });
  const probeCheck = checkRoundGate(probeMetrics, options.baseline, minFoundGain);
  if (!probeCheck.pass) {
    return finalize({
      track: proposal.track,
      promoted: false,
      stoppedAt: "probe",
      outcome: "reverted_probe",
      reasonCode: probeCheck.reasonCode,
      proposal,
      probe: probeMetrics,
    });
  }

  // Stage 2: 2-round pass^2 (BOTH rounds must clear baseline + minFoundGain, decoy ceiling, and g2_1_pass)
  const pass2Round1 = await options.evaluateRound({
    stage: "pass2",
    roundIndex: 1,
    proposal,
  });
  const pass2Round2 = await options.evaluateRound({
    stage: "pass2",
    roundIndex: 2,
    proposal,
  });
  const pass2Tuple: readonly [RoundEvalMetrics, RoundEvalMetrics] = [
    pass2Round1,
    pass2Round2,
  ];

  const r1Check = checkRoundGate(pass2Round1, options.baseline, minFoundGain);
  if (!r1Check.pass) {
    return finalize({
      track: proposal.track,
      promoted: false,
      stoppedAt: "pass2",
      outcome: "reverted_pass2",
      reasonCode: r1Check.reasonCode,
      proposal,
      probe: probeMetrics,
      pass2: pass2Tuple,
    });
  }
  const r2Check = checkRoundGate(pass2Round2, options.baseline, minFoundGain);
  if (!r2Check.pass) {
    return finalize({
      track: proposal.track,
      promoted: false,
      stoppedAt: "pass2",
      outcome: "reverted_pass2",
      reasonCode: r2Check.reasonCode,
      proposal,
      probe: probeMetrics,
      pass2: pass2Tuple,
    });
  }

  // Stage 3: Unanimous 3-verifier clean-room panel
  const panelResult = await runCleanRoomThreeVerifierPanel({
    packet: options.packet,
    proposal,
    baseline: options.baseline,
    probe: probeMetrics,
    pass2: pass2Tuple,
    minFoundGain,
    frozenBrief: options.frozenBrief,
    leakGuard: options.leakGuard,
    modelPattern: options.modelPattern,
    repoRoot: options.repoRoot,
    turnRunner: options.verifierTurnRunner,
    spawnOptions: options.spawnOptions,
  });

  if (!panelResult.unanimous) {
    const firstRejectReason =
      panelResult.verdicts.find((v) => !v.approve)?.reason_code ?? "PANEL_REJECTED";
    return finalize({
      track: proposal.track,
      promoted: false,
      stoppedAt: "panel",
      outcome: "reverted_panel",
      reasonCode:
        firstRejectReason === "NONE" ? "PANEL_REJECTED" : firstRejectReason,
      proposal,
      probe: probeMetrics,
      pass2: pass2Tuple,
      panel: panelResult,
    });
  }

  return finalize({
    track: proposal.track,
    promoted: true,
    stoppedAt: "promoted",
    outcome: "promoted",
    reasonCode: "NONE",
    proposal,
    probe: probeMetrics,
    pass2: pass2Tuple,
    panel: panelResult,
  });
}
