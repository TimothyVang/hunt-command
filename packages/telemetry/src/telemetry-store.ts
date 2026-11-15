import { Database } from "bun:sqlite";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
  type Claim,
  type ClaimKind,
  computeCostAccounting,
  type DataOrigin,
  extractInlineCitations,
  findEnclosingGitMarker,
  type HuntWave,
  MODEL_PRICE_TABLE,
  normalizeModelPricingId,
  PROFILE_DISPLAY_TITLES,
  type ProfileId,
  resolveRuntimeDir,
  RuntimeFenceError,
} from "@hunt-command/shared";
import { ContentAddressedZstdBlobStore } from "./blob-store.ts";
import {
  type ExportOtlpLoopbackOptions,
  type ExportOtlpResult,
  exportOtlpLoopback,
} from "./otlp-exporter.ts";
import { scrubQueryPreview, scrubSecrets, scrubSecretsValue } from "./scrubber.ts";

export const HUNT_SPAN_NAMES = [
  "hunt.run",
  "hunt.wave",
  "hunt.bot.step",
  "gen_ai.chat",
  "gen_ai.execute_tool",
  "hunt.handoff.validate",
  "hunt.gate.decision",
  "hunt.coach.eval",
] as const;

export type HuntSpanName = (typeof HUNT_SPAN_NAMES)[number];

export type OpenInferenceSpanKind =
  | "CHAIN"
  | "AGENT"
  | "LLM"
  | "TOOL"
  | "GUARDRAIL"
  | "EVALUATOR";

export type TelemetryBillingMode = "oauth_subscription" | "api_key" | "local";

export type EvidenceCitationType = "event" | "frame" | "ioc";

export interface TelemetrySpanRecord {
  spanId: string;
  traceId: string;
  parentSpanId: string | null;
  huntId: string;
  name: HuntSpanName;
  openInferenceKind: OpenInferenceSpanKind;
  wave: HuntWave | null;
  stepId: string | null;
  botProfile: ProfileId | null;
  startTimeMs: number;
  endTimeMs: number;
  durationMs: number;
  status: "ok" | "error";
  errorCode: string | null;
  attributes: Record<string, unknown>;
  messageHashes: string[];
  blobHash: string | null;
}

export interface ClaimLineageRow {
  huntId: string;
  stepId: string;
  botProfile: ProfileId;
  claimId: string;
  claimKind: ClaimKind;
  evidenceType: EvidenceCitationType;
  evidenceId: string;
}

export interface RunWaterfallEntry {
  spanId: string;
  parentSpanId: string | null;
  traceId: string;
  name: HuntSpanName;
  openInferenceKind: OpenInferenceSpanKind;
  wave: HuntWave | null;
  stepId: string | null;
  botProfile: ProfileId | null;
  startTimeMs: number;
  endTimeMs: number;
  durationMs: number;
  offsetFromRunStartMs: number;
  depth: number;
  status: "ok" | "error";
  errorCode: string | null;
  safetyDeclined: boolean;
  safetyFinishReason: string | null;
  safetyCategory: string | null;
  attributes: Record<string, unknown>;
  messageHashes: string[];
  blobHash: string | null;
}

export interface RunWaterfall {
  huntId: string;
  traceId: string;
  caseId: string;
  dataOrigin: DataOrigin;
  syntheticOnly: boolean;
  mode: string;
  startedAtMs: number;
  endedAtMs: number | null;
  totalDurationMs: number;
  completed: boolean;
  haltedAt: string | null;
  spans: RunWaterfallEntry[];
}

export interface TokenCostBucket {
  inputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
  outputTokens: number;
  totalPromptTokens: number;
  totalTokens: number;
  cacheHitRatio: number;
  actualUsd: number;
  apiEquivalentUsd: number;
  cacheSavingsUsd: number;
  chatSpanCount: number;
}

export interface RunCostSummary extends TokenCostBucket {
  huntId: string;
  cyberRefusalCount: number;
  byModel: Record<string, TokenCostBucket>;
  byProfile: Record<string, TokenCostBucket>;
  byWave: Record<string, TokenCostBucket>;
}

export interface CoachTrendPoint {
  evalId: string;
  spanId: string;
  huntId: string | null;
  iteration: number;
  track: "playbook" | "code_pr";
  stage: "judge" | "probe" | "pass2";
  meanFound: number;
  attackFound: number;
  misattributedDecoys: number;
  citationPrecision: number;
  g2_1Pass: boolean;
  promoted: boolean;
  recordedAtMs: number;
  totalTokens: number | null;
  actualUsd: number | null;
  apiEquivalentUsd: number | null;
}

export interface WalCheckpointStats {
  busy: number;
  log: number;
  checkpointed: number;
}

export interface TelemetryStoreOptions {
  dbPath?: string;
  blobsDir?: string;
  runtimeDir?: string;
}

function makeTraceId(huntId: string): string {
  const h = new Bun.CryptoHasher("sha256");
  h.update(`hunt-trace:${huntId}`);
  return h.digest("hex").slice(0, 32);
}

function makeSpanId(): string {
  return crypto.randomBytes(8).toString("hex");
}

function round8(n: number): number {
  return Math.round(n * 1e8) / 1e8;
}

function round6(n: number): number {
  return Math.round(n * 1e6) / 1e6;
}

function normalizeFrameId(raw: string): string {
  const m = /^frame-(\d+)$/i.exec(raw);
  if (!m) return raw;
  return `frame-${Number.parseInt(m[1]!, 10)}`;
}

function emptyBucket(): TokenCostBucket {
  return {
    inputTokens: 0,
    cacheReadTokens: 0,
    cacheWriteTokens: 0,
    outputTokens: 0,
    totalPromptTokens: 0,
    totalTokens: 0,
    cacheHitRatio: 0,
    actualUsd: 0,
    apiEquivalentUsd: 0,
    cacheSavingsUsd: 0,
    chatSpanCount: 0,
  };
}

function addIntoBucket(
  bucket: TokenCostBucket,
  row: {
    input: number;
    cacheRead: number;
    cacheWrite: number;
    output: number;
    actualUsd: number;
    apiUsd: number;
    cacheSavingsUsd: number;
  },
): void {
  bucket.inputTokens += row.input;
  bucket.cacheReadTokens += row.cacheRead;
  bucket.cacheWriteTokens += row.cacheWrite;
  bucket.outputTokens += row.output;
  bucket.totalPromptTokens =
    bucket.inputTokens + bucket.cacheReadTokens + bucket.cacheWriteTokens;
  bucket.totalTokens = bucket.totalPromptTokens + bucket.outputTokens;
  bucket.cacheHitRatio =
    bucket.totalPromptTokens > 0
      ? round6(bucket.cacheReadTokens / bucket.totalPromptTokens)
      : 0;
  bucket.actualUsd = round8(bucket.actualUsd + row.actualUsd);
  bucket.apiEquivalentUsd = round8(bucket.apiEquivalentUsd + row.apiUsd);
  bucket.cacheSavingsUsd = round8(bucket.cacheSavingsUsd + row.cacheSavingsUsd);
  bucket.chatSpanCount += 1;
}

/**
 * Self-owned Hot Indexed SQLite (`hunt_telemetry.sqlite` WAL) + Cold Content-Addressed Zstd Store.
 */
export class HuntTelemetryStore {
  public readonly dbPath: string;
  public readonly blobStore: ContentAddressedZstdBlobStore;
  private readonly db: Database;

  constructor(options: TelemetryStoreOptions = {}) {
    let resolvedDbPath: string;
    let resolvedBlobsDir: string;

    if (options.dbPath && options.blobsDir) {
      resolvedDbPath = options.dbPath === ":memory:" ? ":memory:" : path.resolve(options.dbPath);
      resolvedBlobsDir = path.resolve(options.blobsDir);
    } else if (options.runtimeDir) {
      const rt = resolveRuntimeDir(options.runtimeDir);
      resolvedDbPath = options.dbPath
        ? options.dbPath === ":memory:"
          ? ":memory:"
          : path.resolve(options.dbPath)
        : rt.telemetryDbPath;
      resolvedBlobsDir = options.blobsDir ? path.resolve(options.blobsDir) : rt.blobsDir;
    } else {
      const rt = resolveRuntimeDir();
      resolvedDbPath = options.dbPath
        ? options.dbPath === ":memory:"
          ? ":memory:"
          : path.resolve(options.dbPath)
        : rt.telemetryDbPath;
      resolvedBlobsDir = options.blobsDir ? path.resolve(options.blobsDir) : rt.blobsDir;
    }

    if (resolvedDbPath !== ":memory:") {
      const gitMarker = findEnclosingGitMarker(resolvedDbPath);
      if (gitMarker !== null) {
        throw new RuntimeFenceError(resolvedDbPath, gitMarker);
      }
      fs.mkdirSync(path.dirname(resolvedDbPath), { recursive: true });
    }

    this.dbPath = resolvedDbPath;
    this.blobStore = new ContentAddressedZstdBlobStore(resolvedBlobsDir);
    this.db = new Database(resolvedDbPath);

    this.db.exec("PRAGMA busy_timeout = 5000;");
    this.db.exec("PRAGMA journal_mode = WAL;");
    this.db.exec("PRAGMA synchronous = NORMAL;");
    this.db.exec("PRAGMA journal_size_limit = 67108864;");
    this.db.exec("PRAGMA foreign_keys = ON;");

    this.initSchema();
  }

  private initSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS hunt_runs (
        hunt_id TEXT PRIMARY KEY,
        trace_id TEXT NOT NULL,
        case_id TEXT NOT NULL,
        data_origin TEXT NOT NULL,
        synthetic_only INTEGER NOT NULL,
        mode TEXT NOT NULL,
        started_at_ms REAL NOT NULL,
        ended_at_ms REAL,
        completed INTEGER NOT NULL DEFAULT 0,
        halted_at TEXT
      );

      CREATE TABLE IF NOT EXISTS spans (
        span_id TEXT PRIMARY KEY,
        trace_id TEXT NOT NULL,
        parent_span_id TEXT,
        hunt_id TEXT NOT NULL,
        name TEXT NOT NULL,
        openinference_kind TEXT NOT NULL,
        wave TEXT,
        step_id TEXT,
        bot_profile TEXT,
        start_time_ms REAL NOT NULL,
        end_time_ms REAL NOT NULL,
        duration_ms REAL NOT NULL,
        status TEXT NOT NULL,
        error_code TEXT,
        input_tokens INTEGER,
        cache_read_tokens INTEGER,
        cache_write_tokens INTEGER,
        output_tokens INTEGER,
        cache_hit_ratio REAL,
        billing_mode TEXT,
        actual_usd REAL,
        api_equivalent_usd REAL,
        cache_savings_usd REAL,
        model TEXT,
        tool_name TEXT,
        query_preview TEXT,
        result_count INTEGER,
        total_hits INTEGER,
        blocked_requests INTEGER,
        safety_declined INTEGER,
        safety_finish_reason TEXT,
        safety_category TEXT,
        attributes_json TEXT NOT NULL,
        message_hashes_json TEXT NOT NULL,
        blob_hash TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_spans_hunt_start
        ON spans(hunt_id, start_time_ms, span_id);
      CREATE INDEX IF NOT EXISTS idx_spans_trace
        ON spans(trace_id);
      CREATE INDEX IF NOT EXISTS idx_spans_parent
        ON spans(parent_span_id);
      CREATE INDEX IF NOT EXISTS idx_spans_name_start
        ON spans(name, start_time_ms);

      CREATE TABLE IF NOT EXISTS claim_evidence_lineage (
        hunt_id TEXT NOT NULL,
        step_id TEXT NOT NULL,
        bot_profile TEXT NOT NULL,
        claim_id TEXT NOT NULL,
        claim_kind TEXT NOT NULL,
        evidence_type TEXT NOT NULL,
        evidence_id TEXT NOT NULL,
        PRIMARY KEY (hunt_id, claim_id, evidence_type, evidence_id)
      );

      CREATE INDEX IF NOT EXISTS idx_lineage_hunt_evidence
        ON claim_evidence_lineage(hunt_id, evidence_id);
      CREATE INDEX IF NOT EXISTS idx_lineage_hunt_claim
        ON claim_evidence_lineage(hunt_id, claim_id);
      CREATE INDEX IF NOT EXISTS idx_lineage_evidence_global
        ON claim_evidence_lineage(evidence_id);

      CREATE TABLE IF NOT EXISTS coach_evals (
        eval_id TEXT PRIMARY KEY,
        span_id TEXT NOT NULL,
        hunt_id TEXT,
        iteration INTEGER NOT NULL,
        track TEXT NOT NULL,
        stage TEXT NOT NULL,
        mean_found REAL NOT NULL,
        attack_found REAL NOT NULL,
        misattributed_decoys REAL NOT NULL,
        citation_precision REAL NOT NULL,
        g2_1_pass INTEGER NOT NULL,
        promoted INTEGER NOT NULL,
        recorded_at_ms REAL NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_coach_evals_track_iter
        ON coach_evals(track, stage, iteration, recorded_at_ms);
    `);
  }

  public getJournalPragmas(): {
    journalMode: string;
    synchronous: number;
    journalSizeLimit: number;
  } {
    const jm = this.db.query("PRAGMA journal_mode;").get() as { journal_mode: string };
    const sync = this.db.query("PRAGMA synchronous;").get() as { synchronous: number };
    const jsl = this.db.query("PRAGMA journal_size_limit;").get() as {
      journal_size_limit: number;
    };
    return {
      journalMode: jm.journal_mode,
      synchronous: sync.synchronous,
      journalSizeLimit: jsl.journal_size_limit,
    };
  }

  public checkpointWal(): WalCheckpointStats {
    const row = this.db
      .query("PRAGMA wal_checkpoint(TRUNCATE);")
      .get() as { busy: number; log: number; checkpointed: number } | null;
    return {
      busy: row?.busy ?? 0,
      log: row?.log ?? 0,
      checkpointed: row?.checkpointed ?? 0,
    };
  }

  public recordRunSpan(params: {
    huntId: string;
    spanId?: string;
    traceId?: string;
    caseId: string;
    dataOrigin: DataOrigin;
    mode?: string;
    startTimeMs: number;
    endTimeMs?: number;
    completed?: boolean;
    haltedAt?: string | null;
  }): TelemetrySpanRecord {
    const syntheticOnly = params.dataOrigin === "synthetic";
    const traceId = params.traceId ?? makeTraceId(params.huntId);
    const spanId = params.spanId ?? makeSpanId();
    const mode = params.mode ?? "headless";
    const endTimeMs = params.endTimeMs ?? params.startTimeMs;
    const completed = params.completed ?? false;
    const haltedAt = params.haltedAt ?? null;

    const existing = this.db
      .query("SELECT data_origin, synthetic_only FROM hunt_runs WHERE hunt_id = ?")
      .get(params.huntId) as { data_origin: string; synthetic_only: number } | null;

    if (existing) {
      if (
        existing.data_origin !== params.dataOrigin ||
        Boolean(existing.synthetic_only) !== syntheticOnly
      ) {
        throw new Error(
          `Immutable data_origin violation on hunt '${params.huntId}': cannot change '${existing.data_origin}' to '${params.dataOrigin}'`,
        );
      }
      this.db
        .query(
          `UPDATE hunt_runs
           SET ended_at_ms = ?, completed = ?, halted_at = ?
           WHERE hunt_id = ?`,
        )
        .run(endTimeMs, completed ? 1 : 0, haltedAt, params.huntId);
    } else {
      this.db
        .query(
          `INSERT INTO hunt_runs (
            hunt_id, trace_id, case_id, data_origin, synthetic_only,
            mode, started_at_ms, ended_at_ms, completed, halted_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          params.huntId,
          traceId,
          params.caseId,
          params.dataOrigin,
          syntheticOnly ? 1 : 0,
          mode,
          params.startTimeMs,
          params.endTimeMs ?? null,
          completed ? 1 : 0,
          haltedAt,
        );
    }

    const attributes = scrubSecretsValue({
      "openinference.span.kind": "CHAIN",
      "hunt.id": params.huntId,
      "hunt.case_id": params.caseId,
      "hunt.data_origin": params.dataOrigin,
      "hunt.synthetic_only": syntheticOnly,
      "hunt.mode": mode,
      "hunt.completed": completed,
      "hunt.halted_at": haltedAt,
    });

    return this.insertSpanRow({
      spanId,
      traceId,
      parentSpanId: null,
      huntId: params.huntId,
      name: "hunt.run",
      openInferenceKind: "CHAIN",
      wave: null,
      stepId: null,
      botProfile: null,
      startTimeMs: params.startTimeMs,
      endTimeMs,
      status: haltedAt ? "error" : "ok",
      errorCode: haltedAt,
      attributes,
      messageHashes: [],
      blobHash: null,
    });
  }

  public recordWaveSpan(params: {
    huntId: string;
    parentSpanId: string;
    spanId?: string;
    traceId?: string;
    wave: HuntWave;
    waveIndex: number;
    parallel: boolean;
    stepIds: readonly string[];
    startTimeMs: number;
    endTimeMs: number;
    status?: "ok" | "error";
    errorCode?: string | null;
  }): TelemetrySpanRecord {
    const durationMs = Math.max(0, params.endTimeMs - params.startTimeMs);
    const attributes = scrubSecretsValue({
      "openinference.span.kind": "CHAIN",
      "hunt.id": params.huntId,
      "hunt.wave": params.wave,
      "hunt.wave.index": params.waveIndex,
      "hunt.wave.parallel": params.parallel,
      "hunt.wave.step_ids": [...params.stepIds],
      duration_ms: durationMs,
    });

    return this.insertSpanRow({
      spanId: params.spanId ?? makeSpanId(),
      traceId: params.traceId ?? this.lookupTraceId(params.huntId),
      parentSpanId: params.parentSpanId,
      huntId: params.huntId,
      name: "hunt.wave",
      openInferenceKind: "CHAIN",
      wave: params.wave,
      stepId: null,
      botProfile: null,
      startTimeMs: params.startTimeMs,
      endTimeMs: params.endTimeMs,
      status: params.status ?? "ok",
      errorCode: params.errorCode ?? null,
      attributes,
      messageHashes: [],
      blobHash: null,
    });
  }

  public recordBotStepSpan(params: {
    huntId: string;
    parentSpanId: string;
    spanId?: string;
    traceId?: string;
    wave: HuntWave;
    stepId: string;
    botProfile: ProfileId;
    attempt?: number;
    stepStatus: string;
    reasonCode?: string | null;
    safetyDeclined?: boolean;
    safetyFinishReason?: string | null;
    safetyCategory?: string | null;
    startTimeMs: number;
    endTimeMs: number;
  }): TelemetrySpanRecord {
    const safetyDeclined = params.safetyDeclined ?? false;
    const safetyFinishReason = params.safetyFinishReason ?? null;
    const safetyCategory =
      params.safetyCategory ?? (safetyDeclined ? "cyber" : null);
    const roleTitle = PROFILE_DISPLAY_TITLES[params.botProfile];
    const durationMs = Math.max(0, params.endTimeMs - params.startTimeMs);

    const attributes = scrubSecretsValue({
      "openinference.span.kind": "AGENT",
      "gen_ai.agent.name": params.botProfile,
      "hunt.bot.role_title": roleTitle,
      "hunt.step_id": params.stepId,
      "hunt.attempt": params.attempt ?? 1,
      "hunt.status": params.stepStatus,
      "hunt.reason_code": params.reasonCode ?? null,
      "hunt.safety.declined": safetyDeclined,
      "hunt.safety.finish_reason": safetyFinishReason,
      "hunt.safety.category": safetyCategory,
      duration_ms: durationMs,
    });

    return this.insertSpanRow({
      spanId: params.spanId ?? makeSpanId(),
      traceId: params.traceId ?? this.lookupTraceId(params.huntId),
      parentSpanId: params.parentSpanId,
      huntId: params.huntId,
      name: "hunt.bot.step",
      openInferenceKind: "AGENT",
      wave: params.wave,
      stepId: params.stepId,
      botProfile: params.botProfile,
      startTimeMs: params.startTimeMs,
      endTimeMs: params.endTimeMs,
      status:
        safetyDeclined || params.stepStatus === "failed" || params.stepStatus === "dropped"
          ? "error"
          : "ok",
      errorCode: params.reasonCode ?? (safetyDeclined ? "cyber_refusal" : null),
      safetyDeclined,
      safetyFinishReason,
      safetyCategory,
      attributes,
      messageHashes: [],
      blobHash: null,
    });
  }

  public recordChatSpan(params: {
    huntId: string;
    parentSpanId: string;
    spanId?: string;
    traceId?: string;
    wave?: HuntWave | null;
    stepId?: string | null;
    botProfile?: ProfileId | null;
    providerName: string;
    model: string;
    inputTokens: number;
    cacheReadTokens?: number;
    cacheWriteTokens?: number;
    outputTokens: number;
    billingMode?: TelemetryBillingMode;
    actualUsd?: number;
    apiEquivalentUsd?: number;
    finishReasons?: readonly string[];
    messages?: readonly unknown[];
    startTimeMs: number;
    endTimeMs: number;
    status?: "ok" | "error";
    errorCode?: string | null;
  }): TelemetrySpanRecord {
    const input = Math.max(0, Math.trunc(params.inputTokens));
    const cacheRead = Math.max(0, Math.trunc(params.cacheReadTokens ?? 0));
    const cacheWrite = Math.max(0, Math.trunc(params.cacheWriteTokens ?? 0));
    const output = Math.max(0, Math.trunc(params.outputTokens));
    const totalPrompt = input + cacheRead + cacheWrite;
    const hitRatio = totalPrompt > 0 ? round6(cacheRead / totalPrompt) : 0;
    const billingMode: TelemetryBillingMode = params.billingMode ?? "oauth_subscription";

    let actualUsd = params.actualUsd;
    let apiEquivalentUsd = params.apiEquivalentUsd;
    let cacheSavingsUsd = 0;

    const normalizedModel = normalizeModelPricingId(params.model);
    if (normalizedModel in MODEL_PRICE_TABLE) {
      const accounting = computeCostAccounting(
        params.model,
        {
          inputTokens: input,
          outputTokens: output,
          cacheReadTokens: cacheRead,
          cacheWriteTokens: cacheWrite,
        },
        billingMode === "api_key" ? "api_key" : "oauth_subscription",
      );
      if (apiEquivalentUsd === undefined) {
        apiEquivalentUsd = accounting.shadowApiUsd;
      }
      if (actualUsd === undefined) {
        actualUsd = billingMode === "api_key" ? accounting.actualBilledUsd : 0;
      }
      cacheSavingsUsd = accounting.cacheSavingsUsd;
    } else {
      apiEquivalentUsd = apiEquivalentUsd ?? 0;
      actualUsd = actualUsd ?? 0;
    }

    const messageHashes = params.messages
      ? this.blobStore.putMessages(params.messages).hashes
      : [];

    const durationMs = Math.max(0, params.endTimeMs - params.startTimeMs);

    const attributes = scrubSecretsValue({
      "openinference.span.kind": "LLM",
      "llm.model_name": params.model,
      "gen_ai.provider.name": params.providerName,
      "gen_ai.request.model": params.model,
      "gen_ai.usage.input_tokens": input,
      "gen_ai.usage.cache_read.input_tokens": cacheRead,
      "gen_ai.usage.cache_creation.input_tokens": cacheWrite,
      "gen_ai.usage.output_tokens": output,
      "hunt.cache.hit_ratio": hitRatio,
      "hunt.billing.mode": billingMode,
      "hunt.cost.actual_usd": round8(actualUsd),
      "hunt.cost.api_equivalent_usd": round8(apiEquivalentUsd),
      "gen_ai.response.finish_reasons": params.finishReasons ? [...params.finishReasons] : [],
      duration_ms: durationMs,
    });

    return this.insertSpanRow({
      spanId: params.spanId ?? makeSpanId(),
      traceId: params.traceId ?? this.lookupTraceId(params.huntId),
      parentSpanId: params.parentSpanId,
      huntId: params.huntId,
      name: "gen_ai.chat",
      openInferenceKind: "LLM",
      wave: params.wave ?? null,
      stepId: params.stepId ?? null,
      botProfile: params.botProfile ?? null,
      startTimeMs: params.startTimeMs,
      endTimeMs: params.endTimeMs,
      status: params.status ?? "ok",
      errorCode: params.errorCode ?? null,
      inputTokens: input,
      cacheReadTokens: cacheRead,
      cacheWriteTokens: cacheWrite,
      outputTokens: output,
      cacheHitRatio: hitRatio,
      billingMode,
      actualUsd: round8(actualUsd),
      apiEquivalentUsd: round8(apiEquivalentUsd),
      cacheSavingsUsd: round8(cacheSavingsUsd),
      model: params.model,
      attributes,
      messageHashes,
      blobHash: null,
    });
  }

  public recordToolSpan(params: {
    huntId: string;
    parentSpanId: string;
    spanId?: string;
    traceId?: string;
    wave?: HuntWave | null;
    stepId?: string | null;
    botProfile?: ProfileId | null;
    toolName: string;
    actionOrEndpoint?: string;
    queryText?: string;
    resultCount?: number | null;
    totalHits?: number | null;
    blockedRequests?: number;
    errorCode?: string | null;
    returnedIds?: readonly string[];
    rawResultPayload?: unknown;
    startTimeMs: number;
    endTimeMs: number;
  }): TelemetrySpanRecord {
    const preview =
      params.queryText !== undefined ? scrubQueryPreview(params.queryText, 512) : "";
    const durationMs = Math.max(0, params.endTimeMs - params.startTimeMs);
    const blockedRequests = params.blockedRequests ?? 0;
    const errorCode = params.errorCode ?? null;
    const returnedIds = params.returnedIds ? [...params.returnedIds] : [];
    const blobHash =
      params.rawResultPayload !== undefined
        ? this.blobStore.putBlock(params.rawResultPayload).sha256
        : null;

    const attributes = scrubSecretsValue({
      "openinference.span.kind": "TOOL",
      "tool.name": params.toolName,
      "gen_ai.tool.name": params.toolName,
      "hunt.tool.action_or_endpoint": params.actionOrEndpoint ?? params.toolName,
      "hunt.tool.query_text": preview,
      "hunt.tool.result_count": params.resultCount ?? null,
      "hunt.tool.total_hits": params.totalHits ?? null,
      "hunt.tool.blocked_requests": blockedRequests,
      "hunt.tool.error_code": errorCode,
      "hunt.evidence.returned_ids": returnedIds,
      duration_ms: durationMs,
    });

    return this.insertSpanRow({
      spanId: params.spanId ?? makeSpanId(),
      traceId: params.traceId ?? this.lookupTraceId(params.huntId),
      parentSpanId: params.parentSpanId,
      huntId: params.huntId,
      name: "gen_ai.execute_tool",
      openInferenceKind: "TOOL",
      wave: params.wave ?? null,
      stepId: params.stepId ?? null,
      botProfile: params.botProfile ?? null,
      startTimeMs: params.startTimeMs,
      endTimeMs: params.endTimeMs,
      status: errorCode ? "error" : "ok",
      errorCode,
      toolName: params.toolName,
      queryPreview: preview,
      resultCount: params.resultCount ?? null,
      totalHits: params.totalHits ?? null,
      blockedRequests,
      attributes,
      messageHashes: [],
      blobHash,
    });
  }

  public indexClaimCitations(params: {
    huntId: string;
    stepId: string;
    botProfile: ProfileId;
    claims: ReadonlyArray<Pick<Claim, "claim_id" | "kind" | "statement">>;
  }): ClaimLineageRow[] {
    const inserted: ClaimLineageRow[] = [];
    const insertStmt = this.db.query(`
      INSERT OR IGNORE INTO claim_evidence_lineage (
        hunt_id, step_id, bot_profile, claim_id, claim_kind, evidence_type, evidence_id
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    const tx = this.db.transaction(() => {
      for (const claim of params.claims) {
        const inline = extractInlineCitations(claim.statement);
        for (const evtId of inline.event_ids) {
          const row: ClaimLineageRow = {
            huntId: params.huntId,
            stepId: params.stepId,
            botProfile: params.botProfile,
            claimId: claim.claim_id,
            claimKind: claim.kind,
            evidenceType: "event",
            evidenceId: evtId,
          };
          insertStmt.run(
            row.huntId,
            row.stepId,
            row.botProfile,
            row.claimId,
            row.claimKind,
            row.evidenceType,
            row.evidenceId,
          );
          inserted.push(row);
        }

        for (const rawFrameId of inline.frame_ids) {
          const frameId = normalizeFrameId(rawFrameId);
          const row: ClaimLineageRow = {
            huntId: params.huntId,
            stepId: params.stepId,
            botProfile: params.botProfile,
            claimId: claim.claim_id,
            claimKind: claim.kind,
            evidenceType: "frame",
            evidenceId: frameId,
          };
          insertStmt.run(
            row.huntId,
            row.stepId,
            row.botProfile,
            row.claimId,
            row.claimKind,
            row.evidenceType,
            row.evidenceId,
          );
          inserted.push(row);
        }

        for (const iocId of inline.ioc_ids) {
          const row: ClaimLineageRow = {
            huntId: params.huntId,
            stepId: params.stepId,
            botProfile: params.botProfile,
            claimId: claim.claim_id,
            claimKind: claim.kind,
            evidenceType: "ioc",
            evidenceId: iocId,
          };
          insertStmt.run(
            row.huntId,
            row.stepId,
            row.botProfile,
            row.claimId,
            row.claimKind,
            row.evidenceType,
            row.evidenceId,
          );
          inserted.push(row);
        }
      }
    });

    tx();
    return inserted;
  }

  public recordHandoffValidateSpan(params: {
    huntId: string;
    parentSpanId: string;
    spanId?: string;
    traceId?: string;
    wave: HuntWave;
    stepId: string;
    botProfile: ProfileId;
    disposition: string;
    claims?: ReadonlyArray<Pick<Claim, "claim_id" | "kind" | "statement">>;
    rejectedReason?: string | null;
    retried?: boolean;
    startTimeMs: number;
    endTimeMs: number;
  }): { span: TelemetrySpanRecord; lineageRows: ClaimLineageRow[] } {
    const claims = params.claims ?? [];
    const rejectedReason = params.rejectedReason ?? null;
    const retried = params.retried ?? false;
    const durationMs = Math.max(0, params.endTimeMs - params.startTimeMs);

    const lineageRows =
      rejectedReason === null && claims.length > 0
        ? this.indexClaimCitations({
            huntId: params.huntId,
            stepId: params.stepId,
            botProfile: params.botProfile,
            claims,
          })
        : [];

    const attributes = scrubSecretsValue({
      "openinference.span.kind": "GUARDRAIL",
      "hunt.handoff.disposition": params.disposition,
      "hunt.claims.count": claims.length,
      "hunt.handoff.rejected_reason": rejectedReason,
      "hunt.handoff.retried": retried,
      "hunt.lineage.indexed_count": lineageRows.length,
      duration_ms: durationMs,
    });

    const span = this.insertSpanRow({
      spanId: params.spanId ?? makeSpanId(),
      traceId: params.traceId ?? this.lookupTraceId(params.huntId),
      parentSpanId: params.parentSpanId,
      huntId: params.huntId,
      name: "hunt.handoff.validate",
      openInferenceKind: "GUARDRAIL",
      wave: params.wave,
      stepId: params.stepId,
      botProfile: params.botProfile,
      startTimeMs: params.startTimeMs,
      endTimeMs: params.endTimeMs,
      status: rejectedReason ? "error" : "ok",
      errorCode: rejectedReason,
      attributes,
      messageHashes: [],
      blobHash: null,
    });

    return { span, lineageRows };
  }

  public recordGateDecisionSpan(params: {
    huntId: string;
    parentSpanId: string;
    spanId?: string;
    traceId?: string;
    wave?: HuntWave | null;
    gateId: string;
    gateKind: "scope" | "wave" | "incident" | "reconcile";
    humanRequired: boolean;
    choice: "approve" | "reject" | "deny";
    decidedBy: string;
    via: "desktop" | "ui" | "cli" | "slack" | "automated";
    checkNoteSha256?: string | null;
    startTimeMs: number;
    endTimeMs: number;
  }): TelemetrySpanRecord {
    const waitDurationMs = Math.max(0, params.endTimeMs - params.startTimeMs);
    const attributes = scrubSecretsValue({
      "openinference.span.kind": "GUARDRAIL",
      "hunt.gate.id": params.gateId,
      "hunt.gate.kind": params.gateKind,
      "hunt.gate.human_required": params.humanRequired,
      "hunt.gate.choice": params.choice,
      "hunt.gate.decided_by": scrubSecrets(params.decidedBy),
      "hunt.gate.via": params.via,
      "hunt.gate.check_note_sha256": params.checkNoteSha256 ?? null,
      wait_duration_ms: waitDurationMs,
    });

    return this.insertSpanRow({
      spanId: params.spanId ?? makeSpanId(),
      traceId: params.traceId ?? this.lookupTraceId(params.huntId),
      parentSpanId: params.parentSpanId,
      huntId: params.huntId,
      name: "hunt.gate.decision",
      openInferenceKind: "GUARDRAIL",
      wave: params.wave ?? null,
      stepId: null,
      botProfile: null,
      startTimeMs: params.startTimeMs,
      endTimeMs: params.endTimeMs,
      status: params.choice === "approve" ? "ok" : "error",
      errorCode: params.choice === "approve" ? null : `gate_${params.choice}`,
      attributes,
      messageHashes: [],
      blobHash: null,
    });
  }

  public recordCoachEvalSpan(params: {
    evalId?: string;
    huntId: string;
    parentSpanId?: string | null;
    spanId?: string;
    traceId?: string;
    iteration: number;
    track: "playbook" | "code_pr";
    stage: "judge" | "probe" | "pass2";
    meanFound: number;
    attackFound: number;
    misattributedDecoys: number;
    citationPrecision: number;
    g2_1Pass: boolean;
    promoted: boolean;
    startTimeMs: number;
    endTimeMs: number;
  }): TelemetrySpanRecord {
    const spanId = params.spanId ?? makeSpanId();
    const evalId = params.evalId ?? `eval-${params.track}-${params.iteration}-${spanId}`;
    const durationMs = Math.max(0, params.endTimeMs - params.startTimeMs);

    const attributes = scrubSecretsValue({
      "openinference.span.kind": "EVALUATOR",
      "hunt.id": params.huntId,
      "hunt.coach.iteration": params.iteration,
      "hunt.coach.track": params.track,
      "hunt.coach.stage": params.stage,
      "hunt.coach.mean_found": params.meanFound,
      "hunt.coach.attack_found": params.attackFound,
      "hunt.coach.misattributed_decoys": params.misattributedDecoys,
      "hunt.coach.citation_precision": params.citationPrecision,
      "hunt.coach.g2_1_pass": params.g2_1Pass,
      "hunt.coach.promoted": params.promoted,
      duration_ms: durationMs,
    });

    const span = this.insertSpanRow({
      spanId,
      traceId: params.traceId ?? this.lookupTraceId(params.huntId),
      parentSpanId: params.parentSpanId ?? null,
      huntId: params.huntId,
      name: "hunt.coach.eval",
      openInferenceKind: "EVALUATOR",
      wave: null,
      stepId: null,
      botProfile: null,
      startTimeMs: params.startTimeMs,
      endTimeMs: params.endTimeMs,
      status: params.g2_1Pass ? "ok" : "error",
      errorCode: params.g2_1Pass ? null : "g2_1_failed",
      attributes,
      messageHashes: [],
      blobHash: null,
    });

    this.db
      .query(
        `INSERT OR REPLACE INTO coach_evals (
          eval_id, span_id, hunt_id, iteration, track, stage,
          mean_found, attack_found, misattributed_decoys, citation_precision,
          g2_1_pass, promoted, recorded_at_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        evalId,
        spanId,
        params.huntId,
        params.iteration,
        params.track,
        params.stage,
        params.meanFound,
        params.attackFound,
        params.misattributedDecoys,
        params.citationPrecision,
        params.g2_1Pass ? 1 : 0,
        params.promoted ? 1 : 0,
        params.endTimeMs,
      );

    return span;
  }

  public getClaimsForEvidence(huntId: string, rawEvidenceId: string): ClaimLineageRow[] {
    const normalizedId = /^frame-\d+$/i.test(rawEvidenceId)
      ? normalizeFrameId(rawEvidenceId)
      : rawEvidenceId;
    const rows = this.db
      .query(
        `SELECT hunt_id, step_id, bot_profile, claim_id, claim_kind, evidence_type, evidence_id
         FROM claim_evidence_lineage
         WHERE hunt_id = ? AND evidence_id = ?
         ORDER BY claim_id ASC`,
      )
      .all(huntId, normalizedId) as Array<{
      hunt_id: string;
      step_id: string;
      bot_profile: ProfileId;
      claim_id: string;
      claim_kind: ClaimKind;
      evidence_type: EvidenceCitationType;
      evidence_id: string;
    }>;

    return rows.map((r) => ({
      huntId: r.hunt_id,
      stepId: r.step_id,
      botProfile: r.bot_profile,
      claimId: r.claim_id,
      claimKind: r.claim_kind,
      evidenceType: r.evidence_type,
      evidenceId: r.evidence_id,
    }));
  }

  public getEvidenceForClaim(huntId: string, claimId: string): ClaimLineageRow[] {
    const rows = this.db
      .query(
        `SELECT hunt_id, step_id, bot_profile, claim_id, claim_kind, evidence_type, evidence_id
         FROM claim_evidence_lineage
         WHERE hunt_id = ? AND claim_id = ?
         ORDER BY evidence_type ASC, evidence_id ASC`,
      )
      .all(huntId, claimId) as Array<{
      hunt_id: string;
      step_id: string;
      bot_profile: ProfileId;
      claim_id: string;
      claim_kind: ClaimKind;
      evidence_type: EvidenceCitationType;
      evidence_id: string;
    }>;

    return rows.map((r) => ({
      huntId: r.hunt_id,
      stepId: r.step_id,
      botProfile: r.bot_profile,
      claimId: r.claim_id,
      claimKind: r.claim_kind,
      evidenceType: r.evidence_type,
      evidenceId: r.evidence_id,
    }));
  }

  public getRunWaterfall(huntId: string): RunWaterfall | null {
    const runRow = this.db
      .query(
        `SELECT hunt_id, trace_id, case_id, data_origin, synthetic_only,
                mode, started_at_ms, ended_at_ms, completed, halted_at
         FROM hunt_runs
         WHERE hunt_id = ?`,
      )
      .get(huntId) as {
      hunt_id: string;
      trace_id: string;
      case_id: string;
      data_origin: DataOrigin;
      synthetic_only: number;
      mode: string;
      started_at_ms: number;
      ended_at_ms: number | null;
      completed: number;
      halted_at: string | null;
    } | null;

    if (!runRow) {
      return null;
    }

    const spanRows = this.db
      .query(
        `SELECT span_id, trace_id, parent_span_id, hunt_id, name, openinference_kind,
                wave, step_id, bot_profile, start_time_ms, end_time_ms, duration_ms,
                status, error_code, safety_declined, safety_finish_reason, safety_category,
                attributes_json, message_hashes_json, blob_hash
         FROM spans
         WHERE hunt_id = ?
         ORDER BY start_time_ms ASC, end_time_ms DESC, span_id ASC`,
      )
      .all(huntId) as Array<{
      span_id: string;
      trace_id: string;
      parent_span_id: string | null;
      hunt_id: string;
      name: HuntSpanName;
      openinference_kind: OpenInferenceSpanKind;
      wave: HuntWave | null;
      step_id: string | null;
      bot_profile: ProfileId | null;
      start_time_ms: number;
      end_time_ms: number;
      duration_ms: number;
      status: "ok" | "error";
      error_code: string | null;
      safety_declined: number | null;
      safety_finish_reason: string | null;
      safety_category: string | null;
      attributes_json: string;
      message_hashes_json: string;
      blob_hash: string | null;
    }>;

    const parentMap = new Map<string, string | null>();
    for (const s of spanRows) {
      parentMap.set(s.span_id, s.parent_span_id);
    }

    const computeDepth = (spanId: string): number => {
      let depth = 0;
      let cur = parentMap.get(spanId) ?? null;
      const seen = new Set<string>([spanId]);
      while (cur !== null && !seen.has(cur)) {
        seen.add(cur);
        depth++;
        cur = parentMap.get(cur) ?? null;
      }
      return depth;
    };

    let maxEndMs = runRow.ended_at_ms ?? runRow.started_at_ms;
    const entries: RunWaterfallEntry[] = spanRows.map((s) => {
      if (s.end_time_ms > maxEndMs) {
        maxEndMs = s.end_time_ms;
      }
      return {
        spanId: s.span_id,
        parentSpanId: s.parent_span_id,
        traceId: s.trace_id,
        name: s.name,
        openInferenceKind: s.openinference_kind,
        wave: s.wave,
        stepId: s.step_id,
        botProfile: s.bot_profile,
        startTimeMs: s.start_time_ms,
        endTimeMs: s.end_time_ms,
        durationMs: s.duration_ms,
        offsetFromRunStartMs: Math.max(0, s.start_time_ms - runRow.started_at_ms),
        depth: computeDepth(s.span_id),
        status: s.status,
        errorCode: s.error_code,
        safetyDeclined: Boolean(s.safety_declined),
        safetyFinishReason: s.safety_finish_reason,
        safetyCategory: s.safety_category,
        attributes: JSON.parse(s.attributes_json) as Record<string, unknown>,
        messageHashes: JSON.parse(s.message_hashes_json) as string[],
        blobHash: s.blob_hash,
      };
    });

    return {
      huntId: runRow.hunt_id,
      traceId: runRow.trace_id,
      caseId: runRow.case_id,
      dataOrigin: runRow.data_origin,
      syntheticOnly: Boolean(runRow.synthetic_only),
      mode: runRow.mode,
      startedAtMs: runRow.started_at_ms,
      endedAtMs: runRow.ended_at_ms,
      totalDurationMs: Math.max(0, maxEndMs - runRow.started_at_ms),
      completed: Boolean(runRow.completed),
      haltedAt: runRow.halted_at,
      spans: entries,
    };
  }

  public getRunCostSummary(huntId: string): RunCostSummary {
    const chatRows = this.db
      .query(
        `SELECT model, bot_profile, wave,
                COALESCE(input_tokens, 0) AS input_tokens,
                COALESCE(cache_read_tokens, 0) AS cache_read_tokens,
                COALESCE(cache_write_tokens, 0) AS cache_write_tokens,
                COALESCE(output_tokens, 0) AS output_tokens,
                COALESCE(actual_usd, 0) AS actual_usd,
                COALESCE(api_equivalent_usd, 0) AS api_equivalent_usd,
                COALESCE(cache_savings_usd, 0) AS cache_savings_usd
         FROM spans
         WHERE hunt_id = ? AND name = 'gen_ai.chat'`,
      )
      .all(huntId) as Array<{
      model: string | null;
      bot_profile: string | null;
      wave: string | null;
      input_tokens: number;
      cache_read_tokens: number;
      cache_write_tokens: number;
      output_tokens: number;
      actual_usd: number;
      api_equivalent_usd: number;
      cache_savings_usd: number;
    }>;

    const refusalRow = this.db
      .query(
        `SELECT COUNT(*) AS cnt
         FROM spans
         WHERE hunt_id = ? AND name = 'hunt.bot.step' AND safety_declined = 1`,
      )
      .get(huntId) as { cnt: number };

    const total = emptyBucket();
    const byModel: Record<string, TokenCostBucket> = {};
    const byProfile: Record<string, TokenCostBucket> = {};
    const byWave: Record<string, TokenCostBucket> = {};

    for (const r of chatRows) {
      const item = {
        input: r.input_tokens,
        cacheRead: r.cache_read_tokens,
        cacheWrite: r.cache_write_tokens,
        output: r.output_tokens,
        actualUsd: r.actual_usd,
        apiUsd: r.api_equivalent_usd,
        cacheSavingsUsd: r.cache_savings_usd,
      };
      addIntoBucket(total, item);

      const modelKey = r.model ?? "unknown";
      byModel[modelKey] ??= emptyBucket();
      addIntoBucket(byModel[modelKey]!, item);

      const profileKey = r.bot_profile ?? "unknown";
      byProfile[profileKey] ??= emptyBucket();
      addIntoBucket(byProfile[profileKey]!, item);

      const waveKey = r.wave ?? "unknown";
      byWave[waveKey] ??= emptyBucket();
      addIntoBucket(byWave[waveKey]!, item);
    }

    return {
      huntId,
      ...total,
      cyberRefusalCount: refusalRow?.cnt ?? 0,
      byModel,
      byProfile,
      byWave,
    };
  }

  public getCoachTrends(
    filter: {
      track?: "playbook" | "code_pr";
      stage?: "judge" | "probe" | "pass2";
      limit?: number;
    } = {},
  ): CoachTrendPoint[] {
    const clauses: string[] = [];
    const params: Array<string | number> = [];

    if (filter.track) {
      clauses.push("ce.track = ?");
      params.push(filter.track);
    }
    if (filter.stage) {
      clauses.push("ce.stage = ?");
      params.push(filter.stage);
    }

    const whereSql = clauses.length > 0 ? `WHERE ${clauses.join(" AND ")}` : "";
    const limit = Math.max(1, Math.min(1000, filter.limit ?? 200));
    params.push(limit);

    const rows = this.db
      .query(
        `SELECT
           ce.eval_id,
           ce.span_id,
           ce.hunt_id,
           ce.iteration,
           ce.track,
           ce.stage,
           ce.mean_found,
           ce.attack_found,
           ce.misattributed_decoys,
           ce.citation_precision,
           ce.g2_1_pass,
           ce.promoted,
           ce.recorded_at_ms,
           agg.total_tokens,
           agg.actual_usd,
           agg.api_equivalent_usd
         FROM coach_evals ce
         LEFT JOIN (
           SELECT
             hunt_id,
             SUM(COALESCE(input_tokens, 0) + COALESCE(cache_read_tokens, 0) + COALESCE(cache_write_tokens, 0) + COALESCE(output_tokens, 0)) AS total_tokens,
             SUM(COALESCE(actual_usd, 0)) AS actual_usd,
             SUM(COALESCE(api_equivalent_usd, 0)) AS api_equivalent_usd
           FROM spans
           WHERE name = 'gen_ai.chat'
           GROUP BY hunt_id
         ) agg ON agg.hunt_id = ce.hunt_id
         ${whereSql}
         ORDER BY ce.iteration ASC, ce.recorded_at_ms ASC
         LIMIT ?`,
      )
      .all(...params) as Array<{
      eval_id: string;
      span_id: string;
      hunt_id: string | null;
      iteration: number;
      track: "playbook" | "code_pr";
      stage: "judge" | "probe" | "pass2";
      mean_found: number;
      attack_found: number;
      misattributed_decoys: number;
      citation_precision: number;
      g2_1_pass: number;
      promoted: number;
      recorded_at_ms: number;
      total_tokens: number | null;
      actual_usd: number | null;
      api_equivalent_usd: number | null;
    }>;

    return rows.map((r) => ({
      evalId: r.eval_id,
      spanId: r.span_id,
      huntId: r.hunt_id,
      iteration: r.iteration,
      track: r.track,
      stage: r.stage,
      meanFound: r.mean_found,
      attackFound: r.attack_found,
      misattributedDecoys: r.misattributed_decoys,
      citationPrecision: r.citation_precision,
      g2_1Pass: Boolean(r.g2_1_pass),
      promoted: Boolean(r.promoted),
      recordedAtMs: r.recorded_at_ms,
      totalTokens: r.total_tokens,
      actualUsd: r.actual_usd !== null ? round8(r.actual_usd) : null,
      apiEquivalentUsd: r.api_equivalent_usd !== null ? round8(r.api_equivalent_usd) : null,
    }));
  }

  public async exportRunOtlpLoopback(
    huntId: string,
    options: Omit<ExportOtlpLoopbackOptions, "spans" | "syntheticOnly" | "dataOrigin">,
  ): Promise<ExportOtlpResult> {
    const wf = this.getRunWaterfall(huntId);
    if (!wf) {
      throw new Error(`Unknown hunt_id '${huntId}' for OTLP export`);
    }

    const spans: TelemetrySpanRecord[] = wf.spans.map((s) => ({
      spanId: s.spanId,
      traceId: s.traceId,
      parentSpanId: s.parentSpanId,
      huntId: wf.huntId,
      name: s.name,
      openInferenceKind: s.openInferenceKind,
      wave: s.wave,
      stepId: s.stepId,
      botProfile: s.botProfile,
      startTimeMs: s.startTimeMs,
      endTimeMs: s.endTimeMs,
      durationMs: s.durationMs,
      status: s.status,
      errorCode: s.errorCode,
      attributes: s.attributes,
      messageHashes: s.messageHashes,
      blobHash: s.blobHash,
    }));

    return exportOtlpLoopback({
      ...options,
      spans,
      syntheticOnly: wf.syntheticOnly,
      dataOrigin: wf.dataOrigin,
    });
  }

  public close(): void {
    this.db.close();
  }

  private lookupTraceId(huntId: string): string {
    const row = this.db
      .query("SELECT trace_id FROM hunt_runs WHERE hunt_id = ?")
      .get(huntId) as { trace_id: string } | null;
    return row?.trace_id ?? makeTraceId(huntId);
  }

  private insertSpanRow(row: {
    spanId: string;
    traceId: string;
    parentSpanId: string | null;
    huntId: string;
    name: HuntSpanName;
    openInferenceKind: OpenInferenceSpanKind;
    wave: HuntWave | null;
    stepId: string | null;
    botProfile: ProfileId | null;
    startTimeMs: number;
    endTimeMs: number;
    status: "ok" | "error";
    errorCode: string | null;
    inputTokens?: number | null;
    cacheReadTokens?: number | null;
    cacheWriteTokens?: number | null;
    outputTokens?: number | null;
    cacheHitRatio?: number | null;
    billingMode?: string | null;
    actualUsd?: number | null;
    apiEquivalentUsd?: number | null;
    cacheSavingsUsd?: number | null;
    model?: string | null;
    toolName?: string | null;
    queryPreview?: string | null;
    resultCount?: number | null;
    totalHits?: number | null;
    blockedRequests?: number | null;
    safetyDeclined?: boolean | null;
    safetyFinishReason?: string | null;
    safetyCategory?: string | null;
    attributes: Record<string, unknown>;
    messageHashes: string[];
    blobHash: string | null;
  }): TelemetrySpanRecord {
    const durationMs = Math.max(0, row.endTimeMs - row.startTimeMs);
    const scrubbedAttrs = scrubSecretsValue(row.attributes);
    const scrubbedPreview =
      row.queryPreview !== undefined && row.queryPreview !== null
        ? scrubQueryPreview(row.queryPreview, 512)
        : null;

    this.db
      .query(
        `INSERT OR REPLACE INTO spans (
          span_id, trace_id, parent_span_id, hunt_id, name, openinference_kind,
          wave, step_id, bot_profile, start_time_ms, end_time_ms, duration_ms,
          status, error_code,
          input_tokens, cache_read_tokens, cache_write_tokens, output_tokens,
          cache_hit_ratio, billing_mode, actual_usd, api_equivalent_usd, cache_savings_usd,
          model, tool_name, query_preview, result_count, total_hits, blocked_requests,
          safety_declined, safety_finish_reason, safety_category,
          attributes_json, message_hashes_json, blob_hash
        ) VALUES (
          ?, ?, ?, ?, ?, ?,
          ?, ?, ?, ?, ?, ?,
          ?, ?,
          ?, ?, ?, ?,
          ?, ?, ?, ?, ?,
          ?, ?, ?, ?, ?, ?,
          ?, ?, ?,
          ?, ?, ?
        )`,
      )
      .run(
        row.spanId,
        row.traceId,
        row.parentSpanId,
        row.huntId,
        row.name,
        row.openInferenceKind,
        row.wave,
        row.stepId,
        row.botProfile,
        row.startTimeMs,
        row.endTimeMs,
        durationMs,
        row.status,
        row.errorCode,
        row.inputTokens ?? null,
        row.cacheReadTokens ?? null,
        row.cacheWriteTokens ?? null,
        row.outputTokens ?? null,
        row.cacheHitRatio ?? null,
        row.billingMode ?? null,
        row.actualUsd ?? null,
        row.apiEquivalentUsd ?? null,
        row.cacheSavingsUsd ?? null,
        row.model ? scrubSecrets(row.model) : null,
        row.toolName ?? null,
        scrubbedPreview,
        row.resultCount ?? null,
        row.totalHits ?? null,
        row.blockedRequests ?? null,
        row.safetyDeclined === undefined || row.safetyDeclined === null
          ? null
          : row.safetyDeclined
            ? 1
            : 0,
        row.safetyFinishReason ?? null,
        row.safetyCategory ?? null,
        JSON.stringify(scrubbedAttrs),
        JSON.stringify(row.messageHashes),
        row.blobHash,
      );

    return {
      spanId: row.spanId,
      traceId: row.traceId,
      parentSpanId: row.parentSpanId,
      huntId: row.huntId,
      name: row.name,
      openInferenceKind: row.openInferenceKind,
      wave: row.wave,
      stepId: row.stepId,
      botProfile: row.botProfile,
      startTimeMs: row.startTimeMs,
      endTimeMs: row.endTimeMs,
      durationMs,
      status: row.status,
      errorCode: row.errorCode,
      attributes: scrubbedAttrs,
      messageHashes: row.messageHashes,
      blobHash: row.blobHash,
    };
  }
}
