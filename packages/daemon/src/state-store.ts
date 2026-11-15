import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { Database } from "bun:sqlite";
import type {
  AuthenticatedGateDecision,
  DataOrigin,
  Handoff,
  HuntWave,
  ModelRefusalReport,
  ProfileId,
  ReceiptStatus,
  Snapshot,
  StepState,
} from "@hunt-command/shared";
import type {
  CitationVerificationReceipt,
  DelegatedStepRecord,
  StepTokenUsage,
} from "./ports.ts";

export interface StepResultRecord {
  readonly step_id: string;
  readonly wave: HuntWave;
  readonly profile: ProfileId;
  readonly status: "done" | "dropped" | "failed" | "unknown" | "cancelled";
  readonly reason_code?: string;
  readonly attempts: number;
  readonly handoff?: Handoff;
  readonly canonical_json?: string;
  readonly usage?: StepTokenUsage;
  readonly refusal?: ModelRefusalReport;
  readonly diagnostic?: string;
  /**
   * Set only on `unknown` / `citation_source_unavailable` results: the validated handoff whose
   * citations could not be checked, and the unavailable receipt. Never used as a step output;
   * kept so the reconcile gate can show the operator what is being decided.
   */
  readonly unverified_handoff?: Handoff;
  readonly citation_receipt?: CitationVerificationReceipt;
  readonly finished_at: string;
}

export interface HandoffRejectionRecord {
  readonly step_id: string;
  readonly execution_id: string;
  readonly attempt: number;
  readonly reason_code: string;
  readonly diagnostic: string;
  readonly raw_bytes: number;
  readonly usage?: StepTokenUsage;
  readonly rejected_at: string;
}

export interface OpenGateState {
  readonly gate: string;
  readonly wave: HuntWave;
  readonly requires_human: boolean;
  readonly payload_sha256: string;
  readonly opened_at: string;
  readonly expires_at: string;
  readonly reason_code?: string;
  readonly unknown_step_id?: string;
  readonly check_note_cleared: true;
  readonly review_file_path?: string;
}

export interface TokenLedgerSummary {
  readonly max_total_tokens: number;
  readonly consumed_total_tokens: number;
  readonly results_tokens: number;
  readonly rejections_tokens: number;
  readonly delegated_tokens: number;
  readonly actual_billed_usd: number;
  readonly shadow_api_usd: number;
  readonly cache_savings_usd: number;
}

export type RunLifecycleStatus =
  | "running"
  | "awaiting_gate"
  | "completed"
  | "failed"
  | "cancelled";

export interface PersistedRunConfig {
  readonly scopeText: string;
  readonly followUps: number;
  readonly maxTotalTokens: number;
  readonly stageGuidance?: Partial<Record<string, string>>;
  readonly optionalOverrides?: Partial<Record<string, boolean>>;
  readonly gateTtlMs?: number;
}

export interface PersistedHuntRun {
  run_id: string;
  case_id: string;
  data_origin: DataOrigin;
  synthetic_only: boolean;
  wave: HuntWave;
  wave_index: number;
  status: RunLifecycleStatus;
  reason_code: string | null;
  step_states: Record<string, StepState>;
  results: Record<string, StepResultRecord>;
  handoff_rejections: HandoffRejectionRecord[];
  reviewed_handoffs: Record<string, Handoff>;
  delegated_ledger: DelegatedStepRecord[];
  open_gate: OpenGateState | null;
  decisions: AuthenticatedGateDecision[];
  token_ledger: TokenLedgerSummary;
  citation_receipt: CitationVerificationReceipt | null;
  snapshot: Snapshot | null;
  config: PersistedRunConfig;
  created_at: string;
  updated_at: string;
}

export interface DispatchReceiptRow {
  readonly execution_id: string;
  readonly run_id: string;
  readonly step_id: string;
  readonly session_id: string;
  readonly input_id: string;
  readonly fingerprint: string;
  readonly status: ReceiptStatus;
  readonly reason_code: string | null;
  readonly output_text: string | null;
  readonly usage: StepTokenUsage | null;
  readonly refusal: ModelRefusalReport | null;
  readonly diagnostic: string | null;
  readonly reserved_at: string;
  readonly finished_at: string | null;
}

export type ReserveReceiptOutcome =
  | { readonly action: "proceed"; readonly receipt: DispatchReceiptRow }
  | { readonly action: "replay_completed"; readonly receipt: DispatchReceiptRow }
  | {
      readonly action: "unknown";
      readonly reason_code: "previous_dispatch_unknown";
      readonly receipt: DispatchReceiptRow;
    }
  | {
      readonly action: "conflict";
      readonly reason_code: "fingerprint_conflict";
      readonly receipt: DispatchReceiptRow;
    };

export type CommitGateDecisionOutcome =
  | { readonly outcome: "committed"; readonly run: PersistedHuntRun }
  | { readonly outcome: "gate_not_open" }
  | { readonly outcome: "decision_id_replayed" }
  | { readonly outcome: "gate_already_decided" };

export function computeDispatchFingerprint(payload: {
  runId: string;
  stepId: string;
  profile: ProfileId;
  prompt: string;
}): string {
  return crypto
    .createHash("sha256")
    .update(
      `${payload.runId}\0${payload.stepId}\0${payload.profile}\0${payload.prompt}`,
      "utf8",
    )
    .digest("hex");
}

function configureDurableSqlite(db: Database): void {
  db.exec("PRAGMA journal_mode = WAL;");
  db.exec("PRAGMA synchronous = FULL;");
  db.exec("PRAGMA busy_timeout = 30000;");
  db.exec("PRAGMA foreign_keys = ON;");
}

/**
 * Durable SQLite WAL store for `hunt_runs`, `dispatch_receipts` (`ReceiptStore`),
 * and `seen_decision_ids` (replay prevention).
 *
 * Uses `PRAGMA journal_mode = WAL` + `PRAGMA synchronous = FULL` + `BEGIN IMMEDIATE`
 * transactions so an in-flight turn reserved BEFORE `session.prompt()` is NEVER
 * auto-rerun after a daemon crash or restart!
 */
export class DurableStateStore {
  public readonly dbPath: string;
  private readonly db: Database;
  private closed = false;

  constructor(dbPath: string) {
    this.dbPath = path.resolve(dbPath);
    fs.mkdirSync(path.dirname(this.dbPath), { recursive: true });
    this.db = new Database(this.dbPath, { create: true });
    configureDurableSqlite(this.db);
    this.initializeSchema();
  }

  private initializeSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS hunt_runs (
        run_id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        data_origin TEXT NOT NULL,
        synthetic_only INTEGER NOT NULL,
        wave TEXT NOT NULL,
        wave_index INTEGER NOT NULL,
        status TEXT NOT NULL,
        reason_code TEXT,
        step_states_json TEXT NOT NULL,
        results_json TEXT NOT NULL,
        handoff_rejections_json TEXT NOT NULL,
        reviewed_handoffs_json TEXT NOT NULL,
        delegated_ledger_json TEXT NOT NULL,
        open_gate_json TEXT,
        decisions_json TEXT NOT NULL,
        token_ledger_json TEXT NOT NULL,
        citation_receipt_json TEXT,
        snapshot_json TEXT,
        config_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_hunt_runs_status ON hunt_runs(status);

      CREATE TABLE IF NOT EXISTS dispatch_receipts (
        execution_id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL,
        step_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        input_id TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        status TEXT NOT NULL,
        reason_code TEXT,
        output_text TEXT,
        usage_json TEXT,
        refusal_json TEXT,
        diagnostic TEXT,
        reserved_at TEXT NOT NULL,
        finished_at TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_dispatch_receipts_run ON dispatch_receipts(run_id, status);

      CREATE TABLE IF NOT EXISTS seen_gate_decisions (
        decision_id TEXT PRIMARY KEY,
        hunt_id TEXT NOT NULL,
        gate TEXT NOT NULL,
        action TEXT NOT NULL,
        payload_sha256 TEXT NOT NULL,
        decided_by TEXT NOT NULL,
        decided_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS gate_instance_decisions (
        hunt_id TEXT NOT NULL,
        gate TEXT NOT NULL,
        gate_instance TEXT NOT NULL,
        decision_id TEXT NOT NULL,
        PRIMARY KEY (hunt_id, gate, gate_instance)
      );
    `);
  }

  public getPragmaStatus(): { journalMode: string; synchronous: number } {
    const jm = this.db
      .query<{ journal_mode: string }, []>("PRAGMA journal_mode;")
      .get();
    const sync = this.db
      .query<{ synchronous: number }, []>("PRAGMA synchronous;")
      .get();
    return {
      journalMode: (jm?.journal_mode ?? "").toLowerCase(),
      synchronous: sync?.synchronous ?? -1,
    };
  }

  private mapReceiptRow(raw: Record<string, unknown>): DispatchReceiptRow {
    return {
      execution_id: String(raw.execution_id),
      run_id: String(raw.run_id),
      step_id: String(raw.step_id),
      session_id: String(raw.session_id),
      input_id: String(raw.input_id),
      fingerprint: String(raw.fingerprint),
      status: String(raw.status) as ReceiptStatus,
      reason_code: raw.reason_code !== null && raw.reason_code !== undefined ? String(raw.reason_code) : null,
      output_text: raw.output_text !== null && raw.output_text !== undefined ? String(raw.output_text) : null,
      usage:
        typeof raw.usage_json === "string" && raw.usage_json.length > 0
          ? (JSON.parse(raw.usage_json) as StepTokenUsage)
          : null,
      refusal:
        typeof raw.refusal_json === "string" && raw.refusal_json.length > 0
          ? (JSON.parse(raw.refusal_json) as ModelRefusalReport)
          : null,
      diagnostic: raw.diagnostic !== null && raw.diagnostic !== undefined ? String(raw.diagnostic) : null,
      reserved_at: String(raw.reserved_at),
      finished_at: raw.finished_at !== null && raw.finished_at !== undefined ? String(raw.finished_at) : null,
    };
  }

  /**
   * Reserves `(execution_id, session_id, input_id)` inside `BEGIN IMMEDIATE` BEFORE calling `session.prompt()`.
   * If a prior dispatch left the receipt `reserved` or `previous_dispatch_unknown`, marks it
   * `previous_dispatch_unknown` and refuses to auto-rerun!
   */
  public reserveReceipt(params: {
    executionId: string;
    runId: string;
    stepId: string;
    sessionId: string;
    inputId: string;
    fingerprint: string;
  }): ReserveReceiptOutcome {
    this.db.exec("BEGIN IMMEDIATE;");
    try {
      const existingRaw = this.db
        .query<Record<string, unknown>, [string]>(
          "SELECT * FROM dispatch_receipts WHERE execution_id = ?;",
        )
        .get(params.executionId);

      if (!existingRaw) {
        const now = new Date().toISOString();
        this.db
          .query(
            `INSERT INTO dispatch_receipts (
              execution_id, run_id, step_id, session_id, input_id, fingerprint, status, reserved_at
            ) VALUES (?, ?, ?, ?, ?, ?, 'reserved', ?);`,
          )
          .run(
            params.executionId,
            params.runId,
            params.stepId,
            params.sessionId,
            params.inputId,
            params.fingerprint,
            now,
          );
        const insertedRaw = this.db
          .query<Record<string, unknown>, [string]>(
            "SELECT * FROM dispatch_receipts WHERE execution_id = ?;",
          )
          .get(params.executionId)!;
        this.db.exec("COMMIT;");
        return { action: "proceed", receipt: this.mapReceiptRow(insertedRaw) };
      }

      const existing = this.mapReceiptRow(existingRaw);

      if (existing.fingerprint !== params.fingerprint) {
        this.db.exec("COMMIT;");
        return {
          action: "conflict",
          reason_code: "fingerprint_conflict",
          receipt: existing,
        };
      }

      if (existing.status === "completed") {
        this.db.exec("COMMIT;");
        return { action: "replay_completed", receipt: existing };
      }

      // `reserved`, `previous_dispatch_unknown`, or `failed` -> fail closed as unknown when in-flight!
      const now = new Date().toISOString();
      this.db
        .query(
          `UPDATE dispatch_receipts
           SET status = 'previous_dispatch_unknown',
               reason_code = 'previous_dispatch_unknown',
               diagnostic = COALESCE(diagnostic, 'Daemon restarted or re-entered while dispatch was reserved in-flight'),
               finished_at = COALESCE(finished_at, ?)
           WHERE execution_id = ?;`,
        )
        .run(now, params.executionId);

      const updatedRaw = this.db
        .query<Record<string, unknown>, [string]>(
          "SELECT * FROM dispatch_receipts WHERE execution_id = ?;",
        )
        .get(params.executionId)!;
      this.db.exec("COMMIT;");
      return {
        action: "unknown",
        reason_code: "previous_dispatch_unknown",
        receipt: this.mapReceiptRow(updatedRaw),
      };
    } catch (err) {
      try {
        this.db.exec("ROLLBACK;");
      } catch {}
      throw err;
    }
  }

  public finalizeReceipt(params: {
    executionId: string;
    status: ReceiptStatus;
    reasonCode?: string | null;
    outputText?: string | null;
    usage?: StepTokenUsage | null;
    refusal?: ModelRefusalReport | null;
    diagnostic?: string | null;
  }): void {
    const now = new Date().toISOString();
    this.db.exec("BEGIN IMMEDIATE;");
    try {
      this.db
        .query(
          `UPDATE dispatch_receipts
           SET status = ?,
               reason_code = ?,
               output_text = ?,
               usage_json = ?,
               refusal_json = ?,
               diagnostic = ?,
               finished_at = ?
           WHERE execution_id = ?;`,
        )
        .run(
          params.status,
          params.reasonCode ?? null,
          params.outputText ?? null,
          params.usage ? JSON.stringify(params.usage) : null,
          params.refusal ? JSON.stringify(params.refusal) : null,
          params.diagnostic ?? null,
          now,
          params.executionId,
        );
      this.db.exec("COMMIT;");
    } catch (err) {
      try {
        this.db.exec("ROLLBACK;");
      } catch {}
      throw err;
    }
  }

  public listReceiptsForRun(runId: string): DispatchReceiptRow[] {
    const rows = this.db
      .query<Record<string, unknown>, [string]>(
        "SELECT * FROM dispatch_receipts WHERE run_id = ? ORDER BY reserved_at ASC;",
      )
      .all(runId);
    return rows.map((r) => this.mapReceiptRow(r));
  }

  public saveRun(run: PersistedHuntRun): void {
    this.db.exec("BEGIN IMMEDIATE;");
    try {
      this.writeRunRow(run);
      this.db.exec("COMMIT;");
    } catch (err) {
      try {
        this.db.exec("ROLLBACK;");
      } catch {}
      throw err;
    }
  }

  /** Upserts one `hunt_runs` row; callers MUST already hold a `BEGIN IMMEDIATE` transaction. */
  private writeRunRow(run: PersistedHuntRun): void {
    run.updated_at = new Date().toISOString();
    this.db
      .query(
        `INSERT INTO hunt_runs (
          run_id, case_id, data_origin, synthetic_only, wave, wave_index,
          status, reason_code, step_states_json, results_json,
          handoff_rejections_json, reviewed_handoffs_json, delegated_ledger_json,
          open_gate_json, decisions_json, token_ledger_json, citation_receipt_json,
          snapshot_json, config_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(run_id) DO UPDATE SET
          wave = excluded.wave,
          wave_index = excluded.wave_index,
          status = excluded.status,
          reason_code = excluded.reason_code,
          step_states_json = excluded.step_states_json,
          results_json = excluded.results_json,
          handoff_rejections_json = excluded.handoff_rejections_json,
          reviewed_handoffs_json = excluded.reviewed_handoffs_json,
          delegated_ledger_json = excluded.delegated_ledger_json,
          open_gate_json = excluded.open_gate_json,
          decisions_json = excluded.decisions_json,
          token_ledger_json = excluded.token_ledger_json,
          citation_receipt_json = excluded.citation_receipt_json,
          snapshot_json = excluded.snapshot_json,
          config_json = excluded.config_json,
          updated_at = excluded.updated_at
        WHERE hunt_runs.status != 'cancelled' OR excluded.status = 'cancelled';`,
      )
      .run(
        run.run_id,
        run.case_id,
        run.data_origin,
        run.synthetic_only ? 1 : 0,
        run.wave,
        run.wave_index,
        run.status,
        run.reason_code,
        JSON.stringify(run.step_states),
        JSON.stringify(run.results),
        JSON.stringify(run.handoff_rejections),
        JSON.stringify(run.reviewed_handoffs),
        JSON.stringify(run.delegated_ledger),
        run.open_gate ? JSON.stringify(run.open_gate) : null,
        JSON.stringify(run.decisions),
        JSON.stringify(run.token_ledger),
        run.citation_receipt ? JSON.stringify(run.citation_receipt) : null,
        run.snapshot ? JSON.stringify(run.snapshot) : null,
        JSON.stringify(run.config),
        run.created_at,
        run.updated_at,
      );
  }

  private mapRunRow(raw: Record<string, unknown>): PersistedHuntRun {
    return {
      run_id: String(raw.run_id),
      case_id: String(raw.case_id),
      data_origin: String(raw.data_origin) as DataOrigin,
      synthetic_only: Number(raw.synthetic_only) === 1,
      wave: String(raw.wave) as HuntWave,
      wave_index: Number(raw.wave_index),
      status: String(raw.status) as RunLifecycleStatus,
      reason_code: raw.reason_code !== null && raw.reason_code !== undefined ? String(raw.reason_code) : null,
      step_states: JSON.parse(String(raw.step_states_json)) as Record<string, StepState>,
      results: JSON.parse(String(raw.results_json)) as Record<string, StepResultRecord>,
      handoff_rejections: JSON.parse(String(raw.handoff_rejections_json)) as HandoffRejectionRecord[],
      reviewed_handoffs: JSON.parse(String(raw.reviewed_handoffs_json)) as Record<string, Handoff>,
      delegated_ledger: JSON.parse(String(raw.delegated_ledger_json)) as DelegatedStepRecord[],
      open_gate:
        typeof raw.open_gate_json === "string" && raw.open_gate_json.length > 0
          ? (JSON.parse(raw.open_gate_json) as OpenGateState)
          : null,
      decisions: JSON.parse(String(raw.decisions_json)) as AuthenticatedGateDecision[],
      token_ledger: JSON.parse(String(raw.token_ledger_json)) as TokenLedgerSummary,
      citation_receipt:
        typeof raw.citation_receipt_json === "string" && raw.citation_receipt_json.length > 0
          ? (JSON.parse(raw.citation_receipt_json) as CitationVerificationReceipt)
          : null,
      snapshot:
        typeof raw.snapshot_json === "string" && raw.snapshot_json.length > 0
          ? (JSON.parse(raw.snapshot_json) as Snapshot)
          : null,
      config: JSON.parse(String(raw.config_json)) as PersistedRunConfig,
      created_at: String(raw.created_at),
      updated_at: String(raw.updated_at),
    };
  }

  public getRun(runId: string): PersistedHuntRun | null {
    const raw = this.db
      .query<Record<string, unknown>, [string]>("SELECT * FROM hunt_runs WHERE run_id = ?;")
      .get(runId);
    return raw ? this.mapRunRow(raw) : null;
  }

  public listRuns(statusFilter?: RunLifecycleStatus): PersistedHuntRun[] {
    const rows = statusFilter
      ? this.db
          .query<Record<string, unknown>, [string]>(
            "SELECT * FROM hunt_runs WHERE status = ? ORDER BY created_at DESC;",
          )
          .all(statusFilter)
      : this.db
          .query<Record<string, unknown>, []>("SELECT * FROM hunt_runs ORDER BY created_at DESC;")
          .all();
    return rows.map((r) => this.mapRunRow(r));
  }

  /**
   * Atomically records `decision_id` to prevent replay across runs or gates.
   * Returns `false` if `decision_id` was already used.
   */
  public recordUniqueDecisionId(decision: AuthenticatedGateDecision): boolean {
    this.db.exec("BEGIN IMMEDIATE;");
    try {
      const existing = this.db
        .query<{ decision_id: string }, [string]>(
          "SELECT decision_id FROM seen_gate_decisions WHERE decision_id = ?;",
        )
        .get(decision.decision_id);
      if (existing) {
        this.db.exec("COMMIT;");
        return false;
      }
      this.db
        .query(
          `INSERT INTO seen_gate_decisions (
            decision_id, hunt_id, gate, action, payload_sha256, decided_by, decided_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?);`,
        )
        .run(
          decision.decision_id,
          decision.hunt_id,
          decision.gate,
          decision.action,
          decision.payload_sha256,
          decision.decided_by,
          decision.decided_at,
        );
      this.db.exec("COMMIT;");
      return true;
    } catch (err) {
      try {
        this.db.exec("ROLLBACK;");
      } catch {}
      throw err;
    }
  }

  /**
   * Atomically consumes one gate decision inside a single `BEGIN IMMEDIATE` transaction:
   * re-reads the run, verifies the SAME gate instance is still open, inserts the unique
   * `decision_id` plus the `(hunt_id, gate, gate_instance)` row, applies `mutate`, and
   * writes the run. Any failure rolls back, so the `decision_id` is never burned.
   */
  public commitGateDecision(params: {
    decision: AuthenticatedGateDecision;
    expectedOpenGate: OpenGateState;
    mutate: (run: PersistedHuntRun) => void;
  }): CommitGateDecisionOutcome {
    const { decision, expectedOpenGate } = params;
    const gateInstance = `${expectedOpenGate.payload_sha256}@${expectedOpenGate.opened_at}`;
    this.db.exec("BEGIN IMMEDIATE;");
    try {
      const raw = this.db
        .query<Record<string, unknown>, [string]>("SELECT * FROM hunt_runs WHERE run_id = ?;")
        .get(decision.hunt_id);
      const run = raw ? this.mapRunRow(raw) : null;
      const open = run?.open_gate;
      if (
        !run ||
        run.status !== "awaiting_gate" ||
        !open ||
        open.gate !== expectedOpenGate.gate ||
        open.payload_sha256 !== expectedOpenGate.payload_sha256 ||
        open.opened_at !== expectedOpenGate.opened_at
      ) {
        this.db.exec("ROLLBACK;");
        return { outcome: "gate_not_open" };
      }

      const seenId = this.db
        .query<{ decision_id: string }, [string]>(
          "SELECT decision_id FROM seen_gate_decisions WHERE decision_id = ?;",
        )
        .get(decision.decision_id);
      if (seenId) {
        this.db.exec("ROLLBACK;");
        return { outcome: "decision_id_replayed" };
      }

      const seenInstance = this.db
        .query<{ decision_id: string }, [string, string, string]>(
          "SELECT decision_id FROM gate_instance_decisions WHERE hunt_id = ? AND gate = ? AND gate_instance = ?;",
        )
        .get(decision.hunt_id, decision.gate, gateInstance);
      if (seenInstance) {
        this.db.exec("ROLLBACK;");
        return { outcome: "gate_already_decided" };
      }

      this.db
        .query(
          `INSERT INTO seen_gate_decisions (
            decision_id, hunt_id, gate, action, payload_sha256, decided_by, decided_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?);`,
        )
        .run(
          decision.decision_id,
          decision.hunt_id,
          decision.gate,
          decision.action,
          decision.payload_sha256,
          decision.decided_by,
          decision.decided_at,
        );
      this.db
        .query(
          `INSERT INTO gate_instance_decisions (hunt_id, gate, gate_instance, decision_id)
           VALUES (?, ?, ?, ?);`,
        )
        .run(decision.hunt_id, decision.gate, gateInstance, decision.decision_id);

      run.decisions.push(decision);
      run.open_gate = null;
      params.mutate(run);
      this.writeRunRow(run);
      this.db.exec("COMMIT;");
      return { outcome: "committed", run };
    } catch (err) {
      try {
        this.db.exec("ROLLBACK;");
      } catch {}
      throw err;
    }
  }

  public checkpointWal(): void {
    if (!this.closed) {
      this.db.exec("PRAGMA wal_checkpoint(TRUNCATE);");
    }
  }

  public close(): void {
    if (!this.closed) {
      this.closed = true;
      this.db.close();
    }
  }
}
