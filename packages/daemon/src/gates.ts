import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
  AuthenticatedGateDecisionSchema,
  RECONCILE_GATE,
  requiresHumanDecision,
  type AuthenticatedGateDecision,
  type DataOrigin,
  type GateChannel,
  type Handoff,
  type HuntWave,
} from "@hunt-command/shared";
import { StrictEgressGuard, type EgressGuardPort, type SanitizedGateCardPayload } from "./ports.ts";
import { scrubCredentials } from "./scrubber-and-fence.ts";
import type { DurableStateStore, OpenGateState } from "./state-store.ts";

export const RBAC_ROLES = ["admin", "analyst", "reviewer", "viewer"] as const;
export type RbacRole = (typeof RBAC_ROLES)[number];

const GATE_DECIDER_ROLES = new Set<string>(["admin", "analyst", "reviewer"]);

export const DEFAULT_GATE_TTL_MS = 24 * 60 * 60 * 1000;
export const MAX_CHECK_NOTE_CHARS = 1_000;

export type GateErrorCode =
  | "rbac_denied"
  | "invalid_operator_token"
  | "automated_channel_forbidden"
  | "gate_not_open"
  | "gate_expired"
  | "payload_digest_mismatch"
  | "decision_id_replayed"
  | "check_note_required"
  | "check_note_too_long"
  | "invalid_gate_decision";

export class GateDecisionError extends Error {
  public readonly errorCode: GateErrorCode;

  constructor(errorCode: GateErrorCode, message: string) {
    super(message);
    this.name = "GateDecisionError";
    this.errorCode = errorCode;
  }
}

export function canRoleDecideGate(role: string): role is "admin" | "analyst" | "reviewer" {
  return GATE_DECIDER_ROLES.has(role);
}

function canonicalizeValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => canonicalizeValue(item));
  }
  if (value !== null && typeof value === "object") {
    const sortedKeys = Object.keys(value as Record<string, unknown>).sort();
    const out: Record<string, unknown> = {};
    for (const k of sortedKeys) {
      const v = (value as Record<string, unknown>)[k];
      if (v !== undefined) {
        out[k] = canonicalizeValue(v);
      }
    }
    return out;
  }
  return value;
}

export function computeCanonicalSha256(payload: unknown): string {
  const canonicalJson = JSON.stringify(canonicalizeValue(payload));
  return crypto.createHash("sha256").update(canonicalJson, "utf8").digest("hex");
}

export interface OperatorTokenPayload {
  readonly principal: string;
  readonly rbacRole: RbacRole;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
}

/**
 * Cryptographic HMAC-SHA256 session token authority for authenticating human operators
 * across Desktop IPC, CLI `drive_gates`, and Slack Socket Mode.
 */
export class OperatorSessionAuthority {
  private readonly secret: Buffer;

  constructor(secret?: Buffer | string) {
    if (secret === undefined) {
      this.secret = crypto.randomBytes(32);
    } else if (typeof secret === "string") {
      if (Buffer.byteLength(secret, "utf8") < 16) {
        throw new Error("OperatorSessionAuthority secret must be >= 16 bytes");
      }
      this.secret = Buffer.from(secret, "utf8");
    } else {
      if (secret.byteLength < 16) {
        throw new Error("OperatorSessionAuthority secret must be >= 16 bytes");
      }
      this.secret = Buffer.from(secret);
    }
  }

  public issueToken(
    principal: string,
    rbacRole: RbacRole,
    ttlMs = 12 * 60 * 60 * 1000,
  ): string {
    if (!principal.trim()) {
      throw new Error("Operator principal must be non-empty");
    }
    const now = Date.now();
    const body: OperatorTokenPayload = {
      principal: principal.trim(),
      rbacRole,
      issuedAtMs: now,
      expiresAtMs: now + ttlMs,
    };
    const encoded = Buffer.from(JSON.stringify(body), "utf8").toString("base64url");
    const sig = crypto
      .createHmac("sha256", this.secret)
      .update(encoded, "utf8")
      .digest("base64url");
    return `${encoded}.${sig}`;
  }

  public verifyToken(token: string, nowMs = Date.now()): OperatorTokenPayload {
    const parts = token.split(".");
    if (parts.length !== 2 || !parts[0] || !parts[1]) {
      throw new GateDecisionError("invalid_operator_token", "Malformed operator session token");
    }
    const [encoded, providedSig] = parts;
    const expectedSig = crypto
      .createHmac("sha256", this.secret)
      .update(encoded, "utf8")
      .digest("base64url");

    const providedBuf = Buffer.from(providedSig, "utf8");
    const expectedBuf = Buffer.from(expectedSig, "utf8");
    if (
      providedBuf.byteLength !== expectedBuf.byteLength ||
      !crypto.timingSafeEqual(providedBuf, expectedBuf)
    ) {
      throw new GateDecisionError(
        "invalid_operator_token",
        "Operator session token HMAC signature mismatch",
      );
    }

    let decoded: OperatorTokenPayload;
    try {
      decoded = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")) as OperatorTokenPayload;
    } catch {
      throw new GateDecisionError("invalid_operator_token", "Corrupt operator token payload");
    }

    if (
      typeof decoded.principal !== "string" ||
      !decoded.principal.trim() ||
      !(RBAC_ROLES as readonly string[]).includes(decoded.rbacRole) ||
      typeof decoded.expiresAtMs !== "number"
    ) {
      throw new GateDecisionError("invalid_operator_token", "Invalid operator token claims");
    }

    if (nowMs > decoded.expiresAtMs) {
      throw new GateDecisionError("invalid_operator_token", "Operator session token has expired");
    }

    return decoded;
  }
}

/**
 * Loads (or creates once, exclusively, mode 0600) the operator-session HMAC secret stored in the
 * runtime dir, so tokens minted by the local human-facing CLI verify in the serving daemon.
 * Possession of the runtime dir is the trust boundary; the secret is never exposed over RPC.
 */
export function loadOrCreateOperatorSessionSecret(secretPath: string): Buffer {
  fs.mkdirSync(path.dirname(secretPath), { recursive: true });
  if (!fs.existsSync(secretPath)) {
    // Write a complete temp file, then hard-link it into place (atomic create-if-absent),
    // so a concurrent reader never observes a partially written secret.
    const tmpPath = `${secretPath}.tmp.${process.pid}.${crypto.randomBytes(4).toString("hex")}`;
    fs.writeFileSync(tmpPath, crypto.randomBytes(32).toString("hex"), { mode: 0o600, flag: "wx" });
    try {
      fs.linkSync(tmpPath, secretPath);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
    } finally {
      fs.unlinkSync(tmpPath);
    }
  }
  const hex = fs.readFileSync(secretPath, "utf8").trim();
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    throw new Error(`Operator session secret at '${secretPath}' is malformed`);
  }
  return Buffer.from(hex, "hex");
}

export interface PendingGateReviewEnvelope {
  readonly card: SanitizedGateCardPayload;
  readonly action_nonce: string;
  readonly synthetic_only: boolean;
  readonly data_origin: DataOrigin;
}

export interface AuditedDecisionLogRecord {
  readonly decision_id: string;
  readonly hunt_id: string;
  readonly gate: string;
  readonly action: "approve" | "reject";
  readonly via: GateChannel;
  readonly authenticated_principal: string;
  readonly decided_by: string;
  readonly rbac_role: string;
  readonly payload_sha256: string;
  readonly decided_at: string;
  readonly expires_at: string;
  readonly check_note?: string;
  readonly note_sha256?: string;
  readonly delegated_by?: string;
  readonly delegation_reason?: string;
}

/**
 * Appends a single JSONL line atomically using OS append mode (`flag: "a"` -> `FILE_APPEND_DATA` on Win32,
 * `O_APPEND` on POSIX) + `fsyncSync`.
 */
export function appendDecisionLogAtomic(
  decisionsLogPath: string,
  record: AuditedDecisionLogRecord,
): void {
  fs.mkdirSync(path.dirname(decisionsLogPath), { recursive: true });
  const line = `${JSON.stringify(record)}\n`;
  const buf = Buffer.from(line, "utf8");
  const fd = fs.openSync(decisionsLogPath, "a", 0o600);
  try {
    fs.writeSync(fd, buf, 0, buf.byteLength);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

export interface GateAuthorityOptions {
  readonly stateStore: DurableStateStore;
  readonly decisionsDir: string;
  readonly decisionsLogPath?: string;
  readonly egressGuard?: EgressGuardPort;
  readonly sessionAuthority?: OperatorSessionAuthority;
  readonly productionMode?: boolean;
}

export interface SubmitGateDecisionInput {
  readonly decisionId?: string;
  readonly huntId: string;
  readonly gate: string;
  readonly action: "approve" | "reject";
  readonly via: GateChannel;
  readonly authenticatedPrincipal?: string;
  readonly rbacRole?: string;
  readonly operatorToken?: string;
  readonly payloadSha256: string;
  readonly checkNote?: string;
  readonly delegatedBy?: string;
  readonly delegationReason?: string;
  readonly nowMs?: number;
}

export class GateAuthority {
  public readonly decisionsDir: string;
  public readonly pendingDir: string;
  public readonly claimedDir: string;
  public readonly decisionsLogPath: string;
  public readonly egressGuard: EgressGuardPort;
  public readonly sessionAuthority: OperatorSessionAuthority;
  public readonly productionMode: boolean;
  private readonly stateStore: DurableStateStore;

  constructor(options: GateAuthorityOptions) {
    this.stateStore = options.stateStore;
    this.decisionsDir = path.resolve(options.decisionsDir);
    this.pendingDir = path.join(this.decisionsDir, "pending");
    this.claimedDir = path.join(this.decisionsDir, "claimed");
    this.decisionsLogPath = options.decisionsLogPath
      ? path.resolve(options.decisionsLogPath)
      : path.join(this.decisionsDir, "decisions.jsonl");
    this.egressGuard = options.egressGuard ?? new StrictEgressGuard();
    this.sessionAuthority = options.sessionAuthority ?? new OperatorSessionAuthority();
    this.productionMode = options.productionMode ?? true;

    fs.mkdirSync(this.pendingDir, { recursive: true });
    fs.mkdirSync(this.claimedDir, { recursive: true });
  }

  public openGate(params: {
    huntId: string;
    caseId: string;
    wave: HuntWave;
    gate: string;
    statusEnum: string;
    gatedPayload: unknown;
    syntheticOnly: boolean;
    dataOrigin: DataOrigin;
    handoff?: Handoff | null;
    reasonCode?: string | null;
    unknownStepId?: string;
    ttlMs?: number;
    nowMs?: number;
  }): { openGate: OpenGateState; reviewEnvelope: PendingGateReviewEnvelope } {
    const now = params.nowMs ?? Date.now();
    const openedAt = new Date(now).toISOString();
    const expiresAt = new Date(now + (params.ttlMs ?? DEFAULT_GATE_TTL_MS)).toISOString();
    const payloadSha256 = computeCanonicalSha256(params.gatedPayload);
    const requiresHuman = requiresHumanDecision(params.gate);

    const sanitizedCard = this.egressGuard.sanitizeGateCard({
      huntId: params.huntId,
      caseId: params.caseId,
      wave: params.wave,
      gateKind: params.gate,
      statusEnum: params.statusEnum,
      openedAtUtc: openedAt,
      expiresAtUtc: expiresAt,
      payloadSha256,
      reasonCode: params.reasonCode ?? null,
      syntheticOnly: params.syntheticOnly,
      handoff: params.handoff ?? null,
    });

    const actionNonce = crypto.randomBytes(16).toString("hex");
    const reviewEnvelope: PendingGateReviewEnvelope = {
      card: sanitizedCard,
      action_nonce: actionNonce,
      synthetic_only: params.syntheticOnly,
      data_origin: params.dataOrigin,
    };

    const safeHunt = params.huntId.replace(/[^A-Za-z0-9_.-]/g, "_");
    const safeGate = params.gate.replace(/[^A-Za-z0-9_.-]/g, "_");
    const digestShort = payloadSha256.slice(0, 12);
    const fileName = `${safeHunt}__${safeGate}__${digestShort}__review.json`;
    const reviewFilePath = path.join(this.pendingDir, fileName);
    const tmpPath = `${reviewFilePath}.tmp.${process.pid}.${crypto.randomBytes(4).toString("hex")}`;
    fs.writeFileSync(tmpPath, `${JSON.stringify(reviewEnvelope, null, 2)}\n`, {
      encoding: "utf8",
      mode: 0o600,
    });
    fs.renameSync(tmpPath, reviewFilePath);

    const openGate: OpenGateState = {
      gate: params.gate,
      wave: params.wave,
      requires_human: requiresHuman,
      payload_sha256: payloadSha256,
      opened_at: openedAt,
      expires_at: expiresAt,
      reason_code: params.reasonCode ?? undefined,
      unknown_step_id: params.unknownStepId,
      // Explicitly clears any check-note state between Gate 1 (scope) and Gate 2 (incident)
      check_note_cleared: true,
      review_file_path: reviewFilePath,
    };

    return { openGate, reviewEnvelope };
  }

  public removeReviewArtifacts(openGate: OpenGateState | null): void {
    if (!openGate?.review_file_path) return;
    const baseName = path.basename(openGate.review_file_path);
    for (const dir of [this.pendingDir, this.claimedDir]) {
      const candidate = path.join(dir, baseName);
      try {
        if (fs.existsSync(candidate)) {
          fs.unlinkSync(candidate);
        }
      } catch {
        // Best-effort cleanup
      }
    }
  }

  /**
   * Standalone validate + record (no run row). The wave engine instead uses `validateDecision`
   * followed by the atomic `DurableStateStore.commitGateDecision` and `finalizeCommittedDecision`.
   */
  public validateAndRecordDecision(
    openGate: OpenGateState | null,
    input: SubmitGateDecisionInput,
  ): { decision: AuthenticatedGateDecision; auditRecord: AuditedDecisionLogRecord } {
    const validated = this.validateDecision(openGate, input);
    // Atomic replay protection in SQLite BEFORE appending to decisions.jsonl
    const unique = this.stateStore.recordUniqueDecisionId(validated.decision);
    if (!unique) {
      throw new GateDecisionError(
        "decision_id_replayed",
        `Replay blocked: decision_id '${validated.decision.decision_id}' has already been consumed`,
      );
    }
    this.finalizeCommittedDecision(openGate, validated.auditRecord);
    return validated;
  }

  /** Appends the audit record and removes review artifacts AFTER the decision is committed. */
  public finalizeCommittedDecision(
    openGate: OpenGateState | null,
    auditRecord: AuditedDecisionLogRecord,
  ): void {
    appendDecisionLogAtomic(this.decisionsLogPath, auditRecord);
    this.removeReviewArtifacts(openGate);
  }

  /** Pure validation: authenticates, checks RBAC/digest/expiry/note, and builds the records. */
  public validateDecision(
    openGate: OpenGateState | null,
    input: SubmitGateDecisionInput,
  ): { decision: AuthenticatedGateDecision; auditRecord: AuditedDecisionLogRecord } {
    if (!openGate || openGate.gate !== input.gate) {
      throw new GateDecisionError(
        "gate_not_open",
        `Gate '${input.gate}' is not currently open on hunt '${input.huntId}'`,
      );
    }

    const nowMs = input.nowMs ?? Date.now();
    const isHumanGate =
      requiresHumanDecision(input.gate) ||
      openGate.requires_human ||
      input.gate === RECONCILE_GATE;

    // Principal + RBAC role come ONLY from a verified operatorToken, except for the in-process
    // Slack bridge (`via: "slack"`), which authenticates via its allowlisted user.id itself.
    let principal: string;
    let rbacRole: string;
    if (input.via === "slack") {
      principal = input.authenticatedPrincipal?.trim() ?? "";
      rbacRole = input.rbacRole?.trim() ?? "";
    } else {
      if (!input.operatorToken) {
        throw new GateDecisionError(
          "invalid_operator_token",
          `A verified operator_token is required for gate decisions via='${input.via}'`,
        );
      }
      const verified = this.sessionAuthority.verifyToken(input.operatorToken, nowMs);
      principal = verified.principal;
      rbacRole = verified.rbacRole;
    }

    if (!principal) {
      throw new GateDecisionError(
        "invalid_gate_decision",
        "authenticated_principal is required for gate decisions",
      );
    }

    if (isHumanGate && input.via === "automated") {
      throw new GateDecisionError(
        "automated_channel_forbidden",
        `Human gate '${input.gate}' rejects via='automated'`,
      );
    }

    if (input.delegatedBy && isHumanGate && this.productionMode) {
      throw new GateDecisionError(
        "automated_channel_forbidden",
        `Delegated non-human mode is forbidden on human gate '${input.gate}' in production`,
      );
    }

    if (!canRoleDecideGate(rbacRole)) {
      throw new GateDecisionError(
        "rbac_denied",
        `RBAC role '${rbacRole || "none"}' is not authorized to approve or reject gates`,
      );
    }

    const expiresMs = Date.parse(openGate.expires_at);
    if (Number.isNaN(expiresMs) || nowMs > expiresMs) {
      throw new GateDecisionError(
        "gate_expired",
        `Gate '${input.gate}' expired at ${openGate.expires_at}`,
      );
    }

    if (input.payloadSha256.trim().toLowerCase() !== openGate.payload_sha256.toLowerCase()) {
      throw new GateDecisionError(
        "payload_digest_mismatch",
        `payload_sha256 mismatch for gate '${input.gate}' (expected ${openGate.payload_sha256})`,
      );
    }

    const trimmedNote = input.checkNote !== undefined ? input.checkNote.trim() : "";
    let scrubbedNote: string | undefined;
    let noteSha256: string | undefined;

    if (isHumanGate) {
      if (trimmedNote.length < 1) {
        throw new GateDecisionError(
          "check_note_required",
          `Human gate '${input.gate}' requires a non-empty check_note (1..${MAX_CHECK_NOTE_CHARS} chars)`,
        );
      }
      if (trimmedNote.length > MAX_CHECK_NOTE_CHARS) {
        throw new GateDecisionError(
          "check_note_too_long",
          `check_note exceeds ${MAX_CHECK_NOTE_CHARS} characters (${trimmedNote.length} chars)`,
        );
      }
      scrubbedNote = scrubCredentials(trimmedNote);
      noteSha256 = crypto.createHash("sha256").update(trimmedNote, "utf8").digest("hex");
    } else if (trimmedNote.length > 0) {
      if (trimmedNote.length > MAX_CHECK_NOTE_CHARS) {
        throw new GateDecisionError(
          "check_note_too_long",
          `check_note exceeds ${MAX_CHECK_NOTE_CHARS} characters`,
        );
      }
      scrubbedNote = scrubCredentials(trimmedNote);
      noteSha256 = crypto.createHash("sha256").update(trimmedNote, "utf8").digest("hex");
    }

    const decisionId = input.decisionId?.trim() || `dec-${crypto.randomUUID()}`;
    const decidedAt = new Date(nowMs).toISOString();

    const candidateDecision = {
      decision_id: decisionId,
      hunt_id: input.huntId,
      gate: input.gate,
      action: input.action,
      via: input.via,
      decided_by: principal,
      rbac_role: rbacRole,
      payload_sha256: openGate.payload_sha256,
      decided_at: decidedAt,
      expires_at: openGate.expires_at,
      ...(scrubbedNote !== undefined ? { note: scrubbedNote } : {}),
    };

    const parsed = AuthenticatedGateDecisionSchema.safeParse(candidateDecision);
    if (!parsed.success) {
      const issue = parsed.error.issues[0];
      throw new GateDecisionError(
        "invalid_gate_decision",
        `Invalid gate decision (${issue?.path.join(".") || "root"}): ${issue?.message ?? "validation failed"}`,
      );
    }

    const auditRecord: AuditedDecisionLogRecord = {
      decision_id: parsed.data.decision_id,
      hunt_id: parsed.data.hunt_id,
      gate: parsed.data.gate,
      action: parsed.data.action,
      via: parsed.data.via,
      authenticated_principal: principal,
      decided_by: principal,
      rbac_role: rbacRole,
      payload_sha256: parsed.data.payload_sha256,
      decided_at: parsed.data.decided_at,
      expires_at: parsed.data.expires_at,
      ...(scrubbedNote !== undefined ? { check_note: scrubbedNote } : {}),
      ...(noteSha256 !== undefined ? { note_sha256: noteSha256 } : {}),
      ...(input.delegatedBy ? { delegated_by: input.delegatedBy } : {}),
      ...(input.delegationReason ? { delegation_reason: input.delegationReason } : {}),
    };

    return { decision: parsed.data, auditRecord };
  }
}
