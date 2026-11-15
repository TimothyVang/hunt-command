import {
  type DataOrigin,
  DataOriginSchema,
  HUNT_WAVES,
  type HuntWave,
  SAFE_ID_RE,
} from "@hunt-command/shared";
import { scrubSecrets, truncateUtf8Safe } from "./scrubber.ts";

export const EGRESS_GATE_KINDS = ["scope", "wave", "incident", "reconcile"] as const;
export type EgressGateKind = (typeof EGRESS_GATE_KINDS)[number];

export const EGRESS_STATUS_ENUMS = [
  "awaiting_approval",
  "approved",
  "rejected",
  "running",
  "completed",
  "halted",
  "reconcile_required",
  "failed",
] as const;
export type EgressStatusEnum = (typeof EGRESS_STATUS_ENUMS)[number];

export const EGRESS_REASON_CODES = ["awaiting_human_scope", "incident_threshold_met"] as const;
export type EgressReasonCode = (typeof EGRESS_REASON_CODES)[number];

// UUID v4 is random: unlike host-derived IDs or UUID v1, it carries no work identifier.
const OPAQUE_HUNT_UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const STRICT_UTC_ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const NON_SYNTHETIC_FILM_BANNER = "NON-SYNTHETIC — OPERATOR LOCAL ONLY" as const;
const NON_SYNTHETIC_MODAL_WARNING =
  "WARNING: NON-SYNTHETIC DATA — Do NOT enter hostnames, usernames, IPs, domains, file paths, or raw log values into external notifications." as const;

export interface EgressTokenCostCounters {
  input_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
  output_tokens: number;
  total_tokens: number;
  cache_hit_ratio: number;
  actual_usd: number;
  api_equivalent_usd: number;
}

export interface EgressSourceRecord {
  hunt_uuid: string;
  data_origin: DataOrigin;
  synthetic_only: boolean;
  wave: HuntWave;
  gate_kind: EgressGateKind;
  status_enum: EgressStatusEnum;
  opened_at_utc: string;
  reason_code?: string | null;
  counters?: Partial<EgressTokenCostCounters>;
  // Potentially sensitive fields that MUST be stripped when !synthetic_only:
  case_id?: string;
  summary?: string;
  query_text?: string;
  messages?: unknown;
  statement?: string;
  outputs_dir?: string;
  hostnames?: readonly string[];
  ips?: readonly string[];
  domains?: readonly string[];
  citations?: readonly string[];
  [extraKey: string]: unknown;
}

export interface EgressGuardOptions {
  includeSummaryOnSynthetic?: boolean;
  maxSyntheticSummaryBytes?: number;
}

export interface RedactedWorkEgressCard {
  hunt_uuid: string;
  wave: HuntWave;
  gate_kind: EgressGateKind;
  status_enum: EgressStatusEnum;
  opened_at_utc: string;
  reason_code: EgressReasonCode | null;
  counters?: EgressTokenCostCounters;
}

export interface SyntheticEgressCard extends RedactedWorkEgressCard {
  synthetic_only: true;
  case_id?: string;
  summary?: string;
}

export type EgressPayload = RedactedWorkEgressCard | SyntheticEgressCard;

export class EgressGuardError extends Error {
  public readonly errorCode: string;

  constructor(errorCode: string, message: string) {
    super(message);
    this.name = "EgressGuardError";
    this.errorCode = errorCode;
  }
}

function sanitizeFiniteNonNegative(val: unknown): number {
  if (typeof val !== "number" || !Number.isFinite(val) || val < 0) {
    return 0;
  }
  return val;
}

function normalizeCounters(
  raw: Partial<EgressTokenCostCounters> | undefined,
): EgressTokenCostCounters | undefined {
  if (!raw) {
    return undefined;
  }
  const input = Math.trunc(sanitizeFiniteNonNegative(raw.input_tokens));
  const cacheRead = Math.trunc(sanitizeFiniteNonNegative(raw.cache_read_tokens));
  const cacheWrite = Math.trunc(sanitizeFiniteNonNegative(raw.cache_write_tokens));
  const output = Math.trunc(sanitizeFiniteNonNegative(raw.output_tokens));
  const promptTotal = input + cacheRead + cacheWrite;
  const computedTotal = promptTotal + output;
  const total =
    raw.total_tokens !== undefined
      ? Math.trunc(sanitizeFiniteNonNegative(raw.total_tokens))
      : computedTotal;
  const ratio =
    raw.cache_hit_ratio !== undefined
      ? Math.min(1, Math.max(0, sanitizeFiniteNonNegative(raw.cache_hit_ratio)))
      : promptTotal > 0
        ? Math.round((cacheRead / promptTotal) * 1e6) / 1e6
        : 0;

  return {
    input_tokens: input,
    cache_read_tokens: cacheRead,
    cache_write_tokens: cacheWrite,
    output_tokens: output,
    total_tokens: total,
    cache_hit_ratio: ratio,
    actual_usd: Math.round(sanitizeFiniteNonNegative(raw.actual_usd) * 1e8) / 1e8,
    api_equivalent_usd: Math.round(sanitizeFiniteNonNegative(raw.api_equivalent_usd) * 1e8) / 1e8,
  };
}

function looksLikeSensitiveIdentifier(id: string): boolean {
  // Reject file paths, URLs, IPv4s, or raw evt-*/ioc-*/frame-* in hunt_uuid.
  if (/[\\/]/.test(id) || /:\/\//.test(id)) return true;
  if (/^(?:evt|ioc|frame)-/i.test(id)) return true;
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(id)) return true;
  return false;
}

/**
 * Code-Level Rule 4 `EgressGuard`.
 * Inspects immutable `data_origin` + `synthetic_only` on the record itself.
 * When `!(data_origin === "synthetic" && synthetic_only === true)`, hard-strips all prose,
 * `summary`, `query_text`, `messages`, `statement`, `outputs_dir` paths, `case_id`, hostnames,
 * IPs, domains, and raw `evt-*`/`ioc-*`/`frame-*` payloads — emitting strictly allowlisted
 * `{ hunt_uuid, wave, gate_kind, status_enum, opened_at_utc, reason_code }` + aggregate counters.
 * Non-synthetic hunt IDs must be UUID v4; reason codes must come from EGRESS_REASON_CODES.
 */
export class EgressGuard {
  public static serialize(
    record: EgressSourceRecord,
    options: EgressGuardOptions = {},
  ): EgressPayload {
    const parsedOrigin = DataOriginSchema.safeParse(record.data_origin);
    if (!parsedOrigin.success) {
      throw new EgressGuardError("invalid_data_origin", "Invalid or missing record.data_origin");
    }

    // Fail-closed: BOTH provenance flags are required for synthetic-friendly identifiers.
    const trulySynthetic =
      parsedOrigin.data === "synthetic" && record.synthetic_only === true;
    const validHuntUuid =
      typeof record.hunt_uuid === "string" &&
      (trulySynthetic
        ? SAFE_ID_RE.test(record.hunt_uuid) && !looksLikeSensitiveIdentifier(record.hunt_uuid)
        : record.hunt_uuid.length === 36 && OPAQUE_HUNT_UUID_RE.test(record.hunt_uuid));
    if (!validHuntUuid) {
      throw new EgressGuardError(
        "invalid_hunt_uuid",
        "hunt_uuid must be an opaque UUID v4 for non-synthetic data, or a safe synthetic identifier",
      );
    }

    if (!(HUNT_WAVES as readonly string[]).includes(record.wave)) {
      throw new EgressGuardError("invalid_wave", `Invalid wave '${String(record.wave)}'`);
    }

    if (!(EGRESS_GATE_KINDS as readonly string[]).includes(record.gate_kind)) {
      throw new EgressGuardError(
        "invalid_gate_kind",
        `Invalid gate_kind '${String(record.gate_kind)}'`,
      );
    }

    if (!(EGRESS_STATUS_ENUMS as readonly string[]).includes(record.status_enum)) {
      throw new EgressGuardError(
        "invalid_status_enum",
        `Invalid status_enum '${String(record.status_enum)}'`,
      );
    }

    if (!STRICT_UTC_ISO_RE.test(record.opened_at_utc)) {
      throw new EgressGuardError(
        "invalid_opened_at_utc",
        "opened_at_utc must be an ISO-8601 UTC timestamp ending in Z",
      );
    }

    let safeReasonCode: EgressReasonCode | null = null;
    if (record.reason_code !== undefined && record.reason_code !== null && record.reason_code !== "") {
      const registeredReasonCode = EGRESS_REASON_CODES.find((code) => code === record.reason_code);
      if (registeredReasonCode === undefined) {
        throw new EgressGuardError(
          "invalid_reason_code",
          "reason_code must be a registered egress reason code, never free text",
        );
      }
      safeReasonCode = registeredReasonCode;
    }

    const counters = normalizeCounters(record.counters);

    if (!trulySynthetic) {
      const allowlisted: RedactedWorkEgressCard = {
        hunt_uuid: record.hunt_uuid,
        wave: record.wave,
        gate_kind: record.gate_kind,
        status_enum: record.status_enum,
        opened_at_utc: record.opened_at_utc,
        reason_code: safeReasonCode,
      };
      if (counters !== undefined) {
        allowlisted.counters = counters;
      }
      return allowlisted;
    }

    const syntheticCard: SyntheticEgressCard = {
      synthetic_only: true,
      hunt_uuid: record.hunt_uuid,
      wave: record.wave,
      gate_kind: record.gate_kind,
      status_enum: record.status_enum,
      opened_at_utc: record.opened_at_utc,
      reason_code: safeReasonCode,
    };

    if (counters !== undefined) {
      syntheticCard.counters = counters;
    }

    if (typeof record.case_id === "string" && SAFE_ID_RE.test(record.case_id)) {
      syntheticCard.case_id = record.case_id;
    }

    if (options.includeSummaryOnSynthetic === true && typeof record.summary === "string") {
      const maxBytes = options.maxSyntheticSummaryBytes ?? 1024;
      const scrubbed = scrubSecrets(record.summary);
      // Strip Windows/POSIX host directory paths even on synthetic summaries.
      const pathStripped = scrubbed.replace(/[A-Za-z]:\\[^\s"']+/g, "[REDACTED_PATH]");
      syntheticCard.summary = truncateUtf8Safe(pathStripped, maxBytes);
    }

    return syntheticCard;
  }

  public static buildGateNotificationBlocks(
    record: EgressSourceRecord,
    options: EgressGuardOptions = {},
  ): {
    payload: EgressPayload;
    warningBanner: string | null;
    text: string;
  } {
    const payload = EgressGuard.serialize(record, options);
    const isSynthetic = "synthetic_only" in payload && payload.synthetic_only === true;
    const warningBanner = isSynthetic ? null : NON_SYNTHETIC_MODAL_WARNING;

    const baseLine = `[${payload.gate_kind}] hunt=${payload.hunt_uuid} wave=${payload.wave} status=${payload.status_enum} opened=${payload.opened_at_utc}${payload.reason_code ? ` reason=${payload.reason_code}` : ""}`;
    const summaryPart =
      isSynthetic && payload.summary ? `\n${payload.summary}` : "";
    const warnPart = warningBanner ? `\n${warningBanner}` : "";

    return {
      payload,
      warningBanner,
      text: `${baseLine}${warnPart}${summaryPart}`,
    };
  }

  public static assertFilmExportAllowed(params: {
    dataOrigin: DataOrigin;
    syntheticOnly: boolean;
    allowWorkFilm?: boolean;
  }): { allowed: true; watermarkBanner: string | null } {
    const parsedOrigin = DataOriginSchema.safeParse(params.dataOrigin);
    if (!parsedOrigin.success) {
      throw new EgressGuardError("invalid_data_origin", "Invalid dataOrigin for film check");
    }
    const isSynthetic = parsedOrigin.data === "synthetic" && params.syntheticOnly === true;
    if (!isSynthetic && params.allowWorkFilm !== true) {
      throw new EgressGuardError(
        "work_film_not_allowed",
        "Refusing .mp4/.ass film capture on non-synthetic case without explicit allowWorkFilm=true",
      );
    }
    return {
      allowed: true,
      watermarkBanner: isSynthetic ? null : NON_SYNTHETIC_FILM_BANNER,
    };
  }
}

export function guardEgress(
  record: EgressSourceRecord,
  options?: EgressGuardOptions,
): EgressPayload {
  return EgressGuard.serialize(record, options);
}
