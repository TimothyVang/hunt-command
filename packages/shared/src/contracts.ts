import { z } from "zod";

export const DATA_ORIGINS = [
  "synthetic",
  "public-dataset",
  "work-export",
  "work-connected",
] as const;

export type DataOrigin = (typeof DATA_ORIGINS)[number];
export const DataOriginSchema = z.enum(DATA_ORIGINS);

export const REAL_DATA_ORIGIN_LABELS: Readonly<
  Record<Exclude<DataOrigin, "synthetic">, readonly [name: string, detail: string]>
> = {
  "public-dataset": ["public research dataset", "real lab telemetry, no customer data"],
  "work-export": [
    "work log export",
    "real telemetry from the operator's environment; unclassified work data",
  ],
  "work-connected": [
    "work log connection",
    "live read-only queries of the operator's work Elastic; unclassified work data",
  ],
} as const;

export function formatRealDataOriginText(origin: Exclude<DataOrigin, "synthetic">): string {
  const [name, detail] = REAL_DATA_ORIGIN_LABELS[origin];
  return `${name} (${detail})`;
}

export const FRAMEWORK_PROFILES = [
  "framework-coordinator",
  "framework-researcher",
  "framework-network-analyst",
  "framework-librarian",
  "framework-builder",
  "framework-reviewer",
] as const;

export type ProfileId = (typeof FRAMEWORK_PROFILES)[number];
export const ProfileIdSchema = z.enum(FRAMEWORK_PROFILES);

export const PROFILE_DISPLAY_TITLES: Readonly<Record<ProfileId, string>> = {
  "framework-coordinator": "Hunt Lead",
  "framework-researcher": "Threat Hunter",
  "framework-network-analyst": "Network Analyst",
  "framework-librarian": "Threat Intel",
  "framework-builder": "Detection & Hypotheses",
  "framework-reviewer": "Adversarial Reviewer / Purple",
} as const;

export const DATA_PLANE_TOOLS = [
  "elastic_search",
  "elastic_aggregate",
  "detection_test",
  "intel_lookup",
  "arkime_sessions",
  "arkime_unique",
  "packet_fields",
  "hunt_lab_query",
  "lab_browser",
] as const;

export type DataPlaneToolName = (typeof DATA_PLANE_TOOLS)[number];

export const DAEMON_META_TOOLS = ["hunt_lab_batch", "delegate_task"] as const;

export const ALL_HUNT_TOOLS = [...DATA_PLANE_TOOLS, ...DAEMON_META_TOOLS] as const;
export type HuntToolName = (typeof ALL_HUNT_TOOLS)[number];

export const ROLE_TOOL_OWNERSHIP: Readonly<Record<ProfileId, readonly HuntToolName[]>> = {
  "framework-coordinator": ["delegate_task"],
  "framework-researcher": [
    "elastic_search",
    "elastic_aggregate",
    "lab_browser",
    "packet_fields",
    "hunt_lab_batch",
  ],
  "framework-network-analyst": [
    "arkime_sessions",
    "arkime_unique",
    "hunt_lab_query",
    "lab_browser",
    "packet_fields",
    "hunt_lab_batch",
  ],
  "framework-librarian": ["intel_lookup", "elastic_aggregate"],
  "framework-builder": ["detection_test", "elastic_aggregate"],
  "framework-reviewer": ["elastic_search", "arkime_sessions", "detection_test"],
} as const;

export const BATCH_MAX_ITEMS = 5;
export const BATCH_MAX_ITEM_SIZE = 25;
export const BATCH_MAX_BYTES = 96 * 1024;
export const BATCH_EXCLUDED_TOOLS = [
  "packet_fields",
  "lab_browser",
  "hunt_lab_batch",
] as const;

export const DATA_PLANE_ERROR_CODES = [
  "tool_not_owned",
  "read_only",
  "leading_wildcard_not_supported",
  "field_not_allowed",
  "invalid_field_list",
  "field_unavailable",
  "invalid_query",
  "invalid_filter",
  "no_network_capture",
  "ambiguous_lab",
  "unauthorized_instance",
  "leaked_api_key_in_env",
  "origin_not_allowed",
  "case_origin_mismatch",
] as const;

export type DataPlaneErrorCode = (typeof DATA_PLANE_ERROR_CODES)[number];

export class DataPlaneAccessError extends Error {
  public readonly statusCode: 400 | 403 | 405;
  public readonly errorCode: DataPlaneErrorCode;

  constructor(statusCode: 400 | 403 | 405, errorCode: DataPlaneErrorCode, message?: string) {
    super(message ?? `${statusCode} ${errorCode}`);
    this.name = "DataPlaneAccessError";
    this.statusCode = statusCode;
    this.errorCode = errorCode;
  }
}

export function getAllowedToolsForStep(profile: ProfileId, stepId?: string): readonly HuntToolName[] {
  if (profile === "framework-coordinator" && stepId === "scope") {
    return [];
  }
  return ROLE_TOOL_OWNERSHIP[profile];
}

export function canRoleUseTool(role: ProfileId, tool: HuntToolName, stepId?: string): boolean {
  return getAllowedToolsForStep(role, stepId).includes(tool);
}

export function assertRoleOwnsTool(role: ProfileId, tool: HuntToolName, stepId?: string): void {
  if (!canRoleUseTool(role, tool, stepId)) {
    throw new DataPlaneAccessError(
      403,
      "tool_not_owned",
      `Profile '${role}'${stepId ? ` (step '${stepId}')` : ""} does not own tool '${tool}'`,
    );
  }
}

export function assertReadOnlyOperation(isMutating: boolean): void {
  if (isMutating) {
    throw new DataPlaneAccessError(405, "read_only", "Mutating operations are prohibited");
  }
}

export const HUNT_WAVES = [
  "scope",
  "investigation",
  "analysis",
  "follow_up",
  "merge",
  "detection",
  "purple",
  "incident",
] as const;

export type HuntWave = (typeof HUNT_WAVES)[number];

export const WAVE_GATE_IDS = [
  "wave-1",
  "wave-2",
  "wave-3",
  "wave-4",
  "wave-5",
  "wave-6",
  "wave-7",
  "wave-8",
] as const;

export type WaveGateId = (typeof WAVE_GATE_IDS)[number];

export const STAGE_IDS = [
  "scope",
  "evidence",
  "hypotheses",
  "network",
  "intel",
  "analysis",
  "follow",
  "merge",
  "detection",
  "purple",
  "incident",
] as const;

export type StageId = (typeof STAGE_IDS)[number];

export const STEP_STATES = [
  "not_reached",
  "awaiting_approval",
  "working",
  "awaiting_review",
  "done",
  "dropped",
  "stopped",
] as const;

export type StepState = (typeof STEP_STATES)[number];

export const DEFAULT_FOLLOW_UPS = 6;
export const MAX_FOLLOW_UPS = 12;
export const MAX_DELEGATED_QUESTIONS = 3;

export interface WaveDefinition {
  readonly waveNumber: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8;
  readonly waveGateId: WaveGateId;
  readonly wave: HuntWave;
  readonly humanGate: "scope" | "incident" | null;
  readonly optional: boolean;
  readonly defaultSteps: ReadonlyArray<{
    readonly stepIdPattern: string;
    readonly profile: ProfileId;
  }>;
}

export const HUNT_WAVE_TOPOLOGY: readonly WaveDefinition[] = [
  {
    waveNumber: 1,
    waveGateId: "wave-1",
    wave: "scope",
    humanGate: "scope",
    optional: false,
    defaultSteps: [{ stepIdPattern: "scope", profile: "framework-coordinator" }],
  },
  {
    waveNumber: 2,
    waveGateId: "wave-2",
    wave: "investigation",
    humanGate: null,
    optional: true,
    defaultSteps: [
      { stepIdPattern: "evidence", profile: "framework-researcher" },
      { stepIdPattern: "hypotheses", profile: "framework-builder" },
      { stepIdPattern: "network", profile: "framework-network-analyst" },
      { stepIdPattern: "intel", profile: "framework-librarian" },
    ],
  },
  {
    waveNumber: 3,
    waveGateId: "wave-3",
    wave: "analysis",
    humanGate: null,
    optional: false,
    defaultSteps: [{ stepIdPattern: "analysis", profile: "framework-coordinator" }],
  },
  {
    waveNumber: 4,
    waveGateId: "wave-4",
    wave: "follow_up",
    humanGate: null,
    optional: true,
    defaultSteps: [{ stepIdPattern: "follow-1..K", profile: "framework-researcher" }],
  },
  {
    waveNumber: 5,
    waveGateId: "wave-5",
    wave: "merge",
    humanGate: null,
    optional: true,
    defaultSteps: [{ stepIdPattern: "merge", profile: "framework-coordinator" }],
  },
  {
    waveNumber: 6,
    waveGateId: "wave-6",
    wave: "detection",
    humanGate: null,
    optional: false,
    defaultSteps: [{ stepIdPattern: "detection", profile: "framework-builder" }],
  },
  {
    waveNumber: 7,
    waveGateId: "wave-7",
    wave: "purple",
    humanGate: null,
    optional: false,
    defaultSteps: [{ stepIdPattern: "purple", profile: "framework-reviewer" }],
  },
  {
    waveNumber: 8,
    waveGateId: "wave-8",
    wave: "incident",
    humanGate: "incident",
    optional: false,
    defaultSteps: [{ stepIdPattern: "incident", profile: "framework-coordinator" }],
  },
] as const;

export const MAX_PROMPT_BYTES = 65_536;
export const MAX_SNAPSHOT_BYTES = 32_768;
export const MAX_HANDOFF_BYTES = 16_384;
export const MAX_PREDECESSORS = 16;
export const MAX_TOOL_RESULT_BYTES = 24_576;
export const MAX_STAGE_GUIDANCE_BYTES = 600;
export const MIN_SHARED_CACHE_HEADER_CHARS = 25;
export const MAX_CONCURRENT_HUNTS = 5;

export const ENTITY_KINDS = [
  "host",
  "account",
  "address",
  "domain",
  "key",
  "process",
  "session",
  "service",
  "resource",
] as const;

export type EntityKind = (typeof ENTITY_KINDS)[number];
export const EntityKindSchema = z.enum(ENTITY_KINDS);

export const PREDICATES = [
  "associated_with",
  "observed_on",
  "communicates_with",
  "resolves_to",
  "spawned",
] as const;

export const PredicateSchema = z.enum(PREDICATES);

export const CLAIM_KINDS = ["observed", "inference", "hypothesis", "finding"] as const;
export type ClaimKind = (typeof CLAIM_KINDS)[number];
export const ClaimKindSchema = z.enum(CLAIM_KINDS);

export const DISPOSITIONS = ["needs_revision", "needs_validation", "review_ready"] as const;
export const DispositionSchema = z.enum(DISPOSITIONS);

export const SAFE_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
export const SAFE_CLAIM_OR_REVIEW_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$/;
export const STEP_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
const RAW_EVIDENCE_ID_PREFIX_RE = /^(?:evt|frame|ioc)-/i;

function hasUniqueItems(items: readonly string[]): boolean {
  return new Set(items).size === items.length;
}

const SafeSourceIdSchema = z
  .string()
  .regex(SAFE_ID_RE, "Invalid identifier")
  .refine(
    (id) => !RAW_EVIDENCE_ID_PREFIX_RE.test(id),
    "evidence_ids must contain supplied source_id values, never raw evt-*/frame-*/ioc-* citations",
  );

const SafeIdent128Schema = z.string().regex(SAFE_ID_RE, "Invalid identifier");
const SafeIdent192Schema = z.string().regex(SAFE_CLAIM_OR_REVIEW_ID_RE, "Invalid claim/review ID");

export const EntitySchema = z
  .object({
    entity_id: SafeIdent128Schema,
    kind: EntityKindSchema,
    label: z
      .string()
      .min(1)
      .refine((s) => s.trim().length > 0 && Buffer.byteLength(s, "utf8") <= 1024),
    evidence_ids: z
      .array(SafeSourceIdSchema)
      .min(1)
      .max(64)
      .refine(hasUniqueItems, "Duplicate evidence_ids"),
  })
  .strict();

export const RelationSchema = z
  .object({
    relation_id: SafeIdent128Schema,
    subject_id: SafeIdent128Schema,
    predicate: PredicateSchema,
    object_id: SafeIdent128Schema,
    evidence_ids: z
      .array(SafeSourceIdSchema)
      .min(1)
      .max(64)
      .refine(hasUniqueItems, "Duplicate evidence_ids"),
  })
  .strict();

export const SnapshotSchema = z
  .object({
    schema_version: z.literal(1),
    case_id: SafeIdent128Schema,
    entities: z.array(EntitySchema).max(64),
    relations: z.array(RelationSchema).max(128),
  })
  .strict()
  .superRefine((val, ctx) => {
    const entityIds = new Set<string>();
    for (const entity of val.entities) {
      if (entityIds.has(entity.entity_id)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["entities"],
          message: `Duplicate entity_id '${entity.entity_id}'`,
        });
      }
      entityIds.add(entity.entity_id);
    }

    const relationIds = new Set<string>();
    for (const rel of val.relations) {
      if (relationIds.has(rel.relation_id)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["relations"],
          message: `Duplicate relation_id '${rel.relation_id}'`,
        });
      }
      relationIds.add(rel.relation_id);

      if (!entityIds.has(rel.subject_id) || !entityIds.has(rel.object_id)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["relations"],
          message: `Relation '${rel.relation_id}' endpoint does not resolve in snapshot entities`,
        });
      }
    }
  });

export type Snapshot = z.infer<typeof SnapshotSchema>;

export const ClaimSchema = z
  .object({
    claim_id: SafeIdent192Schema,
    kind: ClaimKindSchema,
    statement: z
      .string()
      .min(1)
      .refine((s) => s.trim().length > 0 && Buffer.byteLength(s, "utf8") <= 2048),
    evidence_ids: z
      .array(SafeSourceIdSchema)
      .min(1)
      .max(32)
      .refine(hasUniqueItems, "Duplicate evidence_ids"),
    entity_ids: z
      .array(SafeIdent128Schema)
      .max(64)
      .refine(hasUniqueItems, "Duplicate entity_ids"),
    contradicts: z
      .array(SafeIdent192Schema)
      .max(32)
      .refine(hasUniqueItems, "Duplicate contradicts IDs"),
  })
  .strict()
  .superRefine((val, ctx) => {
    if (val.contradicts.includes(val.claim_id)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["contradicts"],
        message: "Claim cannot contradict itself",
      });
    }
  });

export type Claim = z.infer<typeof ClaimSchema>;

export const ReviewSchema = z
  .object({
    review_id: SafeIdent192Schema,
    claim_ids: z
      .array(SafeIdent192Schema)
      .min(1)
      .max(32)
      .refine(hasUniqueItems, "Duplicate claim_ids"),
    disposition: DispositionSchema,
    rationale: z
      .string()
      .min(1)
      .refine((s) => s.trim().length > 0 && Buffer.byteLength(s, "utf8") <= 2048),
    evidence_ids: z
      .array(SafeSourceIdSchema)
      .max(32)
      .refine(hasUniqueItems, "Duplicate evidence_ids"),
  })
  .strict();

export type Review = z.infer<typeof ReviewSchema>;

const BoundedNoteSchema = z
  .string()
  .min(1)
  .refine((s) => s.trim().length > 0 && Buffer.byteLength(s, "utf8") <= 512);

export const HandoffSchema = z
  .object({
    schema_version: z.literal(1),
    case_id: SafeIdent128Schema,
    step_id: z.string().regex(STEP_ID_RE, "Invalid step_id"),
    profile: ProfileIdSchema,
    claims: z.array(ClaimSchema).max(16),
    reviews: z.array(ReviewSchema).max(16),
    disposition: DispositionSchema,
    limitations: z.array(BoundedNoteSchema).max(16),
    requested_decisions: z.array(BoundedNoteSchema).max(16),
  })
  .strict()
  .superRefine((val, ctx) => {
    if (val.profile !== "framework-reviewer" && val.reviews.length > 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["reviews"],
        message: "Only framework-reviewer may supply reviews",
      });
    }

    const prefix = `${val.step_id}:`;
    const claimIds = new Set<string>();
    for (const claim of val.claims) {
      if (!claim.claim_id.startsWith(prefix)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["claims"],
          message: `claim_id '${claim.claim_id}' must start with '${prefix}'`,
        });
      }
      if (claimIds.has(claim.claim_id)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["claims"],
          message: `Duplicate claim_id '${claim.claim_id}'`,
        });
      }
      claimIds.add(claim.claim_id);
    }

    const reviewIds = new Set<string>();
    for (const review of val.reviews) {
      if (!review.review_id.startsWith(prefix)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["reviews"],
          message: `review_id '${review.review_id}' must start with '${prefix}'`,
        });
      }
      if (reviewIds.has(review.review_id)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["reviews"],
          message: `Duplicate review_id '${review.review_id}'`,
        });
      }
      reviewIds.add(review.review_id);
    }
  });

export type Handoff = z.infer<typeof HandoffSchema>;

export const CaseMetadataSchema = z
  .object({
    case_id: z.string().min(1),
    title: z.string().min(1),
    data_origin: DataOriginSchema,
    synthetic_only: z.boolean(),
    time_window: z.object({
      start_iso: z.string().min(1),
      end_iso: z.string().min(1),
    }),
    sources: z.array(z.string().min(1)),
    pcap_relpath: z.string().min(1).optional(),
  })
  .superRefine((val, ctx) => {
    const expectedSynthetic = val.data_origin === "synthetic";
    if (val.synthetic_only !== expectedSynthetic) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["synthetic_only"],
        message: `synthetic_only must be ${expectedSynthetic} when data_origin is '${val.data_origin}'`,
      });
    }
  });

export type CaseMetadata = z.infer<typeof CaseMetadataSchema>;

export interface InlineCitationLineage {
  event_ids: string[];
  frame_ids: string[];
  ioc_ids: string[];
}

export function extractInlineCitations(statement: string): InlineCitationLineage {
  const eventSet = new Set<string>();
  const frameSet = new Set<string>();
  const iocSet = new Set<string>();

  for (const match of statement.matchAll(/\bevt-[A-Za-z0-9_-]+\b/g)) {
    eventSet.add(match[0]);
  }
  for (const match of statement.matchAll(/\bframe-\d+\b/g)) {
    frameSet.add(match[0]);
  }
  for (const match of statement.matchAll(/\bioc-\d+\b/g)) {
    iocSet.add(match[0]);
  }

  return {
    event_ids: [...eventSet],
    frame_ids: [...frameSet],
    ioc_ids: [...iocSet],
  };
}

export const HUMAN_GATES = ["scope", "incident"] as const;
export const RECONCILE_GATE = "reconcile" as const;

export const GATE_CHANNELS = ["cli", "desktop", "slack", "automated"] as const;
export type GateChannel = (typeof GATE_CHANNELS)[number];

export function requiresHumanDecision(gate: string): boolean {
  return gate === "scope" || gate === "incident" || gate === "reconcile";
}

export const AuthenticatedGateDecisionSchema = z
  .object({
    decision_id: z.string().min(1),
    hunt_id: z.string().min(1),
    gate: z.string().min(1),
    action: z.enum(["approve", "reject"]),
    via: z.enum(GATE_CHANNELS),
    decided_by: z.string().min(1),
    rbac_role: z.string().min(1),
    payload_sha256: z.string().regex(/^[a-f0-9]{64}$/i, "Expected 64-hex SHA-256 digest"),
    decided_at: z.string().min(1),
    expires_at: z.string().min(1),
    note: z.string().optional(),
  })
  .superRefine((val, ctx) => {
    if (requiresHumanDecision(val.gate) && val.via === "automated") {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["via"],
        message: `Gate '${val.gate}' requires an authenticated human decision and cannot use via='automated'`,
      });
    }
  });

export type AuthenticatedGateDecision = z.infer<typeof AuthenticatedGateDecisionSchema>;

export const RECEIPT_STATUSES = [
  "reserved",
  "completed",
  "failed",
  "previous_dispatch_unknown",
] as const;

export type ReceiptStatus = (typeof RECEIPT_STATUSES)[number];

export type EgressCardMode = "full_synthetic" | "id_and_status_only";

export function resolveEgressCardMode(syntheticOnly: boolean): EgressCardMode {
  return syntheticOnly ? "full_synthetic" : "id_and_status_only";
}

export const ModelRefusalReportSchema = z.object({
  refused: z.boolean(),
  finish_reason: z.string().optional(),
  category: z.string().optional(),
  diagnostic: z.string().optional(),
});

export type ModelRefusalReport = z.infer<typeof ModelRefusalReportSchema>;

export const RpcRequestSchema = z.object({
  jsonrpc: z.literal("2.0"),
  id: z.union([z.string(), z.number()]),
  method: z.string().min(1),
  params: z.record(z.string(), z.unknown()).optional(),
});

export type RpcRequest = z.infer<typeof RpcRequestSchema>;

export const RpcResponseSchema = z.object({
  jsonrpc: z.literal("2.0"),
  id: z.union([z.string(), z.number()]),
  result: z.unknown().optional(),
  error: z
    .object({
      code: z.number().int(),
      message: z.string(),
      error_code: z.string().optional(),
    })
    .optional(),
});

export type RpcResponse = z.infer<typeof RpcResponseSchema>;

export const RpcEventNotificationSchema = z.object({
  jsonrpc: z.literal("2.0"),
  method: z.literal("hunt.event"),
  params: z.object({
    hunt_id: z.string().min(1),
    seq: z.number().int().nonnegative(),
    ts: z.string().min(1),
    type: z.string().min(1),
    payload: z.record(z.string(), z.unknown()),
  }),
});

export type RpcEventNotification = z.infer<typeof RpcEventNotificationSchema>;
