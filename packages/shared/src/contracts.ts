import { z } from "zod";

export const DATA_ORIGINS = [
  "synthetic",
  "public-dataset",
  "work-export",
  "work-connected",
] as const;

export type DataOrigin = (typeof DATA_ORIGINS)[number];
export const DataOriginSchema = z.enum(DATA_ORIGINS);

export function isSyntheticDataOrigin(origin: DataOrigin): boolean {
  return origin === "synthetic";
}

export const AGENT_ROLES = [
  "coordinator",
  "threat_hunter",
  "host_analyst",
  "network_analyst",
  "intel_analyst",
  "detection_engineer",
] as const;

export type AgentRole = (typeof AGENT_ROLES)[number];
export const AgentRoleSchema = z.enum(AGENT_ROLES);

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
export const DataPlaneToolNameSchema = z.enum(DATA_PLANE_TOOLS);

export const DAEMON_META_TOOLS = ["hunt_lab_batch", "delegate_task"] as const;
export type DaemonMetaToolName = (typeof DAEMON_META_TOOLS)[number];

export const ROLE_TOOL_OWNERSHIP: Readonly<Record<AgentRole, readonly DataPlaneToolName[]>> = {
  coordinator: [],
  threat_hunter: ["elastic_search", "elastic_aggregate", "hunt_lab_query", "lab_browser"],
  host_analyst: ["elastic_search", "elastic_aggregate", "hunt_lab_query"],
  network_analyst: [
    "arkime_sessions",
    "arkime_unique",
    "hunt_lab_query",
    "lab_browser",
    "packet_fields",
  ],
  intel_analyst: ["intel_lookup", "elastic_search", "elastic_aggregate", "hunt_lab_query"],
  detection_engineer: ["detection_test", "elastic_search", "elastic_aggregate", "hunt_lab_query"],
} as const;

export const DATA_PLANE_ERROR_CODES = [
  "tool_not_owned",
  "read_only",
  "leading_wildcard_not_supported",
  "field_not_allowed",
  "field_unavailable",
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

export function canRoleUseTool(role: AgentRole, tool: DataPlaneToolName): boolean {
  return ROLE_TOOL_OWNERSHIP[role].includes(tool);
}

export function assertRoleOwnsTool(role: AgentRole, tool: DataPlaneToolName): void {
  if (!canRoleUseTool(role, tool)) {
    throw new DataPlaneAccessError(
      403,
      "tool_not_owned",
      `Role '${role}' does not own tool '${tool}'`,
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
  "triage",
  "evidence",
  "network",
  "follow",
  "detection",
  "merge",
  "incident",
] as const;

export type HuntWave = (typeof HUNT_WAVES)[number];
export const HuntWaveSchema = z.enum(HUNT_WAVES);

export const MAX_PROMPT_BYTES = 65_536;
export const MAX_TOOL_RESULT_BYTES = 24_576;
export const MAX_STAGE_GUIDANCE_BYTES = 600;
export const MIN_SHARED_CACHE_HEADER_CHARS = 25;
export const MAX_CONCURRENT_HUNTS = 5;

export const PACKET_FIELDS_REDACTED_QUERY = "?[redacted]" as const;

export const ADR0003_PACKET_FIELD_ALLOWLIST = [
  "frame.number",
  "frame.time_epoch",
  "frame.len",
  "ip.src",
  "ip.dst",
  "ipv6.src",
  "ipv6.dst",
  "tcp.srcport",
  "tcp.dstport",
  "tcp.flags",
  "udp.srcport",
  "udp.dstport",
  "dns.qry.name",
  "dns.qry.type",
  "dns.a",
  "dns.aaaa",
  "dns.cname",
  "dns.txt",
  "dns.flags.rcode",
  "tls.handshake.extensions_server_name",
  "tls.handshake.version",
  "tls.ja3",
  "tls.ja4",
  "http.request.method",
  "http.host",
  "http.request.uri",
  "http.user_agent",
  "http.response.code",
] as const;

export type AllowedPacketField = (typeof ADR0003_PACKET_FIELD_ALLOWLIST)[number];

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

const RAW_EVIDENCE_ID_PREFIX_RE = /^(?:evt|frame|ioc)-/i;

export const ClaimSchema = z.object({
  claim_id: z.string().min(1),
  wave: HuntWaveSchema,
  author_role: AgentRoleSchema,
  statement: z.string().min(1),
  evidence_ids: z
    .array(
      z
        .string()
        .min(1)
        .refine(
          (id) => !RAW_EVIDENCE_ID_PREFIX_RE.test(id),
          "claim.evidence_ids must contain source_id values (e.g. 'lab-case-001'), not raw evt-*/frame-*/ioc-* citations",
        ),
    )
    .min(1),
  entities: z.array(z.string().min(1)),
  confidence: z.enum(["high", "medium", "low"]),
  limitations: z.array(z.string()).optional(),
});

export type Claim = z.infer<typeof ClaimSchema>;

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
export type HumanGateName = (typeof HUMAN_GATES)[number];
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
