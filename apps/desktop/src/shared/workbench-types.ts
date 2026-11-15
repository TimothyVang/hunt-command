import type {
  AuthenticatedGateDecision,
  CaseMetadata,
  Claim,
  Handoff,
  HuntToolName,
  HuntWave,
  ModelRefusalReport,
  ProfileId,
  Review,
  Snapshot,
  StepState,
} from "@hunt-command/shared";

export type GanttSpanKind =
  | "hunt.run"
  | "hunt.wave"
  | "hunt.bot.step"
  | "gen_ai.chat"
  | "gen_ai.execute_tool"
  | "hunt.handoff.validate"
  | "hunt.gate.decision";

export interface GanttSpanRecord {
  spanId: string;
  parentSpanId: string | null;
  kind: GanttSpanKind;
  waveNumber: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8;
  wave: HuntWave;
  stepId: string;
  profile: ProfileId | null;
  label: string;
  startEpochMs: number;
  endEpochMs: number;
  durationMs: number;
  status: "ok" | "running" | "error" | "refused" | "blocked";
  model?: string;
  inputTokens?: number;
  outputTokens?: number;
  cacheReadTokens?: number;
  cacheWriteTokens?: number;
  cacheHitRatio?: number;
  toolName?: HuntToolName;
  queryPreview?: string;
  resultCount?: number;
  totalHits?: number;
  errorCode?: string;
  citedIds?: string[];
  handoffBytes?: number;
  isRetry?: boolean;
  gateVia?: "desktop" | "cli" | "slack" | "automated";
  refusal?: ModelRefusalReport;
}

export interface StepExecutionSummary {
  stepId: string;
  waveNumber: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8;
  wave: HuntWave;
  profile: ProfileId;
  state: StepState;
  reasonCode?: string;
  model: string;
  turnsUsed: number;
  maxTurns: number;
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
  totalTokens: number;
  handoffBytes?: number;
  mergeFallbackApplied?: boolean;
  refusal?: ModelRefusalReport;
  startedAtIso?: string;
  endedAtIso?: string;
}

export interface CitationStatusEntry {
  citationId: string;
  kind: "evt" | "frame" | "ioc";
  status: "verified" | "unresolved" | "out_of_scope";
  referencedIn: ReadonlyArray<{
    sourceKind: "claim" | "limitation";
    sourceId: string;
    stepId: string;
  }>;
  timestampIso?: string;
  summary?: string;
}

export interface CitationVerificationReceipt {
  totalCited: number;
  verifiedCount: number;
  unresolvedCount: number;
  outOfScopeCount: number;
  allVerified: boolean;
  entries: CitationStatusEntry[];
}

/** Reconcile gate after a crash: a step dispatch was reserved but its outcome is unknown. */
export interface ReconcileDispatchContext {
  executionId: string;
  sessionId: string;
  inputId: string;
  stepId: string;
  profile: ProfileId;
  reservedAtIso: string;
  reasonCode: "previous_dispatch_unknown";
  /** Further reserved-but-unknown dispatches beyond the one shown. */
  additionalReceiptCount?: number;
  affectedStep?: ReconcileAffectedStep;
}

/**
 * The step a reconcile gate decides, as the daemon engine resolves it (`planGateTransition`):
 * approving drops an optional step (`reconcile_drop`) or fails the run for a required one (`reconcile_halt`).
 */
export interface ReconcileAffectedStep {
  stepId: string;
  profile: ProfileId;
  wave: HuntWave;
  optional: boolean;
  approveTransition: "reconcile_drop" | "reconcile_halt";
}

/** Reconcile gate because the citation source could not be reached while verifying citations. */
export interface ReconcileCitationSourceContext {
  reasonCode: "citation_source_unavailable";
  unavailableSources: string[];
  citationReceipt: CitationVerificationReceipt;
  /** Required before approval: without it nobody can say what Approve does. */
  affectedStep?: ReconcileAffectedStep;
}

export type ReconcileReceiptContext = ReconcileDispatchContext | ReconcileCitationSourceContext;

export interface ActiveGatePrompt {
  gate: "scope" | "incident" | "reconcile";
  huntId: string;
  openedAtIso: string;
  expiresAtIso: string;
  payloadSha256: string;
  scopeText?: string;
  scopeHandoff?: Handoff;
  scopeSummary?: {
    hostsInScope: string[];
    allowedRoleTools: Record<ProfileId, readonly HuntToolName[]>;
    maxTotalTokens: number;
    followUpCount: number;
  };
  incidentHandoff?: Handoff;
  incidentSummary?: {
    citationReceipt: CitationVerificationReceipt;
    observedCount: number;
    findingCount: number;
    inferenceCount: number;
    hypothesisCount: number;
    limitationCount: number;
    purpleVerdictCounts: {
      review_ready: number;
      needs_validation: number;
      needs_revision: number;
    };
  };
  reconcileContext?: ReconcileReceiptContext;
  /**
   * Cited-record paging (F18): approval coverage comes from the complete cited-status list, while
   * records load in pages. `loaded < total` means the record list on screen is partial.
   */
  evidencePaging?: { loaded: number; total: number; hasMore: boolean };
  /**
   * Set when the gate's decision context (scope text, incident citations and evidence, or reconcile
   * receipt) could not be loaded. Approval is refused while it is set or the context is absent.
   */
  contextError?: string;
}

export interface EnrichedClaimRow {
  claim: Claim;
  stepId: string;
  waveNumber: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8;
  profile: ProfileId;
  inlineCitations: {
    id: string;
    kind: "evt" | "frame" | "ioc";
    status: "verified" | "unresolved" | "out_of_scope";
  }[];
  reviews: Review[];
}

export interface TelemetryGaugeSummary {
  totalTokensUsed: number;
  handoffRejectionTokens: number;
  maxTotalTokens: number;
  promptCacheHitRatio: number;
  cacheBelowTarget: boolean;
  billingMode: "oauth_subscription" | "api_key";
  actualBilledUsd: number;
  shadowApiUsd: number;
  cacheSavingsUsd: number;
  cyberRefusalCount: number;
}

export interface HistogramSeriesData {
  bucketTimestampsSec: number[];
  ecsEventCounts: number[];
  networkFlowCounts: number[];
  intervalSec: number;
}

export interface DissectorEventRow {
  eventId: string;
  timestampIso: string;
  timestampMs: number;
  hostName: string;
  category: string;
  action: string;
  userName: string;
  processName: string;
  commandLine: string;
  sourceIp: string;
  destinationIp: string;
  message: string;
  entityIds: string[];
}

export interface DissectorArkimeRow {
  sessionId: string;
  firstPacketIso: string;
  firstPacketMs: number;
  lastPacketIso: string;
  sourceIp: string;
  sourcePort: number;
  destinationIp: string;
  destinationPort: number;
  protocol: string[];
  networkBytes: number;
  networkPackets: number;
  httpHost: string;
  dnsHost: string;
  tlsJa4: string;
  tlsJa3: string;
  linkedFrameIds: string[];
  entityIds: string[];
}

export interface DissectorPacketRow {
  frameId: string;
  frameNumber: number;
  timeEpochSec: number;
  timeIso: string;
  frameLen: number;
  protocol: string;
  ipSrc: string;
  ipDst: string;
  dstPort: number | null;
  dnsQryName: string;
  dnsTxtAnswer: string;
  httpHost: string;
  httpRequestUriRedacted: string;
  tlsServerName: string;
  tlsJa4: string;
  tlsJa3: string;
  smb2Filename: string;
  entityIds: string[];
}

export interface EvidenceRecordDetail {
  id: string;
  kind: "evt" | "frame" | "ioc" | "entity";
  verified: boolean;
  timestampIso?: string;
  title: string;
  fields: Record<string, string | number | boolean | readonly string[]>;
  citingClaimIds: string[];
  linkedEntityIds: string[];
}

export interface WatchBrowserState {
  enabled: boolean;
  runId: string;
  role: ProfileId;
  partition: string;
  currentUrl: string;
  title: string;
  loading: boolean;
  allowedOrigins: string[];
  blockedRequestCount: number;
  lastBlockedReason: string | null;
  cdpEndpointUrl: string | null;
}

export interface TranscriptPageSlice {
  huntId: string;
  stepId: string;
  profile: ProfileId;
  byteOffset: number;
  byteLength: number;
  totalBytes: number;
  hasMore: boolean;
  /** Where the next page starts (the daemon snaps offsets to UTF-8 boundaries). */
  nextByteOffset?: number;
  content: string;
}

export interface WorkbenchSnapshot {
  provenanceMode: "live_daemon" | "fixture_preview";
  huntId: string;
  runStatus: "running" | "awaiting_human_gate" | "completed" | "stopped" | "failed";
  caseMetadata: CaseMetadata;
  currentWaveNumber: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8;
  mergeFallbackActive: boolean;
  gauges: TelemetryGaugeSummary;
  steps: StepExecutionSummary[];
  ganttSpans: GanttSpanRecord[];
  activeGate: ActiveGatePrompt | null;
  gateHistory: AuthenticatedGateDecision[];
  claims: EnrichedClaimRow[];
  limitations: { stepId: string; profile: ProfileId; text: string }[];
  handoffs: Handoff[];
  snapshot: Snapshot;
  citationReceipt: CitationVerificationReceipt;
  histogram: HistogramSeriesData;
  events: DissectorEventRow[];
  arkimeFlows: DissectorArkimeRow[];
  packets: DissectorPacketRow[];
  evidenceCatalog: Record<string, EvidenceRecordDetail>;
  watchState: WatchBrowserState;
}
