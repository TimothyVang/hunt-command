import { z } from "zod";
import { DataOriginSchema, ProfileIdSchema, type RpcEventNotification } from "@hunt-command/shared";
import type {
  TranscriptPageSlice,
  WatchBrowserState,
  WorkbenchSnapshot,
} from "./workbench-types.ts";

export {
  EVENT_CHANNEL_LIST,
  EVENT_CHANNELS,
  type EventChannel,
  INVOKE_CHANNEL_LIST,
  INVOKE_CHANNELS,
  type InvokeChannel,
} from "./ipc-channels.ts";
import type { EventChannel, InvokeChannel } from "./ipc-channels.ts";

export const StartRunInputSchema = z
  .object({
    caseId: z.string().min(1).max(128),
    scope: z.string().max(100_000).refine((value) => value.trim().length > 0, "Scope is required"),
    dataOrigin: DataOriginSchema,
    maxTotalTokens: z.number().int().min(10_000).max(50_000_000).default(4_000_000),
    followUps: z.number().int().min(0).max(12).default(6),
  })
  .strict();

export type StartRunInput = z.infer<typeof StartRunInputSchema>;

export const GlobalStopInputSchema = z
  .object({
    huntId: z.string().min(1).max(128),
    reason: z.string().min(1).max(240).default("operator_global_stop"),
  })
  .strict();

export type GlobalStopInput = z.infer<typeof GlobalStopInputSchema>;

export const SubmitGateDecisionInputSchema = z
  .object({
    huntId: z.string().min(1).max(128),
    gate: z.enum(["scope", "incident", "reconcile"]),
    action: z.enum(["approve", "reject"]),
    operatorName: z
      .string()
      .min(1, "Operator principal is required")
      .max(128)
      .refine((s) => s.trim().length > 0, "Operator principal cannot be blank"),
    rbacRole: z.enum(["incident_commander", "lead_hunter", "soc_lead"]),
    checkNote: z
      .string()
      .min(1, '"What did you check?" note is required (1..1000 chars)')
      .max(1000, '"What did you check?" note cannot exceed 1000 chars')
      .refine((s) => s.trim().length >= 1, '"What did you check?" note cannot be blank'),
    payloadSha256: z.string().regex(/^[a-f0-9]{64}$/i, "Expected 64-hex SHA-256 payload digest"),
    operatorToken: z.string().min(1).max(8192).optional(),
  })
  .strict();

export type SubmitGateDecisionInput = z.infer<typeof SubmitGateDecisionInputSchema>;

export const InspectTranscriptInputSchema = z
  .object({
    huntId: z.string().min(1).max(128),
    stepId: z.string().min(1).max(64),
    byteOffset: z.number().int().min(0).default(0),
    byteLimit: z.number().int().min(512).max(32_768).default(16_384),
  })
  .strict();

export type InspectTranscriptInput = z.infer<typeof InspectTranscriptInputSchema>;

export const QueryDissectorInputSchema = z
  .object({
    huntId: z.string().min(1).max(128),
    tab: z.enum(["events", "arkime", "packets"]),
    searchText: z.string().max(500).default(""),
    startMs: z.number().nonnegative().optional(),
    endMs: z.number().nonnegative().optional(),
    offset: z.number().int().min(0).default(0),
    limit: z.number().int().min(1).max(1000).default(250),
  })
  .strict();

export type QueryDissectorInput = z.infer<typeof QueryDissectorInputSchema>;

export const WatchBoundsInputSchema = z
  .object({
    runId: z.string().min(1).max(128),
    bounds: z
      .object({
        x: z.number().int(),
        y: z.number().int(),
        width: z.number().int().min(100).max(8192),
        height: z.number().int().min(100).max(8192),
      })
      .nullable(),
  })
  .strict();

export const WatchNavigateInputSchema = z
  .object({
    runId: z.string().min(1).max(128),
    role: ProfileIdSchema,
    url: z.string().min(1).max(2048),
  })
  .strict();

/**
 * Opens the fenced Watch session for a run/role. Every origin is re-validated in the main process by
 * `createWatchScope` (pinned `http(s)://127.0.0.1:<port>` only); `arkimeOrigin` defaults to `labOrigin`.
 */
export const WatchOpenInputSchema = z
  .object({
    runId: z.string().min(1).max(128),
    role: ProfileIdSchema,
    caseId: z.string().min(1).max(128),
    labOrigin: z.string().min(1).max(2048),
    arkimeOrigin: z.string().min(1).max(2048).optional(),
    kibanaOrigin: z.string().min(1).max(2048).nullable().optional(),
    startSec: z.number().int().nonnegative(),
    stopSec: z.number().int().positive(),
    initialUrl: z.string().min(1).max(2048).optional(),
  })
  .strict();

export type WatchOpenInput = z.infer<typeof WatchOpenInputSchema>;

export const ExportReportInputSchema = z
  .object({
    huntId: z.string().min(1).max(128),
  })
  .strict();

export const FilmCutInputSchema = z
  .object({
    huntId: z.string().min(1).max(128),
    speed: z.number().min(2).max(30).default(5),
    captions: z.boolean().default(true),
    allowWorkFilm: z.boolean().default(false),
  })
  .strict();

export type FilmCutInput = z.infer<typeof FilmCutInputSchema>;

export const VaultSetSecretInputSchema = z
  .object({
    ref: z.string().regex(/^[a-z0-9_.:-]{1,80}$/i),
    secret: z.string().min(1).max(4096),
  })
  .strict();

export const VaultRefInputSchema = z
  .object({
    ref: z.string().regex(/^[a-z0-9_.:-]{1,80}$/i),
  })
  .strict();

export interface IpcResult<T> {
  ok: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
  };
}

export interface DaemonHealthStatus {
  status: "ready" | "starting" | "restarting" | "standby_fixture" | "failed";
  pid: number | null;
  restarts: number;
  runtimeRootDir: string;
  piNativesDir: string | null;
  lastError: string | null;
}

export interface ReportExportResult {
  exportDir: string;
  markdownPath: string;
  pdfPath: string;
  provenanceJsonPath: string;
  reportSha256: string;
}

export interface FilmExportResult {
  filmDir: string;
  video5xPath: string;
  videoFull1xPath: string;
  assPath: string;
  editJsonPath: string;
  frameCount: number;
  nonSyntheticWorkBannerBurned: boolean;
}

export interface DesktopBridge {
  invoke<T = unknown>(channel: InvokeChannel, payload?: unknown): Promise<IpcResult<T>>;
  on<TPayload = unknown>(channel: EventChannel, listener: (payload: TPayload) => void): () => void;
  platform: string;
}

export type DaemonEventBatchPayload = {
  huntId: string;
  events: RpcEventNotification["params"][];
};

export type { TranscriptPageSlice, WatchBrowserState, WorkbenchSnapshot };
