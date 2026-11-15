/**
 * Main-Process DFIR Workbench Coordinator (`workbench-service.ts`).
 *
 * Bridges allowlisted Preload IPC invocations to:
 * - Persistent `HuntDaemonSidecar` (stdio NDJSON JSON-RPC 2.0) when live, with seamless fallback
 *   to schema-validated DFIR workbench runs (`buildFixtureWorkbenchSnapshot`) in standby/preview mode.
 * - Authenticated Human Gate validation & `decisions.jsonl` persistence (`ADR 0002`, `F03`).
 * - Global Stop (`F13`), byte-paged lazy bot transcript slicing, and dissector filtering.
 * - Customer Report Exporter (`.md` + `.pdf` + provenance JSON) and Offscreen CFR 30fps filming.
 */
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { z } from "zod";
import {
  AuthenticatedGateDecisionSchema,
  type AuthenticatedGateDecision,
  type ProfileId,
  type RuntimePaths,
} from "@hunt-command/shared";
import { buildFixtureWorkbenchSnapshot } from "../shared/fixture-workbench.ts";
import { validateGateSubmission } from "../shared/gate-validation.ts";
import {
  ExportReportInputSchema,
  FilmCutInputSchema,
  GlobalStopInputSchema,
  InspectTranscriptInputSchema,
  QueryDissectorInputSchema,
  StartRunInputSchema,
  SubmitGateDecisionInputSchema,
  VaultRefInputSchema,
  VaultSetSecretInputSchema,
  WatchBoundsInputSchema,
  WatchNavigateInputSchema,
  type WatchOpenInput,
  WatchOpenInputSchema,
  type DaemonHealthStatus,
  type FilmExportResult,
  type ReportExportResult,
} from "../shared/ipc.ts";
import { stripControlAndBidiChars } from "../shared/sanitize.ts";
import type {
  DissectorArkimeRow,
  DissectorEventRow,
  DissectorPacketRow,
  EvidenceRecordDetail,
  TranscriptPageSlice,
  WatchBrowserState,
  WorkbenchSnapshot,
} from "../shared/workbench-types.ts";
import type { HuntDaemonSidecar } from "./daemon/daemon-sidecar.ts";
import { exportCustomerReport } from "./export/report-exporter.ts";
import { resolveFfmpegBinary } from "./film/cfr-editor.ts";
import type { SecretVault } from "./secret-vault.ts";

export interface RunSummaryItem {
  huntId: string;
  caseId: string;
  title: string;
  dataOrigin: WorkbenchSnapshot["caseMetadata"]["data_origin"];
  runStatus: WorkbenchSnapshot["runStatus"];
  openGate: "scope" | "incident" | "reconcile" | null;
}

export interface DissectorQueryResult {
  tab: "events" | "arkime" | "packets";
  totalMatched: number;
  events?: DissectorEventRow[];
  arkimeFlows?: DissectorArkimeRow[];
  packets?: DissectorPacketRow[];
}

export interface WorkbenchServiceDeps {
  runtimePaths: RuntimePaths;
  sidecar: HuntDaemonSidecar;
  vault: SecretVault;
  pdfRenderer?: (printHtml: string, fallbackMarkdown: string) => Promise<Uint8Array>;
  filmRunner?: (
    workbench: WorkbenchSnapshot,
    speed: number,
    captions: boolean,
    allowWorkFilm: boolean,
  ) => Promise<FilmExportResult>;
  watchHandlers?: {
    getState: () => WatchBrowserState;
    setBounds: (bounds: { x: number; y: number; width: number; height: number } | null) => WatchBrowserState;
    invalidate: () => void;
    navigate: (runId: string, role: ProfileId, url: string) => Promise<WatchBrowserState>;
    open: (input: WatchOpenInput) => Promise<WatchBrowserState>;
  };
}

function buildStepTranscriptText(snapshot: WorkbenchSnapshot, stepId: string): string {
  const step = snapshot.steps.find((s) => s.stepId === stepId) ?? snapshot.steps[0];
  const profile = step?.profile ?? "framework-researcher";
  const spans = snapshot.ganttSpans.filter((sp) => sp.stepId === stepId);
  const handoff = snapshot.handoffs.find((h) => h.step_id === stepId);

  const lines: string[] = [
    `=== Hunt Command Bot Transcript Slice ===`,
    `hunt_id: ${snapshot.huntId}`,
    `case_id: ${snapshot.caseMetadata.case_id}`,
    `step_id: ${stepId}`,
    `profile: ${profile}`,
    `model: ${step?.model ?? "claude-sonnet-4-6"}`,
    `state: ${step?.state ?? "done"}${step?.reasonCode ? ` (${step.reasonCode})` : ""}`,
    `tokens: input=${step?.inputTokens ?? 0} output=${step?.outputTokens ?? 0} cache_read=${step?.cacheReadTokens ?? 0} cache_write=${step?.cacheWriteTokens ?? 0}`,
    "",
  ];

  if (step?.refusal?.refused) {
    lines.push(
      `[MODEL_REFUSAL] finish_reason=${step.refusal.finish_reason ?? "unknown"} category=${step.refusal.category ?? "unknown"} diagnostic=${step.refusal.diagnostic ?? ""}`,
      "",
    );
  }

  for (const sp of spans) {
    lines.push(
      `[${new Date(sp.startEpochMs).toISOString()}] (${sp.kind}) ${sp.label} [${sp.durationMs}ms, status=${sp.status}]`,
    );
    if (sp.queryPreview) {
      lines.push(`  query: ${sp.queryPreview}`);
    }
    if (sp.citedIds && sp.citedIds.length > 0) {
      lines.push(`  cited_records: ${sp.citedIds.join(", ")}`);
    }
  }

  if (handoff) {
    lines.push("", "--- Validated Handoff JSON ---", JSON.stringify(handoff, null, 2));
  }

  return `${stripControlAndBidiChars(lines.join("\n"))}\n`;
}
const LiveStartResultSchema = z.object({
  run_id: z.string().min(1),
  status: z.enum(["running", "awaiting_gate", "completed", "failed", "cancelled"]),
});

export interface LiveStartResult {
  provenanceMode: "live_daemon";
  huntId: string;
  runStatus: "running" | "awaiting_human_gate" | "completed" | "stopped" | "failed";
}


export class WorkbenchService {
  readonly #deps: WorkbenchServiceDeps;
  readonly #runs = new Map<string, WorkbenchSnapshot>();
  readonly #liveRunIds = new Set<string>();
  #selectionVersion = 0;
  #activeHuntId: string;

  constructor(deps: WorkbenchServiceDeps) {
    this.#deps = deps;

    const incidentRun = buildFixtureWorkbenchSnapshot({
      huntId: "hunt-20261115-nv01",
      dataOrigin: "synthetic",
      openGate: "incident",
    });
    const scopeWorkRun = buildFixtureWorkbenchSnapshot({
      huntId: "hunt-20261115-scope-work",
      dataOrigin: "work-export",
      openGate: "scope",
    });
    const reconcileRun = buildFixtureWorkbenchSnapshot({
      huntId: "hunt-20261115-reconcile",
      dataOrigin: "synthetic",
      openGate: "reconcile",
    });

    this.#runs.set(incidentRun.huntId, incidentRun);
    this.#runs.set(scopeWorkRun.huntId, scopeWorkRun);
    this.#runs.set(reconcileRun.huntId, reconcileRun);
    this.#activeHuntId = incidentRun.huntId;
  }

  getDaemonStatus(): DaemonHealthStatus {
    return this.#deps.sidecar.health();
  }

  async restartDaemon(): Promise<DaemonHealthStatus> {
    return await this.#deps.sidecar.restart();
  }

  async listRuns(): Promise<RunSummaryItem[]> {
    if (this.#deps.sidecar.isLiveReady) {
      try {
        const liveRuns = await this.#deps.sidecar.request<RunSummaryItem[]>("hunt.listRuns");
        if (Array.isArray(liveRuns) && liveRuns.length > 0) {
          return liveRuns;
        }
      } catch {
        // Fall back to local state store if RPC method is unavailable.
      }
    }

    return [...this.#runs.values()].map((snap) => ({
      huntId: snap.huntId,
      caseId: snap.caseMetadata.case_id,
      title: snap.caseMetadata.title,
      dataOrigin: snap.caseMetadata.data_origin,
      runStatus: snap.runStatus,
      openGate: snap.activeGate?.gate ?? null,
    }));
  }

  async getWorkbenchState(rawPayload?: unknown): Promise<WorkbenchSnapshot> {
    const selection = ++this.#selectionVersion;
    const requestedHuntId =
      typeof rawPayload === "object" &&
      rawPayload !== null &&
      "huntId" in rawPayload &&
      typeof (rawPayload as { huntId?: unknown }).huntId === "string"
        ? (rawPayload as { huntId: string }).huntId
        : this.#activeHuntId;

    if (this.#liveRunIds.has(requestedHuntId)) {
      throw new Error(`Live workbench state is not available for hunt '${requestedHuntId}'.`);
    }

    if (this.#deps.sidecar.isLiveReady) {
      try {
        const liveSnap = await this.#deps.sidecar.request<WorkbenchSnapshot>("hunt.getWorkbenchState", {
          huntId: requestedHuntId,
        });
        if (liveSnap && typeof liveSnap.huntId === "string") {
          this.#runs.set(liveSnap.huntId, liveSnap);
          if (selection === this.#selectionVersion) this.#selectHunt(liveSnap.huntId);
          return this.#attachWatchState(liveSnap);
        }
      } catch {
        // Fall through to cached/fixture run when daemon does not hold this huntId.
      }
    }

    const snap =
      this.#runs.get(requestedHuntId) ??
      this.#runs.get(this.#activeHuntId) ??
      buildFixtureWorkbenchSnapshot({ huntId: requestedHuntId });
    this.#runs.set(snap.huntId, snap);
    if (selection === this.#selectionVersion) this.#selectHunt(snap.huntId);
    return this.#attachWatchState(snap);
  }

  async startRun(rawInput: unknown): Promise<WorkbenchSnapshot | LiveStartResult> {
    const parsed = StartRunInputSchema.parse(rawInput);

    if (this.#deps.sidecar.isLiveReady) {
      const response = await this.#deps.sidecar.request<unknown>("hunt.start", {
        case_id: parsed.caseId,
        scope: parsed.scope,
        follow_ups: parsed.followUps,
        max_total_tokens: parsed.maxTotalTokens,
      });
      const started = LiveStartResultSchema.parse(response);
      this.#liveRunIds.add(started.run_id);
      return {
        provenanceMode: "live_daemon",
        huntId: started.run_id,
        runStatus: started.status === "awaiting_gate" ? "awaiting_human_gate"
          : started.status === "cancelled" ? "stopped" : started.status,
      };
    }

    const newHuntId = `hunt-${Date.now().toString(36)}-${parsed.caseId.slice(0, 16)}`;
    const created = buildFixtureWorkbenchSnapshot({
      huntId: newHuntId,
      dataOrigin: parsed.dataOrigin,
      openGate: "scope",
    });
    created.gauges.maxTotalTokens = parsed.maxTotalTokens;
    if (created.activeGate?.scopeSummary) {
      created.activeGate.scopeSummary.maxTotalTokens = parsed.maxTotalTokens;
      created.activeGate.scopeSummary.followUpCount = parsed.followUps;
    }
    this.#runs.set(newHuntId, created);
    this.#selectHunt(newHuntId);
    return this.#attachWatchState(created);
  }

  async globalStop(rawInput: unknown): Promise<WorkbenchSnapshot> {
    const parsed = GlobalStopInputSchema.parse(rawInput);

    if (this.#deps.sidecar.isLiveReady) {
      await this.#deps.sidecar
        .request("hunt.globalStop", { huntId: parsed.huntId, reason: parsed.reason })
        .catch(() => {});
    }

    const current = await this.getWorkbenchState({ huntId: parsed.huntId });
    const stoppedSteps = current.steps.map((s) =>
      s.state === "working" || s.state === "awaiting_approval" || s.state === "awaiting_review"
        ? { ...s, state: "stopped" as const, reasonCode: parsed.reason }
        : s,
    );
    const updated: WorkbenchSnapshot = {
      ...current,
      runStatus: "stopped",
      activeGate: null,
      steps: stoppedSteps,
    };
    this.#runs.set(updated.huntId, updated);
    return this.#attachWatchState(updated);
  }

  async submitGateDecision(rawInput: unknown): Promise<WorkbenchSnapshot> {
    const parsed = SubmitGateDecisionInputSchema.parse(rawInput);
    const current = await this.getWorkbenchState({ huntId: parsed.huntId });

    if (!current.activeGate || current.activeGate.gate !== parsed.gate) {
      throw new Error(`No active '${parsed.gate}' gate is currently open for hunt '${parsed.huntId}'.`);
    }

    const validation = validateGateSubmission(current.activeGate, {
      operatorName: parsed.operatorName,
      rbacRole: parsed.rbacRole,
      checkNote: parsed.checkNote,
      payloadSha256: parsed.payloadSha256,
      action: parsed.action,
    });

    if (!validation.valid) {
      throw new Error(validation.errors.join(" "));
    }

    const nowIso = new Date().toISOString();
    const decision: AuthenticatedGateDecision = AuthenticatedGateDecisionSchema.parse({
      decision_id: `dec-${randomUUID()}`,
      hunt_id: parsed.huntId,
      gate: parsed.gate,
      action: parsed.action,
      via: "desktop",
      decided_by: validation.sanitizedOperatorName,
      rbac_role: parsed.rbacRole,
      payload_sha256: parsed.payloadSha256.toLowerCase(),
      decided_at: nowIso,
      expires_at: current.activeGate.expiresAtIso,
      note: validation.sanitizedCheckNote,
    });

    fs.mkdirSync(path.dirname(this.#deps.runtimePaths.decisionsLogPath), { recursive: true });
    fs.appendFileSync(
      this.#deps.runtimePaths.decisionsLogPath,
      `${JSON.stringify(decision)}\n`,
      "utf8",
    );

    if (this.#deps.sidecar.isLiveReady) {
      try {
        const liveNext = await this.#deps.sidecar.request<WorkbenchSnapshot>(
          "hunt.submitGateDecision",
          { decision },
        );
        if (liveNext && typeof liveNext.huntId === "string") {
          this.#runs.set(liveNext.huntId, liveNext);
          return this.#attachWatchState(liveNext);
        }
      } catch {
        // Apply state transition locally if daemon RPC is in standby.
      }
    }

    let nextSnap: WorkbenchSnapshot;
    if (parsed.action === "reject") {
      nextSnap = {
        ...current,
        runStatus: "stopped",
        activeGate: null,
        gateHistory: [...current.gateHistory, decision],
        steps: current.steps.map((s) =>
          s.state === "awaiting_approval"
            ? { ...s, state: "stopped" as const, reasonCode: `gate_${parsed.gate}_rejected` }
            : s,
        ),
      };
    } else if (parsed.gate === "scope") {
      const progressed = buildFixtureWorkbenchSnapshot({
        huntId: current.huntId,
        dataOrigin: current.caseMetadata.data_origin,
        openGate: "incident",
      });
      nextSnap = {
        ...progressed,
        gateHistory: [...current.gateHistory, decision],
      };
    } else {
      nextSnap = {
        ...current,
        runStatus: "completed",
        activeGate: null,
        gateHistory: [...current.gateHistory, decision],
        steps: current.steps.map((s) =>
          s.state === "awaiting_approval" ? { ...s, state: "done" as const } : s,
        ),
      };
    }

    this.#runs.set(nextSnap.huntId, nextSnap);
    return this.#attachWatchState(nextSnap);
  }

  async inspectTranscriptPage(rawInput: unknown): Promise<TranscriptPageSlice> {
    const parsed = InspectTranscriptInputSchema.parse(rawInput);
    const current = await this.getWorkbenchState({ huntId: parsed.huntId });

    if (this.#deps.sidecar.isLiveReady) {
      try {
        return await this.#deps.sidecar.request<TranscriptPageSlice>("hunt.inspectTranscriptPage", parsed);
      } catch {
        // Fall back to deterministic step slice.
      }
    }

    const fullText = buildStepTranscriptText(current, parsed.stepId);
    const fullBytes = Buffer.from(fullText, "utf8");
    const safeStart = Math.min(parsed.byteOffset, fullBytes.byteLength);
    const safeEnd = Math.min(safeStart + parsed.byteLimit, fullBytes.byteLength);
    const sliceText = fullBytes.subarray(safeStart, safeEnd).toString("utf8");
    const step = current.steps.find((s) => s.stepId === parsed.stepId);

    return {
      huntId: current.huntId,
      stepId: parsed.stepId,
      profile: step?.profile ?? "framework-researcher",
      byteOffset: safeStart,
      byteLength: safeEnd - safeStart,
      totalBytes: fullBytes.byteLength,
      hasMore: safeEnd < fullBytes.byteLength,
      content: sliceText,
    };
  }

  async queryDissector(rawInput: unknown): Promise<DissectorQueryResult> {
    const parsed = QueryDissectorInputSchema.parse(rawInput);
    const current = await this.getWorkbenchState({ huntId: parsed.huntId });
    const needle = parsed.searchText.trim().toLowerCase();

    const inBrush = (tsMs: number): boolean => {
      if (parsed.startMs !== undefined && tsMs < parsed.startMs) return false;
      if (parsed.endMs !== undefined && tsMs > parsed.endMs) return false;
      return true;
    };

    if (parsed.tab === "events") {
      const matched = current.events.filter((ev) => {
        if (!inBrush(ev.timestampMs)) return false;
        if (!needle) return true;
        return (
          ev.eventId.toLowerCase().includes(needle) ||
          ev.hostName.toLowerCase().includes(needle) ||
          ev.processName.toLowerCase().includes(needle) ||
          ev.commandLine.toLowerCase().includes(needle) ||
          ev.message.toLowerCase().includes(needle)
        );
      });
      return {
        tab: "events",
        totalMatched: matched.length,
        events: matched.slice(parsed.offset, parsed.offset + parsed.limit),
      };
    }

    if (parsed.tab === "arkime") {
      const matched = current.arkimeFlows.filter((fl) => {
        if (!inBrush(fl.firstPacketMs)) return false;
        if (!needle) return true;
        return (
          fl.sessionId.toLowerCase().includes(needle) ||
          fl.sourceIp.toLowerCase().includes(needle) ||
          fl.destinationIp.toLowerCase().includes(needle) ||
          fl.dnsHost.toLowerCase().includes(needle) ||
          fl.httpHost.toLowerCase().includes(needle) ||
          fl.tlsJa4.toLowerCase().includes(needle)
        );
      });
      return {
        tab: "arkime",
        totalMatched: matched.length,
        arkimeFlows: matched.slice(parsed.offset, parsed.offset + parsed.limit),
      };
    }

    const matched = current.packets.filter((pkt) => {
      if (!inBrush(pkt.timeEpochSec * 1000)) return false;
      if (!needle) return true;
      return (
        pkt.frameId.toLowerCase().includes(needle) ||
        pkt.protocol.toLowerCase().includes(needle) ||
        pkt.ipSrc.toLowerCase().includes(needle) ||
        pkt.ipDst.toLowerCase().includes(needle) ||
        pkt.dnsQryName.toLowerCase().includes(needle) ||
        pkt.httpRequestUriRedacted.toLowerCase().includes(needle) ||
        pkt.tlsJa4.toLowerCase().includes(needle)
      );
    });
    return {
      tab: "packets",
      totalMatched: matched.length,
      packets: matched.slice(parsed.offset, parsed.offset + parsed.limit),
    };
  }

  async resolveEvidence(rawInput: unknown): Promise<EvidenceRecordDetail | null> {
    const id =
      typeof rawInput === "object" &&
      rawInput !== null &&
      "id" in rawInput &&
      typeof (rawInput as { id?: unknown }).id === "string"
        ? (rawInput as { id: string }).id
        : "";
    if (!id) return null;
    const current = await this.getWorkbenchState();
    return current.evidenceCatalog[id] ?? null;
  }

  getWatchState(): WatchBrowserState {
    if (this.#deps.watchHandlers) {
      const state = this.#deps.watchHandlers.getState();
      if (state.runId === this.#activeHuntId) return state;
      return this.#standbyWatchState(this.#activeHuntId);
    }
    const snap = this.#runs.get(this.#activeHuntId);
    return (
      snap?.watchState ?? this.#standbyWatchState(this.#activeHuntId)
    );
  }

  setWatchBounds(rawInput: unknown): WatchBrowserState {
    const parsed = WatchBoundsInputSchema.parse(rawInput);
    if (!this.#deps.watchHandlers) {
      return this.getWatchState();
    }
    if (parsed.bounds && (parsed.runId !== this.#activeHuntId ||
      this.#deps.watchHandlers.getState().runId !== parsed.runId)) {
      throw new Error("Watch bounds do not belong to the active hunt.");
    }
    this.#deps.watchHandlers.setBounds(parsed.bounds);
    return this.getWatchState();
  }

  async openWatch(rawInput: unknown): Promise<WatchBrowserState> {
    const parsed = WatchOpenInputSchema.parse(rawInput);
    if (parsed.runId !== this.#activeHuntId) {
      throw new Error("Watch session does not belong to the active hunt.");
    }
    const current = this.#runs.get(this.#activeHuntId);
    if (!current || parsed.caseId !== current.caseMetadata.case_id) {
      throw new Error("Watch case does not match the active hunt.");
    }
    if (!this.#deps.watchHandlers) {
      throw new Error("Watch Browser controller is not attached in headless test mode.");
    }
    return await this.#deps.watchHandlers.open(parsed);
  }

  async navigateWatch(rawInput: unknown): Promise<WatchBrowserState> {
    const parsed = WatchNavigateInputSchema.parse(rawInput);
    if (parsed.runId !== this.#activeHuntId) {
      throw new Error("Watch session does not belong to the active hunt.");
    }
    if (!this.#deps.watchHandlers) {
      throw new Error("Watch Browser controller is not attached in headless test mode.");
    }
    return await this.#deps.watchHandlers.navigate(parsed.runId, parsed.role, parsed.url);
  }

  async exportReport(rawInput: unknown): Promise<ReportExportResult> {
    const parsed = ExportReportInputSchema.parse(rawInput);
    const current = await this.getWorkbenchState({ huntId: parsed.huntId });
    return await exportCustomerReport({
      workbench: current,
      exportsRootDir: this.#deps.runtimePaths.exportsDir,
      ...(this.#deps.pdfRenderer ? { pdfRenderer: this.#deps.pdfRenderer } : {}),
    });
  }

  getFilmStatus(): { ffmpegAvailable: boolean; hasLibass: boolean; ffmpegSource: string } {
    const res = resolveFfmpegBinary();
    return {
      ffmpegAvailable: res.available,
      hasLibass: res.hasLibass,
      ffmpegSource: res.source,
    };
  }

  async recordAndCutFilm(rawInput: unknown): Promise<FilmExportResult> {
    const parsed = FilmCutInputSchema.parse(rawInput);
    const current = await this.getWorkbenchState({ huntId: parsed.huntId });
    if (!this.#deps.filmRunner) {
      throw new Error("Offscreen film runner requires an active Electron compositor.");
    }
    return await this.#deps.filmRunner(
      current,
      parsed.speed,
      parsed.captions,
      parsed.allowWorkFilm,
    );
  }

  getVaultStatus(): { available: boolean; refs: string[] } {
    return {
      available: this.#deps.vault.available,
      refs: this.#deps.vault.listRefs(),
    };
  }

  hasVaultSecret(rawInput: unknown): boolean {
    const parsed = VaultRefInputSchema.parse(rawInput);
    return this.#deps.vault.has(parsed.ref);
  }

  setVaultSecret(rawInput: unknown): { saved: true; ref: string } {
    const parsed = VaultSetSecretInputSchema.parse(rawInput);
    this.#deps.vault.set(parsed.ref, parsed.secret);
    return { saved: true, ref: parsed.ref };
  }

  deleteVaultSecret(rawInput: unknown): { deleted: true; ref: string } {
    const parsed = VaultRefInputSchema.parse(rawInput);
    this.#deps.vault.delete(parsed.ref);
    return { deleted: true, ref: parsed.ref };
  }

  #selectHunt(huntId: string): void {
    if (this.#activeHuntId !== huntId) {
      this.#deps.watchHandlers?.invalidate();
      this.#activeHuntId = huntId;
    }
  }

  #standbyWatchState(runId: string): WatchBrowserState {
    return {
      enabled: false,
      runId,
      role: "framework-researcher",
      partition: `hunt-watch:${runId}:framework-researcher`,
      currentUrl: "about:blank",
      title: "Watch Browser (Standby)",
      loading: false,
      allowedOrigins: [],
      blockedRequestCount: 0,
      lastBlockedReason: null,
      cdpEndpointUrl: null,
    };
  }

  #attachWatchState(snapshot: WorkbenchSnapshot): WorkbenchSnapshot {
    if (!this.#deps.watchHandlers) return snapshot;
    return {
      ...snapshot,
      watchState: snapshot.huntId === this.#activeHuntId
        ? this.getWatchState()
        : this.#standbyWatchState(snapshot.huntId),
    };
  }
}
