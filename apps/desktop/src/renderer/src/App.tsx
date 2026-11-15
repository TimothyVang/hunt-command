import { useEffect, useMemo, useSyncExternalStore } from "react";
import type {
  DaemonEventBatchPayload,
  FilmExportResult,
  ReportExportResult,
} from "../../shared/ipc.ts";
import type { WatchBrowserState, WorkbenchSnapshot } from "../../shared/workbench-types.ts";
import { invokeDesktop, subscribeDesktopEvent } from "./lib/bridge.ts";
import { AttackGraphLineagePane } from "./panes/AttackGraphLineagePane.tsx";
import { ClaimsAndGatesPane } from "./panes/ClaimsAndGatesPane.tsx";
import { FlightRecorderHeader } from "./panes/FlightRecorderHeader.tsx";
import { TimelineDissectorPane } from "./panes/TimelineDissectorPane.tsx";
import { workbenchStore } from "./state/workbench-store.ts";

export function App() {
  const ui = useSyncExternalStore(workbenchStore.subscribe, workbenchStore.getState);

  const isFilmMode = useMemo(() => {
    if (typeof window === "undefined") return false;
    return new URLSearchParams(window.location.search).get("film") === "1";
  }, []);

  useEffect(() => {
    const initialHuntId =
      typeof window !== "undefined"
        ? new URLSearchParams(window.location.search).get("huntId") ?? undefined
        : undefined;

    void invokeDesktop<WorkbenchSnapshot>(
      "hunt:getWorkbenchState",
      initialHuntId ? { huntId: initialHuntId } : undefined,
    ).then((res) => {
      if (res.ok && res.data) {
        workbenchStore.setWorkbenchSnapshot(res.data);
      }
    });

    const unsubBatch = subscribeDesktopEvent<DaemonEventBatchPayload>(
      "daemon:eventBatch",
      (batch) => {
        void invokeDesktop<WorkbenchSnapshot>("hunt:getWorkbenchState", {
          huntId: batch.huntId,
        }).then((res) => {
          if (res.ok && res.data) {
            workbenchStore.setWorkbenchSnapshot(res.data);
          }
        });
      },
    );

    const unsubWatch = subscribeDesktopEvent<WatchBrowserState>("watch:stateChanged", (watch) => {
      const curr = workbenchStore.getState().workbench;
      workbenchStore.setWorkbenchSnapshot({
        ...curr,
        watchState: watch,
      });
    });

    return () => {
      unsubBatch();
      unsubWatch();
    };
  }, []);

  const handleSwitchPresetRun = (huntId: string) => {
    void invokeDesktop<WorkbenchSnapshot>("hunt:getWorkbenchState", { huntId }).then((res) => {
      if (res.ok && res.data) {
        workbenchStore.setWorkbenchSnapshot(res.data);
        workbenchStore.setStatusBanner(null);
      }
    });
  };

  const handleGlobalStop = () => {
    void invokeDesktop<WorkbenchSnapshot>("hunt:globalStop", {
      huntId: ui.workbench.huntId,
      reason: "operator_global_stop",
    }).then((res) => {
      if (res.ok && res.data) {
        workbenchStore.setWorkbenchSnapshot(res.data);
        workbenchStore.setStatusBanner({
          kind: "info",
          message: `Global Stop executed on ${res.data.huntId}: all in-flight bot steps halted.`,
        });
      }
    });
  };

  const handleSubmitGateDecision = (action: "approve" | "reject") => {
    const gate = ui.workbench.activeGate;
    if (!gate) return;
    const draft = workbenchStore.getActiveGateDraft();

    void invokeDesktop<WorkbenchSnapshot>("hunt:submitGateDecision", {
      huntId: ui.workbench.huntId,
      gate: gate.gate,
      action,
      operatorName: draft.operatorName,
      rbacRole: draft.rbacRole,
      checkNote: draft.checkNote,
      payloadSha256: gate.payloadSha256,
    }).then((res) => {
      if (res.ok && res.data) {
        workbenchStore.setWorkbenchSnapshot(res.data);
        workbenchStore.setStatusBanner({
          kind: "success",
          message: `Signed Gate '${gate.gate}' (${action.toUpperCase()}) recorded in decisions.jsonl.`,
        });
      } else if (res.error) {
        workbenchStore.setStatusBanner({
          kind: "error",
          message: res.error.message,
        });
      }
    });
  };

  const handleExportReport = () => {
    workbenchStore.setStatusBanner({
      kind: "info",
      message: "Exporting cited Markdown + PDF + Provenance JSON bundle...",
    });
    void invokeDesktop<ReportExportResult>("export:customerReport", {
      huntId: ui.workbench.huntId,
    }).then((res) => {
      if (res.ok && res.data) {
        workbenchStore.setStatusBanner({
          kind: "success",
          message: `Report exported to ${res.data.exportDir} (SHA-256: ${res.data.reportSha256.slice(0, 16)}...)`,
        });
      } else if (res.error) {
        workbenchStore.setStatusBanner({
          kind: "error",
          message: res.error.message,
        });
      }
    });
  };

  const handleRecordFilm = () => {
    workbenchStore.setStatusBanner({
      kind: "info",
      message: "Recording 1920x1080@30fps offscreen compositor & encoding CFR MP4 + ASS...",
    });
    void invokeDesktop<FilmExportResult>("film:recordAndCut", {
      huntId: ui.workbench.huntId,
      speed: 5,
      captions: true,
      allowWorkFilm: false,
    }).then((res) => {
      if (res.ok && res.data) {
        workbenchStore.setStatusBanner({
          kind: "success",
          message: `1080p30 CFR film rendered: ${res.data.video5xPath} (${res.data.frameCount} frames)`,
        });
      } else if (res.error) {
        workbenchStore.setStatusBanner({
          kind: "error",
          message: res.error.message,
        });
      }
    });
  };

  return (
    <div className="flex flex-col h-screen w-screen overflow-hidden bg-[#090d16] text-slate-100">
      {/* Pane 1: 8-Wave DAG + Gantt Flight Recorder + Gauges + Global Stop */}
      <FlightRecorderHeader
        workbench={ui.workbench}
        selectedWaveFilter={ui.selectedWaveFilter}
        ganttExpanded={ui.ganttExpanded}
        isFilmMode={isFilmMode}
        onSelectWave={(w) => workbenchStore.setWaveFilter(w)}
        onToggleGantt={() => workbenchStore.toggleGanttExpanded()}
        onSelectSpan={(sp) => {
          workbenchStore.selectStep(sp.stepId);
          const firstCite = sp.citedIds?.[0];
          if (firstCite) {
            workbenchStore.selectProvenanceBadge(firstCite);
          }
        }}
        onSwitchPresetRun={handleSwitchPresetRun}
        onGlobalStop={handleGlobalStop}
        onExportReport={handleExportReport}
        onRecordFilm={handleRecordFilm}
      />

      {ui.statusBanner && (
        <div
          className={`px-3 py-1 text-xs font-mono border-b shrink-0 flex items-center justify-between ${
            ui.statusBanner.kind === "error"
              ? "bg-rose-950/90 border-rose-500/60 text-rose-100"
              : ui.statusBanner.kind === "success"
                ? "bg-emerald-950/85 border-emerald-500/50 text-emerald-100"
                : "bg-cyan-950/80 border-cyan-500/40 text-cyan-100"
          }`}
        >
          <span>{ui.statusBanner.message}</span>
          <button
            type="button"
            onClick={() => workbenchStore.setStatusBanner(null)}
            className="text-[10px] underline cursor-pointer"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Synchronized 4-Pane Workspace Body */}
      <main className="flex-1 min-h-0 grid grid-cols-12 overflow-hidden">
        {/* Left/Center Column (8 cols): Pane 2 (Claims & Gates) + Pane 3 (uPlot Histogram & Dissector) */}
        <div className="col-span-8 flex flex-col min-h-0 overflow-hidden">
          <div className="h-[56%] min-h-0">
            <ClaimsAndGatesPane
              workbench={ui.workbench}
              centerTab={ui.centerTab}
              claimKindFilter={ui.claimKindFilter}
              selectedClaimId={ui.selectedClaimId}
              selectedCitationId={ui.selectedCitationId}
              selectedStepId={ui.selectedStepId}
              gateDraft={workbenchStore.getActiveGateDraft()}
              onSetCenterTab={(tab) => workbenchStore.setCenterTab(tab)}
              onSetClaimKindFilter={(kind) => workbenchStore.setClaimKindFilter(kind)}
              onSelectClaim={(cid) => workbenchStore.selectClaim(cid)}
              onSelectCitation={(id) => {
                workbenchStore.selectProvenanceBadge(id);
              }}
              onSelectStep={(sid) => workbenchStore.selectStep(sid)}
              onUpdateGateDraft={(patch) => workbenchStore.updateActiveGateDraft(patch)}
              onSubmitGateDecision={handleSubmitGateDecision}
            />
          </div>

          <div className="h-[44%] min-h-0">
            <TimelineDissectorPane
              workbench={ui.workbench}
              dissectorTab={ui.dissectorTab}
              dissectorSearch={ui.dissectorSearch}
              selectedCitationId={ui.selectedCitationId}
              timeBrushRangeMs={ui.timeBrushRangeMs}
              onSetDissectorTab={(tab) => workbenchStore.setDissectorTab(tab)}
              onSetDissectorSearch={(txt) => workbenchStore.setDissectorSearch(txt)}
              onSetTimeBrushRange={(range) => workbenchStore.setTimeBrushRange(range)}
              onSelectCitation={(id) => {
                workbenchStore.selectProvenanceBadge(id);
              }}
            />
          </div>
        </div>

        {/* Right Column (4 cols): Pane 4 (Sigma WebGL Attack Graph + Provenance Drawer) */}
        <div className="col-span-4 min-h-0 overflow-hidden">
          <AttackGraphLineagePane
            workbench={ui.workbench}
            selectedEntityId={ui.selectedEntityId}
            selectedEvidenceId={ui.selectedEvidenceId}
            selectedCitationId={ui.selectedCitationId}
            lastHighlightLatencyMs={ui.lastHighlightLatencyMs}
            onSelectProvenance={(id) => {
              workbenchStore.selectProvenanceBadge(id);
            }}
            onSelectClaim={(cid) => workbenchStore.selectClaim(cid)}
          />
        </div>
      </main>
    </div>
  );
}
