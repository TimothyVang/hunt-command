import { useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import type {
  DaemonEventBatchPayload,
  FilmExportResult,
  ReportExportResult,
  StartRunInput,
} from "../../shared/ipc.ts";
import type { WatchBrowserState, WorkbenchSnapshot } from "../../shared/workbench-types.ts";
import { EventRefreshGuard, listRuns, loadGateEvidencePage, selectRun, startRun } from "./lib/run-actions.ts";
import { invokeDesktop, subscribeDesktopEvent } from "./lib/bridge.ts";
import { scopeWatchSnapshot } from "./lib/watch-open.ts";
import { AttackGraphLineagePane } from "./panes/AttackGraphLineagePane.tsx";
import { ClaimsAndGatesPane } from "./panes/ClaimsAndGatesPane.tsx";
import { FlightRecorderHeader } from "./panes/FlightRecorderHeader.tsx";
import { RunControls, type RunOption } from "./panes/RunControls.tsx";
import { TimelineDissectorPane } from "./panes/TimelineDissectorPane.tsx";
import { type WorkbenchConnection, workbenchStore } from "./state/workbench-store.ts";

function WorkbenchUnavailable({
  connection,
}: {
  connection: Exclude<WorkbenchConnection, { kind: "ready" }>;
}) {
  return (
    <div className="flex h-screen w-screen items-center justify-center bg-[#090d16] text-slate-100">
      {connection.kind === "connecting" ? (
        <p className="font-mono text-sm text-slate-400" role="status">
          Connecting to the Hunt Command main process...
        </p>
      ) : (
        <div
          role="alert"
          data-testid="workbench-unavailable"
          className="max-w-xl rounded border border-rose-500/60 bg-rose-950/60 p-4 font-mono text-sm space-y-2"
        >
          <p className="font-semibold text-rose-100">Workbench unavailable ({connection.code})</p>
          <p className="text-rose-200/90">{connection.message}</p>
          <p className="text-slate-400 text-xs">No hunt data is displayed until the desktop bridge responds.</p>
        </div>
      )}
    </div>
  );
}

export function App() {
  const ui = useSyncExternalStore(workbenchStore.subscribe, workbenchStore.getState);
  const selectedHunt = useRef<string | null>(null);
  const selectionVersion = useRef(0);
  const [switchingHunt, setSwitchingHunt] = useState(false);
  const [runs, setRuns] = useState<RunOption[]>([]);
  const [runError, setRunError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  const watchEvents = useRef(new Map<string, { version: number; state: WatchBrowserState }>());
  const watchVersion = useRef(0);
  const eventRefresh = useMemo(() => new EventRefreshGuard(), []);

  const applySnapshot = (snapshot: WorkbenchSnapshot, requestVersion: number) => {
    eventRefresh.snapshotApplied();
    const latest = watchEvents.current.get(snapshot.huntId);
    workbenchStore.setWorkbenchSnapshot(scopeWatchSnapshot(
      snapshot,
      latest && latest.version > requestVersion ? latest.state : undefined,
    ));
  };

  const refreshRuns = (preserveError = false) => {
    void listRuns().then((res) => {
      if (res.ok && res.data) {
        setRuns(res.data);
        if (!preserveError) setRunError(null);
      } else if (!preserveError) {
        setRunError(res.error?.message ?? "Could not list hunts.");
      }
    });
  };

  const isFilmMode = useMemo(() => {
    if (typeof window === "undefined") return false;
    return new URLSearchParams(window.location.search).get("film") === "1";
  }, []);

  useEffect(() => {
    refreshRuns();
    const initialHuntId =
      typeof window !== "undefined"
        ? new URLSearchParams(window.location.search).get("huntId") ?? undefined
        : undefined;

    selectedHunt.current = initialHuntId ?? null;
    const initialSelection = selectionVersion.current;
    const initialVersion = watchVersion.current;
    void invokeDesktop<WorkbenchSnapshot>(
      "hunt:getWorkbenchState",
      initialHuntId ? { huntId: initialHuntId } : undefined,
    ).then((res) => {
      if (res.ok && res.data && initialSelection === selectionVersion.current && (!selectedHunt.current || selectedHunt.current === res.data.huntId)) {
        selectedHunt.current = res.data.huntId;
        applySnapshot(res.data, initialVersion);
      } else if (!res.ok && initialSelection === selectionVersion.current) {
        workbenchStore.setConnectionUnavailable(
          res.error?.code ?? "WORKBENCH_UNAVAILABLE",
          res.error?.message ?? "The main process returned no workbench snapshot.",
        );
      }
    });

    const unsubBatch = subscribeDesktopEvent<DaemonEventBatchPayload>(
      "daemon:eventBatch",
      (batch) => {
        if (selectedHunt.current !== batch.huntId) return;
        const requestVersion = watchVersion.current;
        const selection = selectionVersion.current;
        void eventRefresh.refresh(
          batch.huntId,
          () => selection === selectionVersion.current && selectedHunt.current === batch.huntId,
          (snapshot) => applySnapshot(snapshot, requestVersion),
        );
      },
    );

    const unsubWatch = subscribeDesktopEvent<WatchBrowserState>("watch:stateChanged", (watch) => {
      watchEvents.current.set(watch.runId, { version: ++watchVersion.current, state: watch });
      const curr = workbenchStore.getState().workbench;
      if (watch.runId !== curr.huntId || selectedHunt.current !== curr.huntId) return;
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
    const selection = ++selectionVersion.current;
    selectedHunt.current = huntId;
    setSwitchingHunt(true);
    if (ui.connection.kind === "ready") {
      void invokeDesktop("watch:setBounds", { runId: ui.workbench.huntId, bounds: null });
    }
    const requestVersion = watchVersion.current;
    void selectRun(huntId).then((res) => {
      if (selection !== selectionVersion.current) return;
      setSwitchingHunt(false);
      if (res.ok && res.data && selectedHunt.current === huntId) {
        applySnapshot(res.data, requestVersion);
        setRunError(null);
        workbenchStore.setStatusBanner(null);
      } else {
        selectedHunt.current = ui.connection.kind === "ready" ? workbenchStore.getState().workbench.huntId : null;
        setRunError(res.error?.message ?? "Could not switch hunts.");
      }
    });
  };

  const handleStartRun = (input: StartRunInput) => {
    const selection = ++selectionVersion.current;
    const requestVersion = watchVersion.current;
    setStarting(true);
    setRunError(null);
    void startRun(input).then((res) => {
      setStarting(false);
      if (selection !== selectionVersion.current) return;
      if (res.ok && res.data) {
        if (ui.connection.kind === "ready") {
          void invokeDesktop("watch:setBounds", { runId: ui.workbench.huntId, bounds: null });
        }
        selectedHunt.current = res.data.huntId;
        applySnapshot(res.data, requestVersion);
        refreshRuns();
      } else {
        setRunError(res.error?.message ?? "Could not start hunt.");
        refreshRuns(true);
      }
    });
  };

  const handleLoadMoreEvidence = (): Promise<string | null> => {
    const snapshot = workbenchStore.getState().workbench;
    const selection = selectionVersion.current;
    const snapshotVersion = workbenchStore.getSnapshotVersion();
    const requestVersion = watchVersion.current;
    return loadGateEvidencePage(
      snapshot,
      () => selection === selectionVersion.current && selectedHunt.current === snapshot.huntId,
      () => snapshotVersion === workbenchStore.getSnapshotVersion(),
      (page) => applySnapshot(page, requestVersion),
    );
  };

  const handleGlobalStop = () => {
    const requestVersion = watchVersion.current;
    const selection = selectionVersion.current;
    void invokeDesktop<WorkbenchSnapshot>("hunt:globalStop", {
      huntId: ui.workbench.huntId,
      reason: "operator_global_stop",
    }).then((res) => {
      if (res.ok && res.data && selection === selectionVersion.current && selectedHunt.current === res.data.huntId) {
        applySnapshot(res.data, requestVersion);
        workbenchStore.setStatusBanner({
          kind: "info",
          message: `Global Stop executed on ${res.data.huntId}: all in-flight bot steps halted.`,
        });
      } else if ((!res.ok || !res.data) && selection === selectionVersion.current) {
        workbenchStore.setStatusBanner({
          kind: "error",
          message: res.error?.message ?? "Global Stop failed; the hunt may still be running.",
        });
      }
    });
  };

  const handleSubmitGateDecision = (action: "approve" | "reject", operatorToken?: string) => {
    const gate = ui.workbench.activeGate;
    if (!gate) return;
    const draft = workbenchStore.getActiveGateDraft();
    const requestVersion = watchVersion.current;
    const selection = selectionVersion.current;

    void invokeDesktop<WorkbenchSnapshot>("hunt:submitGateDecision", {
      huntId: ui.workbench.huntId,
      gate: gate.gate,
      action,
      operatorName: draft.operatorName,
      rbacRole: draft.rbacRole,
      checkNote: draft.checkNote,
      ...(operatorToken ? { operatorToken } : {}),
      payloadSha256: gate.payloadSha256,
    }).then((res) => {
      if (res.ok && res.data && selection === selectionVersion.current && selectedHunt.current === res.data.huntId) {
        applySnapshot(res.data, requestVersion);
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

  const controls = !isFilmMode && (
    <RunControls runs={runs} selectedHuntId={ui.connection.kind === "ready" ? ui.workbench.huntId : null}
      busy={starting || switchingHunt} error={runError} onStart={handleStartRun}
      onSelect={handleSwitchPresetRun} onRefresh={() => refreshRuns()} />
  );
  if (ui.connection.kind !== "ready") {
    return <div className="flex h-screen flex-col bg-[#090d16] text-slate-100">{controls}<WorkbenchUnavailable connection={ui.connection} /></div>;
  }

  return (
    <div className="flex flex-col h-screen w-screen overflow-hidden bg-[#090d16] text-slate-100">
      {controls}
      {ui.workbench.provenanceMode === "fixture_preview" && (
        <div
          role="status"
          data-testid="fixture-preview-banner"
          className="px-3 py-1 text-xs font-mono font-semibold border-b shrink-0 bg-amber-950/90 border-amber-500/70 text-amber-100"
        >
          FIXTURE PREVIEW: built-in synthetic sample data, not results from a live hunt-daemon run.
        </div>
      )}

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
              switchingHunt={switchingHunt}
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
              onLoadMoreEvidence={handleLoadMoreEvidence}
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
