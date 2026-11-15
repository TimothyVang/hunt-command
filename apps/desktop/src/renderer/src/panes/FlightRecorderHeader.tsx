import {
  Activity,
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  DollarSign,
  Download,
  Film,
  OctagonX,
  ShieldCheck,
  Zap,
} from "lucide-react";
import { HUNT_WAVE_TOPOLOGY } from "@hunt-command/shared";
import type { GanttSpanRecord, WorkbenchSnapshot } from "../../../shared/workbench-types.ts";

export interface FlightRecorderHeaderProps {
  workbench: WorkbenchSnapshot;
  selectedWaveFilter: number | null;
  ganttExpanded: boolean;
  isFilmMode: boolean;
  onSelectWave: (waveNumber: number | null) => void;
  onToggleGantt: () => void;
  onSelectSpan: (span: GanttSpanRecord) => void;
  onSwitchPresetRun: (huntId: string) => void;
  onGlobalStop: () => void;
  onExportReport: () => void;
  onRecordFilm: () => void;
}

function spanBarColor(span: GanttSpanRecord): string {
  if (span.status === "refused" || span.refusal?.refused) {
    return "bg-rose-600/85 border-rose-400";
  }
  switch (span.kind) {
    case "gen_ai.execute_tool":
      return "bg-cyan-600/80 border-cyan-400/80";
    case "gen_ai.chat":
      return "bg-indigo-600/80 border-indigo-400/80";
    case "hunt.handoff.validate":
      return "bg-emerald-600/80 border-emerald-400/80";
    case "hunt.gate.decision":
      return "bg-amber-600/85 border-amber-400";
    default:
      return "bg-slate-600/80 border-slate-400";
  }
}

export function FlightRecorderHeader({
  workbench,
  selectedWaveFilter,
  ganttExpanded,
  isFilmMode,
  onSelectWave,
  onToggleGantt,
  onSelectSpan,
  onSwitchPresetRun,
  onGlobalStop,
  onExportReport,
  onRecordFilm,
}: FlightRecorderHeaderProps) {
  const { gauges, steps, ganttSpans, caseMetadata } = workbench;
  const cachePct = (gauges.promptCacheHitRatio * 100).toFixed(1);
  const tokenPct = Math.min(100, (gauges.totalTokensUsed / Math.max(1, gauges.maxTotalTokens)) * 100);

  const visibleSpans = selectedWaveFilter
    ? ganttSpans.filter((s) => s.waveNumber === selectedWaveFilter)
    : ganttSpans;

  const minEpochMs =
    visibleSpans.length > 0 ? Math.min(...visibleSpans.map((s) => s.startEpochMs)) : 0;
  const maxEpochMs =
    visibleSpans.length > 0
      ? Math.max(...visibleSpans.map((s) => s.endEpochMs), minEpochMs + 1_000)
      : 1_000;
  const totalWindowMs = Math.max(1_000, maxEpochMs - minEpochMs);

  return (
    <header className="border-b border-slate-800 bg-[#0c1220] shrink-0 select-none">
      {/* Non-Synthetic Rule 4 Global Strip */}
      {!caseMetadata.synthetic_only && (
        <div
          data-testid="rule4-global-banner"
          className="flex items-center justify-between bg-rose-950/90 border-b border-rose-500/60 px-3 py-1 text-[11px] font-semibold text-rose-100"
        >
          <span className="flex items-center gap-1.5">
            <AlertTriangle className="h-3.5 w-3.5 text-rose-400" />
            RULE 4 NON-SYNTHETIC CASE ({caseMetadata.data_origin.toUpperCase()}) — EXTERNAL EGRESS RESTRICTED TO ID+STATUS; FILM RECORDING WATERMARKED
          </span>
          <span className="font-mono text-[10px] text-rose-200">synthetic_only=false</span>
        </div>
      )}

      {/* Top Tactical Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 px-3 py-2 border-b border-slate-800/80">
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="flex items-center gap-1.5 rounded border border-cyan-500/40 bg-cyan-950/50 px-2 py-1">
            <ShieldCheck className="h-4 w-4 text-cyan-400" />
            <span className="text-xs font-bold tracking-wider uppercase text-cyan-100">
              HUNT COMMAND
            </span>
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2 text-xs font-semibold text-slate-100 truncate">
              <span className="font-mono text-cyan-300">{caseMetadata.case_id}</span>
              <span className="text-slate-600">·</span>
              <span className="truncate max-w-[360px]">{caseMetadata.title}</span>
              <span
                className={`rounded px-1.5 py-0.5 font-mono text-[10px] uppercase ${
                  workbench.runStatus === "stopped"
                    ? "bg-rose-950 text-rose-300 border border-rose-600/50"
                    : workbench.runStatus === "awaiting_human_gate"
                      ? "bg-amber-950 text-amber-200 border border-amber-500/60"
                      : "bg-emerald-950 text-emerald-300 border border-emerald-600/50"
                }`}
              >
                {workbench.runStatus}
              </span>
            </div>
            <div className="flex items-center gap-2 text-[10px] font-mono text-slate-400">
              <span>Run: {workbench.huntId}</span>
              <span>·</span>
              <span>
                Window: {caseMetadata.time_window.start_iso} → {caseMetadata.time_window.end_iso}
              </span>
              <span>·</span>
              <span>Origin: {caseMetadata.data_origin}</span>
            </div>
          </div>
        </div>

        {/* Live Telemetry Gauges + Global Stop */}
        <div className="flex items-center gap-2">
          {!isFilmMode && (
            <select
              aria-label="Select Active Hunt Run"
              value={workbench.huntId}
              onChange={(e) => onSwitchPresetRun(e.target.value)}
              className="rounded border border-slate-700 bg-slate-900 px-2 py-1 font-mono text-[11px] text-slate-200 focus:border-cyan-500 focus:outline-none"
            >
              <option value="hunt-20261115-nv01">nv01 · Gate 2 Incident (Synthetic)</option>
              <option value="hunt-20261115-scope-work">nv01 · Gate 1 Scope (Work-Export)</option>
              <option value="hunt-20261115-reconcile">nv01 · Reconcile Crash Recovery</option>
            </select>
          )}

          {/* Prompt-Cache Hit % Gauge */}
          <div
            data-testid="cache-hit-gauge"
            className={`flex items-center gap-1.5 rounded border px-2 py-1 text-[11px] font-mono ${
              gauges.cacheBelowTarget
                ? "border-amber-500/70 bg-amber-950/60 text-amber-200"
                : "border-emerald-500/40 bg-emerald-950/40 text-emerald-200"
            }`}
            title="Per-conversation prompt cache hit ratio (target >= 76%)"
          >
            <Zap className="h-3.5 w-3.5 shrink-0" />
            <span>CACHE {cachePct}%</span>
            {gauges.cacheBelowTarget && (
              <span className="rounded bg-amber-500/30 px-1 text-[9px] font-bold text-amber-100">
                &lt;76% WARN
              </span>
            )}
          </div>

          {/* $0 OAuth Actual vs Shadow API Cost */}
          <div
            data-testid="oauth-shadow-cost"
            className="flex items-center gap-1.5 rounded border border-slate-700 bg-slate-900/80 px-2 py-1 text-[11px] font-mono text-slate-200"
            title="Subscription OAuth actual billed cost vs theoretical public API shadow cost"
          >
            <DollarSign className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
            <span className="text-emerald-300">${gauges.actualBilledUsd.toFixed(2)} OAuth</span>
            <span className="text-slate-500">/</span>
            <span className="text-slate-400">${gauges.shadowApiUsd.toFixed(2)} Shadow</span>
          </div>

          {/* Token Ceiling Bar */}
          <div className="hidden xl:flex flex-col justify-center rounded border border-slate-700 bg-slate-900/80 px-2 py-0.5 w-44">
            <div className="flex justify-between font-mono text-[10px] text-slate-300">
              <span>TOKENS</span>
              <span>
                {(gauges.totalTokensUsed / 1_000).toFixed(0)}k /{" "}
                {(gauges.maxTotalTokens / 1_000).toFixed(0)}k
              </span>
            </div>
            <div className="mt-0.5 h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
              <div
                className="h-full bg-cyan-400 transition-all"
                style={{ width: `${tokenPct.toFixed(1)}%` }}
              />
            </div>
          </div>

          {!isFilmMode && (
            <>
              <button
                type="button"
                onClick={onExportReport}
                className="inline-flex items-center gap-1 rounded border border-slate-700 bg-slate-800/90 px-2 py-1 text-[11px] font-medium text-slate-200 hover:border-cyan-500/60 hover:text-cyan-100 cursor-pointer"
                title="Export Customer Report (.md + .pdf + provenance JSON without answer keys)"
              >
                <Download className="h-3.5 w-3.5 text-cyan-400" />
                <span>Report</span>
              </button>

              <button
                type="button"
                onClick={onRecordFilm}
                className="inline-flex items-center gap-1 rounded border border-slate-700 bg-slate-800/90 px-2 py-1 text-[11px] font-medium text-slate-200 hover:border-indigo-400/60 hover:text-indigo-100 cursor-pointer"
                title="Render Offscreen 1920x1080 CFR 30fps MP4 + ASS subtitles"
              >
                <Film className="h-3.5 w-3.5 text-indigo-400" />
                <span>1080p30 Film</span>
              </button>
            </>
          )}

          {/* Prominent Global Stop Button (F13) */}
          <button
            type="button"
            data-testid="global-stop-button"
            onClick={onGlobalStop}
            disabled={workbench.runStatus === "stopped"}
            className="inline-flex items-center gap-1.5 rounded border border-rose-500 bg-rose-700 px-2.5 py-1 text-xs font-bold tracking-wide uppercase text-white shadow-sm hover:bg-rose-600 disabled:opacity-45 cursor-pointer"
          >
            <OctagonX className="h-3.5 w-3.5" />
            <span>GLOBAL STOP</span>
          </button>
        </div>
      </div>

      {/* 8-Wave Topological DAG Bar */}
      <div className="flex items-center justify-between gap-1.5 px-3 py-1.5 bg-[#0a0f1c] overflow-x-auto">
        <div className="flex items-center gap-1">
          {HUNT_WAVE_TOPOLOGY.map((waveDef, idx) => {
            const waveSteps = steps.filter((s) => s.waveNumber === waveDef.waveNumber);
            const hasGate = waveSteps.some((s) => s.state === "awaiting_approval");
            const hasRefusal = waveSteps.some((s) => Boolean(s.refusal?.refused));
            const allDone =
              waveSteps.length > 0 && waveSteps.every((s) => s.state === "done");
            const isSelected = selectedWaveFilter === waveDef.waveNumber;

            const pillColor = hasGate
              ? "border-amber-400 bg-amber-950/70 text-amber-100"
              : hasRefusal
                ? "border-rose-500/60 bg-rose-950/50 text-rose-200"
                : allDone
                  ? "border-emerald-500/40 bg-emerald-950/35 text-emerald-200"
                  : "border-slate-700 bg-slate-900/70 text-slate-300";

            return (
              <div key={waveDef.waveGateId} className="flex items-center gap-1">
                <button
                  type="button"
                  onClick={() => onSelectWave(waveDef.waveNumber)}
                  className={`flex items-center gap-1.5 rounded border px-2 py-0.5 text-[11px] font-mono transition-colors cursor-pointer ${pillColor} ${
                    isSelected ? "ring-1 ring-cyan-400" : ""
                  }`}
                >
                  <span className="font-bold text-slate-400">W{waveDef.waveNumber}</span>
                  <span>{waveDef.wave}</span>
                  {waveDef.humanGate && (
                    <span className="rounded bg-amber-500/25 px-1 text-[9px] text-amber-200">
                      GATE
                    </span>
                  )}
                  {hasRefusal && (
                    <span className="rounded bg-rose-500/30 px-1 text-[9px] text-rose-200">
                      CYBER-REFUSAL
                    </span>
                  )}
                </button>
                {idx < HUNT_WAVE_TOPOLOGY.length - 1 && (
                  <span className="text-slate-600 text-[10px]">→</span>
                )}
              </div>
            );
          })}
        </div>

        <button
          type="button"
          onClick={onToggleGantt}
          className="inline-flex items-center gap-1 rounded border border-slate-800 bg-slate-900 px-2 py-0.5 text-[11px] font-mono text-slate-300 hover:border-slate-600 cursor-pointer shrink-0"
        >
          <Activity className="h-3 w-3 text-cyan-400" />
          <span>Gantt Waterfall ({visibleSpans.length})</span>
          {ganttExpanded ? (
            <ChevronDown className="h-3 w-3" />
          ) : (
            <ChevronRight className="h-3 w-3" />
          )}
        </button>
      </div>

      {/* Collapsible DevTools Gantt Hunt Flight Recorder */}
      {ganttExpanded && (
        <div
          data-testid="gantt-flight-recorder"
          className="max-h-36 overflow-y-auto border-t border-slate-800/80 bg-[#080c15] px-3 py-1.5 space-y-1"
        >
          {visibleSpans.map((sp) => {
            const leftPct = ((sp.startEpochMs - minEpochMs) / totalWindowMs) * 100;
            const widthPct = Math.max(1.8, (sp.durationMs / totalWindowMs) * 100);
            return (
              <div
                key={sp.spanId}
                onClick={() => onSelectSpan(sp)}
                className="group grid grid-cols-12 items-center gap-2 rounded px-1.5 py-0.5 hover:bg-slate-900/90 cursor-pointer text-[11px]"
              >
                <div className="col-span-4 flex items-center gap-1.5 truncate font-mono">
                  <span className="text-slate-500">W{sp.waveNumber}</span>
                  <span className="text-cyan-300 font-semibold">{sp.stepId}</span>
                  <span className="truncate text-slate-300">{sp.label}</span>
                </div>
                <div className="col-span-6 relative h-4 rounded bg-slate-900/90 border border-slate-800/80 overflow-hidden">
                  <div
                    className={`absolute top-0.5 bottom-0.5 rounded-sm border ${spanBarColor(sp)}`}
                    style={{
                      left: `${Math.min(98, Math.max(0, leftPct)).toFixed(2)}%`,
                      width: `${Math.min(100 - leftPct, widthPct).toFixed(2)}%`,
                    }}
                  />
                </div>
                <div className="col-span-2 flex items-center justify-end gap-1.5 font-mono text-[10px] text-slate-400">
                  {sp.refusal?.refused && (
                    <span className="rounded bg-rose-950 border border-rose-500/60 px-1 text-rose-200 font-semibold">
                      REFUSAL:{sp.refusal.category ?? "cyber"}
                    </span>
                  )}
                  <span>{(sp.durationMs / 1000).toFixed(2)}s</span>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </header>
  );
}
