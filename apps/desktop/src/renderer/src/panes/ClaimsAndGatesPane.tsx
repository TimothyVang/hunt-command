import { useEffect, useMemo, useRef, useState } from "react";
import { Eye, FileText, GitCompare, Globe, Lock, ShieldCheck } from "lucide-react";
import { PROFILE_DISPLAY_TITLES, type ClaimKind } from "@hunt-command/shared";
import type {
  TranscriptPageSlice,
  WorkbenchSnapshot,
} from "../../../shared/workbench-types.ts";
import { SafeForensicText } from "../components/SafeForensicText.tsx";
import { invokeDesktop } from "../lib/bridge.ts";
import { buildWatchOpenRequest } from "../lib/watch-open.ts";
import type { CenterPaneTab, GateDraftFields } from "../state/workbench-store.ts";
import { AuthorityGateCard } from "./AuthorityGateCard.tsx";

export interface ClaimsAndGatesPaneProps {
  workbench: WorkbenchSnapshot;
  centerTab: CenterPaneTab;
  claimKindFilter: ClaimKind | "all";
  selectedClaimId: string | null;
  selectedCitationId: string | null;
  selectedStepId: string;
  gateDraft: GateDraftFields;
  onSetCenterTab: (tab: CenterPaneTab) => void;
  onSetClaimKindFilter: (kind: ClaimKind | "all") => void;
  onSelectClaim: (claimId: string) => void;
  onSelectCitation: (citationId: string) => void;
  onSelectStep: (stepId: string) => void;
  onUpdateGateDraft: (patch: Partial<GateDraftFields>) => void;
  onSubmitGateDecision: (action: "approve" | "reject") => void;
}

const CLAIM_KIND_BADGE: Record<ClaimKind, string> = {
  observed: "border-emerald-500/50 bg-emerald-950/50 text-emerald-200",
  finding: "border-cyan-500/50 bg-cyan-950/50 text-cyan-200",
  inference: "border-sky-500/50 bg-sky-950/50 text-sky-200",
  hypothesis: "border-violet-500/50 bg-violet-950/50 text-violet-200",
};

export function ClaimsAndGatesPane({
  workbench,
  centerTab,
  claimKindFilter,
  selectedClaimId,
  selectedCitationId,
  selectedStepId,
  gateDraft,
  onSetCenterTab,
  onSetClaimKindFilter,
  onSelectClaim,
  onSelectCitation,
  onSelectStep,
  onUpdateGateDraft,
  onSubmitGateDecision,
}: ClaimsAndGatesPaneProps) {
  const [transcriptPage, setTranscriptPage] = useState<TranscriptPageSlice | null>(null);
  const [byteOffset, setByteOffset] = useState(0);
  const [watchUrlInput, setWatchUrlInput] = useState("http://127.0.0.1:18400/");
  const [watchError, setWatchError] = useState<string | null>(null);
  const watchViewportRef = useRef<HTMLDivElement | null>(null);

  const handleWatchGo = () => {
    setWatchError(null);
    if (!workbench.watchState.enabled) {
      const built = buildWatchOpenRequest(workbench, watchUrlInput);
      if (!built.ok) {
        setWatchError(built.error);
        return;
      }
      void invokeDesktop("watch:open", built.request).then((res) => {
        if (!res.ok) setWatchError(res.error?.message ?? "Watch session could not be opened");
      });
      return;
    }
    void invokeDesktop("watch:navigate", {
      runId: workbench.watchState.runId,
      role: workbench.watchState.role,
      url: watchUrlInput,
    }).then((res) => {
      if (!res.ok) setWatchError(res.error?.message ?? "Navigation blocked");
    });
  };

  const citationStatusMap = useMemo(
    () =>
      new Map(
        workbench.citationReceipt.entries.map((entry) => [entry.citationId, entry.status] as const),
      ),
    [workbench.citationReceipt.entries],
  );

  useEffect(() => {
    setByteOffset(0);
  }, [selectedStepId, workbench.huntId]);

  useEffect(() => {
    if (centerTab !== "transcript") return;
    let cancelled = false;
    void invokeDesktop<TranscriptPageSlice>("hunt:inspectTranscriptPage", {
      huntId: workbench.huntId,
      stepId: selectedStepId,
      byteOffset,
      byteLimit: 16_384,
    }).then((res) => {
      if (!cancelled && res.ok && res.data) {
        setTranscriptPage(res.data);
      }
    });
    return () => {
      cancelled = true;
    };
  }, [centerTab, workbench.huntId, selectedStepId, byteOffset]);

  // Synchronize WebContentsView bounds only while the Watch tab is active.
  useEffect(() => {
    if (centerTab !== "watch") {
      void invokeDesktop("watch:setBounds", { bounds: null });
      return;
    }
    const reportBounds = () => {
      const el = watchViewportRef.current;
      if (!el) return;
      const rect = el.getBoundingClientRect();
      if (rect.width >= 100 && rect.height >= 100) {
        void invokeDesktop("watch:setBounds", {
          bounds: {
            x: Math.round(rect.left),
            y: Math.round(rect.top),
            width: Math.round(rect.width),
            height: Math.round(rect.height),
          },
        });
      }
    };
    reportBounds();
    window.addEventListener("resize", reportBounds);
    return () => {
      window.removeEventListener("resize", reportBounds);
      void invokeDesktop("watch:setBounds", { bounds: null });
    };
  }, [centerTab]);

  const filteredClaims =
    claimKindFilter === "all"
      ? workbench.claims
      : workbench.claims.filter((c) => c.claim.kind === claimKindFilter);

  return (
    <section className="flex flex-col h-full min-h-0 bg-[#0b101d] border-r border-slate-800">
      {/* Center Pane Mode Tabs */}
      <div className="flex items-center justify-between gap-2 border-b border-slate-800 bg-[#0e1526] px-3 py-1.5 shrink-0">
        <div className="flex items-center gap-1">
          <button
            type="button"
            onClick={() => onSetCenterTab("claims")}
            className={`inline-flex items-center gap-1.5 rounded px-2.5 py-1 text-xs font-medium cursor-pointer ${
              centerTab === "claims"
                ? "bg-cyan-950/80 text-cyan-200 border border-cyan-500/50"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <ShieldCheck className="h-3.5 w-3.5" />
            <span>Claims Matrix ({workbench.claims.length})</span>
          </button>

          <button
            type="button"
            onClick={() => onSetCenterTab("gate")}
            className={`inline-flex items-center gap-1.5 rounded px-2.5 py-1 text-xs font-medium cursor-pointer ${
              centerTab === "gate"
                ? "bg-amber-950/80 text-amber-200 border border-amber-500/60"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <Lock className="h-3.5 w-3.5 text-amber-400" />
            <span>Authority Gate</span>
            {workbench.activeGate && (
              <span className="rounded bg-amber-500/30 px-1.5 py-0.2 font-mono text-[10px] text-amber-100">
                {workbench.activeGate.gate.toUpperCase()}
              </span>
            )}
          </button>

          <button
            type="button"
            onClick={() => onSetCenterTab("transcript")}
            className={`inline-flex items-center gap-1.5 rounded px-2.5 py-1 text-xs font-medium cursor-pointer ${
              centerTab === "transcript"
                ? "bg-indigo-950/80 text-indigo-200 border border-indigo-500/50"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <FileText className="h-3.5 w-3.5" />
            <span>Transcript Slice</span>
          </button>

          <button
            type="button"
            onClick={() => onSetCenterTab("watch")}
            className={`inline-flex items-center gap-1.5 rounded px-2.5 py-1 text-xs font-medium cursor-pointer ${
              centerTab === "watch"
                ? "bg-emerald-950/80 text-emerald-200 border border-emerald-500/50"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <Eye className="h-3.5 w-3.5" />
            <span>Watch Browser</span>
          </button>
        </div>
      </div>

      {/* Tab Body */}
      <div className="flex-1 min-h-0 overflow-y-auto p-3 space-y-3">
        {centerTab === "gate" && (
          <>
            {workbench.activeGate ? (
              <AuthorityGateCard
                activeGate={workbench.activeGate}
                caseMetadata={workbench.caseMetadata}
                draft={gateDraft}
                onUpdateDraft={onUpdateGateDraft}
                onSubmitDecision={onSubmitGateDecision}
                onSelectCitation={onSelectCitation}
              />
            ) : (
              <div className="rounded border border-emerald-500/40 bg-emerald-950/25 p-4 text-xs text-emerald-200">
                No pending human gate — all required Gate 1/2 decisions for this hunt are signed.
              </div>
            )}

            {workbench.gateHistory.length > 0 && (
              <div className="rounded border border-slate-800 bg-slate-900/50 p-2.5 space-y-1.5">
                <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
                  Tamper-Evident Gate Decision Ledger (decisions.jsonl)
                </div>
                {workbench.gateHistory.map((gd) => (
                  <div
                    key={gd.decision_id}
                    className="rounded border border-slate-800 bg-slate-950/70 px-2.5 py-1.5 text-[11px] space-y-0.5"
                  >
                    <div className="flex items-center justify-between font-mono">
                      <span className="text-emerald-300">
                        {gd.gate.toUpperCase()} → {gd.action.toUpperCase()} by {gd.decided_by} (
                        {gd.rbac_role})
                      </span>
                      <span className="text-slate-500">{gd.decided_at}</span>
                    </div>
                    <div className="font-mono text-[10px] text-slate-500 truncate">
                      sha256: {gd.payload_sha256}
                    </div>
                    {gd.note && <div className="text-slate-300">{gd.note}</div>}
                  </div>
                ))}
              </div>
            )}
          </>
        )}

        {centerTab === "claims" && (
          <div className="space-y-2.5">
            {/* Kind Filter Strip */}
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-1 text-[11px] font-mono">
                {(["all", "observed", "finding", "hypothesis", "inference"] as const).map(
                  (kind) => (
                    <button
                      key={kind}
                      type="button"
                      onClick={() => onSetClaimKindFilter(kind)}
                      className={`rounded border px-2 py-0.5 uppercase cursor-pointer ${
                        claimKindFilter === kind
                          ? "border-cyan-400 bg-cyan-950/70 text-cyan-100"
                          : "border-slate-800 bg-slate-900 text-slate-400 hover:text-slate-200"
                      }`}
                    >
                      {kind}
                    </button>
                  ),
                )}
              </div>
              <span className="font-mono text-[11px] text-slate-400">
                Citations: {workbench.citationReceipt.verifiedCount}/
                {workbench.citationReceipt.totalCited} verified
              </span>
            </div>

            {/* Structured Claims Cards */}
            {filteredClaims.map((row) => {
              const isSelected = selectedClaimId === row.claim.claim_id;
              return (
                <article
                  key={row.claim.claim_id}
                  onClick={() => onSelectClaim(row.claim.claim_id)}
                  className={`rounded border p-2.5 space-y-2 transition-colors cursor-pointer ${
                    isSelected
                      ? "border-cyan-400/70 bg-[#111c33]"
                      : "border-slate-800 bg-[#0e1525] hover:border-slate-700"
                  }`}
                >
                  <div className="flex flex-wrap items-center justify-between gap-1.5">
                    <div className="flex items-center gap-1.5">
                      <span
                        className={`rounded border px-1.5 py-0.5 font-mono text-[10px] font-bold uppercase ${
                          CLAIM_KIND_BADGE[row.claim.kind]
                        }`}
                      >
                        {row.claim.kind}
                      </span>
                      <code className="text-xs font-semibold text-slate-100">
                        {row.claim.claim_id}
                      </code>
                      <span className="text-[11px] text-slate-400">
                        · {PROFILE_DISPLAY_TITLES[row.profile]} ({row.stepId})
                      </span>
                    </div>

                    <div className="flex items-center gap-1">
                      {row.reviews.map((rev) => (
                        <span
                          key={rev.review_id}
                          className={`rounded border px-1.5 py-0.5 font-mono text-[10px] ${
                            rev.disposition === "review_ready"
                              ? "border-violet-400/50 bg-violet-950/60 text-violet-200"
                              : "border-amber-400/60 bg-amber-950/60 text-amber-200"
                          }`}
                        >
                          purple:{rev.disposition}
                        </span>
                      ))}
                    </div>
                  </div>

                  <p className="text-xs leading-relaxed text-slate-200">
                    <SafeForensicText
                      text={row.claim.statement}
                      selectedCitationId={selectedCitationId}
                      citationStatusMap={citationStatusMap}
                      onSelectCitation={onSelectCitation}
                    />
                  </p>

                  {row.claim.contradicts.length > 0 && (
                    <div className="flex items-center gap-1.5 text-[11px] font-mono text-amber-300">
                      <GitCompare className="h-3.5 w-3.5" />
                      <span>Contradicts: {row.claim.contradicts.join(", ")}</span>
                    </div>
                  )}

                  {row.reviews.map((rev) => (
                    <div
                      key={rev.review_id}
                      className="rounded border border-violet-500/25 bg-violet-950/20 px-2 py-1 text-[11px] text-violet-100/90"
                    >
                      <span className="font-mono font-semibold text-violet-300">
                        [{rev.review_id}]{" "}
                      </span>
                      <SafeForensicText
                        text={rev.rationale}
                        selectedCitationId={selectedCitationId}
                        citationStatusMap={citationStatusMap}
                        onSelectCitation={onSelectCitation}
                      />
                    </div>
                  ))}
                </article>
              );
            })}

            {/* Telemetry Limitations */}
            {workbench.limitations.length > 0 && (
              <div className="rounded border border-slate-800 bg-slate-950/70 p-2.5 space-y-1">
                <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
                  Explicit Telemetry &amp; Visibility Limitations
                </div>
                {workbench.limitations.map((lim, i) => (
                  <div key={`${lim.stepId}-${i}`} className="text-xs text-slate-300">
                    <span className="font-mono text-cyan-300">[{lim.stepId}] </span>
                    <SafeForensicText
                      text={lim.text}
                      selectedCitationId={selectedCitationId}
                      citationStatusMap={citationStatusMap}
                      onSelectCitation={onSelectCitation}
                    />
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {centerTab === "transcript" && (
          <div className="space-y-2.5">
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <span className="text-xs text-slate-400">Step:</span>
                <select
                  value={selectedStepId}
                  onChange={(e) => onSelectStep(e.target.value)}
                  className="rounded border border-slate-700 bg-slate-900 px-2 py-1 font-mono text-xs text-slate-100"
                >
                  {workbench.steps.map((s) => (
                    <option key={s.stepId} value={s.stepId}>
                      W{s.waveNumber} · {s.stepId} ({s.profile})
                    </option>
                  ))}
                </select>
              </div>
              <div className="flex items-center gap-1.5 font-mono text-[11px] text-slate-400">
                <span>
                  Bytes {transcriptPage?.byteOffset ?? 0}..
                  {(transcriptPage?.byteOffset ?? 0) + (transcriptPage?.byteLength ?? 0)} /{" "}
                  {transcriptPage?.totalBytes ?? 0}
                </span>
                <button
                  type="button"
                  disabled={byteOffset === 0}
                  onClick={() => setByteOffset(Math.max(0, byteOffset - 16_384))}
                  className="rounded border border-slate-700 px-2 py-0.5 text-slate-200 disabled:opacity-40 cursor-pointer"
                >
                  Prev
                </button>
                <button
                  type="button"
                  disabled={!transcriptPage?.hasMore}
                  onClick={() => setByteOffset(byteOffset + 16_384)}
                  className="rounded border border-slate-700 px-2 py-0.5 text-slate-200 disabled:opacity-40 cursor-pointer"
                >
                  Next
                </button>
              </div>
            </div>
            <pre className="rounded border border-slate-800 bg-[#070b13] p-3 font-mono text-[11px] text-slate-200 whitespace-pre-wrap break-words">
              {transcriptPage?.content ?? "Loading byte-paged bot transcript slice..."}
            </pre>
          </div>
        )}

        {centerTab === "watch" && (
          <div className="flex flex-col h-full min-h-[300px] space-y-2">
            <div className="rounded border border-emerald-500/35 bg-emerald-950/20 p-2 text-[11px] font-mono space-y-1">
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-1.5 text-emerald-300 font-semibold">
                  <Globe className="h-3.5 w-3.5" />
                  Fenced Ephemeral Watch Browser ({workbench.watchState.partition})
                </span>
                <span className="text-slate-400">
                  Blocked egress attempts: {workbench.watchState.blockedRequestCount}
                </span>
              </div>
              <div className="text-slate-400">
                Pinned 127.0.0.1 Origins:{" "}
                {workbench.watchState.allowedOrigins.join(", ") || "none"} · Proxy Blackhole:
                127.0.0.1:1 (&lt;-loopback&gt;)
              </div>
            </div>

            <div className="flex items-center gap-1.5">
              <input
                type="text"
                value={watchUrlInput}
                onChange={(e) => setWatchUrlInput(e.target.value)}
                className="flex-1 rounded border border-slate-700 bg-slate-900 px-2.5 py-1 font-mono text-xs text-slate-100"
              />
              <button
                type="button"
                onClick={handleWatchGo}
                data-testid="watch-go"
                className="rounded border border-cyan-500/50 bg-cyan-950/70 px-3 py-1 text-xs font-medium text-cyan-100 cursor-pointer"
              >
                {workbench.watchState.enabled ? "Navigate (Pinned 127.0.0.1)" : "Open Fenced Session"}
              </button>
            </div>
            {watchError && (
              <div role="alert" className="text-[11px] font-mono text-rose-300">
                {watchError}
              </div>
            )}

            <div
              ref={watchViewportRef}
              className="flex-1 min-h-[220px] rounded border border-slate-800 bg-[#070a12] flex items-center justify-center text-xs font-mono text-slate-500"
            >
              Isolated WebContentsView Surface (cache=false · Fetch.enable · CDP-filtered)
            </div>
          </div>
        )}
      </div>
    </section>
  );
}
