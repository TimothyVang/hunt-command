import { useState } from "react";
import { AlertOctagon, CheckCircle2, FileCheck2, Lock, ShieldAlert, XCircle } from "lucide-react";
import {
  formatRealDataOriginText,
  FRAMEWORK_PROFILES,
  PROFILE_DISPLAY_TITLES,
  type CaseMetadata,
} from "@hunt-command/shared";
import { missingGateContextReason, validateGateSubmission } from "../../../shared/gate-validation.ts";
import { SafeForensicText } from "../components/SafeForensicText.tsx";
import type { ActiveGatePrompt } from "../../../shared/workbench-types.ts";
import type { GateDraftFields } from "../state/workbench-store.ts";

export interface AuthorityGateCardProps {
  activeGate: ActiveGatePrompt;
  caseMetadata: CaseMetadata;
  requiresToken: boolean;
  draft: GateDraftFields;
  onUpdateDraft: (patch: Partial<GateDraftFields>) => void;
  onSubmitDecision: (action: "approve" | "reject", operatorToken?: string) => void;
  onSelectCitation: (citationId: string) => void;
}

export function AuthorityGateCard({
  activeGate,
  caseMetadata,
  requiresToken,
  draft,
  onUpdateDraft,
  onSubmitDecision,
  onSelectCitation,
}: AuthorityGateCardProps) {
  const [operatorToken, setOperatorToken] = useState("");
  const submit = (action: "approve" | "reject") => {
    onSubmitDecision(action, requiresToken ? operatorToken : undefined);
    setOperatorToken("");
  };
  const approveValidation = validateGateSubmission(activeGate, {
    operatorName: draft.operatorName,
    rbacRole: draft.rbacRole,
    checkNote: draft.checkNote,
    payloadSha256: activeGate.payloadSha256,
    action: "approve",
  });

  const rejectValidation = validateGateSubmission(activeGate, {
    operatorName: draft.operatorName,
    rbacRole: draft.rbacRole,
    checkNote: draft.checkNote,
    payloadSha256: activeGate.payloadSha256,
    action: "reject",
  });

  const contextMissing = missingGateContextReason(activeGate);

  const citationBlocked =
    activeGate.gate === "incident" &&
    activeGate.incidentSummary !== undefined &&
    !activeGate.incidentSummary.citationReceipt.allVerified;

  return (
    <div
      data-testid={`authority-gate-card-${activeGate.gate}`}
      className="rounded-md border border-amber-500/50 bg-[#0f1628] p-3.5 space-y-3 shadow-lg"
    >
      {/* Header */}
      <div className="flex items-start justify-between gap-2 border-b border-slate-800 pb-2.5">
        <div>
          <div className="flex items-center gap-2">
            <Lock className="h-4 w-4 text-amber-400" />
            <h2 className="text-xs font-bold uppercase tracking-wider text-amber-200">
              {activeGate.gate === "scope"
                ? "Human Authority Gate 1 — Hunt Scope & Data-Origin Authorization"
                : activeGate.gate === "incident"
                  ? "Human Authority Gate 2 — Incident Report & Citation Verification"
                  : "Crash-Recovery Authority Gate — Reconcile In-Flight Dispatch"}
            </h2>
          </div>
          <p className="mt-0.5 text-[11px] text-slate-400 font-mono">
            Opened {activeGate.openedAtIso} · Expires {activeGate.expiresAtIso}
          </p>
        </div>
        <span className="rounded border border-amber-500/40 bg-amber-950/60 px-2 py-0.5 font-mono text-[10px] text-amber-200">
          via=desktop (human-only)
        </span>
      </div>

      {/* Data Origin Banner (Prominent crimson Rule 4 warning when !synthetic_only) */}
      {caseMetadata.data_origin === "synthetic" ? (
        <div className="flex items-center justify-between rounded border border-emerald-500/40 bg-emerald-950/35 px-3 py-1.5 text-xs text-emerald-200">
          <span className="font-semibold">DATA ORIGIN: SYNTHETIC LAB TELEMETRY</span>
          <span className="font-mono text-[11px]">synthetic_only=true</span>
        </div>
      ) : (
        <div
          data-testid="gate-non-synthetic-banner"
          className="rounded border border-rose-500 bg-rose-950/80 px-3 py-2 text-xs text-rose-100 space-y-1"
        >
          <div className="flex items-center gap-1.5 font-bold uppercase tracking-wide text-rose-200">
            <ShieldAlert className="h-4 w-4 text-rose-400 shrink-0" />
            <span>RULE 4 NON-SYNTHETIC TELEMETRY NOTICE — {caseMetadata.data_origin}</span>
          </div>
          <p className="text-[11px] text-rose-100/90">
            {formatRealDataOriginText(caseMetadata.data_origin)}. External notifications carry{" "}
            <code className="font-mono">hunt_id + status</code> only; offscreen film export is blocked
            unless explicit local operator watermark override is enabled.
          </p>
        </div>
      )}

      {activeGate.gate === "scope" && activeGate.scopeText && (
        <div className="rounded border border-slate-800 bg-slate-950/80 p-2 text-xs">
          <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-slate-400">Hunt scope</div>
          <SafeForensicText text={activeGate.scopeText} className="whitespace-pre-wrap break-words text-slate-100" />
        </div>
      )}

      {/* Gate 1: Scope Details + Read-Only Role Tool Ownership Matrix */}
      {activeGate.gate === "scope" && activeGate.scopeSummary && (
        <div className="space-y-2.5 text-xs">
          <div className="grid grid-cols-3 gap-2 font-mono text-[11px]">
            <div className="rounded border border-slate-800 bg-slate-900/70 p-2">
              <div className="text-slate-400 text-[10px]">HOSTS IN SCOPE</div>
              <div className="text-slate-100 mt-0.5">
                {activeGate.scopeSummary.hostsInScope.join(", ")}
              </div>
            </div>
            <div className="rounded border border-slate-800 bg-slate-900/70 p-2">
              <div className="text-slate-400 text-[10px]">TOKEN CEILING</div>
              <div className="text-cyan-300 mt-0.5">
                {activeGate.scopeSummary.maxTotalTokens.toLocaleString()} tokens
              </div>
            </div>
            <div className="rounded border border-slate-800 bg-slate-900/70 p-2">
              <div className="text-slate-400 text-[10px]">FOLLOW-UP CAP (WAVE 4)</div>
              <div className="text-slate-100 mt-0.5">
                K = {activeGate.scopeSummary.followUpCount} bounded tasks
              </div>
            </div>
          </div>

          <div className="rounded border border-slate-800 bg-slate-950/80 p-2">
            <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
              Per-Role Read-Only Tool Ownership Matrix (Enforced by Data-Plane)
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-1.5 font-mono text-[11px]">
              {FRAMEWORK_PROFILES.map((role) => {
                const tools = activeGate.scopeSummary?.allowedRoleTools[role] ?? [];
                return (
                  <div
                    key={role}
                    className="flex items-start justify-between gap-2 rounded border border-slate-800/80 bg-slate-900/50 px-2 py-1"
                  >
                    <span className="text-cyan-300 shrink-0">{PROFILE_DISPLAY_TITLES[role]}</span>
                    <span className="text-right text-slate-300">
                      {tools.length > 0 ? tools.join(", ") : "[] (no data-plane tools in scope)"}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* Gate 2: Automated Citation Verification Receipt + Epistemic Split + Purple Summary */}
      {activeGate.gate === "incident" && activeGate.incidentSummary && (
        <div className="space-y-2.5 text-xs">
          <div
            data-testid="citation-verification-receipt"
            className={`rounded border p-2.5 ${
              activeGate.incidentSummary.citationReceipt.allVerified
                ? "border-emerald-500/45 bg-emerald-950/30"
                : "border-rose-500/70 bg-rose-950/50"
            }`}
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5 font-semibold">
                {activeGate.incidentSummary.citationReceipt.allVerified ? (
                  <FileCheck2 className="h-4 w-4 text-emerald-400" />
                ) : (
                  <AlertOctagon className="h-4 w-4 text-rose-400" />
                )}
                <span className="text-slate-100">
                  Automated Citation Verification Receipt:{" "}
                  <span className="font-mono">
                    {activeGate.incidentSummary.citationReceipt.verifiedCount}/
                    {activeGate.incidentSummary.citationReceipt.totalCited}
                  </span>{" "}
                  resolved
                </span>
              </div>
              <span className="font-mono text-[11px] text-slate-300">
                unresolved={activeGate.incidentSummary.citationReceipt.unresolvedCount} · out_of_scope=
                {activeGate.incidentSummary.citationReceipt.outOfScopeCount}
              </span>
            </div>

            <div className="mt-2 flex flex-wrap gap-1.5">
              {activeGate.incidentSummary.citationReceipt.entries.map((entry) => (
                <button
                  key={entry.citationId}
                  type="button"
                  onClick={() => onSelectCitation(entry.citationId)}
                  className={`rounded border px-1.5 py-0.5 font-mono text-[10px] cursor-pointer ${
                    entry.status === "verified"
                      ? "border-emerald-500/40 bg-emerald-950/50 text-emerald-200"
                      : "border-rose-500 bg-rose-950 text-rose-200 font-bold"
                  }`}
                >
                  {entry.citationId} ({entry.status})
                </button>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-3 gap-2 font-mono text-[11px]">
            <div className="rounded border border-slate-800 bg-slate-900/70 p-2">
              <div className="text-slate-400 text-[10px]">OBSERVED &amp; FINDINGS</div>
              <div className="text-emerald-300 mt-0.5">
                {activeGate.incidentSummary.observedCount} observed ·{" "}
                {activeGate.incidentSummary.findingCount} findings
              </div>
            </div>
            <div className="rounded border border-slate-800 bg-slate-900/70 p-2">
              <div className="text-slate-400 text-[10px]">INFERENCE &amp; HYPOTHESIS</div>
              <div className="text-sky-300 mt-0.5">
                {activeGate.incidentSummary.inferenceCount} inferences ·{" "}
                {activeGate.incidentSummary.hypothesisCount} hypotheses
              </div>
            </div>
            <div className="rounded border border-slate-800 bg-slate-900/70 p-2">
              <div className="text-slate-400 text-[10px]">PURPLE ADVERSARIAL REVIEW</div>
              <div className="text-violet-300 mt-0.5">
                {activeGate.incidentSummary.purpleVerdictCounts.review_ready} ready ·{" "}
                {activeGate.incidentSummary.purpleVerdictCounts.needs_revision} rev ·{" "}
                {activeGate.incidentSummary.limitationCount} limitations
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Crash-Recovery Reconcile Gate */}
      {activeGate.gate === "reconcile" && activeGate.reconcileContext && (
        <div
          data-testid="reconcile-gate-context"
          className="rounded border border-amber-500/50 bg-amber-950/30 p-2.5 font-mono text-[11px] space-y-1"
        >
          <div className="font-bold text-amber-200">
            reason_code: {activeGate.reconcileContext.reasonCode}
          </div>
          <div className="text-slate-300">
            execution_id: {activeGate.reconcileContext.executionId} · session_id:{" "}
            {activeGate.reconcileContext.sessionId}
          </div>
          <div className="text-slate-300">
            step_id: {activeGate.reconcileContext.stepId} ({activeGate.reconcileContext.profile}) ·
            input_id: {activeGate.reconcileContext.inputId}
          </div>
          <div className="text-slate-400">
            reserved_at: {activeGate.reconcileContext.reservedAtIso} — Daemon crashed after reserving
            step execution receipt; operator must approve replay or reject to halt run cleanly.
          </div>
        </div>
      )}

      {/* 64-Hex SHA-256 Tamper-Evident Payload Digest */}
      <div className="rounded border border-slate-800 bg-slate-950 px-2.5 py-1.5 font-mono text-[11px] flex items-center justify-between gap-2">
        <span className="text-slate-400 shrink-0">PAYLOAD SHA-256:</span>
        <code data-testid="gate-sha256-digest" className="text-cyan-300 break-all">
          {activeGate.payloadSha256}
        </code>
      </div>

      {/* Operator Principal, Role & Mandatory "What did you check?" (1..1000 chars) */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
        <label className="space-y-1">
          <span className="text-[11px] font-medium text-slate-300">Operator Principal</span>
          <input
            type="text"
            value={draft.operatorName}
            onChange={(e) => onUpdateDraft({ operatorName: e.target.value })}
            placeholder="analyst.handle"
            className="w-full rounded border border-slate-700 bg-slate-900 px-2.5 py-1.5 font-mono text-xs text-slate-100 focus:border-cyan-500 focus:outline-none"
          />
        </label>

        <label className="space-y-1">
          <span className="text-[11px] font-medium text-slate-300">RBAC Authority Role</span>
          <select
            value={draft.rbacRole}
            onChange={(e) =>
              onUpdateDraft({
                rbacRole: e.target.value as GateDraftFields["rbacRole"],
              })
            }
            className="w-full rounded border border-slate-700 bg-slate-900 px-2.5 py-1.5 font-mono text-xs text-slate-100 focus:border-cyan-500 focus:outline-none"
          >
            <option value="lead_hunter">lead_hunter</option>
            <option value="incident_commander">incident_commander</option>
            <option value="soc_lead">soc_lead</option>
          </select>
        </label>
      </div>

      {requiresToken && (
        <label className="block space-y-1 text-xs">
          <span className="text-slate-300">Signed operator token</span>
          <input type="password" autoComplete="off" value={operatorToken}
            onChange={(e) => setOperatorToken(e.target.value)}
            className="w-full rounded border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-slate-100 focus:border-cyan-500 focus:outline-none" />
        </label>
      )}

      <label className="block space-y-1">
        <div className="flex items-center justify-between text-[11px]">
          <span className="font-semibold text-slate-200">
            What did you check? <span className="text-amber-300">(Required · 1..1000 chars)</span>
          </span>
          <span className="font-mono text-slate-400">{draft.checkNote.trim().length} / 1000</span>
        </div>
        <textarea
          rows={2}
          data-testid="gate-check-note-input"
          value={draft.checkNote}
          onChange={(e) => onUpdateDraft({ checkNote: e.target.value })}
          placeholder="Document the specific raw records, host/time bounds, or purple review findings you verified..."
          className="w-full rounded border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-xs text-slate-100 focus:border-cyan-500 focus:outline-none"
        />
      </label>

      {citationBlocked && (
        <div
          data-testid="gate2-unresolved-blocker"
          className="rounded border border-rose-500/70 bg-rose-950/60 px-2.5 py-1.5 text-[11px] font-medium text-rose-200"
        >
          Approve is hard-blocked: all inline evt-*/frame-*/ioc-* citations must resolve in the bounded
          case store before Gate 2 Incident sign-off.
        </div>
      )}

      {contextMissing && (
        <div
          role="alert"
          data-testid="gate-context-unavailable"
          className="rounded border border-rose-500/70 bg-rose-950/60 px-2.5 py-1.5 text-[11px] font-medium text-rose-200"
        >
          {contextMissing} You can still reject this gate.
        </div>
      )}

      {/* Action Buttons */}
      <div className="flex items-center justify-end gap-2 pt-1">
        <button
          type="button"
          data-testid="gate-reject-button"
          disabled={!rejectValidation.valid || (requiresToken && !operatorToken.trim())}
          onClick={() => submit("reject")}
          className="inline-flex items-center gap-1.5 rounded border border-rose-500/70 bg-rose-950/70 px-3 py-1.5 text-xs font-semibold text-rose-100 hover:bg-rose-900 disabled:opacity-40 cursor-pointer"
        >
          <XCircle className="h-3.5 w-3.5" />
          <span>Reject Gate</span>
        </button>
        <button
          type="button"
          data-testid="gate-approve-button"
          disabled={contextMissing !== null || !approveValidation.valid || (requiresToken && !operatorToken.trim())}
          onClick={() => submit("approve")}
          className="inline-flex items-center gap-1.5 rounded border border-emerald-400/70 bg-emerald-700 px-3.5 py-1.5 text-xs font-bold text-white hover:bg-emerald-600 disabled:opacity-40 cursor-pointer"
        >
          <CheckCircle2 className="h-3.5 w-3.5" />
          <span>Approve &amp; Sign Digest</span>
        </button>
      </div>
    </div>
  );
}
