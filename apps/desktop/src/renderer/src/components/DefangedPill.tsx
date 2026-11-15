import { useState } from "react";
import { Check, Copy, ShieldAlert } from "lucide-react";
import { defangIndicator, type IndicatorKind } from "../../../shared/sanitize.ts";

export interface DefangedPillProps {
  raw: string;
  defanged?: string;
  indicatorKind?: IndicatorKind;
}

/**
 * Copy-Only Defanged Indicator Pill (`#178` G1.2, `#189`).
 *
 * Security invariants:
 * - Renders `<button type="button">` ONLY — NEVER `<a href>` and NEVER calls `window.open`.
 * - Copies the defanged representation (`hxxps://...`, `[.]`) to clipboard so pasting into notes,
 *   Slack, or tickets cannot auto-unfurl a live C2 or canary URL.
 */
export function DefangedPill({ raw, defanged, indicatorKind = "url" }: DefangedPillProps) {
  const [copied, setCopied] = useState(false);
  const safeText = defanged ?? defangIndicator(raw);

  const handleCopy = () => {
    void navigator.clipboard?.writeText(safeText).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1_400);
    });
  };

  return (
    <button
      type="button"
      onClick={(e) => {
        e.stopPropagation();
        handleCopy();
      }}
      title={`Defanged ${indicatorKind.toUpperCase()} indicator (click to copy defanged text — external launch disabled)`}
      data-testid="defanged-pill"
      className="inline-flex items-center gap-1 rounded border border-rose-500/35 bg-rose-950/45 px-1.5 py-0.5 font-mono text-[11px] text-rose-200 hover:border-rose-400/70 hover:bg-rose-900/50 transition-colors align-baseline cursor-pointer"
    >
      <ShieldAlert className="h-3 w-3 text-rose-400 shrink-0" />
      <span className="truncate max-w-[340px]">{safeText}</span>
      {copied ? (
        <Check className="h-3 w-3 text-emerald-400 shrink-0" />
      ) : (
        <Copy className="h-2.5 w-2.5 text-rose-300/70 shrink-0" />
      )}
    </button>
  );
}
