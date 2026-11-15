import { tokenizeForensicText } from "../../../shared/sanitize.ts";
import { DefangedPill } from "./DefangedPill.tsx";

export interface SafeForensicTextProps {
  text: string;
  selectedCitationId?: string | null;
  citationStatusMap?: ReadonlyMap<string, "verified" | "unresolved" | "out_of_scope">;
  onSelectCitation?: (citationId: string) => void;
  className?: string;
}

/**
 * Renders untrusted model claims, tool outputs, and gate rationales exclusively as
 * sanitized React text nodes, interactive `evt-*`/`frame-*`/`ioc-*` provenance chips,
 * and `<DefangedPill />` buttons (zero `dangerouslySetInnerHTML`, zero `<a href>`).
 */
export function SafeForensicText({
  text,
  selectedCitationId,
  citationStatusMap,
  onSelectCitation,
  className,
}: SafeForensicTextProps) {
  const tokens = tokenizeForensicText(text);

  return (
    <span className={className}>
      {tokens.map((tok, index) => {
        if (tok.kind === "text") {
          return <span key={index}>{tok.text}</span>;
        }
        if (tok.kind === "indicator") {
          return (
            <DefangedPill
              key={index}
              raw={tok.raw}
              defanged={tok.defanged}
              indicatorKind={tok.indicatorKind}
            />
          );
        }

        const status = citationStatusMap?.get(tok.id) ?? "verified";
        const isSelected = selectedCitationId === tok.id;
        const colorClasses =
          status === "verified"
            ? isSelected
              ? "border-cyan-300 bg-cyan-500/30 text-cyan-100 ring-1 ring-cyan-400/60"
              : "border-cyan-500/40 bg-cyan-950/55 text-cyan-200 hover:border-cyan-400"
            : "border-amber-500/60 bg-amber-950/60 text-amber-200 hover:border-amber-400";

        return (
          <button
            key={index}
            type="button"
            data-testid={`citation-badge-${tok.id}`}
            onClick={(e) => {
              e.stopPropagation();
              onSelectCitation?.(tok.id);
            }}
            title={`Provenance ${tok.citationKind.toUpperCase()} (${status}) — click to cross-highlight timeline, graph & raw record`}
            className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 font-mono text-[11px] transition-colors cursor-pointer align-baseline ${colorClasses}`}
          >
            <span>{tok.id}</span>
            <span
              className={`h-1.5 w-1.5 rounded-full ${
                status === "verified" ? "bg-emerald-400" : "bg-amber-400"
              }`}
            />
          </button>
        );
      })}
    </span>
  );
}
