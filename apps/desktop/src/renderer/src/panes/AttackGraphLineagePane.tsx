import { useEffect, useMemo, useRef, useState } from "react";
import { Database, GitFork, Sparkles } from "lucide-react";
import { DirectedGraph } from "graphology";
import Sigma from "sigma";
import type { EntityKind } from "@hunt-command/shared";
import type { WorkbenchSnapshot } from "../../../shared/workbench-types.ts";
import { SafeForensicText } from "../components/SafeForensicText.tsx";

export interface AttackGraphLineagePaneProps {
  workbench: WorkbenchSnapshot;
  selectedEntityId: string | null;
  selectedEvidenceId: string | null;
  selectedCitationId: string | null;
  lastHighlightLatencyMs: number;
  onSelectProvenance: (id: string) => void;
  onSelectClaim: (claimId: string) => void;
}

const ENTITY_COLOR: Record<EntityKind, string> = {
  host: "#38bdf8",
  account: "#fbbf24",
  process: "#f43f5e",
  domain: "#a78bfa",
  address: "#34d399",
  key: "#fb923c",
  session: "#60a5fa",
  service: "#2dd4bf",
  resource: "#94a3b8",
};

function computeDeterministicEntityCoords(
  entities: WorkbenchSnapshot["snapshot"]["entities"],
): Map<string, { x: number; y: number }> {
  const rankByKind: Record<EntityKind, number> = {
    account: 0,
    host: 1,
    process: 2,
    domain: 3,
    address: 4,
    session: 1,
    service: 2,
    key: 3,
    resource: 4,
  };
  const buckets = new Map<number, string[]>();
  for (const ent of entities) {
    const rank = rankByKind[ent.kind] ?? 2;
    const list = buckets.get(rank) ?? [];
    list.push(ent.entity_id);
    buckets.set(rank, list);
  }

  const coords = new Map<string, { x: number; y: number }>();
  for (const [rank, ids] of buckets.entries()) {
    ids.forEach((id, idx) => {
      const x = rank * 2.2;
      const y = (idx - (ids.length - 1) / 2) * 1.8;
      coords.set(id, { x, y });
    });
  }
  return coords;
}

function canCreateWebGlContext(): boolean {
  if (typeof document === "undefined") return false;
  try {
    const canvas = document.createElement("canvas");
    return Boolean(canvas.getContext("webgl2") || canvas.getContext("webgl"));
  } catch {
    return false;
  }
}

export function AttackGraphLineagePane({
  workbench,
  selectedEntityId,
  selectedEvidenceId,
  selectedCitationId,
  lastHighlightLatencyMs,
  onSelectProvenance,
  onSelectClaim,
}: AttackGraphLineagePaneProps) {
  const sigmaHostRef = useRef<HTMLDivElement | null>(null);
  const [webglReady, setWebglReady] = useState(true);

  const coordsMap = useMemo(
    () => computeDeterministicEntityCoords(workbench.snapshot.entities),
    [workbench.snapshot.entities],
  );

  // Build Graphology DirectedGraph + Sigma v3 WebGL instance
  useEffect(() => {
    const container = sigmaHostRef.current;
    if (!container) return;

    if (!canCreateWebGlContext()) {
      setWebglReady(false);
      return;
    }

    const graph = new DirectedGraph();
    for (const ent of workbench.snapshot.entities) {
      const pos = coordsMap.get(ent.entity_id) ?? { x: 0, y: 0 };
      const isSelected = selectedEntityId === ent.entity_id;
      graph.addNode(ent.entity_id, {
        x: pos.x,
        y: pos.y,
        size: isSelected ? 13 : 9,
        label: ent.label,
        color: isSelected ? "#ffffff" : ENTITY_COLOR[ent.kind],
      });
    }

    for (const rel of workbench.snapshot.relations) {
      if (graph.hasNode(rel.subject_id) && graph.hasNode(rel.object_id)) {
        graph.addDirectedEdgeWithKey(rel.relation_id, rel.subject_id, rel.object_id, {
          label: rel.predicate,
          size: 2,
          color: "#475569",
        });
      }
    }

    let renderer: Sigma | null = null;
    try {
      renderer = new Sigma(graph, container, {
        renderLabels: true,
        renderEdgeLabels: true,
        labelColor: { color: "#e2e8f0" },
        labelSize: 11,
        labelFont: "Cascadia Mono, Consolas, monospace",
        edgeLabelSize: 9,
        edgeLabelColor: { color: "#94a3b8" },
        allowInvalidContainer: true,
      });

      renderer.on("clickNode", ({ node }) => {
        onSelectProvenance(node);
      });
      setWebglReady(true);
    } catch {
      setWebglReady(false);
    }

    return () => {
      renderer?.kill();
    };
  }, [workbench.snapshot, coordsMap, selectedEntityId, onSelectProvenance]);

  const activeEvidence =
    (selectedEvidenceId ? workbench.evidenceCatalog[selectedEvidenceId] : undefined) ??
    (selectedCitationId ? workbench.evidenceCatalog[selectedCitationId] : undefined) ??
    Object.values(workbench.evidenceCatalog)[0] ??
    null;

  return (
    <aside
      data-testid="attack-graph-lineage-pane"
      className="flex flex-col h-full min-h-0 bg-[#0b101d]"
    >
      {/* Top Half: Sigma.js v3 WebGL Entity Attack Graph */}
      <div className="flex flex-col h-1/2 min-h-[210px] border-b border-slate-800">
        <div className="flex items-center justify-between border-b border-slate-800 bg-[#0e1526] px-3 py-1.5 shrink-0">
          <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-200">
            <GitFork className="h-3.5 w-3.5 text-cyan-400" />
            <span>Entity Attack Graph ({workbench.snapshot.entities.length} nodes)</span>
          </div>
          <span className="font-mono text-[10px] text-emerald-400 flex items-center gap-1">
            <Sparkles className="h-3 w-3" />
            sync {lastHighlightLatencyMs.toFixed(2)}ms
          </span>
        </div>

        <div className="relative flex-1 min-h-0 bg-[#070b14]">
          {webglReady ? (
            <div ref={sigmaHostRef} className="absolute inset-0" />
          ) : (
            /* Deterministic SVG Attack Graph fallback when headless GPU disables WebGL */
            <svg viewBox="-1 -2.5 11 5" className="w-full h-full p-2">
              {workbench.snapshot.relations.map((rel) => {
                const a = coordsMap.get(rel.subject_id) ?? { x: 0, y: 0 };
                const b = coordsMap.get(rel.object_id) ?? { x: 0, y: 0 };
                return (
                  <line
                    key={rel.relation_id}
                    x1={a.x}
                    y1={a.y}
                    x2={b.x}
                    y2={b.y}
                    stroke="#475569"
                    strokeWidth="0.06"
                  />
                );
              })}
              {workbench.snapshot.entities.map((ent) => {
                const p = coordsMap.get(ent.entity_id) ?? { x: 0, y: 0 };
                const selected = selectedEntityId === ent.entity_id;
                return (
                  <g
                    key={ent.entity_id}
                    onClick={() => onSelectProvenance(ent.entity_id)}
                    className="cursor-pointer"
                  >
                    <circle
                      cx={p.x}
                      cy={p.y}
                      r={selected ? 0.28 : 0.2}
                      fill={ENTITY_COLOR[ent.kind]}
                      stroke={selected ? "#ffffff" : "none"}
                      strokeWidth="0.06"
                    />
                    <text
                      x={p.x}
                      y={p.y + 0.42}
                      textAnchor="middle"
                      fill="#cbd5e1"
                      fontSize="0.22"
                    >
                      {ent.entity_id}
                    </text>
                  </g>
                );
              })}
            </svg>
          )}
        </div>

        {/* Compact Entity Chips */}
        <div className="flex flex-wrap gap-1 border-t border-slate-800/80 bg-[#0a0f1c] px-2.5 py-1.5 shrink-0">
          {workbench.snapshot.entities.map((ent) => (
            <button
              key={ent.entity_id}
              type="button"
              onClick={() => onSelectProvenance(ent.entity_id)}
              className={`rounded border px-1.5 py-0.5 font-mono text-[10px] cursor-pointer ${
                selectedEntityId === ent.entity_id
                  ? "border-cyan-400 bg-cyan-950/80 text-cyan-100"
                  : "border-slate-800 bg-slate-900 text-slate-400 hover:text-slate-200"
              }`}
            >
              {ent.entity_id}
            </button>
          ))}
        </div>
      </div>

      {/* Bottom Half: Claim-to-Evidence Provenance Drawer */}
      <div
        data-testid="provenance-evidence-drawer"
        className="flex flex-col flex-1 min-h-0 overflow-hidden"
      >
        <div className="flex items-center justify-between border-b border-slate-800 bg-[#0e1526] px-3 py-1.5 shrink-0">
          <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-200">
            <Database className="h-3.5 w-3.5 text-emerald-400" />
            <span>Provenance &amp; Raw Record Drawer</span>
          </div>
          {activeEvidence && (
            <span className="rounded border border-emerald-500/40 bg-emerald-950/50 px-1.5 py-0.2 font-mono text-[10px] text-emerald-200">
              {activeEvidence.verified ? "VERIFIED IN STORE" : "UNRESOLVED"}
            </span>
          )}
        </div>

        <div className="flex-1 min-h-0 overflow-y-auto p-3 space-y-2.5 text-xs">
          {activeEvidence ? (
            <>
              <div>
                <div className="font-mono text-xs font-bold text-cyan-300">{activeEvidence.id}</div>
                <div className="text-[11px] text-slate-300 mt-0.5">{activeEvidence.title}</div>
              </div>

              {activeEvidence.citingClaimIds.length > 0 && (
                <div className="flex flex-wrap items-center gap-1">
                  <span className="text-[10px] font-mono text-slate-400">Cited by:</span>
                  {activeEvidence.citingClaimIds.map((cid) => (
                    <button
                      key={cid}
                      type="button"
                      onClick={() => onSelectClaim(cid)}
                      className="rounded border border-indigo-500/40 bg-indigo-950/50 px-1.5 py-0.5 font-mono text-[10px] text-indigo-200 cursor-pointer"
                    >
                      {cid}
                    </button>
                  ))}
                </div>
              )}

              <div className="rounded border border-slate-800 bg-[#070b14] divide-y divide-slate-800/70 font-mono text-[11px]">
                {Object.entries(activeEvidence.fields).map(([key, val]) => {
                  const strVal = Array.isArray(val) ? val.join(", ") : String(val);
                  if (strVal.length === 0) return null;
                  return (
                    <div key={key} className="grid grid-cols-12 gap-2 px-2.5 py-1">
                      <span className="col-span-5 text-slate-400 break-all">{key}</span>
                      <span className="col-span-7 text-slate-100 break-all">
                        <SafeForensicText
                          text={strVal}
                          selectedCitationId={selectedCitationId}
                          onSelectCitation={onSelectProvenance}
                        />
                      </span>
                    </div>
                  );
                })}
              </div>
            </>
          ) : (
            <div className="text-slate-500 font-mono text-[11px]">
              Click any evt-*, frame-*, ioc-*, or entity badge to inspect raw source telemetry.
            </div>
          )}
        </div>
      </div>
    </aside>
  );
}
