import { useEffect, useMemo, useRef, useState } from "react";
import { FilterX, Layers, Network, Radio, Search } from "lucide-react";
import uPlot from "uplot";
import type { WorkbenchSnapshot } from "../../../shared/workbench-types.ts";
import { SafeForensicText } from "../components/SafeForensicText.tsx";
import type { DissectorTab } from "../state/workbench-store.ts";

export interface TimelineDissectorPaneProps {
  workbench: WorkbenchSnapshot;
  dissectorTab: DissectorTab;
  dissectorSearch: string;
  selectedCitationId: string | null;
  timeBrushRangeMs: readonly [number, number] | null;
  onSetDissectorTab: (tab: DissectorTab) => void;
  onSetDissectorSearch: (text: string) => void;
  onSetTimeBrushRange: (range: readonly [number, number] | null) => void;
  onSelectCitation: (citationId: string) => void;
}

const ROW_HEIGHT_PX = 30;
const OVERSCAN_ROWS = 8;

export function TimelineDissectorPane({
  workbench,
  dissectorTab,
  dissectorSearch,
  selectedCitationId,
  timeBrushRangeMs,
  onSetDissectorTab,
  onSetDissectorSearch,
  onSetTimeBrushRange,
  onSelectCitation,
}: TimelineDissectorPaneProps) {
  const chartHostRef = useRef<HTMLDivElement | null>(null);
  const scrollContainerRef = useRef<HTMLDivElement | null>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewportHeight, setViewportHeight] = useState(180);

  // Mount uPlot 60fps Canvas Histogram with brush-to-zoom
  useEffect(() => {
    const host = chartHostRef.current;
    if (!host) return;

    const width = Math.max(320, host.clientWidth || 760);
    const height = 96;

    const alignedData: uPlot.AlignedData = [
      workbench.histogram.bucketTimestampsSec,
      workbench.histogram.ecsEventCounts,
      workbench.histogram.networkFlowCounts,
    ];

    const opts: uPlot.Options = {
      width,
      height,
      cursor: {
        drag: { x: true, y: false, setScale: false },
      },
      scales: {
        x: { time: true },
        y: { auto: true },
      },
      axes: [
        {
          stroke: "#64748b",
          grid: { stroke: "rgba(51,65,85,0.35)", width: 1 },
          font: "10px Cascadia Mono, Consolas, monospace",
        },
        {
          stroke: "#64748b",
          size: 36,
          grid: { stroke: "rgba(51,65,85,0.35)", width: 1 },
          font: "10px Cascadia Mono, Consolas, monospace",
        },
      ],
      series: [
        {},
        {
          label: "ECS Events",
          stroke: "#22d3ee",
          fill: "rgba(34, 211, 238, 0.18)",
          width: 1.5,
        },
        {
          label: "Arkime / PCAP Flows",
          stroke: "#a78bfa",
          fill: "rgba(167, 139, 250, 0.15)",
          width: 1.5,
        },
      ],
      hooks: {
        setSelect: [
          (u: uPlot) => {
            if (u.select.width >= 6) {
              const minSec = u.posToVal(u.select.left, "x");
              const maxSec = u.posToVal(u.select.left + u.select.width, "x");
              if (Number.isFinite(minSec) && Number.isFinite(maxSec) && maxSec > minSec) {
                onSetTimeBrushRange([Math.round(minSec * 1000), Math.round(maxSec * 1000)]);
              }
            }
          },
        ],
      },
    };

    let plot: uPlot | null = null;
    try {
      host.replaceChildren();
      plot = new uPlot(opts, alignedData, host);
    } catch {
      // Headless environments without Canvas2D ignore uPlot draw cleanly.
    }

    const handleResize = () => {
      if (plot && host.clientWidth > 100) {
        plot.setSize({ width: host.clientWidth, height });
      }
    };
    window.addEventListener("resize", handleResize);
    return () => {
      window.removeEventListener("resize", handleResize);
      plot?.destroy();
    };
  }, [workbench.histogram, onSetTimeBrushRange]);

  useEffect(() => {
    const scroller = scrollContainerRef.current;
    if (!scroller) return;
    setViewportHeight(scroller.clientHeight || 180);
  }, [dissectorTab]);

  const needle = dissectorSearch.trim().toLowerCase();
  const inBrush = (tsMs: number): boolean => {
    if (!timeBrushRangeMs) return true;
    return tsMs >= timeBrushRangeMs[0] && tsMs <= timeBrushRangeMs[1];
  };

  const filteredEvents = useMemo(
    () =>
      workbench.events.filter((ev) => {
        if (!inBrush(ev.timestampMs)) return false;
        if (!needle) return true;
        return (
          ev.eventId.toLowerCase().includes(needle) ||
          ev.hostName.toLowerCase().includes(needle) ||
          ev.processName.toLowerCase().includes(needle) ||
          ev.commandLine.toLowerCase().includes(needle) ||
          ev.message.toLowerCase().includes(needle)
        );
      }),
    [workbench.events, needle, timeBrushRangeMs],
  );

  const filteredFlows = useMemo(
    () =>
      workbench.arkimeFlows.filter((fl) => {
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
      }),
    [workbench.arkimeFlows, needle, timeBrushRangeMs],
  );

  const filteredPackets = useMemo(
    () =>
      workbench.packets.filter((pkt) => {
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
      }),
    [workbench.packets, needle, timeBrushRangeMs],
  );

  const activeCount =
    dissectorTab === "events"
      ? filteredEvents.length
      : dissectorTab === "arkime"
        ? filteredFlows.length
        : filteredPackets.length;

  const startIdx = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT_PX) - OVERSCAN_ROWS);
  const endIdx = Math.min(
    activeCount,
    Math.ceil((scrollTop + viewportHeight) / ROW_HEIGHT_PX) + OVERSCAN_ROWS,
  );

  return (
    <section
      data-testid="timeline-dissector-pane"
      className="flex flex-col h-full min-h-0 bg-[#090e1a] border-t border-slate-800"
    >
      {/* Histogram Header */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 bg-[#0d1424] px-3 py-1 shrink-0">
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => onSetDissectorTab("events")}
            className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-[11px] font-mono cursor-pointer ${
              dissectorTab === "events"
                ? "bg-cyan-950 text-cyan-200 border border-cyan-500/50"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <Layers className="h-3 w-3 text-cyan-400" />
            <span>ECS Events ({filteredEvents.length})</span>
          </button>

          <button
            type="button"
            onClick={() => onSetDissectorTab("arkime")}
            className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-[11px] font-mono cursor-pointer ${
              dissectorTab === "arkime"
                ? "bg-violet-950 text-violet-200 border border-violet-500/50"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <Network className="h-3 w-3 text-violet-400" />
            <span>Arkime Sessions ({filteredFlows.length})</span>
          </button>

          <button
            type="button"
            onClick={() => onSetDissectorTab("packets")}
            className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-[11px] font-mono cursor-pointer ${
              dissectorTab === "packets"
                ? "bg-emerald-950 text-emerald-200 border border-emerald-500/50"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <Radio className="h-3 w-3 text-emerald-400" />
            <span>Packet Fields / JA4 ({filteredPackets.length})</span>
          </button>
        </div>

        <div className="flex items-center gap-2">
          {timeBrushRangeMs && (
            <button
              type="button"
              onClick={() => onSetTimeBrushRange(null)}
              className="inline-flex items-center gap-1 rounded border border-cyan-500/50 bg-cyan-950/60 px-2 py-0.5 font-mono text-[10px] text-cyan-200 cursor-pointer"
            >
              <FilterX className="h-3 w-3" />
              <span>Clear Time Brush</span>
            </button>
          )}

          <div className="relative">
            <Search className="h-3 w-3 text-slate-500 absolute left-2 top-1.5" />
            <input
              type="text"
              value={dissectorSearch}
              onChange={(e) => onSetDissectorSearch(e.target.value)}
              placeholder="Filter events, JA4, frame-*..."
              className="rounded border border-slate-700 bg-slate-900 pl-6 pr-2 py-0.5 font-mono text-[11px] text-slate-200 w-52 focus:border-cyan-500 focus:outline-none"
            />
          </div>
        </div>
      </div>

      {/* uPlot 60fps Canvas Histogram */}
      <div className="border-b border-slate-800/80 bg-[#080c16] px-2 py-1 shrink-0">
        <div ref={chartHostRef} className="w-full h-[96px]" />
      </div>

      {/* Virtualized Pure Text-Node Dissector Grid */}
      <div
        ref={scrollContainerRef}
        onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)}
        className="flex-1 min-h-0 overflow-y-auto font-mono text-[11px]"
      >
        <div
          style={{
            height: `${Math.max(activeCount * ROW_HEIGHT_PX, ROW_HEIGHT_PX)}px`,
            position: "relative",
          }}
        >
          <div style={{ transform: `translateY(${startIdx * ROW_HEIGHT_PX}px)` }}>
            {dissectorTab === "events" &&
              filteredEvents.slice(startIdx, endIdx).map((ev) => {
                const isSelected = selectedCitationId === ev.eventId;
                return (
                  <div
                    key={ev.eventId}
                    onClick={() => onSelectCitation(ev.eventId)}
                    style={{ height: `${ROW_HEIGHT_PX}px` }}
                    className={`grid grid-cols-12 items-center gap-2 border-b border-slate-800/60 px-3 cursor-pointer ${
                      isSelected ? "bg-cyan-950/60 text-cyan-100" : "hover:bg-slate-900/80 text-slate-300"
                    }`}
                  >
                    <span className="col-span-2 truncate text-cyan-300 font-semibold">
                      {ev.eventId}
                    </span>
                    <span className="col-span-2 truncate text-slate-400">
                      {ev.timestampIso.slice(11, 23)}Z
                    </span>
                    <span className="col-span-2 truncate text-emerald-300">
                      {ev.hostName} · {ev.processName}
                    </span>
                    <span className="col-span-6 truncate">
                      <SafeForensicText
                        text={ev.commandLine}
                        selectedCitationId={selectedCitationId}
                        onSelectCitation={onSelectCitation}
                      />
                    </span>
                  </div>
                );
              })}

            {dissectorTab === "arkime" &&
              filteredFlows.slice(startIdx, endIdx).map((fl) => (
                <div
                  key={fl.sessionId}
                  onClick={() => {
                    const firstFrame = fl.linkedFrameIds[0];
                    if (firstFrame) onSelectCitation(firstFrame);
                  }}
                  style={{ height: `${ROW_HEIGHT_PX}px` }}
                  className="grid grid-cols-12 items-center gap-2 border-b border-slate-800/60 px-3 hover:bg-slate-900/80 text-slate-300 cursor-pointer"
                >
                  <span className="col-span-2 truncate text-violet-300">{fl.sessionId}</span>
                  <span className="col-span-3 truncate">
                    {fl.sourceIp}:{fl.sourcePort} → {fl.destinationIp}:{fl.destinationPort}
                  </span>
                  <span className="col-span-2 truncate text-slate-400">
                    {fl.protocol.join("/")} · {fl.networkBytes} B
                  </span>
                  <span className="col-span-3 truncate text-amber-200">
                    {fl.tlsJa4 ? `JA4:${fl.tlsJa4}` : fl.dnsHost}
                  </span>
                  <span className="col-span-2 truncate text-cyan-300 text-right">
                    {fl.linkedFrameIds.join(", ")}
                  </span>
                </div>
              ))}

            {dissectorTab === "packets" &&
              filteredPackets.slice(startIdx, endIdx).map((pkt) => {
                const isSelected = selectedCitationId === pkt.frameId;
                return (
                  <div
                    key={pkt.frameId}
                    onClick={() => onSelectCitation(pkt.frameId)}
                    style={{ height: `${ROW_HEIGHT_PX}px` }}
                    className={`grid grid-cols-12 items-center gap-2 border-b border-slate-800/60 px-3 cursor-pointer ${
                      isSelected
                        ? "bg-emerald-950/55 text-emerald-100"
                        : "hover:bg-slate-900/80 text-slate-300"
                    }`}
                  >
                    <span className="col-span-2 truncate text-emerald-300 font-semibold">
                      {pkt.frameId} ({pkt.protocol})
                    </span>
                    <span className="col-span-3 truncate">
                      {pkt.ipSrc} → {pkt.ipDst}
                      {pkt.dstPort ? `:${pkt.dstPort}` : ""}
                    </span>
                    <span className="col-span-3 truncate text-amber-200">
                      {pkt.httpRequestUriRedacted || pkt.dnsTxtAnswer || pkt.dnsQryName}
                    </span>
                    <span className="col-span-4 truncate text-cyan-200">
                      {pkt.tlsJa4 ? `tls.handshake.ja4=${pkt.tlsJa4}` : `len=${pkt.frameLen}B`}
                    </span>
                  </div>
                );
              })}
          </div>
        </div>
      </div>
    </section>
  );
}
