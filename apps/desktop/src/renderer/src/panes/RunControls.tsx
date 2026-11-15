import { useState, type FormEvent } from "react";
import { DATA_ORIGINS, type DataOrigin } from "@hunt-command/shared";
import type { StartRunInput } from "../../../shared/ipc.ts";

export interface RunOption {
  huntId: string;
  caseId: string;
  runStatus: string;
}

export function RunControls({ runs, selectedHuntId, busy, error, onStart, onSelect, onRefresh }: {
  runs: RunOption[];
  selectedHuntId: string | null;
  busy: boolean;
  error: string | null;
  onStart: (input: StartRunInput) => void;
  onSelect: (huntId: string) => void;
  onRefresh: () => void;
}) {
  const [caseId, setCaseId] = useState("");
  const [scope, setScope] = useState("");
  const [dataOrigin, setDataOrigin] = useState<DataOrigin>("synthetic");
  const [maxTotalTokens, setMaxTotalTokens] = useState(4_000_000);
  const [followUps, setFollowUps] = useState(6);
  const field = "rounded border border-slate-700 bg-slate-900 px-2 py-1 text-slate-100";
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!caseId.trim() || !scope.trim()) return;
    onStart({ caseId: caseId.trim(), scope, dataOrigin, maxTotalTokens, followUps });
  };
  return (
    <section aria-label="Hunt runs" className="shrink-0 border-b border-slate-800 bg-[#0c1220] p-2 text-xs space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <label>Active hunt {" "}
          <select aria-label="Select Active Hunt Run" className={field} value={selectedHuntId ?? ""} onChange={(e) => e.target.value && onSelect(e.target.value)} disabled={busy}>
            <option value="">Select a run</option>
            {selectedHuntId && !runs.some((run) => run.huntId === selectedHuntId) && <option value={selectedHuntId}>{selectedHuntId}</option>}
            {runs.map((run) => <option key={run.huntId} value={run.huntId}>{run.caseId} · {run.huntId} · {run.runStatus}</option>)}
          </select>
        </label>
        <button type="button" className={field} onClick={onRefresh} disabled={busy}>Refresh runs</button>
      </div>
      <details>
        <summary className="cursor-pointer font-semibold text-cyan-200">Start a hunt</summary>
        <form onSubmit={submit} className="mt-2 flex flex-wrap items-end gap-2">
          <label className="grid gap-1">Case ID<input className={field} required maxLength={128} value={caseId} onChange={(e) => setCaseId(e.target.value)} /></label>
          <label className="grid gap-1">Scope<textarea className={field} required maxLength={100000} rows={2} value={scope} onChange={(e) => setScope(e.target.value)} /></label>
          <label className="grid gap-1">Data origin<select className={field} value={dataOrigin} onChange={(e) => setDataOrigin(e.target.value as DataOrigin)}>{DATA_ORIGINS.map((origin) => <option key={origin} value={origin}>{origin}</option>)}</select></label>
          <label className="grid gap-1">Token limit<input className={field} type="number" required min={10000} max={50000000} step={1} value={maxTotalTokens} onChange={(e) => setMaxTotalTokens(e.target.valueAsNumber)} /></label>
          <label className="grid gap-1">Follow-ups<input className={field} type="number" required min={0} max={12} step={1} value={followUps} onChange={(e) => setFollowUps(e.target.valueAsNumber)} /></label>
          <button className={field} disabled={busy} type="submit">{busy ? "Working…" : "Start hunt"}</button>
        </form>
      </details>
      {error && <p role="alert" className="text-rose-300">{error}</p>}
    </section>
  );
}
