import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { buildFixtureWorkbenchSnapshot } from "../src/shared/fixture-workbench.ts";
import { AuthorityGateCard } from "../src/renderer/src/panes/AuthorityGateCard.tsx";
import { RunControls } from "../src/renderer/src/panes/RunControls.tsx";
import { listRuns, selectRun, startRun } from "../src/renderer/src/lib/run-actions.ts";

describe("live run controls", () => {
  test("offers all supported start fields and live run selection", () => {
    const html = renderToStaticMarkup(<RunControls runs={[{ huntId: "live-123", caseId: "case-42", runStatus: "running" }]}
      selectedHuntId="live-123" busy={false} error={null} onStart={() => {}} onSelect={() => {}} onRefresh={() => {}} />);
    expect(html).toContain("Case ID");
    expect(html).toContain("Scope");
    expect(html).toContain("Data origin");
    expect(html).toContain("work-connected");
    expect(html).toContain("Token limit");
    expect(html).toContain("Follow-ups");
    expect(html).toContain("live-123");
    expect(html).toContain("Refresh runs");
  });

  test("live gate requires an externally issued token without storing it in the draft", () => {
    const snapshot = buildFixtureWorkbenchSnapshot();
    if (!snapshot.activeGate) throw new Error("Expected a fixture gate");
    const html = renderToStaticMarkup(<AuthorityGateCard activeGate={snapshot.activeGate}
      caseMetadata={snapshot.caseMetadata} requiresToken draft={{ operatorName: "operator", rbacRole: "lead_hunter", checkNote: "checked" }}
      onUpdateDraft={() => {}} onSubmitDecision={() => {}} onSelectCitation={() => {}} />);
    expect(html).toContain("Signed operator token");
    expect(html).toContain('type="password"');
    expect(html).toContain('data-testid="gate-reject-button" disabled');
  });

  test("shows the daemon's scope text on a live scope gate", () => {
    const snapshot = buildFixtureWorkbenchSnapshot({ openGate: "scope" });
    if (!snapshot.activeGate) throw new Error("Expected a scope gate");
    const gate = { ...snapshot.activeGate, scopeSummary: undefined, scopeText: "Investigate workstation alpha" };
    const html = renderToStaticMarkup(<AuthorityGateCard activeGate={gate}
      caseMetadata={snapshot.caseMetadata} requiresToken draft={{ operatorName: "operator", rbacRole: "lead_hunter", checkNote: "checked" }}
      onUpdateDraft={() => {}} onSubmitDecision={() => {}} onSelectCitation={() => {}} />);
    expect(html).toContain("Investigate workstation alpha");
  });

  test("routes start, list and selection to the desktop bridge and returns its snapshots", async () => {
    const snapshot = { ...buildFixtureWorkbenchSnapshot(), huntId: "live-123", provenanceMode: "live_daemon" as const };
    const runs = [{ huntId: "live-123", caseId: "case-42", runStatus: "running" }];
    const calls: Array<[string, unknown]> = [];
    const globals = globalThis as unknown as { window?: unknown };
    const previous = globals.window;
    globals.window = { huntWorkbench: { invoke: async (channel: string, payload: unknown) => {
      calls.push([channel, payload]);
      return { ok: true, data: channel === "hunt:listRuns" ? runs : snapshot };
    } } };
    try {
      const input = { caseId: "case-42", scope: "host A", dataOrigin: "work-export" as const, maxTotalTokens: 10000, followUps: 2 };
      expect((await startRun(input)).data).toBe(snapshot);
      expect((await listRuns()).data).toBe(runs);
      expect((await selectRun("live-123")).data).toBe(snapshot);
      expect(calls).toEqual([["hunt:startRun", input], ["hunt:listRuns", undefined], ["hunt:getWorkbenchState", { huntId: "live-123" }]]);
    } finally {
      if (previous === undefined) delete globals.window;
      else globals.window = previous;
    }
  });
});
