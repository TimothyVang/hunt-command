import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { buildFixtureWorkbenchSnapshot } from "../src/shared/fixture-workbench.ts";
import { AuthorityGateCard } from "../src/renderer/src/panes/AuthorityGateCard.tsx";
import { projectLiveGate } from "../src/main/live-gate-context.ts";
import { RunControls } from "../src/renderer/src/panes/RunControls.tsx";
import { EventRefreshGuard, listRuns, loadGateEvidencePage, selectRun, startRun } from "../src/renderer/src/lib/run-actions.ts";
import { WorkbenchStore } from "../src/renderer/src/state/workbench-store.ts";

describe("live run controls", () => {
  test("offers all supported start fields and live run selection", () => {
    const html = renderToStaticMarkup(<RunControls runs={[{ huntId: "live-123", caseId: "case-42", title: "Case title", metadataAvailable: true, runStatus: "running" }, { huntId: "live-456", caseId: "case-43", title: null, metadataAvailable: false, runStatus: "running" }]}
      selectedHuntId="live-123" busy={false} error={null} onStart={() => {}} onSelect={() => {}} onRefresh={() => {}} />);
    expect(html).toContain("Case ID");
    expect(html).toContain("Scope");
    expect(html).toContain("Data origin");
    expect(html).toContain("work-connected");
    expect(html).toContain("Token limit");
    expect(html).toContain("Follow-ups");
    expect(html).toContain("Case title");
    expect(html).toContain("Case metadata unavailable");
    expect(html).toContain("live-456");
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
    const scopeHandoff = { ...snapshot.handoffs[0]!, step_id: "scope", limitations: ["Scope excludes external hosts."] };
    const gate = { ...snapshot.activeGate, scopeSummary: undefined, scopeText: "Investigate workstation alpha", scopeHandoff };
    const html = renderToStaticMarkup(<AuthorityGateCard activeGate={gate}
      caseMetadata={snapshot.caseMetadata} requiresToken draft={{ operatorName: "operator", rbacRole: "lead_hunter", checkNote: "checked" }}
      onUpdateDraft={() => {}} onSubmitDecision={() => {}} onSelectCitation={() => {}} />);
    expect(html).toContain("Investigate workstation alpha");
    expect(html).toContain("Generated scope handoff");
    expect(html).toContain("Scope excludes external hosts.");
    expect(html).toContain(scopeHandoff.claims[0]!.claim_id);
  });

  test("reconcile gate explains the actual approval and rejection outcomes", () => {
    const snapshot = buildFixtureWorkbenchSnapshot({ openGate: "reconcile" });
    if (!snapshot.activeGate) throw new Error("Expected a reconcile gate");
    const html = renderToStaticMarkup(<AuthorityGateCard activeGate={snapshot.activeGate}
      caseMetadata={snapshot.caseMetadata} requiresToken={false} draft={{ operatorName: "operator", rbacRole: "lead_hunter", checkNote: "checked" }}
      onUpdateDraft={() => {}} onSubmitDecision={() => {}} onSelectCitation={() => {}} />);
    expect(html).toContain("approval drops an optional unknown");
    expect(html).toContain("fails the run if the step is required");
    expect(html).toContain("dispatch is not replayed");
    expect(html).toContain("Rejection fails the run");
  });

  test("incident handoff claims and limitations remain visible when the gate context fails to load", () => {
    const snapshot = buildFixtureWorkbenchSnapshot();
    const handoff = { ...snapshot.handoffs[0]!, step_id: "incident", limitations: ["Coverage excludes remote hosts."] };
    const claim = { ...handoff.claims[0]!, statement: "Incident finding for operator review." };
    const gate = projectLiveGate(snapshot.huntId, {
      gate: "incident", payload_sha256: "a".repeat(64),
      opened_at: "2026-11-14T10:00:00Z", expires_at: "2099-01-01T00:00:00Z",
    }, [{ ...handoff, claims: [claim] }], {
      run_id: snapshot.huntId, case_id: snapshot.caseMetadata.case_id, gate: "incident", payload_sha256: "a".repeat(64),
      incident: { citation_receipt: { verified: true, checked_at: "2026-11-14T10:00:00Z",
        case_id: snapshot.caseMetadata.case_id, total_checked: 0, missing_event_ids: [], missing_frame_ids: [],
        missing_ioc_ids: [], ambiguous_ids: [], out_of_scope_ids: [], source_status: "ok" },
        // Inconsistent F18 block (total disagrees with the cited list): the context fails closed.
        cited: [], evidence: [], evidence_total: 3, evidence_next_cursor: null },
    }).activeGate;
    const html = renderToStaticMarkup(<AuthorityGateCard activeGate={gate}
      caseMetadata={snapshot.caseMetadata} requiresToken={false} draft={{ operatorName: "operator", rbacRole: "lead_hunter", checkNote: "checked" }}
      onUpdateDraft={() => {}} onSubmitDecision={() => {}} onSelectCitation={() => {}} />);
    expect(html).toContain("Incident finding for operator review.");
    expect(html).toContain("Coverage excludes remote hosts.");
    expect(html).toContain("could not be loaded");
    expect(html).not.toContain("Automated Citation Verification Receipt:");
    expect(html).toContain('data-testid="gate-approve-button" disabled');
  });

  test("F18: a paged incident gate says how many records are loaded and offers Load more, never implying completeness", () => {
    const snapshot = buildFixtureWorkbenchSnapshot();
    const ids = Array.from({ length: 1_200 }, (_, i) => `evt-p${String(i).padStart(4, "0")}`);
    const claims = Array.from({ length: 6 }, (_, c) => ({
      ...snapshot.handoffs[0]!.claims[0]!, claim_id: `incident:p${c}`, statement: ids.slice(c * 200, c * 200 + 200).join(" "),
    }));
    const handoff = { ...snapshot.handoffs[0]!, step_id: "incident", claims, limitations: [] };
    const cited = ids.map((id) => ({ id, kind: "evt", status: "verified" }));
    const evidence = cited.slice(0, 200).map((c) => ({ ...c, timestamp_iso: "2026-11-14T10:01:00Z", title: `Record ${c.id}`, fields: { "host.name": "h" } }));
    const projection = projectLiveGate(snapshot.huntId, {
      gate: "incident", payload_sha256: "a".repeat(64), opened_at: "2026-11-14T10:00:00Z", expires_at: "2099-01-01T00:00:00Z",
    }, [handoff], {
      run_id: snapshot.huntId, case_id: snapshot.caseMetadata.case_id, gate: "incident", payload_sha256: "a".repeat(64),
      incident: { citation_receipt: { verified: true, checked_at: "2026-11-14T10:00:00Z", case_id: snapshot.caseMetadata.case_id,
        total_checked: 1_200, missing_event_ids: [], missing_frame_ids: [], missing_ioc_ids: [], ambiguous_ids: [], out_of_scope_ids: [],
        source_status: "ok" }, cited, evidence, evidence_total: 1_200, evidence_next_cursor: "cursor-1" },
    });
    expect(projection.activeGate.contextError).toBeUndefined();
    expect(projection.activeGate.incidentSummary!.citationReceipt.totalCited).toBe(1_200);
    expect(projection.activeGate.incidentSummary!.citationReceipt.allVerified).toBe(true);
    expect(projection.pagingState?.nextCursor).toBe("cursor-1");
    const html = renderToStaticMarkup(<AuthorityGateCard activeGate={projection.activeGate}
      caseMetadata={snapshot.caseMetadata} requiresToken={false} draft={{ operatorName: "operator", rbacRole: "lead_hunter", checkNote: "checked" }}
      onUpdateDraft={() => {}} onSubmitDecision={() => {}} onSelectCitation={() => {}} onLoadMoreEvidence={async () => null} />);
    const text = html.replace(/<[^>]+>/g, "").replace(/\s+/g, " ");
    expect(text).toContain("1200/1200 resolved");
    expect(text).toContain("200 of 1200 records loaded (partial record list; every citation status above is complete)");
    expect(html).toContain('data-testid="evidence-load-more"');
    expect(/<button[^>]*data-testid="gate-approve-button"[^>]*>/.exec(html)?.[0]).not.toContain('disabled=""');
    // The cursor never reaches the renderer.
    expect(JSON.stringify(projection.activeGate)).not.toContain("cursor-1");
  });

  test("delayed daemon events cannot restore a decided gate or supersede a newer refresh", async () => {
    const snapshot = buildFixtureWorkbenchSnapshot();
    const globals = globalThis as unknown as { window?: unknown };
    const previous = globals.window;
    const store = new WorkbenchStore(snapshot);
    const guard = new EventRefreshGuard();
    const responses: Array<(result: unknown) => void> = [];
    let selected = true;
    globals.window = { huntWorkbench: { invoke: () => {
      const deferred = Promise.withResolvers<unknown>();
      responses.push(deferred.resolve);
      return deferred.promise;
    } } };
    const apply = (value: typeof snapshot) => {
      guard.snapshotApplied();
      store.setWorkbenchSnapshot(value);
    };
    const refresh = () => guard.refresh(snapshot.huntId, () => selected, apply);
    try {
      const staleDecision = refresh();
      const decided = { ...snapshot, activeGate: null };
      apply(decided);
      responses.shift()!({ ok: true, data: snapshot });
      await staleDecision;
      expect(store.getState().workbench).toBe(decided);

      const older = refresh();
      const newer = refresh();
      const resolveOlder = responses.shift()!;
      const resolveNewer = responses.shift()!;
      const updated = { ...decided, runStatus: "completed" as const };
      resolveNewer({ ok: true, data: updated });
      await newer;
      resolveOlder({ ok: true, data: snapshot });
      await older;
      expect(store.getState().workbench).toBe(updated);

      const staleSelection = refresh();
      selected = false;
      responses.shift()!({ ok: true, data: snapshot });
      await staleSelection;
      expect(store.getState().workbench).toBe(updated);
    } finally {
      if (previous === undefined) delete globals.window;
      else globals.window = previous;
    }
  });

  test("F19: delayed evidence pages cannot replace newer workbench or selection state", async () => {
    const snapshot = buildFixtureWorkbenchSnapshot();
    const globals = globalThis as unknown as { window?: unknown };
    const previous = globals.window;
    const store = new WorkbenchStore(snapshot);
    let selection = 0;
    let resolvePage!: (result: unknown) => void;
    globals.window = { huntWorkbench: { invoke: () => {
      const deferred = Promise.withResolvers<unknown>();
      resolvePage = deferred.resolve;
      return deferred.promise;
    } } };
    const request = () => {
      const current = store.getState().workbench;
      const version = store.getSnapshotVersion();
      const selected = selection;
      return loadGateEvidencePage(current, () => selected === selection,
        () => version === store.getSnapshotVersion(), (page) => store.setWorkbenchSnapshot(page));
    };
    try {
      const page = { ...snapshot };
      const pendingDecision = request();
      const decided = { ...snapshot, activeGate: null };
      store.setWorkbenchSnapshot(decided);
      resolvePage({ ok: true, data: page });
      expect(await pendingDecision).toContain("workbench changed");
      expect(store.getState().workbench).toBe(decided);

      const pendingChangedGate = request();
      const changed = { ...snapshot, activeGate: snapshot.activeGate && { ...snapshot.activeGate, payloadSha256: "b".repeat(64) } };
      store.setWorkbenchSnapshot(changed);
      store.setWorkbenchSnapshot(decided);
      resolvePage({ ok: true, data: page });
      expect(await pendingChangedGate).toContain("workbench changed");
      expect(store.getState().workbench).toBe(decided);

      const pendingCursor = request();
      const paged = { ...snapshot, activeGate: snapshot.activeGate && {
        ...snapshot.activeGate, evidencePaging: { loaded: 20, total: 30, hasMore: true },
      } };
      store.setWorkbenchSnapshot(paged);
      resolvePage({ ok: true, data: page });
      expect(await pendingCursor).toContain("workbench changed");
      expect(store.getState().workbench).toBe(paged);

      const pendingSwitch = request();
      selection += 2;
      resolvePage({ ok: true, data: page });
      expect(await pendingSwitch).toBeNull();
      expect(store.getState().workbench).toBe(paged);

      const pendingSuccess = request();
      resolvePage({ ok: true, data: page });
      expect(await pendingSuccess).toBeNull();
      expect(store.getState().workbench).toBe(page);
    } finally {
      if (previous === undefined) delete globals.window;
      else globals.window = previous;
    }
  });

  test("F19: current evidence-page failures are surfaced, including rejected bridge calls", async () => {
    const snapshot = buildFixtureWorkbenchSnapshot();
    const globals = globalThis as unknown as { window?: unknown };
    const previous = globals.window;
    const apply = () => { throw new Error("A failed page must not be applied"); };
    try {
      globals.window = { huntWorkbench: { invoke: async () => ({ ok: false, error: { message: "Page expired" } }) } };
      expect(await loadGateEvidencePage(snapshot, () => true, () => true, apply)).toBe("Page expired");
      globals.window = { huntWorkbench: { invoke: async () => { throw new Error("Bridge failed"); } } };
      expect(await loadGateEvidencePage(snapshot, () => true, () => true, apply)).toBe("Bridge failed");
      globals.window = { huntWorkbench: { invoke: async () => ({ ok: true, data: { ...snapshot, huntId: "other" } }) } };
      expect(await loadGateEvidencePage(snapshot, () => true, () => true, apply)).toContain("different hunt");
    } finally {
      if (previous === undefined) delete globals.window;
      else globals.window = previous;
    }
  });

  test("routes start, list and selection to the desktop bridge and returns its snapshots", async () => {
    const snapshot = { ...buildFixtureWorkbenchSnapshot(), huntId: "live-123", provenanceMode: "live_daemon" as const };
    const runs = [{ huntId: "live-123", caseId: "case-42", title: "Case title", metadataAvailable: true, runStatus: "running" }];
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
