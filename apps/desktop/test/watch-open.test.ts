import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { resolveRuntimeDir } from "@hunt-command/shared";
import { HuntDaemonSidecar } from "../src/main/daemon/daemon-sidecar.ts";
import { createLogger } from "../src/main/logger.ts";
import { SecretVault } from "../src/main/secret-vault.ts";
import { createWatchScope, decideWatchRequest } from "../src/main/watch/browser-policy.ts";
import { WorkbenchService, type WorkbenchServiceDeps } from "../src/main/workbench-service.ts";
import { buildWatchOpenRequest, scopeWatchSnapshot, watchForHunt } from "../src/renderer/src/lib/watch-open.ts";
import { buildFixtureWorkbenchSnapshot } from "../src/shared/fixture-workbench.ts";
import { INVOKE_CHANNELS, type WatchOpenInput } from "../src/shared/ipc.ts";

describe("Watch tab opens the fenced session", () => {
  test("watch:open is an allowlisted channel", () => {
    expect(INVOKE_CHANNELS.has("watch:open")).toBe(true);
  });

  test("a previous hunt's enabled browser is never presented as the current session", () => {
    const previous = buildFixtureWorkbenchSnapshot({ huntId: "hunt-a" });
    const current = buildFixtureWorkbenchSnapshot({ huntId: "hunt-b" });
    const oldWatch = {
      ...previous.watchState,
      enabled: true,
      currentUrl: "http://127.0.0.1:18400/old",
      allowedOrigins: ["http://127.0.0.1:18400"],
      blockedRequestCount: 3,
    };
    const scoped = scopeWatchSnapshot({ ...current, watchState: oldWatch });
    expect(scoped.watchState.enabled).toBe(false);
    expect(scoped.watchState.runId).toBe("hunt-b");
    expect(scoped.watchState.currentUrl).toBe("about:blank");
    expect(scoped.watchState.allowedOrigins).toEqual([]);
    expect(scoped.watchState.blockedRequestCount).toBe(0);
    expect(buildWatchOpenRequest(scoped, "http://127.0.0.1:18400/")).toMatchObject({
      ok: true,
      request: { runId: "hunt-b", caseId: current.caseMetadata.case_id },
    });
  });

  test("a newer current-hunt watch event wins over an older snapshot, not another hunt's event", () => {
    const current = buildFixtureWorkbenchSnapshot({ huntId: "hunt-b" });
    const active = { ...current.watchState, enabled: true, currentUrl: "http://127.0.0.1:18400/new" };
    const old = { ...active, runId: "hunt-a" };
    expect(scopeWatchSnapshot(current, active).watchState).toEqual(active);
    expect(scopeWatchSnapshot(current, old).watchState).toEqual(current.watchState);
    expect(watchForHunt("hunt-b", active)).toBe(active);
  });

  test("buildWatchOpenRequest binds the typed origin to the run, role, case and case window", () => {
    const snap = buildFixtureWorkbenchSnapshot({ huntId: "hunt-x" });
    const built = buildWatchOpenRequest(snap, "http://127.0.0.1:18400/watch/arkime_sessions?q=1");
    expect(built.ok).toBe(true);
    if (!built.ok) return;
    expect(built.request.runId).toBe("hunt-x");
    expect(built.request.caseId).toBe(snap.caseMetadata.case_id);
    expect(built.request.labOrigin).toBe("http://127.0.0.1:18400");
    expect(built.request.startSec).toBeLessThan(built.request.stopSec);
    // The request is a valid main-process scope.
    expect(() =>
      createWatchScope({ ...built.request, arkimeOrigin: built.request.labOrigin }),
    ).not.toThrow();

    for (const bad of ["http://localhost:18400/", "https://example.invalid/", "file:///C:/x", "nope"]) {
      expect(buildWatchOpenRequest(snap, bad).ok).toBe(false);
    }
  });

  test("the UI's default same-origin scope fences Arkime requests", () => {
    const snap = buildFixtureWorkbenchSnapshot({ huntId: "hunt-x" });
    const built = buildWatchOpenRequest(snap, "http://127.0.0.1:18400/watch/arkime_sessions?key=fixture");
    expect(built.ok).toBe(true);
    if (!built.ok) throw new Error(built.error);
    const scope = createWatchScope({
      ...built.request,
      arkimeOrigin: built.request.arkimeOrigin ?? built.request.labOrigin,
    });
    const verdict = decideWatchRequest(
      scope,
      "GET",
      "http://127.0.0.1:18400/api/sessions?date=-1&startTime=1&stopTime=9999999999",
    );
    expect(verdict.block).toBeUndefined();
    expect(verdict.url).toBeDefined();
    const query = new URL(verdict.url!).searchParams;
    expect(query.get("expression")).toBe(`tags == "case:${scope.caseId}"`);
    expect(query.get("startTime")).toBe(String(scope.startSec));
    expect(query.get("stopTime")).toBe(String(scope.stopSec));
    expect(query.has("date")).toBe(false);
    expect(decideWatchRequest(scope, "GET", "http://127.0.0.1:18400/api/sessions.pcap").block)
      .toBe("arkime_route_denied");
    expect(decideWatchRequest(scope, "GET", built.request.initialUrl!).block).toBeUndefined();
  });

  test("WorkbenchService.openWatch validates and forwards to the controller's open handler", async () => {
    const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hunt-watch-open-"));
    try {
      const repoRoot = path.resolve(import.meta.dir, "../../..");
      const runtimePaths = resolveRuntimeDir(path.join(tmpRoot, "rt"), { repoRoot });
      const log = createLogger(path.join(tmpRoot, "logs"));
      const sidecar = new HuntDaemonSidecar({
        resolveLaunch: () => ({ available: false, command: "", args: [], piNativesDir: null, source: "unavailable" }),
        runtimeRootDir: runtimePaths.rootDir,
        log,
      });
      const vault = new SecretVault(path.join(tmpRoot, "vault"), {
        isEncryptionAvailable: () => true,
        encryptString: (s) => Buffer.from(s, "utf8"),
        decryptString: (b) => b.toString("utf8"),
      });
      const opened: WatchOpenInput[] = [];
      const first = buildFixtureWorkbenchSnapshot({ huntId: "hunt-20261115-nv01" });
      let state = { ...first.watchState, runId: first.huntId, enabled: true };
      let invalidations = 0;
      const svc = new WorkbenchService({
        runtimePaths,
        sidecar,
        vault,
        watchHandlers: {
          getState: () => state,
          setBounds: () => state,
          invalidate: () => { invalidations++; },
          navigate: async () => state,
          open: async (input) => {
            opened.push(input);
            return { ...state, enabled: true };
          },
        },
      });
      const request = {
        runId: first.huntId,
        role: state.role,
        caseId: first.caseMetadata.case_id,
        labOrigin: "http://127.0.0.1:18400",
        startSec: 1,
        stopSec: 2,
      };
      const result = await svc.openWatch(request);
      expect(result.enabled).toBe(true);
      expect(opened).toEqual([request]);
      await expect(svc.openWatch({ ...request, extra: 1 })).rejects.toThrow();
      const switched = await svc.getWorkbenchState({ huntId: "hunt-20261115-scope-work" });
      expect(invalidations).toBe(1);
      expect(switched.watchState.enabled).toBe(false);
      expect(switched.watchState.runId).toBe(switched.huntId);
      await expect(svc.navigateWatch({ runId: first.huntId, role: state.role, url: request.labOrigin })).rejects.toThrow();
      await expect(svc.openWatch(request)).rejects.toThrow();
      expect(() => svc.setWatchBounds({ runId: first.huntId, bounds: { x: 0, y: 0, width: 100, height: 100 } })).toThrow();
      state = { ...state, runId: switched.huntId };
      expect(svc.setWatchBounds({ runId: switched.huntId, bounds: { x: 0, y: 0, width: 100, height: 100 } }).runId).toBe(switched.huntId);
    } finally {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    }
  });
});
const input = {
  caseId: "case-001",
  scope: "Investigate workstation activity within the approved time window.",
  dataOrigin: "synthetic",
  maxTotalTokens: 100_000,
  followUps: 2,
};

function makeService(isLiveReady: boolean, request: (method: string, params: unknown) => Promise<unknown>) {
  const sidecar = { isLiveReady, request } as unknown as WorkbenchServiceDeps["sidecar"];
  return new WorkbenchService({
    sidecar,
    runtimePaths: {} as WorkbenchServiceDeps["runtimePaths"],
    vault: {} as WorkbenchServiceDeps["vault"],
  });
}

describe("WorkbenchService live runs", () => {
  const metadata = {
    case_id: input.caseId, title: "Actual case", data_origin: "synthetic", synthetic_only: true,
    time_window: { start_iso: "2026-01-01T00:00:00Z", end_iso: "2026-01-02T00:00:00Z" }, sources: [],
  };
  const run = (runId: string) => ({
    run_id: runId, case_id: input.caseId, data_origin: "synthetic", synthetic_only: true,
    wave: "scope", wave_index: 0, status: "awaiting_gate", reason_code: null,
    step_states: {}, results: { scope: { step_id: "scope", wave: "scope", profile: "framework-coordinator",
      status: "done", attempts: 1, finished_at: "2026-01-01T00:00:00Z", handoff: {
        schema_version: 1, case_id: input.caseId, step_id: "scope", profile: "framework-coordinator",
        claims: [], reviews: [], disposition: "review_ready", limitations: [], requested_decisions: [],
      } } }, reviewed_handoffs: {}, decisions: [],
    token_ledger: { max_total_tokens: 100_000, consumed_total_tokens: 300, rejections_tokens: 0,
      actual_billed_usd: 0, shadow_api_usd: 0, cache_savings_usd: 0 },
    open_gate: { gate: "scope", payload_sha256: "a".repeat(64),
      opened_at: "2026-01-01T00:00:00Z", expires_at: "2099-01-01T00:00:00Z" },
    citation_receipt: null, snapshot: null,
    config: { scopeText: input.scope, followUps: input.followUps, maxTotalTokens: input.maxTotalTokens },
  });

  test("incident approval and reopening reload case evidence; unavailable reads never reuse verified data", async () => {
    const id = "hunt-reload-evidence";
    const citation = "evt-0000000000000001";
    const handoff = {
      schema_version: 1, case_id: input.caseId, step_id: "incident", profile: "framework-coordinator",
      claims: [{ claim_id: "incident:c1", kind: "finding", statement: `Observed ${citation}.`,
        evidence_ids: ["events.jsonl"], entity_ids: [], contradicts: [] }],
      reviews: [], disposition: "review_ready", limitations: [], requested_decisions: [],
    };
    const receipt = {
      verified: true, case_id: input.caseId, total_checked: 1, source_status: "ok",
      missing_event_ids: [], missing_frame_ids: [], missing_ioc_ids: [], ambiguous_ids: [], out_of_scope_ids: [],
    };
    const record = { id: citation, kind: "evt", status: "verified", timestamp_iso: "2026-01-01T01:00:00Z",
      title: "Process", fields: { "host.name": "host-one", message: "Process observed" } };
    const base = run(id);
    let current = {
      ...base, wave: "incident", results: { ...base.results, incident: {
        step_id: "incident", wave: "incident", profile: "framework-coordinator", status: "done",
        attempts: 1, finished_at: "2026-01-01T00:00:00Z", handoff,
      } }, reviewed_handoffs: { incident: handoff }, citation_receipt: receipt,
      open_gate: { ...base.open_gate, gate: "incident" },
    };
    let offline = false;
    const request = async (method: string) => {
      if (method === "hunt.status") return current;
      if (method === "case.metadata") return metadata;
      if (method === "hunt.gateContext") return {
        run_id: id, case_id: input.caseId, gate: "incident", payload_sha256: current.open_gate!.payload_sha256,
        incident: {
          citation_receipt: receipt, cited: [{ id: record.id, kind: record.kind, status: record.status }],
          evidence: [record], evidence_total: 1, evidence_next_cursor: null,
        },
      };
      if (method === "hunt.decideGate") {
        current = { ...current, status: "completed", open_gate: null as unknown as typeof current.open_gate };
        return current;
      }
      if (method === "hunt.evidence") {
        if (offline) throw new Error("evidence_unavailable");
        return {
          run_id: id, case_id: input.caseId, citation_receipt: receipt,
          cited: [{ id: record.id, kind: record.kind, status: record.status }],
          evidence: [record], evidence_total: 1, evidence_next_cursor: null,
        };
      }
      throw new Error(method);
    };
    const service = makeService(true, request);
    const before = await service.getWorkbenchState({ huntId: id });
    const after = await service.submitGateDecision({
      huntId: id, gate: "incident", action: "approve", operatorName: "analyst", rbacRole: "incident_commander",
      checkNote: "Reviewed the evidence.", payloadSha256: before.activeGate!.payloadSha256, operatorToken: "token",
    });
    expect(after.activeGate).toBeNull();
    expect(after.evidenceCatalog[citation]?.verified).toBe(true);
    expect(after.events[0]?.hostName).toBe("host-one");
    const reopened = await makeService(true, request).getWorkbenchState({ huntId: id });
    expect(reopened.evidenceCatalog[citation]?.verified).toBe(true);
    expect(reopened.claims[0]?.inlineCitations[0]?.status).toBe("verified");
    offline = true;
    const unavailable = await service.getWorkbenchState({ huntId: id });
    expect(unavailable.evidenceCatalog).toEqual({});
    expect(unavailable.events).toEqual([]);
    expect(unavailable.citationReceipt.allVerified).toBe(false);
    expect(unavailable.claims[0]?.inlineCitations[0]?.status).toBe("unresolved");
  });

  test("lists every persisted hunt when a case pack is unavailable without loading full snapshots", async () => {
    const missing = { ...run("hunt-missing"), case_id: "case-missing", status: "running", open_gate: null };
    const available = run("hunt-available");
    const calls: Array<{ method: string; params: unknown }> = [];
    const service = makeService(true, async (method, params) => {
      calls.push({ method, params });
      if (method === "hunt.list") return { runs: [missing, available] };
      if (method === "case.metadata") {
        if (params && typeof params === "object" && "case_id" in params && params.case_id === missing.case_id) {
          throw new Error("case pack unavailable");
        }
        return metadata;
      }
      if (method === "hunt.status") {
        return params && typeof params === "object" && "run_id" in params && params.run_id === missing.run_id
          ? missing : available;
      }
      throw new Error(`unexpected ${method}`);
    });

    const items = await service.listRuns();
    expect(items.find((item) => item.huntId === missing.run_id)).toMatchObject({
      caseId: missing.case_id, title: null, dataOrigin: "synthetic", metadataAvailable: false,
      runStatus: "running", openGate: null,
    });
    expect(items.find((item) => item.huntId === available.run_id)).toMatchObject({
      caseId: input.caseId, title: metadata.title, metadataAvailable: true,
      runStatus: "awaiting_human_gate", openGate: "scope",
    });
    expect(calls.map((call) => call.method)).toEqual(["hunt.list", "case.metadata", "case.metadata"]);
    await expect(service.getWorkbenchState({ huntId: missing.run_id })).rejects.toThrow("case pack unavailable");
    expect((await service.getWorkbenchState({ huntId: available.run_id })).huntId).toBe(available.run_id);
  });

  test("returns real metadata and empty evidence, and refreshes status", async () => {
    let id = "";
    const calls: string[] = [];
    const service = makeService(true, async (method, params) => {
      calls.push(method);
      if (method === "hunt.start") {
        id = (params as { run_id: string }).run_id;
        return run(id);
      }
      if (method === "case.metadata") return metadata;
      if (method === "hunt.status") return run(id);
      if (method === "hunt.list") return { runs: [run(id)] };
      throw new Error(method);
    });
    const snapshot = await service.startRun(input);
    expect(snapshot).toMatchObject({ huntId: id, provenanceMode: "live_daemon", caseMetadata: metadata,
      runStatus: "awaiting_human_gate", activeGate: { payloadSha256: "a".repeat(64) },
      events: [], claims: [], snapshot: { entities: [], relations: [] } });
    expect(snapshot.handoffs.map((handoff) => handoff.step_id)).toEqual(["scope"]);
    expect((await service.getWorkbenchState({ huntId: id })).huntId).toBe(id);
    expect((await service.listRuns()).some((item) => item.huntId === id && item.title === metadata.title)).toBe(true);
    expect(calls.filter((call) => call === "hunt.start")).toHaveLength(1);
  });

  test("recovers a timed out start using the same ID without another start", async () => {
    let id = "";
    const calls: string[] = [];
    const service = makeService(true, async (method, params) => {
      calls.push(method);
      if (method === "hunt.start") {
        id = (params as { run_id: string }).run_id;
        throw new Error("RPC request 'hunt.start' timed out");
      }
      if (method === "hunt.status") {
        expect(params).toEqual({ run_id: id });
        return run(id);
      }
      return metadata;
    });
    expect((await service.startRun(input)).huntId).toBe(id);
    expect(calls).toEqual(["case.metadata", "hunt.start", "hunt.status", "case.metadata"]);
  });

  test("reports an indeterminate start with its ID when recovery cannot yet find it", async () => {
    let id = "";
    const service = makeService(true, async (method, params) => {
      if (method === "case.metadata") return metadata;
      if (method === "hunt.start") {
        id = (params as { run_id: string }).run_id;
        throw new Error("timed out");
      }
      throw new Error("hunt_not_found");
    });
    let message = "";
    try { await service.startRun(input); } catch (error) { message = String(error); }
    expect(message).toContain("Start outcome is unknown");
    expect(id).toBeTruthy();
    expect(message).toContain(id);
  });

  test("forwards authenticated gate decisions and cancel, propagating failures", async () => {
    let id = "";
    let fail = false;
    const calls: Array<{ method: string; params: unknown }> = [];
    const service = makeService(true, async (method, params) => {
      calls.push({ method, params });
      if (method === "hunt.start") { id = (params as { run_id: string }).run_id; return run(id); }
      if (method === "case.metadata") return metadata;
      if (method === "hunt.status") return run(id);
      if (fail) throw new Error("daemon denied");
      return run(id);
    });
    await service.startRun(input);
    const decision = { huntId: id, gate: "scope", action: "approve", operatorName: "self asserted",
      rbacRole: "lead_hunter", checkNote: "Checked scope", payloadSha256: "a".repeat(64), operatorToken: "signed-token" };
    await service.submitGateDecision(decision);
    expect(calls.find((call) => call.method === "hunt.decideGate")?.params).toEqual({
      hunt_id: id, gate: "scope", action: "approve", via: "desktop", operator_token: "signed-token",
      payload_sha256: "a".repeat(64), check_note: "Checked scope",
    });
    await service.globalStop({ huntId: id, reason: "stop" });
    expect(calls.find((call) => call.method === "hunt.cancel")?.params).toEqual({ run_id: id, reason: "stop" });
    fail = true;
    await expect(service.submitGateDecision(decision)).rejects.toThrow("daemon denied");
    await expect(service.globalStop({ huntId: id, reason: "stop" })).rejects.toThrow("daemon denied");
    await expect(service.submitGateDecision({ ...decision, operatorToken: "" })).rejects.toThrow();
  });

  test("propagates live failures and rejects malformed responses", async () => {
    const failed = makeService(true, async (method) => {
      if (method === "case.metadata") return metadata;
      throw new Error("case not found");
    });
    await expect(failed.startRun(input)).rejects.toThrow("case not found");
    const malformed = makeService(true, async () => ({ huntId: "fixture-like" }));
    await expect(malformed.startRun(input)).rejects.toThrow();
  });

  test("rejects a data origin that does not match the actual case before starting", async () => {
    const calls: string[] = [];
    const service = makeService(true, async (method) => {
      calls.push(method);
      return metadata;
    });
    await expect(service.startRun({ ...input, dataOrigin: "work-export" })).rejects.toThrow("data origin");
    expect(calls).toEqual(["case.metadata"]);
  });

  test("requires an operator scope and keeps explicit standby fixture behavior", async () => {
    const service = makeService(false, async () => { throw new Error("unexpected RPC"); });
    await expect(service.startRun({ ...input, scope: "  " })).rejects.toThrow("Scope is required");
    const started = await service.startRun(input);
    expect(started.provenanceMode).toBe("fixture_preview");
    expect(started.runStatus).toBe("awaiting_human_gate");
  });
});
