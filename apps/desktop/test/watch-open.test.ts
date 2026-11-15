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

describe("WorkbenchService startRun", () => {
  test("an older workbench response cannot switch the active hunt back", async () => {
    const firstResponse = Promise.withResolvers<unknown>();
    const first = buildFixtureWorkbenchSnapshot({ huntId: "hunt-20261115-nv01" });
    const second = buildFixtureWorkbenchSnapshot({ huntId: "hunt-20261115-scope-work" });
    let calls = 0;
    const service = makeService(true, async () => {
      calls++;
      if (calls === 1) return await firstResponse.promise;
      if (calls === 2) return second;
      throw new Error("unavailable");
    });
    const older = service.getWorkbenchState({ huntId: first.huntId });
    await service.getWorkbenchState({ huntId: second.huntId });
    firstResponse.resolve(first);
    await older;
    expect((await service.getWorkbenchState()).huntId).toBe(second.huntId);
  });

  test("sends the daemon start contract and returns a live run acknowledgement", async () => {
    const calls: Array<{ method: string; params: unknown }> = [];
    const service = makeService(true, async (method, params) => {
      calls.push({ method, params });
      return {
        run_id: "hunt-live-001", case_id: "case-001", data_origin: "synthetic",
        synthetic_only: true, wave: "scope", wave_index: 0, status: "awaiting_gate",
        reason_code: null, step_states: {}, results: {}, handoff_rejections: [],
        reviewed_handoffs: {}, delegated_ledger: [], open_gate: { gate: "scope" },
        decisions: [], token_ledger: { max_total_tokens: 100_000, consumed_total_tokens: 300 },
        citation_receipt: null, snapshot: null,
        config: { scopeText: input.scope, followUps: 2, maxTotalTokens: 100_000 },
        created_at: "2026-11-15T00:00:00.000Z", updated_at: "2026-11-15T00:00:01.000Z",
      };
    });

    expect(await service.startRun(input)).toEqual({
      provenanceMode: "live_daemon", huntId: "hunt-live-001", runStatus: "awaiting_human_gate",
    });
    expect(calls).toEqual([{ method: "hunt.start", params: {
      case_id: input.caseId, scope: input.scope, follow_ups: 2, max_total_tokens: 100_000,
    } }]);
    await expect(service.getWorkbenchState({ huntId: "hunt-live-001" })).rejects.toThrow("Live workbench state is not available");
  });

  test("propagates live RPC failures and rejects malformed responses rather than using a fixture", async () => {
    const failed = makeService(true, async () => { throw new Error("case not found"); });
    await expect(failed.startRun(input)).rejects.toThrow("case not found");
    const malformed = makeService(true, async () => ({ huntId: "fixture-like" }));
    await expect(malformed.startRun(input)).rejects.toThrow();
  });

  test("requires an operator scope and keeps explicit standby fixture behavior", async () => {
    const service = makeService(false, async () => { throw new Error("unexpected RPC"); });
    await expect(service.startRun({ ...input, scope: "  " })).rejects.toThrow("Scope is required");
    const started = await service.startRun(input);
    expect(started.provenanceMode).toBe("fixture_preview");
    expect(started.runStatus).toBe("awaiting_human_gate");
  });
});
