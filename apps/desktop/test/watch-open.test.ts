import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { resolveRuntimeDir } from "@hunt-command/shared";
import { HuntDaemonSidecar } from "../src/main/daemon/daemon-sidecar.ts";
import { createLogger } from "../src/main/logger.ts";
import { SecretVault } from "../src/main/secret-vault.ts";
import { createWatchScope, decideWatchRequest } from "../src/main/watch/browser-policy.ts";
import { WorkbenchService } from "../src/main/workbench-service.ts";
import { buildWatchOpenRequest } from "../src/renderer/src/lib/watch-open.ts";
import { buildFixtureWorkbenchSnapshot } from "../src/shared/fixture-workbench.ts";
import { INVOKE_CHANNELS, type WatchOpenInput } from "../src/shared/ipc.ts";

describe("Watch tab opens the fenced session", () => {
  test("watch:open is an allowlisted channel", () => {
    expect(INVOKE_CHANNELS.has("watch:open")).toBe(true);
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
      const state = buildFixtureWorkbenchSnapshot().watchState;
      const svc = new WorkbenchService({
        runtimePaths,
        sidecar,
        vault,
        watchHandlers: {
          getState: () => state,
          setBounds: () => state,
          navigate: async () => state,
          open: async (input) => {
            opened.push(input);
            return { ...state, enabled: true };
          },
        },
      });
      const request = {
        runId: "hunt-x",
        role: state.role,
        caseId: "northvale-lab-001",
        labOrigin: "http://127.0.0.1:18400",
        startSec: 1,
        stopSec: 2,
      };
      const result = await svc.openWatch(request);
      expect(result.enabled).toBe(true);
      expect(opened).toEqual([request]);
      await expect(svc.openWatch({ ...request, extra: 1 })).rejects.toThrow();
    } finally {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    }
  });
});
