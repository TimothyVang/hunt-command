import { describe, expect, test } from "bun:test";
import { invokeDesktop, PRELOAD_UNAVAILABLE } from "../src/renderer/src/lib/bridge.ts";
import { WorkbenchStore } from "../src/renderer/src/state/workbench-store.ts";

describe("renderer without the preload bridge", () => {
  test("never invents hunts: every channel reports PRELOAD_UNAVAILABLE", async () => {
    expect((globalThis as { window?: unknown }).window).toBeUndefined();
    for (const channel of ["hunt:getWorkbenchState", "hunt:listRuns", "daemon:status"] as const) {
      const res = await invokeDesktop(channel, { huntId: "hunt-20261115-nv01" });
      expect(res.ok).toBe(false);
      expect(res.data).toBeUndefined();
      expect(res.error?.code).toBe(PRELOAD_UNAVAILABLE);
    }
  });

  test("store starts disconnected and reports the bridge error instead of showing data", () => {
    const store = new WorkbenchStore();
    expect(store.getState().connection).toEqual({ kind: "connecting" });
    store.setConnectionUnavailable(PRELOAD_UNAVAILABLE, "no bridge");
    expect(store.getState().connection).toEqual({
      kind: "unavailable",
      code: PRELOAD_UNAVAILABLE,
      message: "no bridge",
    });
  });
});
