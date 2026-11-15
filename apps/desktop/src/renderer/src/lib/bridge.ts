import { buildFixtureWorkbenchSnapshot } from "../../../shared/fixture-workbench.ts";
import type {
  DesktopBridge,
  EventChannel,
  InvokeChannel,
  IpcResult,
} from "../../../shared/ipc.ts";

/** Error code returned on every channel when the Electron preload bridge is missing. */
export const PRELOAD_UNAVAILABLE = "PRELOAD_UNAVAILABLE";

/** `?preview=fixtures` opts a dev-server renderer into labelled synthetic fixture data. */
export const FIXTURE_PREVIEW_QUERY = "fixtures";

interface RendererWindow {
  huntWorkbench?: DesktopBridge;
  location: { search: string };
}

/** `window` without requiring DOM lib types (this module is also type-checked by the node project). */
function rendererWindow(): RendererWindow | undefined {
  return (globalThis as { window?: RendererWindow }).window;
}

function getNativeBridge(): DesktopBridge | null {
  return rendererWindow()?.huntWorkbench ?? null;
}

export function hasDesktopBridge(): boolean {
  return getNativeBridge() !== null;
}

/**
 * Fixture data is served only when explicitly requested on a dev-server renderer
 * (`electron-vite dev` / `vite` with `?preview=fixtures`). A packaged or built renderer
 * without the preload bridge reports {@link PRELOAD_UNAVAILABLE} instead of inventing hunts.
 */
export function isFixturePreviewRequested(): boolean {
  const env = (import.meta as { env?: { DEV?: boolean } }).env;
  const win = rendererWindow();
  if (env?.DEV !== true || win === undefined) {
    return false;
  }
  return new URLSearchParams(win.location.search).get("preview") === FIXTURE_PREVIEW_QUERY;
}

function previewFixture<T>(channel: InvokeChannel, payload?: unknown): IpcResult<T> | null {
  if (channel === "hunt:listRuns") {
    return {
      ok: true,
      data: [
        { huntId: "hunt-20261115-nv01", caseId: "nv01", runStatus: "awaiting_human_gate" },
        { huntId: "hunt-20261115-scope-work", caseId: "nv01", runStatus: "awaiting_human_gate" },
        { huntId: "hunt-20261115-reconcile", caseId: "nv01", runStatus: "awaiting_human_gate" },
      ] as unknown as T,
    };
  }
  if (channel === "hunt:getWorkbenchState") {
    const huntId =
      typeof payload === "object" && payload !== null && "huntId" in payload
        ? String((payload as { huntId?: unknown }).huntId ?? "hunt-20261115-nv01")
        : "hunt-20261115-nv01";
    const openGate = huntId.includes("scope")
      ? "scope"
      : huntId.includes("reconcile")
        ? "reconcile"
        : "incident";
    const dataOrigin = huntId.includes("work") ? "work-export" : "synthetic";
    return {
      ok: true,
      data: buildFixtureWorkbenchSnapshot({ huntId, openGate, dataOrigin }) as unknown as T,
    };
  }
  return null;
}

export async function invokeDesktop<T>(
  channel: InvokeChannel,
  payload?: unknown,
): Promise<IpcResult<T>> {
  const bridge = getNativeBridge();
  if (bridge) {
    return await bridge.invoke<T>(channel, payload);
  }

  if (isFixturePreviewRequested()) {
    const fixture = previewFixture<T>(channel, payload);
    if (fixture) return fixture;
  }

  return {
    ok: false,
    error: {
      code: PRELOAD_UNAVAILABLE,
      message:
        `The Hunt Command desktop bridge is unavailable, so '${channel}' cannot reach the app. ` +
        "The preload script did not load; no hunt data is shown.",
    },
  };
}

export function subscribeDesktopEvent<TPayload>(
  channel: EventChannel,
  listener: (payload: TPayload) => void,
): () => void {
  const bridge = getNativeBridge();
  if (!bridge) {
    return () => {};
  }
  return bridge.on<TPayload>(channel, listener);
}
