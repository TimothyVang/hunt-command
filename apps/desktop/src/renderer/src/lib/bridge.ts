import { buildFixtureWorkbenchSnapshot } from "../../../shared/fixture-workbench.ts";
import type {
  DesktopBridge,
  EventChannel,
  InvokeChannel,
  IpcResult,
} from "../../../shared/ipc.ts";

function getNativeBridge(): DesktopBridge | null {
  if (typeof window !== "undefined" && window.huntWorkbench) {
    return window.huntWorkbench;
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

  // Standalone browser preview fallback when opened outside Electron preload.
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

  if (channel === "hunt:listRuns") {
    return {
      ok: true,
      data: [
        {
          huntId: "hunt-20261115-nv01",
          caseId: "northvale-lab-001",
          title: "Northvale Scheduled Task & C2 DNS/TLS Beaconing",
          dataOrigin: "synthetic",
          runStatus: "awaiting_human_gate",
          openGate: "incident",
        },
        {
          huntId: "hunt-20261115-scope-work",
          caseId: "northvale-lab-001",
          title: "Work Export Scope Gate Preview",
          dataOrigin: "work-export",
          runStatus: "awaiting_human_gate",
          openGate: "scope",
        },
        {
          huntId: "hunt-20261115-reconcile",
          caseId: "northvale-lab-001",
          title: "Crash-Recovery Reconcile Gate Preview",
          dataOrigin: "synthetic",
          runStatus: "awaiting_human_gate",
          openGate: "reconcile",
        },
      ] as unknown as T,
    };
  }

  return {
    ok: false,
    error: {
      code: "PRELOAD_UNAVAILABLE",
      message: `Channel '${channel}' requires the Electron preload bridge`,
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
