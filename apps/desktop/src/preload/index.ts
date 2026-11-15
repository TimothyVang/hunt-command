/**
 * Adapted from omp-desktop/app/src/preload/index.ts
 * Copyright (c) omp-desktop contributors (MIT License — see root THIRD-PARTY-NOTICES.md).
 * Modified for Hunt Command v2:
 * - Exposes only allowlisted Hunt Command IPC channels (`INVOKE_CHANNELS` / `EVENT_CHANNELS`).
 * - Zero `app:openExternal`, zero `terminal`, zero `workspace`, zero `mcp` or `connectors` channels.
 */
import { contextBridge, type IpcRendererEvent, ipcRenderer } from "electron";
import {
  type DesktopBridge,
  EVENT_CHANNELS,
  type EventChannel,
  INVOKE_CHANNELS,
  type InvokeChannel,
  type IpcResult,
} from "../shared/ipc.ts";

const bridge: DesktopBridge = {
  invoke<T = unknown>(channel: InvokeChannel, payload?: unknown): Promise<IpcResult<T>> {
    if (!INVOKE_CHANNELS.has(channel)) {
      return Promise.resolve({
        ok: false,
        error: {
          code: "ipc_channel_denied",
          message: `IPC invoke channel not allowed: ${String(channel)}`,
        },
      });
    }
    return ipcRenderer.invoke(channel, payload) as Promise<IpcResult<T>>;
  },
  on<TPayload = unknown>(channel: EventChannel, listener: (payload: TPayload) => void): () => void {
    if (!EVENT_CHANNELS.has(channel)) {
      throw new Error(`IPC event channel not allowed: ${String(channel)}`);
    }
    const wrapped = (_event: IpcRendererEvent, payload: unknown) => {
      listener(payload as TPayload);
    };
    ipcRenderer.on(channel, wrapped);
    return () => {
      ipcRenderer.removeListener(channel, wrapped);
    };
  },
  platform: process.platform,
};

contextBridge.exposeInMainWorld("huntWorkbench", bridge);
