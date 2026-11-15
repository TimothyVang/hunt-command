/**
 * Adapted from omp-desktop/app/src/main/index.ts
 * Copyright (c) omp-desktop contributors (MIT License — see root THIRD-PARTY-NOTICES.md).
 * Modified for Hunt Command v2 (#178, #179, #180, #189):
 * - Calls `app.enableSandbox()` globally before `app.whenReady()`.
 * - Isolates `userData` (`HUNT_COMMAND_USER_DATA` or `HuntCommand`).
 * - Resolves runtime directory outside `.git` (`resolveRuntimeDir(..., { repoRoot })`).
 * - Enforces `TrustedRenderers.isTrustedSender` on every `ipcMain.handle` channel.
 * - Routes `hunt-daemon` streaming notifications through the 33ms `EventBatcher`.
 * - Zero `shell.openExternal`, zero PTY `terminal`, zero `workspace`/`git`/`mcp`/`connectors`.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { app, BrowserWindow, ipcMain, safeStorage } from "electron";
import { resolveRuntimeDir } from "@hunt-command/shared";
import { INVOKE_CHANNEL_LIST, type InvokeChannel, type IpcResult } from "../shared/ipc.ts";
import { HuntDaemonSidecar } from "./daemon/daemon-sidecar.ts";
import { EventBatcher } from "./daemon/event-batcher.ts";
import { resolveDaemonLaunch } from "./daemon/resolve-daemon.ts";
import { renderHtmlToPdfViaChromium } from "./export/pdf-print.ts";
import { recordOffscreenWorkbenchAndCutFilm } from "./film/offscreen-recorder.ts";
import { createLogger } from "./logger.ts";
import { SecretVault } from "./secret-vault.ts";
import { hardenSession, hardenWindow, TrustedRenderers } from "./security.ts";
import { WatchBrowserController } from "./watch/watch-panel.ts";
import { WorkbenchService } from "./workbench-service.ts";

// Must be called before app.whenReady() so every renderer & utility process runs OS-sandboxed.
app.enableSandbox();

const mainDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(mainDir, "../../../..");

const customUserData = process.env.HUNT_COMMAND_USER_DATA;
if (customUserData && customUserData.trim().length > 0) {
  const resolvedUserData = path.resolve(customUserData);
  fs.mkdirSync(resolvedUserData, { recursive: true });
  app.setPath("userData", resolvedUserData);
} else {
  app.setName("HuntCommand");
}

if (!customUserData) {
  const gotLock = app.requestSingleInstanceLock();
  if (!gotLock) {
    app.quit();
  }
}

let mainWindow: BrowserWindow | null = null;
let watchController: WatchBrowserController | null = null;
let daemonSidecar: HuntDaemonSidecar | null = null;

function resolveRendererTargetUrl(): URL {
  const devUrl = process.env.ELECTRON_RENDERER_URL;
  if (devUrl && devUrl.trim().length > 0) {
    return new URL(devUrl);
  }
  const indexHtmlPath = path.join(mainDir, "../renderer/index.html");
  return pathToFileURL(indexHtmlPath);
}

function broadcastToWindow(channel: string, payload: unknown): void {
  if (mainWindow && !mainWindow.isDestroyed() && !mainWindow.webContents.isDestroyed()) {
    mainWindow.webContents.send(channel, payload);
  }
}

async function bootstrap(): Promise<void> {
  const userDataDir = app.getPath("userData");
  const log = createLogger(path.join(userDataDir, "logs"));

  const runtimeCandidate =
    process.env.HUNT_COMMAND_RUNTIME_DIR ?? path.join(userDataDir, "runtime");
  const runtimePaths = resolveRuntimeDir(runtimeCandidate, { repoRoot });
  fs.mkdirSync(runtimePaths.rootDir, { recursive: true });

  const rendererUrl = resolveRendererTargetUrl();
  const preloadPath = path.join(mainDir, "../preload/index.cjs");
  const trustedRenderers = new TrustedRenderers(rendererUrl);

  hardenSession(trustedRenderers);

  const eventBatcher = new EventBatcher((huntId, events) => {
    broadcastToWindow("daemon:eventBatch", { huntId, events });
  }, 33);

  daemonSidecar = new HuntDaemonSidecar({
    resolveLaunch: () =>
      resolveDaemonLaunch({
        isPackaged: app.isPackaged,
        resourcesPath: process.resourcesPath,
        repoRoot,
      }),
    runtimeRootDir: runtimePaths.rootDir,
    log,
    onEvent: (ev) => {
      eventBatcher.push(ev.hunt_id, ev);
    },
    onStatusChanged: (status) => {
      broadcastToWindow("daemon:stateChanged", status);
    },
  });
  daemonSidecar.start();

  const vault = new SecretVault(path.join(userDataDir, "vault"), safeStorage);

  const win = new BrowserWindow({
    width: 1640,
    height: 980,
    minWidth: 1200,
    minHeight: 760,
    title: "Hunt Command — DFIR Case Workbench",
    backgroundColor: "#090d16",
    show: process.env.HUNT_COMMAND_HEADLESS !== "1",
    webPreferences: {
      preload: preloadPath,
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false,
      webSecurity: true,
      allowRunningInsecureContent: false,
      navigateOnDragDrop: false,
      spellcheck: false,
    },
  });

  mainWindow = win;
  trustedRenderers.add(win);
  hardenWindow(win, trustedRenderers);

  const watch = new WatchBrowserController({
    window: win,
    log,
    onStateChanged: (state) => broadcastToWindow("watch:stateChanged", state),
  });
  watchController = watch;

  const service = new WorkbenchService({
    runtimePaths,
    sidecar: daemonSidecar,
    vault,
    pdfRenderer: renderHtmlToPdfViaChromium,
    filmRunner: (workbench, speed, captions, allowWorkFilm) =>
      recordOffscreenWorkbenchAndCutFilm({
        filmsRootDir: runtimePaths.filmsDir,
        rendererUrl: rendererUrl.toString(),
        preloadPath,
        trustedRenderers,
        workbench,
        speed,
        captions,
        allowWorkFilm,
        onProgress: (phase, detail) => broadcastToWindow("film:progress", { phase, detail }),
      }),
    watchHandlers: {
      getState: () => watch.getState(),
      setBounds: (bounds) => watch.setBounds(bounds),
      navigate: async (runId, role, url) => await watch.navigate(runId, role, url),
    },
  });

  const dispatchChannel = async (channel: InvokeChannel, payload: unknown): Promise<unknown> => {
    switch (channel) {
      case "daemon:status":
        return service.getDaemonStatus();
      case "daemon:restart":
        return await service.restartDaemon();
      case "hunt:listRuns":
        return await service.listRuns();
      case "hunt:getWorkbenchState":
        return await service.getWorkbenchState(payload);
      case "hunt:startRun":
        return await service.startRun(payload);
      case "hunt:globalStop":
        return await service.globalStop(payload);
      case "hunt:submitGateDecision":
        return await service.submitGateDecision(payload);
      case "hunt:inspectTranscriptPage":
        return await service.inspectTranscriptPage(payload);
      case "hunt:queryDissector":
        return await service.queryDissector(payload);
      case "hunt:resolveEvidence":
        return await service.resolveEvidence(payload);
      case "watch:getState":
        return service.getWatchState();
      case "watch:setBounds":
        return service.setWatchBounds(payload);
      case "watch:navigate":
        return await service.navigateWatch(payload);
      case "export:customerReport":
        return await service.exportReport(payload);
      case "film:recordAndCut":
        return await service.recordAndCutFilm(payload);
      case "film:status":
        return service.getFilmStatus();
      case "vault:status":
        return service.getVaultStatus();
      case "vault:hasSecret":
        return service.hasVaultSecret(payload);
      case "vault:setSecret":
        return service.setVaultSecret(payload);
      case "vault:deleteSecret":
        return service.deleteVaultSecret(payload);
    }
  };

  for (const channel of INVOKE_CHANNEL_LIST) {
    ipcMain.handle(channel, async (event, payload: unknown): Promise<IpcResult<unknown>> => {
      if (!trustedRenderers.isTrustedSender(event)) {
        log.warn(`Blocked untrusted IPC sender on channel '${channel}'`);
        return {
          ok: false,
          error: {
            code: "UNTRUSTED_IPC_SENDER",
            message: "IPC invocation denied: untrusted frame or origin",
          },
        };
      }
      try {
        const data = await dispatchChannel(channel, payload);
        return { ok: true, data };
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        const code =
          err && typeof err === "object" && "code" in err && typeof (err as { code?: unknown }).code === "string"
            ? (err as { code: string }).code
            : "IPC_HANDLER_ERROR";
        return {
          ok: false,
          error: { code, message },
        };
      }
    });
  }

  await win.loadURL(rendererUrl.toString());

  app.on("second-instance", () => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
    }
  });
}

app.whenReady().then(() => {
  void bootstrap();
});

app.on("window-all-closed", () => {
  app.quit();
});

app.on("before-quit", () => {
  void watchController?.dispose();
  void daemonSidecar?.stop();
});
