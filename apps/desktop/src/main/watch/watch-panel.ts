/**
 * Adapted from omp-desktop/app/src/main/features/browser/panel.ts
 * Copyright (c) omp-desktop contributors (MIT License — see root THIRD-PARTY-NOTICES.md).
 * Modified for Hunt Command v2 (#178 G1.3, #189):
 * - Uses ephemeral non-persistent partition `session.fromPartition("hunt-watch:${runId}:${role}", { cache: false })`
 *   eliminating cross-case cookie, cache, and storage leakage.
 * - Sets loopback blackhole proxy (`127.0.0.1:1` + `<allowed 127.0.0.1:ports>;<-loopback>`) before navigation.
 * - Attaches main-process `webContents.debugger` and enforces `Fetch.enable` (`decideWatchRequest` +
 *   `sanitizeWatchRequestHeaders`) on both the root page and all attached child targets.
 * - Denies all popups (`setWindowOpenHandler`), downloads (`will-download`), permissions, and out-of-scope navigations.
 */
import { type BrowserWindow, type Rectangle, session, WebContentsView } from "electron";
import type { ProfileId } from "@hunt-command/shared";
import type { WatchBrowserState } from "../../shared/workbench-types.ts";
import type { Logger } from "../logger.ts";
import {
  buildWatchProxyConfig,
  decideWatchRequest,
  documentAllowed,
  listAllowedWatchOrigins,
  sanitizeWatchRequestHeaders,
  type WatchHeaderEntry,
  type WatchScope,
} from "./browser-policy.ts";
import { isOpenableWatchUrl } from "./cdp-filter.ts";
import { CdpHub, type HubPage } from "./cdp-hub.ts";
import { CdpEndpoint } from "./cdp-server.ts";

interface RequestPausedParams {
  requestId: string;
  request?: {
    url?: string;
    method?: string;
    headers?: Record<string, string>;
    postData?: string;
    hasPostData?: boolean;
  };
}

export interface WatchBrowserControllerOptions {
  window: BrowserWindow;
  log: Logger;
  onStateChanged?: (state: WatchBrowserState) => void;
}

export class WatchBrowserController {
  readonly #win: BrowserWindow;
  readonly #log: Logger;
  readonly #onStateChanged: ((state: WatchBrowserState) => void) | undefined;
  #view: WebContentsView | null = null;
  #hub: CdpHub | null = null;
  #endpoint: CdpEndpoint | null = null;
  #scope: WatchScope | null = null;
  #bounds: Rectangle | null = null;
  #runId = "standby";
  #role: ProfileId = "framework-researcher";
  #partition = "hunt-watch:standby:framework-researcher";
  #blockedRequestCount = 0;
  #lastBlockedReason: string | null = null;

  constructor(options: WatchBrowserControllerOptions) {
    this.#win = options.window;
    this.#log = options.log.child("watch-browser");
    this.#onStateChanged = options.onStateChanged;
  }

  getState(): WatchBrowserState {
    const wc = this.#view?.webContents;
    return {
      enabled: this.#view !== null && this.#scope !== null,
      runId: this.#runId,
      role: this.#role,
      partition: this.#partition,
      currentUrl: wc && !wc.isDestroyed() ? wc.getURL() || "about:blank" : "about:blank",
      title: wc && !wc.isDestroyed() ? wc.getTitle() || "Watch Browser (Fenced)" : "Watch Browser (Standby)",
      loading: wc && !wc.isDestroyed() ? wc.isLoading() : false,
      allowedOrigins: this.#scope ? listAllowedWatchOrigins(this.#scope) : [],
      blockedRequestCount: this.#blockedRequestCount,
      lastBlockedReason: this.#lastBlockedReason,
      cdpEndpointUrl: this.#endpoint?.httpUrl ?? null,
    };
  }

  setBounds(bounds: Rectangle | null): WatchBrowserState {
    this.#bounds = bounds;
    if (this.#view) {
      if (bounds) {
        this.#view.setBounds(bounds);
        this.#view.setVisible(true);
      } else {
        this.#view.setVisible(false);
      }
    }
    return this.getState();
  }

  async openFencedSession(
    runId: string,
    role: ProfileId,
    scope: WatchScope,
    initialUrl = "about:blank",
  ): Promise<WatchBrowserState> {
    if (!documentAllowed(scope, initialUrl)) {
      throw new Error(`Refusing Watch navigation outside pinned 127.0.0.1 scope: ${initialUrl}`);
    }

    await this.disposeViewOnly();

    this.#runId = runId;
    this.#role = role;
    this.#scope = scope;
    this.#partition = `hunt-watch:${runId}:${role}`;
    this.#blockedRequestCount = 0;
    this.#lastBlockedReason = null;

    const ses = session.fromPartition(this.#partition, { cache: false });
    await ses.setProxy(buildWatchProxyConfig(scope));
    ses.setPermissionRequestHandler((_wc, _perm, callback) => callback(false));
    ses.setPermissionCheckHandler(() => false);
    ses.setDevicePermissionHandler(() => false);
    ses.on("will-download", (ev) => ev.preventDefault());

    const view = new WebContentsView({
      webPreferences: {
        session: ses,
        sandbox: true,
        contextIsolation: true,
        nodeIntegration: false,
        webSecurity: true,
        allowRunningInsecureContent: false,
        navigateOnDragDrop: false,
      },
    });

    const wc = view.webContents;
    wc.setAudioMuted(true);
    wc.setWindowOpenHandler(() => ({ action: "deny" }));
    wc.on("will-attach-webview", (ev) => ev.preventDefault());
    wc.on("will-navigate", (ev, targetUrl) => {
      if (!documentAllowed(scope, targetUrl)) {
        ev.preventDefault();
        this.#recordBlock("navigation_outside_scope");
      }
    });
    wc.on("will-redirect", (ev, targetUrl) => {
      if (!documentAllowed(scope, targetUrl)) {
        ev.preventDefault();
        this.#recordBlock("redirect_outside_scope");
      }
    });
    // `will-navigate` covers only renderer-initiated main-frame loads; sub-frames need their own guard.
    wc.on("will-frame-navigate", (details) => {
      if (!details.isMainFrame && !documentAllowed(scope, details.url)) {
        details.preventDefault();
        this.#recordBlock("frame_navigation_outside_scope");
      }
    });
    // Backstop for loads that skip the `will-*` events (CDP `Page.navigate`, history, browser-initiated):
    // any main- or sub-frame navigation outside scope halts loading and resets the view to about:blank.
    wc.on("did-start-navigation", (details) => {
      if (!documentAllowed(scope, details.url)) {
        this.#recordBlock("navigation_outside_scope");
        wc.stop();
        void wc.loadURL("about:blank").catch(() => {});
      }
    });

    await this.#armDebuggerFence(wc, scope);

    this.#win.contentView.addChildView(view);
    if (this.#bounds) {
      view.setBounds(this.#bounds);
      view.setVisible(true);
    } else {
      view.setVisible(false);
    }
    this.#view = view;

    const hubPage = this.#buildHubPage(view);
    const hub = new CdpHub({
      pages: () => [hubPage],
      createPage: async (targetUrl) => {
        await wc.loadURL(targetUrl);
        return hubPage;
      },
      closePage: async () => {
        await wc.loadURL("about:blank");
      },
      activatePage: () => {},
      isOpenableUrl: (candidateUrl) => isOpenableWatchUrl(scope, candidateUrl),
      version: () => ({
        product: "HuntCommandWatch/0.2.0",
        userAgent: wc.getUserAgent(),
      }),
      onActivity: () => this.#emit(),
    });
    this.#hub = hub;
    this.#endpoint = await CdpEndpoint.start(hub);

    wc.on("did-start-loading", () => {
      hub.pageUpdated(hubPage.id);
      this.#emit();
    });
    wc.on("did-stop-loading", () => {
      hub.pageUpdated(hubPage.id);
      this.#emit();
    });
    wc.on("page-title-updated", () => {
      hub.pageUpdated(hubPage.id);
      this.#emit();
    });

    await wc.loadURL(initialUrl);
    this.#emit();
    return this.getState();
  }

  async navigate(runId: string, role: ProfileId, url: string): Promise<WatchBrowserState> {
    if (!this.#scope || !this.#view || this.#runId !== runId || this.#role !== role) {
      throw new Error(
        "Watch Browser has no active lab scope bound for this run/role; start a live lab-scoped run first.",
      );
    }
    if (!documentAllowed(this.#scope, url)) {
      this.#recordBlock("origin_not_lab");
      throw new Error(`Navigation blocked by Watch Browser policy: ${url}`);
    }
    await this.#view.webContents.loadURL(url);
    this.#emit();
    return this.getState();
  }

  async dispose(): Promise<void> {
    await this.disposeViewOnly();
  }

  async disposeViewOnly(): Promise<void> {
    if (this.#endpoint) {
      await this.#endpoint.close().catch(() => {});
      this.#endpoint = null;
    }
    this.#hub?.closeAll();
    this.#hub = null;
    if (this.#view) {
      const view = this.#view;
      this.#view = null;
      try {
        if (!this.#win.isDestroyed()) {
          this.#win.contentView.removeChildView(view);
        }
      } catch {
        // Ignore already removed view.
      }
      try {
        if (!view.webContents.isDestroyed()) {
          if (view.webContents.debugger.isAttached()) {
            view.webContents.debugger.detach();
          }
          view.webContents.close();
        }
      } catch {
        // Ignore teardown race.
      }
    }
  }

  async #armDebuggerFence(wc: Electron.WebContents, scope: WatchScope): Promise<void> {
    if (!wc.debugger.isAttached()) {
      wc.debugger.attach("1.3");
    }

    await wc.debugger.sendCommand("Fetch.enable", {
      patterns: [{ urlPattern: "*" }],
    });
    await wc.debugger.sendCommand("Target.setAutoAttach", {
      autoAttach: true,
      waitForDebuggerOnStart: false,
      flatten: true,
    });

    wc.debugger.on("message", (_event, method, params: Record<string, unknown>, sessionId?: string) => {
      if (method === "Fetch.requestPaused") {
        void this.#handlePausedRequest(
          wc,
          scope,
          params as unknown as RequestPausedParams,
          sessionId || undefined,
        );
        return;
      }

      if (method === "Target.attachedToTarget" && typeof params.sessionId === "string") {
        const childSession = params.sessionId;
        void wc.debugger
          .sendCommand("Fetch.enable", { patterns: [{ urlPattern: "*" }] }, childSession)
          .catch(() => {});
      }

      this.#hub?.pageEvent(wc.id, method, params, sessionId || undefined);
    });

    wc.debugger.on("detach", (_event, reason) => {
      this.#log.warn(`Watch Browser debugger detached (${reason}); blocking session`);
      this.#hub?.pageDetached(wc.id);
    });
  }

  async #handlePausedRequest(
    wc: Electron.WebContents,
    scope: WatchScope,
    paused: RequestPausedParams,
    sessionId?: string,
  ): Promise<void> {
    const requestId = paused.requestId;
    const rawUrl = paused.request?.url ?? "";
    const method = paused.request?.method ?? "GET";
    const postData =
      paused.request?.postData !== undefined
        ? paused.request.postData
        : paused.request?.hasPostData
          ? null
          : "";

    const verdict = decideWatchRequest(scope, method, rawUrl, postData);
    if (verdict.block) {
      this.#recordBlock(verdict.block);
      await wc.debugger
        .sendCommand(
          "Fetch.failRequest",
          { requestId, errorReason: "BlockedByClient" },
          sessionId,
        )
        .catch(() => {});
      return;
    }

    const effectiveUrl = verdict.url ?? rawUrl;
    const incomingHeaders: WatchHeaderEntry[] = Object.entries(paused.request?.headers ?? {}).map(
      ([name, value]) => ({ name, value }),
    );
    const headers = sanitizeWatchRequestHeaders(scope, effectiveUrl, incomingHeaders);

    const continueParams: Record<string, unknown> = {
      requestId,
      headers,
    };
    if (verdict.url !== undefined) {
      continueParams.url = verdict.url;
    }
    if (verdict.body !== undefined) {
      continueParams.postData = Buffer.from(verdict.body, "utf8").toString("base64");
    }

    await wc.debugger.sendCommand("Fetch.continueRequest", continueParams, sessionId).catch(() => {});
  }

  #buildHubPage(view: WebContentsView): HubPage {
    const wc = view.webContents;
    return {
      id: wc.id,
      url: () => (wc.isDestroyed() ? "about:blank" : wc.getURL() || "about:blank"),
      title: () => (wc.isDestroyed() ? "" : wc.getTitle()),
      attach: () => {
        if (!wc.isDestroyed() && !wc.debugger.isAttached()) {
          wc.debugger.attach("1.3");
        }
      },
      detach: () => {
        // Keep main-process Fetch.enable attached even when bot CDP client disconnects!
      },
      send: (method, params, sessionId) => wc.debugger.sendCommand(method, params, sessionId),
    };
  }

  #recordBlock(reason: string): void {
    this.#blockedRequestCount += 1;
    this.#lastBlockedReason = reason;
    this.#emit();
  }

  #emit(): void {
    this.#onStateChanged?.(this.getState());
  }
}
