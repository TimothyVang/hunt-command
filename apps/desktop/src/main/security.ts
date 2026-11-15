/**
 * Adapted from omp-desktop/app/src/main/security.ts
 * Copyright (c) omp-desktop contributors (MIT License — see root THIRD-PARTY-NOTICES.md).
 * Modified for Hunt Command v2 (#178 G1.2 & G3.1, ADR-0003):
 * - DELETED `shell.openExternal` / `openExternalSafe` completely so clicking a C2/phishing/canary
 *   indicator in the DFIR workbench can NEVER launch the analyst's external browser.
 * - Denies all `media` (audio, video, screen-capture) permissions; offscreen filming uses
 *   a dedicated hidden offscreen BrowserWindow `paint` hook instead of renderer MediaRecorder.
 * - Cancels downloads (`will-download`) and blocks foreign navigation/redirects/webviews.
 */
import electronModule, {
  type BrowserWindow,
  type IpcMainInvokeEvent,
  type Session,
  type WebContents,
} from "electron";

/**
 * Pure URL match helper (exported for unit tests without requiring a live Electron instance).
 */
export function matchesTrustedRendererUrl(trustedRendererUrl: URL, candidateUrl: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(candidateUrl);
  } catch {
    return false;
  }
  if (trustedRendererUrl.protocol === "file:") {
    return parsed.protocol === "file:" && parsed.pathname === trustedRendererUrl.pathname;
  }
  return parsed.origin === trustedRendererUrl.origin;
}

/** Tracks the app's own windows and the exact URL their renderer is served from. */
export class TrustedRenderers {
  readonly #ids = new Set<number>();
  readonly #rendererUrl: URL;

  constructor(rendererUrl: URL) {
    this.#rendererUrl = rendererUrl;
  }

  add(win: BrowserWindow): void {
    const id = win.webContents.id;
    this.#ids.add(id);
    win.on("closed", () => this.#ids.delete(id));
  }

  webContentsIds(): number[] {
    return [...this.#ids];
  }

  isRendererUrl(url: string): boolean {
    return matchesTrustedRendererUrl(this.#rendererUrl, url);
  }

  /** Validates that an IPC call originates from the main frame of a registered Hunt Command window. */
  isTrustedSender(event: IpcMainInvokeEvent): boolean {
    const frame = event.senderFrame;
    if (!frame || !this.#ids.has(event.sender.id)) {
      return false;
    }
    if (frame !== event.sender.mainFrame) {
      return false;
    }
    return this.isRendererUrl(frame.url);
  }
}

/**
 * Window-level hardening:
 * - Zero popups (`action: "deny"`, never forwards to external browser).
 * - Zero foreign navigation or redirects.
 * - Zero `<webview>` attachment.
 */
export function hardenWindow(win: BrowserWindow, trusted: TrustedRenderers): void {
  const contents = win.webContents;
  contents.setWindowOpenHandler(() => ({ action: "deny" }));
  contents.on("will-navigate", (event, url) => {
    if (!trusted.isRendererUrl(url)) {
      event.preventDefault();
    }
  });
  contents.on("will-redirect", (event, url) => {
    if (!trusted.isRendererUrl(url)) {
      event.preventDefault();
    }
  });
  contents.on("will-attach-webview", (event) => {
    event.preventDefault();
  });
}

/**
 * Session-level hardening:
 * - Denies all permissions except `clipboard-sanitized-write` for Defanged Copy-Only Pills
 *   on the main frame of a trusted Hunt Command window.
 * - Denies all `media`, camera, microphone, screen capture, USB/HID/serial devices, and downloads.
 */
export function hardenSession(trusted: TrustedRenderers, targetSession?: Session): void {
  const ses =
    targetSession ??
    (electronModule as unknown as { session: { defaultSession: Session } }).session.defaultSession;
  const isAppMainFrame = (
    contents: WebContents | null,
    url: string | undefined,
    isMainFrame: boolean,
  ): boolean =>
    Boolean(
      contents &&
        isMainFrame &&
        url &&
        trusted.webContentsIds().includes(contents.id) &&
        trusted.isRendererUrl(url),
    );

  ses.setPermissionRequestHandler((contents, permission, callback, details) => {
    if (permission === "clipboard-sanitized-write") {
      callback(isAppMainFrame(contents, details.requestingUrl, details.isMainFrame));
      return;
    }
    callback(false);
  });

  ses.setPermissionCheckHandler((contents, permission, _origin, details) => {
    if (permission === "clipboard-sanitized-write") {
      return isAppMainFrame(contents, details.requestingUrl, details.isMainFrame);
    }
    return false;
  });

  ses.setDevicePermissionHandler(() => false);
  ses.on("will-download", (event) => {
    event.preventDefault();
  });
}
