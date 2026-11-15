/**
 * Adapted from omp-desktop/app/src/main/features/browser/cdp-filter.ts
 * Copyright (c) omp-desktop contributors (MIT License — see root THIRD-PARTY-NOTICES.md).
 * Modified for Hunt Command v2 (#178 G1.3, #189):
 * - Blocks `Fetch.*` so bot CDP clients can NEVER disable or override main-process `Fetch.enable`.
 * - Blocks all mutating `Network.*` commands (`setExtraHTTPHeaders`, `setCookie*`, `deleteCookies`,
 *   `clearBrowserCookies`, `setBypassServiceWorker`, `emulateNetworkConditions`, `setRequestInterception`, etc.),
 *   permitting only read-only `Network.enable`, `Network.disable`, `Network.getResponseBody`, and `Network.getRequestPostData`.
 * - Blocks `ServiceWorker.*`, `Storage.*`, `IndexedDB.*`, `CacheStorage.*`, `BackgroundService.*`,
 *   `Page.setDownloadBehavior`, `Page.setBypassCSP`, and `Security.setIgnoreCertificateErrors`.
 * - Scopes `isOpenableWatchUrl` to `documentAllowed(scope, url)` (pinned `127.0.0.1:<port>` only — zero `localhost`).
 * - Validates `Page.navigate` URLs with the same allowed-document check (CDP-initiated loads skip `will-navigate`),
 *   and denies `Page.navigateToHistoryEntry`, `Page.setDocumentContent`, `Page.printToPDF`, `IO.*`, and
 *   `DOM.setFileInputFiles` outright.
 */
import { documentAllowed, type WatchScope } from "./browser-policy.ts";

/** `Target.*` commands a page session may issue; the hub answers or scopes each one itself. */
const PAGE_TARGET_METHODS: Record<string, true> = {
  "Target.setAutoAttach": true,
  "Target.detachFromTarget": true,
  "Target.getTargetInfo": true,
  "Target.createTarget": true,
  "Target.closeTarget": true,
  "Target.activateTarget": true,
};

/** Domains blocked completely on Watch Browser sessions to preserve the main-process request & storage fence. */
const DENIED_DOMAINS: Record<string, true> = {
  Fetch: true,
  ServiceWorker: true,
  Storage: true,
  IndexedDB: true,
  CacheStorage: true,
  BackgroundService: true,
  Browser: true,
  Tethering: true,
  SystemInfo: true,
  Extensions: true,
  PWA: true,
  Cast: true,
  FileSystem: true,
  WebAuthn: true,
  DeviceAccess: true,
  BluetoothEmulation: true,
  FedCm: true,
  IO: true,
};

/** Read-only `Network.*` commands permitted for passive telemetry inspection; all mutating `Network.*` fail. */
const ALLOWED_NETWORK_METHODS: Record<string, true> = {
  "Network.enable": true,
  "Network.disable": true,
  "Network.getResponseBody": true,
  "Network.getRequestPostData": true,
};

/** Specific bypass/download/TLS commands denied inside otherwise-allowed domains. */
const DENIED_METHODS: Record<string, true> = {
  "Page.setDownloadBehavior": true,
  "Page.setBypassCSP": true,
  "Security.setIgnoreCertificateErrors": true,
  "Security.setOverrideCertificateErrors": true,
  "Emulation.setUserAgentOverride": true,
  // History entries and replaced documents carry no URL the fence can check; PDF/IO/file inputs read local data.
  "Page.navigateToHistoryEntry": true,
  "Page.setDocumentContent": true,
  "Page.printToPDF": true,
  "DOM.setFileInputFiles": true,
};

/** Commands whose `params.url` loads a document and must pass the session's allowed-document check. */
const URL_NAVIGATION_METHODS: Record<string, true> = {
  "Page.navigate": true,
};

/** Browser-domain reads that are harmless on a page session. */
const ALLOWED_BROWSER_METHODS: Record<string, true> = {
  "Browser.getVersion": true,
};

export const CDP_ERROR_SERVER = -32000;
export const CDP_ERROR_METHOD_NOT_FOUND = -32601;

/**
 * Returns why `method` is refused on a Watch Browser page (or child) session, or `null` when
 * the hub may handle or forward it. `isOpenableUrl` is the session scope's allowed-document check;
 * without it every URL-carrying navigation is refused (fail closed).
 */
/**
 * Exact shape of every Chromium DevTools protocol method name (`Domain.method`, case-sensitive).
 * Anything else (`io.read`, `Page.printToPDF `, a trailing NUL, `Page..x`) is refused before the
 * allow/deny tables are consulted, so a near-miss spelling can never slip past an exact-match deny entry.
 */
export const CDP_METHOD_NAME_RE = /^[A-Z][A-Za-z]+\.[a-z][A-Za-z]+$/;

export function deniedSessionCommand(
  method: string,
  params: Record<string, unknown> | undefined,
  isOpenableUrl?: (url: string) => boolean,
): string | null {
  if (typeof method !== "string" || !CDP_METHOD_NAME_RE.test(method)) {
    return `'${String(method).slice(0, 80)}' is not a valid CDP method`;
  }
  const dot = method.indexOf(".");
  const domain = method.slice(0, dot);

  if (domain === "Target") {
    return PAGE_TARGET_METHODS[method] === true
      ? null
      : `'${method}' is denied in the Hunt Command Watch Browser`;
  }

  if (domain === "Network") {
    return ALLOWED_NETWORK_METHODS[method] === true
      ? null
      : `'${method}' is denied in the Hunt Command Watch Browser (read-only Network domain)`;
  }

  if (DENIED_METHODS[method] === true) {
    return `'${method}' is denied in the Hunt Command Watch Browser`;
  }

  if (DENIED_DOMAINS[domain] === true && ALLOWED_BROWSER_METHODS[method] !== true) {
    return `'${method}' is denied in the Hunt Command Watch Browser`;
  }

  if (params && Object.hasOwn(params, "browserContextId")) {
    return `'${method}' with browserContextId is denied in the Hunt Command Watch Browser`;
  }

  if (URL_NAVIGATION_METHODS[method] === true) {
    const url = params?.url;
    if (typeof url !== "string" || isOpenableUrl === undefined || !isOpenableUrl(url)) {
      return `'${method}' URL is outside the pinned 127.0.0.1 Watch Browser scope`;
    }
  }

  return null;
}

/** URLs a bot CDP client or analyst Watch bar may open: strictly pinned `127.0.0.1` lab scope or `about:blank`. */
export function isOpenableWatchUrl(scope: WatchScope, url: string): boolean {
  return documentAllowed(scope, url);
}
