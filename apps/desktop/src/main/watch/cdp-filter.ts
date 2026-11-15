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
};

/** Browser-domain reads that are harmless on a page session. */
const ALLOWED_BROWSER_METHODS: Record<string, true> = {
  "Browser.getVersion": true,
};

export const CDP_ERROR_SERVER = -32000;
export const CDP_ERROR_METHOD_NOT_FOUND = -32601;

/**
 * Returns why `method` is refused on a Watch Browser page (or child) session, or `null` when
 * the hub may handle or forward it.
 */
export function deniedSessionCommand(
  method: string,
  params: Record<string, unknown> | undefined,
): string | null {
  const dot = method.indexOf(".");
  if (dot <= 0) {
    return `'${method}' is not a valid CDP method`;
  }
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

  return null;
}

/** URLs a bot CDP client or analyst Watch bar may open: strictly pinned `127.0.0.1` lab scope or `about:blank`. */
export function isOpenableWatchUrl(scope: WatchScope, url: string): boolean {
  return documentAllowed(scope, url);
}
