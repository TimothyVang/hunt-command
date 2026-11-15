/**
 * Keeps Chromium from binding non-loopback sockets on its own.
 *
 * Measured on Electron 36 / Windows (see the fix2-desktop mdns experiment):
 * - `WebRtcHideLocalIpsWithMdns` makes any `RTCPeerConnection` start an mDNS responder that binds
 *   UDP `0.0.0.0:5353` and `[::]:5353` and keeps them open after the connection closes. Disabling the
 *   feature is the only switch that stops that bind.
 * - Without an IP handling policy, ICE gathering binds a UDP socket on every LAN interface and emits
 *   host candidates. `disable_non_proxied_udp` removes those binds and all candidates (the Watch session's
 *   proxy is the `127.0.0.1:1` blackhole, so no proxied path exists either).
 * - `--force-webrtc-ip-handling-policy` has no effect in Electron, so the policy is set per webContents.
 * - Media Router / DIAL / Cast discovery are disabled too: they use SSDP/mDNS discovery that the app
 *   never needs.
 */
export const CHROMIUM_DISABLED_FEATURES = [
  "MediaRouter",
  "DialMediaRouteProvider",
  "CastMediaRouteProvider",
  "WebRtcHideLocalIpsWithMdns",
] as const;

export const WEBRTC_IP_HANDLING_POLICY = "disable_non_proxied_udp" as const;

interface CommandLineLike {
  getSwitchValue(name: string): string;
  appendSwitch(name: string, value?: string): void;
}

interface WebContentsLike {
  setWebRTCIPHandlingPolicy(policy: typeof WEBRTC_IP_HANDLING_POLICY): void;
}

interface AppLike {
  commandLine: CommandLineLike;
  on(event: "web-contents-created", listener: (event: unknown, contents: WebContentsLike) => void): unknown;
}

/** Must run before `app.whenReady()`: feature switches are read when the browser process starts. */
export function applyNetworkQuietSwitches(app: AppLike): void {
  const existing = app.commandLine
    .getSwitchValue("disable-features")
    .split(",")
    .map((f) => f.trim())
    .filter(Boolean);
  const merged = [...new Set([...existing, ...CHROMIUM_DISABLED_FEATURES])];
  app.commandLine.appendSwitch("disable-features", merged.join(","));
  app.on("web-contents-created", (_event, contents) => {
    contents.setWebRTCIPHandlingPolicy(WEBRTC_IP_HANDLING_POLICY);
  });
}
