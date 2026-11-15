import { describe, expect, test } from "bun:test";
import {
  applyNetworkQuietSwitches,
  CHROMIUM_DISABLED_FEATURES,
  WEBRTC_IP_HANDLING_POLICY,
} from "../src/main/network-quiet.ts";
import fs from "node:fs";
import path from "node:path";

function fakeApp(initialDisable = "") {
  const switches = new Map<string, string>(initialDisable ? [["disable-features", initialDisable]] : []);
  const listeners: Array<(e: unknown, wc: { setWebRTCIPHandlingPolicy(p: string): void }) => void> = [];
  return {
    switches,
    listeners,
    app: {
      commandLine: {
        getSwitchValue: (n: string) => switches.get(n) ?? "",
        appendSwitch: (n: string, v = "") => void switches.set(n, v),
      },
      on: (_ev: "web-contents-created", l: (typeof listeners)[number]) => void listeners.push(l),
    },
  };
}

describe("Chromium binds no non-loopback sockets on its own", () => {
  test("disables the mDNS responder and Cast/DIAL discovery, keeping existing disabled features", () => {
    const f = fakeApp("SomethingElse");
    applyNetworkQuietSwitches(f.app);
    const disabled = (f.switches.get("disable-features") ?? "").split(",");
    expect(disabled).toContain("SomethingElse");
    for (const feat of ["WebRtcHideLocalIpsWithMdns", "MediaRouter", "DialMediaRouteProvider", "CastMediaRouteProvider"]) {
      expect(disabled).toContain(feat);
    }
    expect(CHROMIUM_DISABLED_FEATURES.length).toBe(4);
  });

  test("every created webContents gets the disable_non_proxied_udp WebRTC policy", () => {
    const f = fakeApp();
    applyNetworkQuietSwitches(f.app);
    const applied: string[] = [];
    for (const l of f.listeners) l({}, { setWebRTCIPHandlingPolicy: (p) => void applied.push(p) });
    expect(applied).toEqual([WEBRTC_IP_HANDLING_POLICY]);
    expect(WEBRTC_IP_HANDLING_POLICY).toBe("disable_non_proxied_udp");
  });

  test("main entry applies the switches before app.whenReady()", () => {
    const src = fs.readFileSync(path.join(import.meta.dir, "../src/main/index.ts"), "utf8");
    const applyAt = src.indexOf("applyNetworkQuietSwitches(app);");
    expect(applyAt).toBeGreaterThan(0);
    expect(applyAt).toBeLessThan(src.indexOf("app.whenReady().then("));
  });
});
