import { describe, expect, test } from "bun:test";
import crypto from "node:crypto";
import net from "node:net";
import { createWatchScope } from "../src/main/watch/browser-policy.ts";
import { deniedSessionCommand, isOpenableWatchUrl } from "../src/main/watch/cdp-filter.ts";
import { CdpHub, type HubPage } from "../src/main/watch/cdp-hub.ts";
import { CdpEndpoint } from "../src/main/watch/cdp-server.ts";

const SCOPE = createWatchScope({
  caseId: "northvale-lab-001",
  labOrigin: "http://127.0.0.1:18400",
  arkimeOrigin: "http://127.0.0.1:18401",
  startSec: 1,
  stopSec: 2,
});

async function startEndpoint(): Promise<{ ep: CdpEndpoint; hub: CdpHub; token: string }> {
  const page: HubPage = {
    id: 1,
    url: () => "about:blank",
    title: () => "t",
    attach() {},
    detach() {},
    send: async () => ({}),
  };
  const hub = new CdpHub({
    pages: () => [page],
    createPage: async () => page,
    closePage: async () => {},
    activatePage() {},
    isOpenableUrl: (u) => isOpenableWatchUrl(SCOPE, u),
    version: () => ({ product: "HuntCommandWatch/test", userAgent: "test" }),
  });
  const ep = await CdpEndpoint.start(hub);
  return { ep, hub, token: ep.wsUrl.split("/").pop()! };
}

function handshake(port: number, token: string): string {
  const key = crypto.randomBytes(16).toString("base64");
  return (
    `GET /devtools/browser/${token} HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nUpgrade: websocket\r\n` +
    `Connection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n\r\n`
  );
}

function maskedText(text: string): Buffer {
  const payload = Buffer.from(text, "utf8");
  if (payload.length >= 126) throw new Error("test frame too long");
  const mask = crypto.randomBytes(4);
  const masked = Buffer.from(payload.map((b, i) => b ^ mask[i & 3]!));
  return Buffer.concat([Buffer.from([0x81, 0x80 | payload.length]), mask, masked]);
}

function connect(port: number, first: Buffer | string): Promise<{ sock: net.Socket; data: () => string }> {
  return new Promise((resolve) => {
    let buf = "";
    const sock = net.connect(port, "127.0.0.1", () => {
      sock.write(first);
      resolve({ sock, data: () => buf });
    });
    sock.on("data", (d) => (buf += d.toString("latin1")));
    sock.on("error", () => {});
  });
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function waitFor(pred: () => boolean, ms = 2_000): Promise<void> {
  const t0 = Date.now();
  while (!pred()) {
    if (Date.now() - t0 > ms) throw new Error("waitFor timed out");
    await sleep(10);
  }
}

describe("CdpEndpoint client slots and framing", () => {
  test("clients that drop without a close frame (destroy / half-close) release their slot", async () => {
    const { ep, hub, token } = await startEndpoint();
    try {
      for (let i = 0; i < 12; i++) {
        const c = await connect(ep.port, handshake(ep.port, token));
        await waitFor(() => c.data().includes("101 Switching Protocols"));
        if (i % 2 === 0) c.sock.destroy();
        else c.sock.end();
        await waitFor(() => ep.clientCount === 0 && hub.clientCount === 0);
      }
      // An attack connection with a bad pipelined frame (unmasked) must also not hold a slot.
      for (let i = 0; i < 10; i++) {
        const c = await connect(ep.port, Buffer.concat([Buffer.from(handshake(ep.port, token)), Buffer.from([0x81, 0x02, 0x7b, 0x7d])]));
        await waitFor(() => ep.clientCount === 0);
        c.sock.destroy();
      }
      const legit = await connect(ep.port, handshake(ep.port, token));
      await waitFor(() => legit.data().length > 0);
      expect(legit.data().split("\r\n")[0]).toBe("HTTP/1.1 101 Switching Protocols");
      legit.sock.destroy();
    } finally {
      await ep.close();
    }
  });

  test("a frame pipelined with the upgrade request is delivered and answered", async () => {
    const { ep, token } = await startEndpoint();
    try {
      const frame = maskedText(JSON.stringify({ id: 7, method: "Browser.getVersion" }));
      const c = await connect(ep.port, Buffer.concat([Buffer.from(handshake(ep.port, token)), frame]));
      await waitFor(() => c.data().includes('"id":7'));
      expect(c.data()).toContain("HuntCommandWatch/test");
      c.sock.destroy();
    } finally {
      await ep.close();
    }
  });
});

describe("CDP method-name normalization", () => {
  test("near-miss spellings of denied methods are refused as invalid", () => {
    for (const m of ["io.read", "Page.printToPDF ", " Page.printToPDF", "page.printToPDF", "IO.read\u0000", "Page..printToPDF", "Page.printToPDF\n", "Fetch.disable;", "__proto__.x", "constructor.constructor", "Page.PrintToPDF"]) {
      expect(deniedSessionCommand(m, undefined, () => true)).toMatch(/not a valid CDP method/);
    }
    expect(deniedSessionCommand("Page.printToPDF", undefined, () => true)).toMatch(/denied/);
    expect(deniedSessionCommand("IO.read", undefined, () => true)).toMatch(/denied/);
    expect(deniedSessionCommand("Runtime.evaluate", undefined, () => true)).toBeNull();
    expect(deniedSessionCommand("Page.captureScreenshot", undefined, () => true)).toBeNull();
  });
});
