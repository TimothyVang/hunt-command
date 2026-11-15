/**
 * Adapted from omp-desktop/app/src/main/features/browser/cdp-server.ts
 * Copyright (c) omp-desktop contributors (MIT License — see root THIRD-PARTY-NOTICES.md).
 * Modified for Hunt Command v2 (#178 G1.3, #189):
 * - Binds strictly to `127.0.0.1` and accepts `Host: 127.0.0.1:<port>` ONLY (`localhost` rejected!).
 * - Requires `Origin === undefined` and timing-safe 48-hex capability token on `/devtools/browser/<token>`.
 */
import { randomBytes, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import type { CdpHub } from "./cdp-hub.ts";
import { acceptUpgrade, rejectUpgrade } from "./ws.ts";

const MAX_MESSAGE_BYTES = 16 * 1024 * 1024;
const MAX_CLIENTS = 8;

export function isAllowedLoopbackCdpRequest(
  headers: IncomingMessage["headers"],
  boundPort: number,
): boolean {
  if (headers.origin !== undefined) {
    return false;
  }
  const host = headers.host?.toLowerCase();
  return host === `127.0.0.1:${boundPort}`;
}

export class CdpEndpoint {
  readonly #server: Server;
  readonly #hub: CdpHub;
  readonly #token: string;
  #port = 0;
  #clients = 0;

  private constructor(hub: CdpHub) {
    this.#hub = hub;
    this.#token = randomBytes(24).toString("hex");
    this.#server = createServer((req, res) => this.#onRequest(req, res));
    this.#server.on("upgrade", (req, socket, head) => {
      socket.on("error", () => socket.destroy());
      if (!this.#allowed(req) || !this.#isSocketPath(req.url ?? "")) {
        rejectUpgrade(socket, 403, "Forbidden");
        return;
      }
      if (this.#clients >= MAX_CLIENTS) {
        rejectUpgrade(socket, 503, "Service Unavailable");
        return;
      }
      const ws = acceptUpgrade(req, socket, { maxMessageBytes: MAX_MESSAGE_BYTES });
      if (!ws) return;
      this.#clients += 1;
      const connId = this.#hub.connect(ws);
      let released = false;
      const release = () => {
        if (released) return;
        released = true;
        this.#clients -= 1;
        this.#hub.disconnect(connId);
      };
      ws.onMessage((text) => this.#hub.message(connId, text));
      ws.onClose(release);
      // Belt and braces: whatever way the socket goes away, the client slot is returned.
      socket.once("close", release);
      // Only now consume bytes pipelined with the handshake, so they reach the listeners above.
      ws.feed(head);
    });
  }

  static async start(hub: CdpHub): Promise<CdpEndpoint> {
    const endpoint = new CdpEndpoint(hub);
    const { promise, resolve, reject } = Promise.withResolvers<void>();
    endpoint.#server.once("error", reject);
    endpoint.#server.listen(0, "127.0.0.1", () => {
      endpoint.#server.off("error", reject);
      resolve();
    });
    await promise;
    endpoint.#port = (endpoint.#server.address() as AddressInfo).port;
    return endpoint;
  }

  /** Connected CDP clients currently holding a slot (max {@link MAX_CLIENTS}). */
  get clientCount(): number {
    return this.#clients;
  }

  get port(): number {
    return this.#port;
  }

  get httpUrl(): string {
    return `http://127.0.0.1:${this.#port}`;
  }

  get wsUrl(): string {
    return `ws://127.0.0.1:${this.#port}/devtools/browser/${this.#token}`;
  }

  async close(): Promise<void> {
    this.#hub.closeAll();
    const { promise, resolve } = Promise.withResolvers<void>();
    this.#server.close(() => resolve());
    this.#server.closeAllConnections();
    await promise;
  }

  #allowed(req: IncomingMessage): boolean {
    return isAllowedLoopbackCdpRequest(req.headers, this.#port);
  }

  #isSocketPath(url: string): boolean {
    const prefix = "/devtools/browser/";
    if (!url.startsWith(prefix)) return false;
    const given = Buffer.from(url.slice(prefix.length));
    const expected = Buffer.from(this.#token);
    return given.length === expected.length && timingSafeEqual(given, expected);
  }

  #onRequest(req: IncomingMessage, res: ServerResponse): void {
    if (!this.#allowed(req)) {
      res.writeHead(403).end();
      return;
    }
    if (req.method !== "GET") {
      res.writeHead(405, { Allow: "GET" }).end();
      return;
    }
    const path = (req.url ?? "/").split("?")[0];
    let body: unknown;
    if (path === "/json/version") {
      body = this.#hub.versionInfo(this.wsUrl);
    } else if (path === "/json" || path === "/json/list") {
      body = this.#hub.listTargets();
    } else {
      res.writeHead(404).end();
      return;
    }
    const json = JSON.stringify(body);
    res.writeHead(200, {
      "Content-Type": "application/json; charset=UTF-8",
      "Content-Length": Buffer.byteLength(json),
      "Cache-Control": "no-store",
    });
    res.end(json);
  }
}
