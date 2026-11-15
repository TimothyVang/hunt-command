import { describe, expect, test } from "bun:test";
import {
  buildWatchProxyConfig,
  createWatchScope,
  decideWatchRequest,
  documentAllowed,
  parsePinnedLoopbackOrigin,
  sanitizeWatchRequestHeaders,
} from "../src/main/watch/browser-policy.ts";
import { deniedSessionCommand, isOpenableWatchUrl } from "../src/main/watch/cdp-filter.ts";
import { CdpHub, type HubPage } from "../src/main/watch/cdp-hub.ts";
import { isAllowedLoopbackCdpRequest } from "../src/main/watch/cdp-server.ts";

const TEST_SCOPE = createWatchScope({
  caseId: "northvale-lab-001",
  labOrigin: "http://127.0.0.1:18400",
  arkimeOrigin: "http://127.0.0.1:18401",
  kibanaOrigin: "http://127.0.0.1:15601",
  startSec: 1_763_128_800,
  stopSec: 1_763_132_400,
  labSecret: "lab-internal-capability-9912",
});

describe("Hardened Watch Browser request policy, proxy blackhole & CDP filter (#178 G1.3, #189)", () => {
  test("rejects localhost, 0.0.0.0, IPv6, credentials, and external hosts at origin level", () => {
    expect(parsePinnedLoopbackOrigin("http://127.0.0.1:18400/status")).toBe(
      "http://127.0.0.1:18400",
    );
    expect(parsePinnedLoopbackOrigin("http://localhost:18400/status")).toBeNull();
    expect(parsePinnedLoopbackOrigin("http://0.0.0.0:18400/status")).toBeNull();
    expect(parsePinnedLoopbackOrigin("http://[::1]:18400/status")).toBeNull();
    expect(parsePinnedLoopbackOrigin("http://admin:pass@127.0.0.1:18400/")).toBeNull();
    expect(parsePinnedLoopbackOrigin("https://evil.example.com/")).toBeNull();

    expect(() =>
      createWatchScope({
        caseId: "c1",
        labOrigin: "http://localhost:8005",
        arkimeOrigin: "http://127.0.0.1:8006",
        startSec: 100,
        stopSec: 200,
      }),
    ).toThrow(/127\.0\.0\.1/);
  });

  test("buildWatchProxyConfig routes all non-pinned ports and <-loopback> to dead 127.0.0.1:1", () => {
    const proxy = buildWatchProxyConfig(TEST_SCOPE);
    expect(proxy.proxyRules).toBe("http://127.0.0.1:1");
    expect(proxy.proxyBypassRules).toBe(
      "<-loopback>;127.0.0.1:18400;127.0.0.1:18401;127.0.0.1:15601",
    );

    // Chromium (net/base/scheme_host_port_matcher.cc) evaluates bypass rules in REVERSE order and the
    // first hit wins, so later rules override earlier ones; with no hit, loopback is implicitly bypassed.
    // `<-loopback>` answers "do not bypass" for loopback hosts.
    const routes = (bypassRules: string, url: string): "DIRECT" | "PROXY" => {
      const u = new URL(url);
      const port = u.port || (u.protocol === "https:" ? "443" : "80");
      const loopback = u.hostname === "127.0.0.1" || u.hostname === "localhost" || u.hostname === "[::1]";
      for (const rule of bypassRules.split(";").reverse()) {
        if (rule === "<-loopback>") {
          if (loopback) return "PROXY";
        } else if (rule === `${u.hostname}:${port}`) {
          return "DIRECT";
        }
      }
      return loopback ? "DIRECT" : "PROXY";
    };
    const rules = proxy.proxyBypassRules;
    expect(routes(rules, "http://127.0.0.1:18400/")).toBe("DIRECT");
    expect(routes(rules, "http://127.0.0.1:18401/api/sessions")).toBe("DIRECT");
    expect(routes(rules, "http://127.0.0.1:15601/app/discover")).toBe("DIRECT");
    expect(routes(rules, "http://127.0.0.1:18402/")).toBe("PROXY");
    expect(routes(rules, "http://localhost:18400/")).toBe("PROXY");
    expect(routes(rules, "https://example.invalid/")).toBe("PROXY");
  });

  test("documentAllowed permits only lab, Arkime, about:blank, and Kibana /app/discover", () => {
    expect(documentAllowed(TEST_SCOPE, "about:blank")).toBe(true);
    expect(documentAllowed(TEST_SCOPE, "http://127.0.0.1:18400/board")).toBe(true);
    expect(documentAllowed(TEST_SCOPE, "http://127.0.0.1:18401/sessions")).toBe(true);
    expect(documentAllowed(TEST_SCOPE, "http://127.0.0.1:15601/app/discover")).toBe(true);
    expect(documentAllowed(TEST_SCOPE, "http://127.0.0.1:15601/app/dev_tools")).toBe(false);
    expect(documentAllowed(TEST_SCOPE, "http://localhost:18400/board")).toBe(false);
    expect(isOpenableWatchUrl(TEST_SCOPE, "https://google.com")).toBe(false);
  });

  test("decideWatchRequest scopes Arkime queries to case tag & window and blocks admin/pcap/delete routes", () => {
    const allowedSearch = decideWatchRequest(
      TEST_SCOPE,
      "GET",
      "http://127.0.0.1:18401/api/sessions?expression=ip.dst%20%3D%3D%20198.51.100.42&date=-1",
    );
    expect(allowedSearch.block).toBeUndefined();
    expect(allowedSearch.expression).toBe(
      '(ip.dst == 198.51.100.42) && tags == "case:northvale-lab-001"',
    );
    expect(allowedSearch.url).toContain(`startTime=${TEST_SCOPE.startSec}`);
    expect(allowedSearch.url).toContain(`stopTime=${TEST_SCOPE.stopSec}`);
    expect(allowedSearch.url).not.toContain("date=-1");

    // Breakout attempt via unbalanced parenthesis must fail
    const breakout = decideWatchRequest(
      TEST_SCOPE,
      "GET",
      "http://127.0.0.1:18401/api/sessions?expression=ip.dst%20%3D%3D%201.2.3.4)%20%7C%7C%20(",
    );
    expect(breakout.block).toBe("arkime_expression_rejected");

    // Denied Arkime routes (/pcap, /delete, /users, /cyberchef)
    expect(
      decideWatchRequest(TEST_SCOPE, "GET", "http://127.0.0.1:18401/api/sessions.pcap").block,
    ).toBe("arkime_route_denied");
    expect(
      decideWatchRequest(TEST_SCOPE, "POST", "http://127.0.0.1:18401/api/delete").block,
    ).toBe("arkime_route_denied");
  });

  test("decideWatchRequest pins Kibana /internal/bsearch to hunt-lab-case-events and case @timestamp window", () => {
    const validBatch = JSON.stringify({
      batch: [
        {
          options: { strategy: "ese" },
          request: {
            params: {
              index: "hunt-lab-case-events",
              body: {
                size: 50,
                query: { match: { "host.name": "wks-fin-07" } },
              },
            },
          },
        },
      ],
    });

    const verdict = decideWatchRequest(
      TEST_SCOPE,
      "POST",
      "http://127.0.0.1:15601/internal/bsearch",
      validBatch,
    );
    expect(verdict.block).toBeUndefined();
    const rewritten = JSON.parse(verdict.body ?? "{}") as {
      batch: Array<{ request: { params: { body: { query: { bool: { filter: unknown[] } } } } } }>;
    };
    expect(rewritten.batch[0]?.request.params.body.query.bool.filter[0]).toEqual({
      range: {
        "@timestamp": {
          gte: TEST_SCOPE.startSec * 1000,
          lt: TEST_SCOPE.stopSec * 1000,
          format: "epoch_millis",
        },
      },
    });

    // Wrong index or ES|QL strategy must be refused
    const wrongIndex = validBatch.replace("hunt-lab-case-events", ".kibana*");
    expect(
      decideWatchRequest(TEST_SCOPE, "POST", "http://127.0.0.1:15601/internal/bsearch", wrongIndex)
        .block,
    ).toBe("kibana_index_denied");

    const esqlAttempt = validBatch.replace('"ese"', '"esql"');
    expect(
      decideWatchRequest(TEST_SCOPE, "POST", "http://127.0.0.1:15601/internal/bsearch", esqlAttempt)
        .block,
    ).toBe("kibana_search_denied");
  });

  test("sanitizeWatchRequestHeaders injects X-Hunt-Lab-Secret ONLY on labOrigin and strips spoofed headers", () => {
    const spoofed = [
      { name: "Accept", value: "application/json" },
      { name: "x-hunt-lab-secret", value: "attacker-spoof" },
    ];

    const onLab = sanitizeWatchRequestHeaders(
      TEST_SCOPE,
      "http://127.0.0.1:18400/api/activity",
      spoofed,
    );
    expect(onLab).toEqual([
      { name: "Accept", value: "application/json" },
      { name: "X-Hunt-Lab-Secret", value: "lab-internal-capability-9912" },
    ]);

    const onArkime = sanitizeWatchRequestHeaders(
      TEST_SCOPE,
      "http://127.0.0.1:18401/api/sessions",
      spoofed,
    );
    expect(onArkime).toEqual([{ name: "Accept", value: "application/json" }]);

    const onKibana = sanitizeWatchRequestHeaders(
      TEST_SCOPE,
      "http://127.0.0.1:15601/app/discover",
      spoofed,
    );
    expect(onKibana).toEqual([{ name: "Accept", value: "application/json" }]);
  });

  test("cdp-filter blocks Fetch.*, mutating Network.*, ServiceWorker.*, and Storage.*, and cdp-server rejects localhost", () => {
    expect(deniedSessionCommand("Fetch.disable", undefined)).toMatch(/denied/);
    expect(deniedSessionCommand("Fetch.enable", undefined)).toMatch(/denied/);
    expect(deniedSessionCommand("Network.setExtraHTTPHeaders", { headers: {} })).toMatch(/denied/);
    expect(deniedSessionCommand("Network.setCookies", { cookies: [] })).toMatch(/denied/);
    expect(deniedSessionCommand("Network.setBypassServiceWorker", { bypass: true })).toMatch(
      /denied/,
    );
    expect(deniedSessionCommand("ServiceWorker.enable", undefined)).toMatch(/denied/);
    expect(deniedSessionCommand("Storage.getCookies", undefined)).toMatch(/denied/);
    expect(deniedSessionCommand("IndexedDB.requestData", undefined)).toMatch(/denied/);
    expect(deniedSessionCommand("Page.setDownloadBehavior", undefined)).toMatch(/denied/);
    expect(deniedSessionCommand("Page.navigate", { browserContextId: "ctx-1" })).toMatch(/denied/);

    // Read-only inspection commands remain allowed
    expect(deniedSessionCommand("Network.enable", undefined)).toBeNull();
    expect(deniedSessionCommand("Page.captureScreenshot", undefined)).toBeNull();
    expect(deniedSessionCommand("Runtime.evaluate", { expression: "document.title" })).toBeNull();

    // CdpEndpoint Host header check: 127.0.0.1:<port> ONLY, no localhost, no Origin
    expect(isAllowedLoopbackCdpRequest({ host: "127.0.0.1:49210" }, 49210)).toBe(true);
    expect(isAllowedLoopbackCdpRequest({ host: "localhost:49210" }, 49210)).toBe(false);
    expect(
      isAllowedLoopbackCdpRequest(
        { host: "127.0.0.1:49210", origin: "http://127.0.0.1:18400" },
        49210,
      ),
    ).toBe(false);
  });

  test("CDP navigation fence: Page.navigate is scope-checked; history/document/PDF/IO/file-input are denied", () => {
    const openable = (url: string) => isOpenableWatchUrl(TEST_SCOPE, url);
    const hostile = [
      "file:///C:/x",
      "data:text/html,<script>alert(1)</script>",
      "chrome://settings",
      "//evil.example.com/x",
      "http://127.0.0.1:9999/",
      "http://evil.example.com/",
      "http://localhost:18400/board",
      "javascript:alert(1)",
    ];
    for (const url of hostile) {
      expect(deniedSessionCommand("Page.navigate", { url }, openable)).toMatch(/outside/);
    }
    expect(deniedSessionCommand("Page.navigate", {}, openable)).toMatch(/outside/);
    expect(deniedSessionCommand("Page.navigate", { url: 42 }, openable)).toMatch(/outside/);
    // Without a scope check the fence fails closed.
    expect(deniedSessionCommand("Page.navigate", { url: "http://127.0.0.1:18400/board" })).toMatch(
      /outside/,
    );
    expect(
      deniedSessionCommand("Page.navigate", { url: "http://127.0.0.1:18400/board" }, openable),
    ).toBeNull();
    expect(deniedSessionCommand("Page.navigate", { url: "about:blank" }, openable)).toBeNull();

    for (const method of [
      "Page.navigateToHistoryEntry",
      "Page.setDocumentContent",
      "Page.printToPDF",
      "IO.read",
      "IO.resolveBlob",
      "DOM.setFileInputFiles",
    ]) {
      expect(deniedSessionCommand(method, { entryId: 1, html: "x", handle: "h" }, openable)).toMatch(
        /denied/,
      );
    }
    expect(deniedSessionCommand("Page.reload", undefined, openable)).toBeNull();
  });

  test("CdpHub threads the session scope into Page.navigate on attached page sessions", async () => {
    const forwarded: { method: string; params: unknown }[] = [];
    const page: HubPage = {
      id: 1,
      url: () => "about:blank",
      title: () => "",
      attach: () => {},
      detach: () => {},
      send: async (method, params) => {
        forwarded.push({ method, params });
        return {};
      },
    };
    const hub = new CdpHub({
      pages: () => [page],
      createPage: async () => page,
      closePage: async () => {},
      activatePage: () => {},
      isOpenableUrl: (url) => isOpenableWatchUrl(TEST_SCOPE, url),
      version: () => ({ product: "test", userAgent: "test" }),
    });
    const replies = new Map<number, Record<string, unknown>>();
    const conn = hub.connect({
      send: (text) => {
        const msg = JSON.parse(text) as Record<string, unknown>;
        if (typeof msg.id === "number") replies.set(msg.id, msg);
      },
      close: () => {},
    });
    const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

    hub.message(conn, JSON.stringify({ id: 1, method: "Target.attachToTarget", params: { targetId: "PAGE1", flatten: true } }));
    await flush();
    const sessionId = (replies.get(1)?.result as { sessionId: string }).sessionId;
    expect(typeof sessionId).toBe("string");

    const urls = [
      "file:///C:/x",
      "data:text/html,<h1>x</h1>",
      "chrome://settings",
      "//evil.example.com/x",
      "http://evil.example.com/",
    ];
    urls.forEach((url, i) => {
      hub.message(conn, JSON.stringify({ id: 10 + i, sessionId, method: "Page.navigate", params: { url } }));
    });
    hub.message(conn, JSON.stringify({ id: 20, sessionId, method: "Page.navigate", params: { url: "http://127.0.0.1:18400/board" } }));
    await flush();

    urls.forEach((_url, i) => {
      expect(replies.get(10 + i)?.error).toBeDefined();
    });
    expect(replies.get(20)?.error).toBeUndefined();
    const navigations = forwarded.filter((f) => f.method === "Page.navigate");
    expect(navigations).toEqual([{ method: "Page.navigate", params: { url: "http://127.0.0.1:18400/board" } }]);
    hub.closeAll();
  });
});
