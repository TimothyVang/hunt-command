import { afterAll, describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import https from "node:https";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import {
  ConnectConfigError,
  ConnectedHuntDataPlane,
  type ConnectedCaseDefinition,
  type ConnectedElasticConfig,
  type ConnectedHttpsTransport,
  createVerifiedHttpsTransport,
  createRoleCapabilityMint,
  extractDataPlaneError,
  formatConnectedCitation,
  NEWER_CLUSTER_PRIVILEGES,
  NEWER_INDEX_PRIVILEGES,
  refuseConnectedRegex,
  scanApiKeyInBotProfiles,
  WRITE_CLUSTER_ACTIONS,
  WRITE_CLUSTER_PRIVILEGES,
  WRITE_INDEX_ACTIONS,
  WRITE_INDEX_PRIVILEGES,
} from "../src/index.ts";

const tempDirs: string[] = [];

function makeTempDir(prefix: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

afterAll(() => {
  for (const dir of tempDirs) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

const FIXED_NOW_MS = Date.parse("2026-11-15T02:00:00Z");
const TEST_API_KEY = "VnVhQ2p5c0JDZk03dG5XOXpMMkE6dGVzdC1yZWFkLW9ubHktZXMta2V5";

function makeValidConfig(overrides: Partial<ConnectedElasticConfig> = {}): ConnectedElasticConfig {
  return {
    url: "https://siem-es.corp.internal:9200",
    index: "logs-win-*,logs-edr-*",
    api_key_env: "HUNT_ELASTIC_API_KEY",
    ...overrides,
  };
}

function makeValidCase(overrides: Partial<ConnectedCaseDefinition> = {}): ConnectedCaseDefinition {
  return {
    case_id: "conn-case-001",
    question: "Investigate suspicious lateral movement across workstation endpoints.",
    schema_version: 1,
    sources: [
      {
        artifact: "windows_security_events",
        coverage: " Endpoint process creation and logon telemetry across scope hosts ",
      },
    ],
    time_range_utc: {
      start_inclusive: "2026-11-14T12:00:00Z",
      end_exclusive: "2026-11-15T01:30:00Z", // 30 minutes before FIXED_NOW_MS (>= 15m settle lag)
    },
    data_origin: "work-connected",
    network_capture: "none",
    hosts: ["wkstn-01", "wkstn-02"],
    ...overrides,
  };
}

interface MockClusterCall {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: Record<string, unknown> | null;
}

interface MockClusterOptions {
  distribution?: string;
  versionNumber?: string;
  tagline?: string;
  apiKeyId?: string | null;
  roleDescriptors?: Record<string, unknown>;
  resolvedConcreteIndices?: string[];
  failReadPrivilege?: boolean;
  grantWritePrivilege?: { target: "cluster" | "index"; priv: string; indexName?: string };
  supportedNewerCluster?: ReadonlySet<string>;
  supportedNewerIndex?: ReadonlySet<string>;
  onSearch?: (
    body: Record<string, unknown>,
    callIndex: number,
  ) => { status: number; response: Record<string, unknown> };
}

function createMockEsTransport(opts: MockClusterOptions = {}): {
  transport: ConnectedHttpsTransport;
  calls: MockClusterCall[];
  openedPits: string[];
  deletedPits: string[];
} {
  const calls: MockClusterCall[] = [];
  const openedPits: string[] = [];
  const deletedPits: string[] = [];
  let pitCounter = 0;
  let searchCallIndex = 0;

  const concreteIndices = opts.resolvedConcreteIndices ?? [
    "logs-win-2026.11.01",
    "logs-win-2026.11.02",
  ];
  const supportedNewerCluster =
    opts.supportedNewerCluster ?? new Set<string>(["manage_esql", "manage_connector"]);
  const supportedNewerIndex =
    opts.supportedNewerIndex ?? new Set<string>(["manage_data_stream_lifecycle"]);

  const jsonReply = (status: number, obj: Record<string, unknown>) => ({
    status,
    payload: Buffer.from(JSON.stringify(obj), "utf8"),
  });

  const transport: ConnectedHttpsTransport = async (method, url, headers, bodyBytes) => {
    const parsedUrl = new URL(url);
    const route = `${parsedUrl.pathname}${parsedUrl.search}`;
    const body =
      bodyBytes !== null
        ? (JSON.parse(Buffer.from(bodyBytes).toString("utf8")) as Record<string, unknown>)
        : null;
    calls.push({ method, url, headers, body });

    if (method === "GET" && route === "/") {
      const versionObj: Record<string, unknown> = {
        number: opts.versionNumber ?? "8.15.2",
      };
      if (opts.distribution !== undefined) {
        versionObj.distribution = opts.distribution;
      }
      return jsonReply(200, {
        name: "es-node-1",
        cluster_name: "prod-siem",
        version: versionObj,
        tagline: opts.tagline ?? "You Know, for Search",
      });
    }

    if (method === "GET" && route === "/_security/_authenticate") {
      if (opts.apiKeyId === null) {
        return jsonReply(200, { username: "elastic", roles: ["superuser"] });
      }
      return jsonReply(200, {
        username: "hunt-reader",
        api_key: { id: opts.apiKeyId ?? "key-id-123", name: "hunt-ro" },
      });
    }

    if (method === "GET" && route.startsWith("/_security/api_key?id=")) {
      const descriptors =
        opts.roleDescriptors ??
        ({
          hunt_reader: {
            cluster: ["monitor"],
            indices: [
              {
                names: ["logs-win-*", "logs-edr-*"],
                privileges: ["read", "view_index_metadata"],
                allow_restricted_indices: false,
              },
            ],
          },
        } satisfies Record<string, unknown>);
      return jsonReply(200, {
        api_keys: [
          {
            id: opts.apiKeyId ?? "key-id-123",
            name: "hunt-ro",
            role_descriptors: descriptors,
          },
        ],
      });
    }

    if (method === "GET" && route.startsWith("/_resolve/index/")) {
      return jsonReply(200, {
        indices: concreteIndices.map((name) => ({ name })),
        aliases: [{ name: "logs-edr-alias", indices: [concreteIndices[0] ?? "logs-edr-0001"] }],
        data_streams: [
          {
            name: "logs-win-default",
            backing_indices: [".ds-logs-win-default-2026.11.14-000001"],
          },
        ],
      });
    }

    if (method === "POST" && route === "/_security/user/_has_privileges") {
      const reqBody = body ?? {};
      const clusterReq = Array.isArray(reqBody.cluster) ? (reqBody.cluster as string[]) : [];
      const indexReq = Array.isArray(reqBody.index)
        ? (reqBody.index as Array<{ names: string[]; privileges: string[] }>)
        : [];

      // Single-privilege probe for NEWER_* privileges
      if (clusterReq.length === 1 && indexReq.length === 0) {
        const probePriv = clusterReq[0]!;
        if (
          (NEWER_CLUSTER_PRIVILEGES as readonly string[]).includes(probePriv) &&
          !supportedNewerCluster.has(probePriv)
        ) {
          return jsonReply(400, {
            error: { type: "illegal_argument_exception", reason: `unknown privilege ${probePriv}` },
          });
        }
      }
      if (
        clusterReq.length === 0 &&
        indexReq.length === 1 &&
        indexReq[0]!.privileges.length === 1
      ) {
        const probePriv = indexReq[0]!.privileges[0]!;
        if (
          (NEWER_INDEX_PRIVILEGES as readonly string[]).includes(probePriv) &&
          !supportedNewerIndex.has(probePriv)
        ) {
          return jsonReply(400, {
            error: { type: "illegal_argument_exception", reason: `unknown privilege ${probePriv}` },
          });
        }
      }

      const clusterResp: Record<string, boolean> = {};
      for (const cPriv of clusterReq) {
        clusterResp[cPriv] =
          opts.grantWritePrivilege?.target === "cluster" &&
          opts.grantWritePrivilege.priv === cPriv;
      }

      const indexResp: Record<string, Record<string, boolean>> = {};
      for (const entry of indexReq) {
        for (const idxName of entry.names) {
          const map: Record<string, boolean> = {};
          for (const iPriv of entry.privileges) {
            if (iPriv === "read") {
              map[iPriv] = !opts.failReadPrivilege;
            } else {
              const shouldGrant =
                opts.grantWritePrivilege?.target === "index" &&
                opts.grantWritePrivilege.priv === iPriv &&
                (opts.grantWritePrivilege.indexName === undefined ||
                  opts.grantWritePrivilege.indexName === idxName);
              map[iPriv] = shouldGrant;
            }
          }
          indexResp[idxName] = map;
        }
      }

      return jsonReply(200, {
        username: "hunt-reader",
        has_all_requested: false,
        cluster: clusterResp,
        index: indexResp,
      });
    }

    if (method === "GET" && route.includes("/_field_caps?")) {
      return jsonReply(200, {
        fields: {
          "@timestamp": { date_nanos: { searchable: true, aggregatable: true } },
          "host.name": { keyword: { searchable: true, aggregatable: true } },
          "process.name": { keyword: { searchable: true, aggregatable: true } },
          "process.command_line": {
            text: { searchable: true, aggregatable: false },
          },
          "event.id": { keyword: { searchable: true, aggregatable: true } },
          "event.id.custom_sub": { keyword: { searchable: true, aggregatable: true } },
        },
      });
    }

    if (method === "POST" && route.includes("/_pit?keep_alive=30m")) {
      pitCounter += 1;
      const pitId = `pit-gen-${pitCounter}`;
      openedPits.push(pitId);
      return jsonReply(200, { id: pitId });
    }

    if (method === "DELETE" && route === "/_pit") {
      if (typeof body?.id === "string") {
        deletedPits.push(body.id);
      }
      return jsonReply(200, { succeeded: true, num_freed: 1 });
    }

    if (method === "POST" && route === "/_search?allow_partial_search_results=false") {
      searchCallIndex += 1;
      if (opts.onSearch) {
        const res = opts.onSearch(body ?? {}, searchCallIndex);
        return jsonReply(res.status, res.response);
      }
      return jsonReply(200, {
        pit_id: (body?.pit as { id?: string } | undefined)?.id ?? "pit-gen-1",
        timed_out: false,
        _shards: { total: 5, successful: 5, skipped: 0, failed: 0 },
        hits: {
          total: { value: 2, relation: "eq" },
          hits: [
            {
              _index: "logs-win-2026.11.01",
              _id: "shared-doc-42",
              sort: ["2026-11-14T14:00:00.123456789Z", 10],
              _source: {
                "@timestamp": "2026-11-14T14:00:00.123456789Z",
                "event.id": "cluster-internal-id-must-be-stripped",
                host: { name: "wkstn-01" },
                process: { name: "powershell.exe", command_line: "powershell -enc AAA" },
                event: { category: "process", code: "4688" },
              },
            },
            {
              _index: "logs-win-2026.11.02",
              _id: "shared-doc-42",
              sort: ["2026-11-14T14:00:01.000000000Z", 11],
              _source: {
                "@timestamp": "2026-11-14T14:00:01.000000000Z",
                host: { name: "wkstn-02" },
                process: { name: "cmd.exe", command_line: "cmd.exe /c whoami" },
                event: { id: "raw-nested-id-must-be-overwritten", category: "process", code: "4688" },
              },
            },
          ],
        },
        aggregations: {
          values: {
            sum_other_doc_count: 3,
            buckets: [
              {
                key: "wkstn-01",
                doc_count: 7,
                sample: {
                  hits: {
                    hits: [{ _index: "logs-win-2026.11.01", _id: "shared-doc-42" }],
                  },
                },
              },
            ],
          },
          hosts: {
            buckets: [{ key: "wkstn-01", doc_count: 2 }],
          },
          first: { value: 1731586000000, value_as_string: "2026-11-14T14:00:00.123Z" },
          last: { value: 1731586001000, value_as_string: "2026-11-14T14:00:01.000Z" },
        },
      });
    }

    return jsonReply(404, { error: { type: "not_found" } });
  };

  return { transport, calls, openedPits, deletedPits };
}

describe("@hunt-command/data-plane — ConnectedHuntDataPlane (ADR 0005 10-Invariant Enterprise Parity)", () => {
  test("validates URL/TLS/redirect invariants, rejects OpenSearch & ES < 7.12, and blocks stateDir inside Git", async () => {
    // 1. URL validation: http://, userinfo, query, fragment all rejected
    for (const badUrl of [
      "http://siem-es.corp.internal:9200",
      "https://elastic:secret@siem-es.corp.internal:9200",
      "https://siem-es.corp.internal:9200?pretty=true",
      "https://siem-es.corp.internal:9200#frag",
    ]) {
      await expect(
        ConnectedHuntDataPlane.open({
          config: makeValidConfig({ url: badUrl }),
          caseDefinition: makeValidCase(),
          environ: { HUNT_ELASTIC_API_KEY: TEST_API_KEY },
          nowEpochMs: FIXED_NOW_MS,
        }),
      ).rejects.toThrow(ConnectConfigError);
    }

    // 2. Rejects OpenSearch (distribution or tagline) and Elasticsearch < 7.12
    for (const badCluster of [
      { distribution: "opensearch", versionNumber: "2.11.0" },
      { tagline: "The OpenSearch Project: https://opensearch.org/", versionNumber: "8.15.0" },
      { versionNumber: "7.10.2" },
    ]) {
      const { transport } = createMockEsTransport(badCluster);
      await expect(
        ConnectedHuntDataPlane.open({
          config: makeValidConfig(),
          caseDefinition: makeValidCase(),
          environ: { HUNT_ELASTIC_API_KEY: TEST_API_KEY },
          transport,
          nowEpochMs: FIXED_NOW_MS,
        }),
      ).rejects.toThrow(ConnectConfigError);
    }

    // 3. Rejects stateDir inside a Git repository
    const fakeGitDir = makeTempDir("hunt-conn-git-");
    fs.mkdirSync(path.join(fakeGitDir, ".git"), { recursive: true });
    const { transport: okTransport } = createMockEsTransport();
    await expect(
      ConnectedHuntDataPlane.open({
        config: makeValidConfig(),
        caseDefinition: makeValidCase(),
        environ: { HUNT_ELASTIC_API_KEY: TEST_API_KEY },
        stateDir: path.join(fakeGitDir, "nested", "state"),
        transport: okTransport,
        nowEpochMs: FIXED_NOW_MS,
      }),
    ).rejects.toThrow(/Git checkout/);

    // 4. Verified node:https transport with custom CA, zero redirects, and proxy immunity
    const certDir = makeTempDir("hunt-conn-tls-");
    const certPath = path.join(certDir, "cert.pem");
    const keyPath = path.join(certDir, "key.pem");
    const opensslCheck = spawnSync(
      "openssl",
      [
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        keyPath,
        "-out",
        certPath,
        "-days",
        "1",
        "-subj",
        "/CN=127.0.0.1",
        "-addext",
        "subjectAltName=IP:127.0.0.1",
      ],
      { windowsHide: true },
    );

    if (opensslCheck.status === 0 && fs.existsSync(certPath)) {
      let respondWithRedirect = false;
      const tlsServer = https.createServer(
        {
          key: fs.readFileSync(keyPath),
          cert: fs.readFileSync(certPath),
        },
        (_req, res) => {
          if (respondWithRedirect) {
            res.writeHead(302, { Location: "https://127.0.0.1:1/evil" });
            res.end();
            return;
          }
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ ok: true }));
        },
      );
      await new Promise<void>((resolve) => tlsServer.listen(0, "127.0.0.1", () => resolve()));
      const port = (tlsServer.address() as AddressInfo).port;

      const prevHttpsProxy = process.env.HTTPS_PROXY;
      const prevHttpProxy = process.env.HTTP_PROXY;
      process.env.HTTPS_PROXY = "http://127.0.0.1:1";
      process.env.HTTP_PROXY = "http://127.0.0.1:1";

      try {
        const verifiedSend = createVerifiedHttpsTransport(certPath, 5_000);
        const okResp = await verifiedSend("GET", `https://127.0.0.1:${port}/`, {}, null);
        expect(okResp.status).toBe(200);

        respondWithRedirect = true;
        await expect(
          verifiedSend("GET", `https://127.0.0.1:${port}/`, {}, null),
        ).rejects.toThrow(/redirect refused/i);
      } finally {
        if (prevHttpsProxy === undefined) delete process.env.HTTPS_PROXY;
        else process.env.HTTPS_PROXY = prevHttpsProxy;
        if (prevHttpProxy === undefined) delete process.env.HTTP_PROXY;
        else process.env.HTTP_PROXY = prevHttpProxy;
        await new Promise<void>((resolve) => tlsServer.close(() => resolve()));
      }
    }
  });

  test("fences state roots and case directories through Git markers and directory links before transport or writes", async () => {
    for (const marker of ["directory", "worktree"] as const) {
      const root = makeTempDir("hunt-conn-canonical-fence-");
      const checkout = path.join(root, "checkout");
      fs.mkdirSync(checkout);
      if (marker === "directory") {
        fs.mkdirSync(path.join(checkout, ".git"));
      } else {
        fs.writeFileSync(path.join(checkout, ".git"), "gitdir: ../git/worktrees/test\n");
      }

      const alias = path.join(root, "checkout-alias");
      const linkType = process.platform === "win32" ? "junction" : "dir";
      fs.symlinkSync(checkout, alias, linkType);
      const stateRoot = path.join(root, "external-state");
      fs.mkdirSync(stateRoot);
      const caseTarget = path.join(checkout, "case-state");
      fs.mkdirSync(caseTarget);
      const sentinel = path.join(caseTarget, "active_pit.json");
      const sentinelContent = '{"pit_id":"must-not-be-reaped"}\n';
      fs.writeFileSync(sentinel, sentinelContent);
      fs.symlinkSync(caseTarget, path.join(stateRoot, "conn-case-001"), linkType);

      for (const stateDir of [
        checkout,
        path.join(checkout, "missing", "state"),
        alias,
        path.join(alias, "missing", "state"),
        stateRoot,
      ]) {
        const before = fs.readdirSync(root, { recursive: true }).sort();
        const { transport, calls } = createMockEsTransport();
        await expect(
          ConnectedHuntDataPlane.open({
            config: makeValidConfig(),
            caseDefinition: makeValidCase(),
            environ: { HUNT_ELASTIC_API_KEY: TEST_API_KEY },
            stateDir,
            transport,
            nowEpochMs: FIXED_NOW_MS,
          }),
        ).rejects.toThrow(ConnectConfigError);
        expect(calls).toEqual([]);
        expect(fs.readdirSync(root, { recursive: true }).sort()).toEqual(before);
        expect(fs.readFileSync(sentinel, "utf8")).toBe(sentinelContent);
      }
    }
  });

  test("persists and reloads connected state through an external directory link with missing descendants", async () => {
    const root = makeTempDir("hunt-conn-external-state-");
    const external = path.join(root, "external");
    fs.mkdirSync(external);
    const alias = path.join(root, "external-alias");
    fs.symlinkSync(external, alias, process.platform === "win32" ? "junction" : "dir");
    const stateDir = path.join(alias, "missing", "state");
    const caseFolder = path.join(external, "missing", "state", "conn-case-001");
    const { transport } = createMockEsTransport();
    const options = {
      config: makeValidConfig(),
      caseDefinition: makeValidCase(),
      stateDir,
      transport,
      nowEpochMs: FIXED_NOW_MS,
    };
    const dp = await ConnectedHuntDataPlane.open({
      ...options,
      environ: { HUNT_ELASTIC_API_KEY: TEST_API_KEY },
    });
    let citation: string;
    try {
      expect(fs.existsSync(path.join(caseFolder, "active_pit.json"))).toBe(true);
      const result = await dp.elasticSearch({});
      citation = result.hits[0]!["event.id"] as string;
      expect(fs.readFileSync(path.join(caseFolder, "citations.jsonl"), "utf8")).toContain(citation);
    } finally {
      await dp.close();
    }
    expect(fs.existsSync(path.join(caseFolder, "active_pit.json"))).toBe(false);
    const reopened = await ConnectedHuntDataPlane.open({
      ...options,
      environ: { HUNT_ELASTIC_API_KEY: TEST_API_KEY },
    });
    try {
      expect(reopened.verifyCitations([citation!]).allValid).toBe(true);
    } finally {
      await reopened.close();
    }
  });

  test("binds persisted citations to canonical connection and nanosecond case scope, refusing legacy records", async () => {
    const stateDir = makeTempDir("hunt-conn-citation-scope-");
    const config = makeValidConfig();
    const caseDefinition = makeValidCase();
    const open = (nextConfig = config, nextCase = caseDefinition, apiKey = TEST_API_KEY) => {
      const mock = createMockEsTransport().transport;
      const prefix = new URL(nextConfig.url).pathname.replace(/\/+$/, "");
      return ConnectedHuntDataPlane.open({
        config: nextConfig,
        caseDefinition: nextCase,
        environ: { HUNT_ELASTIC_API_KEY: apiKey },
        stateDir,
        transport: (method, url, headers, body) => {
          const target = new URL(url);
          if (prefix) target.pathname = target.pathname.slice(prefix.length) || "/";
          return mock(method, target.toString(), headers, body);
        },
        nowEpochMs: FIXED_NOW_MS,
      });
    };
    const initial = await open();
    let citations: string[];
    try {
      citations = (await initial.elasticSearch({})).hits.map((hit) => String(hit["event.id"]));
    } finally {
      await initial.close();
    }
    const citationsPath = path.join(stateDir, caseDefinition.case_id, "citations.jsonl");
    const persisted = fs.readFileSync(citationsPath, "utf8");
    const records = persisted.trim().split(/\r?\n/).map((line) => JSON.parse(line));
    expect(records).toHaveLength(2);
    expect(records[0].scope_fingerprint).toMatch(/^[a-f0-9]{64}$/);
    expect(records[1].scope_fingerprint).toBe(records[0].scope_fingerprint);
    expect(persisted).not.toContain(TEST_API_KEY);
    const legacyCitation = formatConnectedCitation("logs-win-2026.11.01", "legacy-unbound");
    fs.appendFileSync(citationsPath, `${JSON.stringify({
      evt: legacyCitation, _index: "logs-win-2026.11.01", _id: "legacy-unbound",
    })}\n`);

    const equivalentCases = [
      caseDefinition,
      makeValidCase({
        hosts: ["wkstn-02", "wkstn-01", "wkstn-02"],
        time_range_utc: {
          start_inclusive: "2026-11-14T12:00:00.000000000Z",
          end_exclusive: "2026-11-15T01:30:00.000000000Z",
        },
      }),
    ];
    for (const equivalentCase of equivalentCases) {
      const reopened = await open(
        makeValidConfig({ url: "https://SIEM-ES.CORP.INTERNAL:9200/" }),
        equivalentCase,
        `${TEST_API_KEY}-rotated`,
      );
      try {
        expect(reopened.verifyCitations(citations!).allValid).toBe(true);
        for (const citation of citations!) {
          expect(reopened.resolveCitationsInLucene(`event.id:${citation}`)).toContain("_index:");
        }
        expect(reopened.verifyCitations([legacyCitation]).unresolved).toEqual([legacyCitation]);
        expect(() => reopened.resolveCitationsInLucene(`event.id:${legacyCitation}`))
          .toThrow(/Unknown citation/);
      } finally {
        await reopened.close();
      }
    }

    const changedScopes = [
      { config, caseDefinition: makeValidCase({
        time_range_utc: {
          ...caseDefinition.time_range_utc,
          start_inclusive: "2026-11-14T12:00:00.000000001Z",
        },
      }) },
      { config, caseDefinition: makeValidCase({
        time_range_utc: {
          ...caseDefinition.time_range_utc,
          end_exclusive: "2026-11-15T01:29:59.999999999Z",
        },
      }) },
      { config, caseDefinition: makeValidCase({ hosts: ["wkstn-01"] }) },
      { config: makeValidConfig({ url: "https://other-es.corp.internal:9200" }), caseDefinition },
      { config: makeValidConfig({ url: `${config.url}/other-cluster` }), caseDefinition },
      { config: makeValidConfig({ index: "logs-win-*" }), caseDefinition },
    ];
    for (const scope of changedScopes) {
      const reopened = await open(scope.config, scope.caseDefinition);
      try {
        expect(reopened.verifyCitations(citations!).unresolved).toEqual(citations!);
        for (const citation of citations!) {
          try {
            reopened.resolveCitationsInLucene(`event.id:${citation}`);
            throw new Error("Expected unknown_citation");
          } catch (error) {
            expect(extractDataPlaneError(error)?.errorCode).toBe("unknown_citation");
          }
        }
        // A fresh query may mint the same stable ID, but must persist its new scope binding.
        await reopened.elasticSearch({});
        const latest = fs.readFileSync(citationsPath, "utf8").trim().split(/\r?\n/).slice(-2)
          .map((line) => JSON.parse(line));
        expect(latest.every((record) => /^[a-f0-9]{64}$/.test(record.scope_fingerprint))).toBe(true);
        expect(latest[0].scope_fingerprint).not.toBe(records[0].scope_fingerprint);
        expect(latest[1].scope_fingerprint).toBe(latest[0].scope_fingerprint);
      } finally {
        await reopened.close();
      }
    }
  });

  test("preserves the fractional exclusive end for terms and histogram aggregations", async () => {
    const timeRange = {
      start_inclusive: "2026-11-14T12:00:00.122999999Z",
      end_exclusive: "2026-11-14T12:00:00.123000900Z",
    };
    const secondNs = BigInt(Date.parse("2026-11-14T12:00:00Z")) * 1_000_000n;
    const events = [
      { id: "before-start", ns: secondNs + 122_999_998n },
      { id: "at-start", ns: secondNs + 122_999_999n },
      { id: "after-millisecond-floor", ns: secondNs + 123_000_001n },
      { id: "at-end", ns: secondNs + 123_000_900n },
      { id: "after-end", ns: secondNs + 123_000_901n },
    ];
    const boundNs = (bound: string | number): bigint => {
      if (typeof bound === "number") return BigInt(bound) * 1_000_000n;
      const [second, fraction = ""] = bound.slice(0, -1).split(".");
      return BigInt(Date.parse(`${second}Z`)) * 1_000_000n + BigInt(fraction.padEnd(9, "0"));
    };
    const { transport } = createMockEsTransport({
      onSearch: (body) => {
        // This in-process request is generated by elasticAggregate; emulate ES date_nanos ranges.
        const query = body.query as {
          bool: { filter: Array<{ range?: Record<string, { gte: string | number; lt: string | number }> }> };
        };
        const inWindow = events.filter((event) => query.bool.filter.every((filter) => {
          const range = filter.range?.["@timestamp"];
          return !range || (event.ns >= boundNs(range.gte) && event.ns < boundNs(range.lt));
        }));
        const aggregations = body.aggs as {
          values: { date_histogram?: unknown };
        };
        const histogram = aggregations.values.date_histogram !== undefined;
        const groups = histogram
          ? [{ key: "2026-11-14T12:00:00Z", events: inWindow }]
          : inWindow.map((event) => ({ key: event.id, events: [event] }));
        return {
          status: 200,
          response: {
            timed_out: false,
            _shards: { total: 1, successful: 1, failed: 0 },
            hits: { total: { value: inWindow.length, relation: "eq" }, hits: [] },
            aggregations: {
              values: {
                buckets: groups.filter((group) => group.events.length > 0).map((group) => ({
                  key: group.key,
                  doc_count: group.events.length,
                  sample: {
                    hits: { hits: [{ _index: "logs-win-2026.11.01", _id: group.events[0]!.id }] },
                  },
                })),
              },
            },
          },
        };
      },
    });
    const dp = await ConnectedHuntDataPlane.open({
      config: makeValidConfig(),
      caseDefinition: makeValidCase({ time_range_utc: timeRange }),
      environ: { HUNT_ELASTIC_API_KEY: TEST_API_KEY },
      transport,
      nowEpochMs: FIXED_NOW_MS,
    });
    try {
      const terms = await dp.elasticAggregate({ field: "process.name" });
      expect(terms.total).toBe(2);
      expect(terms.buckets.map((bucket) => [bucket.key, bucket.count])).toEqual([
        ["at-start", 1],
        ["after-millisecond-floor", 1],
      ]);
      const histogram = await dp.elasticAggregate({ field: "@timestamp", interval: "1m" });
      expect(histogram.total).toBe(2);
      expect(histogram.buckets.map((bucket) => [bucket.key, bucket.count])).toEqual([
        ["2026-11-14T12:00:00Z", 2],
      ]);
    } finally {
      await dp.close();
    }
  });

  test("enforces 15-minute settle lag, cluster/index anonymization, env deletion, and 1MiB boundary profile scan", async () => {
    const { transport } = createMockEsTransport();

    // 1. 15m settle lag: window ending 10 minutes ago -> 400 window_not_closed
    try {
      await ConnectedHuntDataPlane.open({
        config: makeValidConfig(),
        caseDefinition: makeValidCase({
          time_range_utc: {
            start_inclusive: "2026-11-15T01:00:00Z",
            end_exclusive: "2026-11-15T01:50:00Z", // only 10m before 02:00:00Z
          },
        }),
        environ: { HUNT_ELASTIC_API_KEY: TEST_API_KEY },
        transport,
        nowEpochMs: FIXED_NOW_MS,
      });
      throw new Error("Expected window_not_closed");
    } catch (err) {
      const dpErr = extractDataPlaneError(err);
      expect(dpErr?.statusCode).toBe(400);
      expect(dpErr?.errorCode).toBe("window_not_closed");
    }

    // 2. Anonymization: naming cluster host or index pattern in question/sources rejected
    await expect(
      ConnectedHuntDataPlane.open({
        config: makeValidConfig(),
        caseDefinition: makeValidCase({
          question: "Check logs on siem-es.corp.internal for suspicious activity",
        }),
        environ: { HUNT_ELASTIC_API_KEY: TEST_API_KEY },
        transport,
        nowEpochMs: FIXED_NOW_MS,
      }),
    ).rejects.toThrow(/names the cluster host or the index pattern/);

    await expect(
      ConnectedHuntDataPlane.open({
        config: makeValidConfig(),
        caseDefinition: makeValidCase({
          sources: [{ artifact: "win", coverage: "Indexed inside logs-win-* indices" }],
        }),
        environ: { HUNT_ELASTIC_API_KEY: TEST_API_KEY },
        transport,
        nowEpochMs: FIXED_NOW_MS,
      }),
    ).rejects.toThrow(/names the cluster host or the index pattern/);

    // 3. Env key deletion happens immediately & missing key -> 403 leaked_api_key_in_env
    const emptyEnv: Record<string, string | undefined> = {};
    try {
      await ConnectedHuntDataPlane.open({
        config: makeValidConfig(),
        caseDefinition: makeValidCase(),
        environ: emptyEnv,
        transport,
        nowEpochMs: FIXED_NOW_MS,
      });
      throw new Error("Expected leaked_api_key_in_env");
    } catch (err) {
      expect(extractDataPlaneError(err)?.errorCode).toBe("leaked_api_key_in_env");
    }

    // 4. Bot profile scan catches API key straddling exact 1 MiB (1,048,576-byte) chunk boundary!
    const hermesHome = makeTempDir("hunt-conn-hermes-");
    const researcherProfile = path.join(hermesHome, "profiles", "researcher");
    fs.mkdirSync(researcherProfile, { recursive: true });
    const prefixLen = 1024 * 1024 - 12; // Straddles 1 MiB boundary!
    const straddlingContent = Buffer.concat([
      Buffer.alloc(prefixLen, 0x41),
      Buffer.from(`ELASTIC_SECRET=${TEST_API_KEY}\n`, "ascii"),
      Buffer.alloc(512, 0x42),
    ]);
    fs.writeFileSync(path.join(researcherProfile, ".env"), straddlingContent);
    expect(scanApiKeyInBotProfiles(hermesHome, TEST_API_KEY)).toBe(true);

    const liveEnv: Record<string, string | undefined> = { HUNT_ELASTIC_API_KEY: TEST_API_KEY };
    try {
      await ConnectedHuntDataPlane.open({
        config: makeValidConfig(),
        caseDefinition: makeValidCase(),
        environ: liveEnv,
        hermesHomeDir: hermesHome,
        transport,
        nowEpochMs: FIXED_NOW_MS,
      });
      throw new Error("Expected key_in_bot_profile");
    } catch (err) {
      const dpErr = extractDataPlaneError(err);
      expect(dpErr?.statusCode).toBe(403);
      expect(dpErr?.errorCode).toBe("key_in_bot_profile");
      // Even though open() failed, env var was deleted immediately!
      expect(liveEnv.HUNT_ELASTIC_API_KEY).toBeUndefined();
    }
  });

  test("enforces 2-layer read-only proof across all 140 base write checks + 16 newer probes & >200 batched concrete indices", async () => {
    // Verify exact connected.py privilege table counts: 14 + 25 + 40 + 61 = 140, 4 + 12 = 16
    expect(WRITE_INDEX_PRIVILEGES.length).toBe(14);
    expect(WRITE_CLUSTER_PRIVILEGES.length).toBe(25);
    expect(WRITE_INDEX_ACTIONS.length).toBe(40);
    expect(WRITE_CLUSTER_ACTIONS.length).toBe(61);
    expect(
      WRITE_INDEX_PRIVILEGES.length +
        WRITE_CLUSTER_PRIVILEGES.length +
        WRITE_INDEX_ACTIONS.length +
        WRITE_CLUSTER_ACTIONS.length,
    ).toBe(140);
    expect(NEWER_INDEX_PRIVILEGES.length + NEWER_CLUSTER_PRIVILEGES.length).toBe(16);

    // Layer 1 failures: non-API-key auth, empty role_descriptors, run_as, allow_restricted_indices: true, write descriptor
    const layer1InvalidCases: MockClusterOptions[] = [
      { apiKeyId: null },
      { roleDescriptors: {} },
      {
        roleDescriptors: {
          ro: {
            cluster: ["monitor"],
            run_as: ["admin"],
            indices: [{ names: ["logs-*"], privileges: ["read"] }],
          },
        },
      },
      {
        roleDescriptors: {
          ro: {
            cluster: ["monitor"],
            indices: [
              { names: ["logs-*"], privileges: ["read"], allow_restricted_indices: true },
            ],
          },
        },
      },
      {
        roleDescriptors: {
          ro: {
            cluster: ["monitor"],
            indices: [{ names: ["logs-*"], privileges: ["read", "write"] }],
          },
        },
      },
    ];

    for (const invalidOpt of layer1InvalidCases) {
      const { transport } = createMockEsTransport(invalidOpt);
      try {
        await ConnectedHuntDataPlane.open({
          config: makeValidConfig(),
          caseDefinition: makeValidCase(),
          environ: { HUNT_ELASTIC_API_KEY: TEST_API_KEY },
          transport,
          nowEpochMs: FIXED_NOW_MS,
        });
        throw new Error("Expected Layer 1 key_not_read_only");
      } catch (err) {
        const dpErr = extractDataPlaneError(err);
        expect(dpErr?.statusCode).toBe(403);
        expect(dpErr?.errorCode).toBe("key_not_read_only");
      }
    }

    // Layer 2 failure on batch #2 (210 concrete indices -> 2 batches of 200) when index #205 has delete privilege!
    const manyIndices = Array.from({ length: 210 }, (_, idx) => {
      const padded = String(idx + 1).padStart(4, "0");
      return `logs-win-rollover-${padded}`;
    });
    const { transport: leakyBatch2Transport } = createMockEsTransport({
      resolvedConcreteIndices: manyIndices,
      grantWritePrivilege: {
        target: "index",
        priv: "indices:data/write/delete",
        indexName: "logs-win-rollover-0205",
      },
    });

    try {
      await ConnectedHuntDataPlane.open({
        config: makeValidConfig(),
        caseDefinition: makeValidCase(),
        environ: { HUNT_ELASTIC_API_KEY: TEST_API_KEY },
        transport: leakyBatch2Transport,
        nowEpochMs: FIXED_NOW_MS,
      });
      throw new Error("Expected Layer 2 batch #2 key_not_read_only");
    } catch (err) {
      const dpErr = extractDataPlaneError(err);
      expect(dpErr?.statusCode).toBe(403);
      expect(dpErr?.errorCode).toBe("key_not_read_only");
    }

    // Layer 2 failure when a probed newer privilege (e.g., manage_esql) is granted
    const { transport: newerPrivLeakTransport } = createMockEsTransport({
      grantWritePrivilege: { target: "cluster", priv: "manage_esql" },
    });
    try {
      await ConnectedHuntDataPlane.open({
        config: makeValidConfig(),
        caseDefinition: makeValidCase(),
        environ: { HUNT_ELASTIC_API_KEY: TEST_API_KEY },
        transport: newerPrivLeakTransport,
        nowEpochMs: FIXED_NOW_MS,
      });
      throw new Error("Expected newer privilege key_not_read_only");
    } catch (err) {
      expect(extractDataPlaneError(err)?.errorCode).toBe("key_not_read_only");
    }
  });

  test("manages PIT lifecycle, crash-reaps stale active_pit.json, rotates PIT IDs, and fails closed on expired pagination cursor", async () => {
    const stateDir = makeTempDir("hunt-conn-pit-");
    const caseFolder = path.join(stateDir, "conn-case-001");
    fs.mkdirSync(caseFolder, { recursive: true });
    const activePitFile = path.join(caseFolder, "active_pit.json");

    // Seed a crashed session's leaked PIT
    fs.writeFileSync(
      activePitFile,
      JSON.stringify({
        url: "https://siem-es.corp.internal:9200",
        pit_id: "stale-crashed-pit-000",
        updated_at: "2026-11-15T01:00:00Z",
      }),
      "utf8",
    );

    let simulatePitLossNext = false;
    const { transport, deletedPits, openedPits, calls } = createMockEsTransport({
      onSearch: (body, callIdx) => {
        if (simulatePitLossNext) {
          simulatePitLossNext = false;
          return {
            status: 404,
            response: {
              error: { type: "search_phase_execution_exception" },
            },
          };
        }
        return {
          status: 200,
          response: {
            pit_id: callIdx === 1 ? "pit-gen-1-rotated" : ((body.pit as { id: string }).id),
            timed_out: false,
            _shards: { total: 3, successful: 3, skipped: 0, failed: 0 },
            hits: {
              total: { value: 2, relation: "eq" },
              hits: [
                {
                  _index: "logs-win-2026.11.01",
                  _id: "doc-page-1",
                  sort: ["2026-11-14T14:00:00Z", 5],
                  _source: { "@timestamp": "2026-11-14T14:00:00Z", host: { name: "wkstn-01" } },
                },
              ],
            },
          },
        };
      },
    });

    const env: Record<string, string | undefined> = { HUNT_ELASTIC_API_KEY: TEST_API_KEY };
    const dp = await ConnectedHuntDataPlane.open({
      config: makeValidConfig(),
      caseDefinition: makeValidCase(),
      environ: env,
      stateDir,
      transport,
      nowEpochMs: FIXED_NOW_MS,
    });
    expect(env.HUNT_ELASTIC_API_KEY).toBeUndefined();

    // Crash reaper deleted stale-crashed-pit-000 before opening pit-gen-1
    expect(deletedPits).toEqual(["stale-crashed-pit-000"]);
    expect(openedPits).toEqual(["pit-gen-1"]);

    // Page 1 (size: 1 -> returns next_after cursor and rotates PIT to pit-gen-1-rotated)
    const page1 = await dp.elasticSearch({ q: "host.name:wkstn-01", size: 1 });
    expect(page1.returned).toBe(1);
    expect(page1.next_after).toBeTruthy();

    // Verify allow_partial_search_results=false and rotated PIT persisted on disk
    const searchCall = calls.find((c) => c.url.includes("/_search?allow_partial_search_results=false"));
    expect(searchCall).toBeDefined();
    const persistedAfterRotate = JSON.parse(fs.readFileSync(activePitFile, "utf8")) as { pit_id: string };
    expect(persistedAfterRotate.pit_id).toBe("pit-gen-1-rotated");

    // Now simulate PIT loss during paginated search -> reopens PIT and rejects stale cursor with 400 cursor_expired!
    simulatePitLossNext = true;
    try {
      await dp.elasticSearch({
        q: "host.name:wkstn-01",
        size: 1,
        after: page1.next_after!,
      });
      throw new Error("Expected cursor_expired");
    } catch (err) {
      const dpErr = extractDataPlaneError(err);
      expect(dpErr?.statusCode).toBe(400);
      expect(dpErr?.errorCode).toBe("cursor_expired");
    }
    expect(openedPits).toEqual(["pit-gen-1", "pit-gen-2"]);

    // Fresh unpaginated search after PIT loss transparently uses reopened pit-gen-2 (and even if lost once, retries cleanly)
    simulatePitLossNext = true;
    const freshSearch = await dp.elasticSearch({ q: "host.name:wkstn-01", size: 5 });
    expect(freshSearch.returned).toBe(1);
    expect(openedPits).toEqual(["pit-gen-1", "pit-gen-2", "pit-gen-3"]);

    // Close deletes active PIT and removes active_pit.json
    await dp.close();
    expect(deletedPits).toEqual(["stale-crashed-pit-000", "pit-gen-3"]);
    expect(fs.existsSync(activePitFile)).toBe(false);
  });

  for (const order of ["asc", "desc"] as const) {
    test(`paginates adjacent date_nanos losslessly in ${order} order through JSON transport`, async () => {
      // Raw numeric date_nanos values already collide at the JSON.parse boundary.
      const rounded = JSON.parse("[1794664800123456789,1794664800123456790]") as number[];
      expect(rounded[0]).toBe(rounded[1]);
      expect(Number.isSafeInteger(rounded[0])).toBe(false);

      const timestamps = [
        "2026-11-14T14:00:00.123456789Z",
        "2026-11-14T14:00:00.123456790Z",
        "2026-11-14T14:00:00.123456791Z",
      ];
      const rows = timestamps.map((timestamp, index) => ({
        _index: "logs-win-2026.11.01",
        _id: `nano-${index}`,
        sort: [timestamp, index + 10],
        _source: { "@timestamp": timestamp, host: { name: "wkstn-01" } },
      }));
      if (order === "desc") rows.reverse();
      const { transport, calls } = createMockEsTransport({
        onSearch: (body) => {
          expect(body.sort).toEqual([
            { "@timestamp": { order, numeric_type: "date_nanos", format: "strict_date_optional_time_nanos" } },
            { _shard_doc: order },
          ]);
          const after = body.search_after;
          const index = after === undefined
            ? 0
            : rows.findIndex((row) => JSON.stringify(row.sort) === JSON.stringify(after)) + 1;
          if (after !== undefined) expect(index).toBeGreaterThan(0);
          return {
            status: 200,
            response: {
              hits: {
                total: { value: rows.length, relation: "eq" },
                hits: rows.slice(index, index + 1),
              },
            },
          };
        },
      });
      const dp = await ConnectedHuntDataPlane.open({
        config: makeValidConfig(),
        caseDefinition: makeValidCase(),
        environ: { HUNT_ELASTIC_API_KEY: TEST_API_KEY },
        transport,
        nowEpochMs: FIXED_NOW_MS,
      });
      try {
        let after: string | undefined;
        const seen: unknown[] = [];
        for (const row of rows) {
          const page = await dp.elasticSearch({ size: 1, sort: order, ...(after ? { after } : {}) });
          expect(page.returned).toBe(1);
          expect(page.next_after).toBeTruthy();
          seen.push(page.hits[0]!["@timestamp"]);
          const tuple = JSON.parse(Buffer.from(page.next_after!, "base64url").toString("utf8")) as unknown[];
          expect(tuple.slice(0, 2)).toEqual(row.sort);
          expect(Number.isSafeInteger(tuple[2])).toBe(true);
          after = page.next_after!;
        }
        expect(seen).toEqual(rows.map((row) => row._source["@timestamp"]));
        expect(new Set(seen).size).toBe(3);
        const end = await dp.elasticSearch({ size: 1, sort: order, after });
        expect(end.returned).toBe(0);
        expect(end.next_after).toBeNull();
        const searches = calls.filter((call) => call.url.includes("/_search?"));
        expect(searches.map((call) => call.body!.search_after)).toEqual([
          undefined,
          ...rows.map((row) => row.sort),
        ]);
      } finally {
        await dp.close();
      }
    });
  }

  for (const order of ["asc", "desc"] as const) {
    test(`budgets role-scoped multibyte search pages without losing adjacent nanosecond events in ${order} order`, async () => {
      const rows = Array.from({ length: 5 }, (_, index) => {
        const timestamp = `2026-11-14T14:00:00.12345678${index}Z`;
        return {
          _index: "logs-win-2026.11.01",
          _id: `budget-nano-${index}`,
          sort: [timestamp, index + 10],
          _source: {
            "@timestamp": timestamp,
            host: { name: "wkstn-01" },
            process: { command_line: index === 2 ? "🧪".repeat(20_000) : "界".repeat(3_000) },
          },
        };
      });
      if (order === "desc") rows.reverse();
      const { transport, calls } = createMockEsTransport({
        onSearch: (body) => {
          const after = body.search_after;
          const index = after === undefined
            ? 0
            : rows.findIndex((row) => JSON.stringify(row.sort) === JSON.stringify(after)) + 1;
          if (after !== undefined) expect(index).toBeGreaterThan(0);
          return {
            status: 200,
            response: {
              hits: {
                total: { value: rows.length, relation: "eq" },
                hits: rows.slice(index, index + Number(body.size)),
              },
            },
          };
        },
      });
      const dp = await ConnectedHuntDataPlane.open({
        config: makeValidConfig(),
        caseDefinition: makeValidCase(),
        environ: { HUNT_ELASTIC_API_KEY: TEST_API_KEY },
        transport,
        nowEpochMs: FIXED_NOW_MS,
      });
      try {
        const mint = createRoleCapabilityMint();
        const scoped = mint.bindDataPlane(dp, mint.issueCapability({
          huntId: "hunt-connected-budget",
          caseId: dp.caseId,
          profile: "framework-researcher",
          stepId: "evidence",
        }));
        let after: string | undefined;
        let seenCount = 0;
        const seen: string[] = [];
        for (const [pageIndex, expectedCount] of [2, 1, 2].entries()) {
          const wire = await scoped.executeTool("elastic_search", {
            size: 5, sort: order, fields: "process.command_line", ...(after ? { after } : {}),
          });
          expect(Buffer.byteLength(wire, "utf8")).toBeLessThanOrEqual(24 * 1024);
          const fenced = /^<untrusted_tool_result_([0-9a-f]{32})>\n([\s\S]*)\n<\/untrusted_tool_result_\1>$/.exec(wire);
          expect(fenced).not.toBeNull();
          const page = JSON.parse(fenced![2]!) as {
            total: number; total_relation: string; returned: number;
            hits: Array<Record<string, unknown>>; next_after: string | null; truncated?: boolean;
          };
          expect(page.total).toBe(rows.length);
          expect(page.total_relation).toBe("eq");
          expect(page.returned).toBe(expectedCount);
          expect(page.hits).toHaveLength(expectedCount);
          expect(page.truncated).toBe(pageIndex < 2 ? true : undefined);
          for (const hit of page.hits) {
            const row = rows[seenCount++]!;
            const citation = formatConnectedCitation(row._index, row._id);
            expect(hit["@timestamp"]).toBe(row._source["@timestamp"]);
            expect(hit["event.id"]).toBe(citation);
            expect(dp.verifyCitations([citation]).allValid).toBe(true);
            expect(dp.resolveCitationsInLucene(`event.id:${citation}`)).toContain(row._id);
            const commandLine = String(hit["process.command_line"]);
            expect(commandLine).not.toContain("\ufffd");
            if (row._id === "budget-nano-2") {
              expect(Buffer.byteLength(commandLine, "utf8")).toBeLessThan(
                Buffer.byteLength(row._source.process.command_line, "utf8"),
              );
            } else {
              expect(commandLine).toBe(row._source.process.command_line);
            }
            seen.push(citation);
          }
          if (pageIndex < 2) {
            expect(page.next_after).toBeTruthy();
            const tuple = JSON.parse(Buffer.from(page.next_after!, "base64url").toString("utf8"));
            expect(tuple.slice(0, 2)).toEqual(rows[seenCount - 1]!.sort);
            expect(Number.isSafeInteger(tuple[2])).toBe(true);
            after = page.next_after!;
          } else {
            expect(page.next_after).toBeNull();
          }
        }
        expect(seen).toEqual(rows.map((row) => formatConnectedCitation(row._index, row._id)));
        expect(new Set(seen).size).toBe(rows.length);
        const searches = calls.filter((call) => call.url.includes("/_search?"));
        expect(searches.map((call) => call.body!.search_after)).toEqual([
          undefined, rows[1]!.sort, rows[2]!.sort,
        ]);
      } finally {
        await dp.close();
      }
    });
  }

  test("rejects malformed date_nanos cursors and unsafe shard-doc or generation integers before transport", async () => {
    const { transport, calls } = createMockEsTransport({
      onSearch: () => ({
        status: 200,
        response: {
          hits: {
            total: { value: 1, relation: "eq" },
            hits: [{
              _index: "logs-win-2026.11.01",
              _id: "safe-shard-doc",
              sort: ["2026-11-14T14:00:00.123456789Z", Number.MAX_SAFE_INTEGER],
              _source: { "@timestamp": "2026-11-14T14:00:00.123456789Z" },
            }],
          },
        },
      }),
    });
    const dp = await ConnectedHuntDataPlane.open({
      config: makeValidConfig(),
      caseDefinition: makeValidCase(),
      environ: { HUNT_ELASTIC_API_KEY: TEST_API_KEY },
      transport,
      nowEpochMs: FIXED_NOW_MS,
    });
    try {
      const page = await dp.elasticSearch({ size: 1 });
      const valid = JSON.parse(Buffer.from(page.next_after!, "base64url").toString("utf8")) as [string, number, number];
      const [timestamp, shardDoc, generation] = valid;
      const malformed = [
        [],
        [timestamp, shardDoc],
        [...valid, 0],
        [1794664800123456789, shardDoc, generation],
        [1794664800123, shardDoc, generation],
        ["1794664800123456789", shardDoc, generation],
        ["not-a-date", shardDoc, generation],
        ["2026-02-30T14:00:00.123456789Z", shardDoc, generation],
        ["2026-11-14T14:00:00.1234567890Z", shardDoc, generation],
        [` ${timestamp}`, shardDoc, generation],
        [timestamp, Number.MAX_SAFE_INTEGER + 1, generation],
        [timestamp, -1, generation],
        [timestamp, 1.5, generation],
        [timestamp, "10", generation],
        [timestamp, shardDoc, Number.MAX_SAFE_INTEGER + 1],
        [timestamp, shardDoc, 1.5],
        [timestamp, shardDoc, -1],
        [timestamp, shardDoc, 0],
        [timestamp, shardDoc, String(generation)],
        [timestamp, shardDoc, null],
      ];
      const searchCount = calls.filter((call) => call.url.includes("/_search?")).length;
      for (const tuple of malformed) {
        const after = Buffer.from(JSON.stringify(tuple), "utf8").toString("base64url");
        try {
          await dp.elasticSearch({ size: 1, after });
          throw new Error("Expected invalid_query");
        } catch (err) {
          expect(extractDataPlaneError(err)).toMatchObject({ statusCode: 400, errorCode: "invalid_query" });
        }
      }
      const stale = Buffer.from(JSON.stringify([timestamp, shardDoc, generation + 1]), "utf8").toString("base64url");
      try {
        await dp.elasticSearch({ size: 1, after: stale });
        throw new Error("Expected cursor_expired");
      } catch (err) {
        expect(extractDataPlaneError(err)).toMatchObject({ statusCode: 400, errorCode: "cursor_expired" });
      }
      expect(calls.filter((call) => call.url.includes("/_search?")).length).toBe(searchCount);
      await dp.elasticSearch({ size: 1, after: page.next_after! });
      expect(calls[calls.length - 1]!.body!.search_after).toEqual([timestamp, shardDoc]);
    } finally {
      await dp.close();
    }
  });

  test("rejects malformed backend sort tuples across search, detectionTest, and event queries", async () => {
    let sortTuple: unknown;
    const { transport } = createMockEsTransport({
      onSearch: (body) => {
        expect(body.sort).toEqual([
          { "@timestamp": { order: "asc", numeric_type: "date_nanos", format: "strict_date_optional_time_nanos" } },
          { _shard_doc: "asc" },
        ]);
        return {
          status: 200,
          response: {
            hits: {
              total: { value: 2, relation: "eq" },
              hits: [
                { _index: "logs-win-2026.11.01", _id: "malformed", sort: sortTuple, _source: {} },
                { _index: "logs-win-2026.11.01", _id: "valid-last", sort: ["2026-11-14T14:00:00Z", 1], _source: {} },
              ],
            },
          },
        };
      },
    });
    const dp = await ConnectedHuntDataPlane.open({
      config: makeValidConfig(),
      caseDefinition: makeValidCase(),
      environ: { HUNT_ELASTIC_API_KEY: TEST_API_KEY },
      transport,
      nowEpochMs: FIXED_NOW_MS,
    });
    try {
      for (const tuple of [
        undefined,
        null,
        [],
        ["2026-11-14T14:00:00Z"],
        ["2026-11-14T14:00:00Z", 0, 1],
        [1794664800123456789, 0],
        ["not-a-date", 0],
        ["2026-11-14T14:00:00Z", Number.MAX_SAFE_INTEGER + 1],
        ["2026-11-14T14:00:00Z", -1],
        ["2026-11-14T14:00:00Z", 1.5],
        ["2026-11-14T14:00:00Z", "0"],
      ]) {
        sortTuple = tuple;
        for (const search of [
          () => dp.elasticSearch({ size: 2 }),
          () => dp.detectionTest({ name: "nano-validation", q: "" }),
          () => dp.huntLabQuery({ dataset: "events" }),
        ]) {
          try {
            await search();
            throw new Error("Expected backend_not_ready");
          } catch (err) {
            expect(extractDataPlaneError(err)).toMatchObject({ statusCode: 503, errorCode: "backend_not_ready" });
          }
        }
      }
    } finally {
      await dp.close();
    }
  });

  test("mints F04 collision-proof sha256(_index + '\\0' + _id) citations, persists citations.jsonl, rewrites Lucene, blocks event.id escapes, refuses /regex/, and gates unsupported tools", async () => {
    const stateDir = makeTempDir("hunt-conn-f04-");
    const { transport, calls } = createMockEsTransport();

    const dp = await ConnectedHuntDataPlane.open({
      config: makeValidConfig(),
      caseDefinition: makeValidCase(),
      environ: { HUNT_ELASTIC_API_KEY: TEST_API_KEY },
      stateDir,
      transport,
      nowEpochMs: FIXED_NOW_MS,
    });

    // 1. Two hits with identical _id ("shared-doc-42") across two rollover indices get DISTINCT evt-<16d> citations!
    const res = await dp.elasticSearch({ q: "" });
    expect(res.returned).toBe(2);
    const cite1 = res.hits[0]!["event.id"] as string;
    const cite2 = res.hits[1]!["event.id"] as string;

    expect(cite1).toBe(formatConnectedCitation("logs-win-2026.11.01", "shared-doc-42"));
    expect(cite2).toBe(formatConnectedCitation("logs-win-2026.11.02", "shared-doc-42"));
    expect(cite1).not.toBe(cite2);
    expect(cite1).toMatch(/^evt-\d{16}$/);
    expect(cite2).toMatch(/^evt-\d{16}$/);

    // Verify citations.jsonl persisted both (_index, _id) pairs
    const citationsFile = path.join(stateDir, "conn-case-001", "citations.jsonl");
    expect(fs.existsSync(citationsFile)).toBe(true);
    const savedLines = fs.readFileSync(citationsFile, "utf8").trim().split(/\r?\n/);
    expect(savedLines.length).toBe(2);

    // 2. verifyCitations resolves minted citations, marks unknown evt-* & frame-0002 unresolved, and garbage malformed
    const ver = dp.verifyCitations([cite1, cite2, "evt-9999999999999999", "frame-0002", "not-a-cite"]);
    expect(ver.allValid).toBe(false);
    expect(ver.resolved.eventIds).toEqual([cite1, cite2]);
    expect(ver.unresolved).toEqual(["evt-9999999999999999", "frame-0002"]);
    expect(ver.malformed).toEqual(["not-a-cite"]);

    // 3. Lucene citation rewrite: event.id:(cite1 OR "cite2") and bare cite1 rewrite to (_index:"..." AND _id:"...")
    const rewrittenGroup = dp.resolveCitationsInLucene(
      `host.name:wkstn-01 AND event.id:(${cite1} OR "${cite2}")`,
    );
    expect(rewrittenGroup).toContain(
      `((_index:"logs-win-2026.11.01" AND _id:"shared-doc-42") OR (_index:"logs-win-2026.11.02" AND _id:"shared-doc-42"))`,
    );
    expect(rewrittenGroup).not.toContain("event.id");

    const rewrittenBare = dp.resolveCitationsInLucene(`${cite1} AND process.name:powershell.exe`);
    expect(rewrittenBare).toContain(`(_index:"logs-win-2026.11.01" AND _id:"shared-doc-42")`);

    // Unknown citation -> 400 unknown_citation
    try {
      dp.resolveCitationsInLucene("event.id:evt-9999999999999999");
      throw new Error("Expected unknown_citation");
    } catch (err) {
      expect(extractDataPlaneError(err)?.errorCode).toBe("unknown_citation");
    }

    // 4. Direct, escaped, unicode-escaped, wildcard, and _exists_ references to event.id are ALL blocked!
    for (const bypassAttempt of [
      "event.id:cluster-internal-id",
      "event\\.id:cluster-internal-id",
      "\\u0065vent.id:cluster-internal-id",
      "event.id*:cluster-internal-id",
      "event.*:cluster-internal-id",
      "event.id.custom_sub:foo",
      "_exists_:event.id",
      '_exists_:("event.id")',
    ]) {
      try {
        dp.resolveCitationsInLucene(bypassAttempt);
        throw new Error(`Expected bypass attempt to be blocked: ${bypassAttempt}`);
      } catch (err) {
        expect(extractDataPlaneError(err)?.errorCode).toBe("invalid_query");
      }
    }

    // 5. Regex refusal: unquoted /regex/ and range /regex/ -> 400 regex_not_supported; quoted paths allowed
    for (const regexQuery of ["/pow.*shell/", "process.name:/cmd.*/", "[a TO /z/]"]) {
      try {
        refuseConnectedRegex(regexQuery);
        throw new Error(`Expected regex_not_supported for ${regexQuery}`);
      } catch (err) {
        expect(extractDataPlaneError(err)?.errorCode).toBe("regex_not_supported");
      }
    }
    expect(() =>
      refuseConnectedRegex('process.command_line:"/usr/bin/curl -s https://example.org/a"'),
    ).not.toThrow();

    // 6. Aggregations, detectionTest, huntLabQuery(case & events), and citations reload across reopen
    const aggRes = await dp.elasticAggregate({ field: "host.name", size: "10" as unknown as number });
    expect(aggRes.buckets[0]?.key).toBe("wkstn-01");
    expect(aggRes.buckets[0]?.sample_event_id).toBe(cite1);
    expect(aggRes.other).toBe(3);

    // Non-aggregatable text field -> 400 field_unavailable
    try {
      await dp.elasticAggregate({ field: "process.command_line" });
      throw new Error("Expected field_unavailable");
    } catch (err) {
      expect(extractDataPlaneError(err)?.errorCode).toBe("field_unavailable");
    }

    const detRes = await dp.detectionTest({
      name: "suspicious-powershell",
      q: `event.id:${cite1}`,
    });
    expect(detRes.total).toBe(2);
    expect(detRes.sample[0]?.["event.id"]).toBe(cite1);

    // Confirm rewritten query sent to ES excluded event.id from query_string.fields
    const lastSearchBody = calls[calls.length - 1]!.body!;
    const serializedQuery = JSON.stringify(lastSearchBody.query);
    expect(serializedQuery).toContain('_index:\\"logs-win-2026.11.01\\"');
    expect(serializedQuery).not.toContain('"event.id"');

    // Safe /case info exposes zero cluster URL or index names
    const casePayload = await dp.huntLabQuery({ dataset: "case" });
    expect(JSON.stringify(casePayload)).not.toContain("siem-es");
    expect(JSON.stringify(casePayload)).not.toContain("logs-win");

    const hlEvents = await dp.huntLabQuery({ dataset: "events", host: "wkstn-01", limit: 10 });
    expect(hlEvents).toMatchObject({ dataset: "events", returned: 2, read_only: true });

    // 7. Unsupported connected surfaces return exact error codes
    for (const [fn, expectedCode] of [
      [() => dp.intelLookup({ values: "1.2.3.4" }), "no_intel_source"],
      [() => dp.arkimeSessions({}), "no_network_capture"],
      [() => dp.arkimeUnique({ field: "ip.dst" }), "no_network_capture"],
      [() => dp.packetFields({ fields: "ip.src" }), "no_network_capture"],
      [() => dp.huntLabQuery({ dataset: "network" }), "no_network_capture"],
      [() => dp.labBrowser({ page: "kibana_discover" }), "no_lab_browser"],
    ] as const) {
      try {
        await fn();
        throw new Error(`Expected ${expectedCode}`);
      } catch (err) {
        const dpErr = extractDataPlaneError(err);
        expect(dpErr?.statusCode).toBe(400);
        expect(dpErr?.errorCode).toBe(expectedCode);
      }
    }

    await dp.close();

    // 8. Reopen from same stateDir reloads persisted citations.jsonl so previous citations still verify!
    const dpReopened = await ConnectedHuntDataPlane.open({
      config: makeValidConfig(),
      caseDefinition: makeValidCase(),
      environ: { HUNT_ELASTIC_API_KEY: TEST_API_KEY },
      stateDir,
      transport,
      nowEpochMs: FIXED_NOW_MS,
    });
    expect(dpReopened.verifyCitations([cite1, cite2]).allValid).toBe(true);
    await dpReopened.close();
  });

  test("regression (pr1-v2 BLOCK 2 & connected parity): enforces analyze_wildcard:false, quoted/range leading-wildcard 400, and unbounded [100 TO *] allowance", async () => {
    const { transport: baseTransport } = createMockEsTransport({
      onSearch: () => ({
        status: 200,
        response: {
          pit_id: "pit-gen-1",
          timed_out: false,
          _shards: { total: 1, successful: 1, skipped: 0, failed: 0 },
          hits: {
            total: { value: 2, relation: "eq" },
            hits: [
              {
                _index: "logs-win-2026.11.01",
                _id: "shared-doc-42",
                sort: ["2026-11-14T14:00:00.123456789Z", 10],
                _source: {
                  "@timestamp": "2026-11-14T14:00:00.123456789Z",
                  host: { name: "wkstn-01" },
                },
              },
            ],
          },
        },
      }),
    });
    const rawSearchBodies: string[] = [];
    const wrappedTransport: ConnectedHttpsTransport = async (method, url, headers, bodyBytes) => {
      if (method === "POST" && url.includes("/_search?allow_partial_search_results=false")) {
        const reqText = bodyBytes ? Buffer.from(bodyBytes).toString("utf8") : "";
        rawSearchBodies.push(reqText);
      }
      return baseTransport(method, url, headers, bodyBytes);
    };

    const stateDir = makeTempDir("hunt-conn-wc-");
    const dp = await ConnectedHuntDataPlane.open({
      config: makeValidConfig(),
      caseDefinition: makeValidCase(),
      environ: { HUNT_ELASTIC_API_KEY: TEST_API_KEY },
      stateDir,
      transport: wrappedTransport,
      nowEpochMs: FIXED_NOW_MS,
    });

    for (const badQ of ['"*evil"', 'host.name:["*a" TO "z"]', 'message:"?foo"']) {
      try {
        await dp.elasticSearch({ q: badQ });
        throw new Error(`Expected leading_wildcard_not_supported for ${badQ}`);
      } catch (err) {
        const dpErr = extractDataPlaneError(err);
        expect(dpErr?.statusCode).toBe(400);
        expect(dpErr?.errorCode).toBe("leading_wildcard_not_supported");
      }
    }

    const page1 = await dp.elasticSearch({ q: "destination.port:[100 TO *]", size: 1 });
    expect(rawSearchBodies[0]).toContain('"analyze_wildcard":false');
    expect(page1.next_after).toBeTruthy();

    await dp.elasticSearch({
      q: "destination.port:[100 TO *]",
      size: 1,
      after: page1.next_after!,
    });
    expect(rawSearchBodies[1]).toContain('"search_after":["2026-11-14T14:00:00.123456789Z",10]');

    await dp.close();
  });
});
