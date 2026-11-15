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
              sort: [1731586000000000000, 10],
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
              sort: [1731586001000000000, 11],
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
                  sort: [1731586000000000000, 5],
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
});
