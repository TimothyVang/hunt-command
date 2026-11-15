import { afterAll, describe, expect, test } from "bun:test";
import fs from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { z } from "zod";
import {
  exportOtlpLoopback,
  guardEgress,
  HuntTelemetryStore,
} from "@hunt-command/telemetry";
import { EmbeddedHuntDataPlane } from "../src/index.ts";

/**
 * Fastest of up to three timed runs, stopping at the first one under budget. A load spike on a
 * busy machine can't fail a linear-time check this way, but a quadratic input is slow on every run.
 */
function fastestMs(run: () => unknown, budgetMs: number): number {
  let best = Number.POSITIVE_INFINITY;
  for (let attempt = 0; attempt < 3 && best >= budgetMs; attempt++) {
    const started = performance.now();
    run();
    best = Math.min(best, performance.now() - started);
  }
  return best;
}

/** Nearest ancestor directory that has a sibling `hermes-hunt-bots/` checkout (override: HUNT_WORKSPACE_ROOT). */
function findWorkspaceRoot(start: string): string {
  if (process.env.HUNT_WORKSPACE_ROOT) return process.env.HUNT_WORKSPACE_ROOT;
  let dir = start;
  for (;;) {
    if (fs.existsSync(path.join(dir, "hermes-hunt-bots"))) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) return start;
    dir = parent;
  }
}

const WORKSPACE = findWorkspaceRoot(import.meta.dir).replaceAll("\\", "/");

const tempDirs: string[] = [];

function makeTempDir(prefix: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

afterAll(() => {
  for (const dir of tempDirs) {
    // Windows refuses to delete a cache file a just-closed SQLite handle still holds; retry briefly.
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
});

function resolveExistingCaseDir(candidates: readonly string[]): string | null {
  for (const candidate of candidates) {
    const caseJson = path.join(candidate, "case.json");
    if (fs.existsSync(caseJson)) {
      return candidate;
    }
  }
  return null;
}

function prepareSyntheticBenchmarkCase(sourceDir: string, caseId: string): string {
  // Legacy benchmark manifests explicitly describe invented telemetry. Migrate only a test-owned copy.
  const definition = z.object({
    case_id: z.literal(caseId),
    data_origin: z.literal("synthetic").optional(),
    sources: z.array(z.object({
      artifact: z.string(),
      coverage: z.string().regex(/^(?:Invented|Selected invented) /),
    })).nonempty(),
  }).passthrough().parse(JSON.parse(fs.readFileSync(path.join(sourceDir, "case.json"), "utf8")));
  const caseDir = makeTempDir(`hunt-bench-${caseId}-`);
  for (const artifact of ["events.jsonl", "traffic.pcap", "intel.jsonl"]) {
    const source = path.join(sourceDir, artifact);
    if (fs.existsSync(source)) fs.copyFileSync(source, path.join(caseDir, artifact));
  }
  fs.writeFileSync(
    path.join(caseDir, "case.json"),
    JSON.stringify({ ...definition, data_origin: "synthetic" }),
  );
  return caseDir;
}

const DNS_LAB_DIR = resolveExistingCaseDir([
  `${WORKSPACE}/hermes-hunt-bots/repo/runtime/cases/dns-lab-001/evidence`,
  `${WORKSPACE}/hermes-hunt-bots/repo/runtime/cases/dns-lab-001`,
  `${WORKSPACE}/hermes-hunt-bots/repo/framework/hunt_lab/fixtures/dns-lab-001`,
]);

const LAB_MED_DIR = resolveExistingCaseDir([
  `${WORKSPACE}/hermes-hunt-bots/repo/runtime/cases/lab-med-001/evidence`,
  `${WORKSPACE}/hermes-hunt-bots/runtime/cases/lab-med-001/evidence`,
]);

describe("Real Case Integration & Latency Benchmarks (dns-lab-001 & lab-med-001)", () => {
  test("dns-lab-001: cold load < 1s, warm attach < 20ms, Lucene/Arkime/packet_fields/0xC0 DNS & end-to-end telemetry guards", async () => {
    if (!DNS_LAB_DIR) {
      console.log("[BENCHMARK] dns-lab-001 skipped (fixture directory not present on host)");
      return;
    }

    const cacheDir = makeTempDir("hunt-bench-dns-cache-");
    const caseDir = prepareSyntheticBenchmarkCase(DNS_LAB_DIR, "dns-lab-001");

    // 1. Cold open benchmark
    const tCold0 = performance.now();
    const dpCold = await EmbeddedHuntDataPlane.open(caseDir, {
      cacheDir,
    });
    const coldMs = performance.now() - tCold0;
    let firstEvtId = "";
    try {
      expect(coldMs).toBeLessThan(1_000);
      expect(dpCold.caseId).toBe("dns-lab-001");
      expect(dpCold.syntheticOnly).toBe(true);

      const allEvents = await dpCold.elasticSearch({ q: "", size: 100 });
      expect(allEvents.total).toBe(40);
      expect(allEvents.returned).toBe(40);
      firstEvtId = allEvents.hits[0]!["event.id"] as string;
      expect(firstEvtId).toMatch(/^evt-/);

      const dnsFrames = await dpCold.packetFields({
        filter: 'dns.qry.name != ""',
        fields: "frame.number,ip.src,ip.dst,dns.qry.name,dns.qry.type,dns.flags.rcode,dns.a,dns.cname",
        length: 50,
      });
      expect(dnsFrames.returned).toBeGreaterThan(0);

      const arkUnique = await dpCold.arkimeUnique({ field: "host.dns", counts: 1 });
      expect(arkUnique.values.length).toBeGreaterThan(0);
    } finally {
      await dpCold.close();
    }

    // 2. Warm attach benchmark (< 20ms)
    // Best of up to three attaches, so a load spike can't fail the documented < 20 ms claim.
    let warmMs = Number.POSITIVE_INFINITY;
    let dpWarm = undefined as unknown as Awaited<ReturnType<typeof EmbeddedHuntDataPlane.open>>;
    for (let attempt = 0; attempt < 3; attempt++) {
      const tWarm0 = performance.now();
      const attached = await EmbeddedHuntDataPlane.open(caseDir, {
        cacheDir,
      });
      const ms = performance.now() - tWarm0;
      if (attempt > 0) await dpWarm.close();
      dpWarm = attached;
      warmMs = Math.min(warmMs, ms);
      if (warmMs < 20) break;
    }
    try {
      expect(warmMs).toBeLessThan(20);

      const citeCheck = dpWarm.verifyCitations([firstEvtId, "frame-1", "frame-0002"]);
      expect(citeCheck.allValid).toBe(true);
    } finally {
      await dpWarm.close();
    }

    // 3. End-to-end Telemetry lineage (<1ms), OTLP proxy/redirect rejection, and Rule 4 EgressGuard
    const telemetryDir = makeTempDir("hunt-bench-telemetry-");
    const store = new HuntTelemetryStore({
      dbPath: path.join(telemetryDir, "hunt_telemetry.sqlite"),
      blobsDir: path.join(telemetryDir, "blobs"),
    });
    const t0 = 1_763_150_000_000;
    const runSpan = store.recordRunSpan({
      huntId: "hunt-bench-001",
      caseId: "dns-lab-001",
      dataOrigin: "synthetic",
      mode: "supervised",
      startTimeMs: t0,
    });
    const waveSpan = store.recordWaveSpan({
      huntId: "hunt-bench-001",
      parentSpanId: runSpan.spanId,
      wave: "investigation",
      waveIndex: 2,
      parallel: true,
      stepIds: ["network"],
      startTimeMs: t0 + 10,
      endTimeMs: t0 + 200,
    });
    const botStep = store.recordBotStepSpan({
      huntId: "hunt-bench-001",
      parentSpanId: waveSpan.spanId,
      wave: "investigation",
      stepId: "network",
      botProfile: "framework-network-analyst",
      stepStatus: "done",
      startTimeMs: t0 + 15,
      endTimeMs: t0 + 195,
    });
    store.recordHandoffValidateSpan({
      huntId: "hunt-bench-001",
      parentSpanId: botStep.spanId,
      wave: "investigation",
      stepId: "network",
      botProfile: "framework-network-analyst",
      disposition: "suspicious",
      claims: [
        {
          claim_id: "claim-001",
          kind: "observed",
          statement: `Observed DNS activity in [${firstEvtId}] and [frame-1].`,
        },
      ],
      startTimeMs: t0 + 180,
      endTimeMs: t0 + 190,
    });

    let lineageRows: ReturnType<typeof store.getEvidenceForClaim> = [];
    const lineageMs = fastestMs(() => {
      lineageRows = store.getEvidenceForClaim("hunt-bench-001", "claim-001");
    }, 1);
    expect(lineageRows.length).toBe(2);
    expect(lineageMs).toBeLessThan(1);

    // OTLP Loopback exporter: rejects HTTP redirect (302) even with malicious HTTP_PROXY set
    const redirectCollector = http.createServer((_req, res) => {
      res.writeHead(302, { Location: "http://127.0.0.1:9999/hijack" });
      res.end();
    });
    await new Promise<void>((resolve) =>
      redirectCollector.listen(0, "127.0.0.1", () => resolve()),
    );
    const collectorPort = (redirectCollector.address() as AddressInfo).port;
    const prevProxy = process.env.HTTP_PROXY;
    process.env.HTTP_PROXY = "http://127.0.0.1:1";
    try {
      await expect(
        exportOtlpLoopback({
          endpoint: `http://127.0.0.1:${collectorPort}/v1/traces`,
          syntheticOnly: true,
          dataOrigin: "synthetic",
          spans: [runSpan],
        }),
      ).rejects.toThrow(/Refusing HTTP 302 redirect/);
    } finally {
      if (prevProxy === undefined) delete process.env.HTTP_PROXY;
      else process.env.HTTP_PROXY = prevProxy;
      await new Promise<void>((resolve) => redirectCollector.close(() => resolve()));
    }

    // Rule 4 EgressGuard: strips all sensitive case content when !synthetic_only
    const guarded = guardEgress({
      hunt_uuid: "0f5e4d3c-2b1a-4978-8abc-0123456789ab",
      data_origin: "work-export",
      synthetic_only: false,
      wave: "investigation",
      gate_kind: "scope",
      status_enum: "awaiting_approval",
      opened_at_utc: "2026-11-15T00:00:00Z",
      reason_code: "awaiting_human_scope",
      summary: `Observed ${firstEvtId} on dc01.corp.internal (10.20.30.40)`,
      query_text: "process.name:powershell.exe",
      outputs_dir: "C:/secret/outputs",
      counters: {
        input_tokens: 1200,
        cache_read_tokens: 960,
        cache_write_tokens: 0,
        output_tokens: 180,
        actual_usd: 0,
        api_equivalent_usd: 0.014,
      },
    });
    const serializedGuarded = JSON.stringify(guarded);
    expect(serializedGuarded).not.toContain(firstEvtId);
    expect(serializedGuarded).not.toContain("dc01.corp.internal");
    expect(serializedGuarded).not.toContain("10.20.30.40");
    expect(serializedGuarded).not.toContain("powershell.exe");
    expect(serializedGuarded).not.toContain("outputs");
    expect(guarded.status_enum).toBe("awaiting_approval");
    expect(guarded.counters?.input_tokens).toBe(1200);

    store.close();

    console.log(
      `[BENCHMARK] dns-lab-001: cold=${coldMs.toFixed(2)}ms (<1000ms), warm=${warmMs.toFixed(2)}ms (<20ms), lineage=${lineageMs.toFixed(3)}ms (<1ms)`,
    );
  });

  test("lab-med-001 (20,931 events + 45,836 frames + 309 IOCs): Worker indexing, warm attach < 20ms, FoxIO TLS JA4, Lucene/Arkime/intel & citations", async () => {
    if (!LAB_MED_DIR) {
      console.log("[BENCHMARK] lab-med-001 skipped (case directory not present on host)");
      return;
    }

    const cacheDir = makeTempDir("hunt-bench-med-cache-");
    const caseDir = prepareSyntheticBenchmarkCase(LAB_MED_DIR, "lab-med-001");

    // 1. Cold Worker indexing across 19.8 MB events.jsonl + 27.8 MB traffic.pcap + intel.jsonl
    const tCold0 = performance.now();
    const dpCold = await EmbeddedHuntDataPlane.open(caseDir, {
      cacheDir,
    });
    const coldMs = performance.now() - tCold0;

    let searchMs = 0;
    let arkMs = 0;
    let pktMs = 0;
    let firstJa4 = "";
    try {
      // Query events, histogram, detection, intel, Arkime sessions/unique, TLS JA4, packet_fields
      const tSearch0 = performance.now();
      const esAll = await dpCold.elasticSearch({ q: "", size: 25 });
      searchMs = performance.now() - tSearch0;
      expect(esAll.total).toBe(20_931);
      expect(esAll.returned).toBe(25);
      const sampleEvtId = esAll.hits[0]!["event.id"] as string;

      const hist = await dpCold.elasticAggregate({ field: "@timestamp", interval: "15m" });
      expect(hist.total).toBe(20_931);
      expect(hist.buckets.length).toBeGreaterThan(0);

      const hostAgg = await dpCold.elasticAggregate({ field: "host.name", size: 30 });
      expect(hostAgg.buckets.length).toBeGreaterThan(0);

      const det = await dpCold.detectionTest({
        name: "sysmon-powershell",
        q: "process.name:powershell.exe",
      });
      expect(det.total).toBeGreaterThanOrEqual(0);

      // Arkime sessions & JA4 fingerprints
      const tArk0 = performance.now();
      const arkAll = await dpCold.arkimeSessions({ length: 25 });
      arkMs = performance.now() - tArk0;
      expect(arkAll.recordsFiltered).toBeGreaterThan(1_000);
      expect(arkAll.returned).toBe(25);

      const ja4Unique = await dpCold.arkimeUnique({ field: "tls.ja4", counts: 1 });
      expect(ja4Unique.values.length).toBeGreaterThan(0);
      firstJa4 = ja4Unique.values[0]!.value;
      // FoxIO JA4 format: 10-char section_a + "_" + 12-hex cipher hash + "_" + 12-hex ext hash
      expect(firstJa4).toMatch(/^t(?:13|12|11|10)[di]\d{4}[A-Za-z0-9]{2}_[0-9a-f]{12}_[0-9a-f]{12}$/);

      // TLS SNI aliased into host.http!
      const httpHostUnique = await dpCold.arkimeUnique({ field: "host.http", counts: 1 });
      expect(httpHostUnique.values.length).toBeGreaterThan(0);

      // packet_fields TLS JA4 verification
      const tPkt0 = performance.now();
      const tlsFrames = await dpCold.packetFields({
        filter: `tls.handshake.ja4 == "${firstJa4}"`,
        fields: "frame.number,ip.src,ip.dst,tls.handshake.ja4,tls.handshake.extensions_server_name,http.host",
        length: 10,
      });
      pktMs = performance.now() - tPkt0;
      expect(tlsFrames.returned).toBeGreaterThan(0);
      const sampleFrameNum = Number(tlsFrames.rows[0]!["frame.number"]);
      expect(sampleFrameNum).toBeGreaterThanOrEqual(1);
      expect(tlsFrames.rows[0]!["tls.handshake.ja4"]).toBe(firstJa4);

      // Threat intel lookup: read first indicator from intel.jsonl to verify exact match + ioc-* citation
      const firstIntelLine = fs
        .readFileSync(path.join(caseDir, "intel.jsonl"), "utf8")
        .split(/\r?\n/)
        .find((l) => l.trim().length > 0)!;
      const parsedIntel = JSON.parse(firstIntelLine) as {
        indicator?: { value?: string };
        event?: { id?: string };
      };
      const indicatorVal = parsedIntel.indicator?.value ?? "example.org";
      const intelRes = await dpCold.intelLookup({
        values: `${indicatorVal.toUpperCase()},DEFINITELY-NOT-IN-FEED.EXAMPLE`,
      });
      expect(intelRes.matches.length).toBeGreaterThanOrEqual(1);
      expect(intelRes.unmatched).toEqual(["DEFINITELY-NOT-IN-FEED.EXAMPLE"]);
      const sampleIocId =
        (intelRes.matches[0]!["event.id"] as string | undefined) ?? parsedIntel.event?.id;

      // Verify citations across evt-*, frame-*, and ioc-*
      const citationsToVerify = [
        sampleEvtId,
        `frame-${sampleFrameNum}`,
        ...(sampleIocId ? [sampleIocId] : []),
      ];
      const ver = dpCold.verifyCitations(citationsToVerify);
      expect(ver.allValid).toBe(true);
    } finally {
      await dpCold.close();
    }

    // 2. Warm attach benchmark on 20,931-event + 45,836-packet SQLite snapshot (< 20ms!)
    // Best of up to three attaches, so a load spike can't fail the documented < 20 ms claim.
    let warmMs = Number.POSITIVE_INFINITY;
    let dpWarm = undefined as unknown as Awaited<ReturnType<typeof EmbeddedHuntDataPlane.open>>;
    for (let attempt = 0; attempt < 3; attempt++) {
      const tWarm0 = performance.now();
      const attached = await EmbeddedHuntDataPlane.open(caseDir, {
        cacheDir,
      });
      const ms = performance.now() - tWarm0;
      if (attempt > 0) await dpWarm.close();
      dpWarm = attached;
      warmMs = Math.min(warmMs, ms);
      if (warmMs < 20) break;
    }
    try {
      expect(warmMs).toBeLessThan(20);

      const warmQuick = await dpWarm.huntLabQuery({ dataset: "network", limit: 5 });
      expect(warmQuick).toMatchObject({ dataset: "network", returned: 5, read_only: true });
    } finally {
      await dpWarm.close();
    }

    console.log(
      `[BENCHMARK] lab-med-001: cold=${coldMs.toFixed(1)}ms, warm=${warmMs.toFixed(2)}ms (<20ms), esSearch=${searchMs.toFixed(2)}ms, arkime=${arkMs.toFixed(2)}ms, packetFields=${pktMs.toFixed(2)}ms, sampleJA4=${firstJa4}`,
    );
    // Cold indexing of the 48 MB case is measured, not asserted; it takes ~5 s idle and 30 s+ under load.
  }, 180_000);
});
