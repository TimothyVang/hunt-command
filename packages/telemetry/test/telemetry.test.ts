import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { RuntimeFenceError } from "@hunt-command/shared";
import {
  ContentAddressedZstdBlobStore,
  EgressGuard,
  EgressGuardError,
  exportOtlpLoopback,
  guardEgress,
  HuntTelemetryStore,
  OtlpExportError,
  scrubQueryPreview,
  scrubSecrets,
  scrubSecretsValue,
  validateOtlpLoopbackUrl,
} from "../src/index.ts";

describe("@hunt-command/telemetry — Hot SQLite WAL, Cold Zstd, Scrubber, OTLP & Rule 4 EgressGuard", () => {
  let tmpRoot: string;

  beforeAll(() => {
    tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hunt-telemetry-test-"));
  });

  afterAll(() => {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  });

  test("enforces RuntimeFenceError inside Git checkouts and configures WAL + 64MiB journal_size_limit", () => {
    const insideGitDb = path.join(import.meta.dir, "forbidden-inside-git.sqlite");
    expect(
      () =>
        new HuntTelemetryStore({
          dbPath: insideGitDb,
          blobsDir: path.join(tmpRoot, "fence-blobs"),
        }),
    ).toThrow(RuntimeFenceError);
    expect(fs.existsSync(insideGitDb)).toBe(false);

    const dbPath = path.join(tmpRoot, "pragmas", "hunt_telemetry.sqlite");
    const blobsDir = path.join(tmpRoot, "pragmas", "blobs");
    const store = new HuntTelemetryStore({ dbPath, blobsDir });
    try {
      const pragmas = store.getJournalPragmas();
      expect(pragmas.journalMode.toLowerCase()).toBe("wal");
      expect(pragmas.synchronous).toBe(1); // NORMAL
      expect(pragmas.journalSizeLimit).toBe(67_108_864);
    } finally {
      store.close();
    }
  });

  test("scrubs all credential families deterministically before hot/cold storage and wire return", () => {
    const rawSamples = [
      "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig",
      "Authorization: ApiKey dGVzdC1hcGkta2V5LWJhc2U2NA==",
      // health: allow FORBIDDEN_TOKEN -- synthetic scrubber test fixture
      "Anthropic key sk-ant-api03-SyntheticTestKeyValue1234567890 leaked",
      "OpenAI key sk-proj-SyntheticOpenAiSecretValue1234567890 leaked",
      // health: allow FORBIDDEN_TOKEN -- synthetic scrubber test fixture
      "Slack tokens xoxb-123456-789012-abcdef123456 and xapp-1-A0123-45678-xyz9876",
      // health: allow FORBIDDEN_TOKEN -- synthetic scrubber test fixture
      "GitHub tokens ghp_SyntheticGitHubPat1234567890 and gho_SyntheticOAuthToken1234567890",
      // health: allow FORBIDDEN_TOKEN -- synthetic scrubber test fixture
      "AWS access key AKIAIOSFODNN7EXAMPLE in log",
      "Cookie: SID=secret_session_cookie_value; csrftoken=xyz123",
      '{"refresh_token":"rt_live_super_secret_refresh_999","nestedUrl":"https://elastic:s3cr3tP@ss@es.corp.internal:9200/_search"}',
    ].join("\n");

    const scrubbed = scrubSecrets(rawSamples);
    expect(scrubbed).not.toContain("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
    expect(scrubbed).not.toContain("dGVzdC1hcGkta2V5LWJhc2U2NA==");
    expect(scrubbed).not.toContain("SyntheticTestKeyValue1234567890");
    expect(scrubbed).not.toContain("SyntheticOpenAiSecretValue1234567890");
    expect(scrubbed).not.toContain("abcdef123456");
    expect(scrubbed).not.toContain("SyntheticGitHubPat1234567890");
    expect(scrubbed).not.toContain("SyntheticOAuthToken1234567890");
    expect(scrubbed).not.toContain("IOSFODNN7EXAMPLE");
    expect(scrubbed).not.toContain("secret_session_cookie_value");
    expect(scrubbed).not.toContain("rt_live_super_secret_refresh_999");
    expect(scrubbed).not.toContain("s3cr3tP@ss");
    expect(scrubbed).toContain("https://[REDACTED_URL_CREDENTIALS]@es.corp.internal:9200/_search");

    const nestedObj = scrubSecretsValue({
      headers: {
        Authorization: "Bearer super_secret_bearer_987654321",
        Cookie: "session_id=top_secret_cookie_abc",
      },
      refresh_token: "oauth_refresh_secret_value_abc",
    });
    expect(JSON.stringify(nestedObj)).not.toContain("super_secret_bearer_987654321");
    expect(JSON.stringify(nestedObj)).not.toContain("top_secret_cookie_abc");
    expect(JSON.stringify(nestedObj)).not.toContain("oauth_refresh_secret_value_abc");

    // UTF-8 safe 512B truncation on multi-byte characters
    const multiByte = `process.name:powershell.exe AND message:"${"🔥".repeat(200)}"`;
    const preview = scrubQueryPreview(multiByte, 512);
    expect(Buffer.byteLength(preview, "utf8")).toBeLessThanOrEqual(512);
    expect(preview.includes("\uFFFD")).toBe(false);
  });

  test("deduplicates multi-turn cached conversation prefixes to 0 extra bytes in cold Zstd blob store & detects tampering", () => {
    const blobsDir = path.join(tmpRoot, "cold-zstd", "blobs");
    const blobStore = new ContentAddressedZstdBlobStore(blobsDir);

    const sysPrompt = {
      role: "system",
      content: `You are SIEM Analyst. ${"Cached playbook rules. ".repeat(80)}`,
    };
    const userBrief = {
      role: "user",
      // health: allow FORBIDDEN_TOKEN -- synthetic scrubber test fixture
      content: "Investigate host WS-FIN-04 (ignore leaked token ghp_SyntheticShouldBeScrubbed9999)",
    };
    const assistantTurn1 = {
      role: "assistant",
      content: "Running initial elastic_search on WS-FIN-04.",
    };

    const turn1 = blobStore.putMessages([sysPrompt, userBrief, assistantTurn1]);
    expect(turn1.hashes).toHaveLength(3);
    expect(turn1.deduplicatedCount).toBe(0);
    expect(turn1.compressedBytesWritten).toBeGreaterThan(0);

    // Turn 2 appends tool output + assistant synthesis while re-sending the exact 3 prefix blocks
    const toolResultTurn2 = {
      role: "tool",
      content: '{"hits":[{"event.id":"evt-00001"}]}',
    };
    const assistantTurn2 = {
      role: "assistant",
      content: "Confirmed PowerShell encoded command in [evt-00001].",
    };

    const turn2 = blobStore.putMessages([
      sysPrompt,
      userBrief,
      assistantTurn1,
      toolResultTurn2,
      assistantTurn2,
    ]);
    expect(turn2.hashes).toHaveLength(5);
    expect(turn2.hashes.slice(0, 3)).toEqual(turn1.hashes);
    expect(turn2.deduplicatedCount).toBe(3);

    // Re-putting the exact 5 messages writes 0 extra bytes on disk!
    const turn2Repeat = blobStore.putMessages([
      sysPrompt,
      userBrief,
      assistantTurn1,
      toolResultTurn2,
      assistantTurn2,
    ]);
    expect(turn2Repeat.deduplicatedCount).toBe(5);
    expect(turn2Repeat.compressedBytesWritten).toBe(0);

    // Verify <aa>/<sha256>.zst sharded layout and secret scrubbing before disk compression
    const firstHash = turn1.hashes[1]!;
    const expectedPath = path.join(blobsDir, firstHash.slice(0, 2), `${firstHash}.zst`);
    expect(fs.existsSync(expectedPath)).toBe(true);

    const roundTripped = blobStore.getMessages(turn2.hashes) as Array<{ content: string }>;
    expect(roundTripped).toHaveLength(5);
    expect(roundTripped[1]!.content).not.toContain("SyntheticShouldBeScrubbed9999");
    expect(roundTripped[1]!.content).toContain("[REDACTED_GITHUB_PAT]");

    // Corrupting the decompressed payload or .zst file triggers integrity failure
    const fakeCompressed = Bun.zstdCompressSync(Buffer.from('{"tampered":true}', "utf8"));
    fs.writeFileSync(expectedPath, fakeCompressed);
    expect(() => blobStore.getBlock(firstHash)).toThrow(/Integrity failure/i);
  });

  test("records full OTel GenAI + OpenInference span hierarchy, cyber refusals, shadow USD cost, <1ms lineage & coach trends", () => {
    const dbPath = path.join(tmpRoot, "hierarchy", "hunt_telemetry.sqlite");
    const blobsDir = path.join(tmpRoot, "hierarchy", "blobs");
    const store = new HuntTelemetryStore({ dbPath, blobsDir });

    try {
      const huntId = "hunt-20261114-001";
      const t0 = 1_763_150_000_000;

      const runSpan = store.recordRunSpan({
        huntId,
        caseId: "dns-lab-001",
        dataOrigin: "synthetic",
        mode: "supervised",
        startTimeMs: t0,
      });
      expect(runSpan.name).toBe("hunt.run");
      expect(runSpan.openInferenceKind).toBe("CHAIN");

      // Immutable data_origin check
      expect(() =>
        store.recordRunSpan({
          huntId,
          caseId: "dns-lab-001",
          dataOrigin: "work-export",
          startTimeMs: t0,
        }),
      ).toThrow(/Immutable data_origin violation/);

      const scopeGate = store.recordGateDecisionSpan({
        huntId,
        parentSpanId: runSpan.spanId,
        wave: "scope",
        gateId: "gate-scope-1",
        gateKind: "scope",
        humanRequired: true,
        choice: "approve",
        decidedBy: "operator-local",
        via: "desktop",
        startTimeMs: t0 + 10,
        endTimeMs: t0 + 110,
      });
      expect(scopeGate.name).toBe("hunt.gate.decision");
      expect(scopeGate.openInferenceKind).toBe("GUARDRAIL");

      const wave1 = store.recordWaveSpan({
        huntId,
        parentSpanId: runSpan.spanId,
        wave: "investigation",
        waveIndex: 2,
        parallel: true,
        stepIds: ["evidence", "network"],
        startTimeMs: t0 + 120,
        endTimeMs: t0 + 900,
      });

      // Bot step 1: Researcher succeeds with OAuth subscription ($0 actual, >$0 API shadow cost) + lineage claims
      const siemStep = store.recordBotStepSpan({
        huntId,
        parentSpanId: wave1.spanId,
        wave: "investigation",
        stepId: "evidence",
        botProfile: "framework-researcher",
        stepStatus: "done",
        startTimeMs: t0 + 130,
        endTimeMs: t0 + 650,
      });

      const chat1 = store.recordChatSpan({
        huntId,
        parentSpanId: siemStep.spanId,
        wave: "investigation",
        stepId: "evidence",
        botProfile: "framework-researcher",
        providerName: "anthropic",
        model: "claude-opus-4-6",
        inputTokens: 2_000,
        cacheReadTokens: 18_000,
        cacheWriteTokens: 0,
        outputTokens: 1_000,
        billingMode: "oauth_subscription",
        finishReasons: ["tool_use"],
        messages: [
          { role: "system", content: "Threat Hunter system prompt" },
          { role: "user", content: "Check DNS tunneling" },
        ],
        startTimeMs: t0 + 140,
        endTimeMs: t0 + 380,
      });
      expect(chat1.attributes["hunt.cache.hit_ratio"]).toBe(0.9);
      expect(chat1.attributes["hunt.cost.actual_usd"]).toBe(0);
      expect(Number(chat1.attributes["hunt.cost.api_equivalent_usd"])).toBeGreaterThan(0);

      const tool1 = store.recordToolSpan({
        huntId,
        parentSpanId: siemStep.spanId,
        wave: "investigation",
        stepId: "evidence",
        botProfile: "framework-researcher",
        toolName: "elastic_search",
        actionOrEndpoint: "/es/search",
        // health: allow FORBIDDEN_TOKEN -- synthetic scrubber test fixture
        queryText: `event.dataset:dns AND Authorization: Bearer secret123 AND sk-ant-SyntheticKey9999 ${"x".repeat(700)}`,
        resultCount: 3,
        totalHits: 3,
        blockedRequests: 0,
        returnedIds: ["evt-00001", "evt-00002", "evt-00003"],
        rawResultPayload: { hits: [{ "event.id": "evt-00001" }] },
        startTimeMs: t0 + 390,
        endTimeMs: t0 + 440,
      });
      const preview = String(tool1.attributes["hunt.tool.query_text"]);
      expect(Buffer.byteLength(preview, "utf8")).toBeLessThanOrEqual(512);
      expect(preview).not.toContain("secret123");
      expect(preview).not.toContain("SyntheticKey9999");
      expect(tool1.blobHash).toMatch(/^[0-9a-f]{64}$/);

      const handoff = store.recordHandoffValidateSpan({
        huntId,
        parentSpanId: siemStep.spanId,
        wave: "investigation",
        stepId: "evidence",
        botProfile: "framework-researcher",
        disposition: "suspicious",
        claims: [
          {
            claim_id: "siem-c01",
            kind: "finding",
            statement:
              "DNS TXT exfiltration observed in [evt-00001] and [frame-0007] matching [ioc-00003].",
          },
          {
            claim_id: "siem-c02",
            kind: "observed",
            statement: "Follow-up query in [evt-00002] corroborated [evt-00001].",
          },
        ],
        startTimeMs: t0 + 600,
        endTimeMs: t0 + 645,
      });
      expect(handoff.lineageRows).toHaveLength(5);

      // Bot step 2: Network Analyst encounters cyber safety refusal (`hunt.safety.declined = true`)
      const ndrRefused = store.recordBotStepSpan({
        huntId,
        parentSpanId: wave1.spanId,
        wave: "investigation",
        stepId: "network",
        botProfile: "framework-network-analyst",
        stepStatus: "dropped",
        safetyDeclined: true,
        safetyFinishReason: "refusal",
        startTimeMs: t0 + 135,
        endTimeMs: t0 + 310,
      });
      expect(ndrRefused.attributes["hunt.safety.declined"]).toBe(true);
      expect(ndrRefused.attributes["hunt.safety.finish_reason"]).toBe("refusal");
      expect(ndrRefused.attributes["hunt.safety.category"]).toBe("cyber");
      expect(ndrRefused.status).toBe("error");

      // Finalize run span & record Coach evaluation
      store.recordRunSpan({
        huntId,
        spanId: runSpan.spanId,
        traceId: runSpan.traceId,
        caseId: "dns-lab-001",
        dataOrigin: "synthetic",
        mode: "supervised",
        startTimeMs: t0,
        endTimeMs: t0 + 1_000,
        completed: true,
      });

      store.recordCoachEvalSpan({
        huntId,
        parentSpanId: runSpan.spanId,
        iteration: 1,
        track: "playbook",
        stage: "judge",
        meanFound: 0.92,
        attackFound: 1.0,
        misattributedDecoys: 0,
        citationPrecision: 1.0,
        g2_1Pass: true,
        promoted: true,
        startTimeMs: t0 + 1_010,
        endTimeMs: t0 + 1_090,
      });

      // Verify <1ms indexed claim_evidence_lineage click-through lookup
      const startLookup = performance.now();
      for (let i = 0; i < 100; i++) {
        const claimsEvt = store.getClaimsForEvidence(huntId, "evt-00001");
        expect(claimsEvt.map((c) => c.claimId)).toEqual(["siem-c01", "siem-c02"]);
      }
      const avgLookupMs = (performance.now() - startLookup) / 100;
      expect(avgLookupMs).toBeLessThan(1.0);

      // Frame normalization (`frame-0007` -> `frame-7`)
      const frameClaims = store.getClaimsForEvidence(huntId, "frame-0007");
      expect(frameClaims).toHaveLength(1);
      expect(frameClaims[0]!.evidenceId).toBe("frame-7");

      const claimEv = store.getEvidenceForClaim(huntId, "siem-c01");
      expect(claimEv.map((e) => e.evidenceId)).toEqual(["evt-00001", "frame-7", "ioc-00003"]);

      // Verify Waterfall hierarchy & Cost Summary & Coach Trends
      const wf = store.getRunWaterfall(huntId);
      expect(wf).not.toBeNull();
      expect(wf!.completed).toBe(true);
      expect(wf!.spans.length).toBe(9);
      const chatEntry = wf!.spans.find((s) => s.name === "gen_ai.chat")!;
      expect(chatEntry.depth).toBe(3); // run (0) -> wave (1) -> bot.step (2) -> chat (3)

      const cost = store.getRunCostSummary(huntId);
      expect(cost.cyberRefusalCount).toBe(1);
      expect(cost.totalPromptTokens).toBe(20_000);
      expect(cost.cacheHitRatio).toBe(0.9);
      expect(cost.actualUsd).toBe(0);
      expect(cost.apiEquivalentUsd).toBeGreaterThan(0);
      expect(cost.byProfile["framework-researcher"]!.chatSpanCount).toBe(1);

      const trends = store.getCoachTrends({ track: "playbook" });
      expect(trends).toHaveLength(1);
      expect(trends[0]!.g2_1Pass).toBe(true);
      expect(trends[0]!.totalTokens).toBe(21_000);
      expect(trends[0]!.apiEquivalentUsd).toBe(cost.apiEquivalentUsd);

      const ckpt = store.checkpointWal();
      expect(ckpt.busy).toBe(0);
    } finally {
      store.close();
    }
  });

  test("validates OTLP loopback URLs strictly, defeats HTTP_PROXY hijacks, rejects 3xx redirects, and gates work data", async () => {
    const forbiddenEndpoints = [
      "https://127.0.0.1:4318/v1/traces", // non-http
      "http://localhost:4318/v1/traces", // DNS name forbidden
      "http://0.0.0.0:4318/v1/traces", // wildcard bind address
      "http://[::]:4318/v1/traces", // IPv6 wildcard
      "http://[::ffff:127.0.0.1]:4318/v1/traces", // IPv4-mapped IPv6
      "http://0177.0.0.1:4318/v1/traces", // octal IP
      "http://0x7f000001:4318/v1/traces", // hex IP
      "http://2130706433:4318/v1/traces", // integer IP
      "http://user:pass@127.0.0.1:4318/v1/traces", // userinfo
      "http://127.0.0.1:4318/v1/traces?token=abc", // query string
      "http://127.0.0.1:4318/v1/traces#frag", // hash fragment
      "http://127.0.0.1:80/v1/traces", // privileged port < 1024
      "http://192.168.1.10:4318/v1/traces", // RFC1918 LAN IP
    ];

    for (const bad of forbiddenEndpoints) {
      expect(() => validateOtlpLoopbackUrl(bad)).toThrow(OtlpExportError);
    }

    expect(() =>
      validateOtlpLoopbackUrl("http://127.0.0.1:18443/v1/traces", {
        internalBoundPorts: [18443],
      }),
    ).toThrow(/collides with an internal Hunt Command bound port/);

    const validIpv6 = validateOtlpLoopbackUrl("http://[::1]:4318");
    expect(validIpv6.hostname).toBe("::1");
    expect(validIpv6.pathname).toBe("/v1/traces");

    // Spin up a rogue HTTP_PROXY server and a genuine loopback OTLP collector
    let proxyHits = 0;
    let collectorBodies: string[] = [];

    const proxyServer = http.createServer((_req, res) => {
      proxyHits += 1;
      res.writeHead(200);
      res.end("hijacked-by-proxy");
    });
    const collectorServer = http.createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        collectorBodies.push(Buffer.concat(chunks).toString("utf8"));
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end("{}");
      });
    });
    const redirectServer = http.createServer((_req, res) => {
      res.writeHead(302, { Location: "http://198.51.100.99:4318/steal" });
      res.end();
    });

    await Promise.all([
      new Promise<void>((r) => proxyServer.listen(0, "127.0.0.1", () => r())),
      new Promise<void>((r) => collectorServer.listen(0, "127.0.0.1", () => r())),
      new Promise<void>((r) => redirectServer.listen(0, "127.0.0.1", () => r())),
    ]);

    const proxyPort = (proxyServer.address() as { port: number }).port;
    const collectorPort = (collectorServer.address() as { port: number }).port;
    const redirectPort = (redirectServer.address() as { port: number }).port;

    const prevHttpProxy = process.env.HTTP_PROXY;
    const prevAllProxy = process.env.ALL_PROXY;
    process.env.HTTP_PROXY = `http://127.0.0.1:${proxyPort}`;
    process.env.ALL_PROXY = `http://127.0.0.1:${proxyPort}`;

    try {
      const sampleSpan = {
        spanId: "0102030405060708",
        traceId: "0102030405060708090a0b0c0d0e0f10",
        parentSpanId: null,
        huntId: "hunt-otlp-1",
        name: "hunt.run" as const,
        openInferenceKind: "CHAIN" as const,
        wave: null,
        stepId: null,
        botProfile: null,
        startTimeMs: 1_763_150_000_000,
        endTimeMs: 1_763_150_000_250,
        durationMs: 250,
        status: "ok" as const,
        errorCode: null,
        // health: allow FORBIDDEN_TOKEN -- synthetic scrubber test fixture
        attributes: { "hunt.note": "Bearer leaked_secret_xyz and ghp_SyntheticToken12345" },
        messageHashes: [],
        blobHash: null,
      };

      // Work data defaults OFF unless allowLocalOtlpOnWorkData === true
      const skipped = await exportOtlpLoopback({
        endpoint: `http://127.0.0.1:${collectorPort}/v1/traces`,
        spans: [sampleSpan],
        syntheticOnly: false,
        dataOrigin: "work-export",
      });
      expect(skipped.exported).toBe(false);
      expect(skipped.skippedReason).toBe("work_data_otlp_disabled");
      expect(collectorBodies).toHaveLength(0);

      // Synthetic data exports directly over loopback, completely ignoring HTTP_PROXY!
      const exported = await exportOtlpLoopback({
        endpoint: `http://127.0.0.1:${collectorPort}/v1/traces`,
        spans: [sampleSpan],
        syntheticOnly: true,
        dataOrigin: "synthetic",
      });
      expect(exported.exported).toBe(true);
      expect(exported.exportedSpanCount).toBe(1);
      expect(proxyHits).toBe(0);
      expect(collectorBodies).toHaveLength(1);
      expect(collectorBodies[0]).not.toContain("leaked_secret_xyz");
      expect(collectorBodies[0]).not.toContain("SyntheticToken12345");

      // 302 redirect is strictly rejected
      await expect(
        exportOtlpLoopback({
          endpoint: `http://127.0.0.1:${redirectPort}/v1/traces`,
          spans: [sampleSpan],
          syntheticOnly: true,
          dataOrigin: "synthetic",
        }),
      ).rejects.toThrow(/Refusing HTTP 302 redirect/);
    } finally {
      if (prevHttpProxy === undefined) delete process.env.HTTP_PROXY;
      else process.env.HTTP_PROXY = prevHttpProxy;
      if (prevAllProxy === undefined) delete process.env.ALL_PROXY;
      else process.env.ALL_PROXY = prevAllProxy;

      await Promise.all([
        new Promise<void>((r) => proxyServer.close(() => r())),
        new Promise<void>((r) => collectorServer.close(() => r())),
        new Promise<void>((r) => redirectServer.close(() => r())),
      ]);
    }
  });

  test("enforces Code-Level Rule 4 EgressGuard hard-stripping on all non-synthetic origins", () => {
    for (const origin of ["public-dataset", "work-export", "work-connected"] as const) {
      const card = guardEgress(
        {
          hunt_uuid: "0f5e4d3c-2b1a-4978-8abc-0123456789ab",
          data_origin: origin,
          synthetic_only: false,
          wave: "incident",
          gate_kind: "incident",
          status_enum: "awaiting_approval",
          opened_at_utc: "2026-11-14T20:15:00Z",
          reason_code: "incident_threshold_met",
          counters: {
            input_tokens: 4_000,
            cache_read_tokens: 16_000,
            cache_write_tokens: 0,
            output_tokens: 800,
            actual_usd: 0,
            api_equivalent_usd: 0.145,
          },
          // Sensitive fields that MUST be stripped:
          case_id: "corp-ir-2026-99",
          summary: "Host DC01.corp.local compromised from 185.220.101.4 via evil-c2.example",
          query_text: 'host.name:"DC01.corp.local" AND source.ip:185.220.101.4',
          messages: [{ role: "assistant", content: "Confirmed C2 beacon [evt-00001234]" }],
          statement: "Active domain controller compromise [evt-00001234] [ioc-00099]",
          outputs_dir: "C:\\Users\\analyst\\cases\\corp-ir-2026-99\\outputs",
          hostnames: ["DC01.corp.local"],
          ips: ["185.220.101.4", "10.10.1.5"],
          domains: ["evil-c2.example"],
          citations: ["evt-00001234", "ioc-00099", "frame-42"],
          custom_secret_blob: "raw-windows-command-line",
        },
        { includeSummaryOnSynthetic: true },
      );

      expect(Object.keys(card).sort()).toEqual([
        "counters",
        "gate_kind",
        "hunt_uuid",
        "opened_at_utc",
        "reason_code",
        "status_enum",
        "wave",
      ]);

      const serializedJson = JSON.stringify(card);
      expect(serializedJson).not.toContain("corp-ir-2026-99");
      expect(serializedJson).not.toContain("DC01");
      expect(serializedJson).not.toContain("185.220.101.4");
      expect(serializedJson).not.toContain("evil-c2.example");
      expect(serializedJson).not.toContain("evt-00001234");
      expect(serializedJson).not.toContain("ioc-00099");
      expect(serializedJson).not.toContain("C:\\\\Users");
      expect(card.counters?.cache_hit_ratio).toBe(0.8);
    }

    // Even if a caller lies and passes synthetic_only: true while data_origin === "work-export", fail-closed!
    const spoofed = guardEgress({
      hunt_uuid: "0f5e4d3c-2b1a-4978-8abc-0123456789ab",
      data_origin: "work-export",
      synthetic_only: true,
      wave: "investigation",
      gate_kind: "wave",
      status_enum: "running",
      opened_at_utc: "2026-11-14T20:16:00Z",
      summary: "Sensitive host CORP-SQL-01",
    });
    expect("summary" in spoofed).toBe(false);
    expect("synthetic_only" in spoofed).toBe(false);

    // Reject free-text reason_code or sensitive hunt_uuid
    expect(() =>
      guardEgress({
        hunt_uuid: "0f5e4d3c-2b1a-4978-8abc-0123456789ab",
        data_origin: "work-connected",
        synthetic_only: false,
        wave: "scope",
        gate_kind: "scope",
        status_enum: "halted",
        opened_at_utc: "2026-11-14T20:17:00Z",
        reason_code: "Host DC01 compromised at 10.0.0.1",
      }),
    ).toThrow(EgressGuardError);

    expect(() =>
      guardEgress({
        hunt_uuid: "evt-00001234",
        data_origin: "work-connected",
        synthetic_only: false,
        wave: "scope",
        gate_kind: "scope",
        status_enum: "halted",
        opened_at_utc: "2026-11-14T20:17:00Z",
      }),
    ).toThrow(EgressGuardError);

    // Notification blocks include explicit non-synthetic operator warning
    const block = EgressGuard.buildGateNotificationBlocks({
      hunt_uuid: "0f5e4d3c-2b1a-4978-8abc-0123456789ab",
      data_origin: "work-connected",
      synthetic_only: false,
      wave: "incident",
      gate_kind: "incident",
      status_enum: "awaiting_approval",
      opened_at_utc: "2026-11-14T20:18:00Z",
      summary: "MUST NOT APPEAR",
    });
    expect(block.warningBanner).toContain("WARNING: NON-SYNTHETIC DATA");
    expect(block.text).not.toContain("MUST NOT APPEAR");

    // Film export guard
    expect(() =>
      EgressGuard.assertFilmExportAllowed({
        dataOrigin: "work-export",
        syntheticOnly: false,
      }),
    ).toThrow(/work_film_not_allowed|Refusing \.mp4/);

    const overriddenFilm = EgressGuard.assertFilmExportAllowed({
      dataOrigin: "work-export",
      syntheticOnly: false,
      allowWorkFilm: true,
    });
    expect(overriddenFilm.watermarkBanner).toBe("NON-SYNTHETIC — OPERATOR LOCAL ONLY");
  });

  test("rejects raw identifiers at every non-synthetic egress boundary", () => {
    const record = {
      hunt_uuid: "0f5e4d3c-2b1a-4978-8abc-0123456789ab",
      data_origin: "work-connected",
      synthetic_only: false,
      wave: "scope",
      gate_kind: "scope",
      status_enum: "awaiting_approval",
      opened_at_utc: "2026-11-14T20:18:00Z",
      reason_code: "awaiting_human_scope",
    } as const;
    for (const data_origin of [
      "synthetic",
      "public-dataset",
      "work-export",
      "work-connected",
    ] as const) {
      for (const synthetic_only of [false, true]) {
        if (data_origin === "synthetic" && synthetic_only) continue;
        for (const hunt_uuid of [
          "dc01",
          "dc01.corp.local",
          "evil-c2.example",
          "analyst_alice",
          "corp-ir-2026-99",
          "evt-00001234",
          "10.20.30.40",
          "C:\\Users\\analyst\\case",
          "0f5e4d3c2b1a49788abc0123456789ab",
          "0f5e4d3c-2b1a-1978-8abc-0123456789ab",
          "0f5e4d3c-2b1a-4978-7abc-0123456789ab",
          "00000000-0000-0000-0000-000000000000",
          "0f5e4d3c-2b1a-4978-8abc-0123456789ab\n",
        ]) {
          expect(() =>
            guardEgress({ ...record, data_origin, synthetic_only, hunt_uuid }),
          ).toThrow(/hunt_uuid must/);
          expect(() =>
            EgressGuard.buildGateNotificationBlocks({
              ...record,
              data_origin,
              synthetic_only,
              hunt_uuid,
            }),
          ).toThrow(/hunt_uuid must/);
        }
      }
    }
  });

  test("serializes only registered reason codes with an opaque hunt UUID", () => {
    const record = {
      hunt_uuid: "0f5e4d3c-2b1a-4978-8abc-0123456789ab",
      data_origin: "work-connected",
      synthetic_only: false,
      wave: "scope",
      gate_kind: "scope",
      status_enum: "awaiting_approval",
      opened_at_utc: "2026-11-14T20:18:00Z",
    } as const;
    for (const reason_code of [
      "dc01",
      "analyst_alice",
      "corp_ir_2026_99",
      "sensitive_investigation",
      "dc01.corp.local",
      "incident_threshold_met_dc01",
      "Host DC01 compromised at 10.0.0.1",
    ]) {
      expect(() => guardEgress({ ...record, reason_code })).toThrow(/registered/);
      expect(() =>
        EgressGuard.buildGateNotificationBlocks({ ...record, reason_code }),
      ).toThrow(/registered/);
    }
    for (const reason_code of ["awaiting_human_scope", "incident_threshold_met"] as const) {
      const block = EgressGuard.buildGateNotificationBlocks({ ...record, reason_code });
      expect(block.payload).toEqual({
        hunt_uuid: record.hunt_uuid,
        wave: record.wave,
        gate_kind: record.gate_kind,
        status_enum: record.status_enum,
        opened_at_utc: record.opened_at_utc,
        reason_code,
      });
      expect(block.text).toContain(`hunt=${record.hunt_uuid}`);
      expect(block.text).toContain(`reason=${reason_code}`);
    }
    for (const reason_code of [undefined, null, ""]) {
      expect(guardEgress({ ...record, reason_code }).reason_code).toBeNull();
    }
  });

  test("preserves friendly synthetic hunt IDs only with both synthetic provenance flags", () => {
    const card = guardEgress(
      {
        hunt_uuid: "hunt-synthetic-lab",
        data_origin: "synthetic",
        synthetic_only: true,
        wave: "scope",
        gate_kind: "scope",
        status_enum: "awaiting_approval",
        opened_at_utc: "2026-11-14T20:18:00Z",
        reason_code: "awaiting_human_scope",
        case_id: "synthetic-case",
        summary: "Invented lab host",
      },
      { includeSummaryOnSynthetic: true },
    );
    expect(card).toMatchObject({
      hunt_uuid: "hunt-synthetic-lab",
      synthetic_only: true,
      case_id: "synthetic-case",
      summary: "Invented lab host",
      reason_code: "awaiting_human_scope",
    });
  });
});
