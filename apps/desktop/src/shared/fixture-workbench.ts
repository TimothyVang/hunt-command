import {
  CaseMetadataSchema,
  HandoffSchema,
  ROLE_TOOL_OWNERSHIP,
  SnapshotSchema,
  computeCostAccounting,
  getAllowedToolsForStep,
  type DataOrigin,
  type HuntToolName,
  type ProfileId,
} from "@hunt-command/shared";
import { computeCitationVerificationReceipt } from "./gate-validation.ts";
import type {
  ActiveGatePrompt,
  DissectorArkimeRow,
  DissectorEventRow,
  DissectorPacketRow,
  EnrichedClaimRow,
  EvidenceRecordDetail,
  GanttSpanRecord,
  StepExecutionSummary,
  WorkbenchSnapshot,
} from "./workbench-types.ts";

export interface FixtureOptions {
  huntId?: string;
  dataOrigin?: DataOrigin;
  openGate?: "scope" | "incident" | "reconcile" | null;
  injectUnresolvedCitation?: boolean;
}

const SCOPE_DIGEST = "8a4f2c91e0b74d6153c2f8901a7e3b5d6c4029f8e1a3b7c5d9012e4f6a8b0c1d";
const INCIDENT_DIGEST = "3f9c1b84d2e07a65c194f02b8e3d7a615c904e2f1a8b3c7d6e50912a4f8c6b2e";
const RECONCILE_DIGEST = "5d2a7e90c1b48f36e205a91c7d4b8e630a195f2c4e8b7d3a6f50192e3c7b4a8f";

export function buildFixtureWorkbenchSnapshot(options: FixtureOptions = {}): WorkbenchSnapshot {
  const huntId = options.huntId ?? "hunt-20261115-nv01";
  const dataOrigin: DataOrigin = options.dataOrigin ?? "synthetic";
  const syntheticOnly = dataOrigin === "synthetic";
  const openGate = options.openGate === undefined ? "incident" : options.openGate;

  const caseMetadata = CaseMetadataSchema.parse({
    case_id: "northvale-lab-001",
    title: "Northvale Scheduled Task & C2 DNS/TLS Beaconing Investigation",
    data_origin: dataOrigin,
    synthetic_only: syntheticOnly,
    time_window: {
      start_iso: "2026-11-14T14:00:00Z",
      end_iso: "2026-11-14T15:00:00Z",
    },
    sources: ["lab-case-events", "lab-case-pcap", "lab-case-intel"],
    pcap_relpath: "traffic.pcap",
  });

  const snapshot = SnapshotSchema.parse({
    schema_version: 1,
    case_id: "northvale-lab-001",
    entities: [
      {
        entity_id: "host:wks-fin-07",
        kind: "host",
        label: "wks-fin-07.northvale.test (10.20.2.107)",
        evidence_ids: ["lab-case-events"],
      },
      {
        entity_id: "acct:svc_sync",
        kind: "account",
        label: "NORTHVALE\\svc_sync",
        evidence_ids: ["lab-case-events"],
      },
      {
        entity_id: "proc:usersynchelper",
        kind: "process",
        label: "C:\\ProgramData\\UserSync\\UserSyncHelper.exe (PID 6812)",
        evidence_ids: ["lab-case-events"],
      },
      {
        entity_id: "dom:cdn-telemetry.northvale-sync.test",
        kind: "domain",
        label: "cdn-telemetry.northvale-sync.test",
        evidence_ids: ["lab-case-pcap", "lab-case-intel"],
      },
      {
        entity_id: "addr:198.51.100.42",
        kind: "address",
        label: "198.51.100.42:443",
        evidence_ids: ["lab-case-pcap", "lab-case-intel"],
      },
      {
        entity_id: "host:wks-it-02",
        kind: "host",
        label: "wks-it-02.northvale.test (benign admin workstation)",
        evidence_ids: ["lab-case-events"],
      },
    ],
    relations: [
      {
        relation_id: "rel:acct-on-host",
        subject_id: "acct:svc_sync",
        predicate: "observed_on",
        object_id: "host:wks-fin-07",
        evidence_ids: ["lab-case-events"],
      },
      {
        relation_id: "rel:acct-spawn-proc",
        subject_id: "acct:svc_sync",
        predicate: "spawned",
        object_id: "proc:usersynchelper",
        evidence_ids: ["lab-case-events"],
      },
      {
        relation_id: "rel:proc-comm-dom",
        subject_id: "proc:usersynchelper",
        predicate: "communicates_with",
        object_id: "dom:cdn-telemetry.northvale-sync.test",
        evidence_ids: ["lab-case-events", "lab-case-pcap"],
      },
      {
        relation_id: "rel:dom-resolves-ip",
        subject_id: "dom:cdn-telemetry.northvale-sync.test",
        predicate: "resolves_to",
        object_id: "addr:198.51.100.42",
        evidence_ids: ["lab-case-pcap", "lab-case-intel"],
      },
    ],
  });

  const extraCitation = options.injectUnresolvedCitation ? " and evt-9999999999999999" : "";

  const evidenceHandoff = HandoffSchema.parse({
    schema_version: 1,
    case_id: "northvale-lab-001",
    step_id: "evidence",
    profile: "framework-researcher",
    claims: [
      {
        claim_id: "evidence:c1",
        kind: "observed",
        statement: `Scheduled task \\UserSyncHelper registered on wks-fin-07 under NORTHVALE\\svc_sync (evt-0000000000001042) spawning C:\\ProgramData\\UserSync\\UserSyncHelper.exe (evt-0000000000001048)${extraCitation}.`,
        evidence_ids: ["lab-case-events"],
        entity_ids: ["host:wks-fin-07", "acct:svc_sync", "proc:usersynchelper"],
        contradicts: [],
      },
      {
        claim_id: "evidence:c2",
        kind: "observed",
        statement:
          "Administrative PowerShell session on wks-it-02 (evt-0000000000001099) executed signed IT inventory scripts; wks-it-02 is benign maintenance activity, not part of the intrusion.",
        evidence_ids: ["lab-case-events"],
        entity_ids: ["host:wks-it-02"],
        contradicts: [],
      },
    ],
    reviews: [],
    disposition: "review_ready",
    limitations: ["Sysmon EventID 7 image-load telemetry was not enabled on wks-fin-07 during evt-0000000000001042."],
    requested_decisions: [],
  });

  const networkHandoff = HandoffSchema.parse({
    schema_version: 1,
    case_id: "northvale-lab-001",
    step_id: "network",
    profile: "framework-network-analyst",
    claims: [
      {
        claim_id: "network:c1",
        kind: "finding",
        statement:
          "wks-fin-07 (10.20.2.107) issued compressed DNS TXT queries to cdn-telemetry.northvale-sync.test resolving to 198.51.100.42 (frame-142) followed by TLS 1.3 HTTPS POST beacons to https://cdn-telemetry.northvale-sync.test/api/v2/checkin (frame-188, ioc-10042) with JA4 fingerprint t13d1516h2_8daaf6152771_b186095e22b6.",
        evidence_ids: ["lab-case-pcap", "lab-case-intel"],
        entity_ids: [
          "host:wks-fin-07",
          "dom:cdn-telemetry.northvale-sync.test",
          "addr:198.51.100.42",
        ],
        contradicts: [],
      },
    ],
    reviews: [],
    disposition: "review_ready",
    limitations: ["HTTP query parameters in packet capture are redacted as ?[redacted] per ADR-0003."],
    requested_decisions: [],
  });

  const hypothesesHandoff = HandoffSchema.parse({
    schema_version: 1,
    case_id: "northvale-lab-001",
    step_id: "hypotheses",
    profile: "framework-builder",
    claims: [
      {
        claim_id: "hypotheses:c1",
        kind: "hypothesis",
        statement:
          "Initial persistence hypothesis evaluated wks-it-02 scheduled maintenance (evt-0000000000001099), which was subsequently ruled out as benign.",
        evidence_ids: ["lab-case-events"],
        entity_ids: ["host:wks-it-02"],
        contradicts: [],
      },
      {
        claim_id: "hypotheses:c2",
        kind: "inference",
        statement:
          "Cadence alignment between UserSyncHelper.exe process creation (evt-0000000000001048) and 60-second TLS 1.3 beacons to 198.51.100.42 (frame-188, ioc-10042) indicates automated task-driven C2.",
        evidence_ids: ["lab-case-events", "lab-case-pcap", "lab-case-intel"],
        entity_ids: ["proc:usersynchelper", "addr:198.51.100.42"],
        contradicts: ["hypotheses:c1"],
      },
    ],
    reviews: [],
    disposition: "review_ready",
    limitations: [],
    requested_decisions: [],
  });

  const purpleHandoff = HandoffSchema.parse({
    schema_version: 1,
    case_id: "northvale-lab-001",
    step_id: "purple",
    profile: "framework-reviewer",
    claims: [],
    reviews: [
      {
        review_id: "purple:r1",
        claim_ids: ["evidence:c1", "network:c1", "hypotheses:c2"],
        disposition: "review_ready",
        rationale:
          "Verified evt-0000000000001042, evt-0000000000001048, frame-142, frame-188, and ioc-10042 directly in case store; timeline correlation holds with zero false-positive hits on benign hosts.",
        evidence_ids: ["lab-case-events", "lab-case-pcap"],
      },
      {
        review_id: "purple:r2",
        claim_ids: ["evidence:c2", "hypotheses:c1"],
        disposition: "review_ready",
        rationale:
          "Confirmed wks-it-02 activity in evt-0000000000001099 is signed IT inventory maintenance and properly excluded from compromise attribution.",
        evidence_ids: ["lab-case-events"],
      },
    ],
    disposition: "review_ready",
    limitations: [],
    requested_decisions: [],
  });

  const handoffs = [evidenceHandoff, networkHandoff, hypothesesHandoff, purpleHandoff];

  const events: DissectorEventRow[] = [
    {
      eventId: "evt-0000000000001042",
      timestampIso: "2026-11-14T14:12:04.118204900Z",
      timestampMs: Date.parse("2026-11-14T14:12:04.118Z"),
      hostName: "wks-fin-07",
      category: "process",
      action: "scheduled-task-created",
      userName: "svc_sync",
      processName: "schtasks.exe",
      commandLine:
        'schtasks.exe /Create /TN "\\UserSyncHelper" /TR "C:\\ProgramData\\UserSync\\UserSyncHelper.exe --beacon https://cdn-telemetry.northvale-sync.test/api/v2/checkin" /SC MINUTE',
      sourceIp: "10.20.2.107",
      destinationIp: "",
      message: "Scheduled task \\UserSyncHelper created by NORTHVALE\\svc_sync",
      entityIds: ["host:wks-fin-07", "acct:svc_sync", "proc:usersynchelper"],
    },
    {
      eventId: "evt-0000000000001048",
      timestampIso: "2026-11-14T14:13:00.004512000Z",
      timestampMs: Date.parse("2026-11-14T14:13:00.004Z"),
      hostName: "wks-fin-07",
      category: "process",
      action: "process-started",
      userName: "svc_sync",
      processName: "UserSyncHelper.exe",
      commandLine:
        "C:\\ProgramData\\UserSync\\UserSyncHelper.exe --beacon https://cdn-telemetry.northvale-sync.test/api/v2/checkin",
      sourceIp: "10.20.2.107",
      destinationIp: "198.51.100.42",
      message: "Sysmon EventID 1: Process Create UserSyncHelper.exe (PID 6812)",
      entityIds: ["host:wks-fin-07", "acct:svc_sync", "proc:usersynchelper", "addr:198.51.100.42"],
    },
    {
      eventId: "evt-0000000000001099",
      timestampIso: "2026-11-14T14:24:18.450000000Z",
      timestampMs: Date.parse("2026-11-14T14:24:18.450Z"),
      hostName: "wks-it-02",
      category: "process",
      action: "process-started",
      userName: "it_admin",
      processName: "powershell.exe",
      commandLine: "powershell.exe -ExecutionPolicy AllSigned -File C:\\IT\\Collect-AssetInventory.ps1",
      sourceIp: "10.20.1.22",
      destinationIp: "",
      message: "Signed IT asset inventory collection on wks-it-02",
      entityIds: ["host:wks-it-02"],
    },
  ];

  const arkimeFlows: DissectorArkimeRow[] = [
    {
      sessionId: "arkime-sess-01",
      firstPacketIso: "2026-11-14T14:13:00.210Z",
      firstPacketMs: Date.parse("2026-11-14T14:13:00.210Z"),
      lastPacketIso: "2026-11-14T14:13:00.295Z",
      sourceIp: "10.20.2.107",
      sourcePort: 54912,
      destinationIp: "10.20.0.53",
      destinationPort: 53,
      protocol: ["udp", "dns"],
      networkBytes: 618,
      networkPackets: 2,
      httpHost: "",
      dnsHost: "cdn-telemetry.northvale-sync.test",
      tlsJa4: "",
      tlsJa3: "",
      linkedFrameIds: ["frame-142"],
      entityIds: ["host:wks-fin-07", "dom:cdn-telemetry.northvale-sync.test"],
    },
    {
      sessionId: "arkime-sess-02",
      firstPacketIso: "2026-11-14T14:13:00.412Z",
      firstPacketMs: Date.parse("2026-11-14T14:13:00.412Z"),
      lastPacketIso: "2026-11-14T14:13:04.880Z",
      sourceIp: "10.20.2.107",
      sourcePort: 51844,
      destinationIp: "198.51.100.42",
      destinationPort: 443,
      protocol: ["tcp", "tls"],
      networkBytes: 14_820,
      networkPackets: 24,
      httpHost: "cdn-telemetry.northvale-sync.test",
      dnsHost: "",
      tlsJa4: "t13d1516h2_8daaf6152771_b186095e22b6",
      tlsJa3: "771,4865-4866-4867-49195,0-23-65281-10-11-35-16-5-13-51-45-43-27,29-23-24,0",
      linkedFrameIds: ["frame-188"],
      entityIds: [
        "host:wks-fin-07",
        "dom:cdn-telemetry.northvale-sync.test",
        "addr:198.51.100.42",
      ],
    },
  ];

  const packets: DissectorPacketRow[] = [
    {
      frameId: "frame-142",
      frameNumber: 142,
      timeEpochSec: Date.parse("2026-11-14T14:13:00.215Z") / 1000,
      timeIso: "2026-11-14T14:13:00.215Z",
      frameLen: 342,
      protocol: "DNS",
      ipSrc: "10.20.0.53",
      ipDst: "10.20.2.107",
      dstPort: 54912,
      dnsQryName: "cdn-telemetry.northvale-sync.test",
      dnsTxtAnswer: "v=nv1;stage=poll;ip=198.51.100.42",
      httpHost: "",
      httpRequestUriRedacted: "",
      tlsServerName: "",
      tlsJa4: "",
      tlsJa3: "",
      smb2Filename: "",
      entityIds: ["host:wks-fin-07", "dom:cdn-telemetry.northvale-sync.test", "addr:198.51.100.42"],
    },
    {
      frameId: "frame-188",
      frameNumber: 188,
      timeEpochSec: Date.parse("2026-11-14T14:13:00.420Z") / 1000,
      timeIso: "2026-11-14T14:13:00.420Z",
      frameLen: 728,
      protocol: "TLSv1.3",
      ipSrc: "10.20.2.107",
      ipDst: "198.51.100.42",
      dstPort: 443,
      dnsQryName: "",
      dnsTxtAnswer: "",
      httpHost: "cdn-telemetry.northvale-sync.test",
      httpRequestUriRedacted: "/api/v2/checkin?[redacted]",
      tlsServerName: "cdn-telemetry.northvale-sync.test",
      tlsJa4: "t13d1516h2_8daaf6152771_b186095e22b6",
      tlsJa3: "cd08e31494f9531f560d64c695473da9",
      smb2Filename: "",
      entityIds: ["host:wks-fin-07", "dom:cdn-telemetry.northvale-sync.test", "addr:198.51.100.42"],
    },
  ];

  const knownEventIds = new Set(events.map((e) => e.eventId));
  const knownFrameIds = new Set(packets.map((p) => p.frameId));
  const knownIocIds = new Set(["ioc-10042"]);

  const allFlatClaims = [
    ...evidenceHandoff.claims.map((c) => ({
      claim: c,
      stepId: "evidence",
      waveNumber: 2 as const,
      profile: "framework-researcher" as const,
    })),
    ...networkHandoff.claims.map((c) => ({
      claim: c,
      stepId: "network",
      waveNumber: 2 as const,
      profile: "framework-network-analyst" as const,
    })),
    ...hypothesesHandoff.claims.map((c) => ({
      claim: c,
      stepId: "hypotheses",
      waveNumber: 2 as const,
      profile: "framework-builder" as const,
    })),
  ];

  const allLimitations = [
    ...evidenceHandoff.limitations.map((text, idx) => ({
      stepId: "evidence",
      profile: "framework-researcher" as const,
      index: idx,
      text,
    })),
    ...networkHandoff.limitations.map((text, idx) => ({
      stepId: "network",
      profile: "framework-network-analyst" as const,
      index: idx,
      text,
    })),
  ];

  const citationReceipt = computeCitationVerificationReceipt(
    allFlatClaims.map((c) => ({
      stepId: c.stepId,
      claimId: c.claim.claim_id,
      statement: c.claim.statement,
    })),
    allLimitations,
    { knownEventIds, knownFrameIds, knownIocIds },
  );

  const statusByCitation = new Map(citationReceipt.entries.map((e) => [e.citationId, e.status]));

  const claims: EnrichedClaimRow[] = allFlatClaims.map((item) => {
    const inlineMatches = [
      ...item.claim.statement.matchAll(/\b(?:evt-[A-Za-z0-9_-]+|frame-\d+|ioc-\d+)\b/g),
    ].map((m) => m[0]);
    const uniqueCitations = [...new Set(inlineMatches)];
    return {
      claim: item.claim,
      stepId: item.stepId,
      waveNumber: item.waveNumber,
      profile: item.profile,
      inlineCitations: uniqueCitations.map((id) => ({
        id,
        kind: id.startsWith("evt-") ? "evt" : id.startsWith("frame-") ? "frame" : "ioc",
        status: statusByCitation.get(id) ?? "unresolved",
      })),
      reviews: purpleHandoff.reviews.filter((r) => r.claim_ids.includes(item.claim.claim_id)),
    };
  });

  const evidenceCatalog: Record<string, EvidenceRecordDetail> = {};
  for (const ev of events) {
    evidenceCatalog[ev.eventId] = {
      id: ev.eventId,
      kind: "evt",
      verified: true,
      timestampIso: ev.timestampIso,
      title: `${ev.hostName} · ${ev.action} (${ev.processName})`,
      fields: {
        "event.id": ev.eventId,
        "@timestamp": ev.timestampIso,
        "host.name": ev.hostName,
        "event.category": ev.category,
        "event.action": ev.action,
        "user.name": ev.userName,
        "process.name": ev.processName,
        "process.command_line": ev.commandLine,
        "source.ip": ev.sourceIp,
        "destination.ip": ev.destinationIp,
        message: ev.message,
      },
      citingClaimIds: claims
        .filter((c) => c.inlineCitations.some((ic) => ic.id === ev.eventId))
        .map((c) => c.claim.claim_id),
      linkedEntityIds: ev.entityIds,
    };
  }
  for (const pkt of packets) {
    evidenceCatalog[pkt.frameId] = {
      id: pkt.frameId,
      kind: "frame",
      verified: true,
      timestampIso: pkt.timeIso,
      title: `Frame #${pkt.frameNumber} · ${pkt.protocol} (${pkt.ipSrc} -> ${pkt.ipDst})`,
      fields: {
        "frame.number": pkt.frameNumber,
        "frame.time_epoch": pkt.timeEpochSec,
        "frame.len": pkt.frameLen,
        "_ws.col.Protocol": pkt.protocol,
        "ip.src": pkt.ipSrc,
        "ip.dst": pkt.ipDst,
        "tcp.dstport": pkt.dstPort ?? "",
        "dns.qry.name": pkt.dnsQryName,
        "dns.txt": pkt.dnsTxtAnswer,
        "http.host": pkt.httpHost,
        "http.request.uri": pkt.httpRequestUriRedacted,
        "tls.handshake.extensions_server_name": pkt.tlsServerName,
        "tls.handshake.ja4": pkt.tlsJa4,
        "tls.handshake.ja3": pkt.tlsJa3,
      },
      citingClaimIds: claims
        .filter((c) => c.inlineCitations.some((ic) => ic.id === pkt.frameId))
        .map((c) => c.claim.claim_id),
      linkedEntityIds: pkt.entityIds,
    };
  }
  evidenceCatalog["ioc-10042"] = {
    id: "ioc-10042",
    kind: "ioc",
    verified: true,
    timestampIso: "2026-11-01T00:00:00Z",
    title: "Threat Intel Match · 198.51.100.42 / cdn-telemetry.northvale-sync.test",
    fields: {
      id: "ioc-10042",
      "indicator.type": "ipv4-addr",
      "indicator.value": "198.51.100.42",
      "threat.feed.name": "northvale-cert-c2-feed",
      confidence: 92,
      description: "Task-driven HTTPS/TLS 1.3 staging & beacon relay node",
      first_seen: "2026-11-01T00:00:00Z",
    },
    citingClaimIds: claims
      .filter((c) => c.inlineCitations.some((ic) => ic.id === "ioc-10042"))
      .map((c) => c.claim.claim_id),
    linkedEntityIds: ["addr:198.51.100.42", "dom:cdn-telemetry.northvale-sync.test"],
  };

  for (const ent of snapshot.entities) {
    evidenceCatalog[ent.entity_id] = {
      id: ent.entity_id,
      kind: "entity",
      verified: true,
      title: `${ent.kind.toUpperCase()} · ${ent.label}`,
      fields: {
        entity_id: ent.entity_id,
        kind: ent.kind,
        label: ent.label,
        evidence_ids: ent.evidence_ids,
      },
      citingClaimIds: claims
        .filter((c) => c.claim.entity_ids.includes(ent.entity_id))
        .map((c) => c.claim.claim_id),
      linkedEntityIds: [ent.entity_id],
    };
  }

  const baseStartMs = Date.parse("2026-11-14T15:05:00Z");
  const steps: StepExecutionSummary[] = [
    {
      stepId: "scope",
      waveNumber: 1,
      wave: "scope",
      profile: "framework-coordinator",
      state: openGate === "scope" ? "awaiting_approval" : "done",
      model: "claude-sonnet-4-6",
      turnsUsed: 2,
      maxTurns: 8,
      inputTokens: 8_200,
      outputTokens: 1_450,
      cacheReadTokens: 28_400,
      cacheWriteTokens: 4_100,
      totalTokens: 42_150,
      handoffBytes: 3_120,
      startedAtIso: new Date(baseStartMs).toISOString(),
      endedAtIso: new Date(baseStartMs + 9_500).toISOString(),
    },
    {
      stepId: "evidence",
      waveNumber: 2,
      wave: "investigation",
      profile: "framework-researcher",
      state: "done",
      model: "claude-sonnet-4-6",
      turnsUsed: 5,
      maxTurns: 6,
      inputTokens: 14_800,
      outputTokens: 3_100,
      cacheReadTokens: 96_000,
      cacheWriteTokens: 6_200,
      totalTokens: 120_100,
      handoffBytes: 6_840,
      startedAtIso: new Date(baseStartMs + 12_000).toISOString(),
      endedAtIso: new Date(baseStartMs + 34_000).toISOString(),
    },
    {
      stepId: "hypotheses",
      waveNumber: 2,
      wave: "investigation",
      profile: "framework-builder",
      state: "done",
      model: "claude-sonnet-4-6",
      turnsUsed: 4,
      maxTurns: 6,
      inputTokens: 11_200,
      outputTokens: 2_600,
      cacheReadTokens: 78_500,
      cacheWriteTokens: 1_500,
      totalTokens: 93_800,
      handoffBytes: 5_210,
      startedAtIso: new Date(baseStartMs + 12_100).toISOString(),
      endedAtIso: new Date(baseStartMs + 31_200).toISOString(),
    },
    {
      stepId: "network",
      waveNumber: 2,
      wave: "investigation",
      profile: "framework-network-analyst",
      state: "done",
      model: "claude-sonnet-4-6",
      turnsUsed: 5,
      maxTurns: 6,
      inputTokens: 13_900,
      outputTokens: 2_950,
      cacheReadTokens: 91_200,
      cacheWriteTokens: 1_800,
      totalTokens: 109_850,
      handoffBytes: 6_110,
      startedAtIso: new Date(baseStartMs + 12_050).toISOString(),
      endedAtIso: new Date(baseStartMs + 36_400).toISOString(),
    },
    {
      stepId: "intel",
      waveNumber: 2,
      wave: "investigation",
      profile: "framework-librarian",
      state: "done",
      model: "claude-haiku-4-5",
      turnsUsed: 3,
      maxTurns: 6,
      inputTokens: 6_400,
      outputTokens: 1_120,
      cacheReadTokens: 42_000,
      cacheWriteTokens: 3_100,
      totalTokens: 52_620,
      handoffBytes: 2_890,
      startedAtIso: new Date(baseStartMs + 12_150).toISOString(),
      endedAtIso: new Date(baseStartMs + 24_800).toISOString(),
    },
    {
      stepId: "analysis",
      waveNumber: 3,
      wave: "analysis",
      profile: "framework-coordinator",
      state: "done",
      model: "claude-opus-4-6",
      turnsUsed: 3,
      maxTurns: 8,
      inputTokens: 18_500,
      outputTokens: 3_800,
      cacheReadTokens: 112_000,
      cacheWriteTokens: 8_400,
      totalTokens: 142_700,
      handoffBytes: 8_920,
      startedAtIso: new Date(baseStartMs + 37_000).toISOString(),
      endedAtIso: new Date(baseStartMs + 56_000).toISOString(),
    },
    {
      stepId: "follow-1",
      waveNumber: 4,
      wave: "follow_up",
      profile: "framework-researcher",
      state: "done",
      model: "claude-sonnet-4-6",
      turnsUsed: 4,
      maxTurns: 6,
      inputTokens: 9_800,
      outputTokens: 1_900,
      cacheReadTokens: 68_000,
      cacheWriteTokens: 1_200,
      totalTokens: 80_900,
      handoffBytes: 4_400,
      startedAtIso: new Date(baseStartMs + 57_000).toISOString(),
      endedAtIso: new Date(baseStartMs + 73_000).toISOString(),
    },
    {
      stepId: "follow-2",
      waveNumber: 4,
      wave: "follow_up",
      profile: "framework-researcher",
      state: "dropped",
      reasonCode: "model_refusal",
      model: "claude-sonnet-4-6",
      turnsUsed: 1,
      maxTurns: 6,
      inputTokens: 3_400,
      outputTokens: 0,
      cacheReadTokens: 24_000,
      cacheWriteTokens: 0,
      totalTokens: 27_400,
      refusal: {
        refused: true,
        finish_reason: "content_filter",
        category: "cyber",
        diagnostic: "finish_reason=content_filter, category=cyber (surfaced verbatim per Rule 5)",
      },
      startedAtIso: new Date(baseStartMs + 57_100).toISOString(),
      endedAtIso: new Date(baseStartMs + 61_200).toISOString(),
    },
    {
      stepId: "merge",
      waveNumber: 5,
      wave: "merge",
      profile: "framework-coordinator",
      state: "done",
      model: "claude-sonnet-4-6",
      turnsUsed: 2,
      maxTurns: 6,
      inputTokens: 11_400,
      outputTokens: 2_700,
      cacheReadTokens: 84_000,
      cacheWriteTokens: 1_900,
      totalTokens: 100_000,
      handoffBytes: 9_150,
      startedAtIso: new Date(baseStartMs + 74_000).toISOString(),
      endedAtIso: new Date(baseStartMs + 88_000).toISOString(),
    },
    {
      stepId: "detection",
      waveNumber: 6,
      wave: "detection",
      profile: "framework-builder",
      state: "done",
      model: "claude-sonnet-4-6",
      turnsUsed: 3,
      maxTurns: 6,
      inputTokens: 9_600,
      outputTokens: 2_200,
      cacheReadTokens: 74_000,
      cacheWriteTokens: 1_100,
      totalTokens: 86_900,
      handoffBytes: 5_800,
      startedAtIso: new Date(baseStartMs + 89_000).toISOString(),
      endedAtIso: new Date(baseStartMs + 104_000).toISOString(),
    },
    {
      stepId: "purple",
      waveNumber: 7,
      wave: "purple",
      profile: "framework-reviewer",
      state: "done",
      model: "claude-opus-4-6",
      turnsUsed: 4,
      maxTurns: 6,
      inputTokens: 15_200,
      outputTokens: 3_100,
      cacheReadTokens: 106_000,
      cacheWriteTokens: 3_800,
      totalTokens: 128_100,
      handoffBytes: 7_300,
      startedAtIso: new Date(baseStartMs + 105_000).toISOString(),
      endedAtIso: new Date(baseStartMs + 124_000).toISOString(),
    },
    {
      stepId: "incident",
      waveNumber: 8,
      wave: "incident",
      profile: "framework-coordinator",
      state: openGate === "incident" ? "awaiting_approval" : "done",
      model: "claude-opus-4-6",
      turnsUsed: 2,
      maxTurns: 8,
      inputTokens: 12_800,
      outputTokens: 3_950,
      cacheReadTokens: 118_000,
      cacheWriteTokens: 2_100,
      totalTokens: 136_850,
      handoffBytes: 12_480,
      startedAtIso: new Date(baseStartMs + 125_000).toISOString(),
      endedAtIso: new Date(baseStartMs + 141_000).toISOString(),
    },
  ];

  const totalInput = steps.reduce((acc, s) => acc + s.inputTokens, 0);
  const totalOutput = steps.reduce((acc, s) => acc + s.outputTokens, 0);
  const totalCacheRead = steps.reduce((acc, s) => acc + s.cacheReadTokens, 0);
  const totalCacheWrite = steps.reduce((acc, s) => acc + s.cacheWriteTokens, 0);
  const handoffRejectionTokens = 14_200;
  const totalTokensUsed =
    steps.reduce((acc, s) => acc + s.totalTokens, 0) + handoffRejectionTokens;
  const promptInputDenom = totalInput + totalCacheRead + totalCacheWrite;
  const promptCacheHitRatio = promptInputDenom > 0 ? totalCacheRead / promptInputDenom : 0;

  const cost = computeCostAccounting(
    "claude-sonnet-4-6",
    {
      inputTokens: totalInput,
      outputTokens: totalOutput,
      cacheReadTokens: totalCacheRead,
      cacheWriteTokens: totalCacheWrite,
    },
    "oauth_subscription",
  );

  const ganttSpans: GanttSpanRecord[] = [
    {
      spanId: "span-gate-1",
      parentSpanId: null,
      kind: "hunt.gate.decision",
      waveNumber: 1,
      wave: "scope",
      stepId: "scope",
      profile: "framework-coordinator",
      label: "Gate 1 Scope Decision (desktop)",
      startEpochMs: baseStartMs + 9_500,
      endEpochMs: baseStartMs + 11_900,
      durationMs: 2_400,
      status: "ok",
      gateVia: "desktop",
    },
    {
      spanId: "span-ev-tool-1",
      parentSpanId: null,
      kind: "gen_ai.execute_tool",
      waveNumber: 2,
      wave: "investigation",
      stepId: "evidence",
      profile: "framework-researcher",
      label: 'elastic_search q="schtasks.exe OR UserSyncHelper"',
      startEpochMs: baseStartMs + 14_200,
      endEpochMs: baseStartMs + 15_050,
      durationMs: 850,
      status: "ok",
      toolName: "elastic_search",
      queryPreview: 'process.name:("schtasks.exe" OR "UserSyncHelper.exe")',
      resultCount: 2,
      totalHits: 2,
      citedIds: ["evt-0000000000001042", "evt-0000000000001048"],
    },
    {
      spanId: "span-ev-chat-1",
      parentSpanId: null,
      kind: "gen_ai.chat",
      waveNumber: 2,
      wave: "investigation",
      stepId: "evidence",
      profile: "framework-researcher",
      label: "gen_ai.chat claude-sonnet-4-6 (84.2% cache)",
      startEpochMs: baseStartMs + 15_100,
      endEpochMs: baseStartMs + 28_400,
      durationMs: 13_300,
      status: "ok",
      model: "claude-sonnet-4-6",
      inputTokens: 14_800,
      outputTokens: 3_100,
      cacheReadTokens: 96_000,
      cacheWriteTokens: 6_200,
      cacheHitRatio: 0.82,
    },
    {
      spanId: "span-net-tool-1",
      parentSpanId: null,
      kind: "gen_ai.execute_tool",
      waveNumber: 2,
      wave: "investigation",
      stepId: "network",
      profile: "framework-network-analyst",
      label: 'packet_fields filter="tls.handshake.ja4 == t13d1516h2_8daaf6152771_b186095e22b6"',
      startEpochMs: baseStartMs + 16_000,
      endEpochMs: baseStartMs + 17_400,
      durationMs: 1_400,
      status: "ok",
      toolName: "packet_fields",
      queryPreview: 'ip.dst == 198.51.100.42 && tcp.dstport == 443',
      resultCount: 1,
      totalHits: 1,
      citedIds: ["frame-142", "frame-188"],
    },
    {
      spanId: "span-intel-tool-1",
      parentSpanId: null,
      kind: "gen_ai.execute_tool",
      waveNumber: 2,
      wave: "investigation",
      stepId: "intel",
      profile: "framework-librarian",
      label: 'intel_lookup indicators="198.51.100.42,cdn-telemetry.northvale-sync.test"',
      startEpochMs: baseStartMs + 14_800,
      endEpochMs: baseStartMs + 15_300,
      durationMs: 500,
      status: "ok",
      toolName: "intel_lookup",
      queryPreview: "198.51.100.42,cdn-telemetry.northvale-sync.test",
      resultCount: 1,
      totalHits: 1,
      citedIds: ["ioc-10042"],
    },
    {
      spanId: "span-follow2-refusal",
      parentSpanId: null,
      kind: "gen_ai.chat",
      waveNumber: 4,
      wave: "follow_up",
      stepId: "follow-2",
      profile: "framework-researcher",
      label: "Refusal (cyber): finish_reason=content_filter",
      startEpochMs: baseStartMs + 57_100,
      endEpochMs: baseStartMs + 61_200,
      durationMs: 4_100,
      status: "refused",
      model: "claude-sonnet-4-6",
      refusal: {
        refused: true,
        finish_reason: "content_filter",
        category: "cyber",
        diagnostic: "finish_reason=content_filter, category=cyber",
      },
    },
    {
      spanId: "span-purple-validate",
      parentSpanId: null,
      kind: "hunt.handoff.validate",
      waveNumber: 7,
      wave: "purple",
      stepId: "purple",
      profile: "framework-reviewer",
      label: "Handoff Ontology & Citation Validation (7,300 / 16,384 B)",
      startEpochMs: baseStartMs + 122_500,
      endEpochMs: baseStartMs + 124_000,
      durationMs: 1_500,
      status: "ok",
      handoffBytes: 7_300,
      isRetry: false,
    },
    {
      spanId: "span-incident-chat",
      parentSpanId: null,
      kind: "gen_ai.chat",
      waveNumber: 8,
      wave: "incident",
      stepId: "incident",
      profile: "framework-coordinator",
      label: "Incident Synthesis claude-opus-4-6 (88.7% cache)",
      startEpochMs: baseStartMs + 125_000,
      endEpochMs: baseStartMs + 141_000,
      durationMs: 16_000,
      status: "ok",
      model: "claude-opus-4-6",
      inputTokens: 12_800,
      outputTokens: 3_950,
      cacheReadTokens: 118_000,
      cacheWriteTokens: 2_100,
      cacheHitRatio: 0.887,
    },
  ];

  const allowedRoleTools: Record<ProfileId, readonly HuntToolName[]> = {
    "framework-coordinator": getAllowedToolsForStep("framework-coordinator", "scope"),
    "framework-researcher": ROLE_TOOL_OWNERSHIP["framework-researcher"],
    "framework-network-analyst": ROLE_TOOL_OWNERSHIP["framework-network-analyst"],
    "framework-librarian": ROLE_TOOL_OWNERSHIP["framework-librarian"],
    "framework-builder": ROLE_TOOL_OWNERSHIP["framework-builder"],
    "framework-reviewer": ROLE_TOOL_OWNERSHIP["framework-reviewer"],
  };

  let activeGate: ActiveGatePrompt | null = null;
  if (openGate === "scope") {
    activeGate = {
      gate: "scope",
      huntId,
      openedAtIso: "2026-11-14T15:05:10Z",
      expiresAtIso: "2027-11-14T15:05:10Z",
      payloadSha256: SCOPE_DIGEST,
      scopeSummary: {
        hostsInScope: ["wks-fin-07", "wks-it-02"],
        allowedRoleTools,
        maxTotalTokens: 4_000_000,
        followUpCount: 6,
      },
    };
  } else if (openGate === "incident") {
    activeGate = {
      gate: "incident",
      huntId,
      openedAtIso: "2026-11-14T15:07:21Z",
      expiresAtIso: "2027-11-14T15:07:21Z",
      payloadSha256: INCIDENT_DIGEST,
      incidentSummary: {
        citationReceipt,
        observedCount: claims.filter((c) => c.claim.kind === "observed").length,
        findingCount: claims.filter((c) => c.claim.kind === "finding").length,
        inferenceCount: claims.filter((c) => c.claim.kind === "inference").length,
        hypothesisCount: claims.filter((c) => c.claim.kind === "hypothesis").length,
        limitationCount: allLimitations.length,
        purpleVerdictCounts: {
          review_ready: purpleHandoff.reviews.filter((r) => r.disposition === "review_ready")
            .length,
          needs_validation: purpleHandoff.reviews.filter(
            (r) => r.disposition === "needs_validation",
          ).length,
          needs_revision: purpleHandoff.reviews.filter((r) => r.disposition === "needs_revision")
            .length,
        },
      },
    };
  } else if (openGate === "reconcile") {
    activeGate = {
      gate: "reconcile",
      huntId,
      openedAtIso: "2026-11-14T15:06:02Z",
      expiresAtIso: "2027-11-14T15:06:02Z",
      payloadSha256: RECONCILE_DIGEST,
      reconcileContext: {
        executionId: "exec-nv01-wave3-analysis-01",
        sessionId: "sess-omp-coord-8812",
        inputId: "in-sha256-4419ab",
        stepId: "analysis",
        profile: "framework-coordinator",
        reservedAtIso: "2026-11-14T15:05:38Z",
        reasonCode: "previous_dispatch_unknown",
      },
    };
  }

  const bucketStartSec = Math.floor(Date.parse("2026-11-14T14:00:00Z") / 1000);
  const bucketTimestampsSec: number[] = [];
  const ecsEventCounts: number[] = [];
  const networkFlowCounts: number[] = [];
  for (let i = 0; i < 60; i++) {
    const ts = bucketStartSec + i * 60;
    bucketTimestampsSec.push(ts);
    ecsEventCounts.push(i === 12 || i === 13 ? 18 : i === 24 ? 9 : (i % 5) + 1);
    networkFlowCounts.push(i >= 13 && i <= 45 ? (i % 3 === 0 ? 14 : 6) : 2);
  }

  return {
    provenanceMode: "fixture_preview",
    huntId,
    runStatus: activeGate ? "awaiting_human_gate" : "completed",
    caseMetadata,
    currentWaveNumber: openGate === "scope" ? 1 : openGate === "reconcile" ? 3 : 8,
    mergeFallbackActive: false,
    gauges: {
      totalTokensUsed,
      handoffRejectionTokens,
      maxTotalTokens: 4_000_000,
      promptCacheHitRatio,
      cacheBelowTarget: promptCacheHitRatio < 0.76,
      billingMode: "oauth_subscription",
      actualBilledUsd: cost.actualBilledUsd,
      shadowApiUsd: cost.shadowApiUsd,
      cacheSavingsUsd: cost.cacheSavingsUsd,
      cyberRefusalCount: 1,
    },
    steps,
    ganttSpans,
    activeGate,
    gateHistory: [
      {
        decision_id: "dec-scope-nv01",
        hunt_id: huntId,
        gate: "scope",
        action: "approve",
        via: "desktop",
        decided_by: "analyst.chen",
        rbac_role: "lead_hunter",
        payload_sha256: SCOPE_DIGEST,
        decided_at: "2026-11-14T15:05:11Z",
        expires_at: "2026-11-15T15:05:10Z",
        note: "Verified case time bounds 14:00..15:00Z, synthetic data_origin, and read-only role tool ownership.",
      },
    ],
    claims,
    limitations: allLimitations.map(({ stepId, profile, text }) => ({ stepId, profile, text })),
    handoffs,
    snapshot,
    citationReceipt,
    histogram: {
      bucketTimestampsSec,
      ecsEventCounts,
      networkFlowCounts,
      intervalSec: 60,
    },
    events,
    arkimeFlows,
    packets,
    evidenceCatalog,
    watchState: {
      enabled: true,
      runId: huntId,
      role: "framework-researcher",
      partition: `hunt-watch:${huntId}:framework-researcher`,
      currentUrl: "about:blank",
      title: "Fenced Watch Browser (Standby)",
      loading: false,
      allowedOrigins: ["http://127.0.0.1:18400"],
      blockedRequestCount: 0,
      lastBlockedReason: null,
      cdpEndpointUrl: null,
    },
  };
}
