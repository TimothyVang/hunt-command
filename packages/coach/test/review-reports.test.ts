import { describe, expect, test } from "bun:test";
import {
  CaseEvents,
  checkClaimsGrounding,
  checkReport,
  countPcapFrames,
  fieldValues,
  inEvent,
  keyConsistency,
  readHandoff,
  reviewReports,
  type ScenarioTruth,
} from "../src/index.ts";

function buildClassicPcapBytes(params: {
  bigEndian: boolean;
  packetLengths: readonly number[];
}): Uint8Array {
  const totalPayload = params.packetLengths.reduce((acc, n) => acc + 16 + n, 0);
  const buf = new Uint8Array(24 + totalPayload);
  const view = new DataView(buf.buffer);
  const le = !params.bigEndian;

  // Classic microsecond libpcap magic: 0xa1b2c3d4 in native endianness
  view.setUint32(0, 0xa1b2c3d4, le);
  view.setUint16(4, 2, le);
  view.setUint16(6, 4, le);
  view.setUint32(16, 65535, le);
  view.setUint32(20, 1, le);

  let offset = 24;
  for (const pktLen of params.packetLengths) {
    view.setUint32(offset + 0, 1_700_000_000, le);
    view.setUint32(offset + 4, 0, le);
    view.setUint32(offset + 8, pktLen, le);
    view.setUint32(offset + 12, pktLen, le);
    offset += 16 + pktLen;
  }
  return buf;
}

function buildPcapngBytes(packetCount: number): Uint8Array {
  // SHB (28 bytes) + IDB (20 bytes) + N * EPB (36 bytes padded to 4B)
  const shbLen = 28;
  const idbLen = 20;
  const epbLen = 36;
  const buf = new Uint8Array(shbLen + idbLen + packetCount * epbLen);
  const view = new DataView(buf.buffer);

  // SHB
  view.setUint32(0, 0x0a0d0d0a, true);
  view.setUint32(4, shbLen, true);
  view.setUint32(8, 0x1a2b3c4d, true); // LE byte-order magic (reads 0x4d3c2b1a BE)
  view.setUint16(12, 1, true);
  view.setUint16(14, 0, true);
  view.setInt32(16, -1, true);
  view.setInt32(20, -1, true);
  view.setUint32(24, shbLen, true);

  // IDB (type 1)
  let offset = shbLen;
  view.setUint32(offset + 0, 0x00000001, true);
  view.setUint32(offset + 4, idbLen, true);
  view.setUint16(8 + offset, 1, true);
  view.setUint32(offset + 12, 65535, true);
  view.setUint32(offset + 16, idbLen, true);
  offset += idbLen;

  // EPBs (type 6)
  for (let i = 0; i < packetCount; i++) {
    view.setUint32(offset + 0, 0x00000006, true);
    view.setUint32(offset + 4, epbLen, true);
    view.setUint32(offset + 8, 0, true);
    view.setUint32(offset + 12, 0, true);
    view.setUint32(offset + 16, i + 1, true);
    view.setUint32(offset + 20, 4, true);
    view.setUint32(offset + 24, 4, true);
    view.setUint32(offset + 28, 0xdeadbeef, true);
    view.setUint32(offset + 32, epbLen, true);
    offset += epbLen;
  }
  return buf;
}

const SAMPLE_EVENTS = [
  {
    event: { id: "evt-000101" },
    host: { name: "ws-eng-07" },
    user: { name: "m.chen" },
    destination: { domain: "sub.stage.c2-node.test", ip: "198.51.100.44" },
  },
  {
    "event.id": "evt-000102",
    "host.name": "ws-eng-07",
    process: { name: "powershell.exe" },
  },
  {
    event: { id: "evt-000201" },
    host: { name: "srv-backup-01" },
    user: { name: "svc-backup" },
  },
];

const SAMPLE_TRUTH: ScenarioTruth = {
  schema_version: 1,
  case_id: "synth-rev-001",
  facts: [
    {
      fact_id: "attack.c2.https-beacon",
      kind: "attack",
      entities: {
        host: ["ws-eng-07"],
        domain: ["stage.c2-node.test"],
      },
      evidence_event_groups: [["evt-000101", "evt-000102"]],
      evidence_frame_groups: [["frame-3"]],
      evidence_intel_groups: [["ioc-00009"]],
    },
  ],
};

describe("packages/coach review-reports & key-free g2_1_pass", () => {
  test("g2_1_pass passes ONLY when 0 evt-*, frame-*, and ioc-* IDs are missing across BOTH claims AND limitations", () => {
    const events = CaseEvents.fromRecords(SAMPLE_EVENTS, {
      maxFrameNumber: 10,
      validIntelIds: ["ioc-00009", "ioc-00010"],
    });

    const cleanReport = {
      case_id: "synth-rev-001",
      claims: [
        {
          claim_id: "incident:c1",
          statement:
            "Host ws-eng-07 beaconed to stage.c2-node.test in evt-000101, Frame-003, and ioc-00009.",
          evidence_ids: ["src-1"],
          entity_ids: ["ws-eng-07"],
        },
      ],
      limitations: [
        "Backup host srv-backup-01 had partial logs after evt-000201 (frame-10, ioc-00010).",
      ],
    };

    const okCheck = checkClaimsGrounding(cleanReport, events);
    expect(okCheck.g2_1_pass).toBe(true);
    expect(okCheck.missing_citation_total).toBe(0);
    expect(okCheck.citation_support.citation_precision).toBe(1);

    // 1. Missing evt-* in claims -> fails g2_1_pass
    const missingClaimEvt = checkClaimsGrounding(
      {
        ...cleanReport,
        claims: [
          {
            claim_id: "incident:c1",
            statement: "ws-eng-07 saw invented evt-999999.",
          },
        ],
      },
      events,
    );
    expect(missingClaimEvt.g2_1_pass).toBe(false);
    expect(missingClaimEvt.missing_ids).toEqual(["evt-999999"]);

    // 2. Missing frame-* in claims -> fails g2_1_pass
    const missingClaimFrame = checkClaimsGrounding(
      {
        ...cleanReport,
        claims: [
          {
            claim_id: "incident:c1",
            statement: "ws-eng-07 saw packet frame-99.",
          },
        ],
      },
      events,
    );
    expect(missingClaimFrame.g2_1_pass).toBe(false);
    expect(missingClaimFrame.missing_frame_ids).toEqual(["frame-99"]);

    // 3. Missing ioc-* in claims -> fails g2_1_pass
    const missingClaimIoc = checkClaimsGrounding(
      {
        ...cleanReport,
        claims: [
          {
            claim_id: "incident:c1",
            statement: "ws-eng-07 matched invented ioc-99999.",
          },
        ],
      },
      events,
    );
    expect(missingClaimIoc.g2_1_pass).toBe(false);
    expect(missingClaimIoc.missing_intel_ids).toEqual(["ioc-99999"]);

    // 4. Missing evt-* in limitations -> fails g2_1_pass
    const missingLimEvt = checkClaimsGrounding(
      {
        ...cleanReport,
        limitations: ["Gap after invented evt-888888."],
      },
      events,
    );
    expect(missingLimEvt.g2_1_pass).toBe(false);
    expect(missingLimEvt.limitation_missing_ids).toEqual(["evt-888888"]);

    // 5. Missing frame-* in limitations -> fails g2_1_pass
    const missingLimFrame = checkClaimsGrounding(
      {
        ...cleanReport,
        limitations: ["Capture truncated at Frame-0042."],
      },
      events,
    );
    expect(missingLimFrame.g2_1_pass).toBe(false);
    expect(missingLimFrame.limitation_missing_frame_ids).toEqual(["frame-42"]);

    // 6. Missing ioc-* in limitations -> fails g2_1_pass
    const missingLimIoc = checkClaimsGrounding(
      {
        ...cleanReport,
        limitations: ["Feed lacked enrichment for ioc-77777."],
      },
      events,
    );
    expect(missingLimIoc.g2_1_pass).toBe(false);
    expect(missingLimIoc.limitation_missing_intel_ids).toEqual(["ioc-77777"]);
  });

  test("inEvent subdomain matching, fieldValues nested/flat ECS extraction, and keyConsistency", () => {
    expect(inEvent("dns query to x.t.relay.test recorded", "t.relay.test")).toBe(true);
    expect(inEvent("dns query to bad-t.relay.test recorded", "t.relay.test")).toBe(false);

    expect(fieldValues(SAMPLE_EVENTS[0], "event.id")).toEqual(["evt-000101"]);
    expect(fieldValues(SAMPLE_EVENTS[1], "event.id")).toEqual(["evt-000102"]);

    const events = CaseEvents.fromRecords(SAMPLE_EVENTS, {
      maxFrameNumber: 5,
      validIntelIds: ["ioc-00009"],
    });
    const consistency = keyConsistency(SAMPLE_TRUTH, events);
    expect(consistency).toHaveLength(1);
    expect(consistency[0]?.consistent).toBe(true);
  });

  test("countPcapFrames accurately counts classic libpcap (LE & BE) and pcapng packet blocks", () => {
    const lePcap = buildClassicPcapBytes({
      bigEndian: false,
      packetLengths: [64, 128, 42],
    });
    expect(countPcapFrames(lePcap)).toBe(3);

    const bePcap = buildClassicPcapBytes({
      bigEndian: true,
      packetLengths: [60, 90, 120, 54],
    });
    expect(countPcapFrames(bePcap)).toBe(4);

    const ngBytes = buildPcapngBytes(5);
    expect(countPcapFrames(ngBytes)).toBe(5);
  });

  test("readHandoff extracts JSON handoff wrapped in prose/fences and reviewReports summarizes G2.1 + G2.2", () => {
    const wrapped = [
      "Analyst summary preamble with {non_handoff: true} brace noise.",
      "```json",
      JSON.stringify({
        case_id: "synth-rev-001",
        claims: [
          {
            claim_id: "incident:c1",
            statement:
              "Host ws-eng-07 contacted stage.c2-node.test in evt-000101 and frame-3.",
          },
        ],
        limitations: [],
      }),
      "```",
    ].join("\n");

    const extracted = readHandoff(wrapped);
    expect(extracted.case_id).toBe("synth-rev-001");

    const events = CaseEvents.fromRecords(SAMPLE_EVENTS, {
      maxFrameNumber: 5,
      validIntelIds: ["ioc-00009"],
    });
    const reviewed = reviewReports({
      reports: [wrapped],
      events,
      truth: SAMPLE_TRUTH,
    });

    expect(reviewed.g2_1_pass).toBe(true);
    expect(reviewed.goals["G2.1"].pass).toBe(true);
    expect(reviewed.goals["G2.2"]?.pass).toBe(true);
    const firstReport = reviewed.reports[0]!;
    expect("scorer" in firstReport && firstReport.scorer.found).toBe(1);
    expect(checkReport(extracted, SAMPLE_TRUTH, events).scorer.found).toBe(1);
  });
});
