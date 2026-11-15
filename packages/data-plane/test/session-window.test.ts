import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  type DissectedPacket,
  EmbeddedHuntDataPlane,
  streamDissectPcapFile,
} from "../src/index.ts";

const SECOND = BigInt(Date.parse("2026-11-14T10:00:00Z") / 1000);
const START_NS = SECOND * 1_000_000_000n + 101n;
const END_NS = SECOND * 1_000_000_000n + 109n;
const CLIENT = [10, 0, 0, 1];
const SERVER = [10, 0, 0, 2];

function tcpFrame(port: number, seq: number, text: string, response = false): Uint8Array {
  const payload = Buffer.from(text, "ascii");
  const frame = new Uint8Array(54 + payload.length);
  const view = new DataView(frame.buffer);
  frame.set([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
  view.setUint16(12, 0x0800);
  frame[14] = 0x45;
  view.setUint16(16, 40 + payload.length);
  view.setUint16(20, 0x4000);
  frame[22] = 64;
  frame[23] = 6;
  frame.set(response ? SERVER : CLIENT, 26);
  frame.set(response ? CLIENT : SERVER, 30);
  view.setUint16(34, response ? 80 : port);
  view.setUint16(36, response ? port : 80);
  view.setUint32(38, seq);
  frame[46] = 0x50;
  frame[47] = 0x18;
  view.setUint16(48, 65535);
  frame.set(payload, 54);
  return frame;
}

function request(host: string, uri: string, agent: string): string {
  return `GET ${uri} HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: ${agent}\r\n\r\n`;
}

interface TimedFrame {
  tsNs: bigint;
  data: Uint8Array;
}

function pcapNs(frames: readonly TimedFrame[]): Uint8Array {
  const capture = new Uint8Array(24 + frames.reduce((size, frame) => size + 16 + frame.data.length, 0));
  const view = new DataView(capture.buffer);
  view.setUint32(0, 0xa1b23c4d, true);
  view.setUint16(4, 2, true);
  view.setUint16(6, 4, true);
  view.setUint32(16, 65535, true);
  view.setUint32(20, 1, true);
  let offset = 24;
  for (const frame of frames) {
    view.setUint32(offset, Number(frame.tsNs / 1_000_000_000n), true);
    view.setUint32(offset + 4, Number(frame.tsNs % 1_000_000_000n), true);
    view.setUint32(offset + 8, frame.data.length, true);
    view.setUint32(offset + 12, frame.data.length, true);
    capture.set(frame.data, offset + 16);
    offset += 16 + frame.data.length;
  }
  return capture;
}

const beforeRequest = request("before.test", "/before", "before-agent");
const insideRequest = request("inside.test", "/inside", "inside-agent");
const insideResponse = "HTTP/1.1 204 No Content\r\n\r\n";
const afterRequest = request("after.test", "/after", "after-agent");
const frames: readonly TimedFrame[] = [
  { tsNs: START_NS - 1n, data: tcpFrame(31000, 1000, beforeRequest) },
  // Neither a pre-window TCP prefix nor a post-window suffix may complete an in-window HTTP message.
  { tsNs: START_NS - 1n, data: tcpFrame(31001, 2000, "GE") },
  { tsNs: START_NS - 1n, data: tcpFrame(31003, 4000, request("before-only.test", "/before-only", "before-only")) },
  { tsNs: START_NS, data: tcpFrame(31000, 1000 + beforeRequest.length, insideRequest) },
  { tsNs: START_NS + 1n, data: tcpFrame(31001, 2002, request("cross-before.test", "/cross-before", "cross-before").slice(2)) },
  { tsNs: END_NS - 2n, data: tcpFrame(31002, 3000, "GE") },
  { tsNs: END_NS - 1n, data: tcpFrame(31000, 5000, insideResponse, true) },
  { tsNs: END_NS, data: tcpFrame(31000, 1000 + beforeRequest.length + insideRequest.length, afterRequest) },
  { tsNs: END_NS, data: tcpFrame(31002, 3002, request("cross-after.test", "/cross-after", "cross-after").slice(2)) },
  { tsNs: END_NS + 1n, data: tcpFrame(31004, 6000, request("after-only.test", "/after-only", "after-only")) },
  { tsNs: END_NS + 1n, data: tcpFrame(31000, 5000 + insideResponse.length, "HTTP/1.1 599 After Window\r\n\r\n", true) },
];
const insideBytes = frames[3]!.data.length + frames[6]!.data.length;

describe("case-window-scoped packet ingestion and sessions", () => {
  let runtime: string;
  let caseDir: string;
  let pcapPath: string;

  beforeAll(() => {
    // All generated case data, captures and SQLite caches remain outside the Git tree.
    runtime = fs.mkdtempSync(path.join(os.tmpdir(), "hunt-session-window-"));
    caseDir = path.join(runtime, "session-window-case");
    fs.mkdirSync(caseDir);
    fs.writeFileSync(path.join(caseDir, "case.json"), JSON.stringify({
      case_id: "session-window-case",
      data_origin: "synthetic",
      time_range_utc: {
        start_inclusive: "2026-11-14T10:00:00.000000101Z",
        end_exclusive: "2026-11-14T10:00:00.000000109Z",
      },
    }));
    pcapPath = path.join(caseDir, "traffic.pcap");
    fs.writeFileSync(pcapPath, pcapNs(frames));
  });

  afterAll(() => {
    fs.rmSync(runtime, { recursive: true, force: true });
  });

  test("filters before decoding and TCP reassembly while preserving physical frame ordinals", () => {
    const packets: DissectedPacket[] = [];
    const scoped = streamDissectPcapFile(pcapPath, {
      window: { startNs: START_NS, endNs: END_NS },
      onPacket: (packet) => packets.push(packet),
    });
    expect(scoped.totalFrames).toBe(frames.length);
    expect(packets.map((packet) => packet.frameNumber)).toEqual([4, 5, 6, 7]);
    expect(packets.map((packet) => packet.tsNs)).toEqual([START_NS, START_NS + 1n, END_NS - 2n, END_NS - 1n]);
    expect(scoped.sessions).toHaveLength(3);
    const session = scoped.sessions.find((candidate) => candidate.srcPort === 31000)!;
    expect(session.networkPackets).toBe(2);
    expect(session.networkBytes).toBe(insideBytes);
    expect(session.srcBytes).toBe(frames[3]!.data.length);
    expect(session.dstBytes).toBe(frames[6]!.data.length);
    expect([...session.httpHosts]).toEqual(["inside.test"]);
    expect([...session.httpUris]).toEqual(["/inside"]);
    expect([...session.httpUserAgents]).toEqual(["inside-agent"]);
    expect([...session.httpStatusCodes]).toEqual([204]);
    for (const port of [31001, 31002]) {
      const split = scoped.sessions.find((candidate) => candidate.srcPort === port)!;
      expect(split.networkPackets).toBe(1);
      expect([...split.protocols]).toEqual(["tcp"]);
      expect([...split.httpHosts]).toEqual([]);
    }

    const unscopedPackets: DissectedPacket[] = [];
    const unscoped = streamDissectPcapFile(pcapPath, { onPacket: (packet) => unscopedPackets.push(packet) });
    expect(unscoped.totalFrames).toBe(frames.length);
    expect(unscopedPackets).toHaveLength(frames.length);
    expect(unscoped.sessions).toHaveLength(5);
    expect([...unscoped.sessions.find((candidate) => candidate.srcPort === 31001)!.httpHosts]).toEqual(["cross-before.test"]);
    expect([...unscoped.sessions.find((candidate) => candidate.srcPort === 31002)!.httpHosts]).toEqual(["cross-after.test"]);
  });

  for (const mode of ["async", "sync"] as const) {
    test(`${mode} cold and warm APIs expose only exact-window session fields, counts and packet rows`, async () => {
      const options = { cacheDir: path.join(runtime, `${mode}-cache`) };
      for (const warm of [false, true]) {
        const plane = mode === "async"
          ? await EmbeddedHuntDataPlane.open(caseDir, options)
          : EmbeddedHuntDataPlane.openSync(caseDir, options);
        try {
          expect(plane.cacheHit).toBe(warm);
          expect(plane.packetFields({}).rows.map((row) => row["frame.number"])).toEqual([4, 5, 6, 7]);
          expect(plane.packetFields({ filter: 'http.host == "inside.test"' }).rows.map((row) => row["frame.number"])).toEqual([4]);
          for (const host of ["before.test", "after.test", "before-only.test", "after-only.test", "cross-before.test", "cross-after.test"]) {
            expect(plane.packetFields({ filter: `http.host == "${host}"` }).returned).toBe(0);
            expect(plane.arkimeSessions({ expression: `host.http == "${host}"` }).returned).toBe(0);
          }
          expect(plane.arkimeSessions({}).recordsFiltered).toBe(3);
          const main = plane.arkimeSessions({
            expression: "port.src == 31000",
            fields: "firstPacket,lastPacket,network.packets,network.bytes,source.bytes,destination.bytes,http.host,http.uri,http.useragent,http.statuscode",
          });
          expect(main.returned).toBe(1);
          expect(main.sessions[0]).toEqual({
            firstPacket: "2026-11-14T10:00:00.000Z",
            lastPacket: "2026-11-14T10:00:00.000Z",
            "network.packets": 2,
            "network.bytes": insideBytes,
            "source.bytes": frames[3]!.data.length,
            "destination.bytes": frames[6]!.data.length,
            "http.host": ["inside.test"],
            "http.uri": ["/inside"],
            "http.useragent": ["inside-agent"],
            "http.statuscode": [204],
          });
          expect(plane.arkimeUnique({ field: "host.http", counts: 1 }).values).toEqual([{ value: "inside.test", count: 1 }]);
          expect(plane.arkimeUnique({ field: "protocols", counts: 1 }).values).toEqual([
            { value: "tcp", count: 3 },
            { value: "http", count: 1 },
          ]);
          const network = plane.huntLabQuery({ dataset: "network" });
          expect(network).toMatchObject({
            total: 3,
            returned: 3,
            records: [
              { source: { port: 31000 }, network: { packets: 2, bytes: insideBytes, protocol: ["tcp", "http"] } },
              { source: { port: 31001 }, network: { packets: 1, bytes: frames[4]!.data.length, protocol: ["tcp"] } },
              { source: { port: 31002 }, network: { packets: 1, bytes: frames[5]!.data.length, protocol: ["tcp"] } },
            ],
          });
          const citations = plane.verifyCitations(frames.map((_, index) => `frame-${index + 1}`));
          expect(citations.resolved.frameIds).toEqual(["frame-4", "frame-5", "frame-6", "frame-7"]);
          expect(citations.unresolved).toEqual(["frame-1", "frame-2", "frame-3", "frame-8", "frame-9", "frame-10", "frame-11"]);
        } finally {
          await plane.close();
        }
      }
    });
  }
});
