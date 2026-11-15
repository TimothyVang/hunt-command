import { Database } from "bun:sqlite";
import { MAX_PACKET_VALUE } from "@hunt-command/shared";
import {
  type DissectedPacket,
  type DissectedSession,
  redactUri,
  streamDissectPcapFile,
} from "./pcap-dissector.ts";
import { formatIsoMillis, ipToBytes16 } from "./timestamps-and-ip.ts";

declare const self: Worker | undefined;

export interface PcapWorkerRequest {
  dbPath: string;
  pcapPath: string;
  caseId: string;
  startNs: bigint;
  endNs: bigint;
}

export interface PcapWorkerResponse {
  ok: boolean;
  totalFrames?: number;
  totalSessions?: number;
  error?: string;
}

const PACKET_IP_KV_FIELDS: ReadonlySet<string> = new Set([
  "ip.src",
  "ip.dst",
  "ipv6.src",
  "ipv6.dst",
  "dns.a",
  "dns.aaaa",
]);

function capPacketString(field: string, raw: string): string {
  const val = field === "http.request.uri" ? redactUri(raw) : raw;
  return val.length > MAX_PACKET_VALUE ? `${val.slice(0, MAX_PACKET_VALUE)}…` : val;
}

function parseNumericIfClean(val: string): number | null {
  if (/^0x[0-9a-fA-F]+$/.test(val)) {
    return Number.parseInt(val, 16);
  }
  if (/^-?[0-9]+(?:\.[0-9]+)?$/.test(val)) {
    const n = Number(val);
    return Number.isFinite(n) ? n : null;
  }
  return null;
}

export function ensureNetworkTables(db: Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS packets (
      frame_number INTEGER PRIMARY KEY,
      ts_ns INTEGER NOT NULL,
      time_epoch TEXT NOT NULL,
      frame_len INTEGER NOT NULL,
      ws_protocol TEXT NOT NULL,
      proto_mask TEXT NOT NULL,
      row_json TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS packet_kv (
      frame_number INTEGER NOT NULL,
      field TEXT NOT NULL,
      val_str TEXT NOT NULL,
      val_num REAL
    );

    CREATE TABLE IF NOT EXISTS packet_ips (
      frame_number INTEGER NOT NULL,
      field TEXT NOT NULL,
      ip_bin BLOB NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
      session_id INTEGER PRIMARY KEY,
      first_packet_ms INTEGER NOT NULL,
      last_packet_ms INTEGER NOT NULL,
      src_ip TEXT NOT NULL,
      src_port INTEGER NOT NULL,
      dst_ip TEXT NOT NULL,
      dst_port INTEGER NOT NULL,
      ip_protocol INTEGER NOT NULL,
      ip_protocol_name TEXT NOT NULL,
      network_bytes INTEGER NOT NULL,
      network_packets INTEGER NOT NULL,
      src_bytes INTEGER NOT NULL,
      dst_bytes INTEGER NOT NULL,
      arkime_json TEXT NOT NULL,
      network_json TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS session_kv (
      session_id INTEGER NOT NULL,
      field TEXT NOT NULL,
      val_str TEXT NOT NULL,
      val_num REAL
    );

    CREATE TABLE IF NOT EXISTS session_ips (
      session_id INTEGER NOT NULL,
      field TEXT NOT NULL,
      ip_bin BLOB NOT NULL
    );
  `);
}

export function createNetworkIndexes(db: Database): void {
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_packet_kv_field_str ON packet_kv(field, val_str, frame_number);
    CREATE INDEX IF NOT EXISTS idx_packet_kv_field_num ON packet_kv(field, val_num, frame_number);
    CREATE INDEX IF NOT EXISTS idx_packet_ips_lookup ON packet_ips(field, ip_bin, frame_number);
    CREATE INDEX IF NOT EXISTS idx_sessions_first_pkt ON sessions(first_packet_ms, session_id);
    CREATE INDEX IF NOT EXISTS idx_session_kv_field_str ON session_kv(field, val_str, session_id);
    CREATE INDEX IF NOT EXISTS idx_session_kv_field_num ON session_kv(field, val_num, session_id);
    CREATE INDEX IF NOT EXISTS idx_session_ips_lookup ON session_ips(field, ip_bin, session_id);
  `);
}

function buildArkimeSessionDoc(s: DissectedSession): Record<string, unknown> {
  const doc: Record<string, unknown> = {
    firstPacket: formatIsoMillis(s.firstPacketMs),
    lastPacket: formatIsoMillis(s.lastPacketMs),
    source: {
      ip: s.srcIp,
      port: s.srcPort,
      bytes: s.srcBytes,
    },
    destination: {
      ip: s.dstIp,
      port: s.dstPort,
      bytes: s.dstBytes,
    },
    ipProtocol: s.ipProtocol,
    protocol: [...s.protocols],
    network: {
      bytes: s.networkBytes,
      packets: s.networkPackets,
    },
    tags: [...s.tags],
  };

  if (s.dnsHosts.size > 0 || s.dnsQueryTypes.size > 0) {
    const dnsObj: Record<string, unknown> = {};
    if (s.dnsHosts.size > 0) dnsObj.host = [...s.dnsHosts];
    if (s.dnsQueryTypes.size > 0) dnsObj.qt = [...s.dnsQueryTypes];
    doc.dns = dnsObj;
  }

  if (
    s.httpHosts.size > 0 ||
    s.httpUris.size > 0 ||
    s.httpMethods.size > 0 ||
    s.httpStatusCodes.size > 0 ||
    s.httpUserAgents.size > 0
  ) {
    const httpObj: Record<string, unknown> = {};
    if (s.httpHosts.size > 0) httpObj.host = [...s.httpHosts];
    if (s.httpUris.size > 0) httpObj.uri = [...s.httpUris];
    if (s.httpMethods.size > 0) httpObj.method = [...s.httpMethods];
    if (s.httpStatusCodes.size > 0) httpObj.statuscode = [...s.httpStatusCodes];
    if (s.httpUserAgents.size > 0) httpObj.useragent = [...s.httpUserAgents];
    doc.http = httpObj;
  }

  if (
    s.tlsVersions.size > 0 ||
    s.tlsCiphers.size > 0 ||
    s.tlsJa3.size > 0 ||
    s.tlsJa4.size > 0
  ) {
    const tlsObj: Record<string, unknown> = {};
    if (s.tlsVersions.size > 0) tlsObj.version = [...s.tlsVersions];
    if (s.tlsCiphers.size > 0) tlsObj.cipher = [...s.tlsCiphers];
    if (s.tlsJa3.size > 0) tlsObj.ja3 = [...s.tlsJa3];
    if (s.tlsJa4.size > 0) tlsObj.ja4 = [...s.tlsJa4];
    doc.tls = tlsObj;
  }

  return doc;
}

function buildNetworkDatasetDoc(s: DissectedSession): Record<string, unknown> {
  const doc: Record<string, unknown> = {
    firstPacket: formatIsoMillis(s.firstPacketMs),
    lastPacket: formatIsoMillis(s.lastPacketMs),
    source: {
      ip: s.srcIp,
      port: s.srcPort,
    },
    destination: {
      ip: s.dstIp,
      port: s.dstPort,
    },
    network: {
      packets: s.networkPackets,
      bytes: s.networkBytes,
      protocol: [...s.protocols],
    },
    node: "hunt-lab",
  };
  if (s.dnsHosts.size > 0) {
    doc.dns = { host: [...s.dnsHosts] };
  }
  return doc;
}

export function indexPcapIntoDatabase(
  db: Database,
  pcapPath: string,
  caseId: string,
  startNs: bigint,
  endNs: bigint,
): { totalFrames: number; totalSessions: number } {
  ensureNetworkTables(db);

  const insertPacket = db.prepare(
    `INSERT INTO packets (frame_number, ts_ns, time_epoch, frame_len, ws_protocol, proto_mask, row_json)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  );
  const insertPacketKv = db.prepare(
    `INSERT INTO packet_kv (frame_number, field, val_str, val_num) VALUES (?, ?, ?, ?)`,
  );
  const insertPacketIp = db.prepare(
    `INSERT INTO packet_ips (frame_number, field, ip_bin) VALUES (?, ?, ?)`,
  );

  const BATCH_SIZE = 4_000;
  let packetBatch: DissectedPacket[] = [];

  const flushPacketBatch = db.transaction((batch: readonly DissectedPacket[]) => {
    for (const pkt of batch) {
      const rowObj: Record<string, unknown> = {
        "frame.number": pkt.frameNumber,
        "frame.time_epoch": pkt.timeEpochStr,
        "frame.len": String(pkt.frameLen),
        "_ws.col.Protocol": pkt.wsProtocol,
      };

      for (const [field, values] of pkt.kv.entries()) {
        if (values.length === 0) continue;
        const joined = capPacketString(field, values.join(","));
        rowObj[field] = joined;

        for (const v of values) {
          insertPacketKv.run(pkt.frameNumber, field, v, parseNumericIfClean(v));
          if (PACKET_IP_KV_FIELDS.has(field)) {
            const bin = ipToBytes16(v);
            if (bin) {
              insertPacketIp.run(pkt.frameNumber, field, bin);
            }
          }
        }
      }

      const protoMask =
        pkt.protocols.size > 0 ? `|${[...pkt.protocols].join("|")}|` : "";
      insertPacket.run(
        pkt.frameNumber,
        pkt.tsNs,
        pkt.timeEpochStr,
        pkt.frameLen,
        pkt.wsProtocol,
        protoMask,
        JSON.stringify(rowObj),
      );
    }
  });

  let totalFrames = 0;
  let sessions: DissectedSession[] = [];
  try {
    const dissected = streamDissectPcapFile(pcapPath, {
      caseId,
      window: { startNs, endNs },
      onPacket: (pkt) => {
        packetBatch.push(pkt);
        if (packetBatch.length >= BATCH_SIZE) {
          flushPacketBatch(packetBatch);
          packetBatch = [];
        }
      },
    });
    totalFrames = dissected.totalFrames;
    sessions = dissected.sessions;

    if (packetBatch.length > 0) {
      flushPacketBatch(packetBatch);
      packetBatch = [];
    }
  } finally {
    insertPacket.finalize();
    insertPacketKv.finalize();
    insertPacketIp.finalize();
  }

  const insertSession = db.prepare(
    `INSERT INTO sessions (
       session_id, first_packet_ms, last_packet_ms, src_ip, src_port, dst_ip, dst_port,
       ip_protocol, ip_protocol_name, network_bytes, network_packets, src_bytes, dst_bytes,
       arkime_json, network_json
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  );
  const insertSessionKv = db.prepare(
    `INSERT INTO session_kv (session_id, field, val_str, val_num) VALUES (?, ?, ?, ?)`,
  );
  const insertSessionIp = db.prepare(
    `INSERT INTO session_ips (session_id, field, ip_bin) VALUES (?, ?, ?)`,
  );

  try {
    const flushSessions = db.transaction((allSessions: readonly DissectedSession[]) => {
      for (const s of allSessions) {
        const arkimeDoc = buildArkimeSessionDoc(s);
        const networkDoc = buildNetworkDatasetDoc(s);

        insertSession.run(
          s.sessionId,
          s.firstPacketMs,
          s.lastPacketMs,
          s.srcIp,
          s.srcPort,
          s.dstIp,
          s.dstPort,
          s.ipProtocol,
          s.ipProtocolName,
          s.networkBytes,
          s.networkPackets,
          s.srcBytes,
          s.dstBytes,
          JSON.stringify(arkimeDoc),
          JSON.stringify(networkDoc),
        );

        if (s.srcIpBin) insertSessionIp.run(s.sessionId, "ip.src", s.srcIpBin);
        if (s.dstIpBin) insertSessionIp.run(s.sessionId, "ip.dst", s.dstIpBin);

        insertSessionKv.run(s.sessionId, "ip.src", s.srcIp, null);
        insertSessionKv.run(s.sessionId, "ip.dst", s.dstIp, null);
        insertSessionKv.run(s.sessionId, "port.src", String(s.srcPort), s.srcPort);
        insertSessionKv.run(s.sessionId, "port.dst", String(s.dstPort), s.dstPort);
        insertSessionKv.run(s.sessionId, "ip.protocol", s.ipProtocolName, s.ipProtocol);

        for (const proto of s.protocols) {
          insertSessionKv.run(s.sessionId, "protocols", proto, null);
        }
        for (const host of s.dnsHosts) {
          insertSessionKv.run(s.sessionId, "host.dns", host, null);
        }
        for (const qt of s.dnsQueryTypes) {
          insertSessionKv.run(s.sessionId, "dns.query.type", qt, null);
        }
        for (const hh of s.httpHosts) {
          insertSessionKv.run(s.sessionId, "host.http", hh, null);
        }
        for (const uri of s.httpUris) {
          insertSessionKv.run(s.sessionId, "http.uri", uri, null);
        }
        for (const method of s.httpMethods) {
          insertSessionKv.run(s.sessionId, "http.method", method, null);
        }
        for (const code of s.httpStatusCodes) {
          insertSessionKv.run(s.sessionId, "http.statuscode", String(code), code);
        }
        for (const ua of s.httpUserAgents) {
          insertSessionKv.run(s.sessionId, "http.user-agent", ua, null);
        }
        for (const ver of s.tlsVersions) {
          insertSessionKv.run(s.sessionId, "tls.version", ver, null);
        }
        for (const ciph of s.tlsCiphers) {
          insertSessionKv.run(s.sessionId, "tls.cipher", ciph, null);
        }
        for (const ja3 of s.tlsJa3) {
          insertSessionKv.run(s.sessionId, "tls.ja3", ja3, null);
        }
        for (const ja4 of s.tlsJa4) {
          insertSessionKv.run(s.sessionId, "tls.ja4", ja4, null);
        }
        for (const tag of s.tags) {
          insertSessionKv.run(s.sessionId, "tags", tag, null);
        }
      }
    });

    flushSessions(sessions);
  } finally {
    insertSession.finalize();
    insertSessionKv.finalize();
    insertSessionIp.finalize();
  }

  createNetworkIndexes(db);
  db.exec("PRAGMA wal_checkpoint(TRUNCATE);");

  return { totalFrames, totalSessions: sessions.length };
}

export function runPcapIndexerWorker(req: PcapWorkerRequest): Promise<{
  totalFrames: number;
  totalSessions: number;
}> {
  return new Promise((resolve, reject) => {
    const workerUrl = new URL("./pcap-worker.ts", import.meta.url).href;
    const worker = new Worker(workerUrl);
    let settled = false;

    worker.onmessage = (ev: MessageEvent<PcapWorkerResponse>) => {
      if (settled) return;
      settled = true;
      worker.terminate();
      if (ev.data.ok) {
        resolve({
          totalFrames: ev.data.totalFrames ?? 0,
          totalSessions: ev.data.totalSessions ?? 0,
        });
      } else {
        reject(new Error(ev.data.error ?? "PCAP worker indexing failed"));
      }
    };

    worker.onerror = (err) => {
      if (settled) return;
      settled = true;
      worker.terminate();
      reject(new Error(err.message || "PCAP worker crashed"));
    };

    worker.postMessage(req);
  });
}

// Worker entrypoint when executed inside a Bun Worker thread
if (typeof self !== "undefined" && typeof self.postMessage === "function" && !Bun.isMainThread) {
  self.onmessage = (ev: MessageEvent<PcapWorkerRequest>) => {
    const { dbPath, pcapPath, caseId, startNs, endNs } = ev.data;
    let db: Database | null = null;
    try {
      db = new Database(dbPath);
      db.exec("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;");
      const stats = indexPcapIntoDatabase(db, pcapPath, caseId, startNs, endNs);
      db.close();
      db = null;
      const resp: PcapWorkerResponse = {
        ok: true,
        totalFrames: stats.totalFrames,
        totalSessions: stats.totalSessions,
      };
      self.postMessage(resp);
    } catch (err) {
      if (db) {
        try {
          db.close();
        } catch {
          // ignore close error on failure
        }
      }
      const resp: PcapWorkerResponse = {
        ok: false,
        error: err instanceof Error ? err.message : String(err),
      };
      self.postMessage(resp);
    }
  };
}
