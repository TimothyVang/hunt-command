const ISO_TS_RE =
  /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:?\d{2})$/;

export function parseTimestampNs(iso: string): bigint {
  const m = ISO_TS_RE.exec(iso.trim());
  if (!m) {
    throw new Error(`Invalid UTC timestamp: '${iso}'`);
  }

  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);
  const hour = Number(m[4]);
  const minute = Number(m[5]);
  const second = Number(m[6]);
  const fracStr = m[7] ?? "";
  const tz = m[8]!;

  if (
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > 31 ||
    hour > 23 ||
    minute > 59 ||
    second > 60
  ) {
    throw new Error(`Out-of-range calendar fields in timestamp '${iso}'`);
  }

  let utcMs = Date.UTC(year, month - 1, day, hour, minute, second, 0);
  // Reject overflowed calendar dates like Feb 30.
  const check = new Date(utcMs);
  if (
    check.getUTCFullYear() !== year ||
    check.getUTCMonth() !== month - 1 ||
    check.getUTCDate() !== day
  ) {
    throw new Error(`Invalid calendar date in timestamp '${iso}'`);
  }

  if (tz !== "Z") {
    const sign = tz[0] === "-" ? -1 : 1;
    const cleanTz = tz.slice(1).replace(":", "");
    const tzHours = Number(cleanTz.slice(0, 2));
    const tzMins = Number(cleanTz.slice(2, 4));
    if (tzHours > 23 || tzMins > 59) {
      throw new Error(`Invalid timezone offset in timestamp '${iso}'`);
    }
    const offsetMs = sign * (tzHours * 60 + tzMins) * 60_000;
    utcMs -= offsetMs;
  }

  const subsecNs = fracStr.length > 0 ? BigInt(fracStr.padEnd(9, "0")) : 0n;
  return BigInt(utcMs) * 1_000_000n + subsecNs;
}

export function epochMillisFromNs(tsNs: bigint): number {
  return Number(tsNs / 1_000_000n);
}

export function formatIsoMillis(epochMs: number): string {
  return new Date(epochMs).toISOString();
}

export function formatIsoSecondsZ(epochMs: number): string {
  return new Date(epochMs).toISOString().replace(/\.\d{3}Z$/, "Z");
}

export function formatNsAsIso(tsNs: bigint): string {
  const secNs = 1_000_000_000n;
  let sec = tsNs / secNs;
  let remNs = tsNs % secNs;
  if (remNs < 0n) {
    sec -= 1n;
    remNs += secNs;
  }
  const baseIso = new Date(Number(sec) * 1000).toISOString().slice(0, 19);
  if (remNs === 0n) {
    return `${baseIso}.000Z`;
  }
  const nano9 = remNs.toString().padStart(9, "0");
  // Trim trailing triplet zeros down to millisecond precision when exact milliseconds, else keep nanos.
  if (nano9.endsWith("000000")) {
    return `${baseIso}.${nano9.slice(0, 3)}Z`;
  }
  if (nano9.endsWith("000")) {
    return `${baseIso}.${nano9.slice(0, 6)}Z`;
  }
  return `${baseIso}.${nano9}Z`;
}

function parseIpv4FourBytes(ip: string): [number, number, number, number] | null {
  const parts = ip.split(".");
  if (parts.length !== 4) {
    return null;
  }
  const out: number[] = [];
  for (const part of parts) {
    if (!/^(?:0|[1-9]\d{0,2})$/.test(part)) {
      return null;
    }
    const val = Number(part);
    if (val < 0 || val > 255) {
      return null;
    }
    out.push(val);
  }
  return [out[0]!, out[1]!, out[2]!, out[3]!];
}

export function isIpv4Address(ip: string): boolean {
  return parseIpv4FourBytes(ip) !== null;
}

/**
 * Encodes IPv4 (`::ffff:a.b.c.d`) or IPv6 into a canonical 16-byte big-endian Uint8Array
 * so SQLite `BLOB(16)` `BETWEEN` performs exact B-tree CIDR and range lookups.
 */
export function ipToBytes16(rawIp: string): Uint8Array | null {
  const ip = rawIp.trim();
  if (ip.length === 0 || ip.length > 64) {
    return null;
  }

  const v4 = parseIpv4FourBytes(ip);
  if (v4 !== null) {
    const buf = new Uint8Array(16);
    buf[10] = 0xff;
    buf[11] = 0xff;
    buf[12] = v4[0];
    buf[13] = v4[1];
    buf[14] = v4[2];
    buf[15] = v4[3];
    return buf;
  }

  if (!ip.includes(":")) {
    return null;
  }

  // Handle optional embedded IPv4 tail (e.g., ::ffff:10.20.2.107)
  let work = ip;
  let embeddedTail: [number, number] | null = null;
  const lastColon = work.lastIndexOf(":");
  if (lastColon >= 0 && work.slice(lastColon + 1).includes(".")) {
    const tailV4 = parseIpv4FourBytes(work.slice(lastColon + 1));
    if (tailV4 === null) {
      return null;
    }
    embeddedTail = [(tailV4[0] << 8) | tailV4[1], (tailV4[2] << 8) | tailV4[3]];
    work = work.slice(0, lastColon + 1) + "0:0";
  }

  const doubleColonParts = work.split("::");
  if (doubleColonParts.length > 2) {
    return null;
  }

  const parseGroups = (segment: string): number[] | null => {
    if (segment === "") {
      return [];
    }
    const pieces = segment.split(":");
    const nums: number[] = [];
    for (const p of pieces) {
      if (!/^[0-9A-Fa-f]{1,4}$/.test(p)) {
        return null;
      }
      nums.push(Number.parseInt(p, 16));
    }
    return nums;
  };

  let groups: number[];
  if (doubleColonParts.length === 2) {
    const left = parseGroups(doubleColonParts[0]!);
    const right = parseGroups(doubleColonParts[1]!);
    if (left === null || right === null) {
      return null;
    }
    const missing = 8 - (left.length + right.length);
    if (missing < 1) {
      return null;
    }
    groups = [...left, ...new Array<number>(missing).fill(0), ...right];
  } else {
    const parsed = parseGroups(work);
    if (parsed === null || parsed.length !== 8) {
      return null;
    }
    groups = parsed;
  }

  if (embeddedTail !== null) {
    groups[6] = embeddedTail[0];
    groups[7] = embeddedTail[1];
  }

  const out = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    const g = groups[i]!;
    out[i * 2] = (g >>> 8) & 0xff;
    out[i * 2 + 1] = g & 0xff;
  }
  return out;
}

export function cidrOrIpToBounds16(
  expr: string,
): { lo: Uint8Array; hi: Uint8Array } | null {
  const trimmed = expr.trim();
  const slashIdx = trimmed.indexOf("/");
  if (slashIdx === -1) {
    const exact = ipToBytes16(trimmed);
    return exact ? { lo: exact, hi: exact } : null;
  }

  const addrPart = trimmed.slice(0, slashIdx);
  const prefixPart = trimmed.slice(slashIdx + 1);
  if (!/^(?:0|[1-9]\d{0,2})$/.test(prefixPart)) {
    return null;
  }
  const rawPrefix = Number(prefixPart);
  const isV4 = isIpv4Address(addrPart);
  const base = ipToBytes16(addrPart);
  if (base === null) {
    return null;
  }

  let bitPrefix: number;
  if (isV4) {
    if (rawPrefix < 0 || rawPrefix > 32) {
      return null;
    }
    // Keep ::ffff:0:0/96 prefix intact so IPv4 0.0.0.0/0 never matches native IPv6.
    bitPrefix = 96 + rawPrefix;
  } else {
    if (rawPrefix < 0 || rawPrefix > 128) {
      return null;
    }
    bitPrefix = rawPrefix;
  }

  const lo = new Uint8Array(base);
  const hi = new Uint8Array(base);

  for (let byteIdx = 0; byteIdx < 16; byteIdx++) {
    const bitStart = byteIdx * 8;
    if (bitPrefix >= bitStart + 8) {
      continue;
    }
    if (bitPrefix <= bitStart) {
      lo[byteIdx] = 0x00;
      hi[byteIdx] = 0xff;
    } else {
      const keepBits = bitPrefix - bitStart;
      const mask = (0xff << (8 - keepBits)) & 0xff;
      lo[byteIdx] = lo[byteIdx]! & mask;
      hi[byteIdx] = hi[byteIdx]! | (~mask & 0xff);
    }
  }

  return { lo, hi };
}

export function formatIpv4Bytes(bytes: Uint8Array, offset = 0): string {
  return `${bytes[offset]!}.${bytes[offset + 1]!}.${bytes[offset + 2]!}.${bytes[offset + 3]!}`;
}

export function formatIpv6Bytes(bytes: Uint8Array, offset = 0): string {
  const groups: number[] = [];
  for (let i = 0; i < 8; i++) {
    groups.push(((bytes[offset + i * 2]! << 8) | bytes[offset + i * 2 + 1]!) >>> 0);
  }

  // RFC 5952 longest zero-run compression
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;

  for (let i = 0; i < 8; i++) {
    if (groups[i] === 0) {
      if (curStart === -1) {
        curStart = i;
        curLen = 1;
      } else {
        curLen++;
      }
      if (curLen > bestLen && curLen >= 2) {
        bestStart = curStart;
        bestLen = curLen;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }

  if (bestStart === -1) {
    return groups.map((g) => g.toString(16)).join(":");
  }

  const left = groups.slice(0, bestStart).map((g) => g.toString(16)).join(":");
  const right = groups.slice(bestStart + bestLen).map((g) => g.toString(16)).join(":");
  return `${left}::${right}`;
}

const MISSING = Symbol("MISSING");

function pickInternal(value: unknown, parts: readonly string[]): unknown {
  if (parts.length === 0) {
    return value;
  }
  if (Array.isArray(value)) {
    const found: unknown[] = [];
    for (const entry of value) {
      const item = pickInternal(entry, parts);
      if (item !== MISSING) {
        found.push(item);
      }
    }
    return found.length > 0 ? found : MISSING;
  }
  if (value === null || typeof value !== "object") {
    return MISSING;
  }
  const obj = value as Record<string, unknown>;
  // Accept nested ECS objects and literal dotted keys (mirrors lab_server.py:317-323).
  for (let size = parts.length; size >= 1; size--) {
    const key = parts.slice(0, size).join(".");
    if (Object.prototype.hasOwnProperty.call(obj, key)) {
      const sub = pickInternal(obj[key], parts.slice(size));
      if (sub !== MISSING) {
        return sub;
      }
    }
  }
  return MISSING;
}

export function pickFieldValue(source: Record<string, unknown>, dottedField: string): unknown {
  const res = pickInternal(source, dottedField.split("."));
  return res === MISSING ? undefined : res;
}

export function flattenFields(
  source: Record<string, unknown>,
  fields: readonly string[],
): Record<string, unknown> {
  const row: Record<string, unknown> = {};
  for (const field of fields) {
    const val = pickFieldValue(source, field);
    if (val !== undefined) {
      row[field] = val;
    }
  }
  return row;
}

export function filterTopLevelFields(
  source: Record<string, unknown>,
  topLevelFields: readonly string[],
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const key of topLevelFields) {
    if (Object.prototype.hasOwnProperty.call(source, key)) {
      out[key] = source[key];
    }
  }
  return out;
}
