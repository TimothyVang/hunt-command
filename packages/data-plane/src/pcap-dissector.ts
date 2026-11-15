import crypto from "node:crypto";
import fs from "node:fs";
import { PACKET_FIELDS_REDACTED_QUERY } from "@hunt-command/shared";
import { formatIpv4Bytes, formatIpv6Bytes, ipToBytes16 } from "./timestamps-and-ip.ts";

const URL_USERINFO_RE = /([A-Za-z][A-Za-z0-9+.-]*:\/\/)[^/]*@/g;

/**
 * Mirrors `lab_server.py:redact_uri`: strips `scheme://user:pw@` userinfo and
 * replaces any `?query` or `#fragment` with `?[redacted]`.
 */
export function redactUri(value: string): string {
  const cutMatch = /[?#]/.exec(value);
  const rawPath = cutMatch ? value.slice(0, cutMatch.index) : value;
  const cleanPath = rawPath.replace(URL_USERINFO_RE, "$1");
  return cutMatch ? `${cleanPath}${PACKET_FIELDS_REDACTED_QUERY}` : cleanPath;
}

export function isGreaseValue(val: number): boolean {
  return (val & 0x0f0f) === 0x0a0a && ((val >>> 8) & 0xff) === (val & 0xff);
}

const DNS_QTYPE_MNEMONICS: Readonly<Record<number, string>> = {
  1: "A",
  2: "NS",
  5: "CNAME",
  6: "SOA",
  12: "PTR",
  15: "MX",
  16: "TXT",
  28: "AAAA",
  33: "SRV",
  35: "NAPTR",
  41: "OPT",
  43: "DS",
  46: "RRSIG",
  47: "NSEC",
  48: "DNSKEY",
  50: "NSEC3",
  64: "SVCB",
  65: "HTTPS",
  255: "ANY",
};

const TLS_CIPHER_NAMES: Readonly<Record<number, string>> = {
  0x1301: "TLS_AES_128_GCM_SHA256",
  0x1302: "TLS_AES_256_GCM_SHA384",
  0x1303: "TLS_CHACHA20_POLY1305_SHA256",
  0x1304: "TLS_AES_128_CCM_SHA256",
  0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
  0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
  0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
  0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
  0xcca8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
  0xcca9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
  0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256",
  0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384",
  0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
  0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
};

export function dnsTypeToMnemonic(qtype: number): string {
  return DNS_QTYPE_MNEMONICS[qtype] ?? `TYPE${qtype}`;
}

/**
 * Loop-guarded (`<= 64` pointer hops) RFC 1035 `0xC0` DNS name reader.
 * Safely decompresses both QNAMEs and RDATA (`CNAME`, `NS`, `PTR`, etc.) without infinite loops.
 */
export function decompressDnsName(
  msg: Uint8Array,
  startOffset: number,
  maxHops = 64,
): { name: string; nextOffset: number } | null {
  if (startOffset < 0 || startOffset >= msg.length) {
    return null;
  }

  const labels: string[] = [];
  let pos = startOffset;
  let nextOffset = -1;
  let hops = 0;
  let totalChars = 0;

  while (true) {
    if (pos >= msg.length) {
      return null;
    }
    const len = msg[pos]!;
    if (len === 0) {
      if (nextOffset === -1) {
        nextOffset = pos + 1;
      }
      break;
    }

    const top2 = len & 0xc0;
    if (top2 === 0xc0) {
      if (pos + 1 >= msg.length) {
        return null;
      }
      const ptr = ((len & 0x3f) << 8) | msg[pos + 1]!;
      if (nextOffset === -1) {
        nextOffset = pos + 2;
      }
      hops++;
      if (hops > maxHops || ptr >= msg.length) {
        return null;
      }
      pos = ptr;
      continue;
    }

    if (top2 !== 0x00) {
      // Extended/reserved DNS label type outside RFC 1035 standard labels
      return null;
    }

    if (pos + 1 + len > msg.length) {
      return null;
    }
    totalChars += len + 1;
    if (totalChars > 255) {
      return null;
    }

    let label = "";
    for (let i = 0; i < len; i++) {
      const b = msg[pos + 1 + i]!;
      if (b >= 0x20 && b <= 0x7e) {
        label += String.fromCharCode(b);
      } else {
        label += `\\x${b.toString(16).padStart(2, "0")}`;
      }
    }
    labels.push(label);
    pos += 1 + len;
  }

  return {
    name: labels.join("."),
    nextOffset: nextOffset === -1 ? pos : nextOffset,
  };
}

export interface TlsClientHelloInfo {
  clientVersion: number;
  negotiatedOrMaxVersion: number;
  ciphers: number[];
  extensions: number[];
  sni: string | null;
  alpnFirst: string | null;
  supportedGroups: number[];
  ecPointFormats: number[];
  signatureAlgorithms: number[];
  ja3: string;
  ja4: string;
}

export interface TlsServerHelloInfo {
  serverVersion: number;
  selectedVersion: number;
  cipherSuite: number;
  extensions: number[];
  ja3s: string;
}

function tlsVersionToJa4Code(ver: number): string {
  switch (ver) {
    case 0x0304:
      return "13";
    case 0x0303:
      return "12";
    case 0x0302:
      return "11";
    case 0x0301:
      return "10";
    case 0x0300:
      return "s3";
    case 0xfeff:
      return "d1";
    case 0xfefd:
      return "d2";
    case 0xfefc:
      return "d3";
    default:
      return "00";
  }
}

function tlsVersionToLabel(ver: number): string {
  switch (ver) {
    case 0x0304:
      return "TLSv1.3";
    case 0x0303:
      return "TLSv1.2";
    case 0x0302:
      return "TLSv1.1";
    case 0x0301:
      return "TLSv1.0";
    case 0x0300:
      return "SSLv3";
    default:
      return `0x${ver.toString(16).padStart(4, "0")}`;
  }
}

function isAsciiAlnum(code: number): boolean {
  return (
    (code >= 0x30 && code <= 0x39) ||
    (code >= 0x41 && code <= 0x5a) ||
    (code >= 0x61 && code <= 0x7a)
  );
}

function formatJa4Alpn(alpnFirst: string | null): string {
  if (!alpnFirst || alpnFirst.length === 0) {
    return "00";
  }
  const firstCode = alpnFirst.charCodeAt(0);
  const lastCode = alpnFirst.charCodeAt(alpnFirst.length - 1);
  if (isAsciiAlnum(firstCode) && isAsciiAlnum(lastCode)) {
    return `${String.fromCharCode(firstCode)}${String.fromCharCode(lastCode)}`;
  }
  const firstHex = firstCode.toString(16).padStart(2, "0");
  const lastHex = lastCode.toString(16).padStart(2, "0");
  return `${firstHex[0]!}${lastHex[1]!}`;
}

/**
 * Computes exact FoxIO JA4 ClientHello fingerprint:
 * `<proto><ver><sni><cipher_cnt_2d><ext_cnt_2d><alpn_2c>_<sha256_12(sorted_ciphers)>_<sha256_12(sorted_exts_no_0000_0010 + "_" + unsorted_sig_algs)>`
 */
export function computeJa4(params: {
  transport: "t" | "q";
  version: number;
  hasSni: boolean;
  ciphers: readonly number[];
  extensions: readonly number[];
  alpnFirst: string | null;
  signatureAlgorithms: readonly number[];
}): string {
  const nonGreaseCiphers = params.ciphers.filter((c) => !isGreaseValue(c));
  const nonGreaseExts = params.extensions.filter((e) => !isGreaseValue(e));
  const nonGreaseSigAlgs = params.signatureAlgorithms.filter((s) => !isGreaseValue(s));

  const verCode = tlsVersionToJa4Code(params.version);
  const sniCode = params.hasSni ? "d" : "i";
  const cipherCount = Math.min(nonGreaseCiphers.length, 99).toString().padStart(2, "0");
  // FoxIO JA4 rule: SNI (0x0000) and ALPN (0x0010) ARE counted in the 2-digit extension count...
  const extCount = Math.min(nonGreaseExts.length, 99).toString().padStart(2, "0");
  const alpnCode = formatJa4Alpn(params.alpnFirst);
  const ja4a = `${params.transport}${verCode}${sniCode}${cipherCount}${extCount}${alpnCode}`;

  const ja4b =
    nonGreaseCiphers.length === 0
      ? "000000000000"
      : crypto
          .createHash("sha256")
          .update(
            nonGreaseCiphers
              .map((c) => c.toString(16).padStart(4, "0"))
              .sort()
              .join(","),
          )
          .digest("hex")
          .slice(0, 12);

  // ...and EXCLUDED from the sorted extension hash list in ja4_c!
  const sortedExtsForHash = nonGreaseExts
    .filter((e) => e !== 0x0000 && e !== 0x0010)
    .map((e) => e.toString(16).padStart(4, "0"))
    .sort();

  const sigAlgsHex = nonGreaseSigAlgs.map((s) => s.toString(16).padStart(4, "0"));

  let ja4c: string;
  if (sortedExtsForHash.length === 0 && sigAlgsHex.length === 0) {
    ja4c = "000000000000";
  } else {
    const extStr = sortedExtsForHash.join(",");
    const rawC =
      sigAlgsHex.length > 0
        ? extStr.length > 0
          ? `${extStr}_${sigAlgsHex.join(",")}`
          : sigAlgsHex.join(",")
        : extStr;
    ja4c = crypto.createHash("sha256").update(rawC).digest("hex").slice(0, 12);
  }

  return `${ja4a}_${ja4b}_${ja4c}`;
}

export function computeJa3(params: {
  clientVersion: number;
  ciphers: readonly number[];
  extensions: readonly number[];
  supportedGroups: readonly number[];
  ecPointFormats: readonly number[];
}): string {
  const c = params.ciphers.filter((v) => !isGreaseValue(v)).join("-");
  const e = params.extensions.filter((v) => !isGreaseValue(v)).join("-");
  const g = params.supportedGroups.filter((v) => !isGreaseValue(v)).join("-");
  const p = params.ecPointFormats.join("-");
  const raw = `${params.clientVersion},${c},${e},${g},${p}`;
  return crypto.createHash("md5").update(raw).digest("hex");
}

export function computeJa3s(params: {
  serverVersion: number;
  cipherSuite: number;
  extensions: readonly number[];
}): string {
  const e = params.extensions.filter((v) => !isGreaseValue(v)).join("-");
  const raw = `${params.serverVersion},${params.cipherSuite},${e}`;
  return crypto.createHash("md5").update(raw).digest("hex");
}

function readU16BE(buf: Uint8Array, off: number): number {
  return ((buf[off]! << 8) | buf[off + 1]!) >>> 0;
}

function readU24BE(buf: Uint8Array, off: number): number {
  return ((buf[off]! << 16) | (buf[off + 1]! << 8) | buf[off + 2]!) >>> 0;
}

function readU32BE(buf: Uint8Array, off: number): number {
  return (
    ((buf[off]! << 24) | (buf[off + 1]! << 16) | (buf[off + 2]! << 8) | buf[off + 3]!) >>> 0
  );
}

function readU16LE(buf: Uint8Array, off: number): number {
  return (buf[off]! | (buf[off + 1]! << 8)) >>> 0;
}

function readU32LE(buf: Uint8Array, off: number): number {
  return (
    (buf[off]! | (buf[off + 1]! << 8) | (buf[off + 2]! << 16) | (buf[off + 3]! << 24)) >>> 0
  );
}

export function parseTlsClientHello(
  body: Uint8Array,
  transport: "t" | "q" = "t",
): TlsClientHelloInfo | null {
  if (body.length < 38) {
    return null;
  }
  const clientVersion = readU16BE(body, 0);
  let pos = 2 + 32; // version + 32-byte random
  const sessionIdLen = body[pos]!;
  pos += 1 + sessionIdLen;
  if (pos + 2 > body.length) {
    return null;
  }

  const cipherBytesLen = readU16BE(body, pos);
  pos += 2;
  if (cipherBytesLen % 2 !== 0 || pos + cipherBytesLen > body.length) {
    return null;
  }
  const ciphers: number[] = [];
  for (let i = 0; i < cipherBytesLen; i += 2) {
    ciphers.push(readU16BE(body, pos + i));
  }
  pos += cipherBytesLen;

  if (pos + 1 > body.length) {
    return null;
  }
  const compLen = body[pos]!;
  pos += 1 + compLen;

  const extensions: number[] = [];
  let sni: string | null = null;
  let alpnFirst: string | null = null;
  const supportedGroups: number[] = [];
  const ecPointFormats: number[] = [];
  const signatureAlgorithms: number[] = [];
  let maxSupportedVersion = 0;

  if (pos + 2 <= body.length) {
    const extTotalLen = readU16BE(body, pos);
    pos += 2;
    const extEnd = Math.min(body.length, pos + extTotalLen);
    while (pos + 4 <= extEnd) {
      const extType = readU16BE(body, pos);
      const extLen = readU16BE(body, pos + 2);
      pos += 4;
      if (pos + extLen > extEnd) {
        break;
      }
      const extData = body.subarray(pos, pos + extLen);
      pos += extLen;
      extensions.push(extType);

      if (extType === 0x0000 && extData.length >= 5) {
        // server_name list
        const listLen = readU16BE(extData, 0);
        let sp = 2;
        const listEnd = Math.min(extData.length, 2 + listLen);
        while (sp + 3 <= listEnd) {
          const nameType = extData[sp]!;
          const nameLen = readU16BE(extData, sp + 1);
          sp += 3;
          if (sp + nameLen > listEnd) break;
          if (nameType === 0 && nameLen > 0 && sni === null) {
            sni = Buffer.from(extData.subarray(sp, sp + nameLen)).toString("utf8");
          }
          sp += nameLen;
        }
      } else if (extType === 0x0010 && extData.length >= 3) {
        // ALPN
        const listLen = readU16BE(extData, 0);
        if (2 <= extData.length && listLen >= 1) {
          const protoLen = extData[2]!;
          if (protoLen > 0 && 3 + protoLen <= extData.length) {
            alpnFirst = Buffer.from(extData.subarray(3, 3 + protoLen)).toString("latin1");
          }
        }
      } else if (extType === 0x000a && extData.length >= 2) {
        // supported_groups
        const listLen = readU16BE(extData, 0);
        const end = Math.min(extData.length, 2 + listLen);
        for (let gp = 2; gp + 2 <= end; gp += 2) {
          supportedGroups.push(readU16BE(extData, gp));
        }
      } else if (extType === 0x000b && extData.length >= 1) {
        // ec_point_formats
        const fmtLen = extData[0]!;
        const end = Math.min(extData.length, 1 + fmtLen);
        for (let fp = 1; fp < end; fp++) {
          ecPointFormats.push(extData[fp]!);
        }
      } else if (extType === 0x000d && extData.length >= 2) {
        // signature_algorithms
        const sigLen = readU16BE(extData, 0);
        const end = Math.min(extData.length, 2 + sigLen);
        for (let sp = 2; sp + 2 <= end; sp += 2) {
          signatureAlgorithms.push(readU16BE(extData, sp));
        }
      } else if (extType === 0x002b && extData.length >= 3) {
        // supported_versions (ClientHello: 1-byte length + uint16 versions)
        const svLen = extData[0]!;
        const end = Math.min(extData.length, 1 + svLen);
        for (let vp = 1; vp + 2 <= end; vp += 2) {
          const ver = readU16BE(extData, vp);
          if (!isGreaseValue(ver) && ver > maxSupportedVersion) {
            maxSupportedVersion = ver;
          }
        }
      }
    }
  }

  const effectiveVersion = maxSupportedVersion > 0 ? maxSupportedVersion : clientVersion;
  const ja4 = computeJa4({
    transport,
    version: effectiveVersion,
    hasSni: sni !== null && sni.length > 0,
    ciphers,
    extensions,
    alpnFirst,
    signatureAlgorithms,
  });
  const ja3 = computeJa3({
    clientVersion,
    ciphers,
    extensions,
    supportedGroups,
    ecPointFormats,
  });

  return {
    clientVersion,
    negotiatedOrMaxVersion: effectiveVersion,
    ciphers,
    extensions,
    sni,
    alpnFirst,
    supportedGroups,
    ecPointFormats,
    signatureAlgorithms,
    ja3,
    ja4,
  };
}

export function parseTlsServerHello(body: Uint8Array): TlsServerHelloInfo | null {
  if (body.length < 38) {
    return null;
  }
  const serverVersion = readU16BE(body, 0);
  let pos = 2 + 32;
  const sessionIdLen = body[pos]!;
  pos += 1 + sessionIdLen;
  if (pos + 3 > body.length) {
    return null;
  }
  const cipherSuite = readU16BE(body, pos);
  pos += 2;
  pos += 1; // compression method

  const extensions: number[] = [];
  let selectedVersion = serverVersion;

  if (pos + 2 <= body.length) {
    const extTotalLen = readU16BE(body, pos);
    pos += 2;
    const extEnd = Math.min(body.length, pos + extTotalLen);
    while (pos + 4 <= extEnd) {
      const extType = readU16BE(body, pos);
      const extLen = readU16BE(body, pos + 2);
      pos += 4;
      if (pos + extLen > extEnd) {
        break;
      }
      const extData = body.subarray(pos, pos + extLen);
      pos += extLen;
      extensions.push(extType);
      if (extType === 0x002b && extData.length >= 2) {
        const ver = readU16BE(extData, 0);
        if (!isGreaseValue(ver)) {
          selectedVersion = ver;
        }
      }
    }
  }

  return {
    serverVersion,
    selectedVersion,
    cipherSuite,
    extensions,
    ja3s: computeJa3s({ serverVersion, cipherSuite, extensions }),
  };
}

function decodeNtlmssp(blob: Uint8Array): { username?: string; domain?: string } | null {
  // Scan for "NTLMSSP\0" (4e 54 4c 4d 53 53 50 00)
  for (let i = 0; i + 64 <= blob.length; i++) {
    if (
      blob[i] === 0x4e &&
      blob[i + 1] === 0x54 &&
      blob[i + 2] === 0x4c &&
      blob[i + 3] === 0x4d &&
      blob[i + 4] === 0x53 &&
      blob[i + 5] === 0x53 &&
      blob[i + 6] === 0x50 &&
      blob[i + 7] === 0x00
    ) {
      const msg = blob.subarray(i);
      const msgType = readU32LE(msg, 8);
      if (msgType !== 3 || msg.length < 64) {
        continue;
      }
      const domLen = readU16LE(msg, 28);
      const domOff = readU32LE(msg, 32);
      const userLen = readU16LE(msg, 36);
      const userOff = readU32LE(msg, 40);
      const flags = readU32LE(msg, 60);
      const isUnicode = (flags & 0x00000001) !== 0;

      const decodeField = (off: number, len: number): string | undefined => {
        if (len === 0 || off + len > msg.length) {
          return undefined;
        }
        const slice = msg.subarray(off, off + len);
        const str = Buffer.from(slice)
          .toString(isUnicode ? "utf16le" : "latin1")
          .replace(/\0+$/g, "");
        return str.length > 0 ? str : undefined;
      };

      const domain = decodeField(domOff, domLen);
      const username = decodeField(userOff, userLen);
      if (domain || username) {
        return { username, domain };
      }
    }
  }
  return null;
}

function readDerTlv(
  buf: Uint8Array,
  offset: number,
): { tag: number; headerLen: number; length: number; valueStart: number; next: number } | null {
  if (offset >= buf.length) return null;
  const tag = buf[offset]!;
  let pos = offset + 1;
  // Long-form tag numbers (tag & 0x1f === 0x1f)
  if ((tag & 0x1f) === 0x1f) {
    while (pos < buf.length && (buf[pos]! & 0x80) !== 0) {
      pos++;
    }
    if (pos >= buf.length) return null;
    pos++;
  }
  if (pos >= buf.length) return null;
  const lenByte = buf[pos]!;
  pos++;
  let length = 0;
  if ((lenByte & 0x80) === 0) {
    length = lenByte;
  } else {
    const numBytes = lenByte & 0x7f;
    if (numBytes === 0 || numBytes > 4 || pos + numBytes > buf.length) {
      return null;
    }
    for (let i = 0; i < numBytes; i++) {
      length = (length << 8) | buf[pos + i]!;
    }
    pos += numBytes;
  }
  if (pos + length > buf.length) {
    return null;
  }
  return {
    tag,
    headerLen: pos - offset,
    length,
    valueStart: pos,
    next: pos + length,
  };
}

function parseKerberosPrincipalName(seqBytes: Uint8Array): string[] | null {
  // PrincipalName ::= SEQUENCE { name-type [0] Int32, name-string [1] SEQUENCE OF KerberosString }
  const outer = readDerTlv(seqBytes, 0);
  if (!outer || outer.tag !== 0x30) return null;
  let pos = outer.valueStart;
  const end = outer.next;
  let nameType: number | null = null;
  const parts: string[] = [];

  while (pos < end) {
    const tlv = readDerTlv(seqBytes, pos);
    if (!tlv) return null;
    if (tlv.tag === 0xa0) {
      const intTlv = readDerTlv(seqBytes, tlv.valueStart);
      if (!intTlv || intTlv.tag !== 0x02 || intTlv.length < 1) return null;
      nameType = seqBytes[intTlv.valueStart]!;
    } else if (tlv.tag === 0xa1) {
      const seqStr = readDerTlv(seqBytes, tlv.valueStart);
      if (!seqStr || seqStr.tag !== 0x30) return null;
      let sp = seqStr.valueStart;
      while (sp < seqStr.next) {
        const sTlv = readDerTlv(seqBytes, sp);
        if (!sTlv || (sTlv.tag !== 0x1b && sTlv.tag !== 0x0c && sTlv.tag !== 0x16)) {
          return null;
        }
        const text = Buffer.from(
          seqBytes.subarray(sTlv.valueStart, sTlv.next),
        ).toString("utf8");
        if (!text || /[\x00-\x1f\x7f]/.test(text)) return null;
        parts.push(text);
        sp = sTlv.next;
      }
    }
    pos = tlv.next;
  }

  if (nameType === null || parts.length === 0) {
    return null;
  }
  return parts;
}

function findDerChildByTag(
  buf: Uint8Array,
  seqStart: number,
  seqEnd: number,
  targetTag: number,
): { valueStart: number; next: number } | null {
  let pos = seqStart;
  while (pos < seqEnd) {
    const tlv = readDerTlv(buf, pos);
    if (!tlv || tlv.next > seqEnd) return null;
    if (tlv.tag === targetTag) {
      return { valueStart: tlv.valueStart, next: tlv.next };
    }
    pos = tlv.next;
  }
  return null;
}

function extractRfc4120KerberosCName(
  buf: Uint8Array,
  appTag: number,
  appValueStart: number,
  appEnd: number,
): { matched: boolean; cname: string | null } | null {
  const outerSeq = readDerTlv(buf, appValueStart);
  if (!outerSeq || outerSeq.tag !== 0x30 || outerSeq.next !== appEnd) {
    return null;
  }

  // RFC 4120 §5.4.1 KDC-REQ (AS-REQ = [APPLICATION 10] 0x6a, TGS-REQ = [APPLICATION 12] 0x6c):
  // req-body is [4] (0xa4) -> SEQUENCE (0x30) -> cname is [1] (0xa1) ONLY (never sname [3] 0xa3!).
  if (appTag === 0x6a || appTag === 0x6c) {
    const reqBodyTag = findDerChildByTag(buf, outerSeq.valueStart, outerSeq.next, 0xa4);
    if (!reqBodyTag) return null;
    const reqBodySeq = readDerTlv(buf, reqBodyTag.valueStart);
    if (!reqBodySeq || reqBodySeq.tag !== 0x30 || reqBodySeq.next !== reqBodyTag.next) {
      return null;
    }
    const cnameTag = findDerChildByTag(buf, reqBodySeq.valueStart, reqBodySeq.next, 0xa1);
    const parts = cnameTag
      ? parseKerberosPrincipalName(buf.subarray(cnameTag.valueStart, cnameTag.next))
      : null;
    return { matched: true, cname: parts && parts.length > 0 ? parts.join("/") : null };
  }

  // RFC 4120 §5.4.2 KDC-REP (AS-REP = [APPLICATION 11] 0x6b, TGS-REP = [APPLICATION 13] 0x6d):
  // cname is [4] (0xa4) ONLY (crealm is [3] 0xa3, ticket is [5] 0xa5).
  if (appTag === 0x6b || appTag === 0x6d) {
    const cnameTag = findDerChildByTag(buf, outerSeq.valueStart, outerSeq.next, 0xa4);
    if (!cnameTag) return null;
    const parts = parseKerberosPrincipalName(buf.subarray(cnameTag.valueStart, cnameTag.next));
    return { matched: true, cname: parts && parts.length > 0 ? parts.join("/") : null };
  }

  // RFC 4120 §5.9.1 KRB-ERROR ([APPLICATION 30] 0x7e):
  // cname is [8] (0xa8) OPTIONAL (sname is [10] 0xaa — never match sname!).
  if (appTag === 0x7e) {
    const cnameTag = findDerChildByTag(buf, outerSeq.valueStart, outerSeq.next, 0xa8);
    const parts = cnameTag
      ? parseKerberosPrincipalName(buf.subarray(cnameTag.valueStart, cnameTag.next))
      : null;
    return { matched: true, cname: parts && parts.length > 0 ? parts.join("/") : null };
  }

  // RFC 4120 §5.5.1 AP-REQ ([APPLICATION 14] 0x6e): valid Kerberos PDU, client principal is encrypted.
  if (appTag === 0x6e) {
    return { matched: true, cname: null };
  }

  return null;
}

function decodeKerberosMessage(work: Uint8Array): { matched: boolean; cname: string | null } {
  for (let i = 0; i + 10 <= work.length; i++) {
    const b = work[i]!;
    if (b === 0x6a || b === 0x6b || b === 0x6c || b === 0x6d || b === 0x6e || b === 0x7e) {
      const tlv = readDerTlv(work, i);
      if (tlv && tlv.length >= 8) {
        const res = extractRfc4120KerberosCName(work, b, tlv.valueStart, tlv.next);
        if (res) {
          return res;
        }
      }
    }
  }
  return { matched: false, cname: null };
}

export interface DissectedPacket {
  frameNumber: number;
  tsNs: bigint;
  timeEpochStr: string;
  frameLen: number;
  ipSrc?: string;
  ipDst?: string;
  ipv6Src?: string;
  ipv6Dst?: string;
  srcIpBin?: Uint8Array;
  dstIpBin?: Uint8Array;
  tcpSrcPort?: number;
  tcpDstPort?: number;
  tcpStream?: number;
  udpSrcPort?: number;
  udpDstPort?: number;
  wsProtocol: string;
  protocols: Set<string>;
  kv: Map<string, string[]>;
}

export interface DissectedSession {
  sessionId: number;
  firstPacketMs: number;
  lastPacketMs: number;
  srcIp: string;
  srcIpBin: Uint8Array | null;
  srcPort: number;
  dstIp: string;
  dstIpBin: Uint8Array | null;
  dstPort: number;
  ipProtocol: number;
  ipProtocolName: string;
  protocols: Set<string>;
  networkBytes: number;
  networkPackets: number;
  srcBytes: number;
  dstBytes: number;
  dnsHosts: Set<string>;
  dnsQueryTypes: Set<string>;
  httpHosts: Set<string>;
  httpUris: Set<string>;
  httpMethods: Set<string>;
  httpStatusCodes: Set<number>;
  httpUserAgents: Set<string>;
  tlsVersions: Set<string>;
  tlsCiphers: Set<string>;
  tlsJa3: Set<string>;
  tlsJa4: Set<string>;
  tags: Set<string>;
}

const STREAM_CAP_BYTES = 16_384;

interface TcpDirectionStream {
  initialized: boolean;
  sawSyn: boolean;
  baseSeq: number;
  buf: Uint8Array;
  maxFilled: number;
  parsedTlsOffsets: Set<number>;
  parsedHttp: boolean;
  dnsParsedOffset: number;
  krbParsedOffset: number;
}

interface SessionState {
  session: DissectedSession;
  initiatorIp: string;
  initiatorPort: number;
  tcpStreamId?: number;
  c2s?: TcpDirectionStream;
  s2c?: TcpDirectionStream;
}

function createDirStream(): TcpDirectionStream {
  return {
    initialized: false,
    sawSyn: false,
    baseSeq: 0,
    buf: new Uint8Array(STREAM_CAP_BYTES),
    maxFilled: 0,
    parsedTlsOffsets: new Set<number>(),
    parsedHttp: false,
    dnsParsedOffset: 0,
    krbParsedOffset: 0,
  };
}

function seqDelta(seq: number, baseSeq: number): number {
  const diff = (seq - baseSeq) | 0;
  return diff;
}

function appendToDirStream(dir: TcpDirectionStream, seq: number, payload: Uint8Array): Uint8Array {
  if (payload.length === 0) {
    return dir.buf.subarray(0, dir.maxFilled);
  }
  const uSeq = seq >>> 0;
  if (!dir.initialized) {
    dir.initialized = true;
    dir.baseSeq = uSeq;
  }
  const rel = seqDelta(uSeq, dir.baseSeq);
  if (rel < 0) {
    const shift = -rel;
    if (!dir.sawSyn && shift <= STREAM_CAP_BYTES) {
      // Mid-stream capture where an earlier TCP segment arrived out-of-order after a later one:
      // shift existing buffered bytes right, rebase baseSeq, and insert the earlier prefix at offset 0.
      const keepExisting = Math.max(0, Math.min(dir.maxFilled, STREAM_CAP_BYTES - shift));
      if (keepExisting > 0) {
        dir.buf.copyWithin(shift, 0, keepExisting);
      }
      if (shift > keepExisting) {
        dir.buf.fill(0, keepExisting, Math.min(shift, STREAM_CAP_BYTES));
      }
      const copyLen = Math.min(payload.length, STREAM_CAP_BYTES);
      dir.buf.set(payload.subarray(0, copyLen), 0);
      dir.baseSeq = uSeq;
      dir.maxFilled = Math.min(STREAM_CAP_BYTES, Math.max(shift + keepExisting, copyLen));

      if (dir.parsedTlsOffsets.size > 0) {
        const shifted = new Set<number>();
        for (const off of dir.parsedTlsOffsets) {
          if (off + shift < STREAM_CAP_BYTES) shifted.add(off + shift);
        }
        dir.parsedTlsOffsets = shifted;
      }
      if (dir.dnsParsedOffset > 0) {
        dir.dnsParsedOffset = Math.min(STREAM_CAP_BYTES, dir.dnsParsedOffset + shift);
      }
      if (dir.krbParsedOffset > 0) {
        dir.krbParsedOffset = Math.min(STREAM_CAP_BYTES, dir.krbParsedOffset + shift);
      }
      return dir.buf.subarray(0, dir.maxFilled);
    }

    // Post-SYN retransmission overlapping before baseSeq: append only any newly revealed tail past maxFilled.
    if (shift >= payload.length) {
      return dir.buf.subarray(0, dir.maxFilled);
    }
    const trimmed = payload.subarray(shift);
    const copyLen = Math.min(trimmed.length, STREAM_CAP_BYTES);
    if (copyLen > dir.maxFilled) {
      dir.buf.set(trimmed.subarray(dir.maxFilled, copyLen), dir.maxFilled);
      dir.maxFilled = copyLen;
    }
    return dir.buf.subarray(0, dir.maxFilled);
  }
  if (rel >= STREAM_CAP_BYTES) {
    return payload;
  }
  const copyLen = Math.min(payload.length, STREAM_CAP_BYTES - rel);
  dir.buf.set(payload.subarray(0, copyLen), rel);
  if (rel + copyLen > dir.maxFilled) {
    dir.maxFilled = rel + copyLen;
  }
  return dir.buf.subarray(0, dir.maxFilled);
}

function pushKv(kv: Map<string, string[]>, key: string, val: string): void {
  if (!val) return;
  let arr = kv.get(key);
  if (!arr) {
    arr = [];
    kv.set(key, arr);
  }
  if (!arr.includes(val)) {
    arr.push(val);
  }
}

function formatEpochString(tsNs: bigint): string {
  const sec = tsNs / 1_000_000_000n;
  const subNs = tsNs % 1_000_000_000n;
  return `${sec.toString()}.${subNs.toString().padStart(9, "0")}`;
}

interface Ipv4FragBucket {
  chunks: Map<number, Uint8Array>;
  totalPayloadLen: number | null;
  collectedBytes: number;
}

interface PcapDissectionWindow {
  startNs: bigint;
  endNs: bigint;
}

interface PcapStreamOptions {
  caseId?: string;
  window?: PcapDissectionWindow;
  onPacket: (pkt: DissectedPacket) => void;
}

export class PcapStreamDissector {
  private readonly caseTag: string | null;
  private readonly onPacket: (pkt: DissectedPacket) => void;
  private readonly window: PcapDissectionWindow | undefined;
  private frameCounter = 0;
  private nextTcpStreamId = 0;
  private nextSessionId = 1;
  private readonly sessions = new Map<string, SessionState>();
  private readonly fragBuckets = new Map<string, Ipv4FragBucket>();

  constructor(options: PcapStreamOptions) {
    this.caseTag = options.caseId ? `case:${options.caseId}` : null;
    this.onPacket = options.onPacket;
    this.window = options.window;
  }

  public getSessions(): DissectedSession[] {
    return [...this.sessions.values()]
      .map((s) => s.session)
      .sort((a, b) => a.firstPacketMs - b.firstPacketMs || a.sessionId - b.sessionId);
  }

  public getTotalFrames(): number {
    return this.frameCounter;
  }

  public processRawFrame(
    linkType: number,
    tsNs: bigint,
    origLen: number,
    data: Uint8Array,
  ): void {
    // Invariant: physical 1-based frame ordinal assigned BEFORE any filter!
    this.frameCounter += 1;
    const frameNumber = this.frameCounter;
    // Windowing precedes all decoding, fragment/TCP reassembly and session mutation.
    if (this.window && (tsNs < this.window.startNs || tsNs >= this.window.endNs)) {
      return;
    }
    const epochMs = Number(tsNs / 1_000_000n);
    const kv = new Map<string, string[]>();
    const protocols = new Set<string>();

    const pkt: DissectedPacket = {
      frameNumber,
      tsNs,
      timeEpochStr: formatEpochString(tsNs),
      frameLen: origLen,
      wsProtocol: "FRAME",
      protocols,
      kv,
    };

    // 1. Decode L2 Link Layer
    let l3Offset = 0;
    let etherType = 0;

    if (linkType === 1) {
      // DLT_EN10MB (Ethernet)
      if (data.length < 14) {
        this.onPacket(pkt);
        return;
      }
      etherType = readU16BE(data, 12);
      l3Offset = 14;
      // Stacked 802.1Q / 802.1ad VLAN tags
      for (let v = 0; v < 4; v++) {
        if (
          (etherType === 0x8100 || etherType === 0x88a8 || etherType === 0x9100) &&
          l3Offset + 4 <= data.length
        ) {
          etherType = readU16BE(data, l3Offset + 2);
          l3Offset += 4;
        } else {
          break;
        }
      }
    } else if (linkType === 113) {
      // DLT_LINUX_SLL
      if (data.length < 16) {
        this.onPacket(pkt);
        return;
      }
      etherType = readU16BE(data, 14);
      l3Offset = 16;
    } else if (linkType === 276) {
      // DLT_LINUX_SLL2
      if (data.length < 20) {
        this.onPacket(pkt);
        return;
      }
      etherType = readU16BE(data, 0);
      l3Offset = 20;
    } else if (linkType === 101 || linkType === 12 || linkType === 14) {
      // DLT_RAW
      if (data.length < 1) {
        this.onPacket(pkt);
        return;
      }
      const ver = data[0]! >>> 4;
      etherType = ver === 4 ? 0x0800 : ver === 6 ? 0x86dd : 0;
      l3Offset = 0;
    } else if (linkType === 0 || linkType === 108) {
      // DLT_NULL / DLT_LOOP
      if (data.length < 4) {
        this.onPacket(pkt);
        return;
      }
      const af = readU32LE(data, 0);
      const afBe = readU32BE(data, 0);
      if (af === 2 || afBe === 2) {
        etherType = 0x0800;
      } else if (
        af === 24 ||
        af === 28 ||
        af === 30 ||
        af === 10 ||
        afBe === 24 ||
        afBe === 28 ||
        afBe === 30 ||
        afBe === 10
      ) {
        etherType = 0x86dd;
      }
      l3Offset = 4;
    }

    if (etherType === 0x0806) {
      protocols.add("arp");
      pkt.wsProtocol = "ARP";
      this.onPacket(pkt);
      return;
    }

    // 2. Decode L3 Network Layer (IPv4 / IPv6)
    let ipProto = 0;
    let l4Payload: Uint8Array | null = null;
    let srcIp = "";
    let dstIp = "";

    if (etherType === 0x0800) {
      if (l3Offset + 20 > data.length) {
        this.onPacket(pkt);
        return;
      }
      const verIhl = data[l3Offset]!;
      if (verIhl >>> 4 !== 4) {
        this.onPacket(pkt);
        return;
      }
      const ihl = (verIhl & 0x0f) * 4;
      const totalLen = readU16BE(data, l3Offset + 2);
      if (ihl < 20 || l3Offset + ihl > data.length) {
        this.onPacket(pkt);
        return;
      }
      const ipEnd =
        totalLen >= ihl ? Math.min(data.length, l3Offset + totalLen) : data.length;

      protocols.add("ip");
      pkt.wsProtocol = "IPv4";
      ipProto = data[l3Offset + 9]!;
      srcIp = formatIpv4Bytes(data, l3Offset + 12);
      dstIp = formatIpv4Bytes(data, l3Offset + 16);
      pkt.ipSrc = srcIp;
      pkt.ipDst = dstIp;
      pkt.srcIpBin = ipToBytes16(srcIp) ?? undefined;
      pkt.dstIpBin = ipToBytes16(dstIp) ?? undefined;
      pushKv(kv, "ip.src", srcIp);
      pushKv(kv, "ip.dst", dstIp);

      const flagsFrag = readU16BE(data, l3Offset + 6);
      const moreFragments = (flagsFrag & 0x2000) !== 0;
      const fragOffset = (flagsFrag & 0x1fff) * 8;
      const ipBody = data.subarray(l3Offset + ihl, ipEnd);

      if (moreFragments || fragOffset > 0) {
        const ipId = readU16BE(data, l3Offset + 4);
        const reassembled = this.handleIpv4Fragment(
          `${srcIp}|${dstIp}|${ipId}|${ipProto}`,
          fragOffset,
          moreFragments,
          ipBody,
        );
        if (!reassembled) {
          this.onPacket(pkt);
          return;
        }
        l4Payload = reassembled;
      } else {
        l4Payload = ipBody;
      }
    } else if (etherType === 0x86dd) {
      if (l3Offset + 40 > data.length) {
        this.onPacket(pkt);
        return;
      }
      if (data[l3Offset]! >>> 4 !== 6) {
        this.onPacket(pkt);
        return;
      }
      protocols.add("ipv6");
      pkt.wsProtocol = "IPv6";
      const payloadLen = readU16BE(data, l3Offset + 4);
      let nextHeader = data[l3Offset + 6]!;
      srcIp = formatIpv6Bytes(data, l3Offset + 8);
      dstIp = formatIpv6Bytes(data, l3Offset + 24);
      pkt.ipv6Src = srcIp;
      pkt.ipv6Dst = dstIp;
      pkt.srcIpBin = ipToBytes16(srcIp) ?? undefined;
      pkt.dstIpBin = ipToBytes16(dstIp) ?? undefined;
      pushKv(kv, "ipv6.src", srcIp);
      pushKv(kv, "ipv6.dst", dstIp);

      let extPos = l3Offset + 40;
      const ipv6End = Math.min(data.length, extPos + payloadLen);
      let ipv6Fragmented = false;
      let ipv6FragOffset = 0;
      let ipv6MoreFragments = false;
      let ipv6FragId = 0;

      for (let hops = 0; hops < 8 && extPos < ipv6End; hops++) {
        if (nextHeader === 0 || nextHeader === 43 || nextHeader === 60) {
          if (extPos + 2 > ipv6End) {
            extPos = ipv6End + 1;
            break;
          }
          const hdrExtLen = (data[extPos + 1]! + 1) * 8;
          nextHeader = data[extPos]!;
          extPos += hdrExtLen;
        } else if (nextHeader === 44) {
          // RFC 8200 §4.5 IPv6 Fragment Header (8 bytes)
          if (extPos + 8 > ipv6End) {
            extPos = ipv6End + 1;
            break;
          }
          const nextHdr = data[extPos]!;
          const fragWord = readU16BE(data, extPos + 2);
          ipv6FragOffset = fragWord & 0xfff8;
          ipv6MoreFragments = (fragWord & 0x0001) !== 0;
          ipv6FragId = readU32BE(data, extPos + 4);
          ipv6Fragmented = ipv6MoreFragments || ipv6FragOffset > 0;
          nextHeader = nextHdr;
          extPos += 8;
          // Non-zero fragment offsets carry mid-payload bytes, never inner headers.
          if (ipv6FragOffset > 0) {
            break;
          }
        } else if (nextHeader === 51) {
          // AH
          if (extPos + 2 > ipv6End) {
            extPos = ipv6End + 1;
            break;
          }
          const ahLen = (data[extPos + 1]! + 2) * 4;
          nextHeader = data[extPos]!;
          extPos += ahLen;
        } else {
          break;
        }
      }
      if (extPos <= ipv6End) {
        ipProto = nextHeader;
        const ipv6Body = data.subarray(extPos, ipv6End);
        if (ipv6Fragmented) {
          const reassembled = this.handleIpv4Fragment(
            `v6|${srcIp}|${dstIp}|${ipv6FragId}|${ipProto}`,
            ipv6FragOffset,
            ipv6MoreFragments,
            ipv6Body,
          );
          if (!reassembled) {
            this.onPacket(pkt);
            return;
          }
          l4Payload = reassembled;
        } else {
          l4Payload = ipv6Body;
        }
      }
    } else {
      this.onPacket(pkt);
      return;
    }

    if (!l4Payload) {
      this.onPacket(pkt);
      return;
    }

    // 3. Decode L4 Transport Layer (ICMP / UDP / TCP)
    if (ipProto === 1 || ipProto === 58) {
      protocols.add("icmp");
      pkt.wsProtocol = ipProto === 58 ? "ICMPv6" : "ICMP";
      const sess = this.touchSession(
        srcIp,
        0,
        dstIp,
        0,
        ipProto,
        ipProto === 58 ? "icmpv6" : "icmp",
        epochMs,
        origLen,
        false,
      );
      sess.session.protocols.add("icmp");
      this.onPacket(pkt);
      return;
    }

    if (ipProto === 17) {
      // UDP
      if (l4Payload.length < 8) {
        this.onPacket(pkt);
        return;
      }
      protocols.add("udp");
      pkt.wsProtocol = "UDP";
      const srcPort = readU16BE(l4Payload, 0);
      const dstPort = readU16BE(l4Payload, 2);
      const udpLen = readU16BE(l4Payload, 4);
      pkt.udpSrcPort = srcPort;
      pkt.udpDstPort = dstPort;
      pushKv(kv, "udp.srcport", String(srcPort));
      pushKv(kv, "udp.dstport", String(dstPort));

      const appPayload = l4Payload.subarray(
        8,
        udpLen >= 8 ? Math.min(l4Payload.length, udpLen) : l4Payload.length,
      );
      const sessState = this.touchSession(
        srcIp,
        srcPort,
        dstIp,
        dstPort,
        17,
        "udp",
        epochMs,
        origLen,
        false,
      );
      sessState.session.protocols.add("udp");

      if (appPayload.length > 0) {
        this.dissectAppLayer({
          pkt,
          session: sessState.session,
          isTcp: false,
          srcPort,
          dstPort,
          segmentPayload: appPayload,
          streamBuffer: appPayload,
          dirStream: undefined,
        });
      }

      this.onPacket(pkt);
      return;
    }

    if (ipProto === 6) {
      // TCP
      if (l4Payload.length < 20) {
        this.onPacket(pkt);
        return;
      }
      const dataOffset = (l4Payload[12]! >>> 4) * 4;
      if (dataOffset < 20 || dataOffset > l4Payload.length) {
        this.onPacket(pkt);
        return;
      }

      protocols.add("tcp");
      // Bare TCP packets NEVER guess L7 protocol from port; stays "TCP" unless L7 payload matches!
      pkt.wsProtocol = "TCP";

      const srcPort = readU16BE(l4Payload, 0);
      const dstPort = readU16BE(l4Payload, 2);
      const seqNum = readU32BE(l4Payload, 4);
      const tcpFlags = l4Payload[13]!;
      pkt.tcpSrcPort = srcPort;
      pkt.tcpDstPort = dstPort;
      pushKv(kv, "tcp.srcport", String(srcPort));
      pushKv(kv, "tcp.dstport", String(dstPort));

      const sessState = this.touchSession(
        srcIp,
        srcPort,
        dstIp,
        dstPort,
        6,
        "tcp",
        epochMs,
        origLen,
        true,
      );
      sessState.session.protocols.add("tcp");
      pkt.tcpStream = sessState.tcpStreamId;
      pushKv(kv, "tcp.stream", String(sessState.tcpStreamId!));

      const isC2S =
        srcIp === sessState.initiatorIp && srcPort === sessState.initiatorPort;
      const dirStream = isC2S ? sessState.c2s! : sessState.s2c!;
      const isSyn = (tcpFlags & 0x02) !== 0;
      const tcpPayload = l4Payload.subarray(dataOffset);

      if (isSyn && !dirStream.initialized) {
        dirStream.initialized = true;
        dirStream.sawSyn = true;
        dirStream.baseSeq = (seqNum + 1) >>> 0;
      }

      if (tcpPayload.length > 0) {
        const payloadStartSeq = isSyn ? (seqNum + 1) >>> 0 : seqNum;
        const streamView = appendToDirStream(dirStream, payloadStartSeq, tcpPayload);
        this.dissectAppLayer({
          pkt,
          session: sessState.session,
          isTcp: true,
          srcPort,
          dstPort,
          segmentPayload: tcpPayload,
          streamBuffer: streamView,
          dirStream,
        });
      }

      this.onPacket(pkt);
      return;
    }

    this.onPacket(pkt);
  }

  private handleIpv4Fragment(
    key: string,
    fragOffset: number,
    moreFragments: boolean,
    body: Uint8Array,
  ): Uint8Array | null {
    if (fragOffset + body.length > 65_535) {
      return null;
    }
    let bucket = this.fragBuckets.get(key);
    if (!bucket) {
      if (this.fragBuckets.size >= 256) {
        const oldest = this.fragBuckets.keys().next().value;
        if (oldest !== undefined) this.fragBuckets.delete(oldest);
      }
      bucket = { chunks: new Map(), totalPayloadLen: null, collectedBytes: 0 };
      this.fragBuckets.set(key, bucket);
    }
    if (!bucket.chunks.has(fragOffset)) {
      bucket.chunks.set(fragOffset, new Uint8Array(body));
      bucket.collectedBytes += body.length;
    }
    if (!moreFragments) {
      bucket.totalPayloadLen = fragOffset + body.length;
    }
    if (bucket.totalPayloadLen !== null && bucket.collectedBytes >= bucket.totalPayloadLen) {
      const out = new Uint8Array(bucket.totalPayloadLen);
      let covered = 0;
      const offsets = [...bucket.chunks.keys()].sort((a, b) => a - b);
      for (const off of offsets) {
        const chunk = bucket.chunks.get(off)!;
        if (off > covered) {
          return null; // Still missing middle fragment
        }
        const writeLen = Math.min(chunk.length, out.length - off);
        out.set(chunk.subarray(0, writeLen), off);
        if (off + writeLen > covered) covered = off + writeLen;
      }
      if (covered >= bucket.totalPayloadLen) {
        this.fragBuckets.delete(key);
        return out;
      }
    }
    return null;
  }

  private touchSession(
    srcIp: string,
    srcPort: number,
    dstIp: string,
    dstPort: number,
    ipProtocol: number,
    ipProtocolName: string,
    epochMs: number,
    bytes: number,
    isTcp: boolean,
  ): SessionState {
    const endA = `${srcIp}:${srcPort}`;
    const endB = `${dstIp}:${dstPort}`;
    const biKey =
      endA <= endB
        ? `${ipProtocol}|${endA}|${endB}`
        : `${ipProtocol}|${endB}|${endA}`;

    let state = this.sessions.get(biKey);
    if (!state) {
      const tags = new Set<string>();
      if (this.caseTag) tags.add(this.caseTag);
      const session: DissectedSession = {
        sessionId: this.nextSessionId++,
        firstPacketMs: epochMs,
        lastPacketMs: epochMs,
        srcIp,
        srcIpBin: ipToBytes16(srcIp),
        srcPort,
        dstIp,
        dstIpBin: ipToBytes16(dstIp),
        dstPort,
        ipProtocol,
        ipProtocolName,
        protocols: new Set<string>(),
        networkBytes: 0,
        networkPackets: 0,
        srcBytes: 0,
        dstBytes: 0,
        dnsHosts: new Set<string>(),
        dnsQueryTypes: new Set<string>(),
        httpHosts: new Set<string>(),
        httpUris: new Set<string>(),
        httpMethods: new Set<string>(),
        httpStatusCodes: new Set<number>(),
        httpUserAgents: new Set<string>(),
        tlsVersions: new Set<string>(),
        tlsCiphers: new Set<string>(),
        tlsJa3: new Set<string>(),
        tlsJa4: new Set<string>(),
        tags,
      };
      state = {
        session,
        initiatorIp: srcIp,
        initiatorPort: srcPort,
        ...(isTcp
          ? {
              tcpStreamId: this.nextTcpStreamId++,
              c2s: createDirStream(),
              s2c: createDirStream(),
            }
          : {}),
      };
      this.sessions.set(biKey, state);
    }

    const s = state.session;
    if (epochMs < s.firstPacketMs) s.firstPacketMs = epochMs;
    if (epochMs > s.lastPacketMs) s.lastPacketMs = epochMs;
    s.networkPackets += 1;
    s.networkBytes += bytes;
    if (srcIp === state.initiatorIp && srcPort === state.initiatorPort) {
      s.srcBytes += bytes;
    } else {
      s.dstBytes += bytes;
    }

    return state;
  }

  private dissectAppLayer(ctx: {
    pkt: DissectedPacket;
    session: DissectedSession;
    isTcp: boolean;
    srcPort: number;
    dstPort: number;
    segmentPayload: Uint8Array;
    streamBuffer: Uint8Array;
    dirStream: TcpDirectionStream | undefined;
  }): void {
    const { pkt, session, isTcp, srcPort, dstPort, segmentPayload, streamBuffer, dirStream } =
      ctx;

    // 1. SMB2 / SMB3 (`\xFE S M B` raw or after 4-byte NetBIOS Session Service header)
    if (isTcp && this.tryDissectSmb2(pkt, session, segmentPayload)) {
      return;
    }

    // 2. TLS Records (handles coalesced TLS records & split TCP segments via 16KiB streamBuffer)
    if (isTcp && this.tryDissectTls(pkt, session, segmentPayload, streamBuffer, dirStream)) {
      return;
    }

    // 3. HTTP/1.x Request or Response
    if (isTcp && this.tryDissectHttp(pkt, session, segmentPayload, streamBuffer, dirStream)) {
      return;
    }

    // 4. DNS (UDP 53/5353 or TCP 53 with 2-byte length prefix & per-stream record offset)
    if (
      srcPort === 53 ||
      dstPort === 53 ||
      srcPort === 5353 ||
      dstPort === 5353
    ) {
      if (isTcp && dirStream) {
        let anyDns = false;
        while (dirStream.dnsParsedOffset + 2 <= streamBuffer.length) {
          const dnsLen = readU16BE(streamBuffer, dirStream.dnsParsedOffset);
          if (dnsLen < 12 || dirStream.dnsParsedOffset + 2 + dnsLen > streamBuffer.length) {
            break;
          }
          const msgSlice = streamBuffer.subarray(
            dirStream.dnsParsedOffset + 2,
            dirStream.dnsParsedOffset + 2 + dnsLen,
          );
          dirStream.dnsParsedOffset += 2 + dnsLen;
          if (this.tryDissectDns(pkt, session, msgSlice, false)) {
            anyDns = true;
          }
        }
        if (anyDns) {
          return;
        }
      } else if (this.tryDissectDns(pkt, session, segmentPayload, false)) {
        return;
      }
    }

    // 5. Kerberos (port 88 UDP or 4-byte record-framed TCP with per-stream record offset)
    if (srcPort === 88 || dstPort === 88) {
      if (isTcp && dirStream) {
        let anyKrb = false;
        while (dirStream.krbParsedOffset + 4 <= streamBuffer.length) {
          const recLen = readU32BE(streamBuffer, dirStream.krbParsedOffset) & 0x7fffffff;
          if (
            recLen < 10 ||
            recLen > STREAM_CAP_BYTES ||
            dirStream.krbParsedOffset + 4 + recLen > streamBuffer.length
          ) {
            break;
          }
          const recSlice = streamBuffer.subarray(
            dirStream.krbParsedOffset + 4,
            dirStream.krbParsedOffset + 4 + recLen,
          );
          dirStream.krbParsedOffset += 4 + recLen;
          const krb = decodeKerberosMessage(recSlice);
          if (krb.matched) {
            anyKrb = true;
            pkt.protocols.add("kerberos");
            pkt.wsProtocol = "KRB5";
            session.protocols.add("krb5");
            if (krb.cname) {
              pushKv(pkt.kv, "kerberos.CNameString", krb.cname);
            }
          }
        }
        if (anyKrb) {
          return;
        }
      } else {
        const krb = decodeKerberosMessage(segmentPayload);
        if (krb.matched) {
          pkt.protocols.add("kerberos");
          pkt.wsProtocol = "KRB5";
          session.protocols.add("krb5");
          if (krb.cname) {
            pushKv(pkt.kv, "kerberos.CNameString", krb.cname);
          }
          return;
        }
      }
    }

    // 6. Standalone NTLMSSP in raw payload
    const ntlm = decodeNtlmssp(segmentPayload);
    if (ntlm) {
      pkt.protocols.add("ntlmssp");
      pkt.wsProtocol = "NTLMSSP";
      session.protocols.add("ntlm");
      if (ntlm.username) pushKv(pkt.kv, "ntlmssp.auth.username", ntlm.username);
      if (ntlm.domain) pushKv(pkt.kv, "ntlmssp.auth.domain", ntlm.domain);
    }
  }

  private tryDissectDns(
    pkt: DissectedPacket,
    session: DissectedSession,
    buf: Uint8Array,
    isTcp: boolean,
  ): boolean {
    let msg = buf;
    if (isTcp) {
      if (buf.length < 14) return false;
      const dnsLen = readU16BE(buf, 0);
      if (dnsLen < 12 || 2 + dnsLen > buf.length) return false;
      msg = buf.subarray(2, 2 + dnsLen);
    }
    if (msg.length < 12) return false;

    const flags = readU16BE(msg, 2);
    const isResponse = (flags & 0x8000) !== 0;
    const opcode = (flags >>> 11) & 0x0f;
    const rcode = flags & 0x0f;
    const qdCount = readU16BE(msg, 4);
    const anCount = readU16BE(msg, 6);
    const nsCount = readU16BE(msg, 8);
    const arCount = readU16BE(msg, 10);

    if (opcode > 5 || qdCount === 0 || qdCount > 32 || anCount > 256) {
      return false;
    }

    let pos = 12;
    let parsedAnyQuestion = false;

    for (let q = 0; q < qdCount; q++) {
      const qnameRes = decompressDnsName(msg, pos);
      if (!qnameRes || qnameRes.nextOffset + 4 > msg.length) {
        return false;
      }
      const qtype = readU16BE(msg, qnameRes.nextOffset);
      pos = qnameRes.nextOffset + 4;
      parsedAnyQuestion = true;

      if (qnameRes.name) {
        pushKv(pkt.kv, "dns.qry.name", qnameRes.name);
        session.dnsHosts.add(qnameRes.name);
      }
      pushKv(pkt.kv, "dns.qry.type", String(qtype));
      session.dnsQueryTypes.add(dnsTypeToMnemonic(qtype));
    }

    if (!parsedAnyQuestion) {
      return false;
    }

    pkt.protocols.add("dns");
    pkt.wsProtocol = "DNS";
    session.protocols.add("dns");

    if (isResponse) {
      pushKv(pkt.kv, "dns.flags.rcode", String(rcode));
    }

    const totalRrs = Math.min(anCount + nsCount + arCount, 128);
    for (let r = 0; r < totalRrs && pos < msg.length; r++) {
      const rrName = decompressDnsName(msg, pos);
      if (!rrName || rrName.nextOffset + 10 > msg.length) {
        break;
      }
      const rrType = readU16BE(msg, rrName.nextOffset);
      const rdLen = readU16BE(msg, rrName.nextOffset + 8);
      const rdataStart = rrName.nextOffset + 10;
      if (rdataStart + rdLen > msg.length) {
        break;
      }

      if (r < anCount) {
        if (rrType === 1 && rdLen === 4) {
          pushKv(pkt.kv, "dns.a", formatIpv4Bytes(msg, rdataStart));
        } else if (rrType === 28 && rdLen === 16) {
          pushKv(pkt.kv, "dns.aaaa", formatIpv6Bytes(msg, rdataStart));
        } else if (rrType === 5 && rdLen >= 1) {
          const cnameRes = decompressDnsName(msg, rdataStart);
          if (cnameRes?.name) {
            pushKv(pkt.kv, "dns.cname", cnameRes.name);
            session.dnsHosts.add(cnameRes.name);
          }
        } else if (rrType === 16 && rdLen >= 1) {
          // DNS TXT <character-string> chunks inside RDATA
          let tp = rdataStart;
          const tend = rdataStart + rdLen;
          const txtParts: string[] = [];
          while (tp < tend) {
            const slen = msg[tp]!;
            tp++;
            if (tp + slen > tend) break;
            txtParts.push(Buffer.from(msg.subarray(tp, tp + slen)).toString("utf8"));
            tp += slen;
          }
          if (txtParts.length > 0) {
            pushKv(pkt.kv, "dns.txt", txtParts.join(""));
          }
        }
      }

      pos = rdataStart + rdLen;
    }

    return true;
  }

  private tryDissectTls(
    pkt: DissectedPacket,
    session: DissectedSession,
    segmentPayload: Uint8Array,
    streamBuffer: Uint8Array,
    dirStream: TcpDirectionStream | undefined,
  ): boolean {
    const looksLikeTlsRecord = (b: Uint8Array, off: number): boolean => {
      if (off + 5 > b.length) return false;
      const ct = b[off]!;
      const maj = b[off + 1]!;
      const min = b[off + 2]!;
      const recLen = readU16BE(b, off + 3);
      return ct >= 20 && ct <= 23 && maj === 0x03 && min <= 0x04 && recLen > 0 && recLen <= 16_640;
    };

    const segIsTls = looksLikeTlsRecord(segmentPayload, 0);
    const streamIsTls = looksLikeTlsRecord(streamBuffer, 0);
    if (!segIsTls && !streamIsTls) {
      return false;
    }

    let matchedAnyRecord = false;
    let highestTlsLabel = "TLS";

    // Walk streamBuffer first (handles split ClientHello/ServerHello across TCP segments AND coalesced records!)
    const scanSource = streamIsTls ? streamBuffer : segmentPayload;
    let recOff = 0;
    while (looksLikeTlsRecord(scanSource, recOff)) {
      const ct = scanSource[recOff]!;
      const recVer = readU16BE(scanSource, recOff + 1);
      const recLen = readU16BE(scanSource, recOff + 3);
      matchedAnyRecord = true;

      if (recOff + 5 + recLen > scanSource.length) {
        // Incomplete TLS record waiting for next TCP segment
        break;
      }

      const alreadyEmitted = streamIsTls && dirStream?.parsedTlsOffsets.has(recOff);
      if (!alreadyEmitted) {
        dirStream?.parsedTlsOffsets.add(recOff);
        pushKv(pkt.kv, "tls.record.version", `0x${recVer.toString(16).padStart(4, "0")}`);

        if (ct === 22) {
          // Handshake record: may contain multiple coalesced handshake messages!
          let hsPos = recOff + 5;
          const hsEnd = recOff + 5 + recLen;
          while (hsPos + 4 <= hsEnd) {
            const hsType = scanSource[hsPos]!;
            const hsLen = readU24BE(scanSource, hsPos + 1);
            if (hsPos + 4 + hsLen > hsEnd) {
              break;
            }
            pushKv(pkt.kv, "tls.handshake.type", String(hsType));
            const hsBody = scanSource.subarray(hsPos + 4, hsPos + 4 + hsLen);

            if (hsType === 1) {
              const ch = parseTlsClientHello(hsBody, "t");
              if (ch) {
                if (ch.sni) {
                  pushKv(pkt.kv, "tls.handshake.extensions_server_name", ch.sni);
                  // Critical Arkime parity: alias TLS SNI into session http.host!
                  session.httpHosts.add(ch.sni);
                }
                pushKv(pkt.kv, "tls.handshake.ja3", ch.ja3);
                pushKv(pkt.kv, "tls.handshake.ja4", ch.ja4);
                session.tlsJa3.add(ch.ja3);
                session.tlsJa4.add(ch.ja4);
                const vLabel = tlsVersionToLabel(ch.negotiatedOrMaxVersion);
                highestTlsLabel = vLabel;
              }
            } else if (hsType === 2) {
              const sh = parseTlsServerHello(hsBody);
              if (sh) {
                pushKv(pkt.kv, "tls.handshake.ja3s", sh.ja3s);
                const vLabel = tlsVersionToLabel(sh.selectedVersion);
                session.tlsVersions.add(vLabel);
                session.tlsCiphers.add(
                  TLS_CIPHER_NAMES[sh.cipherSuite] ??
                    `0x${sh.cipherSuite.toString(16).padStart(4, "0")}`,
                );
                highestTlsLabel = vLabel;
              }
            }
            hsPos += 4 + hsLen;
          }
        }
      }

      recOff += 5 + recLen;
    }

    if (!matchedAnyRecord) {
      return false;
    }

    pkt.protocols.add("tls");
    session.protocols.add("tls");
    if (highestTlsLabel !== "TLS") {
      pkt.wsProtocol = highestTlsLabel;
    } else if (session.tlsVersions.size > 0) {
      pkt.wsProtocol = [...session.tlsVersions][0]!;
    } else {
      pkt.wsProtocol = `TLSv1.2`;
    }
    return true;
  }

  private tryDissectHttp(
    pkt: DissectedPacket,
    session: DissectedSession,
    segmentPayload: Uint8Array,
    streamBuffer: Uint8Array,
    dirStream: TcpDirectionStream | undefined,
  ): boolean {
    const checkSource =
      dirStream && !dirStream.parsedHttp && streamBuffer.length >= segmentPayload.length
        ? streamBuffer
        : segmentPayload;
    const headSlice = checkSource.subarray(0, Math.min(checkSource.length, 8192));
    const headText = Buffer.from(headSlice).toString("latin1");

    const reqMatch =
      /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) ([^\r\n ]+) HTTP\/1\.[01]\r?\n/.exec(
        headText,
      );
    const respMatch = !reqMatch ? /^HTTP\/1\.[01] (\d{3})\b[^\r\n]*\r?\n/.exec(headText) : null;

    if (!reqMatch && !respMatch) {
      return false;
    }

    const hdrEndIdx = headText.indexOf("\r\n\r\n");
    const lfEndIdx = hdrEndIdx === -1 ? headText.indexOf("\n\n") : hdrEndIdx;
    if (lfEndIdx === -1 && dirStream && checkSource === streamBuffer && streamBuffer.length < 8192) {
      // Incomplete HTTP header block split across TCP segments: mark packet/session as HTTP,
      // keep dirStream.parsedHttp = false, and wait for the completing segment before extracting headers!
      pkt.protocols.add("http");
      pkt.wsProtocol = "HTTP";
      session.protocols.add("http");
      return true;
    }
    if (dirStream) {
      dirStream.parsedHttp = true;
    }

    pkt.protocols.add("http");
    pkt.wsProtocol = "HTTP";
    session.protocols.add("http");

    if (reqMatch) {
      const method = reqMatch[1]!;
      const safeUri = redactUri(reqMatch[2]!);
      pushKv(pkt.kv, "http.request.method", method);
      pushKv(pkt.kv, "http.request.uri", safeUri);
      session.httpMethods.add(method);
      session.httpUris.add(safeUri);
    } else if (respMatch) {
      const statusStr = respMatch[1]!;
      pushKv(pkt.kv, "http.response.code", statusStr);
      session.httpStatusCodes.add(Number(statusStr));
    }

    const headerBlock = lfEndIdx >= 0 ? headText.slice(0, lfEndIdx) : headText;
    const lines = headerBlock.split(/\r?\n/);
    for (let i = 1; i < lines.length; i++) {
      const line = lines[i]!;
      const colon = line.indexOf(":");
      if (colon <= 0) continue;
      const name = line.slice(0, colon).trim().toLowerCase();
      const val = line.slice(colon + 1).trim();
      if (!val) continue;

      if (name === "host") {
        pushKv(pkt.kv, "http.host", val);
        session.httpHosts.add(val);
      } else if (name === "user-agent") {
        pushKv(pkt.kv, "http.user_agent", val);
        session.httpUserAgents.add(val);
      } else if (name === "content-type") {
        pushKv(pkt.kv, "http.content_type", val);
      } else if (name === "content-length" && /^[0-9]+$/.test(val)) {
        pushKv(pkt.kv, "http.content_length", val);
      } else if (name === "authorization" || name === "proxy-authorization") {
        // Never keep credential header values; ONLY decode NTLMSSP Type 3 username/domain if NTLM/Negotiate!
        const authMatch = /^(?:NTLM|Negotiate)\s+([A-Za-z0-9+/=]+)$/i.exec(val);
        if (authMatch) {
          const decoded = Buffer.from(authMatch[1]!, "base64");
          const ntlm = decodeNtlmssp(decoded);
          if (ntlm) {
            pkt.protocols.add("ntlmssp");
            if (ntlm.username) pushKv(pkt.kv, "ntlmssp.auth.username", ntlm.username);
            if (ntlm.domain) pushKv(pkt.kv, "ntlmssp.auth.domain", ntlm.domain);
          }
        }
      }
    }

    return true;
  }

  private tryDissectSmb2(
    pkt: DissectedPacket,
    session: DissectedSession,
    payload: Uint8Array,
  ): boolean {
    let off = 0;
    if (
      payload.length >= 68 &&
      payload[0] === 0x00 &&
      payload[4] === 0xfe &&
      payload[5] === 0x53 &&
      payload[6] === 0x4d &&
      payload[7] === 0x42
    ) {
      off = 4;
    } else if (
      payload.length >= 64 &&
      payload[0] === 0xfe &&
      payload[1] === 0x53 &&
      payload[2] === 0x4d &&
      payload[3] === 0x42
    ) {
      off = 0;
    } else {
      return false;
    }

    pkt.protocols.add("smb2");
    pkt.wsProtocol = "SMB2";
    session.protocols.add("smb");

    // Walk compounded SMB2 commands in the PDU
    let cmdOff = off;
    for (let chain = 0; chain < 8 && cmdOff + 64 <= payload.length; chain++) {
      if (
        payload[cmdOff] !== 0xfe ||
        payload[cmdOff + 1] !== 0x53 ||
        payload[cmdOff + 2] !== 0x4d ||
        payload[cmdOff + 3] !== 0x42
      ) {
        break;
      }
      const hdrLen = readU16LE(payload, cmdOff + 4);
      if (hdrLen !== 64) break;
      const cmd = readU16LE(payload, cmdOff + 12);
      const flags = readU32LE(payload, cmdOff + 16);
      const nextCommand = readU32LE(payload, cmdOff + 20);
      const isResponse = (flags & 0x00000001) !== 0;

      pushKv(pkt.kv, "smb2.cmd", String(cmd));

      const pduEnd =
        nextCommand > 0
          ? Math.min(payload.length, cmdOff + nextCommand)
          : payload.length;
      const pduSlice = payload.subarray(cmdOff, pduEnd);

      if (!isResponse && cmd === 3 && pduSlice.length >= 72) {
        // SMB2 TREE_CONNECT Request: PathOffset (u16 at 64+4), PathLength (u16 at 64+6)
        const pathOffset = readU16LE(pduSlice, 68);
        const pathLength = readU16LE(pduSlice, 70);
        if (pathLength > 0 && pathOffset >= 64 && pathOffset + pathLength <= pduSlice.length) {
          const tree = Buffer.from(
            pduSlice.subarray(pathOffset, pathOffset + pathLength),
          )
            .toString("utf16le")
            .replace(/\0+$/g, "");
          if (tree) pushKv(pkt.kv, "smb2.tree", tree);
        }
      } else if (!isResponse && cmd === 5 && pduSlice.length >= 120) {
        // SMB2 CREATE Request: NameOffset (u16 at 64+44=108), NameLength (u16 at 64+46=110)
        const nameOffset = readU16LE(pduSlice, 108);
        const nameLength = readU16LE(pduSlice, 110);
        if (nameLength > 0 && nameOffset >= 64 && nameOffset + nameLength <= pduSlice.length) {
          const filename = Buffer.from(
            pduSlice.subarray(nameOffset, nameOffset + nameLength),
          )
            .toString("utf16le")
            .replace(/\0+$/g, "");
          if (filename) pushKv(pkt.kv, "smb2.filename", filename);
        }
      } else if (cmd === 1 && pduSlice.length > 72) {
        // SMB2 SESSION_SETUP: inspect security blob for NTLMSSP or Kerberos CNameString
        const ntlm = decodeNtlmssp(pduSlice.subarray(64));
        if (ntlm) {
          pkt.protocols.add("ntlmssp");
          if (ntlm.username) pushKv(pkt.kv, "ntlmssp.auth.username", ntlm.username);
          if (ntlm.domain) pushKv(pkt.kv, "ntlmssp.auth.domain", ntlm.domain);
        } else {
          const krb = decodeKerberosMessage(pduSlice.subarray(64));
          if (krb.matched) {
            pkt.protocols.add("kerberos");
            if (krb.cname) pushKv(pkt.kv, "kerberos.CNameString", krb.cname);
          }
        }
      }

      if (nextCommand === 0) break;
      cmdOff += nextCommand;
    }

    return true;
  }
}

class ChunkedFileReader {
  private readonly fd: number;
  private buf: Uint8Array;
  private start = 0;
  private end = 0;
  private eof = false;

  constructor(fd: number, chunkSize = 65_536) {
    this.fd = fd;
    this.buf = new Uint8Array(chunkSize);
  }

  public ensure(neededBytes: number): boolean {
    if (this.end - this.start >= neededBytes) {
      return true;
    }
    if (this.eof) {
      return this.end - this.start >= neededBytes;
    }

    const unread = this.end - this.start;
    if (neededBytes > this.buf.length) {
      const nextCap = Math.max(this.buf.length * 2, neededBytes + 65_536);
      const bigger = new Uint8Array(nextCap);
      if (unread > 0) {
        bigger.set(this.buf.subarray(this.start, this.end), 0);
      }
      this.buf = bigger;
      this.start = 0;
      this.end = unread;
    } else if (this.start > 0) {
      if (unread > 0) {
        this.buf.copyWithin(0, this.start, this.end);
      }
      this.start = 0;
      this.end = unread;
    }

    while (this.end - this.start < neededBytes && !this.eof) {
      const n = fs.readSync(this.fd, this.buf, this.end, this.buf.length - this.end, null);
      if (n <= 0) {
        this.eof = true;
        break;
      }
      this.end += n;
    }

    return this.end - this.start >= neededBytes;
  }

  public peek(len: number): Uint8Array | null {
    if (!this.ensure(len)) return null;
    return this.buf.subarray(this.start, this.start + len);
  }

  public consume(len: number): Uint8Array | null {
    if (!this.ensure(len)) return null;
    const view = this.buf.subarray(this.start, this.start + len);
    this.start += len;
    return view;
  }
}

function readU32Endian(buf: Uint8Array, off: number, littleEndian: boolean): number {
  return littleEndian ? readU32LE(buf, off) : readU32BE(buf, off);
}

function readU16Endian(buf: Uint8Array, off: number, littleEndian: boolean): number {
  return littleEndian ? readU16LE(buf, off) : readU16BE(buf, off);
}

function parsePcapngTsNs(tsHigh: number, tsLow: number, tsResolByte: number): bigint {
  const ticks = (BigInt(tsHigh >>> 0) << 32n) | BigInt(tsLow >>> 0);
  if (tsResolByte === 6) {
    return ticks * 1_000n;
  }
  if (tsResolByte === 9) {
    return ticks;
  }
  if ((tsResolByte & 0x80) === 0) {
    const pow10 = tsResolByte & 0x7f;
    if (pow10 <= 9) {
      return ticks * 10n ** BigInt(9 - pow10);
    }
    return ticks / 10n ** BigInt(pow10 - 9);
  }
  const pow2 = tsResolByte & 0x7f;
  return (ticks * 1_000_000_000n) >> BigInt(pow2);
}

/**
 * Streams a `.pcap` (LE/BE µs & ns) or `.pcapng` capture file in bounded `64 KiB` chunks
 * so large captures (`179 MB` `lab-large-001`) use minimal heap and never load the whole file in memory.
 */
export function streamDissectPcapFile(
  pcapPath: string,
  options: PcapStreamOptions,
): { totalFrames: number; sessions: DissectedSession[] } {
  const dissector = new PcapStreamDissector(options);
  const fd = fs.openSync(pcapPath, "r");
  try {
    const reader = new ChunkedFileReader(fd, 65_536);
    const magicBytes = reader.peek(4);
    if (!magicBytes) {
      return { totalFrames: 0, sessions: [] };
    }
    const magicBE = readU32BE(magicBytes, 0);

    if (magicBE === 0x0a0d0d0a) {
      // pcapng
      let littleEndian = true;
      let interfaces: Array<{ linkType: number; tsResol: number }> = [];

      while (reader.ensure(8)) {
        const hdr = reader.peek(12);
        if (!hdr || hdr.length < 8) break;
        const blockType = readU32BE(hdr, 0);

        if (blockType === 0x0a0d0d0a) {
          if (!reader.ensure(12)) break;
          const shbPeek = reader.peek(12)!;
          const bom = readU32BE(shbPeek, 8);
          if (bom === 0x1a2b3c4d) {
            littleEndian = false;
          } else if (bom === 0x4d3c2b1a) {
            littleEndian = true;
          } else {
            break;
          }
          const totalLen = readU32Endian(shbPeek, 4, littleEndian);
          if (totalLen < 28 || totalLen > 16 * 1024 * 1024) break;
          if (!reader.consume(totalLen)) break;
          interfaces = [];
          continue;
        }

        const peek8 = reader.peek(8)!;
        const realType = readU32Endian(peek8, 0, littleEndian);
        const totalLen = readU32Endian(peek8, 4, littleEndian);
        if (totalLen < 12 || totalLen > 16 * 1024 * 1024) {
          break;
        }
        const block = reader.consume(totalLen);
        if (!block) break;

        if (realType === 0x00000001 && block.length >= 20) {
          // Interface Description Block (IDB)
          const linkType = readU16Endian(block, 8, littleEndian);
          let tsResol = 6; // default 10^-6 (microseconds)
          let optPos = 16;
          const optEnd = block.length - 4;
          while (optPos + 4 <= optEnd) {
            const optCode = readU16Endian(block, optPos, littleEndian);
            const optLen = readU16Endian(block, optPos + 2, littleEndian);
            optPos += 4;
            if (optCode === 0) break;
            if (optPos + optLen > optEnd) break;
            if (optCode === 9 && optLen >= 1) {
              tsResol = block[optPos]!;
            }
            optPos += (optLen + 3) & ~3;
          }
          interfaces.push({ linkType, tsResol });
        } else if (realType === 0x00000006 && block.length >= 32) {
          // Enhanced Packet Block (EPB)
          const ifaceId = readU32Endian(block, 8, littleEndian);
          const tsHigh = readU32Endian(block, 12, littleEndian);
          const tsLow = readU32Endian(block, 16, littleEndian);
          const capLen = readU32Endian(block, 20, littleEndian);
          const origLen = readU32Endian(block, 24, littleEndian);
          if (28 + capLen <= block.length - 4) {
            const iface = interfaces[ifaceId] ?? { linkType: 1, tsResol: 6 };
            const tsNs = parsePcapngTsNs(tsHigh, tsLow, iface.tsResol);
            dissector.processRawFrame(
              iface.linkType,
              tsNs,
              origLen,
              block.subarray(28, 28 + capLen),
            );
          }
        } else if (realType === 0x00000003 && block.length >= 16) {
          // Simple Packet Block (SPB)
          const origLen = readU32Endian(block, 8, littleEndian);
          const capLen = Math.min(origLen, block.length - 16);
          if (capLen > 0) {
            const iface = interfaces[0] ?? { linkType: 1, tsResol: 6 };
            dissector.processRawFrame(
              iface.linkType,
              0n,
              origLen,
              block.subarray(12, 12 + capLen),
            );
          }
        }
      }
    } else {
      // Classic libpcap
      let littleEndian: boolean;
      let nanoPrecision: boolean;
      if (magicBE === 0xa1b2c3d4) {
        littleEndian = false;
        nanoPrecision = false;
      } else if (magicBE === 0xd4c3b2a1) {
        littleEndian = true;
        nanoPrecision = false;
      } else if (magicBE === 0xa1b23c4d) {
        littleEndian = false;
        nanoPrecision = true;
      } else if (magicBE === 0x4d3cb2a1) {
        littleEndian = true;
        nanoPrecision = true;
      } else {
        throw new Error(`Unsupported PCAP magic 0x${magicBE.toString(16).padStart(8, "0")}`);
      }

      const globalHdr = reader.consume(24);
      if (!globalHdr) {
        return { totalFrames: 0, sessions: [] };
      }
      const linkType = readU32Endian(globalHdr, 20, littleEndian) & 0xffff;

      while (reader.ensure(16)) {
        const pktHdr = reader.consume(16)!;
        const tsSec = readU32Endian(pktHdr, 0, littleEndian);
        const tsSub = readU32Endian(pktHdr, 4, littleEndian);
        const capLen = readU32Endian(pktHdr, 8, littleEndian);
        const origLen = readU32Endian(pktHdr, 12, littleEndian);

        if (capLen > 16 * 1024 * 1024) {
          break;
        }
        const pktData = reader.consume(capLen);
        if (!pktData) {
          break;
        }
        const tsNs =
          BigInt(tsSec >>> 0) * 1_000_000_000n +
          (nanoPrecision ? BigInt(tsSub >>> 0) : BigInt(tsSub >>> 0) * 1_000n);
        dissector.processRawFrame(linkType, tsNs, origLen, pktData);
      }
    }
  } finally {
    fs.closeSync(fd);
  }

  return {
    totalFrames: dissector.getTotalFrames(),
    sessions: dissector.getSessions(),
  };
}
