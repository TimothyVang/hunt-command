import {
  MAX_PACKET_FILTER,
  MAX_PACKET_FILTER_DEPTH,
  PACKET_FILTER_FIELDS,
  PACKET_FILTER_OPERATORS,
  PACKET_FILTER_PROTOCOLS,
  PACKET_FILTER_WORDS,
} from "@hunt-command/shared";
import { throwDataPlaneError } from "./errors.ts";
import type { CompiledSqlPredicate, SqlParam } from "./lucene-compiler.ts";
import { cidrOrIpToBounds16, ipToBytes16 } from "./timestamps-and-ip.ts";

// Mirrors lab_server.py:189-194 PACKET_FILTER_TOKEN 1-for-1
const PACKET_TOKEN_STICKY_RE =
  / *(?:(?<string>"[\x20\x21\x23-\x5b\x5d-\x7e]*")|(?<operator>==|!=|>=|<=|&&|\|\||[<>!()])|(?<ipv6>(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:\/[0-9]{1,3})?)(?![0-9A-Za-z_.:/])|(?<number>0x[0-9A-Fa-f]+|[0-9]+(?:\.[0-9]+){0,3}(?:\/[0-9]{1,2})?)(?![0-9A-Za-z_.:/])|(?<word>[A-Za-z_][A-Za-z0-9_.]*)(?![0-9A-Za-z_.:\[-]))/y;

const PACKET_IP_FIELDS: ReadonlySet<string> = new Set([
  "ip.src",
  "ip.dst",
  "ipv6.src",
  "ipv6.dst",
  "dns.a",
  "dns.aaaa",
]);

const PACKET_STRICT_NUMERIC_FIELDS: ReadonlySet<string> = new Set([
  "frame.number",
  "frame.len",
  "frame.time_epoch",
  "tcp.srcport",
  "tcp.dstport",
  "tcp.stream",
  "udp.srcport",
  "udp.dstport",
  "dns.qry.type",
  "dns.flags.rcode",
  "http.response.code",
  "http.content_length",
  "tls.handshake.type",
  "tls.record.version",
  "smb2.cmd",
]);

const PROTOCOL_SET: ReadonlySet<string> = new Set<string>(PACKET_FILTER_PROTOCOLS);

type PacketTokKind = "logic" | "not" | "open" | "close" | "compare" | "field" | "protocol" | "value";
type PacketTok = {
  kind: PacketTokKind;
  raw: string;
  valType?: "string" | "number" | "ipv6";
};

type PacketAst =
  | { type: "not"; child: PacketAst }
  | { type: "logic"; op: "AND" | "OR"; left: PacketAst; right: PacketAst }
  | { type: "proto"; proto: string }
  | { type: "exists"; field: string }
  | {
      type: "cmp";
      field: string;
      op: "==" | "!=" | ">" | "<" | ">=" | "<=";
      rawVal: string;
      valType: "string" | "number" | "ipv6";
    };

function normalizeCompareOp(op: string): "==" | "!=" | ">" | "<" | ">=" | "<=" {
  switch (op) {
    case "==":
    case "eq":
      return "==";
    case "!=":
    case "ne":
      return "!=";
    case ">":
    case "gt":
      return ">";
    case "<":
    case "lt":
      return "<";
    case ">=":
    case "ge":
      return ">=";
    case "<=":
    case "le":
      return "<=";
    default:
      throwDataPlaneError(400, "invalid_filter", `Unsupported comparison operator '${op}'`);
  }
}

function parseNumberLiteral(raw: string): number | null {
  const clean = raw.startsWith('"') && raw.endsWith('"') ? raw.slice(1, -1) : raw;
  if (/^0x[0-9a-fA-F]+$/.test(clean)) {
    return Number.parseInt(clean, 16);
  }
  if (/^[0-9]+(?:\.[0-9]+)?$/.test(clean)) {
    const n = Number(clean);
    return Number.isFinite(n) ? n : null;
  }
  return null;
}

function parseEpochNsLiteral(raw: string): bigint | null {
  const clean = raw.startsWith('"') && raw.endsWith('"') ? raw.slice(1, -1) : raw;
  const m = /^([0-9]+)(?:\.([0-9]{1,9}))?$/.exec(clean);
  if (!m) return null;
  const sec = BigInt(m[1]!);
  const sub = m[2] ? BigInt(m[2].padEnd(9, "0")) : 0n;
  return sec * 1_000_000_000n + sub;
}

function compilePacketAst(node: PacketAst, params: SqlParam[]): string {
  switch (node.type) {
    case "not":
      return `NOT (${compilePacketAst(node.child, params)})`;

    case "logic":
      return `(${compilePacketAst(node.left, params)} ${node.op} ${compilePacketAst(node.right, params)})`;

    case "proto": {
      params.push(`|${node.proto}|`);
      return "instr(p.proto_mask, ?) > 0";
    }

    case "exists": {
      if (
        node.field === "frame.number" ||
        node.field === "frame.time_epoch" ||
        node.field === "frame.len"
      ) {
        return "1 = 1";
      }
      if (PACKET_IP_FIELDS.has(node.field)) {
        params.push(node.field);
        return "EXISTS (SELECT 1 FROM packet_ips pi WHERE pi.frame_number = p.frame_number AND pi.field = ?)";
      }
      params.push(node.field);
      return "EXISTS (SELECT 1 FROM packet_kv pk WHERE pk.frame_number = p.frame_number AND pk.field = ?)";
    }

    case "cmp": {
      const sqlOp = node.op === "==" ? "=" : node.op;
      const unquoted =
        node.valType === "string" ? node.rawVal.slice(1, -1) : node.rawVal;

      if (node.field === "frame.number" || node.field === "frame.len") {
        const num = parseNumberLiteral(node.rawVal);
        if (num === null || !Number.isInteger(num)) {
          throwDataPlaneError(400, "invalid_filter", `Expected integer for ${node.field}`);
        }
        const col = node.field === "frame.number" ? "p.frame_number" : "p.frame_len";
        params.push(num);
        return `${col} ${sqlOp} ?`;
      }

      if (node.field === "frame.time_epoch") {
        const tsNs = parseEpochNsLiteral(node.rawVal);
        if (tsNs === null) {
          throwDataPlaneError(400, "invalid_filter", "Invalid frame.time_epoch literal");
        }
        params.push(tsNs);
        return `p.ts_ns ${sqlOp} ?`;
      }

      if (PACKET_IP_FIELDS.has(node.field)) {
        const isV6Field = node.field === "ipv6.src" || node.field === "ipv6.dst" || node.field === "dns.aaaa";
        if (unquoted.includes("/")) {
          if (node.op !== "==" && node.op !== "!=") {
            throwDataPlaneError(400, "invalid_filter", "CIDR masks only support == and !=");
          }
          const bounds = cidrOrIpToBounds16(unquoted);
          if (!bounds) {
            throwDataPlaneError(400, "invalid_filter", `Invalid CIDR '${unquoted}'`);
          }
          const isV4Expr = !unquoted.includes(":");
          if (isV6Field && isV4Expr) {
            throwDataPlaneError(400, "invalid_filter", "IPv4 CIDR on IPv6 packet field");
          }
          if (!isV6Field && !isV4Expr) {
            throwDataPlaneError(400, "invalid_filter", "IPv6 CIDR on IPv4 packet field");
          }
          params.push(node.field, bounds.lo, bounds.hi);
          if (node.op === "==") {
            return "EXISTS (SELECT 1 FROM packet_ips pi WHERE pi.frame_number = p.frame_number AND pi.field = ? AND pi.ip_bin BETWEEN ? AND ?)";
          }
          return "EXISTS (SELECT 1 FROM packet_ips pi WHERE pi.frame_number = p.frame_number AND pi.field = ? AND pi.ip_bin NOT BETWEEN ? AND ?)";
        }

        const bin = ipToBytes16(unquoted);
        if (!bin) {
          throwDataPlaneError(400, "invalid_filter", `Invalid IP address '${unquoted}'`);
        }
        const isV4Addr = !unquoted.includes(":");
        if ((isV6Field && isV4Addr) || (!isV6Field && !isV4Addr)) {
          throwDataPlaneError(400, "invalid_filter", "IP version mismatch in packet filter");
        }
        params.push(node.field, bin);
        return `EXISTS (SELECT 1 FROM packet_ips pi WHERE pi.frame_number = p.frame_number AND pi.field = ? AND pi.ip_bin ${sqlOp} ?)`;
      }

      if (PACKET_STRICT_NUMERIC_FIELDS.has(node.field)) {
        const num = parseNumberLiteral(node.rawVal);
        if (num === null) {
          throwDataPlaneError(
            400,
            "invalid_filter",
            `Field '${node.field}' requires a numeric comparison value`,
          );
        }
        params.push(node.field, num);
        return `EXISTS (SELECT 1 FROM packet_kv pk WHERE pk.frame_number = p.frame_number AND pk.field = ? AND pk.val_num ${sqlOp} ?)`;
      }

      // String / hex field comparison (e.g. dns.qry.name, tls.handshake.ja4, smb2.filename, etc.)
      if (node.valType !== "string" && !/^0x[0-9a-fA-F]+$/.test(node.rawVal)) {
        // Unquoted bare numbers on string fields like dns.qry.name == 123 are allowed only if quoted in Wireshark,
        // except hex/numeric literals which tshark rejects on pure string fields unless valid. Keep strict string check.
        const num = parseNumberLiteral(node.rawVal);
        if (num !== null) {
          params.push(node.field, String(unquoted));
          return `EXISTS (SELECT 1 FROM packet_kv pk WHERE pk.frame_number = p.frame_number AND pk.field = ? AND pk.val_str ${sqlOp} ?)`;
        }
      }

      params.push(node.field, unquoted);
      return `EXISTS (SELECT 1 FROM packet_kv pk WHERE pk.frame_number = p.frame_number AND pk.field = ? AND pk.val_str ${sqlOp} ?)`;
    }
  }
}

/**
 * Closed-grammar Wireshark display filter validator & SQLite compiler (`lab_server.py:653-724`).
 * Rejects `http.request.uri`, `_ws.col.Protocol`, `contains`, `matches`, `~`, `in {...}`, slices,
 * functions, backslashes in strings, and depth > 20 with `400 invalid_filter`.
 */
export function compilePacketDisplayFilter(rawFilter: string | undefined): {
  whereSql: string;
  params: SqlParam[];
  testedFields: string[];
} {
  const raw = rawFilter ?? "";
  if (raw.length > MAX_PACKET_FILTER) {
    throwDataPlaneError(400, "invalid_filter", "Packet filter exceeds 300 characters");
  }
  for (let i = 0; i < raw.length; i++) {
    const code = raw.charCodeAt(i);
    if (code < 32 || code === 127) {
      throwDataPlaneError(400, "invalid_filter", "Packet filter contains control characters");
    }
  }

  const trimmed = raw.trim();
  if (trimmed.length === 0) {
    return { whereSql: "1 = 1", params: [], testedFields: [] };
  }

  const tokens: PacketTok[] = [];
  let position = 0;

  while (position < trimmed.length) {
    PACKET_TOKEN_STICKY_RE.lastIndex = position;
    const match = PACKET_TOKEN_STICKY_RE.exec(trimmed);
    if (!match || !match.groups) {
      throwDataPlaneError(400, "invalid_filter", "Disallowed token in packet display filter");
    }
    position = PACKET_TOKEN_STICKY_RE.lastIndex;

    if (match.groups.operator !== undefined) {
      const op = match.groups.operator as keyof typeof PACKET_FILTER_OPERATORS;
      tokens.push({ kind: PACKET_FILTER_OPERATORS[op], raw: op });
    } else if (match.groups.word !== undefined) {
      const w = match.groups.word;
      if (Object.prototype.hasOwnProperty.call(PACKET_FILTER_WORDS, w)) {
        const wk = PACKET_FILTER_WORDS[w as keyof typeof PACKET_FILTER_WORDS];
        tokens.push({ kind: wk, raw: w });
      } else if (PACKET_FILTER_FIELDS.has(w)) {
        tokens.push({ kind: "field", raw: w });
      } else if (PROTOCOL_SET.has(w)) {
        tokens.push({ kind: "protocol", raw: w });
      } else {
        throwDataPlaneError(400, "invalid_filter", `Field or keyword '${w}' is not allowed`);
      }
    } else if (match.groups.string !== undefined) {
      tokens.push({ kind: "value", raw: match.groups.string, valType: "string" });
    } else if (match.groups.ipv6 !== undefined) {
      tokens.push({ kind: "value", raw: match.groups.ipv6, valType: "ipv6" });
    } else if (match.groups.number !== undefined) {
      tokens.push({ kind: "value", raw: match.groups.number, valType: "number" });
    } else {
      throwDataPlaneError(400, "invalid_filter", "Malformed packet filter token");
    }
  }

  const testedFields: string[] = [];
  let idx = 0;

  const peek = (): PacketTok | undefined => tokens[idx];
  const take = (expected: PacketTokKind): PacketTok => {
    const tok = tokens[idx];
    if (!tok || tok.kind !== expected) {
      throwDataPlaneError(400, "invalid_filter", `Expected ${expected} in packet filter`);
    }
    idx++;
    return tok;
  };

  const parseTerm = (depth: number): PacketAst => {
    if (depth > MAX_PACKET_FILTER_DEPTH) {
      throwDataPlaneError(400, "invalid_filter", "Packet filter nesting depth exceeded");
    }
    const next = peek();
    if (!next) {
      throwDataPlaneError(400, "invalid_filter", "Unexpected end of packet filter");
    }
    if (next.kind === "not") {
      take("not");
      return { type: "not", child: parseTerm(depth + 1) };
    }
    if (next.kind === "open") {
      take("open");
      const inner = parseOrExpr(depth + 1);
      take("close");
      return inner;
    }
    if (next.kind === "protocol") {
      const p = take("protocol");
      return { type: "proto", proto: p.raw };
    }
    const f = take("field");
    testedFields.push(f.raw);
    if (peek()?.kind === "compare") {
      const cmp = take("compare");
      const val = take("value");
      return {
        type: "cmp",
        field: f.raw,
        op: normalizeCompareOp(cmp.raw),
        rawVal: val.raw,
        valType: val.valType ?? "string",
      };
    }
    return { type: "exists", field: f.raw };
  };

  const parseAndExpr = (depth: number): PacketAst => {
    let left = parseTerm(depth);
    while (peek()?.kind === "logic" && (peek()!.raw === "&&" || peek()!.raw === "and")) {
      take("logic");
      const right = parseTerm(depth);
      left = { type: "logic", op: "AND", left, right };
    }
    return left;
  };

  const parseOrExpr = (depth: number): PacketAst => {
    let left = parseAndExpr(depth);
    while (peek()?.kind === "logic" && (peek()!.raw === "||" || peek()!.raw === "or")) {
      take("logic");
      const right = parseAndExpr(depth);
      left = { type: "logic", op: "OR", left, right };
    }
    return left;
  };

  const ast = parseOrExpr(0);
  if (idx !== tokens.length) {
    throwDataPlaneError(400, "invalid_filter", "Trailing tokens in packet filter");
  }

  const params: SqlParam[] = [];
  const whereSql = compilePacketAst(ast, params);
  return { whereSql, params, testedFields };
}

// ============================================================================
// Arkime Expression Validator & SQLite Session Compiler
// ============================================================================

type ArkimeTok =
  | { kind: "LPAREN" }
  | { kind: "RPAREN" }
  | { kind: "LBRACK" }
  | { kind: "RBRACK" }
  | { kind: "COMMA" }
  | { kind: "AND" }
  | { kind: "OR" }
  | { kind: "NOT" }
  | { kind: "CMP"; op: "==" | "!=" | ">=" | "<=" | ">" | "<" }
  | { kind: "ATOM"; text: string; quoted: boolean };

type ArkimeAst =
  | { type: "not"; child: ArkimeAst }
  | { type: "logic"; op: "AND" | "OR"; left: ArkimeAst; right: ArkimeAst }
  | {
      type: "cmp";
      field: string;
      op: "==" | "!=" | ">=" | "<=" | ">" | "<";
      values: Array<{ text: string; quoted: boolean }>;
    };

export function checkArkimeBalancedExpression(rawExpression: string | undefined): string {
  const expr = rawExpression ?? "";
  if (expr.length > 500) {
    throwDataPlaneError(400, "invalid_expression", "Arkime expression exceeds 500 characters");
  }
  for (let i = 0; i < expr.length; i++) {
    const code = expr.charCodeAt(i);
    if (code < 32 || code === 127) {
      throwDataPlaneError(400, "invalid_expression", "Arkime expression contains control characters");
    }
  }

  let depth = 0;
  let quote: string | null = null;
  let escaped = false;
  for (let i = 0; i < expr.length; i++) {
    const ch = expr[i]!;
    if (quote !== null) {
      if (escaped) {
        escaped = false;
      } else if (ch === "\\") {
        escaped = true;
      } else if (ch === quote) {
        quote = null;
      }
    } else if (ch === '"') {
      quote = ch;
    } else if (ch === "(") {
      depth++;
    } else if (ch === ")") {
      depth--;
      if (depth < 0) {
        throwDataPlaneError(400, "invalid_expression", "Unbalanced ')' in Arkime expression");
      }
    }
  }

  if (quote !== null || depth !== 0) {
    throwDataPlaneError(400, "invalid_expression", "Unbalanced quote or parenthesis in Arkime expression");
  }

  return expr.trim();
}

function tokenizeArkime(expr: string): ArkimeTok[] {
  const tokens: ArkimeTok[] = [];
  let i = 0;

  while (i < expr.length) {
    const ch = expr[i]!;
    if (ch === " " || ch === "\t" || ch === "\n" || ch === "\r") {
      i++;
      continue;
    }
    if (ch === "(") {
      tokens.push({ kind: "LPAREN" });
      i++;
      continue;
    }
    if (ch === ")") {
      tokens.push({ kind: "RPAREN" });
      i++;
      continue;
    }
    if (ch === "[") {
      tokens.push({ kind: "LBRACK" });
      i++;
      continue;
    }
    if (ch === "]") {
      tokens.push({ kind: "RBRACK" });
      i++;
      continue;
    }
    if (ch === ",") {
      tokens.push({ kind: "COMMA" });
      i++;
      continue;
    }
    if (ch === "&" && expr[i + 1] === "&") {
      tokens.push({ kind: "AND" });
      i += 2;
      continue;
    }
    if (ch === "|" && expr[i + 1] === "|") {
      tokens.push({ kind: "OR" });
      i += 2;
      continue;
    }
    if (ch === "=" && expr[i + 1] === "=") {
      tokens.push({ kind: "CMP", op: "==" });
      i += 2;
      continue;
    }
    if (ch === "!" && expr[i + 1] === "=") {
      tokens.push({ kind: "CMP", op: "!=" });
      i += 2;
      continue;
    }
    if (ch === ">" && expr[i + 1] === "=") {
      tokens.push({ kind: "CMP", op: ">=" });
      i += 2;
      continue;
    }
    if (ch === "<" && expr[i + 1] === "=") {
      tokens.push({ kind: "CMP", op: "<=" });
      i += 2;
      continue;
    }
    if (ch === ">") {
      tokens.push({ kind: "CMP", op: ">" });
      i++;
      continue;
    }
    if (ch === "<") {
      tokens.push({ kind: "CMP", op: "<" });
      i++;
      continue;
    }
    if (ch === "!") {
      tokens.push({ kind: "NOT" });
      i++;
      continue;
    }
    if (ch === '"') {
      i++;
      let val = "";
      while (i < expr.length && expr[i] !== '"') {
        if (expr[i] === "\\" && i + 1 < expr.length) {
          val += expr[i + 1]!;
          i += 2;
        } else {
          val += expr[i]!;
          i++;
        }
      }
      if (i >= expr.length || expr[i] !== '"') {
        throwDataPlaneError(400, "invalid_expression", "Unclosed quote in Arkime expression");
      }
      i++;
      tokens.push({ kind: "ATOM", text: val, quoted: true });
      continue;
    }

    let atom = "";
    while (
      i < expr.length &&
      !/[\s()[\],&|=<>!"]/.test(expr[i]!)
    ) {
      if (expr[i] === "!" && expr.slice(i - 6, i) === "EXISTS") {
        atom += "!";
        i++;
        break;
      }
      if (expr[i] === "\\" && i + 1 < expr.length) {
        atom += expr[i + 1]!;
        i += 2;
      } else {
        atom += expr[i]!;
        i++;
      }
    }

    if (atom.length === 0) {
      throwDataPlaneError(400, "invalid_expression", `Unexpected character '${expr[i]!}' in Arkime expression`);
    }

    if (atom === "AND") {
      tokens.push({ kind: "AND" });
    } else if (atom === "OR") {
      tokens.push({ kind: "OR" });
    } else if (atom === "NOT") {
      tokens.push({ kind: "NOT" });
    } else {
      tokens.push({ kind: "ATOM", text: atom, quoted: false });
    }
  }

  return tokens;
}

const ARKIME_CASE_INSENSITIVE_KV: ReadonlySet<string> = new Set([
  "host.dns",
  "host.http",
  "dns.query.type",
  "protocols",
  "ip.protocol",
  "tls.ja3",
  "tls.ja4",
]);

function mapArkimeField(rawField: string):
  | { kind: "ip_both" }
  | { kind: "ip_single"; field: "ip.src" | "ip.dst" }
  | { kind: "port_both" }
  | { kind: "col_num"; col: string }
  | { kind: "kv"; field: string; numeric?: boolean } {
  switch (rawField) {
    case "ip":
      return { kind: "ip_both" };
    case "ip.src":
    case "src.ip":
      return { kind: "ip_single", field: "ip.src" };
    case "ip.dst":
    case "dst.ip":
      return { kind: "ip_single", field: "ip.dst" };
    case "port":
      return { kind: "port_both" };
    case "port.src":
    case "src.port":
    case "source.port":
      return { kind: "col_num", col: "s.src_port" };
    case "port.dst":
    case "dst.port":
    case "destination.port":
      return { kind: "col_num", col: "s.dst_port" };
    case "bytes":
    case "databytes":
    case "network.bytes":
      return { kind: "col_num", col: "s.network_bytes" };
    case "packets":
    case "network.packets":
      return { kind: "col_num", col: "s.network_packets" };
    case "source.bytes":
    case "src.bytes":
      return { kind: "col_num", col: "s.src_bytes" };
    case "destination.bytes":
    case "dst.bytes":
      return { kind: "col_num", col: "s.dst_bytes" };
    case "ip.protocol":
    case "ipProtocol":
      return { kind: "kv", field: "ip.protocol", numeric: true };
    case "protocols":
    case "protocol":
      return { kind: "kv", field: "protocols" };
    case "host.dns":
    case "dns.host":
      return { kind: "kv", field: "host.dns" };
    case "dns.query.type":
    case "dns.qt":
      return { kind: "kv", field: "dns.query.type" };
    case "host.http":
    case "http.host":
    case "host.tls":
      return { kind: "kv", field: "host.http" };
    case "http.uri":
    case "uri":
      return { kind: "kv", field: "http.uri" };
    case "http.method":
    case "method":
      return { kind: "kv", field: "http.method" };
    case "http.statuscode":
    case "statuscode":
      return { kind: "kv", field: "http.statuscode", numeric: true };
    case "http.user-agent":
    case "http.useragent":
      return { kind: "kv", field: "http.user-agent" };
    case "tls.version":
      return { kind: "kv", field: "tls.version" };
    case "tls.cipher":
      return { kind: "kv", field: "tls.cipher" };
    case "tls.ja3":
    case "ja3":
      return { kind: "kv", field: "tls.ja3" };
    case "tls.ja4":
    case "ja4":
      return { kind: "kv", field: "tls.ja4" };
    case "tags":
      return { kind: "kv", field: "tags" };
    default:
      throwDataPlaneError(
        400,
        "invalid_expression",
        `Unknown Arkime expression field '${rawField}'`,
      );
  }
}

function wildcardToGlob(pattern: string): string {
  let out = "";
  for (const ch of pattern) {
    if (ch === "*") out += "*";
    else if (ch === "?") out += "?";
    else if (ch === "[") out += "[[]";
    else out += ch;
  }
  return out;
}

function compileSingleArkimeValue(
  field: string,
  op: "==" | "!=" | ">=" | "<=" | ">" | "<",
  val: { text: string; quoted: boolean },
  params: SqlParam[],
): string {
  const mapped = mapArkimeField(field);
  const rawText = val.text;

  // Handle EXISTS!
  if (!val.quoted && rawText === "EXISTS!") {
    if (op !== "==" && op !== "!=") {
      throwDataPlaneError(400, "invalid_expression", "EXISTS! only supports == and !=");
    }
    let existsSql: string;
    if (mapped.kind === "ip_both") {
      existsSql = "EXISTS (SELECT 1 FROM session_ips si WHERE si.session_id = s.session_id)";
    } else if (mapped.kind === "ip_single") {
      params.push(mapped.field);
      existsSql =
        "EXISTS (SELECT 1 FROM session_ips si WHERE si.session_id = s.session_id AND si.field = ?)";
    } else if (mapped.kind === "port_both" || mapped.kind === "col_num") {
      existsSql = "1 = 1";
    } else {
      params.push(mapped.field);
      existsSql =
        "EXISTS (SELECT 1 FROM session_kv sk WHERE sk.session_id = s.session_id AND sk.field = ?)";
    }
    return op === "==" ? existsSql : `NOT (${existsSql})`;
  }

  if (op === "!=") {
    // In Arkime, `field != value` negates `field == value` across the session's multi-value set.
    return `NOT (${compileSingleArkimeValue(field, "==", val, params)})`;
  }

  const sqlOp = op === "==" ? "=" : op;

  if (mapped.kind === "ip_both" || mapped.kind === "ip_single") {
    const bounds = cidrOrIpToBounds16(rawText);
    if (!bounds) {
      throwDataPlaneError(400, "invalid_expression", `Invalid IP or CIDR '${rawText}'`);
    }
    if (rawText.includes("/") && op !== "==") {
      throwDataPlaneError(400, "invalid_expression", "CIDR only supports == and !=");
    }
    if (mapped.kind === "ip_both") {
      params.push(bounds.lo, bounds.hi);
      return "EXISTS (SELECT 1 FROM session_ips si WHERE si.session_id = s.session_id AND si.ip_bin BETWEEN ? AND ?)";
    }
    if (op === "==") {
      params.push(mapped.field, bounds.lo, bounds.hi);
      return "EXISTS (SELECT 1 FROM session_ips si WHERE si.session_id = s.session_id AND si.field = ? AND si.ip_bin BETWEEN ? AND ?)";
    }
    params.push(mapped.field, bounds.lo);
    return `EXISTS (SELECT 1 FROM session_ips si WHERE si.session_id = s.session_id AND si.field = ? AND si.ip_bin ${sqlOp} ?)`;
  }

  if (mapped.kind === "port_both") {
    if (!/^[0-9]{1,5}$/.test(rawText)) {
      throwDataPlaneError(400, "invalid_expression", `Invalid port '${rawText}'`);
    }
    const pNum = Number(rawText);
    params.push(pNum, pNum);
    return `(s.src_port ${sqlOp} ? OR s.dst_port ${sqlOp} ?)`;
  }

  if (mapped.kind === "col_num") {
    if (!/^[0-9]+$/.test(rawText)) {
      throwDataPlaneError(400, "invalid_expression", `Expected integer for '${field}'`);
    }
    params.push(Number(rawText));
    return `${mapped.col} ${sqlOp} ?`;
  }

  // KV field
  if (mapped.numeric && /^[0-9]+$/.test(rawText)) {
    params.push(mapped.field, Number(rawText));
    return `EXISTS (SELECT 1 FROM session_kv sk WHERE sk.session_id = s.session_id AND sk.field = ? AND sk.val_num ${sqlOp} ?)`;
  }

  if (op !== "==") {
    params.push(mapped.field, rawText);
    return `EXISTS (SELECT 1 FROM session_kv sk WHERE sk.session_id = s.session_id AND sk.field = ? AND sk.val_str ${sqlOp} ?)`;
  }

  const hasWildcard = rawText.includes("*") || rawText.includes("?");
  const caseInsensitive = ARKIME_CASE_INSENSITIVE_KV.has(mapped.field);

  if (hasWildcard) {
    if (caseInsensitive) {
      params.push(mapped.field, wildcardToGlob(rawText.toLowerCase()));
      return "EXISTS (SELECT 1 FROM session_kv sk WHERE sk.session_id = s.session_id AND sk.field = ? AND lower(sk.val_str) GLOB ?)";
    }
    params.push(mapped.field, wildcardToGlob(rawText));
    return "EXISTS (SELECT 1 FROM session_kv sk WHERE sk.session_id = s.session_id AND sk.field = ? AND sk.val_str GLOB ?)";
  }

  if (caseInsensitive) {
    params.push(mapped.field, rawText.toLowerCase());
    return "EXISTS (SELECT 1 FROM session_kv sk WHERE sk.session_id = s.session_id AND sk.field = ? AND lower(sk.val_str) = ?)";
  }

  params.push(mapped.field, rawText);
  return "EXISTS (SELECT 1 FROM session_kv sk WHERE sk.session_id = s.session_id AND sk.field = ? AND sk.val_str = ?)";
}

function compileArkimeAst(node: ArkimeAst, params: SqlParam[]): string {
  switch (node.type) {
    case "not":
      return `NOT (${compileArkimeAst(node.child, params)})`;
    case "logic":
      return `(${compileArkimeAst(node.left, params)} ${node.op} ${compileArkimeAst(node.right, params)})`;
    case "cmp": {
      if (node.values.length === 1) {
        return compileSingleArkimeValue(node.field, node.op, node.values[0]!, params);
      }
      if (node.op !== "==" && node.op !== "!=") {
        throwDataPlaneError(400, "invalid_expression", "Value lists only support == and !=");
      }
      const orParts = node.values.map((v) =>
        compileSingleArkimeValue(node.field, "==", v, params),
      );
      const joined = `(${orParts.join(" OR ")})`;
      return node.op === "==" ? joined : `NOT ${joined}`;
    }
  }
}

export function compileArkimeExpression(
  rawExpression: string | undefined,
): CompiledSqlPredicate {
  const clean = checkArkimeBalancedExpression(rawExpression);
  if (clean.length === 0) {
    return { whereSql: "1 = 1", params: [] };
  }

  const tokens = tokenizeArkime(clean);
  let pos = 0;

  const peek = (): ArkimeTok | undefined => tokens[pos];
  const consume = (): ArkimeTok => {
    const t = tokens[pos];
    if (!t) {
      throwDataPlaneError(400, "invalid_expression", "Unexpected end of Arkime expression");
    }
    pos++;
    return t;
  };

  const parsePrimary = (depth: number): ArkimeAst => {
    if (depth > 24) {
      throwDataPlaneError(400, "invalid_expression", "Arkime expression nesting too deep");
    }
    const next = peek();
    if (!next) {
      throwDataPlaneError(400, "invalid_expression", "Expected clause in Arkime expression");
    }
    if (next.kind === "NOT") {
      consume();
      return { type: "not", child: parsePrimary(depth + 1) };
    }
    if (next.kind === "LPAREN") {
      consume();
      const inner = parseOr(depth + 1);
      if (peek()?.kind !== "RPAREN") {
        throwDataPlaneError(400, "invalid_expression", "Expected ')' in Arkime expression");
      }
      consume();
      return inner;
    }
    if (next.kind !== "ATOM" || next.quoted) {
      throwDataPlaneError(400, "invalid_expression", "Expected field name in Arkime expression");
    }
    const fieldTok = consume() as Extract<ArkimeTok, { kind: "ATOM" }>;
    const cmpTok = consume();
    if (cmpTok.kind !== "CMP") {
      throwDataPlaneError(
        400,
        "invalid_expression",
        `Expected comparison operator after '${fieldTok.text}'`,
      );
    }

    const values: Array<{ text: string; quoted: boolean }> = [];
    if (peek()?.kind === "LBRACK") {
      consume(); // [
      while (peek() && peek()!.kind !== "RBRACK") {
        const v = consume();
        if (v.kind !== "ATOM") {
          throwDataPlaneError(400, "invalid_expression", "Expected value inside [...] list");
        }
        values.push({ text: v.text, quoted: v.quoted });
        if (peek()?.kind === "COMMA") {
          consume();
        } else if (peek()?.kind !== "RBRACK") {
          throwDataPlaneError(400, "invalid_expression", "Expected ',' or ']' in list");
        }
      }
      if (peek()?.kind !== "RBRACK" || values.length === 0) {
        throwDataPlaneError(400, "invalid_expression", "Malformed value list in Arkime expression");
      }
      consume(); // ]
    } else {
      const v = consume();
      if (v.kind !== "ATOM") {
        throwDataPlaneError(
          400,
          "invalid_expression",
          `Expected value after '${fieldTok.text} ${cmpTok.op}'`,
        );
      }
      values.push({ text: v.text, quoted: v.quoted });
    }

    return {
      type: "cmp",
      field: fieldTok.text,
      op: cmpTok.op,
      values,
    };
  };

  const parseAnd = (depth: number): ArkimeAst => {
    let left = parsePrimary(depth);
    while (peek()?.kind === "AND") {
      consume();
      const right = parsePrimary(depth);
      left = { type: "logic", op: "AND", left, right };
    }
    return left;
  };

  const parseOr = (depth: number): ArkimeAst => {
    let left = parseAnd(depth);
    while (peek()?.kind === "OR") {
      consume();
      const right = parseAnd(depth);
      left = { type: "logic", op: "OR", left, right };
    }
    return left;
  };

  const ast = parseOr(0);
  if (pos !== tokens.length) {
    throwDataPlaneError(400, "invalid_expression", "Unexpected trailing tokens in Arkime expression");
  }

  const params: SqlParam[] = [];
  const whereSql = compileArkimeAst(ast, params);
  return { whereSql, params };
}

/**
 * Compiles `hunt_lab_query(dataset="network")` `q` (`simple_query_string` over `dns.host` and
 * `network.protocol` with `default_operator: 'and'`) and `host` (`source.ip` or `destination.ip`).
 */
export function compileNetworkDatasetFilter(
  rawQ: string | undefined,
  rawHost: string | undefined,
): CompiledSqlPredicate {
  const q = rawQ ?? "";
  const host = rawHost ?? "";

  if (q.length > 300 || host.length > 100) {
    throwDataPlaneError(400, "invalid_query", "Network query or host parameter too long");
  }
  for (const s of [q, host]) {
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      if (c < 32 || c === 127) {
        throwDataPlaneError(400, "invalid_query", "Control character in network query");
      }
    }
  }

  const clauses: string[] = [];
  const params: SqlParam[] = [];

  if (host.trim().length > 0) {
    const h = host.trim();
    params.push(h, h);
    clauses.push("(s.src_ip = ? OR s.dst_ip = ?)");
  }

  if (q.trim().length > 0) {
    // Parse simple_query_string tokens: phrases "...", | (OR), -term (NOT), +term, prefix*
    const rawTokens = q.trim().match(/"[^"]*"|\||[^\s|]+/g) ?? [];
    const orGroups: Array<Array<{ neg: boolean; term: string }>> = [[]];

    for (const rt of rawTokens) {
      if (rt === "|") {
        if (orGroups[orGroups.length - 1]!.length > 0) {
          orGroups.push([]);
        }
        continue;
      }
      let neg = false;
      let clean = rt;
      if (clean.startsWith("-") && clean.length > 1) {
        neg = true;
        clean = clean.slice(1);
      } else if (clean.startsWith("+") && clean.length > 1) {
        clean = clean.slice(1);
      }
      if (clean.startsWith('"') && clean.endsWith('"') && clean.length >= 2) {
        clean = clean.slice(1, -1);
      }
      if (clean.length > 0) {
        orGroups[orGroups.length - 1]!.push({ neg, term: clean.toLowerCase() });
      }
    }

    const groupSqls: string[] = [];
    for (const grp of orGroups) {
      if (grp.length === 0) continue;
      const andSqls: string[] = [];
      for (const item of grp) {
        let singleMatch: string;
        if (item.term.endsWith("*") && item.term.length > 1) {
          const glob = `${wildcardToGlob(item.term.slice(0, -1))}*`;
          params.push(glob, glob);
          singleMatch =
            "EXISTS (SELECT 1 FROM session_kv sk WHERE sk.session_id = s.session_id AND ((sk.field = 'host.dns' AND lower(sk.val_str) GLOB ?) OR (sk.field = 'protocols' AND lower(sk.val_str) GLOB ?)))";
        } else {
          const escapedLike = item.term.replace(/[\\%_]/g, "\\$&");
          params.push(`%${escapedLike}%`, item.term);
          singleMatch =
            "EXISTS (SELECT 1 FROM session_kv sk WHERE sk.session_id = s.session_id AND ((sk.field = 'host.dns' AND lower(sk.val_str) LIKE ? ESCAPE '\\') OR (sk.field = 'protocols' AND lower(sk.val_str) = ?)))";
        }
        andSqls.push(item.neg ? `NOT (${singleMatch})` : singleMatch);
      }
      groupSqls.push(`(${andSqls.join(" AND ")})`);
    }

    if (groupSqls.length > 0) {
      clauses.push(`(${groupSqls.join(" OR ")})`);
    }
  }

  return {
    whereSql: clauses.length > 0 ? clauses.join(" AND ") : "1 = 1",
    params,
  };
}
