import { QUERY_FIELDS } from "@hunt-command/shared";
import { throwDataPlaneError } from "./errors.ts";
import { cidrOrIpToBounds16, ipToBytes16, parseTimestampNs } from "./timestamps-and-ip.ts";

export type SqlParam = string | number | bigint | Uint8Array | null;

export interface CompiledSqlPredicate {
  whereSql: string;
  params: SqlParam[];
}

const IP_FIELDS: ReadonlySet<string> = new Set([
  "host.ip",
  "source.ip",
  "destination.ip",
  "dns.resolved_ip",
]);

const FTS_FIELD_TO_COLUMN: Readonly<Record<string, string>> = {
  message: "message",
  "powershell.file.script_block_text": "script_block_text",
  "process.command_line.text": "process_command_line",
  "process.parent.command_line.text": "process_parent_command_line",
  "url.full.text": "url_full",
  "file.path.text": "file_path",
  "user_agent.original.text": "user_agent_original",
};

type PatternPiece = { kind: "lit"; text: string } | { kind: "wild"; op: "*" | "?" };

type LexToken =
  | { kind: "LPAREN" }
  | { kind: "RPAREN" }
  | { kind: "COLON" }
  | { kind: "AND" }
  | { kind: "OR" }
  | { kind: "NOT" }
  | { kind: "PLUS" }
  | { kind: "MINUS" }
  | { kind: "CMP"; op: ">=" | "<=" | ">" | "<" }
  | { kind: "PHRASE"; value: string }
  | { kind: "WORD"; raw: string; pieces: PatternPiece[]; unescaped: string }
  | {
      kind: "RANGE";
      incLo: boolean;
      incHi: boolean;
      lo: string;
      hi: string;
      loQuoted: boolean;
      hiQuoted: boolean;
    };

type AstNode =
  | {
      type: "bool";
      clauses: Array<{ occur: "MUST" | "SHOULD" | "MUST_NOT"; node: AstNode }>;
    }
  | { type: "phrase"; field: string | null; value: string }
  | {
      type: "term";
      field: string | null;
      pieces: PatternPiece[];
      unescaped: string;
    }
  | {
      type: "range";
      field: string | null;
      incLo: boolean;
      incHi: boolean;
      lo: string | null;
      hi: string | null;
    }
  | { type: "exists"; field: string };

function isWhitespace(ch: string): boolean {
  return ch === " " || ch === "\t" || ch === "\n" || ch === "\r";
}

function isWordStop(ch: string): boolean {
  return (
    isWhitespace(ch) ||
    ch === "(" ||
    ch === ")" ||
    ch === ":" ||
    ch === '"' ||
    ch === "[" ||
    ch === "]" ||
    ch === "{" ||
    ch === "}"
  );
}

function unescapeLuceneChar(src: string, idx: number): { ch: string; nextIdx: number } {
  // Assumes src[idx] === '\\'
  if (idx + 1 >= src.length) {
    throwDataPlaneError(400, "invalid_query", "Trailing backslash in Lucene query");
  }
  const next = src[idx + 1]!;
  if (next === "u") {
    const hex = src.slice(idx + 2, idx + 6);
    if (!/^[0-9a-fA-F]{4}$/.test(hex)) {
      throwDataPlaneError(400, "invalid_query", "Invalid \\uXXXX escape in Lucene query");
    }
    return { ch: String.fromCharCode(Number.parseInt(hex, 16)), nextIdx: idx + 6 };
  }
  return { ch: next, nextIdx: idx + 2 };
}

function readRangeBound(
  src: string,
  startIdx: number,
): { value: string; quoted: boolean; rawWildcardStart: boolean; nextIdx: number } {
  let i = startIdx;
  while (i < src.length && isWhitespace(src[i]!)) {
    i++;
  }
  if (i >= src.length) {
    throwDataPlaneError(400, "invalid_query", "Unclosed range expression");
  }

  if (src[i] === '"') {
    i++;
    let out = "";
    while (i < src.length && src[i] !== '"') {
      if (src[i] === "\\") {
        const esc = unescapeLuceneChar(src, i);
        out += esc.ch;
        i = esc.nextIdx;
      } else {
        out += src[i]!;
        i++;
      }
    }
    if (i >= src.length || src[i] !== '"') {
      throwDataPlaneError(400, "invalid_query", "Unclosed quote inside range expression");
    }
    return { value: out, quoted: true, rawWildcardStart: false, nextIdx: i + 1 };
  }

  let out = "";
  let rawFirst = "";
  while (
    i < src.length &&
    !isWhitespace(src[i]!) &&
    src[i] !== "]" &&
    src[i] !== "}"
  ) {
    if (src[i] === "\\") {
      const esc = unescapeLuceneChar(src, i);
      out += esc.ch;
      if (rawFirst === "") rawFirst = "\\";
      i = esc.nextIdx;
    } else {
      const c = src[i]!;
      if (rawFirst === "") rawFirst = c;
      out += c;
      i++;
    }
  }

  if (out.length === 0) {
    throwDataPlaneError(400, "invalid_query", "Empty bound in range expression");
  }

  const isExactStar = out === "*" && rawFirst === "*";
  const rawWildcardStart = !isExactStar && (rawFirst === "*" || rawFirst === "?");
  return { value: out, quoted: false, rawWildcardStart, nextIdx: i };
}

function tokenizeLucene(src: string): LexToken[] {
  const tokens: LexToken[] = [];
  let i = 0;

  while (i < src.length) {
    const ch = src[i]!;
    if (isWhitespace(ch)) {
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
    if (ch === ":") {
      tokens.push({ kind: "COLON" });
      i++;
      continue;
    }
    if (ch === "&" && src[i + 1] === "&") {
      tokens.push({ kind: "AND" });
      i += 2;
      continue;
    }
    if (ch === "|" && src[i + 1] === "|") {
      tokens.push({ kind: "OR" });
      i += 2;
      continue;
    }
    if (ch === "!") {
      tokens.push({ kind: "NOT" });
      i++;
      continue;
    }

    // Unary + / - at clause start (after whitespace, '(', or start of string) when followed by non-space
    const prevCh = i > 0 ? src[i - 1]! : " ";
    const atClauseBoundary = prevCh === " " || prevCh === "\t" || prevCh === "\n" || prevCh === "\r" || prevCh === "(";
    if (atClauseBoundary && (ch === "+" || ch === "-") && i + 1 < src.length && !isWhitespace(src[i + 1]!)) {
      tokens.push({ kind: ch === "+" ? "PLUS" : "MINUS" });
      i++;
      continue;
    }

    // Comparison operators directly following ':'
    const prevTok = tokens[tokens.length - 1];
    if (prevTok?.kind === "COLON" && (ch === ">" || ch === "<")) {
      if (src[i + 1] === "=") {
        tokens.push({ kind: "CMP", op: ch === ">" ? ">=" : "<=" });
        i += 2;
      } else {
        tokens.push({ kind: "CMP", op: ch });
        i += 1;
      }
      continue;
    }

    // Quoted phrase
    if (ch === '"') {
      i++;
      let phrase = "";
      while (i < src.length && src[i] !== '"') {
        if (src[i] === "\\") {
          const esc = unescapeLuceneChar(src, i);
          phrase += esc.ch;
          i = esc.nextIdx;
        } else {
          phrase += src[i]!;
          i++;
        }
      }
      if (i >= src.length || src[i] !== '"') {
        throwDataPlaneError(400, "invalid_query", "Unclosed double quote in Lucene query");
      }
      i++;
      // Optional boost ^N or slop ~N after phrase
      if (i < src.length && (src[i] === "^" || src[i] === "~")) {
        i++;
        while (i < src.length && /[0-9.]/.test(src[i]!)) {
          i++;
        }
      }
      tokens.push({ kind: "PHRASE", value: phrase });
      continue;
    }

    // Range [lo TO hi] / {lo TO hi}
    if (ch === "[" || ch === "{") {
      const incLo = ch === "[";
      const loRes = readRangeBound(src, i + 1);
      if (loRes.rawWildcardStart) {
        throwDataPlaneError(
          400,
          "leading_wildcard_not_supported",
          "Leading wildcard in range lower bound is not supported",
        );
      }
      let j = loRes.nextIdx;
      while (j < src.length && isWhitespace(src[j]!)) {
        j++;
      }
      if (src.slice(j, j + 2) !== "TO" || (j + 2 < src.length && !isWhitespace(src[j + 2]!))) {
        throwDataPlaneError(400, "invalid_query", "Expected 'TO' in Lucene range expression");
      }
      const hiRes = readRangeBound(src, j + 2);
      if (hiRes.rawWildcardStart) {
        throwDataPlaneError(
          400,
          "leading_wildcard_not_supported",
          "Leading wildcard in range upper bound is not supported",
        );
      }
      j = hiRes.nextIdx;
      while (j < src.length && isWhitespace(src[j]!)) {
        j++;
      }
      if (j >= src.length || (src[j] !== "]" && src[j] !== "}")) {
        throwDataPlaneError(400, "invalid_query", "Unclosed Lucene range expression");
      }
      const incHi = src[j] === "]";
      i = j + 1;
      tokens.push({
        kind: "RANGE",
        incLo,
        incHi,
        lo: loRes.value,
        hi: hiRes.value,
        loQuoted: loRes.quoted,
        hiQuoted: hiRes.quoted,
      });
      continue;
    }

    if (ch === "]" || ch === "}") {
      throwDataPlaneError(400, "invalid_query", `Unexpected '${ch}' in Lucene query`);
    }

    // Unquoted word / wildcard / field token
    const start = i;
    const pieces: PatternPiece[] = [];
    let unescaped = "";
    const pushLit = (text: string) => {
      const last = pieces[pieces.length - 1];
      if (last && last.kind === "lit") {
        last.text += text;
      } else {
        pieces.push({ kind: "lit", text });
      }
    };

    while (i < src.length && !isWordStop(src[i]!)) {
      const c = src[i]!;
      if (c === "\\") {
        const esc = unescapeLuceneChar(src, i);
        pushLit(esc.ch);
        unescaped += esc.ch;
        i = esc.nextIdx;
      } else if (c === "*" || c === "?") {
        pieces.push({ kind: "wild", op: c });
        unescaped += c;
        i++;
      } else if ((c === "^" || c === "~") && pieces.length > 0) {
        // Boost / fuzziness suffix
        i++;
        while (i < src.length && /[0-9.]/.test(src[i]!)) {
          i++;
        }
        break;
      } else {
        pushLit(c);
        unescaped += c;
        i++;
      }
    }

    const raw = src.slice(start, i);
    if (pieces.length === 1 && pieces[0]!.kind === "lit") {
      if (raw === "AND") {
        tokens.push({ kind: "AND" });
        continue;
      }
      if (raw === "OR") {
        tokens.push({ kind: "OR" });
        continue;
      }
      if (raw === "NOT") {
        tokens.push({ kind: "NOT" });
        continue;
      }
    }

    if (pieces.length > 0 && pieces[0]!.kind === "wild") {
      throwDataPlaneError(
        400,
        "leading_wildcard_not_supported",
        `Leading wildcard in '${raw}' is not supported`,
      );
    }

    tokens.push({ kind: "WORD", raw, pieces, unescaped });
  }

  return tokens;
}

function parseLuceneAst(tokens: readonly LexToken[]): AstNode {
  let pos = 0;

  const peek = (): LexToken | undefined => tokens[pos];
  const consume = (): LexToken => {
    const tok = tokens[pos];
    if (!tok) {
      throwDataPlaneError(400, "invalid_query", "Unexpected end of Lucene query");
    }
    pos++;
    return tok;
  };

  const parseOrExpr = (defaultField: string | null, depth: number): AstNode => {
    if (depth > 32) {
      throwDataPlaneError(400, "invalid_query", "Lucene query nesting depth exceeded");
    }

    type JoinedItem = {
      joinBefore: "DEFAULT" | "AND" | "OR";
      modifier: "NONE" | "PLUS" | "NOT";
      node: AstNode;
    };

    const items: JoinedItem[] = [];
    let pendingJoin: "DEFAULT" | "AND" | "OR" = "DEFAULT";

    while (pos < tokens.length && peek()?.kind !== "RPAREN") {
      if (items.length > 0) {
        const nextKind = peek()?.kind;
        if (nextKind === "AND") {
          consume();
          pendingJoin = "AND";
        } else if (nextKind === "OR") {
          consume();
          pendingJoin = "OR";
        } else {
          pendingJoin = "DEFAULT";
        }
      } else if (peek()?.kind === "AND" || peek()?.kind === "OR") {
        throwDataPlaneError(400, "invalid_query", "Leading binary operator in Lucene query");
      }

      if (pos >= tokens.length || peek()?.kind === "RPAREN") {
        throwDataPlaneError(400, "invalid_query", "Trailing binary operator in Lucene query");
      }

      let modifier: "NONE" | "PLUS" | "NOT" = "NONE";
      const modTok = peek();
      if (modTok?.kind === "NOT" || modTok?.kind === "MINUS") {
        consume();
        modifier = "NOT";
      } else if (modTok?.kind === "PLUS") {
        consume();
        modifier = "PLUS";
      }

      const atom = parsePrimary(defaultField, depth);
      items.push({ joinBefore: pendingJoin, modifier, node: atom });
    }

    if (items.length === 0) {
      throwDataPlaneError(400, "invalid_query", "Empty Lucene sub-expression");
    }

    if (items.length === 1 && items[0]!.modifier !== "NOT") {
      return items[0]!.node;
    }

    // Group OR chains with lower precedence than AND (default operator is AND per lab_server.py:355).
    const andGroups: Array<JoinedItem[]> = [];
    for (const item of items) {
      if (andGroups.length === 0 || item.joinBefore !== "OR") {
        andGroups.push([item]);
      } else {
        andGroups[andGroups.length - 1]!.push(item);
      }
    }

    const buildGroupNode = (group: JoinedItem[]): { occur: "MUST" | "MUST_NOT"; node: AstNode } => {
      if (group.length === 1) {
        const single = group[0]!;
        return {
          occur: single.modifier === "NOT" ? "MUST_NOT" : "MUST",
          node: single.node,
        };
      }
      // OR group of multiple alternatives
      return {
        occur: "MUST",
        node: {
          type: "bool",
          clauses: group.map((g) => ({
            occur: g.modifier === "NOT" ? ("MUST_NOT" as const) : ("SHOULD" as const),
            node: g.node,
          })),
        },
      };
    };

    if (andGroups.length === 1 && andGroups[0]!.length > 1) {
      return buildGroupNode(andGroups[0]!).node;
    }

    return {
      type: "bool",
      clauses: andGroups.map((grp) => {
        const built = buildGroupNode(grp);
        return { occur: built.occur, node: built.node };
      }),
    };
  };

  const parsePrimary = (defaultField: string | null, depth: number): AstNode => {
    const tok = peek();
    if (!tok) {
      throwDataPlaneError(400, "invalid_query", "Expected Lucene term or group");
    }

    if (tok.kind === "LPAREN") {
      consume();
      const inner = parseOrExpr(defaultField, depth + 1);
      if (peek()?.kind !== "RPAREN") {
        throwDataPlaneError(400, "invalid_query", "Unbalanced '(' in Lucene query");
      }
      consume();
      return inner;
    }

    // Field prefix: WORD followed by COLON
    if (tok.kind === "WORD" && tokens[pos + 1]?.kind === "COLON") {
      if (tok.pieces.some((p) => p.kind === "wild")) {
        throwDataPlaneError(400, "invalid_query", `Wildcard field name '${tok.raw}' is not supported`);
      }
      const fieldName = tok.unescaped;
      consume(); // WORD
      consume(); // COLON

      if (fieldName === "_exists_") {
        return parseExistsValue(depth + 1);
      }

      const valTok = peek();
      if (!valTok) {
        throwDataPlaneError(400, "invalid_query", `Missing value after '${fieldName}:'`);
      }

      if (valTok.kind === "CMP") {
        const cmp = consume() as Extract<LexToken, { kind: "CMP" }>;
        const boundTok = consume();
        let boundStr: string;
        if (boundTok.kind === "WORD") {
          boundStr = boundTok.unescaped;
        } else if (boundTok.kind === "PHRASE") {
          boundStr = boundTok.value;
        } else {
          throwDataPlaneError(400, "invalid_query", `Invalid comparison operand on '${fieldName}'`);
        }
        if (cmp.op === ">=" || cmp.op === ">") {
          return {
            type: "range",
            field: fieldName,
            incLo: cmp.op === ">=",
            incHi: true,
            lo: boundStr,
            hi: null,
          };
        }
        return {
          type: "range",
          field: fieldName,
          incLo: true,
          incHi: cmp.op === "<=",
          lo: null,
          hi: boundStr,
        };
      }

      if (valTok.kind === "LPAREN") {
        consume();
        const groupNode = parseOrExpr(fieldName, depth + 1);
        if (peek()?.kind !== "RPAREN") {
          throwDataPlaneError(400, "invalid_query", `Unbalanced '(' in '${fieldName}:(...)'`);
        }
        consume();
        return groupNode;
      }

      return parseValueAtom(fieldName);
    }

    return parseValueAtom(defaultField);
  };

  const parseExistsValue = (depth: number): AstNode => {
    const next = peek();
    if (!next) {
      throwDataPlaneError(400, "invalid_query", "Missing field name after _exists_:");
    }
    if (next.kind === "PHRASE") {
      consume();
      return { type: "exists", field: next.value };
    }
    if (next.kind === "WORD") {
      consume();
      return { type: "exists", field: next.unescaped };
    }
    if (next.kind === "LPAREN") {
      consume();
      // Support _exists_:(fieldA OR fieldB) by parsing as OR/AND of bare words turned into exists nodes
      const sub = parseOrExpr("__EXISTS__", depth + 1);
      if (peek()?.kind !== "RPAREN") {
        throwDataPlaneError(400, "invalid_query", "Unbalanced '(' in _exists_:(...)");
      }
      consume();
      return convertTermsToExists(sub);
    }
    throwDataPlaneError(400, "invalid_query", "Invalid target for _exists_:");
  };

  const convertTermsToExists = (node: AstNode): AstNode => {
    if (node.type === "term") {
      return { type: "exists", field: node.unescaped };
    }
    if (node.type === "phrase") {
      return { type: "exists", field: node.value };
    }
    if (node.type === "bool") {
      return {
        type: "bool",
        clauses: node.clauses.map((c) => ({
          occur: c.occur,
          node: convertTermsToExists(c.node),
        })),
      };
    }
    return node;
  };

  const parseValueAtom = (field: string | null): AstNode => {
    const tok = consume();
    if (tok.kind === "PHRASE") {
      return { type: "phrase", field, value: tok.value };
    }
    if (tok.kind === "WORD") {
      return {
        type: "term",
        field,
        pieces: tok.pieces,
        unescaped: tok.unescaped,
      };
    }
    if (tok.kind === "RANGE") {
      const lo = !tok.loQuoted && tok.lo === "*" ? null : tok.lo;
      const hi = !tok.hiQuoted && tok.hi === "*" ? null : tok.hi;
      return {
        type: "range",
        field,
        incLo: tok.incLo,
        incHi: tok.incHi,
        lo,
        hi,
      };
    }
    throwDataPlaneError(400, "invalid_query", `Unexpected token '${tok.kind}' in Lucene query`);
  };

  const ast = parseOrExpr(null, 0);
  if (pos !== tokens.length) {
    throwDataPlaneError(400, "invalid_query", "Unexpected trailing tokens in Lucene query");
  }
  return ast;
}

function normalizeKeywordField(field: string): string {
  return field.endsWith(".keyword") ? field.slice(0, -8) : field;
}

function piecesHaveWildcard(pieces: readonly PatternPiece[]): boolean {
  return pieces.some((p) => p.kind === "wild");
}

function piecesToSqliteGlob(pieces: readonly PatternPiece[]): string {
  let glob = "";
  for (const piece of pieces) {
    if (piece.kind === "wild") {
      glob += piece.op;
    } else {
      for (const ch of piece.text) {
        if (ch === "*") glob += "[*]";
        else if (ch === "?") glob += "[?]";
        else if (ch === "[") glob += "[[]";
        else glob += ch;
      }
    }
  }
  return glob;
}

function buildFtsMatchExpr(
  ftsColumn: string,
  text: string,
  trailingPrefixWildcard: boolean,
): string | null {
  const words = text.match(/[\p{L}\p{N}_]+/gu);
  if (!words || words.length === 0) {
    return null;
  }
  if (words.length === 1) {
    const token = words[0]!;
    return trailingPrefixWildcard
      ? `${ftsColumn} : "${token}"*`
      : `${ftsColumn} : "${token}"`;
  }
  // Phrase sequence in FTS5; if trailing wildcard, last token gets prefix '*' outside quote
  if (trailingPrefixWildcard) {
    const prefixPhrase = words
      .slice(0, -1)
      .map((w) => `"${w}"`)
      .join(" ");
    const last = words[words.length - 1]!;
    return `${ftsColumn} : (${prefixPhrase} AND "${last}"*)`;
  }
  const phrase = words.map((w) => `"${w}"`).join(" ");
  return `${ftsColumn} : (${phrase})`;
}

function compileSingleFieldTermOrPhrase(
  rawField: string,
  value: string,
  pieces: readonly PatternPiece[] | null,
  params: SqlParam[],
): string {
  const ftsCol = FTS_FIELD_TO_COLUMN[rawField];
  if (ftsCol) {
    const hasWild = pieces !== null && piecesHaveWildcard(pieces);
    const trailingStar =
      hasWild &&
      pieces!.length >= 2 &&
      pieces![pieces!.length - 1]!.kind === "wild" &&
      (pieces![pieces!.length - 1] as Extract<PatternPiece, { kind: "wild" }>).op === "*";
    const matchExpr = buildFtsMatchExpr(ftsCol, value, trailingStar);
    if (!matchExpr) {
      return "0 = 1";
    }
    params.push(matchExpr);
    return "e.doc_id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)";
  }

  const field = normalizeKeywordField(rawField);
  if (field === "@timestamp") {
    try {
      const tsNs = parseTimestampNs(value);
      params.push(tsNs);
      return "e.ts_ns = ?";
    } catch {
      return "0 = 1";
    }
  }

  if (IP_FIELDS.has(field) && (pieces === null || !piecesHaveWildcard(pieces))) {
    const cidrBounds = cidrOrIpToBounds16(value);
    if (cidrBounds !== null) {
      const exactEq = Buffer.compare(Buffer.from(cidrBounds.lo), Buffer.from(cidrBounds.hi)) === 0;
      if (exactEq) {
        params.push(field, cidrBounds.lo);
        return "EXISTS (SELECT 1 FROM event_ips ip WHERE ip.doc_id = e.doc_id AND ip.field = ? AND ip.ip_bin = ?)";
      }
      params.push(field, cidrBounds.lo, cidrBounds.hi);
      return "EXISTS (SELECT 1 FROM event_ips ip WHERE ip.doc_id = e.doc_id AND ip.field = ? AND ip.ip_bin BETWEEN ? AND ?)";
    }
    return "0 = 1";
  }

  if (pieces !== null && piecesHaveWildcard(pieces)) {
    const globPat = piecesToSqliteGlob(pieces);
    params.push(field, globPat);
    return "EXISTS (SELECT 1 FROM event_kv kv WHERE kv.doc_id = e.doc_id AND kv.field = ? AND kv.val_str GLOB ?)";
  }

  if (field === "event.id") {
    params.push(value);
    return "e.event_id = ?";
  }

  params.push(field, value);
  return "EXISTS (SELECT 1 FROM event_kv kv WHERE kv.doc_id = e.doc_id AND kv.field = ? AND kv.val_str = ?)";
}

function compileRangeNode(
  node: Extract<AstNode, { type: "range" }>,
  params: SqlParam[],
): string {
  if (!node.field) {
    // Unqualified range: lenient across QUERY_FIELDS keyword columns
    return "0 = 1";
  }
  const field = normalizeKeywordField(node.field);

  if (field === "@timestamp") {
    const conds: string[] = [];
    if (node.lo !== null) {
      try {
        const loNs = parseTimestampNs(node.lo);
        params.push(loNs);
        conds.push(node.incLo ? "e.ts_ns >= ?" : "e.ts_ns > ?");
      } catch {
        throwDataPlaneError(400, "invalid_query", `Invalid @timestamp lower bound '${node.lo}'`);
      }
    }
    if (node.hi !== null) {
      try {
        const hiNs = parseTimestampNs(node.hi);
        params.push(hiNs);
        conds.push(node.incHi ? "e.ts_ns <= ?" : "e.ts_ns < ?");
      } catch {
        throwDataPlaneError(400, "invalid_query", `Invalid @timestamp upper bound '${node.hi}'`);
      }
    }
    return conds.length > 0 ? `(${conds.join(" AND ")})` : "1 = 1";
  }

  if (IP_FIELDS.has(field)) {
    const conds: string[] = ["ip.doc_id = e.doc_id", "ip.field = ?"];
    params.push(field);
    if (node.lo !== null) {
      const loBin = ipToBytes16(node.lo);
      if (!loBin) {
        throwDataPlaneError(400, "invalid_query", `Invalid IP lower bound '${node.lo}'`);
      }
      params.push(loBin);
      conds.push(node.incLo ? "ip.ip_bin >= ?" : "ip.ip_bin > ?");
    }
    if (node.hi !== null) {
      const hiBin = ipToBytes16(node.hi);
      if (!hiBin) {
        throwDataPlaneError(400, "invalid_query", `Invalid IP upper bound '${node.hi}'`);
      }
      params.push(hiBin);
      conds.push(node.incHi ? "ip.ip_bin <= ?" : "ip.ip_bin < ?");
    }
    return `EXISTS (SELECT 1 FROM event_ips ip WHERE ${conds.join(" AND ")})`;
  }

  const loNum = node.lo !== null && /^-?\d+(?:\.\d+)?$/.test(node.lo) ? Number(node.lo) : null;
  const hiNum = node.hi !== null && /^-?\d+(?:\.\d+)?$/.test(node.hi) ? Number(node.hi) : null;
  const isNumericRange =
    (node.lo === null || loNum !== null) &&
    (node.hi === null || hiNum !== null) &&
    (loNum !== null || hiNum !== null);

  if (isNumericRange) {
    const conds: string[] = ["kv.doc_id = e.doc_id", "kv.field = ?", "kv.val_num IS NOT NULL"];
    params.push(field);
    if (loNum !== null) {
      params.push(loNum);
      conds.push(node.incLo ? "kv.val_num >= ?" : "kv.val_num > ?");
    }
    if (hiNum !== null) {
      params.push(hiNum);
      conds.push(node.incHi ? "kv.val_num <= ?" : "kv.val_num < ?");
    }
    return `EXISTS (SELECT 1 FROM event_kv kv WHERE ${conds.join(" AND ")})`;
  }

  const strConds: string[] = ["kv.doc_id = e.doc_id", "kv.field = ?", "kv.val_str IS NOT NULL"];
  params.push(field);
  if (node.lo !== null) {
    params.push(node.lo);
    strConds.push(node.incLo ? "kv.val_str >= ?" : "kv.val_str > ?");
  }
  if (node.hi !== null) {
    params.push(node.hi);
    strConds.push(node.incHi ? "kv.val_str <= ?" : "kv.val_str < ?");
  }
  return `EXISTS (SELECT 1 FROM event_kv kv WHERE ${strConds.join(" AND ")})`;
}

function compileExistsNode(rawField: string, params: SqlParam[]): string {
  const field = normalizeKeywordField(rawField);
  if (field === "@timestamp" || field === "event.id") {
    return "1 = 1";
  }
  if (field === "message") {
    return "e.has_message = 1";
  }
  if (field === "powershell.file.script_block_text") {
    return "e.has_script_block = 1";
  }
  const ftsCol = FTS_FIELD_TO_COLUMN[rawField];
  if (ftsCol) {
    const baseField = rawField.endsWith(".text") ? rawField.slice(0, -5) : rawField;
    params.push(baseField);
    return "EXISTS (SELECT 1 FROM event_kv kv WHERE kv.doc_id = e.doc_id AND kv.field = ?)";
  }
  if (IP_FIELDS.has(field)) {
    params.push(field);
    return "EXISTS (SELECT 1 FROM event_ips ip WHERE ip.doc_id = e.doc_id AND ip.field = ?)";
  }
  params.push(field);
  return "EXISTS (SELECT 1 FROM event_kv kv WHERE kv.doc_id = e.doc_id AND kv.field = ?)";
}

function compileAstToSql(node: AstNode, params: SqlParam[]): string {
  switch (node.type) {
    case "exists":
      return compileExistsNode(node.field, params);

    case "range":
      return compileRangeNode(node, params);

    case "phrase":
    case "term": {
      const value = node.type === "phrase" ? node.value : node.unescaped;
      const pieces = node.type === "term" ? node.pieces : null;
      if (node.field !== null) {
        return compileSingleFieldTermOrPhrase(node.field, value, pieces, params);
      }

      // Unqualified query_string searches across QUERY_FIELDS (lab_server.py:126-130)
      const subDisjuncts: string[] = [];
      for (const qf of QUERY_FIELDS) {
        const subSql = compileSingleFieldTermOrPhrase(qf, value, pieces, params);
        if (subSql !== "0 = 1") {
          subDisjuncts.push(subSql);
        }
      }
      if (subDisjuncts.length === 0) {
        return "0 = 1";
      }
      return `(${subDisjuncts.join(" OR ")})`;
    }

    case "bool": {
      const mustSql: string[] = [];
      const shouldSql: string[] = [];
      const mustNotSql: string[] = [];

      for (const c of node.clauses) {
        const compiled = compileAstToSql(c.node, params);
        if (c.occur === "MUST") {
          mustSql.push(compiled);
        } else if (c.occur === "SHOULD") {
          shouldSql.push(compiled);
        } else {
          mustNotSql.push(`NOT (${compiled})`);
        }
      }

      const parts: string[] = [...mustSql];
      if (shouldSql.length > 0) {
        parts.push(`(${shouldSql.join(" OR ")})`);
      }
      parts.push(...mustNotSql);

      if (parts.length === 0) {
        return "1 = 1";
      }
      return `(${parts.join(" AND ")})`;
    }
  }
}

export function compileLuceneQueryString(rawQuery: string | undefined): CompiledSqlPredicate {
  const q = rawQuery ?? "";
  if (q.length > 500) {
    throwDataPlaneError(400, "invalid_query", "Lucene query exceeds 500 characters");
  }
  for (let i = 0; i < q.length; i++) {
    const code = q.charCodeAt(i);
    if (code < 32 || code === 127) {
      throwDataPlaneError(400, "invalid_query", "Lucene query contains control characters");
    }
  }

  if (q.trim().length === 0) {
    return { whereSql: "1 = 1", params: [] };
  }

  const tokens = tokenizeLucene(q);
  const ast = parseLuceneAst(tokens);
  const params: SqlParam[] = [];
  const whereSql = compileAstToSql(ast, params);
  return { whereSql, params };
}
