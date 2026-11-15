import fs from "node:fs";

export const SCORER_SCHEMA_VERSION = 1 as const;

// The Python reference (`scenario.py`) compiles `str` patterns, so `re` is
// Unicode-aware there: `\w`/`\b` cover every letter, number and `_`, `\d` is any
// decimal digit (Nd) and `\s` is `str.isspace()`. JS `\b`, `\d` and `\s` are
// ASCII-only or a different set, so every scorer pattern spells those classes
// out below and is compiled with the `u` flag (see `PY_RE_FLAGS`).
/** Python `str` `\w`: letters, numbers and `_`. */
export const PY_WORD_CLASS = String.raw`[\p{L}\p{N}_]`;
/** Python `\b` before a word character. */
export const PY_WORD_START = String.raw`(?<![\p{L}\p{N}_])`;
/** Python `\b` after a word character. */
export const PY_WORD_END = String.raw`(?![\p{L}\p{N}_])`;
/** Python `\d` for `str` patterns: any Unicode decimal digit. */
export const PY_DIGIT = String.raw`\p{Nd}`;
/** Python `\s` for `str` patterns: exactly the characters where `str.isspace()` is true. */
export const PY_SPACE = String.raw`[\t\n\x0b\x0c\r\x1c-\x1f \x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]`;
/** Python `$` without MULTILINE: end of string, or just before one final `\n`. */
const PY_END = String.raw`(?=\n?(?![\s\S]))`;
/** Every scorer pattern built from the sources below must carry these flags. */
export const PY_RE_FLAGS = "u" as const;
const S = PY_SPACE;
const B0 = PY_WORD_START;
const B1 = PY_WORD_END;

const EVENT_ID_SOURCE = `${PY_WORD_START}evt-${PY_DIGIT}{6,}${PY_WORD_END}`;
// Python compiles this one with re.IGNORECASE, which folds the literal only;
// its word boundary still sees U+0345 (a mark) as a non-word character. A JS `/iu` flag
// would also case-fold the boundary class (U+0345 folds to a Greek letter), so
// the literal spells out its case variants and the pattern runs without `i`.
const FRAME_ID_SOURCE = `${PY_WORD_START}[fF][rR][aA][mM][eE]-(${PY_DIGIT}+)${PY_WORD_END}`;
const INTEL_ID_SOURCE = `${PY_WORD_START}ioc-${PY_DIGIT}{5,}${PY_WORD_END}`;

/** Fresh global matchers for the citation patterns (the sources need `PY_RE_FLAGS`). */
export const eventIdMatcher = (): RegExp => new RegExp(EVENT_ID_SOURCE, `g${PY_RE_FLAGS}`);
export const frameIdMatcher = (): RegExp => new RegExp(FRAME_ID_SOURCE, `g${PY_RE_FLAGS}`);
export const intelIdMatcher = (): RegExp => new RegExp(INTEL_ID_SOURCE, `g${PY_RE_FLAGS}`);

export const EVENT_ID_EXACT_RE = /^evt-\d{6,}$/;
export const FRAME_ID_EXACT_RE = /^frame-(\d+)$/i;
export const INTEL_ID_EXACT_RE = /^ioc-\d{5,}$/;

export const ALTERNATIVE_GROUPS = [
  ["evidence_frame_groups", "cited_frames"],
  ["evidence_intel_groups", "cited_intel_ids"],
] as const;

export const SIBLING_GROUPS = "evidence_sibling_groups" as const;

export const COMPROMISE_TERMS = [
  "malicious",
  "compromise",
  "compromised",
  "attacker",
  "adversary",
  "intrusion",
  "threat actor",
  "command-and-control",
  "command and control",
  "c2",
  "exfiltration",
  "exfiltrate",
  "exfiltrated",
  "lateral movement",
  "backdoor",
  "implant",
  "brute force",
  "brute-force",
  "password spray",
  "malware",
] as const;

export const BENIGN_TERMS = [
  "benign",
  "legitimate",
  "authorized",
  "authorised",
  "expected",
  "false positive",
  "not malicious",
  "routine",
  "sanctioned",
  "scheduled backup",
  "administrative",
  "approved",
  "normal",
  "not an attack",
  "not compromise",
  "no evidence of compromise",
] as const;

const COMP_NEG_SOURCE = `${B0}(?:not|no|never|neither|nor|without|lacks?|ruled?${S}+out|ruling${S}+out|rather${S}+than|instead${S}+of|looks?${S}+like|looked${S}+like|resembles?|resembled|mimics?|appeared${S}+to${S}+be|appears${S}+to${S}+be|false${S}+positive(?:${S}+for)?)${B1}`;

export const COMP_NEG_RE = new RegExp(COMP_NEG_SOURCE, PY_RE_FLAGS);

export const COMP_POST_NEG_RE = new RegExp(
  `(?<!not${S})(?<!never${S})${B0}(?:(?:was|were|is|are|been)${S}+(?:ruled${S}+out|disproved|refuted|unfounded|false${S}+positive|not${S}+(?:observed|found|detected|confirmed|present))|ruled${S}+out|disproved|refuted|not${S}+(?:observed|found|detected))${B1}`,
  PY_RE_FLAGS,
);

export const BENIGN_HEDGE_PRE_RE = new RegExp(
  `${B0}(?:not|no|never|without|zero|lacks?|unlikely(?:${S}+to${S}+be)?|possibly|possible|maybe|potentially|potential|whether|if|despite|although|though|rule[ds]?${S}+out)${S}+(?:a${S}+|an${S}+|the${S}+|any${S}+|to${S}+be${S}+)?${PY_END}`,
  PY_RE_FLAGS,
);

export const BENIGN_HEDGE_POST_RE = new RegExp(
  `^${S}*(?:alternative|explanation|possibility|hypothesis|(?:is${S}+|was${S}+)?unlikely|not${S}+ruled${S}+out)${B1}`,
  PY_RE_FLAGS,
);

export const LEADING_COMPROMISE_RE = new RegExp(
  `^${S}*(?:malicious|compromised?|intrusion)${S}*[(,:]`,
  PY_RE_FLAGS,
);

const CONTRAST_PIVOT_SOURCE = `(?:,${S}*|${S}+)(?:but|however|yet)${B1}`;
export const CONTRAST_PIVOT_RE = new RegExp(CONTRAST_PIVOT_SOURCE, PY_RE_FLAGS);
const CLAUSE_BOUNDARY_RE = new RegExp(String.raw`\.(?=${S}|${PY_END})|[;:]`, PY_RE_FLAGS);
const OR_NOR_LEAD_RE = new RegExp(`^${S}*(?:or|nor)${B1}`, PY_RE_FLAGS);
const HEDGE_SPLIT_RE = /[,;.():]/;

export interface TruthFact {
  fact_id: string;
  kind: string;
  observation?: string;
  entities: Record<string, readonly string[]>;
  evidence_event_groups: ReadonlyArray<readonly string[]>;
  evidence_frame_groups?: ReadonlyArray<readonly string[]>;
  evidence_intel_groups?: ReadonlyArray<readonly string[]>;
  evidence_sibling_groups?: ReadonlyArray<readonly string[]>;
  [extraKey: string]: unknown;
}

export interface ScenarioTruth {
  schema_version: number;
  case_id?: string;
  story?: string;
  source?: string;
  data_origin?: string;
  facts: readonly TruthFact[];
  [extraKey: string]: unknown;
}

export interface SiblingFactDetail {
  found: boolean;
  cited_groups: number[];
  missing_groups: number[];
}

export interface ScoredFactDetail {
  fact_id: string;
  kind: string;
  found: boolean;
  cited_groups: number[];
  missing_groups: number[];
  cited_event_ids: string[];
  entities_named: string[];
  cited_frames?: string[];
  cited_intel_ids?: string[];
  cited_sibling_ids?: string[];
  with_siblings?: SiblingFactDetail;
}

export interface KindTallyBucket {
  total: number;
  found: number;
  partial: number;
}

export interface MisattributedDecoy {
  fact_id: string;
  claim_id: unknown;
  entities: string[];
  terms: string[];
}

export interface WithSiblingsSummary {
  found: number;
  total: number;
  by_kind: Record<string, KindTallyBucket>;
  decoys_cleared: number;
  method: string;
}

export interface ScoreReportResult {
  found: number;
  total: number;
  by_kind: Record<string, KindTallyBucket>;
  decoys_cleared: number;
  facts: ScoredFactDetail[];
  misattributed_decoys: MisattributedDecoy[];
  method: string;
  with_siblings?: WithSiblingsSummary;
  report?: string;
}

export interface ScoreBatchResult {
  schema_version: typeof SCORER_SCHEMA_VERSION;
  case_id: unknown;
  reports: ScoreReportResult[];
}

export function compareLexicographic(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

export function compareByLengthThenLex(a: string, b: string): number {
  return a.length - b.length || compareLexicographic(a, b);
}

export function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function parseStrictJson(source: string): unknown {
  let pos = 0;
  const len = source.length;

  const skipWs = (): void => {
    while (pos < len) {
      const ch = source.charCodeAt(pos);
      if (ch === 0x20 || ch === 0x09 || ch === 0x0a || ch === 0x0d) {
        pos++;
      } else {
        break;
      }
    }
  };

  const parseString = (): string => {
    const start = pos;
    pos++; // skip opening '"'
    while (pos < len) {
      const ch = source.charCodeAt(pos);
      if (ch === 0x22) {
        pos++;
        return JSON.parse(source.slice(start, pos)) as string;
      }
      if (ch === 0x5c) {
        pos += 2;
        continue;
      }
      if (ch < 0x20) {
        throw new Error(`Invalid control character in JSON string at position ${pos}`);
      }
      pos++;
    }
    throw new Error("Unterminated JSON string");
  };

  const parseNumberOrNonFinite = (): number => {
    const rest = source.slice(pos);
    const nonFinite = /^(?:-?Infinity|NaN)\b/.exec(rest);
    if (nonFinite) {
      throw new Error(`non-finite JSON number: ${nonFinite[0]}`);
    }
    const numMatch = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(rest);
    if (!numMatch) {
      throw new Error(`Unexpected JSON token at position ${pos}`);
    }
    pos += numMatch[0].length;
    const parsed = JSON.parse(numMatch[0]) as number;
    if (!Number.isFinite(parsed)) {
      throw new Error(`non-finite JSON number: ${numMatch[0]}`);
    }
    return parsed;
  };

  const parseValue = (): unknown => {
    skipWs();
    if (pos >= len) {
      throw new Error("Unexpected end of JSON input");
    }
    const ch = source[pos];
    if (ch === '"') {
      return parseString();
    }
    if (ch === "{") {
      pos++;
      skipWs();
      const obj: Record<string, unknown> = {};
      const seenKeys = new Set<string>();
      if (pos < len && source[pos] === "}") {
        pos++;
        return obj;
      }
      while (pos < len) {
        skipWs();
        if (source[pos] !== '"') {
          throw new Error(`Expected JSON object key string at position ${pos}`);
        }
        const key = parseString();
        if (seenKeys.has(key)) {
          throw new Error(`duplicate JSON key: ${key}`);
        }
        seenKeys.add(key);
        skipWs();
        if (source[pos] !== ":") {
          throw new Error(`Expected ':' after JSON object key at position ${pos}`);
        }
        pos++;
        const val = parseValue();
        Object.defineProperty(obj, key, {
          value: val,
          enumerable: true,
          writable: true,
          configurable: true,
        });
        skipWs();
        if (source[pos] === ",") {
          pos++;
          skipWs();
          if (source[pos] === "}") {
            throw new Error(`Trailing comma in JSON object at position ${pos}`);
          }
          continue;
        }
        if (source[pos] === "}") {
          pos++;
          return obj;
        }
        throw new Error(`Expected ',' or '}' in JSON object at position ${pos}`);
      }
      throw new Error("Unterminated JSON object");
    }
    if (ch === "[") {
      pos++;
      skipWs();
      const arr: unknown[] = [];
      if (pos < len && source[pos] === "]") {
        pos++;
        return arr;
      }
      while (pos < len) {
        arr.push(parseValue());
        skipWs();
        if (source[pos] === ",") {
          pos++;
          skipWs();
          if (source[pos] === "]") {
            throw new Error(`Trailing comma in JSON array at position ${pos}`);
          }
          continue;
        }
        if (source[pos] === "]") {
          pos++;
          return arr;
        }
        throw new Error(`Expected ',' or ']' in JSON array at position ${pos}`);
      }
      throw new Error("Unterminated JSON array");
    }
    if (source.startsWith("true", pos)) {
      pos += 4;
      return true;
    }
    if (source.startsWith("false", pos)) {
      pos += 5;
      return false;
    }
    if (source.startsWith("null", pos)) {
      pos += 4;
      return null;
    }
    return parseNumberOrNonFinite();
  };

  const result = parseValue();
  skipWs();
  if (pos !== len) {
    throw new Error(`Unexpected trailing JSON content at position ${pos}`);
  }
  return result;
}

export function loadJsonText(text: string): unknown {
  const withoutBom = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  let stripped = withoutBom.trim();
  const fence = /^```[A-Za-z0-9_-]*\s*\n([\s\S]*)\r?\n```$/.exec(stripped);
  if (fence && fence[1] !== undefined) {
    stripped = fence[1];
  }
  return parseStrictJson(stripped);
}

export function textOf(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => textOf(item)).join("\n");
  }
  if (isPlainRecord(value)) {
    return Object.values(value)
      .map((item) => textOf(item))
      .join("\n");
  }
  return "";
}

export function names(text: string, value: string): boolean {
  const escaped = escapeRegExp(value.toLowerCase());
  const re = new RegExp(`(?<![A-Za-z0-9_.-])${escaped}(?![A-Za-z0-9_-]|\\.[A-Za-z0-9])`);
  return re.test(text);
}

export function hasTerm(text: string, terms: readonly string[]): string[] {
  const matched: string[] = [];
  for (const term of terms) {
    const re = new RegExp(`(?<![a-z0-9])${escapeRegExp(term)}(?![a-z0-9])`);
    if (re.test(text)) {
      matched.push(term);
    }
  }
  return matched;
}

const DECIMAL_DIGIT_RE = /^\p{Nd}$/u;

/**
 * Value of one Unicode decimal digit, as Python's `int()` reads it. Unicode
 * encodes every decimal digit set as a contiguous run in 0..9 order (adjacent
 * sets, such as the mathematical digits, abut), so the value is the offset from
 * the start of its run, modulo 10.
 */
function decimalDigitValue(codePoint: number): number {
  let start = codePoint;
  while (start > 0 && DECIMAL_DIGIT_RE.test(String.fromCodePoint(start - 1))) {
    start -= 1;
  }
  return (codePoint - start) % 10;
}

/** ASCII spelling of a run of Unicode decimal digits (Python `str(int(digits))` minus sign handling). */
export function asciiDigits(digits: string): string {
  let out = "";
  for (const ch of digits) {
    const cp = ch.codePointAt(0)!;
    out += cp >= 0x30 && cp <= 0x39 ? ch : String(decimalDigitValue(cp));
  }
  return out;
}

export function normalizeFrameCitation(digits: string): string {
  return `frame-${BigInt(asciiDigits(digits)).toString(10)}`;
}

/** Python `s[-n:]`: the last `n` code points (JS string indices are UTF-16 units). */
export function lastCodePoints(text: string, count: number): string {
  let idx = text.length;
  for (let seen = 0; idx > 0 && seen < count; seen++) {
    const low = text.charCodeAt(idx - 1);
    const pair =
      idx >= 2 && low >= 0xdc00 && low <= 0xdfff && (text.charCodeAt(idx - 2) & 0xfc00) === 0xd800;
    idx -= pair ? 2 : 1;
  }
  return text.slice(idx);
}

/** Python `s[:n]`: the first `n` code points. */
export function firstCodePoints(text: string, count: number): string {
  let idx = 0;
  for (let seen = 0; idx < text.length && seen < count; seen++) {
    const high = text.charCodeAt(idx);
    const pair =
      idx + 1 < text.length &&
      (high & 0xfc00) === 0xd800 &&
      (text.charCodeAt(idx + 1) & 0xfc00) === 0xdc00;
    idx += pair ? 2 : 1;
  }
  return text.slice(0, idx);
}

export function citedIds(text: string): Set<string> {
  const result = new Set<string>();
  for (const match of text.matchAll(eventIdMatcher())) {
    result.add(match[0]);
  }
  for (const match of text.matchAll(frameIdMatcher())) {
    if (match[1] !== undefined) {
      result.add(normalizeFrameCitation(match[1]));
    }
  }
  for (const match of text.matchAll(intelIdMatcher())) {
    result.add(match[0]);
  }
  return result;
}

export interface TermPositionHit {
  readonly start: number;
  readonly term: string;
}

function splitContrastPivots(segment: string): string[] {
  return segment.split(CONTRAST_PIVOT_RE);
}

export function compNegated(statement: string, matchStart: number, matchEnd: number): boolean {
  const preClause = statement.slice(0, matchStart).split(CLAUSE_BOUNDARY_RE).at(-1) ?? "";
  const pre = lastCodePoints(splitContrastPivots(preClause).at(-1) ?? "", 96);

  for (const neg of pre.matchAll(new RegExp(COMP_NEG_SOURCE, `g${PY_RE_FLAGS}`))) {
    const negIdx = neg.index ?? 0;
    const span = pre.slice(negIdx + neg[0].length);
    const bhits: number[] = [];
    for (const benignTerm of BENIGN_TERMS) {
      const benignRe = new RegExp(`(?<![a-z0-9])${escapeRegExp(benignTerm)}(?![a-z0-9])`, "g");
      for (const bm of span.matchAll(benignRe)) {
        bhits.push((bm.index ?? 0) + bm[0].length);
      }
    }
    if (bhits.length === 0 || OR_NOR_LEAD_RE.test(span.slice(Math.max(...bhits)))) {
      return true;
    }
  }

  const postClause = statement.slice(matchEnd).split(CLAUSE_BOUNDARY_RE)[0] ?? "";
  const clause = firstCodePoints(splitContrastPivots(postClause)[0] ?? "", 96);
  const hit = COMP_POST_NEG_RE.exec(clause);
  return Boolean(hit && hasTerm(clause.slice(0, hit.index), BENIGN_TERMS).length === 0);
}

export function affirmativeCompromise(statement: string): TermPositionHit[] {
  const hits: TermPositionHit[] = [];
  for (const term of COMPROMISE_TERMS) {
    const re = new RegExp(`(?<![a-z0-9])${escapeRegExp(term)}(?![a-z0-9])`, "g");
    for (const match of statement.matchAll(re)) {
      const start = match.index ?? 0;
      const end = start + match[0].length;
      if (!compNegated(statement, start, end)) {
        hits.push({ start, term });
      }
    }
  }
  hits.sort((a, b) => a.start - b.start || compareLexicographic(a.term, b.term));
  return hits;
}

export function affirmativeBenign(statement: string): TermPositionHit[] {
  const hits: TermPositionHit[] = [];
  for (const term of BENIGN_TERMS) {
    const re = new RegExp(`(?<![a-z0-9])${escapeRegExp(term)}(?![a-z0-9])`, "g");
    for (const match of statement.matchAll(re)) {
      const start = match.index ?? 0;
      const end = start + match[0].length;
      const preClause = statement.slice(0, start).split(HEDGE_SPLIT_RE).at(-1) ?? "";
      const postSlice = firstCodePoints(statement.slice(end), 32);
      if (!BENIGN_HEDGE_PRE_RE.test(preClause) && !BENIGN_HEDGE_POST_RE.test(postSlice)) {
        hits.push({ start, term });
      }
    }
  }
  hits.sort((a, b) => a.start - b.start || compareLexicographic(a.term, b.term));
  return hits;
}

export function blamesDecoy(statement: string): boolean {
  const low = statement.toLowerCase();
  const comp = affirmativeCompromise(low);
  if (comp.length === 0) {
    return false;
  }

  const pivots = [...low.matchAll(new RegExp(CONTRAST_PIVOT_SOURCE, `g${PY_RE_FLAGS}`))];
  const lastPivot = pivots.at(-1);
  if (lastPivot !== undefined) {
    const tail = low.slice((lastPivot.index ?? 0) + lastPivot[0].length);
    if (affirmativeBenign(tail).length > 0 && affirmativeCompromise(tail).length === 0) {
      return false;
    }
  }

  const benign = LEADING_COMPROMISE_RE.test(low) ? [] : affirmativeBenign(low);
  if (benign.length === 0) {
    return true;
  }
  if (comp.length > benign.length) {
    return true;
  }
  return comp.length === benign.length && comp[0]!.start < benign[0]!.start;
}

function isStringArrayList(value: unknown, expectedLength?: number): value is string[][] {
  if (!Array.isArray(value)) {
    return false;
  }
  if (expectedLength !== undefined && value.length !== expectedLength) {
    return false;
  }
  return value.every(
    (group) => Array.isArray(group) && group.every((item) => typeof item === "string"),
  );
}

export function validateTruth(truth: unknown): asserts truth is ScenarioTruth {
  if (
    !isPlainRecord(truth) ||
    truth.schema_version !== SCORER_SCHEMA_VERSION ||
    !Array.isArray(truth.facts)
  ) {
    throw new Error("truth must be a scenario truth.json with schema_version 1 and facts");
  }

  const optionalGroupKeys = [
    ...ALTERNATIVE_GROUPS.map(([key]) => key),
    SIBLING_GROUPS,
  ] as const;

  for (const fact of truth.facts) {
    if (
      !isPlainRecord(fact) ||
      typeof fact.fact_id !== "string" ||
      typeof fact.kind !== "string" ||
      !isPlainRecord(fact.entities) ||
      !("evidence_event_groups" in fact)
    ) {
      throw new Error("truth fact is missing required keys");
    }

    const groups = fact.evidence_event_groups;
    if (
      !isStringArrayList(groups) ||
      groups.length === 0 ||
      groups.some((group) => group.length === 0)
    ) {
      throw new Error(`truth fact ${fact.fact_id} has empty evidence groups`);
    }

    for (const key of optionalGroupKeys) {
      if (key in fact && !isStringArrayList(fact[key], groups.length)) {
        throw new Error(`truth fact ${fact.fact_id} has malformed ${key}`);
      }
    }
  }
}

export interface ClaimCitationsPair {
  readonly ids: ReadonlySet<string>;
  readonly low: string;
}

export function factCitations(
  coverage: boolean,
  entities: readonly string[],
  perClaim: readonly ClaimCitationsPair[],
  allClaimIds: ReadonlySet<string>,
  limitationIds: ReadonlySet<string>,
): Set<string> {
  if (coverage) {
    const union = new Set<string>(allClaimIds);
    for (const id of limitationIds) {
      union.add(id);
    }
    return union;
  }
  const union = new Set<string>();
  for (const { ids, low } of perClaim) {
    if (entities.some((entity) => names(low, entity))) {
      for (const id of ids) {
        union.add(id);
      }
    }
  }
  return union;
}

function tally(
  details: readonly ScoredFactDetail[],
  blamed: ReadonlySet<string>,
  status: (detail: ScoredFactDetail) => readonly [found: boolean, citedGroups: readonly number[]],
): {
  found: number;
  byKind: Record<string, KindTallyBucket>;
  decoysCleared: number;
} {
  let found = 0;
  const byKind: Record<string, KindTallyBucket> = {};
  let decoysCleared = 0;

  for (const detail of details) {
    const [factFound, citedGroups] = status(detail);
    found += factFound ? 1 : 0;
    let bucket = byKind[detail.kind];
    if (!bucket) {
      bucket = { total: 0, found: 0, partial: 0 };
      byKind[detail.kind] = bucket;
    }
    bucket.total += 1;
    bucket.found += factFound ? 1 : 0;
    bucket.partial += !factFound && citedGroups.length > 0 ? 1 : 0;
    if (detail.kind === "decoy" && factFound && !blamed.has(detail.fact_id)) {
      decoysCleared += 1;
    }
  }

  return { found, byKind, decoysCleared };
}

function setIntersects(a: ReadonlySet<string>, b: ReadonlySet<string>): boolean {
  for (const item of b) {
    if (a.has(item)) {
      return true;
    }
  }
  return false;
}

export function scoreReport(truth: unknown, report: unknown): ScoreReportResult {
  validateTruth(truth);
  if (!isPlainRecord(report) || !Array.isArray(report.claims)) {
    throw new Error("report must be a JSON object with a claims list");
  }

  const claims = report.claims.filter(isPlainRecord);
  const perClaim: ClaimCitationsPair[] = claims.map((claim) => {
    const raw = textOf(claim);
    return { ids: citedIds(raw), low: raw.toLowerCase() };
  });

  const claimText = perClaim.map((c) => c.low).join("\n");
  const limitationText = textOf(report.limitations ?? []);
  const allClaimIds = new Set<string>();
  for (const { ids } of perClaim) {
    for (const id of ids) {
      allClaimIds.add(id);
    }
  }
  const limitationIds = citedIds(limitationText);

  const attackEntities = new Set<string>();
  for (const fact of truth.facts) {
    if (fact.kind === "attack") {
      for (const values of Object.values(fact.entities)) {
        if (Array.isArray(values)) {
          for (const val of values) {
            attackEntities.add(String(val).toLowerCase());
          }
        }
      }
    }
  }

  const details: ScoredFactDetail[] = [];
  const misattributed: MisattributedDecoy[] = [];
  const withSiblings = truth.facts.some((fact) => SIBLING_GROUPS in fact);

  for (const fact of truth.facts) {
    const coverage = fact.kind === "coverage";
    const entitySet = new Set<string>();
    for (const values of Object.values(fact.entities)) {
      if (Array.isArray(values)) {
        for (const val of values) {
          entitySet.add(String(val));
        }
      }
    }
    const entities = [...entitySet].sort(compareLexicographic);
    const cited = factCitations(coverage, entities, perClaim, allClaimIds, limitationIds);
    const text = coverage ? `${claimText}\n${limitationText.toLowerCase()}` : claimText;
    const groups = fact.evidence_event_groups;

    const alternatives = ALTERNATIVE_GROUPS.filter(([key]) => key in fact);
    // The reference (`scenario.py` score_report) unions the truth's alternative
    // groups into each event group verbatim: an id listed in two groups credits
    // both, and truth spellings are not normalised.
    const altGroups = new Map<string, ReadonlyArray<readonly string[]>>();
    for (const [key] of alternatives) {
      altGroups.set(key, fact[key] as ReadonlyArray<readonly string[]>);
    }

    const accepted: Set<string>[] = groups.map((group, index) => {
      const groupSet = new Set<string>(group);
      for (const [key] of alternatives) {
        const altForGroup = altGroups.get(key)?.[index] ?? [];
        for (const item of altForGroup) {
          groupSet.add(item);
        }
      }
      return groupSet;
    });

    const covered: number[] = [];
    const missingGroups: number[] = [];
    for (let idx = 0; idx < accepted.length; idx++) {
      if (setIntersects(cited, accepted[idx]!)) {
        covered.push(idx);
      } else {
        missingGroups.push(idx);
      }
    }

    const named = entities.filter((value) => names(text, value));
    const factEventPool = new Set<string>();
    for (const group of groups) {
      for (const eid of group) {
        factEventPool.add(eid);
      }
    }
    const citedEventIds = [...factEventPool]
      .filter((eid) => cited.has(eid))
      .sort(compareLexicographic);

    const detail: ScoredFactDetail = {
      fact_id: fact.fact_id,
      kind: fact.kind,
      found: covered.length === groups.length && named.length > 0,
      cited_groups: covered,
      missing_groups: missingGroups,
      cited_event_ids: citedEventIds,
      entities_named: named,
    };

    for (const [key, label] of alternatives) {
      const altPool = new Set<string>();
      for (const grp of altGroups.get(key) ?? []) {
        for (const item of grp) {
          altPool.add(item);
        }
      }
      const citedAlt = [...altPool]
        .filter((item) => cited.has(item))
        .sort(compareByLengthThenLex);
      detail[label] = citedAlt;
    }

    if (withSiblings) {
      const rawSiblings = fact[SIBLING_GROUPS];
      const siblings: ReadonlyArray<readonly string[]> =
        rawSiblings && rawSiblings.length > 0 ? rawSiblings : groups.map(() => []);
      const wider: number[] = [];
      const siblingMissing: number[] = [];
      const siblingPool = new Set<string>();

      for (let idx = 0; idx < groups.length; idx++) {
        const combined = new Set<string>(accepted[idx]!);
        for (const sibId of siblings[idx] ?? []) {
          combined.add(sibId);
          siblingPool.add(sibId);
        }
        if (setIntersects(cited, combined)) {
          wider.push(idx);
        } else {
          siblingMissing.push(idx);
        }
      }

      detail.cited_sibling_ids = [...siblingPool]
        .filter((eid) => cited.has(eid))
        .sort(compareLexicographic);
      detail.with_siblings = {
        found: wider.length === groups.length && named.length > 0,
        cited_groups: wider,
        missing_groups: siblingMissing,
      };
    }

    details.push(detail);

    if (fact.kind !== "decoy") {
      continue;
    }

    const distinctive = entities.filter((value) => !attackEntities.has(value.toLowerCase()));
    for (const claim of claims) {
      const statement = textOf(claim.statement ?? "").toLowerCase();
      const hits = distinctive.filter((value) => names(statement, value));
      const terms = hasTerm(statement, COMPROMISE_TERMS);
      if (hits.length > 0 && terms.length > 0 && blamesDecoy(statement)) {
        misattributed.push({
          fact_id: fact.fact_id,
          claim_id: claim.claim_id ?? null,
          entities: hits,
          terms,
        });
      }
    }
  }

  const blamed = new Set<string>(misattributed.map((item) => item.fact_id));
  const strictTally = tally(details, blamed, (d) => [d.found, d.cited_groups]);
  const hasAnyAlternatives = truth.facts.some((fact) =>
    ALTERNATIVE_GROUPS.some(([key]) => key in fact),
  );
  const methodPrefix = hasAnyAlternatives
    ? "keyword and event-, frame- and intel-ID citation matching"
    : "keyword and event-ID citation matching";

  const result: ScoreReportResult = {
    found: strictTally.found,
    total: details.length,
    by_kind: strictTally.byKind,
    decoys_cleared: strictTally.decoysCleared,
    facts: details,
    misattributed_decoys: misattributed,
    method: `${methodPrefix} against the operator key; not human judgment`,
  };

  if (withSiblings) {
    const siblingTally = tally(details, blamed, (d) => [
      d.with_siblings!.found,
      d.with_siblings!.cited_groups,
    ]);
    result.with_siblings = {
      found: siblingTally.found,
      total: details.length,
      by_kind: siblingTally.byKind,
      decoys_cleared: siblingTally.decoysCleared,
      method:
        "as found, but a group is also cited by an event the key lists beside it (evidence_sibling_groups: same process, same kind of event)",
    };
  }

  return result;
}

export function scoreFiles(
  truthPath: string,
  reportPaths: readonly string[],
): ScoreBatchResult {
  const truth = loadJsonText(fs.readFileSync(truthPath, "utf8"));
  const reports: ScoreReportResult[] = [];
  for (const reportPath of reportPaths) {
    const scored = scoreReport(truth, loadJsonText(fs.readFileSync(reportPath, "utf8")));
    scored.report = String(reportPath);
    reports.push(scored);
  }
  const caseId = isPlainRecord(truth) ? (truth.case_id ?? null) : null;
  return {
    schema_version: SCORER_SCHEMA_VERSION,
    case_id: caseId,
    reports,
  };
}

export interface IntelIndicatorDoc {
  readonly id: string;
  readonly indicator: {
    readonly type: string;
    readonly value: string;
  };
}

/**
 * Derive `evidence_frame_groups` and `evidence_intel_groups` per fact matching
 * `scenario.py:1235-1249` (listing each `ioc-*` in at most one group — the first
 * group of the fact whose sessions carry that indicator).
 */
export function deriveAlternativeGroups(params: {
  readonly facts: ReadonlyArray<{
    readonly fact_id: string;
    readonly entities: Record<string, readonly string[]>;
  }>;
  readonly groupSessionsByFact: Readonly<Record<string, ReadonlyArray<readonly number[]>>>;
  readonly sessionFrames: Readonly<Record<number, readonly number[]>>;
  readonly sessionValues: Readonly<Record<number, ReadonlySet<string> | readonly string[]>>;
  readonly intelDocs: readonly IntelIndicatorDoc[];
}): Record<
  string,
  { evidence_frame_groups: string[][]; evidence_intel_groups: string[][] }
> {
  const recordsByIndicator = new Map<string, string[]>();
  for (const doc of params.intelDocs) {
    if (doc.indicator.type === "domain" || doc.indicator.type === "ip") {
      const key = doc.indicator.value.toLowerCase();
      const bucket = recordsByIndicator.get(key) ?? [];
      bucket.push(doc.id);
      recordsByIndicator.set(key, bucket);
    }
  }

  const out: Record<
    string,
    { evidence_frame_groups: string[][]; evidence_intel_groups: string[][] }
  > = {};

  for (const fact of params.facts) {
    const named = new Set<string>();
    for (const key of ["domains", "ips"]) {
      for (const val of fact.entities[key] ?? []) {
        named.add(val.toLowerCase());
      }
    }
    const frameGroups: string[][] = [];
    const intelGroups: string[][] = [];
    const listed = new Set<string>();

    for (const sessions of params.groupSessionsByFact[fact.fact_id] ?? []) {
      const frameNums = new Set<number>();
      const sessionVals = new Set<string>();
      for (const sessionIdx of sessions) {
        for (const num of params.sessionFrames[sessionIdx] ?? []) {
          frameNums.add(num);
        }
        for (const v of params.sessionValues[sessionIdx] ?? []) {
          sessionVals.add(v.toLowerCase());
        }
      }
      const sortedFrames = [...frameNums].sort((a, b) => a - b).map((n) => `frame-${n}`);
      frameGroups.push(sortedFrames);

      const ids = new Set<string>();
      for (const val of named) {
        if (sessionVals.has(val)) {
          for (const recId of recordsByIndicator.get(val) ?? []) {
            if (!listed.has(recId)) {
              ids.add(recId);
            }
          }
        }
      }
      for (const id of ids) {
        listed.add(id);
      }
      intelGroups.push([...ids].sort(compareLexicographic));
    }

    out[fact.fact_id] = {
      evidence_frame_groups: frameGroups,
      evidence_intel_groups: intelGroups,
    };
  }

  return out;
}

/**
 * Derive `evidence_sibling_groups` per fact matching `scenario.py:1251-1272`.
 */
export function deriveSiblingGroups(params: {
  readonly facts: ReadonlyArray<{ readonly fact_id: string; readonly kind: string }>;
  readonly groupSeqsByFact: Readonly<Record<string, ReadonlyArray<readonly number[]>>>;
  readonly startedProcessBySeq: Readonly<Record<number, string>>;
  readonly processCategorySeqs: ReadonlyArray<{
    readonly processEntityId: string;
    readonly category: string;
    readonly seqs: readonly number[];
  }>;
  readonly eventIdsBySeq: Readonly<Record<number, string>>;
}): Record<string, string[][]> {
  const accepted = new Set<number>();
  for (const groups of Object.values(params.groupSeqsByFact)) {
    for (const seqs of groups) {
      for (const seq of seqs) {
        accepted.add(seq);
      }
    }
  }

  const lineage = new Set<string>();
  for (const fact of params.facts) {
    if (fact.kind !== "attack") {
      continue;
    }
    for (const seqs of params.groupSeqsByFact[fact.fact_id] ?? []) {
      for (const seq of seqs) {
        const proc = params.startedProcessBySeq[seq];
        if (proc !== undefined) {
          lineage.add(proc);
        }
      }
    }
  }

  const keySeqsMap = new Map<string, readonly number[]>();
  const keyOfSeq = new Map<number, string>();
  for (const bucket of params.processCategorySeqs) {
    if (!lineage.has(bucket.processEntityId)) {
      continue;
    }
    const key = `${bucket.processEntityId}\0${bucket.category}`;
    keySeqsMap.set(key, bucket.seqs);
    for (const seq of bucket.seqs) {
      if (accepted.has(seq)) {
        keyOfSeq.set(seq, key);
      }
    }
  }

  const candidates = new Map<string, Set<number>[]>();
  const counts = new Map<number, number>();

  for (const fact of params.facts) {
    const groups = params.groupSeqsByFact[fact.fact_id] ?? [];
    const factCandidates: Set<number>[] = groups.map((seqs) => {
      if (fact.kind !== "attack") {
        return new Set<number>();
      }
      const sibs = new Set<number>();
      for (const seq of seqs) {
        const key = keyOfSeq.get(seq);
        if (key !== undefined) {
          for (const sibling of keySeqsMap.get(key) ?? []) {
            if (!accepted.has(sibling)) {
              sibs.add(sibling);
            }
          }
        }
      }
      for (const s of sibs) {
        counts.set(s, (counts.get(s) ?? 0) + 1);
      }
      return sibs;
    });
    candidates.set(fact.fact_id, factCandidates);
  }

  const result: Record<string, string[][]> = {};
  for (const fact of params.facts) {
    const factCandidates = candidates.get(fact.fact_id) ?? [];
    result[fact.fact_id] = factCandidates.map((siblings) =>
      [...siblings]
        .filter((seq) => counts.get(seq) === 1)
        .map((seq) => params.eventIdsBySeq[seq]!)
        .sort(compareLexicographic),
    );
  }
  return result;
}
