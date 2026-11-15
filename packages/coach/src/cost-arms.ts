import fs from "node:fs";
import path from "node:path";
import {
  MODEL_PRICE_TABLE,
  normalizeModelPricingId,
  type BillingMode,
  type ModelPriceEntry,
} from "@hunt-command/shared";
import { compareLexicographic } from "./scorer.ts";
import { sha256File, sha256Hex } from "./review-reports.ts";

export const DEFAULT_COST_CASES = [
  "team-med-011",
  "team-med-012",
  "team-med-013",
  "team-med-014",
  "team-med-015",
] as const;

export const DEFAULT_BASELINE_ARM = "K6" as const;
export const ARM_LABEL_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/;
export const FACT_MARGIN = 1 as const;

export const USAGE_KEYS = [
  "input_tokens",
  "output_tokens",
  "cache_read_tokens",
  "cache_write_tokens",
  "total_tokens",
] as const;

export const TOKEN_TYPES = {
  uncached_input: "input",
  cache_read: "cache_read",
  cache_write: "cache_write",
  output: "output",
} as const;

export type PricedTokenKind = keyof typeof TOKEN_TYPES;
export type TokenBucketKey = PricedTokenKind | "total";
export const ALL_TOKEN_BUCKET_KEYS: readonly TokenBucketKey[] = [
  "uncached_input",
  "cache_read",
  "cache_write",
  "output",
  "total",
];

export const PRICE_KEYS = ["input", "output", "cache_read", "cache_write"] as const;
export type PriceRateKey = (typeof PRICE_KEYS)[number];

function absBigInt(n: bigint): bigint {
  return n < 0n ? -n : n;
}

function gcdBigInt(a: bigint, b: bigint): bigint {
  let x = absBigInt(a);
  let y = absBigInt(b);
  while (y !== 0n) {
    const r = x % y;
    x = y;
    y = r;
  }
  return x === 0n ? 1n : x;
}

function pow10BigInt(exp: number): bigint {
  if (!Number.isInteger(exp) || exp < 0) {
    throw new RangeError(`Exponent must be a non-negative integer, got ${exp}`);
  }
  return 10n ** BigInt(exp);
}

/**
 * Exact arbitrary-precision rational value `numerator / denominator` backed by `BigInt`.
 */
export class BigRational {
  public readonly numerator: bigint;
  public readonly denominator: bigint;

  public static readonly ZERO = new BigRational(0n, 1n);
  public static readonly ONE = new BigRational(1n, 1n);
  public static readonly MILLION = new BigRational(1_000_000n, 1n);

  public constructor(numerator: bigint, denominator: bigint = 1n) {
    if (denominator === 0n) {
      throw new RangeError("BigRational denominator cannot be zero");
    }
    const sign = denominator < 0n ? -1n : 1n;
    const normNum = numerator * sign;
    const normDen = denominator * sign;
    if (normNum === 0n) {
      this.numerator = 0n;
      this.denominator = 1n;
      return;
    }
    const g = gcdBigInt(normNum, normDen);
    this.numerator = normNum / g;
    this.denominator = normDen / g;
  }

  public static fromInt(value: bigint | number): BigRational {
    if (typeof value === "bigint") {
      return new BigRational(value, 1n);
    }
    if (!Number.isInteger(value)) {
      throw new RangeError(`Expected integer for BigRational.fromInt, got ${value}`);
    }
    return new BigRational(BigInt(value), 1n);
  }

  public static fromFraction(
    numerator: bigint | number,
    denominator: bigint | number,
  ): BigRational {
    const num = typeof numerator === "bigint" ? numerator : BigInt(numerator);
    const den = typeof denominator === "bigint" ? denominator : BigInt(denominator);
    return new BigRational(num, den);
  }

  public static fromDecimal(value: string | number | bigint): BigRational {
    if (typeof value === "bigint") {
      return new BigRational(value, 1n);
    }
    if (typeof value === "number") {
      if (!Number.isFinite(value)) {
        throw new RangeError(`Non-finite number in BigRational.fromDecimal: ${value}`);
      }
      return BigRational.fromDecimal(value.toString());
    }

    const trimmed = value.trim();
    const match = /^([+-])?(?:(\d+)(?:\.(\d*))?|\.(\d+))(?:[eE]([+-]?\d+))?$/.exec(trimmed);
    if (!match) {
      throw new SyntaxError(`Invalid decimal string for BigRational: '${value}'`);
    }
    const sign = match[1] === "-" ? -1n : 1n;
    const intPart = match[2] ?? "0";
    const fracPart = match[3] ?? match[4] ?? "";
    const exp = match[5] !== undefined ? Number.parseInt(match[5], 10) : 0;

    const digits = `${intPart}${fracPart}`.replace(/^0+(?=\d)/, "") || "0";
    const rawInt = sign * BigInt(digits);
    const netScale = exp - fracPart.length;

    if (netScale >= 0) {
      return new BigRational(rawInt * pow10BigInt(netScale), 1n);
    }
    return new BigRational(rawInt, pow10BigInt(-netScale));
  }

  public add(other: BigRational): BigRational {
    return new BigRational(
      this.numerator * other.denominator + other.numerator * this.denominator,
      this.denominator * other.denominator,
    );
  }

  public sub(other: BigRational): BigRational {
    return new BigRational(
      this.numerator * other.denominator - other.numerator * this.denominator,
      this.denominator * other.denominator,
    );
  }

  public mul(other: BigRational): BigRational {
    return new BigRational(
      this.numerator * other.numerator,
      this.denominator * other.denominator,
    );
  }

  public div(other: BigRational): BigRational {
    if (other.numerator === 0n) {
      throw new RangeError("Division by zero BigRational");
    }
    return new BigRational(
      this.numerator * other.denominator,
      this.denominator * other.numerator,
    );
  }

  public compare(other: BigRational): -1 | 0 | 1 {
    const lhs = this.numerator * other.denominator;
    const rhs = other.numerator * this.denominator;
    return lhs < rhs ? -1 : lhs > rhs ? 1 : 0;
  }

  public lt(other: BigRational): boolean {
    return this.compare(other) < 0;
  }

  public lte(other: BigRational): boolean {
    return this.compare(other) <= 0;
  }

  public gt(other: BigRational): boolean {
    return this.compare(other) > 0;
  }

  public gte(other: BigRational): boolean {
    return this.compare(other) >= 0;
  }

  public eq(other: BigRational): boolean {
    return this.compare(other) === 0;
  }

  public equals(other: BigRational): boolean {
    return this.eq(other);
  }

  public isNegative(): boolean {
    return this.numerator < 0n;
  }

  public isZero(): boolean {
    return this.numerator === 0n;
  }

  /**
   * Exact BigInt round-half-to-even decimal rounding (matches Python `round(Fraction, digits)`).
   */
  public toRoundedNumber(digits: number): number {
    const scale = pow10BigInt(digits);
    const negative = this.numerator < 0n;
    const scaledNum = absBigInt(this.numerator) * scale;
    let quotient = scaledNum / this.denominator;
    const remainder = scaledNum % this.denominator;
    const twiceRem = remainder * 2n;

    if (
      twiceRem > this.denominator ||
      (twiceRem === this.denominator && quotient % 2n === 1n)
    ) {
      quotient += 1n;
    }

    const signedStr = quotient.toString(10).padStart(digits + 1, "0");
    const formatted =
      digits === 0
        ? signedStr
        : `${signedStr.slice(0, signedStr.length - digits)}.${signedStr.slice(signedStr.length - digits)}`;
    const num = Number(negative && quotient !== 0n ? `-${formatted}` : formatted);
    return Object.is(num, -0) ? 0 : num;
  }

  public toFractionString(): string {
    return this.denominator === 1n
      ? this.numerator.toString(10)
      : `${this.numerator.toString(10)}/${this.denominator.toString(10)}`;
  }
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function parseNonNegativeInt(value: unknown): bigint | null {
  if (typeof value === "bigint") {
    return value >= 0n ? value : null;
  }
  if (typeof value === "number" && Number.isInteger(value) && value >= 0) {
    return BigInt(value);
  }
  return null;
}

export type BigTokenBucket = Record<TokenBucketKey, bigint>;

export interface TokenSplitInfo {
  readonly kind: "model" | "profile";
  readonly buckets: Record<string, BigTokenBucket>;
}

export interface ParsedTokenUsage {
  readonly types: BigTokenBucket | null;
  readonly split: TokenSplitInfo | null;
  readonly problem: string | null;
}

function parseBucketTypes(usage: Record<string, unknown>): {
  bucket: BigTokenBucket | null;
  error: string | null;
} {
  const absent: string[] = [];
  const parsedVals: Partial<Record<(typeof USAGE_KEYS)[number], bigint>> = {};

  for (const key of USAGE_KEYS) {
    const val = parseNonNegativeInt(usage[key]);
    if (val === null) {
      absent.push(key);
    } else {
      parsedVals[key] = val;
    }
  }

  if (absent.length > 0) {
    return { bucket: null, error: `usage lacks ${absent.join(", ")}` };
  }

  const inputTokens = parsedVals.input_tokens!;
  const outputTokens = parsedVals.output_tokens!;
  const cacheReadTokens = parsedVals.cache_read_tokens!;
  const cacheWriteTokens = parsedVals.cache_write_tokens!;
  const totalTokens = parsedVals.total_tokens!;

  const uncached = inputTokens - cacheReadTokens - cacheWriteTokens;
  if (uncached < 0n) {
    return {
      bucket: null,
      error: "input_tokens is below cache reads plus cache writes",
    };
  }

  return {
    bucket: {
      uncached_input: uncached,
      cache_read: cacheReadTokens,
      cache_write: cacheWriteTokens,
      output: outputTokens,
      total: totalTokens,
    },
    error: null,
  };
}

function parseSplitBuckets(
  raw: unknown,
  label: string,
): { buckets: Record<string, BigTokenBucket> | null; error: string | null } {
  if (!isPlainRecord(raw) || Object.keys(raw).length === 0) {
    return { buckets: null, error: `${label} must be a non-empty object` };
  }
  const buckets: Record<string, BigTokenBucket> = {};
  for (const [name, sub] of Object.entries(raw)) {
    if (!name.trim() || !isPlainRecord(sub)) {
      return { buckets: null, error: `${label}.${name} is malformed` };
    }
    const { bucket, error } = parseBucketTypes(sub);
    if (!bucket || error) {
      return { buckets: null, error: `${label}.${name}: ${error}` };
    }
    buckets[name.trim()] = bucket;
  }
  return { buckets, error: null };
}

/**
 * Exact BigInt validation of `uncached_input = input - cache_read - cache_write >= 0`,
 * `by_model`/`by_profile` bucket reconciliation, and `steps_without_usage === 0`.
 */
export function parseTokenTypes(usage: unknown): ParsedTokenUsage {
  if (!isPlainRecord(usage)) {
    return { types: null, split: null, problem: "no usage recorded" };
  }

  const { bucket: types, error } = parseBucketTypes(usage);
  if (!types || error) {
    return { types: null, split: null, problem: error };
  }

  let split: TokenSplitInfo | null = null;
  const splitFields = [
    ["by_model", "model"],
    ["by_profile", "profile"],
  ] as const;

  for (const [field, kind] of splitFields) {
    if (field in usage && usage[field] !== null && usage[field] !== undefined) {
      const { buckets, error: splitErr } = parseSplitBuckets(usage[field], field);
      if (!buckets || splitErr) {
        return { types, split: null, problem: splitErr };
      }
      for (const tkey of ALL_TOKEN_BUCKET_KEYS) {
        let sum = 0n;
        for (const b of Object.values(buckets)) {
          sum += b[tkey];
        }
        if (sum !== types[tkey]) {
          const label = tkey === "total" ? "total_tokens" : tkey;
          return {
            types,
            split: null,
            problem: `${field} ${label} does not match usage.${label}`,
          };
        }
      }
      split = { kind, buckets };
      break;
    }
  }

  const missingSteps = parseNonNegativeInt(usage.steps_without_usage);
  if (missingSteps === null) {
    return { types, split, problem: "steps_without_usage not recorded" };
  }
  if (missingSteps > 0n) {
    return {
      types,
      split,
      problem: `${missingSteps.toString(10)} steps without usage`,
    };
  }

  return { types, split, problem: null };
}

export interface ParsedHuntRecord {
  case: string;
  workflow: unknown;
  completed: boolean;
  halted_at: unknown;
  attack_found: bigint;
  attack_partial: bigint;
  attack_total: number | null;
  decoys_blamed: bigint;
  minutes: number | null;
  tokens: BigTokenBucket | null;
  token_split: TokenSplitInfo | null;
  usage_problem: string | null;
}

export function readHuntRecord(item: unknown, where: string): ParsedHuntRecord {
  if (!isPlainRecord(item)) {
    throw new Error(`${where}: a hunt must be a JSON object`);
  }
  const caseName = item.case;
  if (typeof caseName !== "string" || caseName.length === 0) {
    throw new Error(`${where}: case must be a non-empty string`);
  }
  const completed =
    item.completed === true && (item.halted_at === null || item.halted_at === undefined);
  const byKind = isPlainRecord(item.by_kind) ? item.by_kind : null;
  const attack = byKind && isPlainRecord(byKind.attack) ? byKind.attack : null;

  const attackFoundParsed = attack ? parseNonNegativeInt(attack.found) : null;
  if (completed && attackFoundParsed === null) {
    throw new Error(`${where}: completed hunt ${caseName} has no by_kind.attack.found`);
  }

  const decoysParsed = parseNonNegativeInt(item.decoys_blamed);
  if (completed && decoysParsed === null) {
    throw new Error(`${where}: completed hunt ${caseName} has no decoys_blamed`);
  }

  const attackPartialParsed = attack ? parseNonNegativeInt(attack.partial) : null;
  const attackTotalRaw = attack?.total;
  const attackTotal =
    typeof attackTotalRaw === "number" && Number.isInteger(attackTotalRaw) && attackTotalRaw >= 0
      ? attackTotalRaw
      : null;

  const minutesRaw = item.minutes_measured;
  const minutes =
    typeof minutesRaw === "number" && Number.isFinite(minutesRaw) ? minutesRaw : null;

  let { types: tokens, split: tokenSplit, problem } = parseTokenTypes(item.usage);
  if (
    tokenSplit === null &&
    typeof item.model === "string" &&
    item.model.trim().length > 0 &&
    tokens !== null
  ) {
    tokenSplit = {
      kind: "model",
      buckets: { [item.model.trim()]: { ...tokens } },
    };
  }

  return {
    case: caseName,
    workflow: item.workflow ?? null,
    completed,
    halted_at: item.halted_at ?? null,
    attack_found: attackFoundParsed ?? 0n,
    attack_partial: attackPartialParsed ?? 0n,
    attack_total: attackTotal,
    decoys_blamed: decoysParsed ?? 0n,
    minutes,
    tokens,
    token_split: tokenSplit,
    usage_problem: problem,
  };
}

export function readArmRecords(
  items: readonly unknown[],
  sourceLabel: string,
): Record<string, ParsedHuntRecord> {
  const hunts: Record<string, ParsedHuntRecord> = {};
  for (let i = 0; i < items.length; i++) {
    const hunt = readHuntRecord(items[i], `${sourceLabel}:${i + 1}`);
    if (hunt.case in hunts) {
      throw new Error(
        `${sourceLabel}:${i + 1}: ${hunt.case} appears twice; keep one hunt per case`,
      );
    }
    hunts[hunt.case] = hunt;
  }
  return hunts;
}

export function readArmFile(filePath: string): Record<string, ParsedHuntRecord> {
  const raw = fs.readFileSync(filePath, "utf8");
  const withoutBom = raw.charCodeAt(0) === 0xfeff ? raw.slice(1) : raw;
  const hunts: Record<string, ParsedHuntRecord> = {};
  const lines = withoutBom.split(/\r?\n/);

  for (let idx = 0; idx < lines.length; idx++) {
    const line = lines[idx]!;
    if (!line.trim()) {
      continue;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch (err) {
      throw new Error(`${filePath}:${idx + 1}: invalid JSON (${String(err)})`);
    }
    const hunt = readHuntRecord(parsed, `${filePath}:${idx + 1}`);
    if (hunt.case in hunts) {
      throw new Error(
        `${filePath}:${idx + 1}: ${hunt.case} appears twice; keep one hunt per case`,
      );
    }
    hunts[hunt.case] = hunt;
  }
  return hunts;
}

export type PriceRates = Record<PriceRateKey, number | null>;

export interface CostPriceTable {
  model: string;
  currency: string;
  source: string;
  per_million: PriceRates;
  models?: Record<string, PriceRates>;
  profiles?: Record<string, string>;
}

function validateRates(raw: unknown, where: string): PriceRates {
  if (!isPlainRecord(raw)) {
    throw new Error(`${where}: must have exactly ${PRICE_KEYS.join(", ")}`);
  }
  const keys = Object.keys(raw);
  if (
    keys.length !== PRICE_KEYS.length ||
    !PRICE_KEYS.every((k) => Object.prototype.hasOwnProperty.call(raw, k))
  ) {
    throw new Error(`${where}: must have exactly ${PRICE_KEYS.join(", ")}`);
  }

  const out = {} as PriceRates;
  for (const key of PRICE_KEYS) {
    const val = raw[key];
    if (val === null) {
      out[key] = null;
      continue;
    }
    if (typeof val !== "number" || !Number.isFinite(val) || val < 0) {
      throw new Error(`${where}.${key} must be a non-negative number or null`);
    }
    out[key] = val;
  }
  return out;
}

export function validatePriceTable(raw: unknown, where = "prices"): CostPriceTable {
  if (!isPlainRecord(raw)) {
    throw new Error(`${where}: the price table must be a JSON object`);
  }
  for (const req of ["model", "currency", "source"] as const) {
    if (typeof raw[req] !== "string" || !(raw[req] as string).trim()) {
      throw new Error(`${where}: ${req} must be a non-empty string`);
    }
  }

  const perMillion = validateRates(raw.per_million, `${where}: per_million`);
  const result: CostPriceTable = {
    model: (raw.model as string).trim(),
    currency: (raw.currency as string).trim(),
    source: (raw.source as string).trim(),
    per_million: perMillion,
  };

  if (raw.models !== undefined && raw.models !== null) {
    if (!isPlainRecord(raw.models)) {
      throw new Error(`${where}: models must be an object mapping model name to rates`);
    }
    const normalizedModels: Record<string, PriceRates> = {};
    for (const [name, entry] of Object.entries(raw.models)) {
      if (!name.trim() || !isPlainRecord(entry)) {
        throw new Error(`${where}: models.${name} must be an object`);
      }
      const entryKeys = Object.keys(entry);
      const inner =
        entryKeys.length === 1 && entryKeys[0] === "per_million" ? entry.per_million : entry;
      normalizedModels[name.trim()] = validateRates(inner, `${where}: models.${name}`);
    }
    result.models = normalizedModels;
  }

  if (raw.profiles !== undefined && raw.profiles !== null) {
    if (!isPlainRecord(raw.profiles)) {
      throw new Error(`${where}: profiles must map profile names to non-empty model strings`);
    }
    const knownModels = new Set<string>([
      result.model,
      ...Object.keys(result.models ?? {}),
    ]);
    const normalizedProfiles: Record<string, string> = {};
    const unknown = new Set<string>();
    for (const [prof, mod] of Object.entries(raw.profiles)) {
      if (!prof.trim() || typeof mod !== "string" || !mod.trim()) {
        throw new Error(`${where}: profiles must map profile names to non-empty model strings`);
      }
      const trimmedMod = mod.trim();
      if (!knownModels.has(trimmedMod)) {
        unknown.add(trimmedMod);
      }
      normalizedProfiles[prof.trim()] = trimmedMod;
    }
    if (unknown.size > 0) {
      throw new Error(
        `${where}: profiles references unknown model(s): ${[...unknown].sort(compareLexicographic).join(", ")}`,
      );
    }
    result.profiles = normalizedProfiles;
  }

  return result;
}

export function loadPricesFile(filePath: string): CostPriceTable {
  const raw = fs.readFileSync(filePath, "utf8");
  const withoutBom = raw.charCodeAt(0) === 0xfeff ? raw.slice(1) : raw;
  return validatePriceTable(JSON.parse(withoutBom), filePath);
}

function sharedEntryToRates(entry: ModelPriceEntry): PriceRates {
  return {
    input: entry.inputPerMillionUsd,
    output: entry.outputPerMillionUsd,
    cache_read: entry.cacheReadPerMillionUsd,
    cache_write: entry.cacheWritePerMillionUsd,
  };
}

/**
 * Construct a multi-model `CostPriceTable` directly from `@hunt-command/shared`
 * `MODEL_PRICE_TABLE` for `$0` OAuth vs API shadow cost evaluation.
 */
export function buildSharedModelPriceTable(options?: {
  readonly defaultModel?: string;
  readonly profiles?: Readonly<Record<string, string>>;
}): CostPriceTable {
  const models: Record<string, PriceRates> = {};
  for (const [name, entry] of Object.entries(MODEL_PRICE_TABLE)) {
    models[name] = sharedEntryToRates(entry);
  }
  // Ensure common live @oh-my-pi Opus/Codex/Gemini aliases resolve cleanly alongside shared entries
  if (!models["claude-opus-4-7"] && models["claude-opus-4-6"]) {
    models["claude-opus-4-7"] = { ...models["claude-opus-4-6"] };
  }
  if (!models["gpt-5.3-codex"] && models["gpt-5.4"]) {
    models["gpt-5.3-codex"] = { ...models["gpt-5.4"] };
  }
  if (!models["gemini-3.1-pro"] && models["gemini-3-pro"]) {
    models["gemini-3.1-pro"] = { ...models["gemini-3-pro"] };
  }

  const rawDefaultModel = options?.defaultModel ?? "claude-sonnet-5";
  const normalizedDefault = normalizeModelPricingId(rawDefaultModel);
  const defaultRates = models[rawDefaultModel] ?? models[normalizedDefault];
  if (!defaultRates) {
    throw new Error(`Default model '${rawDefaultModel}' is not in MODEL_PRICE_TABLE`);
  }
  const effectiveDefaultModel =
    rawDefaultModel in models ? rawDefaultModel : normalizedDefault;

  return validatePriceTable({
    model: effectiveDefaultModel,
    currency: "USD",
    source: "@hunt-command/shared MODEL_PRICE_TABLE",
    per_million: { ...defaultRates },
    models,
    ...(options?.profiles ? { profiles: { ...options.profiles } } : {}),
  });
}

export interface G41CompletenessResult {
  goal: string;
  expected_hunts: number;
  complete_hunts: number;
  missing: Array<{ arm: string; case: string }>;
  incomplete: Array<{ arm: string; case: string; workflow: unknown; halted_at: unknown }>;
  usage_missing: Array<{ arm: string; case: string; workflow: unknown; problem: string }>;
  ignored_not_in_cases: Array<{ arm: string; case: string }>;
  pass: boolean;
}

export function completeness(
  arms: Readonly<Record<string, Readonly<Record<string, ParsedHuntRecord>>>>,
  cases: readonly string[],
): G41CompletenessResult {
  const caseSet = new Set<string>(cases);
  const missing: G41CompletenessResult["missing"] = [];
  const incomplete: G41CompletenessResult["incomplete"] = [];
  const unmetered: G41CompletenessResult["usage_missing"] = [];
  const extra: G41CompletenessResult["ignored_not_in_cases"] = [];
  let ready = 0;

  for (const [arm, hunts] of Object.entries(arms)) {
    for (const c of Object.keys(hunts)) {
      if (!caseSet.has(c)) {
        extra.push({ arm, case: c });
      }
    }
    for (const c of cases) {
      const hunt = hunts[c];
      if (!hunt) {
        missing.push({ arm, case: c });
        continue;
      }
      if (!hunt.completed) {
        incomplete.push({
          arm,
          case: c,
          workflow: hunt.workflow,
          halted_at: hunt.halted_at,
        });
      }
      if (hunt.usage_problem) {
        unmetered.push({
          arm,
          case: c,
          workflow: hunt.workflow,
          problem: hunt.usage_problem,
        });
      }
      if (hunt.completed && !hunt.usage_problem) {
        ready++;
      }
    }
  }

  const expected = Object.keys(arms).length * cases.length;
  return {
    goal: "Complete data: every case has a completed hunt in every arm, usage recorded for every step",
    expected_hunts: expected,
    complete_hunts: ready,
    missing,
    incomplete,
    usage_missing: unmetered,
    ignored_not_in_cases: extra,
    pass: expected > 0 && ready === expected,
  };
}

function meanBigInt(values: readonly bigint[]): BigRational | null {
  if (values.length === 0) {
    return null;
  }
  const sum = values.reduce((acc, v) => acc + v, 0n);
  return new BigRational(sum, BigInt(values.length));
}

function resolveHuntModels(
  hunt: ParsedHuntRecord,
  prices: CostPriceTable | null,
): Record<string, BigTokenBucket> | null {
  const split = hunt.token_split;
  if (!split) {
    return null;
  }
  if (split.kind === "model") {
    return split.buckets;
  }
  const profileMap = prices?.profiles ?? {};
  const defaultModel = prices?.model ?? "default";
  const merged: Record<string, BigTokenBucket> = {};

  for (const [profile, tok] of Object.entries(split.buckets)) {
    const model = profileMap[profile] ?? defaultModel;
    let dst = merged[model];
    if (!dst) {
      dst = {
        uncached_input: 0n,
        cache_read: 0n,
        cache_write: 0n,
        output: 0n,
        total: 0n,
      };
      merged[model] = dst;
    }
    for (const k of ALL_TOKEN_BUCKET_KEYS) {
      dst[k] += tok[k];
    }
  }
  return merged;
}

export interface ArmExactRationals {
  found: BigRational | null;
  tokens: Record<TokenBucketKey, BigRational> | null;
  by_model: Record<string, Record<TokenBucketKey, BigRational>> | null;
  cost: BigRational | null;
  cache_savings: BigRational | null;
}

export interface ArmSummaryStats {
  hunts: number;
  mean_attack_found: number | null;
  mean_attack_partial: number | null;
  halts: number;
  decoys_blamed_total: number;
  decoys_blamed_max: number;
  mean_minutes: number | null;
  mean_tokens: Record<TokenBucketKey, number> | null;
  mean_tokens_by_model?: Record<string, Record<TokenBucketKey, number>>;
  tokens_unknown_because: string | null;
}

interface InternalArmStats extends ArmSummaryStats {
  _exact: ArmExactRationals;
}

function computeArmStats(
  hunts: readonly ParsedHuntRecord[],
  prices: CostPriceTable | null,
): InternalArmStats {
  const found = meanBigInt(hunts.map((h) => h.attack_found));
  const partial = meanBigInt(hunts.map((h) => h.attack_partial));
  const minutes = hunts.map((h) => h.minutes).filter((m): m is number => m !== null);
  const metered = hunts.every((h) => h.tokens !== null && h.usage_problem === null);

  let tokensExact: Record<TokenBucketKey, BigRational> | null = null;
  if (hunts.length > 0 && metered) {
    tokensExact = {} as Record<TokenBucketKey, BigRational>;
    for (const kind of ALL_TOKEN_BUCKET_KEYS) {
      tokensExact[kind] = meanBigInt(hunts.map((h) => h.tokens![kind]))!;
    }
  }

  let byModelExact: Record<string, Record<TokenBucketKey, BigRational>> | null = null;
  if (hunts.length > 0 && metered && hunts.some((h) => h.token_split !== null)) {
    const defaultModel = prices?.model ?? "default";
    const perHunt = hunts.map(
      (h) => resolveHuntModels(h, prices) ?? { [defaultModel]: h.tokens! },
    );
    const modelSet = new Set<string>();
    for (const item of perHunt) {
      for (const m of Object.keys(item)) {
        modelSet.add(m);
      }
    }
    const sortedModels = [...modelSet].sort(compareLexicographic);
    byModelExact = {};
    for (const m of sortedModels) {
      const bucket = {} as Record<TokenBucketKey, BigRational>;
      for (const kind of ALL_TOKEN_BUCKET_KEYS) {
        const sum = perHunt.reduce((acc, item) => acc + (item[m]?.[kind] ?? 0n), 0n);
        bucket[kind] = new BigRational(sum, BigInt(hunts.length));
      }
      byModelExact[m] = bucket;
    }
  }

  const decoys = hunts.map((h) => Number(h.decoys_blamed));
  const decoysTotal = decoys.reduce((acc, v) => acc + v, 0);
  const decoysMax = decoys.length > 0 ? Math.max(...decoys) : 0;
  const meanMinutes =
    minutes.length > 0
      ? Math.round((minutes.reduce((a, b) => a + b, 0) / minutes.length) * 100) / 100
      : null;

  const meanTokensOut =
    tokensExact === null
      ? null
      : (Object.fromEntries(
          ALL_TOKEN_BUCKET_KEYS.map((k) => [k, tokensExact[k].toRoundedNumber(1)]),
        ) as Record<TokenBucketKey, number>);

  const out: InternalArmStats = {
    hunts: hunts.length,
    mean_attack_found: found ? found.toRoundedNumber(4) : null,
    mean_attack_partial: partial ? partial.toRoundedNumber(4) : null,
    halts: hunts.filter((h) => !h.completed).length,
    decoys_blamed_total: decoysTotal,
    decoys_blamed_max: decoysMax,
    mean_minutes: meanMinutes,
    mean_tokens: meanTokensOut,
    tokens_unknown_because:
      tokensExact !== null || hunts.length === 0
        ? null
        : "a paired hunt has incomplete usage",
    _exact: {
      found,
      tokens: tokensExact,
      by_model: byModelExact,
      cost: null,
      cache_savings: null,
    },
  };

  if (byModelExact !== null) {
    out.mean_tokens_by_model = Object.fromEntries(
      Object.entries(byModelExact).map(([m, tok]) => [
        m,
        Object.fromEntries(
          ALL_TOKEN_BUCKET_KEYS.map((k) => [k, tok[k].toRoundedNumber(1)]),
        ) as Record<TokenBucketKey, number>,
      ]),
    );
  }

  return out;
}

function ratesForModel(
  prices: CostPriceTable,
  model: string,
): { rates: PriceRates | null; prefix: string } {
  if (prices.models && model in prices.models) {
    return { rates: prices.models[model]!, prefix: `${model}.` };
  }
  if (model === prices.model) {
    return { rates: prices.per_million, prefix: "" };
  }
  const normalized = normalizeModelPricingId(model);
  if (prices.models && normalized in prices.models) {
    return { rates: prices.models[normalized]!, prefix: `${model}.` };
  }
  if (normalized === prices.model) {
    return { rates: prices.per_million, prefix: "" };
  }
  return { rates: null, prefix: `${model}:` };
}

function priceBucketRational(
  tokens: Record<TokenBucketKey, BigRational>,
  rates: PriceRates,
): {
  byType: Record<PricedTokenKind, number | null>;
  total: number | null;
  totalExact: BigRational | null;
  cacheSavingsExact: BigRational | null;
} {
  const exactMap = {} as Record<PricedTokenKind, BigRational | null>;
  const byType = {} as Record<PricedTokenKind, number | null>;
  let allKnown = true;

  for (const [kind, rateKey] of Object.entries(TOKEN_TYPES) as Array<
    [PricedTokenKind, PriceRateKey]
  >) {
    const rateVal = rates[rateKey];
    if (rateVal === null) {
      exactMap[kind] = null;
      byType[kind] = null;
      allKnown = false;
    } else {
      const exactCost = tokens[kind]
        .mul(BigRational.fromDecimal(rateVal))
        .div(BigRational.MILLION);
      exactMap[kind] = exactCost;
      byType[kind] = exactCost.toRoundedNumber(6);
    }
  }

  let totalExact: BigRational | null = null;
  if (allKnown) {
    totalExact = BigRational.ZERO;
    for (const kind of Object.keys(TOKEN_TYPES) as PricedTokenKind[]) {
      totalExact = totalExact.add(exactMap[kind]!);
    }
  }

  let cacheSavingsExact: BigRational | null = null;
  if (rates.input !== null && rates.cache_read !== null) {
    const rateDelta = BigRational.fromDecimal(rates.input).sub(
      BigRational.fromDecimal(rates.cache_read),
    );
    const rawSavings = tokens.cache_read.mul(rateDelta).div(BigRational.MILLION);
    cacheSavingsExact = rawSavings.isNegative() ? BigRational.ZERO : rawSavings;
  }

  return {
    byType,
    total: totalExact ? totalExact.toRoundedNumber(6) : null,
    totalExact,
    cacheSavingsExact,
  };
}

export interface ArmPricedBreakdown {
  by_type: Record<PricedTokenKind, number | null> | null;
  by_model?: Record<
    string,
    {
      by_type: Record<PricedTokenKind, number | null> | null;
      total: number | null;
      reason?: string;
    }
  >;
  total: number | null;
  reason?: string;
}

export interface ArmOAuthShadowLedger {
  billing_mode: BillingMode;
  actual_billed_usd: number | null;
  actual_billed_rational: string | null;
  shadow_api_usd: number | null;
  shadow_api_rational: string | null;
  cache_savings_usd: number | null;
  cache_savings_rational: string | null;
}

export interface G43PricedResult {
  goal: string;
  table:
    | (CostPriceTable & {
        path: string;
        sha256: string;
      })
    | null;
  unpriced_rates?: string[];
  arms: Record<string, ArmPricedBreakdown>;
  oauth_vs_shadow: Record<string, ArmOAuthShadowLedger>;
  reason?: string;
  pass: boolean;
}

function priceArmsInternal(
  stats: Record<string, InternalArmStats>,
  prices: CostPriceTable | null,
  pricesMeta: { path: string; sha256: string } | null,
  billingMode: BillingMode,
): G43PricedResult {
  if (!prices) {
    return {
      goal: "Priced: cost of one hunt per arm by token type",
      table: null,
      arms: {},
      oauth_vs_shadow: {},
      reason: "no --prices table given",
      pass: false,
    };
  }

  const defaultRates = prices.per_million;
  const unpricedSeen: string[] = [];
  const armsOut: Record<string, ArmPricedBreakdown> = {};
  const oauthLedger: Record<string, ArmOAuthShadowLedger> = {};
  let usesDefault = false;

  for (const [arm, item] of Object.entries(stats)) {
    const tokens = item._exact.tokens;
    if (!tokens) {
      armsOut[arm] = { by_type: null, total: null, reason: "mean tokens unknown" };
      oauthLedger[arm] = {
        billing_mode: billingMode,
        actual_billed_usd: billingMode === "oauth_subscription" ? 0 : null,
        actual_billed_rational: billingMode === "oauth_subscription" ? "0" : null,
        shadow_api_usd: null,
        shadow_api_rational: null,
        cache_savings_usd: null,
        cache_savings_rational: null,
      };
      continue;
    }

    const byModel = item._exact.by_model;
    if (!byModel) {
      usesDefault = true;
      const priced = priceBucketRational(tokens, defaultRates);
      item._exact.cost = priced.totalExact;
      item._exact.cache_savings = priced.cacheSavingsExact;
      armsOut[arm] = { by_type: priced.byType, total: priced.total };
      oauthLedger[arm] = {
        billing_mode: billingMode,
        actual_billed_usd:
          billingMode === "oauth_subscription" ? 0 : priced.total,
        actual_billed_rational:
          billingMode === "oauth_subscription"
            ? "0"
            : (priced.totalExact?.toFractionString() ?? null),
        shadow_api_usd: priced.total,
        shadow_api_rational: priced.totalExact?.toFractionString() ?? null,
        cache_savings_usd: priced.cacheSavingsExact
          ? priced.cacheSavingsExact.toRoundedNumber(6)
          : null,
        cache_savings_rational: priced.cacheSavingsExact?.toFractionString() ?? null,
      };
      continue;
    }

    const modelCosts: NonNullable<ArmPricedBreakdown["by_model"]> = {};
    const sumByType: Record<PricedTokenKind, BigRational> = {
      uncached_input: BigRational.ZERO,
      cache_read: BigRational.ZERO,
      cache_write: BigRational.ZERO,
      output: BigRational.ZERO,
    };
    let sumCacheSavings = BigRational.ZERO;
    let ok = true;

    for (const [model, mtokens] of Object.entries(byModel)) {
      const { rates: mrates, prefix } = ratesForModel(prices, model);
      if (!mrates) {
        unpricedSeen.push(`${model}:unlisted`);
        modelCosts[model] = {
          by_type: null,
          total: null,
          reason: `model ${model} not in price table`,
        };
        ok = false;
        continue;
      }
      for (const key of PRICE_KEYS) {
        if (mrates[key] === null) {
          unpricedSeen.push(prefix ? `${prefix}${key}` : key);
        }
      }
      const mPriced = priceBucketRational(mtokens, mrates);
      modelCosts[model] = { by_type: mPriced.byType, total: mPriced.total };
      if (!mPriced.totalExact || !mPriced.cacheSavingsExact) {
        ok = false;
      } else {
        for (const [kind, rateKey] of Object.entries(TOKEN_TYPES) as Array<
          [PricedTokenKind, PriceRateKey]
        >) {
          sumByType[kind] = sumByType[kind].add(
            mtokens[kind]
              .mul(BigRational.fromDecimal(mrates[rateKey]!))
              .div(BigRational.MILLION),
          );
        }
        sumCacheSavings = sumCacheSavings.add(mPriced.cacheSavingsExact);
      }
    }

    if (ok) {
      let totalExact = BigRational.ZERO;
      for (const k of Object.keys(TOKEN_TYPES) as PricedTokenKind[]) {
        totalExact = totalExact.add(sumByType[k]);
      }
      item._exact.cost = totalExact;
      item._exact.cache_savings = sumCacheSavings;
      const totalRounded = totalExact.toRoundedNumber(6);
      armsOut[arm] = {
        by_type: Object.fromEntries(
          (Object.keys(TOKEN_TYPES) as PricedTokenKind[]).map((k) => [
            k,
            sumByType[k].toRoundedNumber(6),
          ]),
        ) as Record<PricedTokenKind, number>,
        by_model: modelCosts,
        total: totalRounded,
      };
      oauthLedger[arm] = {
        billing_mode: billingMode,
        actual_billed_usd: billingMode === "oauth_subscription" ? 0 : totalRounded,
        actual_billed_rational:
          billingMode === "oauth_subscription" ? "0" : totalExact.toFractionString(),
        shadow_api_usd: totalRounded,
        shadow_api_rational: totalExact.toFractionString(),
        cache_savings_usd: sumCacheSavings.toRoundedNumber(6),
        cache_savings_rational: sumCacheSavings.toFractionString(),
      };
    } else {
      armsOut[arm] = {
        by_type: {
          uncached_input: null,
          cache_read: null,
          cache_write: null,
          output: null,
        },
        by_model: modelCosts,
        total: null,
      };
      oauthLedger[arm] = {
        billing_mode: billingMode,
        actual_billed_usd: billingMode === "oauth_subscription" ? 0 : null,
        actual_billed_rational: billingMode === "oauth_subscription" ? "0" : null,
        shadow_api_usd: null,
        shadow_api_rational: null,
        cache_savings_usd: null,
        cache_savings_rational: null,
      };
    }
  }

  if (usesDefault) {
    for (const key of PRICE_KEYS) {
      if (defaultRates[key] === null) {
        unpricedSeen.push(key);
      }
    }
  }

  const unpriced = [...new Set(unpricedSeen)];
  const meta = pricesMeta ?? {
    path: "<in-memory>",
    sha256: sha256Hex(JSON.stringify(prices)),
  };

  return {
    goal: "Priced: cost of one hunt per arm by token type",
    table: {
      ...prices,
      path: meta.path,
      sha256: meta.sha256,
    },
    unpriced_rates: unpriced,
    arms: armsOut,
    oauth_vs_shadow: oauthLedger,
    pass:
      Object.keys(armsOut).length > 0 &&
      unpriced.length === 0 &&
      Object.values(armsOut).every((cost) => cost.total !== null),
  };
}

export interface G42RuleResult {
  goal: string;
  baseline?: string;
  attack_found_floor?: number | null;
  baseline_decoys_blamed_total?: number;
  ranked_by?: "mean_cost" | "mean_tokens";
  arms: Record<string, { qualifies: boolean; reasons: string[] }>;
  chosen: string | null;
  result: string;
  reason?: string;
  on_complete_data?: boolean;
  pass: boolean;
}

function applyRuleInternal(
  stats: Record<string, InternalArmStats>,
  order: readonly string[],
  baseline: string,
  paired: readonly string[],
): G42RuleResult {
  if (paired.length === 0) {
    return {
      goal: 'Rule applied: one chosen arm or "none qualifies"',
      chosen: null,
      result: "none qualifies",
      reason: "no case is present in every arm",
      arms: {},
      pass: false,
    };
  }

  const base = stats[baseline]!;
  const floor = base._exact.found!.sub(BigRational.fromInt(FACT_MARGIN));
  const verdicts: Record<string, { qualifies: boolean; reasons: string[] }> = {};
  const qualified: string[] = [];

  for (const arm of order) {
    const item = stats[arm]!;
    const reasons: string[] = [];
    if (item._exact.found!.lt(floor)) {
      const floorRounded = floor.toRoundedNumber(4);
      const floorText = Number.isInteger(floorRounded)
        ? `${floorRounded}.0`
        : String(floorRounded);
      reasons.push(
        `mean attack facts ${item.mean_attack_found} below ${floorText}`,
      );
    }
    if (item.halts > 0) {
      reasons.push(`${item.halts} halts`);
    }
    if (item.decoys_blamed_total > base.decoys_blamed_total) {
      reasons.push(
        `${item.decoys_blamed_total} decoys blamed, baseline ${base.decoys_blamed_total}`,
      );
    }
    if (item._exact.tokens === null) {
      reasons.push("mean tokens unknown: a paired hunt has incomplete usage");
    }
    verdicts[arm] = { qualifies: reasons.length === 0, reasons };
    if (reasons.length === 0) {
      qualified.push(arm);
    }
  }

  const rankByCost =
    qualified.some((a) => stats[a]!._exact.by_model !== null) &&
    qualified.every((a) => stats[a]!._exact.cost !== null);

  let chosen: string | null = null;
  if (qualified.length > 0) {
    const sortedQualified = [...qualified].sort((a, b) => {
      if (rankByCost) {
        const costCmp = stats[a]!._exact.cost!.compare(stats[b]!._exact.cost!);
        if (costCmp !== 0) return costCmp;
      }
      const tokCmp = stats[a]!._exact.tokens!.total.compare(
        stats[b]!._exact.tokens!.total,
      );
      if (tokCmp !== 0) return tokCmp;
      return order.indexOf(a) - order.indexOf(b);
    });
    chosen = sortedQualified[0] ?? null;
  }

  return {
    goal: 'Rule applied: one chosen arm or "none qualifies"',
    baseline,
    attack_found_floor: floor.toRoundedNumber(4),
    baseline_decoys_blamed_total: base.decoys_blamed_total,
    ranked_by: rankByCost ? "mean_cost" : "mean_tokens",
    arms: verdicts,
    chosen,
    result: chosen ?? "none qualifies",
    pass: true,
  };
}

export interface CostArmsEvaluationResult {
  schema_version: 1;
  cases: string[];
  baseline: string;
  fact_margin: typeof FACT_MARGIN;
  billing_mode: BillingMode;
  arms: Record<string, { rounds: string; rounds_sha256: string }>;
  paired_cases: string[];
  unpaired: Array<{ case: string; missing_from: string[] }>;
  per_arm: Record<string, ArmSummaryStats>;
  goals: {
    "G4.1": G41CompletenessResult;
    "G4.2": G42RuleResult;
    "G4.3": G43PricedResult;
  };
  notes: string[];
}

export interface CostArmInput {
  readonly label: string;
  readonly hunts?: readonly unknown[];
  readonly roundsPath?: string;
}

/**
 * Evaluate cost arms with exact `BigInt` rational arithmetic (`BigRational`),
 * enforcing `uncached_input >= 0`, `steps_without_usage === 0`, G4.1/G4.2/G4.3,
 * and `$0` OAuth subscription vs API-equivalent shadow cost breakdown.
 */
export function costArms(params: {
  readonly arms: readonly CostArmInput[];
  readonly cases?: readonly string[];
  readonly baseline?: string;
  readonly prices?: CostPriceTable | null;
  readonly pricesPath?: string;
  readonly billingMode?: BillingMode;
  readonly outPath?: string;
}): CostArmsEvaluationResult {
  const order = params.arms.map((a) => a.label);
  if (order.length === 0) {
    throw new Error("costArms requires at least one arm");
  }
  const seenLabels = new Set<string>();
  for (const label of order) {
    if (!ARM_LABEL_RE.test(label)) {
      throw new Error(`Invalid arm label '${label}'`);
    }
    if (seenLabels.has(label)) {
      throw new Error("each arm label must be different");
    }
    seenLabels.add(label);
  }

  const baseline = params.baseline ?? DEFAULT_BASELINE_ARM;
  if (!seenLabels.has(baseline)) {
    throw new Error(
      `baseline ${baseline} is not one of the arms (${order.join(", ")})`,
    );
  }

  const dedupCases = [...new Set(params.cases ?? DEFAULT_COST_CASES)].filter(
    (c) => c.trim().length > 0,
  );
  if (dedupCases.length === 0) {
    throw new Error("cases names no case");
  }

  const parsedArms: Record<string, Record<string, ParsedHuntRecord>> = {};
  const armMeta: Record<string, { rounds: string; rounds_sha256: string }> = {};

  for (const armInput of params.arms) {
    if (armInput.roundsPath !== undefined) {
      parsedArms[armInput.label] = readArmFile(armInput.roundsPath);
      armMeta[armInput.label] = {
        rounds: armInput.roundsPath,
        rounds_sha256: sha256File(armInput.roundsPath),
      };
    } else if (armInput.hunts !== undefined) {
      parsedArms[armInput.label] = readArmRecords(armInput.hunts, armInput.label);
      armMeta[armInput.label] = {
        rounds: `<in-memory:${armInput.label}>`,
        rounds_sha256: sha256Hex(JSON.stringify(armInput.hunts)),
      };
    } else {
      throw new Error(`Arm '${armInput.label}' must provide either hunts or roundsPath`);
    }
  }

  let prices: CostPriceTable | null = null;
  let pricesMeta: { path: string; sha256: string } | null = null;
  if (params.pricesPath !== undefined) {
    prices = loadPricesFile(params.pricesPath);
    pricesMeta = {
      path: params.pricesPath,
      sha256: sha256File(params.pricesPath),
    };
  } else if (params.prices !== undefined && params.prices !== null) {
    prices = validatePriceTable(params.prices);
    pricesMeta = {
      path: "<in-memory>",
      sha256: sha256Hex(JSON.stringify(prices)),
    };
  }

  const paired = dedupCases.filter((c) =>
    order.every((arm) => c in parsedArms[arm]!),
  );
  const unpaired = dedupCases
    .filter((c) => !paired.includes(c))
    .map((c) => ({
      case: c,
      missing_from: order.filter((arm) => !(c in parsedArms[arm]!)),
    }));

  const internalStats: Record<string, InternalArmStats> = {};
  for (const arm of order) {
    const pairedHunts = paired.map((c) => parsedArms[arm]![c]!);
    internalStats[arm] = computeArmStats(pairedHunts, prices);
  }

  const billingMode: BillingMode = params.billingMode ?? "oauth_subscription";
  const g41 = completeness(parsedArms, dedupCases);
  const g43 = priceArmsInternal(internalStats, prices, pricesMeta, billingMode);
  const g42 = applyRuleInternal(internalStats, order, baseline, paired);
  g42.on_complete_data = g41.pass;

  const multi = Object.values(internalStats).some(
    (s) => s.mean_tokens_by_model !== undefined,
  );

  const publicStats: Record<string, ArmSummaryStats> = {};
  for (const [arm, st] of Object.entries(internalStats)) {
    const { _exact: _ignored, ...rest } = st;
    publicStats[arm] = rest;
  }

  const splitNote = multi
    ? "Split usage is priced per model/profile bucket via models/profiles."
    : "Usage is not split by model; every token is priced at the table's one model.";

  const result: CostArmsEvaluationResult = {
    schema_version: 1,
    cases: dedupCases,
    baseline,
    fact_margin: FACT_MARGIN,
    billing_mode: billingMode,
    arms: armMeta,
    paired_cases: paired,
    unpaired,
    per_arm: publicStats,
    goals: {
      "G4.1": g41,
      "G4.2": g42,
      "G4.3": g43,
    },
    notes: [
      'input_tokens include cache reads and writes; uncached_input is the rest, priced at "input".',
      splitNote,
      billingMode === "oauth_subscription"
        ? "OAuth subscription mode bills $0.00 actual cost while tracking exact API-equivalent shadow cost and cache read savings."
        : "API-key mode bills API-equivalent list cost.",
    ],
  };

  if (params.outPath !== undefined) {
    fs.mkdirSync(path.dirname(params.outPath), { recursive: true });
    fs.writeFileSync(params.outPath, `${JSON.stringify(result, null, 2)}\n`, "utf8");
  }

  return result;
}

export function formatCostArmsTable(result: CostArmsEvaluationResult): string {
  const costs = result.goals["G4.3"].arms;
  const currency = result.goals["G4.3"].table?.currency ?? "";
  const lines: string[] = [
    `${"arm".padEnd(6)} ${"hunts".padStart(5)} ${"attack".padStart(7)} ${"tokens/hunt".padStart(12)} ${"halts".padStart(5)} ${"decoys".padStart(6)} ${"minutes".padStart(7)} ${"cost/hunt".padStart(12)}`,
  ];

  for (const [arm, item] of Object.entries(result.per_arm)) {
    const tokens = item.mean_tokens?.total ?? null;
    const rawCost = costs[arm]?.total ?? null;
    const costStr =
      rawCost === null ? "-" : `${rawCost.toFixed(2)} ${currency}`.trim();
    const attackStr =
      item.mean_attack_found === null ? "-" : item.mean_attack_found.toFixed(2);
    const tokStr =
      tokens === null ? "-" : Math.round(tokens).toLocaleString("en-US");
    const minStr =
      item.mean_minutes === null ? "-" : item.mean_minutes.toFixed(1);

    lines.push(
      `${arm.padEnd(6)} ${String(item.hunts).padStart(5)} ${attackStr.padStart(7)} ${tokStr.padStart(12)} ${String(item.halts).padStart(5)} ${String(item.decoys_blamed_total).padStart(6)} ${minStr.padStart(7)} ${costStr.padStart(12)}`,
    );
  }

  const unpairedStr =
    result.unpaired.length > 0
      ? result.unpaired.map((u) => u.case).join(", ")
      : "none";
  lines.push(`paired cases ${result.paired_cases.length}; unpaired ${unpairedStr}`);
  lines.push(`chosen: ${result.goals["G4.2"].result}`);
  for (const key of ["G4.1", "G4.2", "G4.3"] as const) {
    lines.push(`${key} ${result.goals[key].pass ? "pass" : "FAIL"}`);
  }
  return lines.join("\n");
}
