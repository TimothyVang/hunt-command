export interface ModelPriceEntry {
  inputPerMillionUsd: number;
  outputPerMillionUsd: number;
  cacheReadPerMillionUsd: number;
  cacheWritePerMillionUsd: number;
}

export const MODEL_PRICE_TABLE: Readonly<Record<string, ModelPriceEntry>> = {
  "claude-opus-4-6": {
    inputPerMillionUsd: 15.0,
    outputPerMillionUsd: 75.0,
    cacheReadPerMillionUsd: 1.5,
    cacheWritePerMillionUsd: 18.75,
  },
  "claude-opus-5-5": {
    inputPerMillionUsd: 15.0,
    outputPerMillionUsd: 75.0,
    cacheReadPerMillionUsd: 1.5,
    cacheWritePerMillionUsd: 18.75,
  },
  "claude-sonnet-4-6": {
    inputPerMillionUsd: 3.0,
    outputPerMillionUsd: 15.0,
    cacheReadPerMillionUsd: 0.3,
    cacheWritePerMillionUsd: 3.75,
  },
  "claude-sonnet-5": {
    inputPerMillionUsd: 3.0,
    outputPerMillionUsd: 15.0,
    cacheReadPerMillionUsd: 0.3,
    cacheWritePerMillionUsd: 3.75,
  },
  "claude-haiku-4-5": {
    inputPerMillionUsd: 0.8,
    outputPerMillionUsd: 4.0,
    cacheReadPerMillionUsd: 0.08,
    cacheWritePerMillionUsd: 1.0,
  },
  "gpt-5": {
    inputPerMillionUsd: 2.5,
    outputPerMillionUsd: 10.0,
    cacheReadPerMillionUsd: 0.25,
    cacheWritePerMillionUsd: 0.0,
  },
  "gpt-5.4": {
    inputPerMillionUsd: 2.5,
    outputPerMillionUsd: 10.0,
    cacheReadPerMillionUsd: 0.25,
    cacheWritePerMillionUsd: 0.0,
  },
  "codex-mini": {
    inputPerMillionUsd: 1.5,
    outputPerMillionUsd: 6.0,
    cacheReadPerMillionUsd: 0.375,
    cacheWritePerMillionUsd: 0.0,
  },
  "gemini-2.5-pro": {
    inputPerMillionUsd: 1.25,
    outputPerMillionUsd: 10.0,
    cacheReadPerMillionUsd: 0.3125,
    cacheWritePerMillionUsd: 0.0,
  },
  "gemini-3-pro": {
    inputPerMillionUsd: 1.25,
    outputPerMillionUsd: 10.0,
    cacheReadPerMillionUsd: 0.3125,
    cacheWritePerMillionUsd: 0.0,
  },
} as const;

export interface TokenUsageBreakdown {
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens?: number;
  cacheWriteTokens?: number;
}

export type BillingMode = "oauth_subscription" | "api_key";

export interface CostAccountingSummary {
  model: string;
  normalizedModel: string;
  billingMode: BillingMode;
  actualBilledUsd: number;
  shadowApiUsd: number;
  cacheSavingsUsd: number;
  breakdownUsd: {
    inputUsd: number;
    outputUsd: number;
    cacheReadUsd: number;
    cacheWriteUsd: number;
  };
}

function roundUsd(amount: number): number {
  return Math.round(amount * 1e8) / 1e8;
}

export function normalizeModelPricingId(model: string): string {
  const withoutProvider = model.includes("/") ? (model.split("/").pop() ?? model) : model;
  return withoutProvider.trim().toLowerCase().replace(/-\d{8}$/, "");
}

export function resolveModelPriceEntry(model: string): ModelPriceEntry {
  const normalized = normalizeModelPricingId(model);
  const exact = MODEL_PRICE_TABLE[normalized];
  if (exact) {
    return exact;
  }
  throw new Error(`Unknown model in MODEL_PRICE_TABLE: '${model}' (normalized '${normalized}')`);
}

export function computeShadowCostUsd(model: string, usage: TokenUsageBreakdown): number {
  const rates = resolveModelPriceEntry(model);
  const cacheReadTokens = usage.cacheReadTokens ?? 0;
  const cacheWriteTokens = usage.cacheWriteTokens ?? 0;

  if (
    usage.inputTokens < 0 ||
    usage.outputTokens < 0 ||
    cacheReadTokens < 0 ||
    cacheWriteTokens < 0
  ) {
    throw new RangeError("Token counts in TokenUsageBreakdown must be non-negative");
  }

  const totalUsd =
    (usage.inputTokens * rates.inputPerMillionUsd +
      usage.outputTokens * rates.outputPerMillionUsd +
      cacheReadTokens * rates.cacheReadPerMillionUsd +
      cacheWriteTokens * rates.cacheWritePerMillionUsd) /
    1_000_000;

  return roundUsd(totalUsd);
}

export function computeCostAccounting(
  model: string,
  usage: TokenUsageBreakdown,
  billingMode: BillingMode = "oauth_subscription",
): CostAccountingSummary {
  const normalizedModel = normalizeModelPricingId(model);
  const rates = resolveModelPriceEntry(model);
  const cacheReadTokens = usage.cacheReadTokens ?? 0;
  const cacheWriteTokens = usage.cacheWriteTokens ?? 0;

  const inputUsd = roundUsd((usage.inputTokens * rates.inputPerMillionUsd) / 1_000_000);
  const outputUsd = roundUsd((usage.outputTokens * rates.outputPerMillionUsd) / 1_000_000);
  const cacheReadUsd = roundUsd((cacheReadTokens * rates.cacheReadPerMillionUsd) / 1_000_000);
  const cacheWriteUsd = roundUsd((cacheWriteTokens * rates.cacheWritePerMillionUsd) / 1_000_000);

  const shadowApiUsd = computeShadowCostUsd(model, usage);
  const uncachedEquivalentForCacheReads =
    (cacheReadTokens * rates.inputPerMillionUsd) / 1_000_000;
  const cacheSavingsUsd = roundUsd(
    Math.max(0, uncachedEquivalentForCacheReads - (cacheReadTokens * rates.cacheReadPerMillionUsd) / 1_000_000),
  );

  return {
    model,
    normalizedModel,
    billingMode,
    actualBilledUsd: billingMode === "oauth_subscription" ? 0 : shadowApiUsd,
    shadowApiUsd,
    cacheSavingsUsd,
    breakdownUsd: {
      inputUsd,
      outputUsd,
      cacheReadUsd,
      cacheWriteUsd,
    },
  };
}
