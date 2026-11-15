import { describe, expect, test } from "bun:test";
import {
  BigRational,
  buildSharedModelPriceTable,
  costArms,
  formatCostArmsTable,
  parseTokenTypes,
} from "../src/index.ts";

function makeHunt(params: {
  caseId: string;
  attackFound: number;
  decoysBlamed?: number;
  completed?: boolean;
  haltedAt?: string | null;
  usage: Record<string, unknown>;
  model?: string;
}): Record<string, unknown> {
  return {
    case: params.caseId,
    workflow: `wf-${params.caseId}`,
    completed: params.completed ?? true,
    halted_at: params.haltedAt ?? null,
    by_kind: {
      attack: {
        found: params.attackFound,
        partial: 0,
        total: 6,
      },
    },
    decoys_blamed: params.decoysBlamed ?? 0,
    minutes_measured: 4.5,
    ...(params.model ? { model: params.model } : {}),
    usage: params.usage,
  };
}

describe("packages/coach exact BigInt rational costArms & OAuth vs shadow cost ledger", () => {
  test("BigRational performs exact arbitrary-precision arithmetic without IEEE-754 drift", () => {
    // 0.1 + 0.2 === 0.3 exactly (3/10)
    const sum = BigRational.fromDecimal("0.1").add(BigRational.fromDecimal("0.2"));
    expect(sum.equals(BigRational.fromDecimal("0.3"))).toBe(true);
    expect(sum.toFractionString()).toBe("3/10");

    // 1/3 + 1/6 === 1/2
    const thirdPlusSixth = BigRational.fromFraction(1, 3).add(
      BigRational.fromFraction(1, 6),
    );
    expect(thirdPlusSixth.toFractionString()).toBe("1/2");
    expect(thirdPlusSixth.toRoundedNumber(4)).toBe(0.5);
  });

  test("parseTokenTypes enforces uncached_input >= 0, steps_without_usage === 0, and split bucket equality", () => {
    const valid = parseTokenTypes({
      input_tokens: 100_000,
      cache_read_tokens: 70_000,
      cache_write_tokens: 10_000,
      output_tokens: 5_000,
      total_tokens: 105_000,
      steps_without_usage: 0,
    });
    expect(valid.problem).toBeNull();
    expect(valid.types?.uncached_input).toBe(20_000n);

    // Negative uncached_input (cache_read + cache_write > input_tokens) -> rejected!
    const negUncached = parseTokenTypes({
      input_tokens: 50_000,
      cache_read_tokens: 40_000,
      cache_write_tokens: 15_000,
      output_tokens: 2_000,
      total_tokens: 52_000,
      steps_without_usage: 0,
    });
    expect(negUncached.problem).toContain(
      "input_tokens is below cache reads plus cache writes",
    );

    // steps_without_usage > 0 -> rejected!
    const missingSteps = parseTokenTypes({
      input_tokens: 50_000,
      cache_read_tokens: 10_000,
      cache_write_tokens: 0,
      output_tokens: 2_000,
      total_tokens: 52_000,
      steps_without_usage: 2,
    });
    expect(missingSteps.problem).toBe("2 steps without usage");

    // by_model bucket mismatch -> rejected!
    const splitMismatch = parseTokenTypes({
      input_tokens: 50_000,
      cache_read_tokens: 10_000,
      cache_write_tokens: 0,
      output_tokens: 2_000,
      total_tokens: 52_000,
      steps_without_usage: 0,
      by_model: {
        "claude-haiku-4-5": {
          input_tokens: 30_000,
          cache_read_tokens: 10_000,
          cache_write_tokens: 0,
          output_tokens: 2_000,
          total_tokens: 32_000,
        },
      },
    });
    expect(splitMismatch.problem).toContain("by_model uncached_input does not match");
  });

  test("costArms ranks hybrid Haiku+Opus cheaper than pure Opus on exact rational cost while enforcing G4.1/G4.2/G4.3 and $0 OAuth vs shadow cost", () => {
    const cases = ["team-med-011", "team-med-012"];
    const priceTable = buildSharedModelPriceTable({
      defaultModel: "claude-opus-4-7",
    });

    // K6 baseline: all Opus, higher cost, 5.0 mean attack facts
    const k6Hunts = cases.map((c) =>
      makeHunt({
        caseId: c,
        attackFound: 5,
        decoysBlamed: 0,
        usage: {
          input_tokens: 1_000_000,
          cache_read_tokens: 800_000,
          cache_write_tokens: 100_000,
          output_tokens: 50_000,
          total_tokens: 1_050_000,
          steps_without_usage: 0,
          by_model: {
            "claude-opus-4-7": {
              input_tokens: 1_000_000,
              cache_read_tokens: 800_000,
              cache_write_tokens: 100_000,
              output_tokens: 50_000,
              total_tokens: 1_050_000,
            },
          },
        },
      }),
    );

    // H1 hybrid: MORE total tokens (1.5M vs 1.05M), but 90% on Haiku -> MUCH lower USD shadow cost!
    // Mean attack facts = 4.5 >= floor (5.0 - 1.0 = 4.0) -> qualifies and wins by mean_cost!
    const h1Hunts = cases.map((c, idx) =>
      makeHunt({
        caseId: c,
        attackFound: idx === 0 ? 5 : 4,
        decoysBlamed: 0,
        usage: {
          input_tokens: 1_400_000,
          cache_read_tokens: 1_000_000,
          cache_write_tokens: 100_000,
          output_tokens: 100_000,
          total_tokens: 1_500_000,
          steps_without_usage: 0,
          by_model: {
            "claude-haiku-4-5": {
              input_tokens: 1_200_000,
              cache_read_tokens: 900_000,
              cache_write_tokens: 80_000,
              output_tokens: 80_000,
              total_tokens: 1_280_000,
            },
            "claude-opus-4-7": {
              input_tokens: 200_000,
              cache_read_tokens: 100_000,
              cache_write_tokens: 20_000,
              output_tokens: 20_000,
              total_tokens: 220_000,
            },
          },
        },
      }),
    );

    // D1 disqualified arm: blames a decoy
    const d1Hunts = cases.map((c) =>
      makeHunt({
        caseId: c,
        attackFound: 5,
        decoysBlamed: 1,
        usage: {
          input_tokens: 200_000,
          cache_read_tokens: 100_000,
          cache_write_tokens: 0,
          output_tokens: 10_000,
          total_tokens: 210_000,
          steps_without_usage: 0,
          by_model: {
            "claude-haiku-4-5": {
              input_tokens: 200_000,
              cache_read_tokens: 100_000,
              cache_write_tokens: 0,
              output_tokens: 10_000,
              total_tokens: 210_000,
            },
          },
        },
      }),
    );

    const evalRes = costArms({
      arms: [
        { label: "K6", hunts: k6Hunts },
        { label: "H1", hunts: h1Hunts },
        { label: "D1", hunts: d1Hunts },
      ],
      cases,
      baseline: "K6",
      prices: priceTable,
      billingMode: "oauth_subscription",
    });

    expect(evalRes.goals["G4.1"].pass).toBe(true);
    expect(evalRes.goals["G4.2"].pass).toBe(true);
    expect(evalRes.goals["G4.2"].ranked_by).toBe("mean_cost");
    expect(evalRes.goals["G4.2"].chosen).toBe("H1");
    expect(evalRes.goals["G4.2"].arms.D1?.qualifies).toBe(false);
    expect(evalRes.goals["G4.3"].pass).toBe(true);

    // Verify $0 OAuth subscription actual billed vs positive API-equivalent shadow cost + cache savings
    const h1Ledger = evalRes.goals["G4.3"].oauth_vs_shadow.H1!;
    expect(h1Ledger.billing_mode).toBe("oauth_subscription");
    expect(h1Ledger.actual_billed_usd).toBe(0);
    expect(h1Ledger.actual_billed_rational).toBe("0");
    expect(h1Ledger.shadow_api_usd).toBeGreaterThan(0);
    expect(h1Ledger.cache_savings_usd).toBeGreaterThan(0);
    expect(evalRes.goals["G4.3"].arms.H1!.total!).toBeLessThan(
      evalRes.goals["G4.3"].arms.K6!.total!,
    );

    const formatted = formatCostArmsTable(evalRes);
    expect(formatted).toContain("chosen: H1");
    expect(formatted).toContain("G4.1 pass");
  });
});
