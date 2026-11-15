import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import path from "node:path";
import { DEFAULT_ROLE_MODEL_PINS } from "../src/hunter-policy.ts";
import { LazyHunterPool } from "../src/lazy-hunter-pool.ts";

const SRC = path.resolve(import.meta.dir, "../src");

/** Every module reachable from `entry` through imports that exist at runtime (type-only imports are erased). */
function runtimeImportGraph(entry: string): { files: Set<string>; packages: Set<string> } {
  const files = new Set<string>();
  const packages = new Set<string>();
  const queue = [entry];
  while (queue.length > 0) {
    const file = queue.pop()!;
    if (files.has(file)) continue;
    files.add(file);
    const text = fs.readFileSync(file, "utf8");
    const statements = text.matchAll(/^(?:import|export)\s+(?!type\b)[^;]*?\sfrom\s+["']([^"']+)["']|^import\s+["']([^"']+)["']/gm);
    for (const match of statements) {
      const spec = (match[1] ?? match[2])!;
      if (spec.startsWith(".")) queue.push(path.resolve(path.dirname(file), spec));
      else packages.add(spec);
    }
  }
  return { files, packages };
}

describe("the agent stack is loaded only when a model turn runs", () => {
  test("nothing the daemon CLI imports at startup reaches the agent stack", () => {
    const graph = runtimeImportGraph(path.join(SRC, "cli.ts"));
    const names = [...graph.files].map((f) => path.basename(f));
    expect(names).toContain("lazy-hunter-pool.ts");
    expect(names).toContain("wave-engine.ts");
    expect(names).not.toContain("omp-pool.ts");
    expect([...graph.packages].filter((p) => p.startsWith("@oh-my-pi/"))).toEqual([]);
  });

  test("the graph walk does see the agent stack where it really is imported", () => {
    const graph = runtimeImportGraph(path.join(SRC, "omp-pool.ts"));
    expect([...graph.packages].some((p) => p.startsWith("@oh-my-pi/pi-coding-agent"))).toBe(true);
  });

  test("before any model call the pool answers pins, strips paid API keys, and has loaded nothing", async () => {
    const saved = process.env.OPENAI_API_KEY;
    process.env.OPENAI_API_KEY = "placeholder-not-a-real-key";
    try {
      const pool = new LazyHunterPool({ subscriptionOnly: true });
      expect(process.env.OPENAI_API_KEY).toBeUndefined();
      expect(pool.loaded).toBe(false);
      expect(pool.getPinnedModelForRole("framework-coordinator")).toEqual(DEFAULT_ROLE_MODEL_PINS["framework-coordinator"]);
      expect(pool.loaded).toBe(false);
      await pool.close();
      expect(pool.loaded).toBe(false);
    } finally {
      if (saved === undefined) delete process.env.OPENAI_API_KEY;
      else process.env.OPENAI_API_KEY = saved;
    }
  });

  test("an invalid pin table is still rejected at construction, not on the first turn", () => {
    expect(
      () => new LazyHunterPool({ roleModelPins: { "framework-builder": { provider: "", model: "x", fallback_providers: [] } } }),
    ).toThrow(/pinned provider/);
  });
});
