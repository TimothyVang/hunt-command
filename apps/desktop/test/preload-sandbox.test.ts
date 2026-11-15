import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import ts from "typescript";

const desktopDir = path.resolve(import.meta.dir, "..");

/** Runtime (non type-only) module specifiers imported or re-exported by a TS source file. */
function runtimeSpecifiers(file: string): string[] {
  const sf = ts.createSourceFile(file, fs.readFileSync(file, "utf8"), ts.ScriptTarget.Latest, true);
  const specs: string[] = [];
  for (const stmt of sf.statements) {
    if (ts.isImportDeclaration(stmt) && ts.isStringLiteral(stmt.moduleSpecifier)) {
      const clause = stmt.importClause;
      if (clause?.isTypeOnly) continue;
      const named = clause?.namedBindings;
      const allNamedTypeOnly =
        clause !== undefined &&
        clause.name === undefined &&
        named !== undefined &&
        ts.isNamedImports(named) &&
        named.elements.length > 0 &&
        named.elements.every((el) => el.isTypeOnly);
      if (allNamedTypeOnly) continue;
      specs.push(stmt.moduleSpecifier.text);
    } else if (
      ts.isExportDeclaration(stmt) &&
      stmt.moduleSpecifier &&
      ts.isStringLiteral(stmt.moduleSpecifier) &&
      !stmt.isTypeOnly
    ) {
      const clause = stmt.exportClause;
      if (clause && ts.isNamedExports(clause) && clause.elements.every((el) => el.isTypeOnly)) {
        continue;
      }
      specs.push(stmt.moduleSpecifier.text);
    }
  }
  return specs;
}

/** Walks the preload's runtime import graph; returns every non-relative module it pulls in. */
function preloadRuntimeExternals(entry: string): { externals: string[]; files: string[] } {
  const externals = new Set<string>();
  const seen = new Set<string>();
  const queue = [entry];
  while (queue.length > 0) {
    const file = queue.pop()!;
    if (seen.has(file)) continue;
    seen.add(file);
    for (const spec of runtimeSpecifiers(file)) {
      if (spec.startsWith(".")) {
        queue.push(path.resolve(path.dirname(file), spec));
      } else {
        externals.add(spec);
      }
    }
  }
  return {
    externals: [...externals].sort(),
    files: [...seen].map((f) => path.relative(desktopDir, f).replaceAll("\\", "/")).sort(),
  };
}

/**
 * A `sandbox: true` preload runs with a restricted `require` that resolves only `electron` (plus a
 * few polyfilled modules). Any other runtime dependency (`node:fs`, `zod`, the `@hunt-command/shared`
 * barrel) makes Electron refuse the whole preload and `window.huntWorkbench` stays undefined.
 */
describe("sandboxed preload", () => {
  test("pulls in nothing but electron at runtime", () => {
    const graph = preloadRuntimeExternals(path.join(desktopDir, "src/preload/index.ts"));
    expect(graph.externals).toEqual(["electron"]);
    expect(graph.files).toEqual(["src/preload/index.ts", "src/shared/ipc-channels.ts"]);
  });

});

/** Sources the built preload is produced from: everything under src/preload plus the channel module. */
function preloadSourceFiles(): string[] {
  const files: string[] = [path.join(desktopDir, "src/shared/ipc-channels.ts")];
  const walk = (dir: string) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else files.push(full);
    }
  };
  walk(path.join(desktopDir, "src/preload"));
  return files;
}

export type BuiltArtifactStatus = "absent" | "stale" | "fresh";

/** `stale` when the built file is older than any source it is built from. */
export function builtArtifactStatus(builtPath: string, sources: readonly string[]): BuiltArtifactStatus {
  if (!fs.existsSync(builtPath)) return "absent";
  const builtMs = fs.statSync(builtPath).mtimeMs;
  const newestSourceMs = Math.max(...sources.map((f) => fs.statSync(f).mtimeMs));
  return builtMs < newestSourceMs ? "stale" : "fresh";
}

const BUILT_PRELOAD = path.join(desktopDir, "out/preload/index.cjs");
const builtStatus = builtArtifactStatus(BUILT_PRELOAD, preloadSourceFiles());
const SKIP_REASON =
  builtStatus === "stale"
    ? "stale build, run bun run --cwd apps/desktop build"
    : "no build, run bun run --cwd apps/desktop build";
if (builtStatus !== "fresh") {
  console.warn(`[preload-sandbox] built-preload assertion skipped: ${SKIP_REASON} (out/preload/index.cjs is ${builtStatus})`);
}

describe("built preload artifact", () => {
  test.skipIf(builtStatus !== "fresh")(
    builtStatus === "fresh"
      ? "out/preload/index.cjs requires only electron"
      : `out/preload/index.cjs requires only electron [skipped: ${SKIP_REASON}]`,
    () => {
      const code = fs.readFileSync(BUILT_PRELOAD, "utf8");
      const required = [...code.matchAll(/\brequire\(\s*["']([^"']+)["']\s*\)/g)].map((m) => m[1]);
      expect([...new Set(required)]).toEqual(["electron"]);
    },
  );

  test("staleness detection: older-than-source is stale, rebuilt is fresh, missing is absent", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hc-stale-"));
    try {
      const src = path.join(dir, "index.ts");
      const built = path.join(dir, "index.cjs");
      expect(builtArtifactStatus(built, [src])).toBe("absent");
      fs.writeFileSync(src, "x");
      fs.writeFileSync(built, "y");
      const t = Date.now() / 1000;
      fs.utimesSync(built, t - 100, t - 100);
      fs.utimesSync(src, t, t);
      expect(builtArtifactStatus(built, [src])).toBe("stale");
      fs.utimesSync(built, t + 1, t + 1);
      expect(builtArtifactStatus(built, [src])).toBe("fresh");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
