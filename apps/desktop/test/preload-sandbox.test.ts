import { describe, expect, test } from "bun:test";
import fs from "node:fs";
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

  test("built preload (when present) requires only electron", () => {
    const built = path.join(desktopDir, "out/preload/index.cjs");
    if (!fs.existsSync(built)) return;
    const code = fs.readFileSync(built, "utf8");
    const required = [...code.matchAll(/\brequire\(\s*["']([^"']+)["']\s*\)/g)].map((m) => m[1]);
    expect([...new Set(required)]).toEqual(["electron"]);
  });
});
