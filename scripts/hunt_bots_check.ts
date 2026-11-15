import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import ts from "typescript";

export interface PolicyViolation {
  rule: string;
  file?: string;
  line?: number;
  message: string;
}

const REQUIRED_GOVERNANCE_FILES = [
  "LICENSE",
  "THIRD-PARTY-NOTICES.md",
  "HUNT-BOTS.md",
  "STACK.md",
] as const;

const FORBIDDEN_PATH_PATTERNS: ReadonlyArray<{ label: string; regex: RegExp }> = [
  { label: "runtime/", regex: /(?:^|\/)runtime(?:\/|$)/i },
  { label: "operator-only", regex: /(?:^|\/)operator-only(?:\/|$)/i },
  { label: "truth.json", regex: /(?:^|\/)truth\.json$/i },
  { label: ".pcap", regex: /\.pcap(?:ng)?(?:\.|$)/i },
  { label: ".sqlite/.db", regex: /\.(?:sqlite|sqlite3|db)(?:-(?:wal|shm))?$/i },
  { label: ".zst/.mp4/.ass", regex: /\.(?:zst|mp4|ass)$/i },
  { label: ".env", regex: /(?:^|\/)\.env(?:\..+)?$/i },
];

const SECRET_TOKEN_PATTERNS: ReadonlyArray<{ label: string; regex: RegExp }> = [
  { label: "sk-ant-", regex: /sk-ant-[A-Za-z0-9_-]{4,}/ },
  { label: "gho_", regex: /\bgho_[A-Za-z0-9_]{4,}/ },
  { label: "ghp_", regex: /\bghp_[A-Za-z0-9_]{4,}/ },
  { label: "xoxb-", regex: /xoxb-[A-Za-z0-9-]{4,}/ },
  { label: "xapp-", regex: /xapp-[A-Za-z0-9-]{4,}/ },
  { label: "AKIA", regex: /\bAKIA[0-9A-Z]{8,}/ },
];

const VENDOR_TELEMETRY_PATTERNS: ReadonlyArray<{ label: string; regex: RegExp }> = [
  { label: "posthog", regex: /posthog/i },
  { label: "users.n8n.cloud", regex: /users\.n8n\.cloud/i },
];

const DOC_EXEMPT_FROM_VENDOR_PROSE = new Set<string>([
  "HUNT-BOTS.md",
  "STACK.md",
  "THIRD-PARTY-NOTICES.md",
  "LICENSE",
  "scripts/hunt_bots_check.ts",
]);

const CHILD_PROCESS_FUNCTIONS = new Set<string>([
  "spawn",
  "spawnSync",
  "exec",
  "execSync",
  "execFile",
  "execFileSync",
  "fork",
]);

const SPAWN_WAIVER_RE = /\/\/\s*health:\s*allow\s+SPAWN_WINDOW\s*--\s*\S+/;
const TOKEN_WAIVER_RE = /\/\/\s*health:\s*allow\s+FORBIDDEN_TOKEN\s*--\s*\S+/;

function normalizeLines(content: string): string[] {
  const trimmed = content.replace(/\r\n/g, "\n").replace(/\n+$/, "");
  if (trimmed.length === 0) {
    return [];
  }
  return trimmed.split("\n");
}

function compareLexicographic(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

export function checkTrackedManifest(
  gitTrackedFiles: readonly string[],
  manifestContent: string,
): PolicyViolation[] {
  const violations: PolicyViolation[] = [];
  const manifestLines = normalizeLines(manifestContent);

  for (let i = 1; i < manifestLines.length; i++) {
    const prev = manifestLines[i - 1]!;
    const curr = manifestLines[i]!;
    if (compareLexicographic(prev, curr) >= 0) {
      violations.push({
        rule: "TRACKED_MANIFEST_ORDER",
        file: "TRACKED-FILES.txt",
        line: i + 1,
        message: `TRACKED-FILES.txt must be strictly sorted lexicographically without duplicates ('${prev}' vs '${curr}')`,
      });
      break;
    }
  }

  const gitSet = new Set(gitTrackedFiles);
  const manifestSet = new Set(manifestLines);

  for (const file of gitTrackedFiles) {
    if (!manifestSet.has(file)) {
      violations.push({
        rule: "TRACKED_MANIFEST_MISSING",
        file: "TRACKED-FILES.txt",
        message: `Tracked file '${file}' is missing from TRACKED-FILES.txt`,
      });
    }
  }

  for (const entry of manifestLines) {
    if (!gitSet.has(entry)) {
      violations.push({
        rule: "TRACKED_MANIFEST_STALE",
        file: "TRACKED-FILES.txt",
        message: `Manifest entry '${entry}' in TRACKED-FILES.txt is not tracked by git`,
      });
    }
  }

  return violations;
}

export function checkForbiddenPathAndContent(
  relPath: string,
  content: string | null,
): PolicyViolation[] {
  const violations: PolicyViolation[] = [];

  for (const pattern of FORBIDDEN_PATH_PATTERNS) {
    if (pattern.regex.test(relPath)) {
      violations.push({
        rule: "FORBIDDEN_TRACKED_PATH",
        file: relPath,
        message: `Forbidden tracked path matching '${pattern.label}'`,
      });
    }
  }

  if (content === null) {
    return violations;
  }

  const isTestFile = /(?:^|\/)test\/|\.test\.[cm]?[jt]sx?$/.test(relPath);
  const lines = content.replace(/\r\n/g, "\n").split("\n");

  for (let idx = 0; idx < lines.length; idx++) {
    const line = lines[idx]!;
    const prevLine = idx > 0 ? lines[idx - 1]! : "";
    const hasTestWaiver =
      isTestFile && (TOKEN_WAIVER_RE.test(line) || TOKEN_WAIVER_RE.test(prevLine));

    for (const secret of SECRET_TOKEN_PATTERNS) {
      if (secret.regex.test(line) && !hasTestWaiver) {
        violations.push({
          rule: "FORBIDDEN_SECRET_TOKEN",
          file: relPath,
          line: idx + 1,
          message: `Forbidden credential prefix '${secret.label}' detected`,
        });
      }
    }

    if (!DOC_EXEMPT_FROM_VENDOR_PROSE.has(relPath) && !hasTestWaiver) {
      for (const vendor of VENDOR_TELEMETRY_PATTERNS) {
        if (vendor.regex.test(line)) {
          violations.push({
            rule: "FORBIDDEN_VENDOR_TOKEN",
            file: relPath,
            line: idx + 1,
            message: `Forbidden vendor phone-home token '${vendor.label}' detected`,
          });
        }
      }
    }
  }

  return violations;
}

function isCoachModuleSpecifier(fromFileRelPath: string, specifier: string): boolean {
  if (
    specifier === "@hunt-command/coach" ||
    specifier.startsWith("@hunt-command/coach/") ||
    /(?:^|\/)packages\/coach(?:\/|$)/.test(specifier)
  ) {
    return true;
  }

  if (specifier.startsWith(".")) {
    const resolvedPosix = path.posix.normalize(
      path.posix.join(path.posix.dirname(fromFileRelPath), specifier),
    );
    if (resolvedPosix === "packages/coach" || resolvedPosix.startsWith("packages/coach/")) {
      return true;
    }
  }

  return false;
}

export function checkCoachIsolationInPackageJson(
  relPath: string,
  jsonText: string,
): PolicyViolation[] {
  if (
    !relPath.startsWith("packages/data-plane/") &&
    !relPath.startsWith("packages/daemon/")
  ) {
    return [];
  }

  const violations: PolicyViolation[] = [];
  const parsed = JSON.parse(jsonText) as Record<string, unknown>;
  const depSections = [
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
  ];

  for (const section of depSections) {
    const deps = parsed[section];
    if (deps && typeof deps === "object" && "@hunt-command/coach" in deps) {
      violations.push({
        rule: "COACH_BOUNDARY",
        file: relPath,
        message: `${relPath} must never depend on '@hunt-command/coach' (${section})`,
      });
    }
  }

  return violations;
}

function hasWindowsHideTrue(args: readonly ts.Expression[]): boolean {
  for (const arg of args) {
    if (!ts.isObjectLiteralExpression(arg)) {
      continue;
    }
    for (const prop of arg.properties) {
      if (
        ts.isPropertyAssignment(prop) &&
        ((ts.isIdentifier(prop.name) && prop.name.text === "windowsHide") ||
          (ts.isStringLiteral(prop.name) && prop.name.text === "windowsHide")) &&
        prop.initializer.kind === ts.SyntaxKind.TrueKeyword
      ) {
        return true;
      }
    }
  }
  return false;
}

function hasSpawnWaiverComment(sourceText: string, lineZeroBased: number): boolean {
  const lines = sourceText.replace(/\r\n/g, "\n").split("\n");
  const currentLine = lines[lineZeroBased] ?? "";
  const previousLine = lineZeroBased > 0 ? (lines[lineZeroBased - 1] ?? "") : "";
  return SPAWN_WAIVER_RE.test(currentLine) || SPAWN_WAIVER_RE.test(previousLine);
}

export function checkTypeScriptAstPolicies(relPath: string, sourceText: string): PolicyViolation[] {
  const violations: PolicyViolation[] = [];
  const scriptKind = relPath.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS;
  const sf = ts.createSourceFile(relPath, sourceText, ts.ScriptTarget.Latest, true, scriptKind);

  const checkCoachBoundary =
    relPath.startsWith("packages/data-plane/") || relPath.startsWith("packages/daemon/");

  const directSpawnIdentifiers = new Set<string>();
  const childProcessNamespaces = new Set<string>();

  const getLineNumber = (node: ts.Node): number =>
    sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;

  const checkSpecifier = (specifier: string, node: ts.Node): void => {
    if (checkCoachBoundary && isCoachModuleSpecifier(relPath, specifier)) {
      violations.push({
        rule: "COACH_BOUNDARY",
        file: relPath,
        line: getLineNumber(node),
        message: `'${relPath}' must never import packages/coach ('${specifier}')`,
      });
    }
  };

  for (const stmt of sf.statements) {
    if (ts.isImportDeclaration(stmt) && ts.isStringLiteral(stmt.moduleSpecifier)) {
      const spec = stmt.moduleSpecifier.text;
      checkSpecifier(spec, stmt.moduleSpecifier);

      if (spec === "child_process" || spec === "node:child_process") {
        const clause = stmt.importClause;
        if (clause?.name) {
          childProcessNamespaces.add(clause.name.text);
        }
        if (clause?.namedBindings) {
          if (ts.isNamespaceImport(clause.namedBindings)) {
            childProcessNamespaces.add(clause.namedBindings.name.text);
          } else if (ts.isNamedImports(clause.namedBindings)) {
            for (const el of clause.namedBindings.elements) {
              const importedName = (el.propertyName ?? el.name).text;
              if (CHILD_PROCESS_FUNCTIONS.has(importedName)) {
                directSpawnIdentifiers.add(el.name.text);
              }
            }
          }
        }
      }
    } else if (
      ts.isExportDeclaration(stmt) &&
      stmt.moduleSpecifier &&
      ts.isStringLiteral(stmt.moduleSpecifier)
    ) {
      checkSpecifier(stmt.moduleSpecifier.text, stmt.moduleSpecifier);
    }
  }

  const visit = (node: ts.Node): void => {
    if (
      ts.isVariableDeclaration(node) &&
      node.initializer &&
      ts.isCallExpression(node.initializer) &&
      ts.isIdentifier(node.initializer.expression) &&
      node.initializer.expression.text === "require" &&
      node.initializer.arguments.length === 1 &&
      ts.isStringLiteral(node.initializer.arguments[0]!)
    ) {
      const spec = node.initializer.arguments[0]!.text;
      if (spec === "child_process" || spec === "node:child_process") {
        if (ts.isIdentifier(node.name)) {
          childProcessNamespaces.add(node.name.text);
        } else if (ts.isObjectBindingPattern(node.name)) {
          for (const el of node.name.elements) {
            const propName = el.propertyName && ts.isIdentifier(el.propertyName)
              ? el.propertyName.text
              : ts.isIdentifier(el.name)
                ? el.name.text
                : "";
            if (CHILD_PROCESS_FUNCTIONS.has(propName) && ts.isIdentifier(el.name)) {
              directSpawnIdentifiers.add(el.name.text);
            }
          }
        }
      }
    }

    if (ts.isCallExpression(node)) {
      if (
        node.expression.kind === ts.SyntaxKind.ImportKeyword &&
        node.arguments.length >= 1 &&
        ts.isStringLiteral(node.arguments[0]!)
      ) {
        checkSpecifier(node.arguments[0]!.text, node.arguments[0]!);
      } else if (
        ts.isIdentifier(node.expression) &&
        node.expression.text === "require" &&
        node.arguments.length >= 1 &&
        ts.isStringLiteral(node.arguments[0]!)
      ) {
        checkSpecifier(node.arguments[0]!.text, node.arguments[0]!);
      }

      let spawnCallLabel: string | null = null;
      if (ts.isIdentifier(node.expression) && directSpawnIdentifiers.has(node.expression.text)) {
        spawnCallLabel = node.expression.text;
      } else if (ts.isPropertyAccessExpression(node.expression)) {
        const obj = node.expression.expression;
        const prop = node.expression.name.text;
        if (
          ts.isIdentifier(obj) &&
          obj.text === "Bun" &&
          (prop === "spawn" || prop === "spawnSync")
        ) {
          spawnCallLabel = `Bun.${prop}`;
        } else if (
          ts.isIdentifier(obj) &&
          childProcessNamespaces.has(obj.text) &&
          CHILD_PROCESS_FUNCTIONS.has(prop)
        ) {
          spawnCallLabel = `${obj.text}.${prop}`;
        }
      }

      if (spawnCallLabel !== null) {
        const lineZeroBased = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line;
        if (
          !hasWindowsHideTrue(node.arguments) &&
          !hasSpawnWaiverComment(sourceText, lineZeroBased)
        ) {
          violations.push({
            rule: "SPAWN_WINDOW",
            file: relPath,
            line: lineZeroBased + 1,
            message: `Child-process call '${spawnCallLabel}(...)' must pass 'windowsHide: true' or carry '// health: allow SPAWN_WINDOW -- <reason>'`,
          });
        }
      }
    }

    ts.forEachChild(node, visit);
  };

  visit(sf);
  return violations;
}

function readUtf8IfText(absPath: string): string | null {
  const buf = fs.readFileSync(absPath);
  const sampleLen = Math.min(buf.length, 4096);
  for (let i = 0; i < sampleLen; i++) {
    if (buf[i] === 0) {
      return null;
    }
  }
  return buf.toString("utf8");
}

export function runAllChecks(repoRoot: string): {
  trackedCount: number;
  testCount: number;
  violations: PolicyViolation[];
} {
  const violations: PolicyViolation[] = [];

  for (const govFile of REQUIRED_GOVERNANCE_FILES) {
    const absGov = path.join(repoRoot, govFile);
    if (!fs.existsSync(absGov) || fs.statSync(absGov).size === 0) {
      violations.push({
        rule: "GOVERNANCE_FILE_MISSING",
        file: govFile,
        message: `Required governance file '${govFile}' is missing or empty`,
      });
    }
  }

  const gitLs = spawnSync("git", ["ls-files"], {
    cwd: repoRoot,
    encoding: "utf8",
    windowsHide: true,
  });
  if (gitLs.status !== 0) {
    violations.push({
      rule: "GIT_LS_FILES_FAILED",
      message: `git ls-files failed: ${(gitLs.stderr || gitLs.stdout || "").trim()}`,
    });
    return { trackedCount: 0, testCount: 0, violations };
  }

  const trackedFiles = normalizeLines(gitLs.stdout);
  const manifestPath = path.join(repoRoot, "TRACKED-FILES.txt");
  if (!fs.existsSync(manifestPath)) {
    violations.push({
      rule: "TRACKED_MANIFEST_MISSING",
      file: "TRACKED-FILES.txt",
      message: "TRACKED-FILES.txt does not exist",
    });
  } else {
    violations.push(
      ...checkTrackedManifest(trackedFiles, fs.readFileSync(manifestPath, "utf8")),
    );
  }

  for (const govFile of REQUIRED_GOVERNANCE_FILES) {
    if (!trackedFiles.includes(govFile)) {
      violations.push({
        rule: "GOVERNANCE_FILE_UNTRACKED",
        file: govFile,
        message: `Required governance file '${govFile}' must be tracked in git`,
      });
    }
  }

  for (const relPath of trackedFiles) {
    const absPath = path.join(repoRoot, relPath);
    if (!fs.existsSync(absPath)) {
      violations.push({
        rule: "MISSING_WORKING_FILE",
        file: relPath,
        message: `Tracked file '${relPath}' is missing on disk`,
      });
      continue;
    }

    const text = readUtf8IfText(absPath);
    violations.push(...checkForbiddenPathAndContent(relPath, text));

    if (text !== null) {
      if (relPath.endsWith("/package.json")) {
        violations.push(...checkCoachIsolationInPackageJson(relPath, text));
      }
      if (/\.[cm]?[jt]sx?$/.test(relPath)) {
        violations.push(...checkTypeScriptAstPolicies(relPath, text));
      }
    }
  }

  let tscEntry: string;
  try {
    tscEntry = Bun.resolveSync("typescript/bin/tsc", repoRoot);
  } catch (err) {
    violations.push({
      rule: "TYPECHECK_FAILED",
      message: `Cannot resolve typescript/bin/tsc from '${repoRoot}': ${String(err)}`,
    });
    return { trackedCount: trackedFiles.length, testCount: 0, violations };
  }

  const tscRun = spawnSync(process.execPath, [tscEntry, "--noEmit"], {
    cwd: repoRoot,
    encoding: "utf8",
    windowsHide: true,
  });
  if (tscRun.status !== 0) {
    const output = `${tscRun.stdout ?? ""}\n${tscRun.stderr ?? ""}`.trim();
    violations.push({
      rule: "TYPECHECK_FAILED",
      message: `tsc --noEmit failed (exit ${tscRun.status}):\n${output}`,
    });
  }

  const testRun = spawnSync(process.execPath, ["test"], {
    cwd: repoRoot,
    encoding: "utf8",
    windowsHide: true,
  });
  const combinedTestOut = `${testRun.stdout ?? ""}\n${testRun.stderr ?? ""}`;
  const passMatches = [...combinedTestOut.matchAll(/^\s*(\d+)\s+pass\b/gm)];
  const failMatches = [...combinedTestOut.matchAll(/^\s*(\d+)\s+fail\b/gm)];

  const passCount = passMatches.reduce((acc, m) => acc + Number(m[1]), 0);
  const failCount = failMatches.reduce((acc, m) => acc + Number(m[1]), 0);

  if (testRun.status !== 0 || failCount > 0 || passCount === 0) {
    violations.push({
      rule: "BUN_TEST_FAILED",
      message: `bun test failed (exit ${testRun.status}, ${passCount} pass, ${failCount} fail):\n${combinedTestOut.trim()}`,
    });
  }

  return {
    trackedCount: trackedFiles.length,
    testCount: passCount,
    violations,
  };
}

if (import.meta.main) {
  const repoRoot = path.resolve(import.meta.dir, "..");
  const { trackedCount, testCount, violations } = runAllChecks(repoRoot);

  if (violations.length > 0) {
    for (const v of violations) {
      const loc = v.file ? (v.line ? `${v.file}:${v.line}` : v.file) : "repo";
      console.error(`[${v.rule}] ${loc} — ${v.message}`);
    }
    console.error(`hunt_bots_check: FAIL (${violations.length} policy violations)`);
    process.exit(1);
  }

  console.log(
    `hunt_bots_check: PASS (${trackedCount} tracked files, ${testCount} tests, 0 policy violations)`,
  );
  process.exit(0);
}
