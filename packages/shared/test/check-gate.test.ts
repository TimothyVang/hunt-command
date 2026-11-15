import { describe, expect, test } from "bun:test";
import {
  checkCoachIsolationInPackageJson,
  checkForbiddenPathAndContent,
  checkTrackedManifest,
  checkTypeScriptAstPolicies,
} from "../../../scripts/hunt_bots_check.ts";

describe("hunt_bots_check AST and policy rules", () => {
  test("enforces exact sorted TRACKED-FILES.txt manifest parity", () => {
    expect(checkTrackedManifest(["LICENSE", "STACK.md"], "LICENSE\nSTACK.md\n")).toEqual([]);
    expect(checkTrackedManifest(["LICENSE", "STACK.md"], "STACK.md\nLICENSE\n").length).toBeGreaterThan(
      0,
    );
    expect(checkTrackedManifest(["LICENSE", "STACK.md"], "LICENSE\n").length).toBeGreaterThan(0);
  });

  test("blocks forbidden paths, credentials, and vendor phone-home tokens", () => {
    expect(checkForbiddenPathAndContent("runtime/state.json", "{}")).toHaveLength(1);
    expect(checkForbiddenPathAndContent("cases/operator-only/key.json", "{}")).toHaveLength(1);
    expect(checkForbiddenPathAndContent("data/truth.json", "{}")).toHaveLength(1);
    expect(checkForbiddenPathAndContent("evidence/traffic.pcap", "")).toHaveLength(1);
    expect(checkForbiddenPathAndContent("telemetry/hunt.sqlite", "")).toHaveLength(1);
    expect(checkForbiddenPathAndContent("packages/shared/src/runtime-paths.ts", "export {};")).toEqual(
      [],
    );

    const fakeAntKey = ["sk", "ant", "api03-abcdef123456"].join("-");
    expect(checkForbiddenPathAndContent("packages/daemon/src/index.ts", fakeAntKey)).toHaveLength(1);

    const fakeVendorImport = "import client from '" + ["post", "hog"].join("") + "-js';";
    expect(checkForbiddenPathAndContent("apps/desktop/src/main.ts", fakeVendorImport)).toHaveLength(
      1,
    );
  });

  test("prevents packages/data-plane and packages/daemon from importing packages/coach", () => {
    expect(
      checkCoachIsolationInPackageJson(
        "packages/daemon/package.json",
        JSON.stringify({ dependencies: { "@hunt-command/coach": "workspace:*" } }),
      ),
    ).toHaveLength(1);

    expect(
      checkTypeScriptAstPolicies(
        "packages/daemon/src/engine.ts",
        `import { COACH_PACKAGE_ID } from "@hunt-command/coach";\nconsole.log(COACH_PACKAGE_ID);`,
      ),
    ).toHaveLength(1);

    expect(
      checkTypeScriptAstPolicies(
        "packages/data-plane/src/query.ts",
        `const mod = await import("../../coach/src/index.ts");\nconsole.log(mod);`,
      ),
    ).toHaveLength(1);
  });

  test("enforces windowsHide: true on child-process spawns without flagging SQLite db.exec", () => {
    const missingHide = `import { spawn } from "node:child_process";\nspawn("ffmpeg", ["-version"], { cwd: "." });\n`;
    expect(checkTypeScriptAstPolicies("packages/daemon/src/proc.ts", missingHide)).toHaveLength(1);

    const bunMissingHide = `Bun.spawn(["git", "status"], { cwd: "." });\n`;
    expect(checkTypeScriptAstPolicies("packages/daemon/src/proc.ts", bunMissingHide)).toHaveLength(
      1,
    );

    const withHide = `import { spawnSync } from "node:child_process";\nspawnSync("git", ["status"], { windowsHide: true });\n`;
    expect(checkTypeScriptAstPolicies("packages/daemon/src/proc.ts", withHide)).toEqual([]);

    const waived = `// health: allow SPAWN_WINDOW -- interactive dev tool test\nBun.spawn(["cmd", "/c", "echo"]);\n`;
    expect(checkTypeScriptAstPolicies("packages/daemon/src/proc.ts", waived)).toEqual([]);

    const sqliteExec = `const db = { exec: (sql: string) => sql };\ndb.exec("CREATE TABLE events_hot (id TEXT)");\n`;
    expect(checkTypeScriptAstPolicies("packages/data-plane/src/db.ts", sqliteExec)).toEqual([]);
  });

  test("forbids the system temp folder in shipped source, with a reasoned waiver, and leaves tests alone", () => {
    const viaNamespace = `import os from "node:os";\nconst dir = os.tmpdir();\n`;
    const viaNamedImport = `import { tmpdir } from "node:os";\nconst dir = tmpdir();\n`;
    for (const source of [viaNamespace, viaNamedImport]) {
      for (const file of ["packages/daemon/src/pool.ts", "apps/desktop/src/main/film.ts"]) {
        const found = checkTypeScriptAstPolicies(file, source);
        expect(found.map((v) => [v.rule, v.line])).toEqual([["SYSTEM_TEMP", 2]]);
      }
    }

    const waived = `import os from "node:os";\n// health: allow SYSTEM_TEMP -- a clean room must be outside the workspace\nconst dir = os.tmpdir();\n`;
    expect(checkTypeScriptAstPolicies("packages/coach/src/room.ts", waived)).toEqual([]);
    const waiverWithoutReason = `import os from "node:os";\n// health: allow SYSTEM_TEMP --\nconst dir = os.tmpdir();\n`;
    expect(checkTypeScriptAstPolicies("packages/coach/src/room.ts", waiverWithoutReason)).toHaveLength(1);

    expect(checkTypeScriptAstPolicies("packages/daemon/test/pool.test.ts", viaNamespace)).toEqual([]);
    expect(checkTypeScriptAstPolicies("scripts/test-temp.ts", viaNamespace)).toEqual([]);
  });
});
