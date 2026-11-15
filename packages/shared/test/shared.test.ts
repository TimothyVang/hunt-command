import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  AGENT_ROLES,
  AuthenticatedGateDecisionSchema,
  CaseMetadataSchema,
  ClaimSchema,
  DATA_PLANE_TOOLS,
  DataPlaneAccessError,
  ROLE_TOOL_OWNERSHIP,
  RuntimeFenceError,
  assertReadOnlyOperation,
  assertRoleOwnsTool,
  canRoleUseTool,
  computeCostAccounting,
  computeShadowCostUsd,
  extractInlineCitations,
  resolveEgressCardMode,
  resolveRuntimeDir,
} from "../src/index.ts";

describe("resolveRuntimeDir git-tree fence", () => {
  test("rejects a runtime path inside a standard .git directory repository", () => {
    const tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), "hunt-cmd-fence-"));
    try {
      const fakeRepo = path.join(tmpBase, "repo");
      fs.mkdirSync(path.join(fakeRepo, ".git"), { recursive: true });

      expect(() => resolveRuntimeDir(fakeRepo)).toThrow(RuntimeFenceError);
      expect(() => resolveRuntimeDir(path.join(fakeRepo, "runtime"))).toThrow(RuntimeFenceError);
      expect(() => resolveRuntimeDir(path.join(fakeRepo, "nested", "deep", "state"))).toThrow(
        RuntimeFenceError,
      );
    } finally {
      fs.rmSync(tmpBase, { recursive: true, force: true });
    }
  });

  test("rejects a runtime path inside a git worktree where .git is a file", () => {
    const tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), "hunt-cmd-wt-fence-"));
    try {
      const fakeWorktree = path.join(tmpBase, "slice1");
      fs.mkdirSync(fakeWorktree, { recursive: true });
      fs.writeFileSync(path.join(fakeWorktree, ".git"), "gitdir: ../.git/worktrees/slice1\n");

      expect(() => resolveRuntimeDir(path.join(fakeWorktree, "runtime"))).toThrow(
        RuntimeFenceError,
      );
    } finally {
      fs.rmSync(tmpBase, { recursive: true, force: true });
    }
  });

  test("accepts an outside-git ../runtime sibling directory and builds canonical paths", () => {
    const tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), "hunt-cmd-valid-"));
    try {
      const fakeRepo = path.join(tmpBase, "repo");
      const siblingRuntime = path.join(tmpBase, "runtime");
      fs.mkdirSync(path.join(fakeRepo, ".git"), { recursive: true });

      const paths = resolveRuntimeDir(siblingRuntime, { repoRoot: fakeRepo });
      expect(paths.rootDir).toBe(fs.realpathSync(tmpBase) + path.sep + "runtime");
      expect(paths.telemetryDbPath).toBe(
        path.join(paths.rootDir, "telemetry", "hunt_telemetry.sqlite"),
      );
      expect(paths.daemonStateDbPath).toBe(path.join(paths.rootDir, "state", "hunt_daemon.sqlite"));

      const worktreeRoot = path.join(tmpBase, ".worktrees", "slice1");
      fs.mkdirSync(worktreeRoot, { recursive: true });
      fs.writeFileSync(path.join(worktreeRoot, ".git"), "gitdir: ../../repo/.git/worktrees/slice1\n");
      const prevEnv = process.env.HUNT_COMMAND_RUNTIME_DIR;
      delete process.env.HUNT_COMMAND_RUNTIME_DIR;
      try {
        const wtPaths = resolveRuntimeDir(undefined, { repoRoot: worktreeRoot });
        expect(wtPaths.rootDir).toBe(fs.realpathSync(tmpBase) + path.sep + "runtime");
      } finally {
        if (prevEnv !== undefined) {
          process.env.HUNT_COMMAND_RUNTIME_DIR = prevEnv;
        }
      }
    } finally {
      fs.rmSync(tmpBase, { recursive: true, force: true });
    }
  });
});

describe("ROLE_TOOL_OWNERSHIP and DataPlaneAccessError", () => {
  test("covers all 6 specialist roles and enforces exact tool ownership", () => {
    expect(Object.keys(ROLE_TOOL_OWNERSHIP).sort()).toEqual([...AGENT_ROLES].sort());
    expect(AGENT_ROLES).toHaveLength(6);
    expect(DATA_PLANE_TOOLS).toHaveLength(9);

    expect(ROLE_TOOL_OWNERSHIP.coordinator).toEqual([]);
    expect(ROLE_TOOL_OWNERSHIP.network_analyst).toEqual([
      "arkime_sessions",
      "arkime_unique",
      "hunt_lab_query",
      "lab_browser",
      "packet_fields",
    ]);

    const browserOwners = AGENT_ROLES.filter((role) => canRoleUseTool(role, "lab_browser"));
    expect(browserOwners).toEqual(["threat_hunter", "network_analyst"]);

    expect(() => assertRoleOwnsTool("coordinator", "elastic_search")).toThrow(DataPlaneAccessError);
    try {
      assertRoleOwnsTool("host_analyst", "packet_fields");
    } catch (err) {
      expect(err).toBeInstanceOf(DataPlaneAccessError);
      expect((err as DataPlaneAccessError).statusCode).toBe(403);
      expect((err as DataPlaneAccessError).errorCode).toBe("tool_not_owned");
    }

    try {
      assertReadOnlyOperation(true);
    } catch (err) {
      expect(err).toBeInstanceOf(DataPlaneAccessError);
      expect((err as DataPlaneAccessError).statusCode).toBe(405);
      expect((err as DataPlaneAccessError).errorCode).toBe("read_only");
    }
  });
});

describe("computeShadowCostUsd vs $0 OAuth billing", () => {
  test("computes exact API-equivalent shadow cost while billing $0.00 in oauth_subscription mode", () => {
    const usage = {
      inputTokens: 100_000,
      outputTokens: 20_000,
      cacheReadTokens: 500_000,
      cacheWriteTokens: 40_000,
    };

    // claude-sonnet-4-6:
    // input:       0.10 * $3.00  = $0.30
    // output:      0.02 * $15.00 = $0.30
    // cacheRead:   0.50 * $0.30  = $0.15
    // cacheWrite:  0.04 * $3.75  = $0.15
    // total shadow API cost      = $0.90
    const shadow = computeShadowCostUsd("anthropic/claude-sonnet-4-6-20260514", usage);
    expect(shadow).toBe(0.9);

    const oauthSummary = computeCostAccounting("anthropic/claude-sonnet-4-6", usage);
    expect(oauthSummary.billingMode).toBe("oauth_subscription");
    expect(oauthSummary.actualBilledUsd).toBe(0);
    expect(oauthSummary.shadowApiUsd).toBe(0.9);
    // 500k cacheRead at $0.30/M ($0.15) vs $3.00/M ($1.50) saves $1.35
    expect(oauthSummary.cacheSavingsUsd).toBe(1.35);

    const apiSummary = computeCostAccounting("claude-sonnet-4-6", usage, "api_key");
    expect(apiSummary.actualBilledUsd).toBe(0.9);
    expect(apiSummary.shadowApiUsd).toBe(0.9);
  });
});

describe("Ontology, case origin, and human gate invariants", () => {
  test("enforces source_id in claim.evidence_ids and extracts inline evt/frame/ioc citations", () => {
    const validClaim = ClaimSchema.parse({
      claim_id: "clm-001",
      wave: "evidence",
      author_role: "network_analyst",
      statement:
        "TLS 1.3 beacon observed in evt-991a2b, packet frame-42, matching feed entry ioc-00123.",
      evidence_ids: ["lab-case-med-021"],
      entities: ["10.10.4.22", "cdn-sync-check.example"],
      confidence: "high",
    });
    expect(validClaim.evidence_ids).toEqual(["lab-case-med-021"]);

    expect(() =>
      ClaimSchema.parse({
        ...validClaim,
        evidence_ids: ["evt-991a2b"],
      }),
    ).toThrow();

    const lineage = extractInlineCitations(validClaim.statement);
    expect(lineage).toEqual({
      event_ids: ["evt-991a2b"],
      frame_ids: ["frame-42"],
      ioc_ids: ["ioc-00123"],
    });
  });

  test("rejects automated approvals on human scope/incident/reconcile gates and enforces egress mode", () => {
    const baseDecision = {
      decision_id: "dec-001",
      hunt_id: "hunt-001",
      action: "approve" as const,
      decided_by: "operator@local",
      rbac_role: "lead_operator",
      payload_sha256: "a".repeat(64),
      decided_at: "2026-11-15T00:00:00Z",
      expires_at: "2026-11-15T01:00:00Z",
    };

    expect(() =>
      AuthenticatedGateDecisionSchema.parse({
        ...baseDecision,
        gate: "scope",
        via: "automated",
      }),
    ).toThrow();

    expect(() =>
      AuthenticatedGateDecisionSchema.parse({
        ...baseDecision,
        gate: "incident",
        via: "automated",
      }),
    ).toThrow();

    const intermediateAuto = AuthenticatedGateDecisionSchema.parse({
      ...baseDecision,
      gate: "evidence_review",
      via: "automated",
    });
    expect(intermediateAuto.via).toBe("automated");

    expect(
      CaseMetadataSchema.safeParse({
        case_id: "real-win-002",
        title: "DEDALE Windows Lab",
        data_origin: "public-dataset",
        synthetic_only: true,
        time_window: { start_iso: "2026-11-01T00:00:00Z", end_iso: "2026-11-02T00:00:00Z" },
        sources: ["dedale-evtx"],
      }).success,
    ).toBe(false);

    expect(resolveEgressCardMode(true)).toBe("full_synthetic");
    expect(resolveEgressCardMode(false)).toBe("id_and_status_only");
  });
});
