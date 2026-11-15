import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  AGG_FIELDS,
  ARKIME_DEFAULT_FIELDS,
  ARKIME_SESSION_FIELDS,
  ARKIME_UNIQUE_FIELDS,
  AuthenticatedGateDecisionSchema,
  BATCH_EXCLUDED_TOOLS,
  BATCH_MAX_BYTES,
  BATCH_MAX_ITEMS,
  BATCH_MAX_ITEM_SIZE,
  CLAIM_KINDS,
  CaseMetadataSchema,
  ClaimSchema,
  DATA_PLANE_TOOLS,
  DEFAULT_FOLLOW_UPS,
  DISPOSITIONS,
  DataPlaneAccessError,
  ENTITY_KINDS,
  EVENT_FIELDS,
  FRAMEWORK_PROFILES,
  HUNT_WAVES,
  HUNT_WAVE_TOPOLOGY,
  HandoffSchema,
  INTEL_FIELDS,
  KEYWORD_FIELDS,
  MAX_FOLLOW_UPS,
  PACKET_FIELDS,
  PACKET_FILTER_FIELDS,
  PREDICATES,
  PROFILE_DISPLAY_TITLES,
  ROLE_TOOL_OWNERSHIP,
  ReviewSchema,
  RuntimeFenceError,
  SEARCH_FIELDS,
  SnapshotSchema,
  assertReadOnlyOperation,
  assertRoleOwnsTool,
  canRoleUseTool,
  computeCostAccounting,
  computeShadowCostUsd,
  extractInlineCitations,
  getAllowedToolsForStep,
  isAllowedSearchField,
  resolveEgressCardMode,
  resolveRuntimeDir,
  resolveWorkspaceTempDir,
} from "../src/index.ts";

describe("resolveWorkspaceTempDir keeps scratch files in the workspace", () => {
  function withTempOverride<T>(value: string | undefined, run: () => T): T {
    const saved = process.env.HUNT_COMMAND_TEMP_DIR;
    if (value === undefined) delete process.env.HUNT_COMMAND_TEMP_DIR;
    else process.env.HUNT_COMMAND_TEMP_DIR = value;
    try {
      return run();
    } finally {
      if (saved === undefined) delete process.env.HUNT_COMMAND_TEMP_DIR;
      else process.env.HUNT_COMMAND_TEMP_DIR = saved;
    }
  }

  test("defaults to a tmp folder beside the runtime directory, not inside it, and creates it", () => {
    const base = fs.mkdtempSync(path.join(os.tmpdir(), "hunt-cmd-wstmp-"));
    try {
      const runtime = path.join(base, "runtime");
      const tempDir = withTempOverride(undefined, () => resolveWorkspaceTempDir(runtime));
      expect(tempDir).toBe(path.join(fs.realpathSync(base), "tmp"));
      expect(fs.statSync(tempDir).isDirectory()).toBe(true);
      expect(tempDir.startsWith(fs.realpathSync(base) + path.sep + "runtime")).toBe(false);
    } finally {
      fs.rmSync(base, { recursive: true, force: true });
    }
  });

  test("HUNT_COMMAND_TEMP_DIR overrides the location", () => {
    const base = fs.mkdtempSync(path.join(os.tmpdir(), "hunt-cmd-wstmp-"));
    try {
      const chosen = path.join(base, "elsewhere");
      const tempDir = withTempOverride(chosen, () => resolveWorkspaceTempDir(path.join(base, "runtime")));
      expect(tempDir).toBe(path.join(fs.realpathSync(base), "elsewhere"));
    } finally {
      fs.rmSync(base, { recursive: true, force: true });
    }
  });

  test("refuses a temp folder inside a Git tree and creates nothing there", () => {
    const base = fs.mkdtempSync(path.join(os.tmpdir(), "hunt-cmd-wstmp-"));
    try {
      const fakeRepo = path.join(base, "repo");
      fs.mkdirSync(path.join(fakeRepo, ".git"), { recursive: true });
      // A runtime directory directly inside a checkout would put `tmp` in the checkout too.
      expect(() => withTempOverride(undefined, () => resolveWorkspaceTempDir(path.join(fakeRepo, "runtime")))).toThrow(
        RuntimeFenceError,
      );
      expect(() => withTempOverride(path.join(fakeRepo, "scratch"), () => resolveWorkspaceTempDir())).toThrow(
        RuntimeFenceError,
      );
      expect(fs.existsSync(path.join(fakeRepo, "tmp"))).toBe(false);
      expect(fs.existsSync(path.join(fakeRepo, "scratch"))).toBe(false);
    } finally {
      fs.rmSync(base, { recursive: true, force: true });
    }
  });
});

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

  test("accepts an outside-git ../runtime sibling directory and resolves worktree defaults", () => {
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
      fs.writeFileSync(
        path.join(worktreeRoot, ".git"),
        "gitdir: ../../repo/.git/worktrees/slice1\n",
      );
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

describe("Canonical FRAMEWORK_PROFILES, ROLE_TOOL_OWNERSHIP, and 8-Wave Topology", () => {
  test("matches all 6 canonical framework profiles, tool ownership, and batch caps", () => {
    expect(FRAMEWORK_PROFILES).toEqual([
      "framework-coordinator",
      "framework-researcher",
      "framework-network-analyst",
      "framework-librarian",
      "framework-builder",
      "framework-reviewer",
    ]);
    expect(Object.keys(PROFILE_DISPLAY_TITLES).sort()).toEqual([...FRAMEWORK_PROFILES].sort());
    expect(DATA_PLANE_TOOLS).toHaveLength(9);

    expect(ROLE_TOOL_OWNERSHIP["framework-coordinator"]).toEqual(["delegate_task"]);
    expect(getAllowedToolsForStep("framework-coordinator", "scope")).toEqual([]);
    expect(getAllowedToolsForStep("framework-coordinator", "analysis")).toEqual(["delegate_task"]);

    expect(ROLE_TOOL_OWNERSHIP["framework-researcher"]).toEqual([
      "elastic_search",
      "elastic_aggregate",
      "lab_browser",
      "packet_fields",
      "hunt_lab_batch",
    ]);
    expect(ROLE_TOOL_OWNERSHIP["framework-network-analyst"]).toEqual([
      "arkime_sessions",
      "arkime_unique",
      "hunt_lab_query",
      "lab_browser",
      "packet_fields",
      "hunt_lab_batch",
    ]);
    expect(ROLE_TOOL_OWNERSHIP["framework-librarian"]).toEqual([
      "intel_lookup",
      "elastic_aggregate",
    ]);
    expect(ROLE_TOOL_OWNERSHIP["framework-builder"]).toEqual([
      "detection_test",
      "elastic_aggregate",
    ]);
    expect(ROLE_TOOL_OWNERSHIP["framework-reviewer"]).toEqual([
      "elastic_search",
      "arkime_sessions",
      "detection_test",
    ]);

    expect(BATCH_MAX_ITEMS).toBe(5);
    expect(BATCH_MAX_ITEM_SIZE).toBe(25);
    expect(BATCH_MAX_BYTES).toBe(96 * 1024);
    expect(BATCH_EXCLUDED_TOOLS).toEqual(["packet_fields", "lab_browser", "hunt_lab_batch"]);

    const browserOwners = FRAMEWORK_PROFILES.filter((role) => canRoleUseTool(role, "lab_browser"));
    expect(browserOwners).toEqual(["framework-researcher", "framework-network-analyst"]);

    expect(() =>
      assertRoleOwnsTool("framework-coordinator", "delegate_task", "scope"),
    ).toThrow(DataPlaneAccessError);

    try {
      assertRoleOwnsTool("framework-librarian", "packet_fields");
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

  test("defines exact 8-wave topology with Gate 1 (scope) and Gate 2 (incident)", () => {
    expect(HUNT_WAVES).toEqual([
      "scope",
      "investigation",
      "analysis",
      "follow_up",
      "merge",
      "detection",
      "purple",
      "incident",
    ]);
    expect(HUNT_WAVE_TOPOLOGY).toHaveLength(8);
    expect(HUNT_WAVE_TOPOLOGY[0]?.humanGate).toBe("scope");
    expect(HUNT_WAVE_TOPOLOGY[1]?.defaultSteps).toEqual([
      { stepIdPattern: "evidence", profile: "framework-researcher" },
      { stepIdPattern: "hypotheses", profile: "framework-builder" },
      { stepIdPattern: "network", profile: "framework-network-analyst" },
      { stepIdPattern: "intel", profile: "framework-librarian" },
    ]);
    expect(HUNT_WAVE_TOPOLOGY[7]?.humanGate).toBe("incident");
    expect(DEFAULT_FOLLOW_UPS).toBe(6);
    expect(MAX_FOLLOW_UPS).toBe(12);
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

    const shadow = computeShadowCostUsd("anthropic/claude-sonnet-4-6-20260514", usage);
    expect(shadow).toBe(0.9);

    const oauthSummary = computeCostAccounting("anthropic/claude-sonnet-4-6", usage);
    expect(oauthSummary.billingMode).toBe("oauth_subscription");
    expect(oauthSummary.actualBilledUsd).toBe(0);
    expect(oauthSummary.shadowApiUsd).toBe(0.9);
    expect(oauthSummary.cacheSavingsUsd).toBe(1.35);

    const apiSummary = computeCostAccounting("claude-sonnet-4-6", usage, "api_key");
    expect(apiSummary.actualBilledUsd).toBe(0.9);
    expect(apiSummary.shadowApiUsd).toBe(0.9);
  });
});

describe("Canonical ontology.py schemas, lab_server.py allowlists, and human gates", () => {
  test("validates exact Snapshot, Claim, Review, and Handoff shapes from ontology.py", () => {
    expect(ENTITY_KINDS).toHaveLength(9);
    expect(PREDICATES).toHaveLength(5);
    expect(CLAIM_KINDS).toEqual(["observed", "inference", "hypothesis", "finding"]);
    expect(DISPOSITIONS).toEqual(["needs_revision", "needs_validation", "review_ready"]);

    const snap = SnapshotSchema.parse({
      schema_version: 1,
      case_id: "team-med-021",
      entities: [
        {
          entity_id: "host:ws-01",
          kind: "host",
          label: "WORKSTATION-01",
          evidence_ids: ["team-med-021:summary"],
        },
        {
          entity_id: "addr:10.10.4.22",
          kind: "address",
          label: "10.10.4.22",
          evidence_ids: ["team-med-021:summary"],
        },
      ],
      relations: [
        {
          relation_id: "rel:1",
          subject_id: "host:ws-01",
          predicate: "communicates_with",
          object_id: "addr:10.10.4.22",
          evidence_ids: ["team-med-021:summary"],
        },
      ],
    });
    expect(snap.entities).toHaveLength(2);

    const validClaim = ClaimSchema.parse({
      claim_id: "network:c1",
      kind: "observed",
      statement:
        "malicious: TLS 1.3 beacon observed in evt-991a2b, packet frame-42, matching ioc-00123.",
      evidence_ids: ["team-med-021:summary"],
      entity_ids: ["host:ws-01", "addr:10.10.4.22"],
      contradicts: [],
    });
    expect(validClaim.evidence_ids).toEqual(["team-med-021:summary"]);

    // Rejects unexpected keys (.strict()) and raw evt-* in evidence_ids
    expect(() =>
      ClaimSchema.parse({
        ...validClaim,
        extra_key: true,
      }),
    ).toThrow();
    expect(() =>
      ClaimSchema.parse({
        ...validClaim,
        evidence_ids: ["evt-991a2b"],
      }),
    ).toThrow();

    const reviewerHandoff = HandoffSchema.parse({
      schema_version: 1,
      case_id: "team-med-021",
      step_id: "purple",
      profile: "framework-reviewer",
      claims: [],
      reviews: [
        ReviewSchema.parse({
          review_id: "purple:r1",
          claim_ids: ["network:c1"],
          disposition: "review_ready",
          rationale: "Re-ran arkime_sessions and reproduced evt-991a2b.",
          evidence_ids: ["team-med-021:summary"],
        }),
      ],
      disposition: "review_ready",
      limitations: ["Packet payload excluded by ADR-0003."],
      requested_decisions: [],
    });
    expect(reviewerHandoff.reviews).toHaveLength(1);

    // Non-reviewer cannot supply reviews
    expect(() =>
      HandoffSchema.parse({
        ...reviewerHandoff,
        step_id: "network",
        profile: "framework-network-analyst",
      }),
    ).toThrow();

    expect(extractInlineCitations(validClaim.statement)).toEqual({
      event_ids: ["evt-991a2b"],
      frame_ids: ["frame-42"],
      ioc_ids: ["ioc-00123"],
    });
  });

  test("matches exact lab_server.py field allowlist counts and filter exclusions", () => {
    expect(EVENT_FIELDS).toHaveLength(22);
    expect(KEYWORD_FIELDS).toHaveLength(113);
    expect(AGG_FIELDS.size).toBe(KEYWORD_FIELDS.length);
    expect(SEARCH_FIELDS.size).toBe(KEYWORD_FIELDS.length + 6);
    expect(isAllowedSearchField("powershell.file.script_block_text")).toBe(true);
    expect(isAllowedSearchField("labels.mitre_tactic_1")).toBe(true);
    expect(isAllowedSearchField("labels.INVALID-UPPER")).toBe(false);
    expect(INTEL_FIELDS).toHaveLength(7);
    expect(ARKIME_SESSION_FIELDS).toHaveLength(24);
    expect(ARKIME_DEFAULT_FIELDS).toHaveLength(12);
    expect(ARKIME_UNIQUE_FIELDS.size).toBe(18);
    expect(PACKET_FIELDS).toHaveLength(38);
    expect(PACKET_FIELDS).toContain("tls.handshake.ja4");
    expect(PACKET_FIELDS).toContain("kerberos.CNameString");
    expect(PACKET_FIELDS).toContain("_ws.col.Protocol");
    expect(PACKET_FILTER_FIELDS.size).toBe(36);
    expect(PACKET_FILTER_FIELDS.has("_ws.col.Protocol")).toBe(false);
    expect(PACKET_FILTER_FIELDS.has("http.request.uri")).toBe(false);
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
