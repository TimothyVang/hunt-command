import { describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import {
  blamesDecoy,
  deriveAlternativeGroups,
  deriveSiblingGroups,
  factCitations,
  loadJsonText,
  names,
  scoreReport,
  validateTruth,
  type ScenarioTruth,
} from "../src/index.ts";

const DEFAULT_REF_REPO =
  process.env.HUNT_PR4_REFERENCE_REPO ??
  "C:/Users/newbi/Desktop/bot-framework/hermes-hunt-bots/repo";

function loadPythonScenarioSource(): string | null {
  if (!fs.existsSync(path.join(DEFAULT_REF_REPO, ".git"))) {
    return null;
  }
  const gitRes = spawnSync(
    "git",
    [
      "-C",
      DEFAULT_REF_REPO,
      "show",
      "saved/pr4-coach:framework/hunt_lab/scenario.py",
    ],
    {
      encoding: "utf8",
      windowsHide: true,
    },
  );
  if (gitRes.status !== 0 || !gitRes.stdout) {
    return null;
  }
  return gitRes.stdout;
}

const PYTHON_DRIVER = [
  "import json, sys",
  "payload = json.loads(sys.stdin.read())",
  "ns = {'__name__': 'hunt_lab_scenario_ref'}",
  "exec(compile(payload['scenario_source'], 'scenario.py', 'exec'), ns)",
  "score_report = ns['score_report']",
  "_blames_decoy = ns['_blames_decoy']",
  "scored_cases = [score_report(item['truth'], item['report']) for item in payload['cases']]",
  "blames_cases = [_blames_decoy(s.lower()) for s in payload['statements']]",
  "sys.stdout.write(json.dumps({'scored': scored_cases, 'blames': blames_cases}, sort_keys=True))",
].join("\n");

function runPythonBatch(
  scenarioSource: string,
  cases: ReadonlyArray<{ truth: ScenarioTruth; report: Record<string, unknown> }>,
  statements: readonly string[],
): {
  scored: unknown[];
  blames: boolean[];
} {
  const pyCmd = process.platform === "win32" ? "py" : "python3";
  const pyArgs =
    process.platform === "win32"
      ? ["-3", "-c", PYTHON_DRIVER]
      : ["-c", PYTHON_DRIVER];
  const res = spawnSync(pyCmd, pyArgs, {
    input: JSON.stringify({
      scenario_source: scenarioSource,
      cases,
      statements,
    }),
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    windowsHide: true,
  });

  if (res.status !== 0) {
    throw new Error(
      `Python scenario.py differential runner failed (exit ${res.status}): ${res.stderr || res.stdout}`,
    );
  }
  return JSON.parse(res.stdout) as { scored: unknown[]; blames: boolean[] };
}

const SYNTHETIC_TRUTH_FULL: ScenarioTruth = {
  schema_version: 1,
  case_id: "synth-diff-001",
  facts: [
    {
      fact_id: "attack.initial.phish-exec",
      kind: "attack",
      entities: {
        host: ["ws-fin-04"],
        account: ["j.mercer"],
      },
      evidence_event_groups: [
        ["evt-000101", "evt-000102"],
        ["evt-000109"],
      ],
      evidence_frame_groups: [["frame-42", "frame-43"], ["frame-88"]],
      evidence_intel_groups: [["ioc-00011"], []],
      evidence_sibling_groups: [["evt-000150"], ["evt-000199"]],
    },
    {
      fact_id: "attack.c2.beacon-channel",
      kind: "attack",
      entities: {
        host: ["ws-fin-04"],
        domain: ["cdn-sync.amber-ridge.test"],
        address: ["198.51.100.77"],
      },
      evidence_event_groups: [
        ["evt-000210"],
        ["evt-000220", "evt-000221"],
      ],
      evidence_frame_groups: [["frame-9", "frame-120"], ["frame-145"]],
      evidence_intel_groups: [["ioc-00025"], []],
      evidence_sibling_groups: [[], ["evt-000229"]],
    },
    {
      fact_id: "decoy.it.nightly-backup",
      kind: "decoy",
      entities: {
        // ws-fin-04 is shared with attack_entities, so ONLY bk-nas-01 & svc-backup are distinctive decoy entities!
        host: ["ws-fin-04", "bk-nas-01"],
        account: ["svc-backup"],
      },
      evidence_event_groups: [["evt-000310", "evt-000311"]],
      evidence_frame_groups: [["frame-310"]],
      evidence_intel_groups: [[]],
      evidence_sibling_groups: [[]],
    },
    {
      fact_id: "decoy.sec.vuln-scanner",
      kind: "decoy",
      entities: {
        host: ["scan-ops-02"],
        address: ["10.20.99.5"],
      },
      evidence_event_groups: [["evt-000410"]],
    },
    {
      fact_id: "coverage.telemetry.edr-gap",
      kind: "coverage",
      entities: {
        host: ["legacy-prn-01"],
      },
      evidence_event_groups: [["evt-000501"]],
    },
  ],
};

const CONTRAST_AND_HEDGE_STATEMENTS: readonly string[] = [
  // 1. Plain compromise blame -> true
  "Host scan-ops-02 conducted malicious lateral movement across the subnet.",
  // 2. Plain affirmative benign without compromise -> false
  "Traffic from scan-ops-02 is authorized vulnerability scanning.",
  // 3. Hedged benign ('unlikely to be benign') + compromise -> true
  "Activity on scan-ops-02 is unlikely to be benign and indicates compromise.",
  // 4. Post-hedged benign ('benign possibility') + compromise -> true
  "A benign possibility was considered for scan-ops-02; attacker C2 remains active.",
  // 5. Negated benign ('not benign') + compromise -> true
  "The session from scan-ops-02 is not benign and reflects adversary backdoor activity.",
  // 6. Leading compromise label zeroes benign credit -> true
  "Malicious: scan-ops-02 mimicked a routine administrative task.",
  // 7. Leading compromised( label zeroes benign credit -> true
  "Compromised (scan-ops-02): despite scheduled backup schedule, implant ran.",
  // 8. Contrast pivot clearing decoy after 'however' -> false
  "Initial alerts flagged scan-ops-02 as potential command and control, however packet inspection confirmed it is an authorized scanner.",
  // 9. Contrast pivot blaming decoy after 'but' -> true
  "scan-ops-02 looked routine at first, but deeper analysis confirmed malicious implant execution.",
  // 10. Pre-window negation ('ruled out compromise') -> false
  "We ruled out compromise and lateral movement on bk-nas-01 after reviewing change tickets.",
  // 11. Post-window passive negation ('intrusion was ruled out') -> false
  "Potential intrusion on bk-nas-01 was ruled out via backup logs.",
  // 12. Post-window double-negative ('not ruled out') -> true!
  "Possible intrusion from scan-ops-02 was not ruled out during triage.",
  // 13. Pre-window 'resembles' + contrast pivot 'yet' -> false
  "Burst traffic on bk-nas-01 resembles exfiltration at high volume, yet it is a scheduled backup.",
  // 14. Pre-window 'false positive for' -> false
  "The alert on scan-ops-02 is a false positive for brute force.",
];

const DIFFERENTIAL_CASES: ReadonlyArray<{
  name: string;
  truth: ScenarioTruth;
  report: Record<string, unknown>;
}> = [
  {
    name: "strict-all-found-via-mixed-evt-frame-ioc-and-coverage-limitations",
    truth: SYNTHETIC_TRUTH_FULL,
    report: {
      case_id: "synth-diff-001",
      claims: [
        {
          claim_id: "incident:c1",
          statement:
            "Account j.mercer on ws-fin-04 executed payload (ioc-00011, Frame-000088).",
          evidence_ids: ["src-1"],
          entity_ids: ["ws-fin-04", "j.mercer"],
        },
        {
          claim_id: "incident:c2",
          statement:
            "ws-fin-04 beaconed to cdn-sync.amber-ridge.test (198.51.100.77) in frame-120, Frame-009, and frame-145.",
          evidence_ids: ["src-2"],
          entity_ids: ["ws-fin-04"],
        },
        {
          claim_id: "incident:c3",
          statement:
            "Nightly transfer between ws-fin-04 and bk-nas-01 under svc-backup (evt-000310) is a scheduled backup and not malicious.",
          evidence_ids: ["src-3"],
          entity_ids: ["bk-nas-01", "svc-backup"],
        },
        {
          claim_id: "incident:c4",
          statement:
            "Traffic from scan-ops-02 (10.20.99.5) in evt-000410 initially looked like brute force, however it was confirmed to be an authorized internal scan.",
          evidence_ids: ["src-4"],
          entity_ids: ["scan-ops-02"],
        },
      ],
      limitations: [
        "Host legacy-prn-01 lacked endpoint agent telemetry after evt-000501.",
      ],
    },
  },
  {
    name: "anti-citation-spraying-blocks-unscoped-claim-dump",
    truth: SYNTHETIC_TRUTH_FULL,
    report: {
      case_id: "synth-diff-001",
      claims: [
        {
          claim_id: "incident:c1",
          statement: "Workstation ws-fin-04 was reviewed by analysts.",
          evidence_ids: ["src-1"],
          entity_ids: ["ws-fin-04"],
        },
        {
          claim_id: "incident:c2",
          statement:
            "Unrelated index sweep observed evt-000101, evt-000109, evt-000210, evt-000220, evt-000310, evt-000410.",
          evidence_ids: ["src-2"],
          entity_ids: ["other-host"],
        },
      ],
      limitations: [],
    },
  },
  {
    name: "sibling-events-credit-with_siblings-only-never-strict-found",
    truth: SYNTHETIC_TRUTH_FULL,
    report: {
      case_id: "synth-diff-001",
      claims: [
        {
          claim_id: "incident:c1",
          statement:
            "Malicious execution under j.mercer on ws-fin-04 recorded in evt-000150 and evt-000199.",
          evidence_ids: ["src-1"],
          entity_ids: ["ws-fin-04", "j.mercer"],
        },
        {
          claim_id: "incident:c2",
          statement:
            "C2 beacon to cdn-sync.amber-ridge.test in evt-000210 and sibling evt-000229.",
          evidence_ids: ["src-2"],
          entity_ids: ["cdn-sync.amber-ridge.test"],
        },
      ],
      limitations: [],
    },
  },
  {
    name: "decoy-misattribution-contrast-hedges-and-shared-attack-entity-immunity",
    truth: SYNTHETIC_TRUTH_FULL,
    report: {
      case_id: "synth-diff-001",
      claims: [
        {
          claim_id: "incident:c1",
          statement:
            "Host ws-fin-04 was compromised by an attacker implant in evt-000101 and evt-000109.",
          evidence_ids: ["src-1"],
          entity_ids: ["ws-fin-04"],
        },
        {
          claim_id: "incident:c2",
          statement:
            "Activity from scan-ops-02 in evt-000410 is unlikely benign and shows lateral movement.",
          evidence_ids: ["src-2"],
          entity_ids: ["scan-ops-02"],
        },
        {
          claim_id: "incident:c3",
          statement:
            "Malicious: svc-backup transfer to bk-nas-01 in evt-000310 disguised as scheduled backup.",
          evidence_ids: ["src-3"],
          entity_ids: ["svc-backup", "bk-nas-01"],
        },
      ],
      limitations: [],
    },
  },
  {
    name: "coverage-fact-credits-citations-split-across-claim-and-limitation",
    truth: SYNTHETIC_TRUTH_FULL,
    report: {
      case_id: "synth-diff-001",
      claims: [
        {
          claim_id: "incident:c1",
          statement: "Print server legacy-prn-01 had partial visibility.",
          evidence_ids: ["src-1"],
          entity_ids: ["legacy-prn-01"],
        },
      ],
      limitations: ["Visibility cut off immediately after heartbeat evt-000501."],
    },
  },
];

describe("packages/coach scorer & Python saved/pr4-coach differential parity", () => {
  test("100% identical JSON output between TypeScript scoreReport/blamesDecoy and Python scenario.py", () => {
    const scenarioPySource = loadPythonScenarioSource();
    expect(scenarioPySource).not.toBeNull();

    const pyResults = runPythonBatch(
      scenarioPySource!,
      DIFFERENTIAL_CASES.map((c) => ({ truth: c.truth, report: c.report })),
      CONTRAST_AND_HEDGE_STATEMENTS,
    );

    for (let i = 0; i < CONTRAST_AND_HEDGE_STATEMENTS.length; i++) {
      const stmt = CONTRAST_AND_HEDGE_STATEMENTS[i]!;
      const tsBlame = blamesDecoy(stmt);
      expect(tsBlame).toBe(pyResults.blames[i]!);
    }

    for (let i = 0; i < DIFFERENTIAL_CASES.length; i++) {
      const tc = DIFFERENTIAL_CASES[i]!;
      const tsScore = JSON.parse(JSON.stringify(scoreReport(tc.truth, tc.report)));
      const pyScore = pyResults.scored[i];
      expect(tsScore).toEqual(pyScore);
    }
  });

  test("entity-scoped factCitations blocks citation spraying and enforces token boundaries", () => {
    expect(names("user admin logged in", "admin")).toBe(true);
    expect(names("user sysadmin logged in", "admin")).toBe(false);
    expect(names("source ip 10.40.2.15 connected", "10.40.2.15")).toBe(true);
    expect(names("source ip 110.40.2.15 connected", "10.40.2.15")).toBe(false);
    expect(names("host c2.alpha.example resolved", "c2.alpha.example")).toBe(true);
    expect(names("host c2.alpha.example.org resolved", "c2.alpha.example")).toBe(false);

    const perClaim = [
      {
        low: "unrelated host other-ws had evt-000101 and evt-000109",
        ids: new Set(["evt-000101", "evt-000109"]),
      },
      {
        low: "workstation ws-fin-04 saw evt-000102",
        ids: new Set(["evt-000102"]),
      },
    ];
    const allClaimIds = new Set(["evt-000101", "evt-000109", "evt-000102"]);
    const limitationIds = new Set(["evt-000501"]);

    const nonCoverageScoped = factCitations(
      false,
      ["ws-fin-04", "j.mercer"],
      perClaim,
      allClaimIds,
      limitationIds,
    );
    expect([...nonCoverageScoped]).toEqual(["evt-000102"]);

    const coverageScoped = factCitations(
      true,
      ["legacy-prn-01"],
      perClaim,
      allClaimIds,
      limitationIds,
    );
    expect(coverageScoped.has("evt-000501")).toBe(true);
    expect(coverageScoped.has("evt-000101")).toBe(true);
  });

  test("with_siblings stays strictly segregated from top-level found, by_kind, and decoys_cleared", () => {
    const siblingCase = DIFFERENTIAL_CASES[2]!;
    const scored = scoreReport(siblingCase.truth, siblingCase.report);

    expect(scored.found).toBe(0);
    expect(scored.by_kind.attack?.found).toBe(0);
    expect(scored.with_siblings).toBeDefined();
    expect(scored.with_siblings?.found).toBe(2);
    expect(scored.with_siblings?.by_kind.attack?.found).toBe(2);
  });

  test("loadJsonText parses fenced json blocks and rejects duplicate keys and non-finite numbers", () => {
    const fenced = '```json\n{"ok": true, "nested": {"count": 3}}\n```';
    expect(loadJsonText(fenced)).toEqual({ ok: true, nested: { count: 3 } });

    expect(() => loadJsonText('{"a": 1, "a": 2}')).toThrow(/duplicate JSON key: a/);
    expect(() =>
      loadJsonText('{"outer": {"dup": "first", "safe": 1, "dup": "second"}}'),
    ).toThrow(/duplicate JSON key: dup/);
    expect(() => loadJsonText('{"val": NaN}')).toThrow();
    expect(() => loadJsonText('{"val": Infinity}')).toThrow();
    expect(() => loadJsonText('{"val": -Infinity}')).toThrow();
  });

  test("deriveAlternativeGroups enforces group-0-only intel deduplication per fact (HUNT-BOTS.md:54) and deriveSiblingGroups excludes group collisions", () => {
    const alt = deriveAlternativeGroups({
      facts: [
        {
          fact_id: "attack.c2.one",
          entities: { domains: ["beacon.mal.test"], ips: ["198.51.100.99"] },
        },
      ],
      groupSessionsByFact: {
        "attack.c2.one": [[0], [1]],
      },
      sessionFrames: {
        0: [12, 4],
        1: [105],
      },
      sessionValues: {
        0: ["beacon.mal.test"],
        1: ["beacon.mal.test"],
      },
      intelDocs: [
        {
          id: "ioc-00007",
          indicator: {
            type: "domain",
            value: "beacon.mal.test",
          },
        },
      ],
    });

    expect(alt["attack.c2.one"]?.evidence_frame_groups).toEqual([
      ["frame-4", "frame-12"],
      ["frame-105"],
    ]);
    // Same ioc-00007 matches both session 0 and session 1, so ONLY group 0 receives it!
    expect(alt["attack.c2.one"]?.evidence_intel_groups).toEqual([
      ["ioc-00007"],
      [],
    ]);

    const siblings = deriveSiblingGroups({
      facts: [
        { fact_id: "attack.c2.one", kind: "attack" },
        { fact_id: "decoy.it.two", kind: "decoy" },
      ],
      groupSeqsByFact: {
        "attack.c2.one": [[1], [2]],
        "decoy.it.two": [[9]],
      },
      startedProcessBySeq: {
        1: "proc-attack-1",
      },
      processCategorySeqs: [
        {
          processEntityId: "proc-attack-1",
          category: "network",
          // seq 1 is accepted in group 0; seq 3 is sibling of group 0 only
          seqs: [1, 3],
        },
        {
          processEntityId: "proc-attack-1",
          category: "process",
          // seq 2 is accepted in group 1; seq 4 is sibling of group 1 only
          seqs: [2, 4],
        },
      ],
      eventIdsBySeq: {
        1: "evt-000001",
        2: "evt-000002",
        3: "evt-000003",
        4: "evt-000004",
        9: "evt-000009",
      },
    });

    expect(siblings["attack.c2.one"]).toEqual([["evt-000003"], ["evt-000004"]]);
    expect(siblings["decoy.it.two"]).toEqual([[]]);

    const sampleTruth: ScenarioTruth = {
      schema_version: 1,
      case_id: "synth-derive-001",
      facts: [
        {
          fact_id: "attack.c2.one",
          kind: "attack",
          entities: { domains: ["beacon.mal.test"] },
          evidence_event_groups: [["evt-000001"], ["evt-000002"]],
          evidence_frame_groups: alt["attack.c2.one"]!.evidence_frame_groups,
          evidence_intel_groups: alt["attack.c2.one"]!.evidence_intel_groups,
          evidence_sibling_groups: siblings["attack.c2.one"]!,
        },
      ],
    };
    expect(() => validateTruth(sampleTruth)).not.toThrow();
  });
});
