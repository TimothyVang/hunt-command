import { describe, expect, test } from "bun:test";
import type { CaseMetadata, Handoff } from "@hunt-command/shared";
import {
  FINAL_HANDOFF_BYTES,
  OntologyValidationError,
  computeTypedOutputCaps,
  disclosedTargetBytes,
  extractSingleHandoffJson,
  parseStrictUniqueJson,
  validateHandoff,
  validateSnapshot,
  verifyHandoffCitations,
  type HuntDataPlanePort,
} from "../src/index.ts";

describe("Strict JSON & Ontology Validator (ontology.py port)", () => {
  test("rejects duplicate JSON keys (including \\uXXXX aliases) and NaN/Infinity", () => {
    expect(() => parseStrictUniqueJson('{"a": 1, "a": 2}')).toThrow(OntologyValidationError);
    expect(() => parseStrictUniqueJson('{"nested": {"x": true, "\\u0078": false}}')).toThrow(
      /Duplicate JSON object key/,
    );
    expect(() => parseStrictUniqueJson('{"score": NaN}')).toThrow(/Non-finite/);
    expect(() => parseStrictUniqueJson('{"score": Infinity}')).toThrow(/Non-finite/);
    expect(() => parseStrictUniqueJson('{"score": -Infinity}')).toThrow(/Non-finite/);

    const valid = parseStrictUniqueJson('{"a": 1, "b": {"a": 2}}') as {
      a: number;
      b: { a: number };
    };
    expect(valid.a).toBe(1);
    expect(valid.b.a).toBe(2);
  });

  test("extractSingleHandoffJson accepts raw JSON or final ```json block, rejecting trailing prose", () => {
    const rawJson = '{"schema_version": 1}';
    expect(extractSingleHandoffJson(rawJson)).toBe(rawJson);

    const fenced = [
      "Brief reasoning summary.",
      "```json",
      '{"schema_version": 1}',
      "```",
    ].join("\n");
    expect(extractSingleHandoffJson(fenced)).toBe('{"schema_version": 1}');

    const trailingProse = `${fenced}\nWait, one more note after the JSON!`;
    expect(() => extractSingleHandoffJson(trailingProse)).toThrow(/Trailing text/);
  });

  test("validates snapshots and enforces claim.evidence_ids vs inline evt-*/frame-*/ioc-* citations", () => {
    const snap = validateSnapshot(
      {
        schema_version: 1,
        case_id: "case-ont-1",
        entities: [
          {
            entity_id: "host-dc01",
            kind: "host",
            label: "DC01",
            evidence_ids: ["elastic-logs"],
          },
        ],
        relations: [],
      },
      "case-ont-1",
    );

    // Rejects raw evt-* inside evidence_ids!
    expect(() =>
      validateHandoff(
        {
          schema_version: 1,
          case_id: "case-ont-1",
          step_id: "evidence",
          profile: "framework-researcher",
          claims: [
            {
              claim_id: "evidence:c1",
              kind: "observed",
              statement: "Suspicious logon on DC01.",
              evidence_ids: ["evt-9991"],
              entity_ids: ["host-dc01"],
              contradicts: [],
            },
          ],
          reviews: [],
          disposition: "needs_validation",
          limitations: [],
          requested_decisions: [],
        },
        {
          caseId: "case-ont-1",
          stepId: "evidence",
          profile: "framework-researcher",
          snapshot: snap,
          suppliedSourceIds: ["elastic-logs"],
        },
      ),
    ).toThrow(OntologyValidationError);

    // Accepts supplied source_id in evidence_ids + inline evt-* in statement
    const validEvidence = validateHandoff(
      {
        schema_version: 1,
        case_id: "case-ont-1",
        step_id: "evidence",
        profile: "framework-researcher",
        claims: [
          {
            claim_id: "evidence:c1",
            kind: "observed",
            statement: "Suspicious logon observed in evt-9991 and frame-42 matching ioc-7.",
            evidence_ids: ["elastic-logs"],
            entity_ids: ["host-dc01"],
            contradicts: [],
          },
        ],
        reviews: [],
        disposition: "review_ready",
        limitations: [],
        requested_decisions: [],
      },
      {
        caseId: "case-ont-1",
        stepId: "evidence",
        profile: "framework-researcher",
        snapshot: snap,
        suppliedSourceIds: ["elastic-logs"],
      },
    );
    expect(validEvidence.handoff.claims[0]?.claim_id).toBe("evidence:c1");
  });

  test("restricts reviews[] to framework-reviewer and validates contradicts[] across ancestor_claims", () => {
    const mergeHandoff: Handoff = {
      schema_version: 1,
      case_id: "case-ont-1",
      step_id: "merge",
      profile: "framework-coordinator",
      claims: [
        {
          claim_id: "merge:c1",
          kind: "inference",
          statement: "Lateral movement via SMB in evt-10.",
          evidence_ids: ["elastic-logs"],
          entity_ids: [],
          contradicts: [],
        },
      ],
      reviews: [],
      disposition: "needs_validation",
      limitations: [],
      requested_decisions: [],
    };

    // Non-reviewer emitting reviews[] -> rejected
    expect(() =>
      validateHandoff(
        {
          schema_version: 1,
          case_id: "case-ont-1",
          step_id: "detection",
          profile: "framework-builder",
          claims: [],
          reviews: [
            {
              review_id: "detection:r1",
              claim_ids: ["merge:c1"],
              disposition: "review_ready",
              rationale: "Looks fine.",
              evidence_ids: ["elastic-logs"],
            },
          ],
          disposition: "review_ready",
          limitations: [],
          requested_decisions: [],
        },
        {
          caseId: "case-ont-1",
          stepId: "detection",
          profile: "framework-builder",
          predecessors: [mergeHandoff],
        },
      ),
    ).toThrow(/Only framework-reviewer/);

    // Reviewer (`purple`) reviewing `merge:c1` -> passes
    const purpleRes = validateHandoff(
      {
        schema_version: 1,
        case_id: "case-ont-1",
        step_id: "purple",
        profile: "framework-reviewer",
        claims: [],
        reviews: [
          {
            review_id: "purple:r1",
            claim_ids: ["merge:c1"],
            disposition: "needs_revision",
            rationale: "evt-10 was benign admin backup traffic.",
            evidence_ids: ["elastic-logs"],
          },
        ],
        disposition: "needs_revision",
        limitations: [],
        requested_decisions: [],
      },
      {
        caseId: "case-ont-1",
        stepId: "purple",
        profile: "framework-reviewer",
        predecessors: [mergeHandoff],
      },
    );

    // Downstream `incident` contradicting `merge:c1` via `ancestorClaims` -> passes!
    const incidentRes = validateHandoff(
      {
        schema_version: 1,
        case_id: "case-ont-1",
        step_id: "incident",
        profile: "framework-coordinator",
        claims: [
          {
            claim_id: "incident:c1",
            kind: "finding",
            statement: "Confirmed benign admin SMB backup in evt-10.",
            evidence_ids: ["elastic-logs"],
            entity_ids: [],
            contradicts: ["merge:c1"],
          },
        ],
        reviews: [],
        disposition: "review_ready",
        limitations: [],
        requested_decisions: [],
      },
      {
        caseId: "case-ont-1",
        stepId: "incident",
        profile: "framework-coordinator",
        predecessors: [purpleRes.handoff],
        ancestorClaims: mergeHandoff.claims,
        handoffLimitBytes: FINAL_HANDOFF_BYTES,
      },
    );
    expect(incidentRes.handoff.claims[0]?.contradicts).toEqual(["merge:c1"]);
  });

  test("computes dynamic typed output caps (55% forwarded vs 80% terminal) and verifies citations across claims & limitations", async () => {
    const caps = computeTypedOutputCaps([
      { stepId: "evidence", profile: "framework-researcher", dependsOn: [], basePromptOverheadBytes: 4096 },
      { stepId: "incident", profile: "framework-coordinator", dependsOn: ["evidence"], basePromptOverheadBytes: 4096 },
    ]);
    expect(caps.get("evidence")).toBe(16_384);
    expect(caps.get("incident")).toBe(FINAL_HANDOFF_BYTES);

    expect(disclosedTargetBytes(16_384, true, true)).toBe(Math.floor((16_384 * 11) / 20)); // 55% = 9011
    expect(disclosedTargetBytes(FINAL_HANDOFF_BYTES, false, true)).toBe(
      Math.floor((FINAL_HANDOFF_BYTES * 4) / 5),
    ); // 80% = 26214

    const meta: CaseMetadata = {
      case_id: "case-cit-1",
      title: "Citation Check",
      data_origin: "synthetic",
      synthetic_only: true,
      time_window: { start_iso: "2026-11-01T00:00:00Z", end_iso: "2026-11-01T01:00:00Z" },
      sources: ["elastic-logs"],
    };
    const knownEvents = new Set(["evt-101"]);
    const knownFrames = new Set(["frame-7"]);

    const dp: HuntDataPlanePort = {
      caseMetadata: meta,
      capabilities: () => ({ hasNetworkCapture: true, hasIntelSource: false, sources: meta.sources }),
      executeTool: async () => ({}),
      verifyCitations: async (req) => {
        const missingEvents = req.event_ids.filter((id) => !knownEvents.has(id));
        const missingFrames = req.frame_ids.filter((id) => !knownFrames.has(id));
        return {
          verified: missingEvents.length === 0 && missingFrames.length === 0 && req.ioc_ids.length === 0,
          checked_at: new Date().toISOString(),
          case_id: req.case_id,
          total_checked: req.event_ids.length + req.frame_ids.length + req.ioc_ids.length,
          missing_event_ids: missingEvents,
          missing_frame_ids: missingFrames,
          missing_ioc_ids: [...req.ioc_ids],
          ambiguous_ids: [],
          out_of_scope_ids: [],
          source_status: "ok",
        };
      },
    };

    // Unverified citation hidden inside `limitations[]` is caught!
    const badHandoff: Handoff = {
      schema_version: 1,
      case_id: "case-cit-1",
      step_id: "incident",
      profile: "framework-coordinator",
      claims: [
        {
          claim_id: "incident:c1",
          kind: "finding",
          statement: "Verified process tree in evt-101 and frame-7.",
          evidence_ids: ["elastic-logs"],
          entity_ids: [],
          contradicts: [],
        },
      ],
      reviews: [],
      disposition: "review_ready",
      limitations: ["Could not correlate fabricated evt-999999 in secondary log."],
      requested_decisions: [],
    };

    const failedCheck = await verifyHandoffCitations(badHandoff, dp);
    expect(failedCheck.status).toBe("failed");
    expect(failedCheck.receipt.missing_event_ids).toEqual(["evt-999999"]);
  });
});
