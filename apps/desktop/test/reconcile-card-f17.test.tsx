import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { AuthorityGateCard } from "../src/renderer/src/panes/AuthorityGateCard.tsx";
import { buildFixtureWorkbenchSnapshot } from "../src/shared/fixture-workbench.ts";
import type { ActiveGatePrompt, ReconcileAffectedStep } from "../src/shared/workbench-types.ts";

const snap = buildFixtureWorkbenchSnapshot({ openGate: "reconcile" });
const DIGEST = "c".repeat(64);
const DRAFT = { operatorName: "analyst", rbacRole: "lead_hunter" as const, checkNote: "Checked the source status." };

function citationGate(affectedStep?: ReconcileAffectedStep, unavailable: string[] = ["events", "packets"]): ActiveGatePrompt {
  return {
    gate: "reconcile",
    huntId: "run-1",
    openedAtIso: "2026-11-14T10:00:00Z",
    expiresAtIso: "2099-01-01T00:00:00Z",
    payloadSha256: DIGEST,
    reconcileContext: {
      reasonCode: "citation_source_unavailable",
      unavailableSources: unavailable,
      citationReceipt: {
        totalCited: 2, verifiedCount: 1, unresolvedCount: 1, outOfScopeCount: 0, allVerified: false,
        entries: [
          { citationId: "evt-aaa-1", kind: "evt", status: "verified", referencedIn: [] },
          { citationId: "frame-7", kind: "frame", status: "unresolved", referencedIn: [] },
        ],
      },
      ...(affectedStep ? { affectedStep } : {}),
    },
  };
}

const render = (gate: ActiveGatePrompt) =>
  renderToStaticMarkup(
    <AuthorityGateCard activeGate={gate} caseMetadata={snap.caseMetadata} requiresToken={false} draft={DRAFT}
      onUpdateDraft={() => {}} onSubmitDecision={() => {}} onSelectCitation={() => {}} />,
  );
const approveTag = (html: string) => /<button[^>]*data-testid="gate-approve-button"[^>]*>/.exec(html)?.[0] ?? "";
const text = (html: string) => html.replace(/<[^>]+>/g, "").replace(/&#x27;|&apos;/g, "'").replace(/\s+/g, " ");

describe("F17: citation-source reconcile card states the step, reason, citations and both outcomes", () => {
  test("optional step: names step/profile/wave, sources, every cited id with status, and the drop-and-resume outcome", () => {
    const html = render(citationGate({ stepId: "follow_up_2", profile: "framework-researcher", wave: "follow_up", optional: true, approveTransition: "reconcile_drop" }));
    const t = text(html);
    expect(t).toContain("affected step: follow_up_2 ( framework-researcher) · wave follow_up · optional".replace("( ", "("));
    expect(t).toContain("unavailable sources: events, packets");
    expect(t).toContain("evt-aaa-1 · verified");
    expect(t).toContain("frame-7 · unresolved");
    expect(t).toContain("Approve: step 'follow_up_2' is optional, so it is marked dropped (reason_code reconciled_drop) without being re-run, and the run resumes.");
    expect(t).toContain("Reject: the run fails (status failed, reason_code reconcile_rejected); steps awaiting review or approval are stopped.");
    expect(approveTag(html)).not.toContain('disabled=""');
  });

  test("required step: states that approval fails the run with reconciled_halt_required_step", () => {
    const t = text(render(citationGate({ stepId: "analysis", profile: "framework-coordinator", wave: "analysis", optional: false, approveTransition: "reconcile_halt" })));
    expect(t).toContain("required");
    expect(t).toContain("Approve: step 'analysis' is required and has no verified handoff, so the run fails (status failed, reason_code reconciled_halt_required_step).");
  });

  test("unidentified step: approval is disabled and the reason is shown", () => {
    const html = render(citationGate(undefined));
    expect(html).toContain('data-testid="reconcile-affected-step-missing"');
    expect(html).toContain('data-testid="gate-context-unavailable"');
    expect(text(html)).toContain("could not be identified, so approval is disabled");
    expect(approveTag(html)).toContain('disabled=""');
    expect(html).not.toContain('data-testid="reconcile-outcomes"');
  });
});
