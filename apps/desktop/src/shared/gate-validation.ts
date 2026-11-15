import { extractInlineCitations } from "@hunt-command/shared";
import { sanitizeSingleLine, stripControlAndBidiChars } from "./sanitize.ts";
import type {
  ActiveGatePrompt,
  CitationStatusEntry,
  CitationVerificationReceipt,
} from "./workbench-types.ts";

export interface GateVerificationSource {
  readonly knownEventIds: ReadonlySet<string>;
  readonly knownFrameIds: ReadonlySet<string>;
  readonly knownIocIds: ReadonlySet<string>;
  readonly outOfScopeIds?: ReadonlySet<string>;
}

/**
 * Computes the automated Citation Verification Receipt across BOTH `claims` AND `limitations`
 * (`g2_1_pass` parity — #189 Deliverable 2, ADR-0002).
 */
export function computeCitationVerificationReceipt(
  claims: ReadonlyArray<{ stepId: string; claimId: string; statement: string }>,
  limitations: ReadonlyArray<{ stepId: string; index: number; text: string }>,
  source: GateVerificationSource,
): CitationVerificationReceipt {
  const byId = new Map<
    string,
    {
      kind: "evt" | "frame" | "ioc";
      referencedIn: { sourceKind: "claim" | "limitation"; sourceId: string; stepId: string }[];
    }
  >();

  const recordText = (
    text: string,
    sourceKind: "claim" | "limitation",
    sourceId: string,
    stepId: string,
  ) => {
    const extracted = extractInlineCitations(text);
    const items: Array<{ id: string; kind: "evt" | "frame" | "ioc" }> = [
      ...extracted.event_ids.map((id) => ({ id, kind: "evt" as const })),
      ...extracted.frame_ids.map((id) => ({ id, kind: "frame" as const })),
      ...extracted.ioc_ids.map((id) => ({ id, kind: "ioc" as const })),
    ];
    for (const item of items) {
      let existing = byId.get(item.id);
      if (!existing) {
        existing = { kind: item.kind, referencedIn: [] };
        byId.set(item.id, existing);
      }
      if (
        !existing.referencedIn.some(
          (r) => r.sourceKind === sourceKind && r.sourceId === sourceId && r.stepId === stepId,
        )
      ) {
        existing.referencedIn.push({ sourceKind, sourceId, stepId });
      }
    }
  };

  for (const c of claims) {
    recordText(c.statement, "claim", c.claimId, c.stepId);
  }
  for (const lim of limitations) {
    recordText(lim.text, "limitation", `${lim.stepId}:limitation-${lim.index + 1}`, lim.stepId);
  }

  const entries: CitationStatusEntry[] = [];
  let verifiedCount = 0;
  let unresolvedCount = 0;
  let outOfScopeCount = 0;

  for (const [citationId, meta] of [...byId.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
    let status: "verified" | "unresolved" | "out_of_scope";
    if (source.outOfScopeIds?.has(citationId)) {
      status = "out_of_scope";
      outOfScopeCount++;
    } else {
      const exists =
        meta.kind === "evt"
          ? source.knownEventIds.has(citationId)
          : meta.kind === "frame"
            ? source.knownFrameIds.has(citationId)
            : source.knownIocIds.has(citationId);
      if (exists) {
        status = "verified";
        verifiedCount++;
      } else {
        status = "unresolved";
        unresolvedCount++;
      }
    }

    entries.push({
      citationId,
      kind: meta.kind,
      status,
      referencedIn: meta.referencedIn,
    });
  }

  return {
    totalCited: entries.length,
    verifiedCount,
    unresolvedCount,
    outOfScopeCount,
    allVerified: unresolvedCount === 0 && outOfScopeCount === 0,
    entries,
  };
}

export interface GateSubmissionDraft {
  operatorName: string;
  rbacRole: "incident_commander" | "lead_hunter" | "soc_lead";
  checkNote: string;
  payloadSha256: string;
  action: "approve" | "reject";
}

export interface GateValidationOutcome {
  valid: boolean;
  sanitizedOperatorName: string;
  sanitizedCheckNote: string;
  errors: string[];
}

/**
 * Why `approve` must be refused because the gate's decision context is not on screen, or `null`.
 * Fail closed: nobody may approve a gate whose context (scope text or summary, incident citation
 * summary, reconcile receipt) failed to load or was never provided. Rejecting stays possible.
 */
export function missingGateContextReason(activeGate: ActiveGatePrompt): string | null {
  if (activeGate.contextError) {
    return `Gate context could not be loaded, so approval is disabled: ${sanitizeSingleLine(activeGate.contextError).slice(0, 300)}`;
  }
  if (activeGate.gate === "scope" && !activeGate.scopeText && !activeGate.scopeSummary) {
    return "Gate 1 scope text is not available, so approval is disabled.";
  }
  if (activeGate.gate === "incident" && !activeGate.incidentSummary) {
    return "Gate 2 incident summary and citations are not available, so approval is disabled.";
  }
  if (activeGate.gate === "reconcile" && !activeGate.reconcileContext) {
    return "Reconcile dispatch receipt is not available, so approval is disabled.";
  }
  return null;
}

/**
 * Validates human Gate 1 (`scope`), Gate 2 (`incident`), and `reconcile` submissions:
 * - Strips bidi/zero-width/ANSI control characters from operator principal and check-note.
 * - Requires `1..1000` chars in `"What did you check?"` (`checkNote`).
 * - Verifies exact 64-hex `SHA-256` payload digest match against `activeGate.payloadSha256`.
 * - Blocks `approve` on Gate 2 (`incident`) whenever any inline `evt-*`/`frame-*`/`ioc-*` citation
 *   is unresolved or out-of-scope (`!citationReceipt.allVerified`).
 */
export function validateGateSubmission(
  activeGate: ActiveGatePrompt,
  draft: GateSubmissionDraft,
  nowMs: number = Date.now(),
): GateValidationOutcome {
  const errors: string[] = [];
  const sanitizedOperatorName = sanitizeSingleLine(draft.operatorName);
  const sanitizedCheckNote = stripControlAndBidiChars(draft.checkNote).trim();

  if (sanitizedOperatorName.length === 0 || sanitizedOperatorName.length > 128) {
    errors.push("Operator principal name is required (1..128 characters).");
  }

  if (sanitizedCheckNote.length < 1 || sanitizedCheckNote.length > 1000) {
    errors.push('"What did you check?" note must be between 1 and 1000 characters.');
  }

  if (!/^[a-f0-9]{64}$/i.test(draft.payloadSha256)) {
    errors.push("Payload digest must be a valid 64-character hex SHA-256 hash.");
  } else if (draft.payloadSha256.toLowerCase() !== activeGate.payloadSha256.toLowerCase()) {
    errors.push("Payload SHA-256 digest does not match the active gate snapshot (stale gate view).");
  }

  const expiresMs = Date.parse(activeGate.expiresAtIso);
  if (!Number.isNaN(expiresMs) && nowMs > expiresMs) {
    errors.push("Gate prompt has expired; refresh workbench state to obtain a current gate token.");
  }

  if (draft.action === "approve") {
    const missing = missingGateContextReason(activeGate);
    if (missing) errors.push(missing);
  }

  if (
    activeGate.gate === "incident" &&
    draft.action === "approve" &&
    activeGate.incidentSummary &&
    !activeGate.incidentSummary.citationReceipt.allVerified
  ) {
    const { unresolvedCount, outOfScopeCount } = activeGate.incidentSummary.citationReceipt;
    errors.push(
      `Gate 2 Incident approval blocked: ${unresolvedCount} unresolved and ${outOfScopeCount} out-of-scope citations must be resolved before approval.`,
    );
  }

  return {
    valid: errors.length === 0,
    sanitizedOperatorName,
    sanitizedCheckNote,
    errors,
  };
}
