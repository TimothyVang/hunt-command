/**
 * Synchronized 4-Pane DFIR Workbench External Store (`<16ms` Cross-Highlighting & Gate Draft Isolation).
 *
 * Pure TypeScript (zero DOM dependency at import time) so unit tests can directly benchmark
 * cross-pane selection latency (`evt-*` / `frame-*` / `ioc-*` / `entity_id`) and verify that
 * `"What did you check?"` (`checkNote`) is keyed per gate & cleared automatically before Gate 2!
 */
import type { ClaimKind } from "@hunt-command/shared";
import { buildFixtureWorkbenchSnapshot } from "../../../shared/fixture-workbench.ts";
import { stripControlAndBidiChars } from "../../../shared/sanitize.ts";
import type { ActiveGatePrompt, WorkbenchSnapshot } from "../../../shared/workbench-types.ts";

export type CenterPaneTab = "claims" | "gate" | "transcript" | "watch";
export type DissectorTab = "events" | "arkime" | "packets";

export interface GateDraftFields {
  operatorName: string;
  rbacRole: "incident_commander" | "lead_hunter" | "soc_lead";
  checkNote: string;
}

/**
 * Whether the renderer has real data from the main process. Until a snapshot arrives the panes are not
 * rendered at all, so a missing preload bridge shows an explicit error instead of placeholder hunts.
 */
export type WorkbenchConnection =
  | { readonly kind: "connecting" }
  | { readonly kind: "ready" }
  | { readonly kind: "unavailable"; readonly code: string; readonly message: string };

export interface WorkbenchUiState {
  connection: WorkbenchConnection;
  workbench: WorkbenchSnapshot;
  selectedCitationId: string | null;
  selectedClaimId: string | null;
  selectedEntityId: string | null;
  selectedEvidenceId: string | null;
  selectedStepId: string;
  selectedWaveFilter: number | null;
  claimKindFilter: ClaimKind | "all";
  timeBrushRangeMs: readonly [number, number] | null;
  centerTab: CenterPaneTab;
  dissectorTab: DissectorTab;
  dissectorSearch: string;
  ganttExpanded: boolean;
  lastHighlightLatencyMs: number;
  statusBanner: { kind: "info" | "success" | "error"; message: string } | null;
  gateDrafts: Readonly<Record<string, GateDraftFields>>;
}

export function buildGateDraftKey(gate: ActiveGatePrompt): string {
  return `${gate.huntId}:${gate.gate}:${gate.payloadSha256}`;
}

const DEFAULT_OPERATOR = "analyst.operator";
const DEFAULT_ROLE: GateDraftFields["rbacRole"] = "lead_hunter";

export class WorkbenchStore {
  #state: WorkbenchUiState;
  readonly #listeners = new Set<() => void>();

  constructor(initialSnapshot?: WorkbenchSnapshot) {
    const snap = initialSnapshot ?? buildFixtureWorkbenchSnapshot();
    const firstCitation = snap.citationReceipt.entries[0]?.citationId ?? "evt-0000000000001042";
    const firstClaim = snap.claims[0]?.claim.claim_id ?? null;
    const firstEntity = snap.snapshot.entities[0]?.entity_id ?? null;

    this.#state = {
      connection: initialSnapshot ? { kind: "ready" } : { kind: "connecting" },
      workbench: snap,
      selectedCitationId: firstCitation,
      selectedClaimId: firstClaim,
      selectedEntityId: firstEntity,
      selectedEvidenceId: firstCitation,
      selectedStepId: snap.steps[1]?.stepId ?? "evidence",
      selectedWaveFilter: null,
      claimKindFilter: "all",
      timeBrushRangeMs: null,
      centerTab: snap.activeGate ? "gate" : "claims",
      dissectorTab: "events",
      dissectorSearch: "",
      ganttExpanded: true,
      lastHighlightLatencyMs: 0,
      statusBanner: null,
      gateDrafts: {},
    };
  }

  getState = (): WorkbenchUiState => this.#state;

  subscribe = (listener: () => void): (() => void) => {
    this.#listeners.add(listener);
    return () => {
      this.#listeners.delete(listener);
    };
  };

  setWorkbenchSnapshot(nextSnapshot: WorkbenchSnapshot): void {
    const prevGateKey = this.#state.workbench.activeGate
      ? buildGateDraftKey(this.#state.workbench.activeGate)
      : null;
    const nextGateKey = nextSnapshot.activeGate
      ? buildGateDraftKey(nextSnapshot.activeGate)
      : null;

    // Preserve operatorName/rbacRole convenience across gates, NEVER carry over `checkNote`!
    const nextDrafts: Record<string, GateDraftFields> = { ...this.#state.gateDrafts };
    if (nextGateKey && !nextDrafts[nextGateKey]) {
      const prevDraft = prevGateKey ? this.#state.gateDrafts[prevGateKey] : undefined;
      nextDrafts[nextGateKey] = {
        operatorName: prevDraft?.operatorName ?? DEFAULT_OPERATOR,
        rbacRole: prevDraft?.rbacRole ?? DEFAULT_ROLE,
        checkNote: "",
      };
    }

    const firstEvidence =
      (this.#state.selectedEvidenceId && nextSnapshot.evidenceCatalog[this.#state.selectedEvidenceId]
        ? this.#state.selectedEvidenceId
        : nextSnapshot.citationReceipt.entries[0]?.citationId) ?? null;

    this.#setState({
      ...this.#state,
      connection: { kind: "ready" },
      workbench: nextSnapshot,
      selectedEvidenceId: firstEvidence,
      centerTab:
        nextGateKey && nextGateKey !== prevGateKey ? "gate" : this.#state.centerTab,
      gateDrafts: nextDrafts,
    });
  }

  /** Records that the main process could not provide a snapshot (for example, no preload bridge). */
  setConnectionUnavailable(code: string, message: string): void {
    if (this.#state.connection.kind === "ready") return;
    this.#setState({ ...this.#state, connection: { kind: "unavailable", code, message } });
  }

  /**
   * Synchronously cross-highlights timeline, attack graph, claims matrix, and raw dissector
   * record in a single `<16ms` state transition when any `evt-*`, `frame-*`, `ioc-*`, or `entity_id`
   * provenance badge is clicked.
   */
  selectProvenanceBadge(id: string): number {
    const t0 = performance.now();
    const { workbench } = this.#state;
    const detail = workbench.evidenceCatalog[id];

    let nextDissectorTab = this.#state.dissectorTab;
    let nextCitationId = this.#state.selectedCitationId;
    let nextEntityId = this.#state.selectedEntityId;
    let nextClaimId = this.#state.selectedClaimId;

    if (id.startsWith("evt-")) {
      nextCitationId = id;
      nextDissectorTab = "events";
    } else if (id.startsWith("frame-")) {
      nextCitationId = id;
      nextDissectorTab = "packets";
    } else if (id.startsWith("ioc-")) {
      nextCitationId = id;
    } else {
      nextEntityId = id;
    }

    if (detail) {
      if (detail.linkedEntityIds.length > 0 && detail.kind !== "entity") {
        nextEntityId = detail.linkedEntityIds[0] ?? nextEntityId;
      }
      if (detail.citingClaimIds.length > 0) {
        nextClaimId = detail.citingClaimIds[0] ?? nextClaimId;
      }
    }

    const elapsedMs = Number((performance.now() - t0).toFixed(3));
    this.#setState({
      ...this.#state,
      selectedCitationId: nextCitationId,
      selectedEntityId: nextEntityId,
      selectedClaimId: nextClaimId,
      selectedEvidenceId: id,
      dissectorTab: nextDissectorTab,
      lastHighlightLatencyMs: elapsedMs,
    });
    return elapsedMs;
  }

  selectClaim(claimId: string): void {
    const row = this.#state.workbench.claims.find((c) => c.claim.claim_id === claimId);
    const firstCite = row?.inlineCitations[0]?.id ?? this.#state.selectedCitationId;
    const firstEnt = row?.claim.entity_ids[0] ?? this.#state.selectedEntityId;
    this.#setState({
      ...this.#state,
      selectedClaimId: claimId,
      selectedCitationId: firstCite ?? null,
      selectedEntityId: firstEnt ?? null,
      selectedEvidenceId: firstCite ?? firstEnt ?? this.#state.selectedEvidenceId,
      selectedStepId: row?.stepId ?? this.#state.selectedStepId,
    });
  }

  selectStep(stepId: string, openTranscript = false): void {
    this.#setState({
      ...this.#state,
      selectedStepId: stepId,
      centerTab: openTranscript ? "transcript" : this.#state.centerTab,
    });
  }

  setWaveFilter(waveNumber: number | null): void {
    this.#setState({
      ...this.#state,
      selectedWaveFilter: this.#state.selectedWaveFilter === waveNumber ? null : waveNumber,
    });
  }

  setClaimKindFilter(filter: ClaimKind | "all"): void {
    this.#setState({ ...this.#state, claimKindFilter: filter });
  }

  setTimeBrushRange(rangeMs: readonly [number, number] | null): void {
    this.#setState({ ...this.#state, timeBrushRangeMs: rangeMs });
  }

  setCenterTab(tab: CenterPaneTab): void {
    this.#setState({ ...this.#state, centerTab: tab });
  }

  setDissectorTab(tab: DissectorTab): void {
    this.#setState({ ...this.#state, dissectorTab: tab });
  }

  setDissectorSearch(search: string): void {
    this.#setState({ ...this.#state, dissectorSearch: stripControlAndBidiChars(search) });
  }

  toggleGanttExpanded(): void {
    this.#setState({ ...this.#state, ganttExpanded: !this.#state.ganttExpanded });
  }

  setStatusBanner(banner: WorkbenchUiState["statusBanner"]): void {
    this.#setState({ ...this.#state, statusBanner: banner });
  }

  getActiveGateDraft(): GateDraftFields {
    const gate = this.#state.workbench.activeGate;
    if (!gate) {
      return { operatorName: DEFAULT_OPERATOR, rbacRole: DEFAULT_ROLE, checkNote: "" };
    }
    const key = buildGateDraftKey(gate);
    return (
      this.#state.gateDrafts[key] ?? {
        operatorName: DEFAULT_OPERATOR,
        rbacRole: DEFAULT_ROLE,
        checkNote: "",
      }
    );
  }

  updateActiveGateDraft(patch: Partial<GateDraftFields>): void {
    const gate = this.#state.workbench.activeGate;
    if (!gate) return;
    const key = buildGateDraftKey(gate);
    const current = this.getActiveGateDraft();
    const nextDraft: GateDraftFields = {
      operatorName:
        patch.operatorName !== undefined
          ? stripControlAndBidiChars(patch.operatorName)
          : current.operatorName,
      rbacRole: patch.rbacRole ?? current.rbacRole,
      checkNote:
        patch.checkNote !== undefined
          ? stripControlAndBidiChars(patch.checkNote).slice(0, 1000)
          : current.checkNote,
    };
    this.#setState({
      ...this.#state,
      gateDrafts: {
        ...this.#state.gateDrafts,
        [key]: nextDraft,
      },
    });
  }

  #setState(next: WorkbenchUiState): void {
    this.#state = next;
    for (const listener of this.#listeners) {
      listener();
    }
  }
}

export const workbenchStore = new WorkbenchStore();
