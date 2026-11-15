import type { StartRunInput } from "../../../shared/ipc.ts";
import type { WorkbenchSnapshot } from "../../../shared/workbench-types.ts";
import type { RunOption } from "../panes/RunControls.tsx";
import { invokeDesktop } from "./bridge.ts";

export const listRuns = () => invokeDesktop<RunOption[]>("hunt:listRuns");
export const startRun = (input: StartRunInput) => invokeDesktop<WorkbenchSnapshot>("hunt:startRun", input);
export const selectRun = (huntId: string) => invokeDesktop<WorkbenchSnapshot>("hunt:getWorkbenchState", { huntId });

/** Keep delayed daemon-event responses from replacing newer workbench state. */
export class EventRefreshGuard {
  #snapshotRevision = 0;
  #refreshSequence = 0;

  snapshotApplied(): void {
    this.#snapshotRevision++;
  }

  async refresh(
    huntId: string,
    isSelectionCurrent: () => boolean,
    applySnapshot: (snapshot: WorkbenchSnapshot) => void,
  ): Promise<void> {
    const revision = this.#snapshotRevision;
    const sequence = ++this.#refreshSequence;
    const result = await selectRun(huntId);
    if (result.ok && result.data?.huntId === huntId && isSelectionCurrent() &&
        revision === this.#snapshotRevision && sequence === this.#refreshSequence) {
      applySnapshot(result.data);
    }
  }
}

/** Apply a page only while the requesting workbench version and selection remain current. */
export async function loadGateEvidencePage(
  snapshot: WorkbenchSnapshot,
  isSelectionCurrent: () => boolean,
  isSnapshotCurrent: () => boolean,
  applySnapshot: (snapshot: WorkbenchSnapshot) => void,
): Promise<string | null> {
  try {
    const res = await invokeDesktop<WorkbenchSnapshot>("hunt:gateEvidencePage", { huntId: snapshot.huntId });
    if (!isSelectionCurrent()) return null;
    if (!isSnapshotCurrent()) return "The workbench changed while loading evidence; try again.";
    if (!res.ok || !res.data) return res.error?.message ?? "Could not load more evidence.";
    if (res.data.huntId !== snapshot.huntId) return "Evidence page returned for a different hunt.";
    applySnapshot(res.data);
    return null;
  } catch (error) {
    if (!isSelectionCurrent()) return null;
    if (!isSnapshotCurrent()) return "The workbench changed while loading evidence; try again.";
    return error instanceof Error ? error.message : "Could not load more evidence.";
  }
}
