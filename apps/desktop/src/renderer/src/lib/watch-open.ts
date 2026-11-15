import type { WatchOpenInput } from "../../../shared/ipc.ts";
import type { WorkbenchSnapshot } from "../../../shared/workbench-types.ts";

/**
 * Builds the `watch:open` request the Watch tab sends: the typed URL's origin becomes the pinned lab
 * origin, and the session is bound to the run, role, case, and case time window shown in the workbench.
 * Returns an error string instead when the URL cannot be a pinned origin; the main process re-validates
 * everything with `createWatchScope` regardless.
 */
export function buildWatchOpenRequest(
  workbench: Pick<WorkbenchSnapshot, "huntId" | "caseMetadata" | "watchState">,
  url: string,
): { ok: true; request: WatchOpenInput } | { ok: false; error: string } {
  let parsed: URL;
  try {
    parsed = new URL(url.trim());
  } catch {
    return { ok: false, error: `Not a URL: ${url}` };
  }
  if ((parsed.protocol !== "http:" && parsed.protocol !== "https:") || parsed.hostname !== "127.0.0.1") {
    return { ok: false, error: "Watch opens only pinned http(s)://127.0.0.1:<port> lab origins" };
  }
  const startMs = Date.parse(workbench.caseMetadata.time_window.start_iso);
  const endMs = Date.parse(workbench.caseMetadata.time_window.end_iso);
  if (!Number.isFinite(startMs) || !Number.isFinite(endMs) || endMs <= startMs) {
    return { ok: false, error: "The case has no valid time window to scope the Watch session" };
  }
  return {
    ok: true,
    request: {
      runId: workbench.huntId,
      role: workbench.watchState.role,
      caseId: workbench.caseMetadata.case_id,
      labOrigin: parsed.origin,
      startSec: Math.floor(startMs / 1000),
      stopSec: Math.ceil(endMs / 1000),
      initialUrl: parsed.toString(),
    },
  };
}
