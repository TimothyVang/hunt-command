import type { IpcResult } from "../../../shared/ipc.ts";
import type { TranscriptPageSlice } from "../../../shared/workbench-types.ts";

export type TranscriptView =
  | { readonly kind: "loading" }
  | { readonly kind: "page"; readonly page: TranscriptPageSlice }
  | { readonly kind: "error"; readonly message: string };

export interface TranscriptRequest {
  readonly huntId: string;
  readonly stepId: string;
  readonly byteOffset: number;
}

/**
 * What the transcript tab shows for one request's IPC result. A failed call, or a page for a different
 * hunt/step/offset than was asked for, is an error: never keep showing a loading message or the
 * previous step's transcript as if it answered this request.
 */
export function transcriptViewFor(request: TranscriptRequest, res: IpcResult<TranscriptPageSlice>): TranscriptView {
  if (!res.ok || !res.data) {
    return { kind: "error", message: res.error?.message ?? "Transcript page could not be loaded." };
  }
  const page = res.data;
  if (page.huntId !== request.huntId || page.stepId !== request.stepId || page.byteOffset !== request.byteOffset) {
    return { kind: "error", message: "Transcript page does not match the requested hunt, step, or offset." };
  }
  return { kind: "page", page };
}
