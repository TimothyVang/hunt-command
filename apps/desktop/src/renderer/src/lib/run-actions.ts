import type { StartRunInput } from "../../../shared/ipc.ts";
import type { WorkbenchSnapshot } from "../../../shared/workbench-types.ts";
import type { RunOption } from "../panes/RunControls.tsx";
import { invokeDesktop } from "./bridge.ts";

export const listRuns = () => invokeDesktop<RunOption[]>("hunt:listRuns");
export const startRun = (input: StartRunInput) => invokeDesktop<WorkbenchSnapshot>("hunt:startRun", input);
export const selectRun = (huntId: string) => invokeDesktop<WorkbenchSnapshot>("hunt:getWorkbenchState", { huntId });
