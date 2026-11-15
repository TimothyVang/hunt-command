/**
 * Strict Preload <-> Main IPC Channel Allowlist.
 *
 * This module is imported by the sandboxed preload, so it must stay dependency-free: a sandboxed
 * preload can `require` only `electron` (and a few polyfilled built-ins), never `node:fs`, `node:path`,
 * `zod`, or the `@hunt-command/shared` barrel. `test/preload-sandbox.test.ts` bundles the preload
 * and fails if anything but `electron` is required.
 *
 * Security invariants (#178 G1.2):
 * - NO `app:openExternal` (`shell.openExternal` is deleted globally).
 * - NO `terminal:*`, `workspace:*`, `git:*`, `mcp:*`, `connectors:*`, `collab:*`, `extensions:*`.
 */
export const INVOKE_CHANNEL_LIST = [
  "daemon:status",
  "daemon:restart",
  "hunt:listRuns",
  "hunt:getWorkbenchState",
  "hunt:startRun",
  "hunt:globalStop",
  "hunt:submitGateDecision",
  "hunt:inspectTranscriptPage",
  "hunt:gateEvidencePage",
  "hunt:queryDissector",
  "hunt:resolveEvidence",
  "watch:getState",
  "watch:open",
  "watch:setBounds",
  "watch:navigate",
  "export:customerReport",
  "film:recordAndCut",
  "film:status",
  "vault:status",
  "vault:hasSecret",
  "vault:setSecret",
  "vault:deleteSecret",
] as const;

export type InvokeChannel = (typeof INVOKE_CHANNEL_LIST)[number];
export const INVOKE_CHANNELS: ReadonlySet<string> = new Set<string>(INVOKE_CHANNEL_LIST);

export const EVENT_CHANNEL_LIST = [
  "daemon:eventBatch",
  "daemon:stateChanged",
  "watch:stateChanged",
  "film:progress",
] as const;

export type EventChannel = (typeof EVENT_CHANNEL_LIST)[number];
export const EVENT_CHANNELS: ReadonlySet<string> = new Set<string>(EVENT_CHANNEL_LIST);
