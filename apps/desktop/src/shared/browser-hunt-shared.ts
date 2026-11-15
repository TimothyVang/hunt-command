/**
 * Browser-safe barrel for `@hunt-command/shared` used by the sandboxed Chromium renderer.
 *
 * Excludes `runtime-paths.ts` (`node:fs` / `node:path`) from the renderer bundle and provides
 * a minimal Web-standard `TextEncoder` `Buffer.byteLength` shim when `nodeIntegration: false`
 * omits Node's global `Buffer` (used by Zod refinements in `packages/shared/src/contracts.ts`).
 */
if (typeof (globalThis as { Buffer?: unknown }).Buffer === "undefined") {
  const encoder = new TextEncoder();
  (globalThis as Record<string, unknown>).Buffer = {
    byteLength: (input: string): number => encoder.encode(String(input)).byteLength,
  };
}

export * from "../../../../packages/shared/src/contracts.ts";
export * from "../../../../packages/shared/src/fields.ts";
export * from "../../../../packages/shared/src/prices.ts";
