/**
 * Adapted from omp-desktop/app/electron.vite.config.ts
 * Copyright (c) omp-desktop contributors (MIT License — see root THIRD-PARTY-NOTICES.md).
 * Modified for Hunt Command v2:
 * - Enforces packaged CSP with `connect-src 'none'` and `worker-src 'self' blob:` (for Sigma.js v3 workers)
 *   plus `frame-ancestors 'none'` and `object-src 'none'`.
 * - Removes @lydell/node-pty external (terminal PTY surface stripped completely).
 * - Resolves @hunt-command/shared and @desktop-shared across main, preload, and renderer.
 */
import { resolve } from "node:path";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "electron-vite";
import type { Plugin } from "vite";

import { DEV_SERVE_RENDERER_CSP, PACKAGED_RENDERER_CSP } from "./src/shared/csp.ts";

const desktopShared = resolve(__dirname, "src/shared");
const huntShared = resolve(__dirname, "../../packages/shared/src/index.ts");
const huntSharedBrowser = resolve(__dirname, "src/shared/browser-hunt-shared.ts");

export { DEV_SERVE_RENDERER_CSP, PACKAGED_RENDERER_CSP };

function cspPlugin(): Plugin {
  let isServe = false;
  return {
    name: "hunt-command-csp",
    configResolved(config) {
      isServe = config.command === "serve";
    },
    transformIndexHtml(html) {
      const policy = isServe ? DEV_SERVE_RENDERER_CSP : PACKAGED_RENDERER_CSP;
      return html.replace("%HUNT_COMMAND_CSP%", policy);
    },
  };
}

export default defineConfig({
  main: {
    resolve: {
      alias: {
        "@desktop-shared": desktopShared,
        "@hunt-command/shared": huntShared,
      },
    },
    build: {
      rollupOptions: {
        input: { index: resolve(__dirname, "src/main/index.ts") },
        external: ["electron"],
      },
    },
  },
  preload: {
    resolve: {
      alias: {
        "@desktop-shared": desktopShared,
        "@hunt-command/shared": huntShared,
      },
    },
    build: {
      rollupOptions: {
        input: { index: resolve(__dirname, "src/preload/index.ts") },
        external: ["electron"],
        output: { format: "cjs", entryFileNames: "[name].cjs" },
      },
    },
  },
  renderer: {
    root: resolve(__dirname, "src/renderer"),
    plugins: [react(), tailwindcss(), cspPlugin()],
    resolve: {
      alias: {
        "@renderer": resolve(__dirname, "src/renderer/src"),
        "@desktop-shared": desktopShared,
        "@hunt-command/shared": huntSharedBrowser,
      },
    },
    build: {
      rollupOptions: {
        input: { index: resolve(__dirname, "src/renderer/index.html") },
      },
    },
  },
});
