# Third-Party Notices

**Hunt Command** (`TimothyVang/hunt-command`) is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)** — see [LICENSE](LICENSE).

Copied or adapted third-party source code retains its original copyright notice and permissive license below, in compliance with AGPL-3.0 Section 7 and Rule 9 of [HUNT-BOTS.md](HUNT-BOTS.md). Modified files adapted from third-party sources carry prominent modification notices in their file headers.

---

## 1. Adapted Source Code

### `omp-desktop/app` (MIT License)

Portions of the Electron 36 shell architecture in `apps/desktop` (sidecar process lifecycle, preload IPC batching, CDP filter hardening, and desktop build configuration) are adapted from `omp-desktop` (`omp-desktop contributors`) and hardened for Hunt Command v2 (`windowsHide: true`, zero internet egress, stripped terminal/MCP/connector/workspace surfaces, defanged URL pills, and fenced Watch `WebContentsView`).

```text
MIT License

Copyright (c) omp-desktop contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 2. Runtime & Build Dependencies

All runtime and build dependencies are consumed unmodified via `package.json` and locked in `bun.lock`:

| Package | License | Role in Hunt Command |
|---|---|---|
| `@oh-my-pi/pi-coding-agent` (`18.20.0`) | MIT | Isolated `$0` OAuth multi-hunter agent session runtime (`packages/daemon`, `packages/coach`) |
| `@oh-my-pi/pi-ai` (`18.20.0`) | MIT | Model registry, OAuth token storage, and typed assistant message/refusal inspection |
| `@oh-my-pi/pi-natives` (`18.20.0`) | MIT | Native platform bindings (`PI_NATIVES_DIR` unpacked in packaged builds) |
| `zod` | MIT | Runtime schema validation for contracts, tool payloads, gates, and NDJSON RPC |
| `electron` (`36.x`) | MIT | Desktop application host, offscreen `1920x1080` CFR paint capture, and fenced `WebContentsView` |
| `react`, `react-dom` (`19.x`) | MIT | 4-pane DFIR Workbench UI rendering (`apps/desktop`) |
| `uplot` (`uPlot`) | MIT | High-frequency 60fps event & network timeline charts (`apps/desktop`) |
| `sigma` (`Sigma.js`) | MIT | WebGL entity/attack-graph rendering (`apps/desktop`) |
| `graphology` | MIT | In-memory directed multigraph model backing the attack graph (`apps/desktop`) |
| `typescript` (`^5.8.3`) | Apache-2.0 | Static type checking and AST policy enforcement (`scripts/hunt_bots_check.ts`) |
| `bun` / `@types/bun` (`>=1.4.4`) | MIT | JavaScript/TypeScript runtime, `bun:sqlite` 3.53+ WAL engine, `zstd`, and `Worker` threads |

---

## 3. Development Workflow Tooling

- **`deep-mode`** (`https://github.com/TimothyVang/deep-mode`, MIT, adapted from Lauren Tan's `pstack` at `https://github.com/cursor/plugins/tree/main/pstack`): Used for local PR review and the 3-verifier exact-SHA landing panel documented in [HUNT-BOTS.md](HUNT-BOTS.md).
