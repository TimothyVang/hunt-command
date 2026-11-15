# Hunt Command (v2) — Monorepo Stack & Slice Architecture

This document defines the authoritative runtime split, workspace package topology, and zero-overlap slice boundaries for **Hunt Command v2** (`TimothyVang/hunt-command`).

---

## 1. Two-Process Runtime Split & Storage Engine

Hunt Command v2 separates the UI host from the agent/database runtime to eliminate Node vs. Bun ABI conflicts and native DLL locking on Windows x64:

1. **Persistent Bun `hunt-daemon` (`Bun >= 1.4.4`, `bun:sqlite 3.53+` WAL):**
   - Runs standalone for headless CLI hunts, local gate verification, and Clean-Room Coach evaluation, or as a child sidecar spawned by Electron (`windowsHide: true`) communicating over **stdio NDJSON JSON-RPC 2.0**.
   - Hosts `@oh-my-pi/pi-coding-agent@18.20.0` (`@oh-my-pi/pi-ai@18.20.0`, `@oh-my-pi/pi-natives@18.20.0` unpacked via `PI_NATIVES_DIR`), `bun:sqlite` in `WAL` mode, `Bun.zstdCompressSync` / `Bun.zstdDecompressSync`, and streaming Bun `Worker` PCAP indexers.
2. **Hardened Electron 36 + React 19 Workbench (`apps/desktop`):**
   - Adapted from the MIT `omp-desktop/app` shell with zero internet egress, `33ms` preload IPC batching, DPAPI secret vaulting, `uPlot` 60fps timelines, `Sigma.js` v3 WebGL attack graphs (`worker-src 'self' blob:`), main-process `Fetch.enable` fenced Watch `WebContentsView`, and a dedicated hidden `1920x1080` offscreen paint recorder piping raw frames to CFR `30fps` `ffmpeg` (`windowsHide: true`).

---

## 2. Monorepo Package Layout & Zero-Overlap Slice Ownership

```text
hunt-command/
├── repo/                                 # Git repository (AGPL-3.0)
│   ├── packages/
│   │   ├── shared/                       # Seed main: shared contracts, ontology, git-fence, RPC, prices
│   │   ├── telemetry/                    # Slice 1: hot SQLite WAL + cold zstd blobs + scrubber + OTLP + EgressGuard
│   │   ├── data-plane/                   # Slice 1: EmbeddedHuntDataPlane + Worker PCAP/JA4 + ConnectedHuntDataPlane
│   │   ├── daemon/                       # Slice 2: durable 8-wave engine + K=6 omp $0 OAuth pool + gates + NDJSON RPC
│   │   └── coach/                        # Slice 4: canonical scenario scorer + 0-tool Clean-Room Two-Tier Coach
│   ├── apps/
│   │   └── desktop/                      # Slice 3: Electron 36 + React 19 4-pane DFIR Workbench + CFR 30fps filming
│   ├── .agents/skills/
│   │   └── verify-hunt-command/          # Slice 3: live app & hunt verification skill
│   ├── planning/wayfinder/adr/           # Slice 1: ADR-0006 runtime migration & architecture decision records
│   └── scripts/
│       └── hunt_bots_check.ts            # Seed main: policy, manifest, boundary, AST windowsHide, tsc & test gate
├── .worktrees/                           # Isolated parallel git worktrees (gitignored)
│   ├── slice1/                           # feat/slice1-data-telemetry
│   ├── slice2/                           # feat/slice2-wave-engine
│   ├── slice3/                           # feat/slice3-workbench
│   └── slice4/                           # feat/slice4-coach-eval
└── runtime/                              # Strictly outside Git (enforced by resolveRuntimeDir)
    ├── cases/                            # Loaded synthetic, public-dataset, or work-export cases
    ├── state/                            # hunt_daemon.sqlite (durable waves, gates, ReceiptStore)
    ├── telemetry/                        # hunt_telemetry.sqlite WAL + content-addressed zstd blobs/
    ├── operator-decisions/               # Append-only decisions.jsonl
    ├── exports/                          # Cited Markdown, PDF, and provenance JSON bundles
    ├── films/                            # 1920x1080 30fps .mp4 + .ass (1x and 5x)
    └── operator-only/                    # Sealed truth.json & answer keys (never reachable by daemon/bots)
```

---

## 3. Detailed Package Contracts by Slice

### Foundation (`main` Seed) — `packages/shared` (`@hunt-command/shared`)
- **Domain, Profiles, Waves & Ontology (`src/contracts.ts`, `src/fields.ts`):**
  - `DataOrigin` (`"synthetic" | "public-dataset" | "work-export" | "work-connected"`), `CaseMetadata` (`synthetic_only` invariant).
  - Canonical 6-bot `FRAMEWORK_PROFILES` (`framework-coordinator`, `framework-researcher`, `framework-network-analyst`, `framework-librarian`, `framework-builder`, `framework-reviewer`) + `PROFILE_DISPLAY_TITLES`, exact `ROLE_TOOL_OWNERSHIP` across the 9 `DATA_PLANE_TOOLS` + `hunt_lab_batch` & `delegate_task` (`delegate_task` disabled on `scope`), and batch caps (`BATCH_MAX_ITEMS = 5`, `BATCH_MAX_ITEM_SIZE = 25`, `BATCH_MAX_BYTES = 98_304`, `BATCH_EXCLUDED_TOOLS`).
  - Canonical 8-wave `HUNT_WAVES` (`scope`, `investigation` [`evidence`, `hypotheses`, `network`, `intel`], `analysis`, `follow_up` [`follow-1..K`, default `K = 6`, `0..12`], `merge`, `detection`, `purple`, `incident`), byte caps (`MAX_PROMPT_BYTES = 65_536`, `MAX_HANDOFF_BYTES = 16_384`, `MAX_SNAPSHOT_BYTES = 32_768`, `MAX_TOOL_RESULT_BYTES = 24_576`), strict `ontology.py`-aligned `SnapshotSchema` / `HandoffSchema` / `ClaimSchema` / `ReviewSchema` (`evidence_ids` strictly holding `source_id` while `evt-*`/`frame-*`/`ioc-*` inline citations index into `claim_evidence_lineage`), exact `lab_server.py` field allowlists (`EVENT_FIELDS`, `KEYWORD_FIELDS`, `SEARCH_FIELDS`, `ARKIME_SESSION_FIELDS`, `ARKIME_UNIQUE_FIELDS`, 38 `PACKET_FIELDS` & `PACKET_FILTER_FIELDS`), and authenticated Gate 1/2 (`scope`, `incident`) + `reconcile` schemas.
  - Stdio NDJSON JSON-RPC 2.0 request, response, and streaming event envelopes.
- **Runtime Fence (`src/runtime-paths.ts`):**
  - `resolveRuntimeDir()` canonicalizes paths (including ancestor symlink targets) and walks every parent directory to reject any path inside a `.git` repository or worktree.
- **Cost & Shadow Pricing (`src/prices.ts`):**
  - `MODEL_PRICE_TABLE`, `computeShadowCostUsd()`, and `computeCostAccounting()` tracking `$0.00` OAuth subscription actual cost alongside exact API-equivalent shadow cost and prompt-cache read savings.

### Slice 1 (`feat/slice1-data-telemetry`) — `packages/telemetry` & `packages/data-plane`
- **`packages/telemetry` (`@hunt-command/telemetry`):**
  - Hot `hunt_telemetry.sqlite` (`WAL` mode) span, wave, token/cache, and `claim_evidence_lineage` tables + between-round `wal_checkpoint(TRUNCATE)`.
  - Cold content-addressed `SHA-256` `zstd` message/tool blob store with pre-write credential scrubbing (`sk-ant-*`, `gho_*`, `ghp_*`, `xoxb-*`, `xapp-*`, `AKIA*`, bearer tokens, Elastic API keys).
  - Proxy- and redirect-proof loopback OTLP exporter (`http://127.0.0.1:<port>` / `http://[::1]:<port>`, `redirect: "error"`, `proxy: ""`), defaulting OFF when `synthetic_only === false`.
  - Code-enforced Rule 4 `EgressGuard` stripping prose, queries, hostnames, and IOCs on outbound cards/webhooks when `synthetic_only === false`, plus `--allow-work-film` enforcement.
- **`packages/data-plane` (`@hunt-command/data-plane`):**
  - `EmbeddedHuntDataPlane`: `bun:sqlite` 3.53+ schema (`events_hot`, multi-value `event_kv`, 16-byte IPv4/IPv6 `event_ips`, `events_fts`, nanosecond `ts_ns`), Lucene PEG/AST compiler (`.keyword` exact/`GLOB` `ignore_above:1024` vs `.text` FTS5, `NOT`, field groups, `_exists_:`, ranges, `400 leading_wildcard_not_supported`, `elastic_aggregate` with `top_hits` `sample_event_id` + `other`), `detection_test`, case-insensitive `intel_lookup`, Arkime session/unique compiler, ADR-0003 `packet_fields` allowlist & `?[redacted]` URI scrubber.
  - Streaming Bun `Worker` PCAP/pcapng indexer assigning 1-based physical `frame_number` prior to time-window filtering, `16 KiB` bidirectional TCP stream reassembly for coalesced/split TLS ClientHellos, TLS 1.3 (`0x0304` via ext `0x002b`) FoxIO JA4 + MD5 JA3, DNS `0xC0` pointer decompression + TXT answers, TLS SNI -> `http.host` aliasing, and local read-only Watch routes (`kibana_discover`, `arkime_sessions`, `arkime_spiview`).
  - `ConnectedHuntDataPlane`: 10-invariant ADR-0005 read-only Elastic client (2-layer API-key role descriptor + privilege check, `15m` settle gate, env-pop key isolation, `allow_partial_search_results=false` PIT + crash reaper, `F04` `sha256(_index + "\0" + _id)` `evt-*` IDs).
  - **Hard Boundary:** Never imports `@hunt-command/coach`.

### Slice 2 (`feat/slice2-wave-engine`) — `packages/daemon`
- **`packages/daemon` (`@hunt-command/daemon`):**
  - Durable SQLite WAL (`PRAGMA synchronous=FULL`) 8-wave DAG orchestrator checkpointing waves, handoffs, rejections, `decisions.jsonl`, and pre-prompt `ReceiptStore` reservations (`previous_dispatch_unknown` -> human `reconcile` gate), `max_total_tokens` (`results + handoff_rejections`), 5-hunt concurrency cap, and Global Stop. Case directory resolution rejects packs whose case ID differs from the requested run. An abandoned runtime reclaim mutex requires manual removal after all reclaimers stop; stop older daemons before upgrading.
  - Isolated `K=6` `@oh-my-pi@18.20.0` hunter pool: `installSqliteLockShim()`, 1 shared `AuthStorage` with pre-wave token refresh, `oauthAccountPools` (`restricted = true`) + stripped `*_API_KEY` env vars, per-hunter `new AgentRegistry()`, unique `agentId`, `bindProcessState: false`, `taskDepth: 1`, `restrictToolNames: true`, `allowRestrictedCustomTools: true`, `spawns: []`, `cacheWarming: false`, `noContextFiles: true`, `skills: []`, `enableMCP: false`, `>=25`-char constant `messages[0]` header for `1h` Claude sibling cache sharing (`stage_guidance <= 600B`), and terminal `AssistantMessage` `cyber` refusal classifier.
  - 128-bit nonce `<untrusted_tool_result_${nonce}>` tool output fence (`<= 24 KiB` pre-capped, control-char stripped), closure-bound HMAC-SHA256 role guard (`403 tool_not_owned` / `405 read_only`), dynamic `_typed_output_caps`, `scope` no-delegation, `follow-1..K` single-claim `focus`, `_MERGE_FALLBACK_PATCH`, `hunt_lab_batch`, and `delegate_task`.
  - Authenticated Gate 1 (`scope`) & Gate 2 (`incident`) (`SHA-256` payload digest, RBAC, replay `decision_id`, expiry), outbound-only Slack Socket Mode (via `EgressGuard`), CLI `drive_gates`, and stdio NDJSON RPC server.
  - **Hard Boundary:** Never imports `@hunt-command/coach`.

### Slice 3 (`feat/slice3-workbench`) — `apps/desktop` & `.agents/skills/verify-hunt-command`
- **`apps/desktop` (`@hunt-command/desktop`):**
  - Hardened Electron 36 + React 19 shell spawning `hunt-daemon` (`windowsHide: true`, unpacked `PI_NATIVES_DIR`), `33ms` preload IPC batcher, DPAPI secret vault, stripped `terminal`/`mcp`/`connectors`/`workspace` IPC, removed `shell.openExternal` (`hxxps://` defanged copy-only pills), `worker-src 'self' blob:`.
  - Synchronized 4-pane DFIR Workbench: (1) 8-Wave DAG + Gantt Hunt Flight Recorder + Cache/`$0`-vs-Shadow-API gauges, (2) Claims Matrix + Authority Gate 1/2 Cards, (3) `uPlot` 60fps Timeline + Virtualized Event/Packet Dissector, (4) `Sigma.js` v3 WebGL Attack Graph + Evidence Lineage Drawer. Operators can start, select, inspect, cancel, and submit authenticated gate decisions for daemon hunts; start requests carry a preallocated run ID for recovery after a timeout. Scope and incident approvals display their pending handoffs; incident approval requires complete evidence context. Reconciliation shows unavailable source citations as unresolved and explains that unknown dispatches are not replayed. Completed hunts reload cited evidence for inspection.
  - Main-process `Fetch.enable` + `127.0.0.1:1` proxy-fenced Watch `WebContentsView` (`hunt-watch:` ephemeral partitions, `Fetch.*` blocked in CDP filter), enforcing case and time scope for Arkime requests. Switching hunts hides and invalidates the previous Watch session.
  - Cited Markdown, PDF, and provenance JSON customer report export.
  - Windows 11 DWM-proof hidden `1920x1080` offscreen `BrowserWindow` paint recorder -> single-pass CFR `30fps` `ffmpeg` (`cwd: outDir`, `windowsHide: true`, relative `ass=filename=video.ass`) producing `1x` and `5x` `.mp4`/`.ass` artifacts.
- **`.agents/skills/verify-hunt-command`:** Live desktop/daemon/film verification workflow skill.

### Slice 4 (`feat/slice4-coach-eval`) — `packages/coach`
- **`packages/coach` (`@hunt-command/coach`):**
  - Canonical `scenario` scorer + `review_reports` + `cost_arms` with differential parity for Story A/B & DEDALE (entity-scoped citations, `frame-*` / `ioc-*` / `evt-*` alternatives, `evidence_sibling_groups`, contrast-aware decoy non-blame, `g2_1_pass`).
  - Out-of-process Clean-Room Two-Tier Coach running `@oh-my-pi` proposers and verifiers in an empty temporary directory outside `repo/` and `../runtime/` with **zero tools** (hard-aborting on `tool_execution_start`), consuming only scrubbed numeric/enum `packet.json` diagnostics. Case-vocabulary leak guards retain terms from one-shot iterables.
  - Strict positive file allowlist keeping `story_b_holdout`, `DEDALE`, and `runtime/operator-only/truth.json` completely sealed, governed by a 3-stage `probe -> pass^2 -> 3-verifier` promotion gate.

---

## 4. Zero-Overlap Merge Matrix

| Slice | Branch | Owned Directories | Shared Files Updated at Merge |
|---|---|---|---|
| Seed (`main`) | `main` | `packages/shared/`, `scripts/hunt_bots_check.ts`, root governance & configs | `TRACKED-FILES.txt`, `bun.lock` |
| Slice 1 | `feat/slice1-data-telemetry` | `packages/telemetry/`, `packages/data-plane/`, `planning/wayfinder/adr/` | `TRACKED-FILES.txt`, `bun.lock` |
| Slice 2 | `feat/slice2-wave-engine` | `packages/daemon/` | `TRACKED-FILES.txt`, `bun.lock` |
| Slice 3 | `feat/slice3-workbench` | `apps/desktop/`, `.agents/skills/verify-hunt-command/` | `TRACKED-FILES.txt`, `bun.lock` |
| Slice 4 | `feat/slice4-coach-eval` | `packages/coach/` | `TRACKED-FILES.txt`, `bun.lock` |
