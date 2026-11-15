# Hunt Command (v2) — Project Rulebook

**Hunt Command** (`TimothyVang/hunt-command`) is a standalone six-bot threat-hunting workbench and durable orchestration engine built on **Bun (`>=1.4.4`)**, **`@oh-my-pi` (`18.20.0`)**, **`bun:sqlite` (`3.53+` WAL + content-addressed `zstd`)**, and a hardened **Electron 36 + React 19** desktop shell. Each specialist bot drives its own read-only data-plane tools (`elastic_search`, `elastic_aggregate`, `detection_test`, `intel_lookup`, `arkime_sessions`, `arkime_unique`, `packet_fields`, `hunt_lab_query`, `lab_browser`) against an embedded zero-Docker SQLite/PCAP case store or a 10-invariant read-only connected Elastic service, handing validated claims across an 8-wave DAG governed by two authenticated human gates.

Built in the open under **AGPL-3.0** ([LICENSE](LICENSE)). **Every contributor, human or AI agent, follows this rulebook without exception.**

---

## What is here

| Path | What it is | License |
|---|---|---|
| `packages/shared/` | Canonical domain types, 6-role ontology & `ROLE_TOOL_OWNERSHIP`, 8-wave & gate schemas, `resolveRuntimeDir` git-fence, NDJSON RPC contracts, and `$0` OAuth vs API shadow price table. | AGPL-3.0 ([LICENSE](LICENSE)) |
| `packages/telemetry/` | Self-owned hot `hunt_telemetry.sqlite` WAL spans + cold content-addressed `zstd` blobs + pre-write credential scrubber + proxy-proof `127.0.0.1` OTLP exporter + code-enforced `EgressGuard`. | AGPL-3.0 ([LICENSE](LICENSE)) |
| `packages/data-plane/` | `EmbeddedHuntDataPlane` (`bun:sqlite` Lucene/Arkime/`packet_fields` AST compilers, Worker PCAP/pcapng/TLS1.3-JA4/JA3/DNS-`0xC0`/SNI indexer, local Watch routes) + 10-invariant `ConnectedHuntDataPlane`. | AGPL-3.0 ([LICENSE](LICENSE)) |
| `packages/daemon/` | Persistent `hunt-daemon`: durable SQLite WAL 8-wave state machine, `ReceiptStore`, isolated `K=6` `@oh-my-pi@18.20.0` `$0` OAuth pool, 128-bit nonce tool fence, HMAC role guard, authenticated Gates 1/2, Slack Socket Mode, CLI `drive_gates`, stdio NDJSON RPC. | AGPL-3.0 ([LICENSE](LICENSE)) |
| `apps/desktop/` | Hardened Electron 36 + React 19 4-pane DFIR Workbench, Gantt Hunt Flight Recorder, fenced Watch `WebContentsView`, cited Markdown/PDF/JSON export, hidden `1920x1080` offscreen 30fps CFR `ffmpeg` film pipeline. | AGPL-3.0 core + MIT adapted shell ([THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)) |
| `packages/coach/` | Canonical `scenario` scorer + `review_reports` + `cost_arms` + out-of-process zero-tool Clean-Room Two-Tier Coach with positive file allowlist keeping holdouts and `truth.json` sealed. | AGPL-3.0 ([LICENSE](LICENSE)) |
| `scripts/hunt_bots_check.ts` | Blocking local policy, manifest, boundary, AST `windowsHide`, typecheck, and test gate. | AGPL-3.0 ([LICENSE](LICENSE)) |
| `../runtime/` (outside `repo/`, never inside Git) | Local cases, datasets, work exports, SQLite state/telemetry DBs, `zstd` blobs, operator decisions, films, and `operator-only/truth.json`. Refused if inside any `.git` tree. | — |

Architecture and slice ownership boundaries live in [STACK.md](STACK.md). Copied or adapted third-party notices live in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

---

## Rules (enforced)

**Safety.** These invariants are non-negotiable. Every PR review and `scripts/hunt_bots_check.ts` checks them.

1. **Data origin & outside-Git runtime boundary (`synthetic | public-dataset | work-export | work-connected`).** Every case declares its `data_origin` in `case.json`:
   - `"synthetic"` (`synthetic_only: true`): invented lab telemetry and synthetic packet captures.
   - `"public-dataset"` (`synthetic_only: false`): an operator-approved public research dataset (e.g., DEDALE) containing real lab telemetry and zero customer data.
   - `"work-export"` (`synthetic_only: false`): an unclassified time-window export of the operator's own work logs.
   - `"work-connected"` (`synthetic_only: false`): live read-only queries against the operator's unclassified work Elastic via `ConnectedHuntDataPlane` (refused by the embedded container/local importer).
   Loading any non-synthetic case requires passing explicit `--data-origin <origin>` matching `case.json`, marks the hunt `synthetic_only: false`, and states the exact real origin to the bots (never misrepresenting real data as synthetic). All cases, datasets, work exports, SQLite databases, telemetry blobs, recordings, and `operator-only/truth.json` answer keys live strictly in `../runtime/` outside the Git repository (`resolveRuntimeDir` walks every ancestor and realpath to reject any directory inside a `.git` tree). Never load customer data or CUI/NSS data without a named, approved boundary. Never commit logs, PCAPs, SQLite/DB files, `.zst` blobs, `.mp4`/`.ass` recordings, `truth.json`, credentials, API keys, OAuth tokens, cookies, or session stores.

2. **Read-only lab-local / connected `HuntDataPlane` & fenced Watch browser.** Bot tools read only the loaded case through `HuntDataPlane` (`EmbeddedHuntDataPlane` on local `bun:sqlite` + `127.0.0.1` Watch routes, or `ConnectedHuntDataPlane` holding the isolated 2-layer verified read-only Elastic API key popped from bot environments, with `15m` settle gate, `allow_partial_search_results=false` PIT + crash reaper, and `F04` `sha256(_index + "\0" + _id)` `evt-*` citations). Role tool ownership is enforced by closure-bound HMAC-SHA256 capabilities returning fixed `snake_case` error codes (`403 tool_not_owned`, `405 read_only`, `400 leading_wildcard_not_supported`, `field_not_allowed`, `field_unavailable`), never raw backend free text. No bot tool may mutate cases, control host processes, capture live traffic, reach external hosts, invoke `imager.exe` (`A4`/`F21` stays outside Slices 1–4 without separate explicit approval), or read `operator-only/` answer keys. `packet_fields` reads only the case's saved capture and enforces the ADR-0003 field allowlist, filter grammar, and HTTP URI query redaction (`?[redacted]`). Every tool output (`<= 24 KiB` pre-capped) is stripped of zero-width/bidi/ANSI control characters and wrapped in a per-call 128-bit nonce `<untrusted_tool_result_${nonce}>` fence. Watch browser views (`WebContentsView` / `lab_browser`) enforce main-process `Fetch.enable`, `127.0.0.1:1` proxy fencing, and ephemeral `hunt-watch:` partitions restricted exclusively to allowed `127.0.0.1` Watch ports (`shell.openExternal` is removed; external URLs render only as defanged `hxxps://` copy-only pills).

3. **Two authenticated human gates per hunt (`ADR-0002`) & honest provenance.** Per ADR-0002, the operator makes two authenticated human decisions per hunt: **Gate 1 (`scope`)** before any specialist hunter queries case data, and **Gate 2 (`incident`)** to accept or reject the final cited report. Both human gates bind an authenticated principal, RBAC check, `SHA-256` digest of the scope or report payload, replay-protected `decision_id`, and expiry timestamp. Intermediate execute/review wave transitions may proceed automatically and MUST be recorded with `via: "automated"`, never presented as human approvals. Pre-prompt `ReceiptStore` reservations recover crashed in-flight model dispatches as `previous_dispatch_unknown` into an explicit human `reconcile` gate rather than silently re-running. Response actions remain human decisions. Never fabricate approvals, evidence IDs, citations, model outputs, scores, or test results; simulated or scripted `drive_gates` runs are explicitly labelled as such.

4. **Zero vendor phone-home, proxy-proof `127.0.0.1` OTLP fence & code-enforced `EgressGuard`.** No real-money trading, no unattended external actions without explicit opt-in, and zero third-party telemetry or cloud phone-home (no PostHog, no n8n cloud endpoints, no analytics beacons). Specialist bots have zero messaging or network egress tools. Optional OTLP telemetry export is hardcoded to loopback (`http://127.0.0.1:<port>` or `http://[::1]:<port>`) with `redirect: "error"` and `proxy: ""` (defeating proxy hijacks and redirect rebinding) and defaults **OFF** whenever `synthetic_only === false`. The opt-in outbound-only Slack Socket Mode bridge (ADR-0004) and webhook notifications pass through code-enforced `EgressGuard`: when `synthetic_only === false`, `EgressGuard` strips all bot prose, queries, hostnames, and IOCs, emitting strictly allowlisted ID-and-status cards. Offscreen `.mp4`/`.ass` film capture on non-synthetic cases requires explicit `--allow-work-film`.

5. **Honest claims, non-evasive `cyber` refusal reporting & `$0` OAuth subscription mode.** Documentation, code comments, and PR briefings state only what was actually executed and measured. `"Enforced"` means enforced at runtime by code with a passing test; anything else is `"configured"` or `"prompt guidance"`. All `@oh-my-pi@18.20.0` model sessions run in `$0` OAuth subscription mode (`oauthAccountPools` with `restricted = true` plus stripped `*_API_KEY` environment variables so transient OAuth errors never fall back to paid API keys), while recording exact API-equivalent shadow cost (`computeShadowCostUsd`) alongside `$0.00` actual billed cost. Terminal `AssistantMessage` safety refusals (`stopReason === "error"`, `stopDetails.category === "cyber"` / `finish_reason=content_filter, category=cyber`) are inspected and surfaced verbatim in wave diagnostics; prompts and model selections must never be reworded or swapped to evade safety classifiers.

**Change process.**

6. **Everything lands by pull request into `main` behind the local gate & 3-verifier panel.** Hosted GitHub Actions stays **off** to keep the project `$0` to run. Every change branches from `main` (in an isolated `.worktrees/<slice>` worktree when parallelized), uses a Conventional Commits title (`type(scope): subject`), and includes truthful `## Why`, `## What changed`, `## Scope`, `## Tradeoffs`, `## Blast Radius`, and `## Verification` sections. Before opening, updating, or merging any PR:
   - `bun run scripts/hunt_bots_check.ts` must exit `0` and print `hunt_bots_check: PASS (<files> tracked files, <tests> tests, 0 policy violations)`, quoted verbatim in the PR.
   - A 3-verifier exact-SHA review panel (correctness/durability, security/isolation, tests/policy) must vote `APPROVE` on the exact head commit SHA.
   - Merge ONLY via `gh pr merge <num> --squash --match-head-commit <sha>` — **never pass `--delete-branch`**, which fails or breaks active git worktrees.

7. **Tests with behavior & Windows process hygiene.** Every behavior change ships with behavior-contract tests that fail before the change and pass after, plus updated docs when contracts move. Never weaken a byte cap, allowlist, clean-room boundary, or test to make the gate pass. Every Windows child-process spawn (`Bun.spawn`, `Bun.spawnSync`, `node:child_process`) MUST set `windowsHide: true` unless explicitly waived on that call with `// health: allow SPAWN_WINDOW -- <reason>`.

8. **Explicit tracked-file manifest (`TRACKED-FILES.txt`).** Every Git-tracked file in the repository is listed in lexicographical order in [TRACKED-FILES.txt](TRACKED-FILES.txt). `scripts/hunt_bots_check.ts` compares `git ls-files` against `TRACKED-FILES.txt` and fails on any mismatch. Update `TRACKED-FILES.txt` in the same commit/PR whenever files are added, renamed, or deleted.

9. **Third-party code attribution (`THIRD-PARTY-NOTICES.md`).** Copying or adapting third-party code (such as MIT shell components from `omp-desktop/app`) requires preserving the original copyright and license notice, adding or updating the attribution entry in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md), and marking modified files. Code with an unknown or AGPL-3.0-incompatible license is rejected.

---

## Review & Clean-Room Boundaries

Reviewers and the automated gate enforce these hard structural boundaries as blocking:

- **`packages/data-plane/**` and `packages/daemon/**` never import `packages/coach`:** Scorer logic, `review_reports`, and answer-key evaluation are strictly isolated from runtime hunting and data-plane packages (enforced by AST check in `scripts/hunt_bots_check.ts`).
- **`packages/coach/**` zero-tool clean-room execution:** Coach proposers and verifiers run out-of-process in an empty temporary directory outside both `repo/` and `../runtime/` with zero tools enabled (hard-aborting on `tool_execution_start`), reading only scrubbed numeric/enum `packet.json` summaries and editing only a strict positive file allowlist. `story_b_holdout`, `DEDALE`, and `runtime/operator-only/truth.json` remain strictly sealed.
- **Browser & renderer isolation (`apps/desktop/**`):** Packaged CSP enforces `worker-src 'self' blob:` without opening external `connect-src`; `shell.openExternal` is absent; `Fetch.*` is blocked from bot CDP commands while main-process `Fetch.enable` fences all Watch navigation to allowed `127.0.0.1` ports.
