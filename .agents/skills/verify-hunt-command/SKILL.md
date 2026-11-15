---
name: verify-hunt-command
description: Verify Hunt Command workstation prerequisites (Bun >= 1.4.4, FFmpeg with libass, pi_natives ABI addon, runtime Git fence) and apps/desktop security & build health.
---

# Verify Hunt Command (`verify-hunt-command`)

Use this skill before cutting a desktop release, filming a 1080p30 hunt run, or opening a PR touching `apps/desktop` or `packages/daemon`.

## Quick Doctor Gate

Run from the repository root:

```powershell
bun run .agents/skills/verify-hunt-command/scripts/doctor.ts
```

Pass `--json` for structured machine-readable diagnostics:

```powershell
bun run .agents/skills/verify-hunt-command/scripts/doctor.ts --json
```

## What `doctor.ts` Verifies

1. **Bun Runtime (`>=1.4.4`)**: Ensures the deterministic TypeScript/SQLite runtime meets `STACK.md` floor.
2. **`ffmpeg.exe` + `libass` (`ass` filter)**: Dynamically resolves `ffmpeg.exe` across `HUNT_COMMAND_FFMPEG_PATH`, `PATH`, and `%LOCALAPPDATA%/hermes/tools/ffmpeg-*-win32-x64/bin/ffmpeg.exe` and proves `libass` subtitle rendering is compiled in.
3. **`pi_natives` Native Addon**: Checks `pi_natives.win32-x64-baseline.node` presence in `node_modules/@oh-my-pi/pi-natives-win32-x64` or staged `apps/desktop/build/extra/hunt-daemon` (reports `standby_ok` when Slice 2 addon is not yet installed in isolated worktrees, or `ok` when present).
4. **Runtime Directory Git Fence**: Confirms `resolveRuntimeDir()` resolves outside every `.git` worktree and rejects in-repo paths with `RUNTIME_INSIDE_GIT_TREE`.
5. **Desktop Security & Build Health**:
   - Confirms `apps/desktop/out/main/index.js`, `apps/desktop/out/preload/index.cjs`, and `apps/desktop/out/renderer/index.html` exist and embed `connect-src 'none'` + `worker-src 'self' blob:`.
   - Scans `apps/desktop/src/**` to prove zero `openExternal` (`shell.openExternal`) and zero `dangerouslySetInnerHTML`.

## Full Desktop Verification Commands

```powershell
bun run --cwd apps/desktop typecheck
bun run --cwd apps/desktop build
bun run --cwd apps/desktop test
bun run .agents/skills/verify-hunt-command/scripts/doctor.ts
```
