import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { AuthStorage, type AssistantMessage } from "@oh-my-pi/pi-ai";
import { AssistantMessageEventStream } from "@oh-my-pi/pi-ai/utils/event-stream";
import * as AIError from "@oh-my-pi/pi-ai/error";
import type { CaseMetadata } from "@hunt-command/shared";
import {
  FORBIDDEN_SUBSCRIPTION_ENV_KEYS,
  InMemoryTelemetrySink,
  OmpHunterPool,
  SHARED_CACHE_HEADER,
  buildCachedInvestigationPrompt,
  classifyAssistantOutcome,
  stripPaidApiEnvVars,
  type HuntDataPlanePort,
} from "../src/index.ts";

const tempDirs: string[] = [];
function makeTmpDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hunt-omp-live-test-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop()!;
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {}
  }
});

function createLiveTestDataPlane(): HuntDataPlanePort {
  const meta: CaseMetadata = {
    case_id: "case-omp-k6",
    title: "Live @oh-my-pi K=6 Concurrency & Isolation",
    data_origin: "synthetic",
    synthetic_only: true,
    time_window: {
      start_iso: "2026-11-01T00:00:00Z",
      end_iso: "2026-11-01T01:00:00Z",
    },
    sources: ["elastic-logs"],
  };

  return {
    caseMetadata: meta,
    capabilities: () => ({
      hasNetworkCapture: true,
      hasIntelSource: true,
      sources: meta.sources,
    }),
    executeTool: async (_tok, toolName, params) => ({
      tool: toolName,
      params,
      events: [{ id: "evt-777", host: "wkstn-07" }],
    }),
    verifyCitations: async (req) => ({
      verified: true,
      checked_at: new Date().toISOString(),
      case_id: req.case_id,
      total_checked: req.event_ids.length,
      missing_event_ids: [],
      missing_frame_ids: [],
      missing_ioc_ids: [],
      ambiguous_ids: [],
      out_of_scope_ids: [],
      source_status: "ok",
    }),
  };
}

describe("Live @oh-my-pi@18.20.0 K=6 Concurrency, Tool Isolation, Cache Header & Cyber Classifier", () => {
  test("runs K=6 parallel createAgentSession hunters in Promise.all with 0 Agent 'Main' collisions, strict custom-tool isolation, tool round-trip & sibling dispose safety", async () => {
    const tmp = makeTmpDir();
    const isolatedAuthDb = path.join(tmp, "isolated_auth.db");
    const authStorage = await AuthStorage.create(isolatedAuthDb);

    // Seed an isolated synthetic OAuth subscription row (far-future expiry so no network refresh occurs)
    // This exercises real OAuth credential resolution, wave preflight, AND oauthAccountPools restriction!
    await authStorage.credentials.set("anthropic", {
      type: "oauth",
      access: "synthetic-oauth-access-bearer",
      refresh: "synthetic-oauth-refresh-bearer",
      expires: Date.now() + 24 * 60 * 60 * 1000,
      email: "hunter-pool@example.local",
      orgId: "org-hunt-01",
    });

    const observedToolSets = new Map<string, string[]>();
    const observedFirstReminderBlocks = new Map<string, string>();
    const observedPromptBlocks = new Map<string, string>();

    const pool = new OmpHunterPool({
      agentDir: tmp,
      subscriptionOnly: true,
      authStorage,
      onSessionCreated: (session, req) => {
        observedToolSets.set(
          req.stepId,
          session.agent.state.tools.map((t) => t.name).sort(),
        );

        // Attach a live in-process streamFn on the real @oh-my-pi AgentSession:
        // Turn 1 invokes `elastic_search` tool; Turn 2 verifies the `<untrusted_tool_result_*>` fence and emits JSON handoff!
        let callIndex = 0;
        session.agent.streamFn = (model, context) => {
          callIndex += 1;
          const stream = new AssistantMessageEventStream();

          const firstMsg = context.messages[0];
          if (firstMsg && firstMsg.role === "user") {
            if (typeof firstMsg.content === "string") {
              observedPromptBlocks.set(req.stepId, firstMsg.content);
            } else {
              const textBlocks = firstMsg.content
                .filter((b) => b.type === "text")
                .map((b) => b.text);
              if (textBlocks.length >= 2) {
                observedFirstReminderBlocks.set(req.stepId, textBlocks[0]!);
                observedPromptBlocks.set(req.stepId, textBlocks[textBlocks.length - 1]!);
              } else if (textBlocks.length === 1) {
                observedPromptBlocks.set(req.stepId, textBlocks[0]!);
              }
            }
          }

          queueMicrotask(async () => {
            // Stagger completion times across K=6 so early sessions call `session.dispose()` while siblings are still mid-turn!
            await Bun.sleep(req.stepId === "follow-1" ? 5 : 25);

            if (callIndex === 1) {
              const toolCallMsg: AssistantMessage = {
                role: "assistant",
                content: [
                  {
                    type: "toolCall",
                    id: `call-${req.stepId}-1`,
                    name: "elastic_search",
                    arguments: { query: `step:${req.stepId}`, size: 5 },
                  },
                ],
                api: model.api,
                provider: model.provider,
                model: model.id,
                usage: {
                  input: 120,
                  output: 30,
                  cacheRead: 80,
                  cacheWrite: 0,
                  totalTokens: 230,
                  cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
                },
                stopReason: "toolUse",
                timestamp: Date.now(),
              };
              stream.push({ type: "done", reason: "toolUse", message: toolCallMsg });
              return;
            }

            // Verify tool result delivered into context was wrapped in our 128-bit nonce fence!
            const toolResultMsg = context.messages.find((m) => m.role === "toolResult");
            const fencedText =
              toolResultMsg && toolResultMsg.role === "toolResult"
                ? toolResultMsg.content
                    .filter((c) => c.type === "text")
                    .map((c) => c.text)
                    .join("")
                : "";
            if (!/<untrusted_tool_result_[0-9a-f]{32}>/.test(fencedText)) {
              throw new Error(`Missing 128-bit nonce fence on toolResult in ${req.stepId}`);
            }

            const finalHandoff = {
              schema_version: 1,
              case_id: req.caseId,
              step_id: req.stepId,
              profile: req.profile,
              claims: [
                {
                  claim_id: `${req.stepId}:c1`,
                  kind: "observed",
                  statement: `Verified evt-777 on wkstn-07 in ${req.stepId}.`,
                  evidence_ids: ["elastic-logs"],
                  entity_ids: [],
                  contradicts: [],
                },
              ],
              reviews: [],
              disposition: "review_ready",
              limitations: [],
              requested_decisions: [],
            };

            const doneMsg: AssistantMessage = {
              role: "assistant",
              content: [{ type: "text", text: JSON.stringify(finalHandoff) }],
              api: model.api,
              provider: model.provider,
              model: model.id,
              usage: {
                input: 150,
                output: 60,
                cacheRead: 100,
                cacheWrite: 0,
                totalTokens: 310,
                cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
              },
              stopReason: "stop",
              timestamp: Date.now(),
            };
            stream.push({ type: "done", reason: "stop", message: doneMsg });
          });

          return stream;
        };
      },
    });

    const dp = createLiveTestDataPlane();
    const telemetry = new InMemoryTelemetrySink();

    // Exercise real single-flight OAuth preflight before K=6 parallel wave fan-out
    await pool.preflightWave(["anthropic"], "run-k6:wave-4");

    // Launch K=6 hunters concurrently in Promise.all!
    const results = await Promise.all(
      Array.from({ length: 6 }, (_, idx) => {
        const stepId = `follow-${idx + 1}`;
        return pool.runTurn({
          executionId: `run-k6:${stepId}`,
          runId: "run-k6",
          caseId: "case-omp-k6",
          stepId,
          wave: "follow_up",
          profile: "framework-researcher",
          syntheticOnly: true,
          dataOrigin: "synthetic",
          userPromptBody: `Investigate slice #${idx + 1}`,
          stageGuidance: `Focus strictly on slice #${idx + 1}.`,
          maxTurns: 6,
          dataPlane: dp,
          telemetry,
        });
      }),
    );

    expect(results.length).toBe(6);
    for (let i = 0; i < 6; i++) {
      const stepId = `follow-${i + 1}`;
      const r = results[i]!;
      expect(r.status).toBe("completed");
      expect(r.usage?.turns).toBe(2);
      expect(r.usage?.total_tokens).toBe(540); // 230 + 310
      expect(r.usage?.actual_billed_usd).toBe(0);
      expect(r.usage?.shadow_api_usd).toBeGreaterThan(0);

      // Verify exact custom tools and zero ambient tools (`bash`, `write`, `edit`, `read`, `task` absent!)
      expect(observedToolSets.get(stepId)).toEqual([
        "elastic_aggregate",
        "elastic_search",
        "hunt_lab_batch",
        "lab_browser",
        "packet_fields",
      ]);

      // Verify prompt-cache sacred invariant:
      // 1) All K=6 siblings share the byte-identical cwd reminder block (so chars [4,7,20] & head cache match!)
      // 2) User prompt block starts with >= 25-char SHARED_CACHE_HEADER and puts stage_guidance at the tail!
      const reminder0 = observedFirstReminderBlocks.get("follow-1");
      if (reminder0 !== undefined) {
        expect(observedFirstReminderBlocks.get(stepId)).toBe(reminder0);
      }
      const userPromptBlock = observedPromptBlocks.get(stepId)!;
      expect(userPromptBlock.startsWith(SHARED_CACHE_HEADER)).toBe(true);
      expect(userPromptBlock.endsWith(`## Stage Guidance\nFocus strictly on slice #${i + 1}.`)).toBe(
        true,
      );
    }

    // Verify all 6 elastic_search calls were recorded in telemetry
    expect(telemetry.toolCalls.length).toBe(6);
    pool.close();
  });

  test("strips paid *_API_KEY env vars, enforces stage_guidance <= 600B, and classifies non-throwing cyber refusals & 404 invalid_model", () => {
    const fakeEnv: Record<string, string | undefined> = {
      // health: allow FORBIDDEN_TOKEN -- synthetic test fixture
      ANTHROPIC_API_KEY: "sk-ant-synthetic0000",
      OPENAI_API_KEY: "synthetic-openai",
      CODEX_API_KEY: "synthetic-codex",
      GEMINI_API_KEY: "synthetic-gemini",
      GOOGLE_API_KEY: "synthetic-google",
      GOOGLE_GENAI_USE_VERTEXAI: "1",
      SAFE_VAR: "keep-me",
    };
    const removed = stripPaidApiEnvVars(fakeEnv);
    expect(removed.sort()).toEqual([...FORBIDDEN_SUBSCRIPTION_ENV_KEYS].sort());
    expect(fakeEnv.SAFE_VAR).toBe("keep-me");

    // stage_guidance > 600B rejected
    expect(() =>
      buildCachedInvestigationPrompt({
        body: "Scope body",
        stageGuidance: "x".repeat(601),
        syntheticOnly: true,
      }),
    ).toThrow(/exceeds 600/);

    // 1. Anthropic `stopDetails: { type: "refusal", category: "cyber" }` -> honest `cyber_refusal`
    const anthropicRefusal = classifyAssistantOutcome({
      role: "assistant",
      content: [],
      api: "anthropic-messages",
      provider: "anthropic",
      model: "claude-opus-4-6",
      usage: {
        input: 50,
        output: 0,
        cacheRead: 0,
        cacheWrite: 0,
        totalTokens: 50,
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
      },
      stopReason: "error",
      stopDetails: { type: "refusal", category: "cyber" } as never,
      timestamp: Date.now(),
    });
    expect(anthropicRefusal.kind).toBe("refused");
    if (anthropicRefusal.kind === "refused") {
      expect(anthropicRefusal.refusal.category).toBe("cyber");
      expect(anthropicRefusal.refusal.finish_reason).toBe("content_filter");
    }

    // 2. `AIError.Flag.ContentBlocked` bitmask -> honest `cyber_refusal`
    const contentBlocked = classifyAssistantOutcome({
      role: "assistant",
      content: [],
      api: "openai-responses",
      provider: "openai-codex",
      model: "gpt-5.4",
      usage: {
        input: 20,
        output: 0,
        cacheRead: 0,
        cacheWrite: 0,
        totalTokens: 20,
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
      },
      stopReason: "error",
      errorId: AIError.Flag.Class | AIError.Flag.ContentBlocked,
      errorMessage: "Blocked by safety classifier",
      timestamp: Date.now(),
    });
    expect(contentBlocked.kind).toBe("refused");

    // 3. HTTP 404 / unsupported model -> `invalid_model`
    const notFoundModel = classifyAssistantOutcome({
      role: "assistant",
      content: [],
      api: "anthropic-messages",
      provider: "anthropic",
      model: "claude-nonexistent-99",
      usage: {
        input: 0,
        output: 0,
        cacheRead: 0,
        cacheWrite: 0,
        totalTokens: 0,
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
      },
      stopReason: "error",
      errorStatus: 404,
      errorMessage: "404 not_found_error: model claude-nonexistent-99 does not exist",
      timestamp: Date.now(),
    });
    expect(notFoundModel.kind).toBe("failed");
    if (notFoundModel.kind === "failed") {
      expect(notFoundModel.reasonCode).toBe("invalid_model");
    }
  });
});
