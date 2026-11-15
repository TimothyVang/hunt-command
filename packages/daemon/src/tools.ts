import type { TSchema } from "@oh-my-pi/pi-ai";
import type { CustomTool } from "@oh-my-pi/pi-coding-agent";
import {
  BATCH_EXCLUDED_TOOLS,
  BATCH_MAX_BYTES,
  BATCH_MAX_ITEMS,
  BATCH_MAX_ITEM_SIZE,
  DATA_PLANE_TOOLS,
  DataPlaneAccessError,
  FRAMEWORK_PROFILES,
  MAX_DELEGATED_QUESTIONS,
  getAllowedToolsForStep,
  type DataOrigin,
  type DataPlaneToolName,
  type HuntToolName,
  type HuntWave,
  type ProfileId,
} from "@hunt-command/shared";
import type {
  DelegateTaskContext,
  HuntDataPlanePort,
  ModelRunnerPort,
  TelemetrySinkPort,
} from "./ports.ts";
import {
  RoleCapabilityAuthority,
  fenceToolOutput,
  truncateUtf8Safe,
} from "./scrubber-and-fence.ts";

export const DELEGATE_MAX_SPAWN_DEPTH = 1;
export const DELEGATE_MAX_ITERATIONS = 8;
export const DELEGATE_MAX_SUMMARY_CHARS = 4_000;

const INTEGER_PARAM_KEYS = new Set([
  "size",
  "limit",
  "top_n",
  "max_packets",
  "start_frame",
  "end_frame",
  "offset",
  "from",
]);

const STRIPPED_CALLER_ROLE_KEYS = new Set([
  "profile",
  "role",
  "agent_role",
  "capability_token",
  "capabilityToken",
  "hmac",
]);

function normalizeDataPlaneParams(rawParams: unknown): Record<string, unknown> {
  if (rawParams === null || typeof rawParams !== "object" || Array.isArray(rawParams)) {
    return {};
  }
  const normalized: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(rawParams as Record<string, unknown>)) {
    // Never forward LLM-supplied role/capability fields to the data plane
    if (STRIPPED_CALLER_ROLE_KEYS.has(key)) {
      continue;
    }
    if (INTEGER_PARAM_KEYS.has(key) && typeof val === "string" && /^-?\d+$/.test(val.trim())) {
      normalized[key] = Number.parseInt(val.trim(), 10);
    } else {
      normalized[key] = val;
    }
  }
  return normalized;
}

const DATA_PLANE_TOOL_SCHEMAS: Readonly<
  Record<DataPlaneToolName, { label: string; description: string; schema: Record<string, unknown> }>
> = {
  elastic_search: {
    label: "Elastic Search",
    description: "Read-only Lucene/KQL query over case telemetry events.",
    schema: {
      type: "object",
      properties: {
        query: { type: "string", description: "Lucene or field:value query (no leading wildcards)." },
        size: { type: "integer", minimum: 1, maximum: 100, description: "Max hits to return." },
        fields: {
          type: "array",
          items: { type: "string" },
          description: "Optional allowlisted fields to project.",
        },
        sort: { type: "string", description: "Optional timestamp sort order (asc or desc)." },
      },
      required: ["query"],
      additionalProperties: true,
    },
  },
  elastic_aggregate: {
    label: "Elastic Aggregate",
    description: "Read-only field bucket aggregation over case telemetry.",
    schema: {
      type: "object",
      properties: {
        field: { type: "string", description: "Field name to aggregate on." },
        query: { type: "string", description: "Optional filter query." },
        size: { type: "integer", minimum: 1, maximum: 100, description: "Top buckets count." },
      },
      required: ["field"],
      additionalProperties: true,
    },
  },
  detection_test: {
    label: "Detection Rule Test",
    description: "Read-only dry-run evaluation of a candidate detection query against case logs.",
    schema: {
      type: "object",
      properties: {
        rule_name: { type: "string" },
        query: { type: "string" },
        size: { type: "integer", minimum: 1, maximum: 50 },
      },
      required: ["query"],
      additionalProperties: true,
    },
  },
  intel_lookup: {
    label: "Threat Intel Lookup",
    description: "Read-only lookup against offline/local case threat intelligence indicators.",
    schema: {
      type: "object",
      properties: {
        indicator: { type: "string", description: "IP, domain, hash, or IOC string." },
        indicator_type: { type: "string" },
        size: { type: "integer", minimum: 1, maximum: 50 },
      },
      required: ["indicator"],
      additionalProperties: true,
    },
  },
  arkime_sessions: {
    label: "Arkime Network Sessions",
    description: "Read-only network session query over case PCAP/session metadata.",
    schema: {
      type: "object",
      properties: {
        expression: { type: "string", description: "Session filter expression." },
        size: { type: "integer", minimum: 1, maximum: 100 },
      },
      additionalProperties: true,
    },
  },
  arkime_unique: {
    label: "Arkime Unique Values",
    description: "Read-only unique network field counts over case PCAP/sessions.",
    schema: {
      type: "object",
      properties: {
        field: { type: "string" },
        expression: { type: "string" },
        size: { type: "integer", minimum: 1, maximum: 100 },
      },
      required: ["field"],
      additionalProperties: true,
    },
  },
  packet_fields: {
    label: "Packet Fields Dissection",
    description: "Read-only frame-level packet field inspection for specific PCAP frames.",
    schema: {
      type: "object",
      properties: {
        filter: { type: "string", description: "Display filter or frame selector." },
        fields: { type: "array", items: { type: "string" } },
        max_packets: { type: "integer", minimum: 1, maximum: 50 },
      },
      additionalProperties: true,
    },
  },
  hunt_lab_query: {
    label: "Hunt Lab Structured Query",
    description: "Read-only structured lab query over auxiliary network/case tables.",
    schema: {
      type: "object",
      properties: {
        table: { type: "string" },
        query: { type: "string" },
        size: { type: "integer", minimum: 1, maximum: 100 },
      },
      additionalProperties: true,
    },
  },
  lab_browser: {
    label: "Lab Case Artifact Browser",
    description: "Read-only inspection of local case manifest or artifact summaries.",
    schema: {
      type: "object",
      properties: {
        view: { type: "string" },
        target: { type: "string" },
      },
      additionalProperties: true,
    },
  },
};

export interface BuildSessionCustomToolsOptions {
  readonly runId: string;
  readonly caseId: string;
  readonly stepId: string;
  readonly wave: HuntWave;
  readonly profile: ProfileId;
  readonly syntheticOnly: boolean;
  readonly dataOrigin: DataOrigin;
  readonly capabilityAuthority: RoleCapabilityAuthority;
  readonly dataPlane: HuntDataPlanePort;
  readonly telemetry: TelemetrySinkPort;
  readonly modelRunner?: ModelRunnerPort;
  readonly delegateContext?: DelegateTaskContext;
  readonly isDelegatedChild?: boolean;
  readonly allowedToolsOverride?: readonly HuntToolName[];
  readonly parentSignal?: AbortSignal;
}

function isDataPlaneTool(name: string): name is DataPlaneToolName {
  return (DATA_PLANE_TOOLS as readonly string[]).includes(name);
}

function isBatchExcludedTool(name: string): boolean {
  return (BATCH_EXCLUDED_TOOLS as readonly string[]).includes(name);
}

const SPECIALIST_PROFILES = FRAMEWORK_PROFILES.filter(
  (p): p is Exclude<ProfileId, "framework-coordinator"> => p !== "framework-coordinator",
);

/**
 * Builds isolated `@oh-my-pi` `CustomTool` definitions for a single `(runId, stepId, profile)` session.
 * Every returned tool:
 * - Closes over a cryptographically signed `RoleCapabilityToken`
 * - Enforces read-only + strict role tool ownership (`403 tool_not_owned`, `405 read_only`)
 * - Wraps ALL outputs (and errors) in `<untrusted_tool_result_${nonce128}>` (`<= 24_576 B` pre-wrap)
 */
export function buildSessionCustomTools(options: BuildSessionCustomToolsOptions): CustomTool[] {
  const baseAllowed =
    options.allowedToolsOverride ?? getAllowedToolsForStep(options.profile, options.stepId);

  // Delegated specialist children (depth >= 1) can NEVER recursively call delegate_task
  const allowedToolNames = options.isDelegatedChild
    ? baseAllowed.filter((name) => name !== "delegate_task")
    : [...baseAllowed];

  const capabilityToken = options.capabilityAuthority.mint(
    options.runId,
    options.stepId,
    options.profile,
  );

  const tools: CustomTool[] = [];
  let delegatedCallCount = 0;

  for (const toolName of allowedToolNames) {
    if (isDataPlaneTool(toolName)) {
      const meta = DATA_PLANE_TOOL_SCHEMAS[toolName];
      tools.push({
        name: toolName,
        label: meta.label,
        description: meta.description,
        loadMode: "essential",
        approval: "read",
        parameters: meta.schema as unknown as TSchema,
        async execute(_toolCallId, rawParams, _onUpdate, _ctx, callSignal) {
          const startedAt = performance.now();
          const effectiveSignal =
            options.parentSignal && callSignal
              ? AbortSignal.any([options.parentSignal, callSignal])
              : (callSignal ?? options.parentSignal);

          try {
            effectiveSignal?.throwIfAborted();
            const cleanParams = normalizeDataPlaneParams(rawParams);
            options.capabilityAuthority.authorizeToolCall(capabilityToken, toolName, cleanParams);
            const rawResult = await options.dataPlane.executeTool(
              capabilityToken,
              toolName,
              cleanParams,
              effectiveSignal,
            );
            const fenced = fenceToolOutput(rawResult);
            options.telemetry.onToolCall?.({
              runId: options.runId,
              stepId: options.stepId,
              profile: options.profile,
              toolName,
              durationMs: Math.round(performance.now() - startedAt),
              isError: false,
              fencedBytes: fenced.innerBytes,
            });
            return {
              content: [{ type: "text", text: fenced.wrappedText }],
            };
          } catch (err) {
            const errorCode =
              err instanceof DataPlaneAccessError ? err.errorCode : "tool_execution_error";
            const statusCode = err instanceof DataPlaneAccessError ? err.statusCode : 400;
            const fenced = fenceToolOutput({
              ok: false,
              status: statusCode,
              error_code: errorCode,
              message: err instanceof Error ? err.message : String(err),
            });
            options.telemetry.onToolCall?.({
              runId: options.runId,
              stepId: options.stepId,
              profile: options.profile,
              toolName,
              durationMs: Math.round(performance.now() - startedAt),
              isError: true,
              errorCode,
              fencedBytes: fenced.innerBytes,
            });
            return {
              content: [{ type: "text", text: fenced.wrappedText }],
              isError: true,
            };
          }
        },
      });
      continue;
    }

    if (toolName === "hunt_lab_batch") {
      tools.push({
        name: "hunt_lab_batch",
        label: "Hunt Lab Batch Query",
        description:
          `Execute 1..${BATCH_MAX_ITEMS} read-only data-plane queries owned by your role in one turn ` +
          `(per-item size <= ${BATCH_MAX_ITEM_SIZE}; excludes ${BATCH_EXCLUDED_TOOLS.join(", ")}).`,
        loadMode: "essential",
        approval: "read",
        parameters: {
          type: "object",
          properties: {
            queries: {
              type: "array",
              minItems: 1,
              maxItems: BATCH_MAX_ITEMS,
              items: {
                type: "object",
                properties: {
                  tool: { type: "string", description: "Data-plane tool name owned by this role." },
                  params: {
                    type: "object",
                    description: "Read-only parameters for that tool (size <= 25).",
                    additionalProperties: true,
                  },
                },
                required: ["tool"],
                additionalProperties: false,
              },
            },
          },
          required: ["queries"],
          additionalProperties: false,
        } as unknown as TSchema,
        async execute(_toolCallId, rawParams, _onUpdate, _ctx, callSignal) {
          const startedAt = performance.now();
          const effectiveSignal =
            options.parentSignal && callSignal
              ? AbortSignal.any([options.parentSignal, callSignal])
              : (callSignal ?? options.parentSignal);

          try {
            effectiveSignal?.throwIfAborted();
            options.capabilityAuthority.authorizeToolCall(capabilityToken, "hunt_lab_batch", {});

            const body =
              rawParams !== null && typeof rawParams === "object"
                ? (rawParams as Record<string, unknown>)
                : {};
            const queries = body.queries;
            if (!Array.isArray(queries) || queries.length < 1 || queries.length > BATCH_MAX_ITEMS) {
              throw new DataPlaneAccessError(
                400,
                "invalid_query",
                `hunt_lab_batch requires 1..${BATCH_MAX_ITEMS} items in 'queries'`,
              );
            }

            const batchResults: Array<{
              index: number;
              tool: string;
              ok: boolean;
              status?: number;
              error_code?: string;
              result?: unknown;
              truncated?: boolean;
            }> = [];
            let cumulativeRawBytes = 0;

            for (let idx = 0; idx < queries.length; idx++) {
              effectiveSignal?.throwIfAborted();
              const item = queries[idx];
              if (item === null || typeof item !== "object" || Array.isArray(item)) {
                throw new DataPlaneAccessError(
                  400,
                  "invalid_query",
                  `hunt_lab_batch item[${idx}] must be an object`,
                );
              }
              const rec = item as Record<string, unknown>;
              const subTool = typeof rec.tool === "string" ? rec.tool.trim() : "";
              if (!subTool || isBatchExcludedTool(subTool)) {
                throw new DataPlaneAccessError(
                  400,
                  "invalid_query",
                  `Tool '${subTool}' cannot be invoked via hunt_lab_batch (excluded: ${BATCH_EXCLUDED_TOOLS.join(", ")})`,
                );
              }
              if (!isDataPlaneTool(subTool)) {
                throw new DataPlaneAccessError(
                  403,
                  "tool_not_owned",
                  `Unknown or forbidden sub-tool '${subTool}' in hunt_lab_batch`,
                );
              }

              const subParams = normalizeDataPlaneParams(rec.params ?? {});
              // Enforce item size <= 25 (BATCH_MAX_ITEM_SIZE)
              if (subParams.size !== undefined) {
                if (
                  typeof subParams.size !== "number" ||
                  !Number.isInteger(subParams.size) ||
                  subParams.size < 1 ||
                  subParams.size > BATCH_MAX_ITEM_SIZE
                ) {
                  throw new DataPlaneAccessError(
                    400,
                    "invalid_query",
                    `hunt_lab_batch item[${idx}] size must be an integer within 1..${BATCH_MAX_ITEM_SIZE}`,
                  );
                }
              } else {
                subParams.size = BATCH_MAX_ITEM_SIZE;
              }

              // Authorize sub-tool against closure-bound role token (403 tool_not_owned / 405 read_only)
              options.capabilityAuthority.authorizeToolCall(capabilityToken, subTool, subParams);

              if (cumulativeRawBytes >= BATCH_MAX_BYTES) {
                batchResults.push({
                  index: idx,
                  tool: subTool,
                  ok: false,
                  error_code: "batch_byte_cap_reached",
                  truncated: true,
                });
                continue;
              }

              const subOut = await options.dataPlane.executeTool(
                capabilityToken,
                subTool,
                subParams,
                effectiveSignal,
              );
              const subSerialized = JSON.stringify(subOut ?? null);
              const subBytes = Buffer.byteLength(subSerialized, "utf8");
              const remainingBatchBudget = Math.max(0, BATCH_MAX_BYTES - cumulativeRawBytes);

              if (subBytes > remainingBatchBudget) {
                const clipped = truncateUtf8Safe(subSerialized, remainingBatchBudget);
                cumulativeRawBytes = BATCH_MAX_BYTES;
                batchResults.push({
                  index: idx,
                  tool: subTool,
                  ok: true,
                  result: `${clipped.text}...[batch_cap_96KiB]`,
                  truncated: true,
                });
              } else {
                cumulativeRawBytes += subBytes;
                batchResults.push({
                  index: idx,
                  tool: subTool,
                  ok: true,
                  result: subOut,
                });
              }
            }

            const fenced = fenceToolOutput({
              ok: true,
              batch_count: batchResults.length,
              raw_batch_bytes: cumulativeRawBytes,
              batch_cap_bytes: BATCH_MAX_BYTES,
              items: batchResults,
            });

            options.telemetry.onToolCall?.({
              runId: options.runId,
              stepId: options.stepId,
              profile: options.profile,
              toolName: "hunt_lab_batch",
              durationMs: Math.round(performance.now() - startedAt),
              isError: false,
              fencedBytes: fenced.innerBytes,
            });

            return {
              content: [{ type: "text", text: fenced.wrappedText }],
            };
          } catch (err) {
            const errorCode =
              err instanceof DataPlaneAccessError ? err.errorCode : "batch_execution_error";
            const statusCode = err instanceof DataPlaneAccessError ? err.statusCode : 400;
            const fenced = fenceToolOutput({
              ok: false,
              status: statusCode,
              error_code: errorCode,
              message: err instanceof Error ? err.message : String(err),
            });
            options.telemetry.onToolCall?.({
              runId: options.runId,
              stepId: options.stepId,
              profile: options.profile,
              toolName: "hunt_lab_batch",
              durationMs: Math.round(performance.now() - startedAt),
              isError: true,
              errorCode,
              fencedBytes: fenced.innerBytes,
            });
            return {
              content: [{ type: "text", text: fenced.wrappedText }],
              isError: true,
            };
          }
        },
      });
      continue;
    }

    if (toolName === "delegate_task") {
      tools.push({
        name: "delegate_task",
        label: "Delegate Bounded Specialist Question",
        description:
          `Ask a bounded specialist hunter (max ${MAX_DELEGATED_QUESTIONS} calls per stage, ` +
          `max_spawn_depth=${DELEGATE_MAX_SPAWN_DEPTH}, max_iterations=${DELEGATE_MAX_ITERATIONS}, ` +
          `max_summary_chars=${DELEGATE_MAX_SUMMARY_CHARS}).`,
        loadMode: "essential",
        approval: "read",
        parameters: {
          type: "object",
          properties: {
            specialist_profile: {
              type: "string",
              enum: [...SPECIALIST_PROFILES],
              description: "Specialist hunter profile to run.",
            },
            question: {
              type: "string",
              description: "Focused, evidence-verifiable question for the specialist.",
            },
          },
          required: ["specialist_profile", "question"],
          additionalProperties: false,
        } as unknown as TSchema,
        async execute(_toolCallId, rawParams, _onUpdate, _ctx, callSignal) {
          const startedAt = performance.now();
          const effectiveSignal =
            options.parentSignal && callSignal
              ? AbortSignal.any([options.parentSignal, callSignal])
              : (callSignal ?? options.parentSignal);

          try {
            effectiveSignal?.throwIfAborted();
            options.capabilityAuthority.authorizeToolCall(capabilityToken, "delegate_task", {});

            if (options.isDelegatedChild) {
              throw new DataPlaneAccessError(
                403,
                "tool_not_owned",
                `max_spawn_depth=${DELEGATE_MAX_SPAWN_DEPTH} exceeded: specialist children cannot call delegate_task`,
              );
            }
            if (!options.modelRunner) {
              throw new Error("delegate_task unavailable: no modelRunner attached");
            }
            if (delegatedCallCount >= MAX_DELEGATED_QUESTIONS) {
              throw new Error(
                `delegate_task limit reached (${MAX_DELEGATED_QUESTIONS} max specialist questions per coordinator step)`,
              );
            }

            const body =
              rawParams !== null && typeof rawParams === "object"
                ? (rawParams as Record<string, unknown>)
                : {};
            const specialistProfile =
              typeof body.specialist_profile === "string" ? body.specialist_profile.trim() : "";
            const question = typeof body.question === "string" ? body.question.trim() : "";

            if (
              !(SPECIALIST_PROFILES as readonly string[]).includes(specialistProfile)
            ) {
              throw new DataPlaneAccessError(
                403,
                "tool_not_owned",
                `Invalid specialist_profile '${specialistProfile}'; must be one of [${SPECIALIST_PROFILES.join(", ")}]`,
              );
            }
            if (question.length === 0 || Buffer.byteLength(question, "utf8") > 4_096) {
              throw new Error("delegate_task 'question' must be 1..4096 UTF-8 bytes");
            }

            // Enforce run token cap BEFORE dispatching child specialist session
            options.delegateContext?.checkBudgetBeforeDelegate();

            delegatedCallCount += 1;
            const delegateIndex = delegatedCallCount;
            const delegateStepId = `${options.stepId}__delegate_${delegateIndex}`;
            const childProfile = specialistProfile as Exclude<ProfileId, "framework-coordinator">;

            const childPrompt = [
              `## Bounded Specialist Question (Parent Step: ${options.stepId})`,
              `Case ID: ${options.caseId}`,
              `Specialist Role: ${childProfile}`,
              `Question: ${question}`,
              "",
              `Investigate using your read-only case tools and return a concise factual summary (<= ${DELEGATE_MAX_SUMMARY_CHARS} chars) citing exact source_ids and inline evt-*/frame-*/ioc-* identifiers.`,
            ].join("\n");

            const childResult = await options.modelRunner.runTurn({
              executionId: `${options.runId}:${delegateStepId}`,
              runId: options.runId,
              caseId: options.caseId,
              stepId: delegateStepId,
              wave: options.wave,
              profile: childProfile,
              syntheticOnly: options.syntheticOnly,
              dataOrigin: options.dataOrigin,
              userPromptBody: childPrompt,
              maxTurns: DELEGATE_MAX_ITERATIONS,
              isDelegatedChild: true,
              dataPlane: options.dataPlane,
              telemetry: options.telemetry,
              signal: effectiveSignal,
            });

            options.delegateContext?.onDelegatedUsage({
              delegate_id: delegateStepId,
              parent_step_id: options.stepId,
              specialist_profile: childProfile,
              question,
              status: childResult.status,
              reason_code: childResult.reason_code,
              usage: childResult.usage,
              created_at: new Date().toISOString(),
            });

            const clippedSummary =
              childResult.output_text.length > DELEGATE_MAX_SUMMARY_CHARS
                ? `${childResult.output_text.slice(0, DELEGATE_MAX_SUMMARY_CHARS)}...[truncated_to_${DELEGATE_MAX_SUMMARY_CHARS}_chars]`
                : childResult.output_text;

            const fenced = fenceToolOutput({
              ok: childResult.status === "completed",
              delegate_id: delegateStepId,
              specialist_profile: childProfile,
              status: childResult.status,
              reason_code: childResult.reason_code ?? null,
              summary: clippedSummary,
            });

            options.telemetry.onToolCall?.({
              runId: options.runId,
              stepId: options.stepId,
              profile: options.profile,
              toolName: "delegate_task",
              durationMs: Math.round(performance.now() - startedAt),
              isError: childResult.status !== "completed",
              errorCode: childResult.reason_code,
              fencedBytes: fenced.innerBytes,
            });

            return {
              content: [{ type: "text", text: fenced.wrappedText }],
              ...(childResult.status !== "completed" ? { isError: true } : {}),
            };
          } catch (err) {
            const errorCode =
              err instanceof DataPlaneAccessError ? err.errorCode : "delegate_task_error";
            const fenced = fenceToolOutput({
              ok: false,
              error_code: errorCode,
              message: err instanceof Error ? err.message : String(err),
            });
            options.telemetry.onToolCall?.({
              runId: options.runId,
              stepId: options.stepId,
              profile: options.profile,
              toolName: "delegate_task",
              durationMs: Math.round(performance.now() - startedAt),
              isError: true,
              errorCode,
              fencedBytes: fenced.innerBytes,
            });
            return {
              content: [{ type: "text", text: fenced.wrappedText }],
              isError: true,
            };
          }
        },
      });
    }
  }

  return tools;
}
