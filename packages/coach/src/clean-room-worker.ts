import fs from "node:fs";
import path from "node:path";
import {
  AgentRegistry,
  createAgentSession,
  SessionManager,
  Settings,
  type AgentSessionEvent,
  type CreateAgentSessionOptions,
} from "@oh-my-pi/pi-coding-agent";

export const CLEAN_ROOM_TOOL_ABORT_EXIT_CODE = 86 as const;

/**
 * Capability / MCP / ambient discovery providers disabled in every clean-room
 * proposer and verifier session (matching upstream `no-mcp.yml`).
 */
export const DISABLED_MCP_PROVIDERS = [
  "claude",
  "claude-plugins",
  "codex",
  "cursor",
  "gemini",
  "github",
  "kimi",
  "mcp-json",
  "opencode",
  "pi",
  "vscode",
  "windsurf",
  "zed",
  "amp",
  "cline",
  "continue",
  "goose",
  "roo",
] as const;

export const EXPLICIT_STRIPPED_ENV_KEYS = [
  "ANTHROPIC_API_KEY",
  "OPENAI_API_KEY",
  "CODEX_API_KEY",
  "GEMINI_API_KEY",
  "GOOGLE_API_KEY",
  "OPENROUTER_API_KEY",
  "FIREWORKS_API_KEY",
  "TOGETHER_API_KEY",
  "MISTRAL_API_KEY",
  "XAI_API_KEY",
  "DEEPSEEK_API_KEY",
  "GROQ_API_KEY",
  "PERPLEXITY_API_KEY",
  "COHERE_API_KEY",
  "VOYAGE_API_KEY",
  "EXA_API_KEY",
  "BRAVE_API_KEY",
  "TAVILY_API_KEY",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_SESSION_TOKEN",
  "AZURE_OPENAI_API_KEY",
  "OMP_AUTH_BROKER_TOKEN",
] as const;

const EXPLICIT_STRIPPED_SET: ReadonlySet<string> = new Set(
  EXPLICIT_STRIPPED_ENV_KEYS.map((k) => k.toUpperCase()),
);

export type CleanRoomRole =
  | "proposer"
  | "verifier-1"
  | "verifier-2"
  | "verifier-3";

export class CleanRoomViolationError extends Error {
  public readonly code: string;

  public constructor(code: string, message: string) {
    super(message);
    this.name = "CleanRoomViolationError";
    this.code = code;
  }
}

export class CleanRoomToolViolationError extends CleanRoomViolationError {
  public readonly toolName: string;
  public readonly toolCallId: string | undefined;

  public constructor(toolName: string, toolCallId?: string) {
    super(
      "clean_room_tool_execution_forbidden",
      `Zero-tool clean-room violation: session attempted tool_execution_start ('${toolName}'${toolCallId ? `, id='${toolCallId}'` : ""})`,
    );
    this.name = "CleanRoomToolViolationError";
    this.toolName = toolName;
    this.toolCallId = toolCallId;
  }
}

export interface CleanRoomSessionSpec {
  readonly cwd: string;
  readonly tools: readonly [];
  readonly customTools: readonly [];
  readonly toolNames: readonly [];
  readonly mountedToolNames: readonly [];
  readonly restrictToolNames: true;
  readonly allowRestrictedCustomTools: false;
  readonly spawns: readonly [];
  readonly enableMCP: false;
  readonly enableLsp: false;
  readonly enableIrc: false;
  readonly skills: readonly [];
  readonly rules: readonly [];
  readonly contextFiles: readonly [];
  readonly promptTemplates: readonly [];
  readonly slashCommands: readonly [];
  readonly additionalDirectories: readonly [];
  readonly noContextFiles: true;
  readonly excludeAgentsMd: true;
  readonly disableExtensionDiscovery: true;
  readonly cacheWarming: false;
  readonly bindProcessState: false;
  readonly hasUI: false;
  readonly interactivePrompts: false;
  readonly autoApprove: false;
  readonly disableModelFallback: true;
  readonly disableServerSideFallback: true;
  readonly subscriptionOnly: true;
  readonly disabledProviders: readonly string[];
}

export interface CleanRoomUsageSummary {
  readonly input_tokens: number;
  readonly output_tokens: number;
  readonly cache_read_tokens: number;
  readonly cache_write_tokens: number;
  readonly total_tokens: number;
}

export interface CleanRoomWorkerTurnRequest {
  readonly role: CleanRoomRole;
  readonly emptyTmpDir: string;
  readonly repoRoot?: string;
  readonly systemPrompt: string;
  readonly prompt: string;
  readonly modelPattern?: string;
  readonly deadlineMs?: number;
  /**
   * Deterministic test-only hooks gated by `allowTestSimulation: true` or
   * `HUNT_COACH_ALLOW_TEST_SIM=1` so out-of-process child-worker tests can
   * prove immediate hard-abort on `tool_execution_start` and clean completion
   * without network credentials.
   */
  readonly simulateToolStart?: {
    readonly toolName: string;
    readonly toolCallId?: string;
  };
  readonly mockResponseText?: string;
}

export interface CleanRoomWorkerTurnResult {
  readonly role: CleanRoomRole;
  readonly text: string;
  readonly model: string;
  readonly provider: string;
  readonly usage: CleanRoomUsageSummary;
  readonly activeToolCount: 0;
}

export type CleanRoomWorkerWireFrame =
  | {
      readonly type: "ready";
      readonly role: CleanRoomRole;
      readonly cwd: string;
      readonly activeToolCount: 0;
    }
  | {
      readonly type: "tool_execution_start";
      readonly role: CleanRoomRole;
      readonly toolName: string;
      readonly toolCallId?: string;
    }
  | {
      readonly type: "result";
      readonly result: CleanRoomWorkerTurnResult;
    }
  | {
      readonly type: "error";
      readonly code: string;
      readonly message: string;
    };

export interface CleanRoomAgentSessionLike {
  readonly state: {
    readonly tools: readonly unknown[];
  };
  getActiveToolNames(): string[];
  getEnabledToolNames(): string[];
  subscribe(listener: (event: AgentSessionEvent) => void): () => void;
  disableStopTimeTodoReminders(): void;
  prepareForHeadlessAdvisorDrain(): void;
  prompt(
    text: string,
    options?: {
      expandPromptTemplates?: boolean;
      throwOnDrop?: boolean;
    },
  ): Promise<boolean>;
  getLastAssistantMessage():
    | {
        readonly role: "assistant";
        readonly content: ReadonlyArray<
          | { readonly type: "text"; readonly text: string }
          | { readonly type: "toolCall"; readonly name: string; readonly id?: string }
          | { readonly type: string }
        >;
        readonly provider?: string;
        readonly model?: string;
        readonly stopReason?: string;
        readonly errorMessage?: string;
        readonly usage?: {
          readonly input?: number;
          readonly output?: number;
          readonly cacheRead?: number;
          readonly cacheWrite?: number;
          readonly totalTokens?: number;
        };
      }
    | undefined;
  abort(options?: { reason?: string }): Promise<void>;
  dispose(): Promise<void>;
}

export interface ExecuteCleanRoomTurnOptions {
  readonly env?: Readonly<Record<string, string | undefined>>;
  readonly allowTestSimulation?: boolean;
  readonly onToolStart?: (toolName: string, toolCallId?: string) => void;
  readonly sessionFactory?: (
    ompOptions: CreateAgentSessionOptions,
    spec: CleanRoomSessionSpec,
  ) => Promise<{ session: CleanRoomAgentSessionLike }>;
}

export function isApiKeyEnvName(envKey: string): boolean {
  const upper = envKey.toUpperCase();
  if (EXPLICIT_STRIPPED_SET.has(upper)) {
    return true;
  }
  return upper === "API_KEY" || upper.endsWith("_API_KEY");
}

export function findLeakedApiKeysInEnv(
  env: Readonly<Record<string, string | undefined>>,
): string[] {
  const leaked: string[] = [];
  for (const [key, val] of Object.entries(env)) {
    if (val !== undefined && val.length > 0 && isApiKeyEnvName(key)) {
      leaked.push(key);
    }
  }
  leaked.sort();
  return leaked;
}

export function assertSubscriptionOnlyEnv(
  env: Readonly<Record<string, string | undefined>> = process.env,
): void {
  const leaked = findLeakedApiKeysInEnv(env);
  if (leaked.length > 0) {
    throw new CleanRoomViolationError(
      "leaked_api_key_in_env",
      `Clean-room subscriptionOnly violation: forbidden API key env var(s) present: ${leaked.join(", ")}`,
    );
  }
}

function normalizePathForComparison(targetPath: string): string {
  const resolved = path.resolve(targetPath);
  const real = fs.existsSync(resolved) ? fs.realpathSync(resolved) : resolved;
  const slashed = real.replace(/\\/g, "/").replace(/\/+$/, "");
  return process.platform === "win32" ? slashed.toLowerCase() : slashed;
}

function isSubpathOrEqual(candidateNorm: string, parentNorm: string): boolean {
  if (candidateNorm === parentNorm) {
    return true;
  }
  return candidateNorm.startsWith(`${parentNorm}/`);
}

/**
 * Verifies `dirPath` exists, is an empty directory (`0` entries), is NOT inside
 * `repoRoot` (or its parent checkout if `repoRoot` is a `.worktrees/<id>` checkout),
 * and contains no `runtime` or `operator-only` segment anywhere in its path.
 */
export function assertEmptyOutsideRepoAndRuntimeDir(
  dirPath: string,
  options?: { repoRoot?: string },
): void {
  if (!dirPath || typeof dirPath !== "string") {
    throw new CleanRoomViolationError(
      "invalid_clean_room_cwd",
      "Clean-room temp directory path must be a non-empty string",
    );
  }

  const resolved = path.resolve(dirPath);
  if (!fs.existsSync(resolved)) {
    throw new CleanRoomViolationError(
      "missing_clean_room_cwd",
      `Clean-room temp directory does not exist: '${resolved}'`,
    );
  }

  const stat = fs.statSync(resolved);
  if (!stat.isDirectory()) {
    throw new CleanRoomViolationError(
      "invalid_clean_room_cwd",
      `Clean-room temp path is not a directory: '${resolved}'`,
    );
  }

  const normDir = normalizePathForComparison(resolved);
  const segments = normDir.split("/").filter((s) => s.length > 0);
  for (const seg of segments) {
    if (seg === "runtime" || seg === "operator-only" || seg === ".worktrees") {
      throw new CleanRoomViolationError(
        "forbidden_clean_room_cwd_segment",
        `Clean-room temp directory '${resolved}' contains forbidden path segment '${seg}'`,
      );
    }
  }

  if (options?.repoRoot) {
    const normRepo = normalizePathForComparison(options.repoRoot);
    if (isSubpathOrEqual(normDir, normRepo) || isSubpathOrEqual(normRepo, normDir)) {
      throw new CleanRoomViolationError(
        "clean_room_cwd_inside_repo",
        `Clean-room temp directory '${resolved}' must be strictly outside repoRoot '${options.repoRoot}'`,
      );
    }
    // If repoRoot is inside `<checkout>/.worktrees/<name>`, also block `<checkout>`.
    const wtMarker = "/.worktrees/";
    const wtIdx = normRepo.indexOf(wtMarker);
    if (wtIdx > 0) {
      const parentCheckoutNorm = normRepo.slice(0, wtIdx);
      if (
        isSubpathOrEqual(normDir, parentCheckoutNorm) ||
        isSubpathOrEqual(parentCheckoutNorm, normDir)
      ) {
        throw new CleanRoomViolationError(
          "clean_room_cwd_inside_repo",
          `Clean-room temp directory '${resolved}' must be strictly outside parent repository checkout`,
        );
      }
    }
  }

  const entries = fs.readdirSync(resolved);
  if (entries.length !== 0) {
    throw new CleanRoomViolationError(
      "non_empty_clean_room_cwd",
      `Clean-room temp directory '${resolved}' must be completely empty (found ${entries.length} entries: ${entries.slice(0, 5).join(", ")})`,
    );
  }
}

export function buildCleanRoomSessionSpec(
  emptyTmpDir: string,
  options?: {
    repoRoot?: string;
    env?: Readonly<Record<string, string | undefined>>;
  },
): CleanRoomSessionSpec {
  assertEmptyOutsideRepoAndRuntimeDir(emptyTmpDir, { repoRoot: options?.repoRoot });
  if (options?.env) {
    assertSubscriptionOnlyEnv(options.env);
  }

  const resolvedCwd = fs.realpathSync(path.resolve(emptyTmpDir));
  const spec: CleanRoomSessionSpec = {
    cwd: resolvedCwd,
    tools: [],
    customTools: [],
    toolNames: [],
    mountedToolNames: [],
    restrictToolNames: true,
    allowRestrictedCustomTools: false,
    spawns: [],
    enableMCP: false,
    enableLsp: false,
    enableIrc: false,
    skills: [],
    rules: [],
    contextFiles: [],
    promptTemplates: [],
    slashCommands: [],
    additionalDirectories: [],
    noContextFiles: true,
    excludeAgentsMd: true,
    disableExtensionDiscovery: true,
    cacheWarming: false,
    bindProcessState: false,
    hasUI: false,
    interactivePrompts: false,
    autoApprove: false,
    disableModelFallback: true,
    disableServerSideFallback: true,
    subscriptionOnly: true,
    disabledProviders: [...DISABLED_MCP_PROVIDERS],
  };

  assertZeroToolSessionSpec(spec, { repoRoot: options?.repoRoot });
  return spec;
}

export function assertZeroToolSessionSpec(
  spec: CleanRoomSessionSpec,
  options?: { repoRoot?: string },
): void {
  assertEmptyOutsideRepoAndRuntimeDir(spec.cwd, { repoRoot: options?.repoRoot });

  if (
    spec.tools.length !== 0 ||
    spec.customTools.length !== 0 ||
    spec.toolNames.length !== 0 ||
    spec.mountedToolNames.length !== 0 ||
    spec.restrictToolNames !== true ||
    spec.allowRestrictedCustomTools !== false ||
    spec.spawns.length !== 0 ||
    spec.enableMCP !== false ||
    spec.enableLsp !== false ||
    spec.enableIrc !== false ||
    spec.skills.length !== 0 ||
    spec.rules.length !== 0 ||
    spec.contextFiles.length !== 0 ||
    spec.promptTemplates.length !== 0 ||
    spec.slashCommands.length !== 0 ||
    spec.additionalDirectories.length !== 0 ||
    spec.noContextFiles !== true ||
    spec.excludeAgentsMd !== true ||
    spec.disableExtensionDiscovery !== true ||
    spec.cacheWarming !== false ||
    spec.bindProcessState !== false ||
    spec.hasUI !== false ||
    spec.interactivePrompts !== false ||
    spec.autoApprove !== false ||
    spec.subscriptionOnly !== true
  ) {
    throw new CleanRoomViolationError(
      "invalid_zero_tool_session_spec",
      "CleanRoomSessionSpec violated mandatory zero-tool / zero-discovery invariants",
    );
  }

  const disabledSet = new Set(spec.disabledProviders);
  for (const requiredProvider of DISABLED_MCP_PROVIDERS) {
    if (!disabledSet.has(requiredProvider)) {
      throw new CleanRoomViolationError(
        "missing_disabled_provider",
        `CleanRoomSessionSpec missing required disabled capability provider '${requiredProvider}'`,
      );
    }
  }
}

export function buildOmpCreateAgentSessionOptions(
  spec: CleanRoomSessionSpec,
  options?: {
    systemPrompt?: string | string[];
    modelPattern?: string;
    deadline?: number;
  },
): CreateAgentSessionOptions {
  assertZeroToolSessionSpec(spec);

  const isolatedSettings = Settings.isolated({
    disabledProviders: [...spec.disabledProviders],
    "skills.enabled": false,
    "skills.enableSkillCommands": false,
    "mcp.enableProjectConfig": false,
    "lsp.enabled": false,
    "lsp.formatOnWrite": false,
    "lsp.diagnosticsOnWrite": false,
    "lsp.diagnosticsOnEdit": false,
  });

  const sessionOptions: CreateAgentSessionOptions = {
    cwd: spec.cwd,
    additionalDirectories: [],
    spawns: "",
    inheritedSessionAgents: [],
    customTools: [],
    extensions: [],
    topLevelExtensions: [],
    additionalExtensionPaths: [],
    disableExtensionDiscovery: true,
    skills: [],
    rules: [],
    contextFiles: [],
    noContextFiles: true,
    excludeAgentsMd: true,
    promptTemplates: [],
    slashCommands: [],
    enableMCP: false,
    enableLsp: false,
    lspReadOnly: true,
    enableIrc: false,
    skipPythonPreflight: true,
    toolNames: [],
    mountedToolNames: [],
    restrictToolNames: true,
    allowRestrictedCustomTools: false,
    requireYieldTool: false,
    bindProcessState: false,
    cacheWarming: false,
    hasUI: false,
    interactivePrompts: false,
    settingsApproval: false,
    tuiTranscript: false,
    autoTitle: false,
    autoApprove: false,
    disableModelFallback: true,
    disableServerSideFallback: true,
    agentRegistry: new AgentRegistry(),
    sessionManager: SessionManager.inMemory(spec.cwd),
    settings: isolatedSettings,
  };

  if (options?.systemPrompt !== undefined) {
    sessionOptions.systemPrompt = options.systemPrompt;
  }
  if (options?.modelPattern !== undefined && options.modelPattern.trim().length > 0) {
    sessionOptions.modelPattern = options.modelPattern.trim();
  }
  if (options?.deadline !== undefined) {
    sessionOptions.deadline = options.deadline;
  }

  return sessionOptions;
}

function createSimulatedSession(request: CleanRoomWorkerTurnRequest): CleanRoomAgentSessionLike {
  const listeners = new Set<(ev: AgentSessionEvent) => void>();
  let aborted = false;
  let lastMessage: ReturnType<CleanRoomAgentSessionLike["getLastAssistantMessage"]>;

  return {
    state: {
      tools: [],
    },
    getActiveToolNames: () => [],
    getEnabledToolNames: () => [],
    subscribe: (listener) => {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    disableStopTimeTodoReminders: () => {},
    prepareForHeadlessAdvisorDrain: () => {},
    prompt: async () => {
      if (request.simulateToolStart) {
        const fakeEvent = {
          type: "tool_execution_start",
          toolCallId: request.simulateToolStart.toolCallId ?? "sim-tool-call-1",
          toolName: request.simulateToolStart.toolName,
          args: {},
        } as unknown as AgentSessionEvent;
        for (const listener of [...listeners]) {
          listener(fakeEvent);
        }
      }
      if (aborted) {
        lastMessage = {
          role: "assistant",
          content: [],
          provider: "simulated-subscription",
          model: request.modelPattern ?? "simulated-clean-room-model",
          stopReason: "aborted",
          errorMessage: "clean_room_tool_execution_forbidden",
          usage: {
            input: 0,
            output: 0,
            cacheRead: 0,
            cacheWrite: 0,
            totalTokens: 0,
          },
        };
        return true;
      }
      lastMessage = {
        role: "assistant",
        content: [
          {
            type: "text",
            text: request.mockResponseText ?? "{}",
          },
        ],
        provider: "simulated-subscription",
        model: request.modelPattern ?? "simulated-clean-room-model",
        stopReason: "stop",
        usage: {
          input: 120,
          output: 48,
          cacheRead: 0,
          cacheWrite: 0,
          totalTokens: 168,
        },
      };
      return true;
    },
    getLastAssistantMessage: () => lastMessage,
    abort: async () => {
      aborted = true;
    },
    dispose: async () => {
      listeners.clear();
    },
  };
}

export async function executeInProcessCleanRoomOmpTurn(
  request: CleanRoomWorkerTurnRequest,
  options?: ExecuteCleanRoomTurnOptions,
): Promise<CleanRoomWorkerTurnResult> {
  const effectiveEnv = options?.env ?? process.env;
  assertSubscriptionOnlyEnv(effectiveEnv);

  const spec = buildCleanRoomSessionSpec(request.emptyTmpDir, {
    repoRoot: request.repoRoot,
    env: effectiveEnv,
  });

  const ompOptions = buildOmpCreateAgentSessionOptions(spec, {
    systemPrompt: [request.systemPrompt],
    modelPattern: request.modelPattern,
    deadline:
      request.deadlineMs !== undefined ? Date.now() + request.deadlineMs : undefined,
  });

  const simAllowed =
    options?.allowTestSimulation === true ||
    effectiveEnv.HUNT_COACH_ALLOW_TEST_SIM === "1";

  if ((request.simulateToolStart || request.mockResponseText !== undefined) && !simAllowed) {
    throw new CleanRoomViolationError(
      "test_simulation_forbidden",
      "Test simulation fields are disabled unless allowTestSimulation is explicitly enabled",
    );
  }

  const created = options?.sessionFactory
    ? await options.sessionFactory(ompOptions, spec)
    : simAllowed && (request.simulateToolStart || request.mockResponseText !== undefined)
      ? { session: createSimulatedSession(request) }
      : await createAgentSession(ompOptions);

  const session = created.session;
  let toolViolation: CleanRoomToolViolationError | null = null;
  let abortPromise: Promise<void> | null = null;

  const unsubscribe = session.subscribe((event: AgentSessionEvent) => {
    if (event.type === "tool_execution_start") {
      const evRecord = event as unknown as {
        toolName?: unknown;
        toolCallId?: unknown;
      };
      const toolName =
        typeof evRecord.toolName === "string" && evRecord.toolName.length > 0
          ? evRecord.toolName
          : "unknown_tool";
      const toolCallId =
        typeof evRecord.toolCallId === "string" ? evRecord.toolCallId : undefined;

      if (toolViolation === null) {
        toolViolation = new CleanRoomToolViolationError(toolName, toolCallId);
      }
      options?.onToolStart?.(toolName, toolCallId);
      if (abortPromise === null) {
        abortPromise = session
          .abort({ reason: "clean_room_tool_execution_forbidden" })
          .catch(() => {});
      }
    }
  });

  try {
    const activeTools = session.getActiveToolNames();
    const enabledTools = session.getEnabledToolNames();
    const stateTools = session.state.tools;
    if (
      activeTools.length !== 0 ||
      enabledTools.length !== 0 ||
      stateTools.length !== 0
    ) {
      throw new CleanRoomViolationError(
        "non_zero_active_tools",
        `Clean-room session must expose 0 tools before prompt (active=${activeTools.length}, enabled=${enabledTools.length}, state=${stateTools.length})`,
      );
    }

    session.disableStopTimeTodoReminders();
    session.prepareForHeadlessAdvisorDrain();

    await session.prompt(request.prompt, {
      expandPromptTemplates: false,
      throwOnDrop: true,
    });

    if (abortPromise !== null) {
      await abortPromise;
    }
    if (toolViolation !== null) {
      throw toolViolation;
    }

    const assistant = session.getLastAssistantMessage();
    if (!assistant) {
      throw new CleanRoomViolationError(
        "missing_assistant_response",
        `Clean-room ${request.role} session produced no assistant response`,
      );
    }

    // Even if a provider returned a toolCall content block without firing execution, hard-fail.
    for (const block of assistant.content) {
      if (block.type === "toolCall") {
        const tc = block as { type: "toolCall"; name: string; id?: string };
        throw new CleanRoomToolViolationError(tc.name || "toolCall_block", tc.id);
      }
    }

    if (assistant.stopReason === "error" || assistant.stopReason === "aborted") {
      throw new CleanRoomViolationError(
        `assistant_${assistant.stopReason}`,
        assistant.errorMessage ||
          `Clean-room ${request.role} turn ended with stopReason='${assistant.stopReason}'`,
      );
    }

    const textParts: string[] = [];
    for (const block of assistant.content) {
      if (block.type === "text" && "text" in block && typeof block.text === "string") {
        textParts.push(block.text);
      }
    }
    const combinedText = textParts.join("\n").trim();

    // Re-assert empty temp directory invariant after turn completion.
    assertEmptyOutsideRepoAndRuntimeDir(spec.cwd, { repoRoot: request.repoRoot });

    const usage = assistant.usage;
    const inputTokens = usage?.input ?? 0;
    const outputTokens = usage?.output ?? 0;
    const cacheReadTokens = usage?.cacheRead ?? 0;
    const cacheWriteTokens = usage?.cacheWrite ?? 0;
    const totalTokens =
      usage?.totalTokens ??
      inputTokens + outputTokens + cacheReadTokens + cacheWriteTokens;

    return {
      role: request.role,
      text: combinedText,
      model: assistant.model ?? "unknown",
      provider: assistant.provider ?? "unknown",
      usage: {
        input_tokens: inputTokens,
        output_tokens: outputTokens,
        cache_read_tokens: cacheReadTokens,
        cache_write_tokens: cacheWriteTokens,
        total_tokens: totalTokens,
      },
      activeToolCount: 0,
    };
  } finally {
    unsubscribe();
    if (abortPromise !== null) {
      await abortPromise;
    }
    await session.dispose().catch(() => {});
  }
}

function writeWireFrame(frame: CleanRoomWorkerWireFrame): void {
  process.stdout.write(`${JSON.stringify(frame)}\n`);
}

async function runWorkerMain(): Promise<void> {
  try {
    assertSubscriptionOnlyEnv(process.env);
    const rawStdin = await Bun.stdin.text();
    if (rawStdin.trim().length === 0) {
      throw new CleanRoomViolationError(
        "empty_worker_stdin",
        "Clean-room worker expected JSON request on stdin",
      );
    }

    const parsed = JSON.parse(rawStdin) as CleanRoomWorkerTurnRequest;
    const processCwdNorm = normalizePathForComparison(process.cwd());
    const reqCwdNorm = normalizePathForComparison(parsed.emptyTmpDir);
    if (processCwdNorm !== reqCwdNorm) {
      throw new CleanRoomViolationError(
        "worker_cwd_mismatch",
        `Worker process.cwd() '${process.cwd()}' does not match requested emptyTmpDir '${parsed.emptyTmpDir}'`,
      );
    }

    assertEmptyOutsideRepoAndRuntimeDir(parsed.emptyTmpDir, {
      repoRoot: parsed.repoRoot,
    });

    writeWireFrame({
      type: "ready",
      role: parsed.role,
      cwd: parsed.emptyTmpDir,
      activeToolCount: 0,
    });

    const result = await executeInProcessCleanRoomOmpTurn(parsed, {
      env: process.env,
      allowTestSimulation: process.env.HUNT_COACH_ALLOW_TEST_SIM === "1",
      onToolStart: (toolName, toolCallId) => {
        writeWireFrame({
          type: "tool_execution_start",
          role: parsed.role,
          toolName,
          toolCallId,
        });
      },
    });

    writeWireFrame({
      type: "result",
      result,
    });
    process.exit(0);
  } catch (err) {
    if (err instanceof CleanRoomToolViolationError) {
      writeWireFrame({
        type: "error",
        code: err.code,
        message: err.message,
      });
      process.exit(CLEAN_ROOM_TOOL_ABORT_EXIT_CODE);
    }
    const code =
      err instanceof CleanRoomViolationError ? err.code : "clean_room_worker_error";
    const message = err instanceof Error ? err.message : String(err);
    writeWireFrame({
      type: "error",
      code,
      message,
    });
    process.exit(1);
  }
}

if (import.meta.main) {
  void runWorkerMain();
}
