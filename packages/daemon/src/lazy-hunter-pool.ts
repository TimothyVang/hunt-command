import type { ProfileId } from "@hunt-command/shared";
import { stripPaidApiEnvVars, validateRoleModelPinTable } from "./hunter-policy.ts";
import type { OmpHunterPool, OmpHunterPoolOptions } from "./omp-pool.ts";
import type { ModelRunnerPort, ModelTurnRequest, RoleModelPin, StepTurnResult } from "./ports.ts";

/**
 * The daemon's default model runner. The agent stack is loaded on the first model call, so a command
 * that never runs a turn, and a daemon that is only serving the workbench, do not pay its memory or
 * startup cost. Paid API keys are still stripped and the pin table still validated at construction.
 */
export class LazyHunterPool implements ModelRunnerPort {
  readonly #options: OmpHunterPoolOptions | undefined;
  readonly #pins: Readonly<Record<ProfileId, RoleModelPin>>;
  #pool: Promise<OmpHunterPool> | null = null;

  constructor(options?: OmpHunterPoolOptions) {
    this.#options = options;
    if (options?.subscriptionOnly ?? true) {
      stripPaidApiEnvVars();
    }
    this.#pins = validateRoleModelPinTable(options?.roleModelPins);
  }

  /** True once the agent stack has been loaded. */
  get loaded(): boolean {
    return this.#pool !== null;
  }

  #load(): Promise<OmpHunterPool> {
    this.#pool ??= import("./omp-pool.ts").then((mod) => new mod.OmpHunterPool(this.#options));
    return this.#pool;
  }

  getPinnedModelForRole(profile: ProfileId): RoleModelPin {
    return this.#pins[profile];
  }

  async preflightWave(providers: readonly string[], waveSessionKey: string, signal?: AbortSignal): Promise<void> {
    return (await this.#load()).preflightWave(providers, waveSessionKey, signal);
  }

  async runTurn(request: ModelTurnRequest): Promise<StepTurnResult> {
    return (await this.#load()).runTurn(request);
  }

  async close(): Promise<void> {
    if (this.#pool !== null) (await this.#pool).close();
  }
}
