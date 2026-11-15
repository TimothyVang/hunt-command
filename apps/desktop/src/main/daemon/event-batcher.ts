/**
 * Adapted from omp-desktop/app/src/main/features/chat/event-batcher.ts
 * Copyright (c) omp-desktop contributors (MIT License — see root THIRD-PARTY-NOTICES.md).
 * Modified for Hunt Command v2: 33ms (~30Hz) IPC batcher coalescing adjacent streaming
 * token/tool updates from `hunt-daemon` while preserving wave, gate, and span milestones.
 */
import type { RpcEventNotification } from "@hunt-command/shared";

export type HuntStreamEvent = RpcEventNotification["params"];

function supersedeKey(ev: HuntStreamEvent): string | undefined {
  if (ev.type === "gen_ai.chat.delta" && typeof ev.payload.step_id === "string") {
    return `chat:${ev.payload.step_id}`;
  }
  if (ev.type === "gen_ai.execute_tool.progress" && typeof ev.payload.tool_call_id === "string") {
    return `tool:${ev.payload.tool_call_id}`;
  }
  return undefined;
}

export class EventBatcher {
  readonly #queues = new Map<string, HuntStreamEvent[]>();
  #timer: ReturnType<typeof setTimeout> | undefined;

  constructor(
    private readonly flushTo: (huntId: string, events: HuntStreamEvent[]) => void,
    private readonly intervalMs = 33,
  ) {}

  push(huntId: string, ev: HuntStreamEvent): void {
    let queue = this.#queues.get(huntId);
    if (!queue) {
      queue = [];
      this.#queues.set(huntId, queue);
    }
    const key = supersedeKey(ev);
    const last = queue.at(-1);
    if (key && last && supersedeKey(last) === key) {
      queue[queue.length - 1] = ev;
    } else {
      queue.push(ev);
    }
    this.#timer ??= setTimeout(() => this.flush(), this.intervalMs);
  }

  flush(): void {
    clearTimeout(this.#timer);
    this.#timer = undefined;
    const entries = [...this.#queues.entries()];
    this.#queues.clear();
    for (const [huntId, events] of entries) {
      if (events.length > 0) {
        this.flushTo(huntId, events);
      }
    }
  }

  drop(huntId: string): void {
    this.#queues.delete(huntId);
  }
}
