/**
 * Adapted from omp-desktop/app/src/main/features/browser/cdp-hub.ts and can1357/oh-my-pi (MIT)
 * Copyright (c) omp-desktop contributors & Can Boluk (MIT License — see root THIRD-PARTY-NOTICES.md).
 * Modified for Hunt Command v2 (#178 G1.3):
 * - Enforces Watch Browser CDP command filter (`deniedSessionCommand` blocking `Fetch.*`, mutating `Network.*`,
 *   `ServiceWorker.*`, `Storage.*`).
 * - Restricts `Target.createTarget` to `host.isOpenableUrl(url)` (`isOpenableWatchUrl`, pinned `127.0.0.1` only).
 */
import { CDP_ERROR_METHOD_NOT_FOUND, CDP_ERROR_SERVER, deniedSessionCommand } from "./cdp-filter.ts";

type Params = Record<string, unknown>;

export interface HubPage {
  readonly id: number;
  url(): string;
  title(): string;
  attach(): void;
  detach(): void;
  send(method: string, params: Params | undefined, sessionId?: string): Promise<unknown>;
}

export interface HubHost {
  pages(): readonly HubPage[];
  createPage(url: string, options: { background: boolean }): Promise<HubPage>;
  closePage(id: number): Promise<void>;
  activatePage(id: number): void;
  isOpenableUrl(url: string): boolean;
  version(): { product: string; userAgent: string };
  onActivity?(): void;
  onConnect?(): void;
}

export interface HubSocket {
  send(text: string): void;
  close(): void;
}

interface TargetInfo {
  targetId: string;
  type: "tab" | "page" | "browser";
  title: string;
  url: string;
  attached: boolean;
  canAccessOpener: boolean;
  browserContextId?: string;
}

interface CdpCommand {
  id: number;
  method: string;
  params?: Params;
  sessionId?: string;
}

type RuntimeState = "default" | "enabled" | "disabled";

interface SessionRef {
  kind: "tab" | "page";
  pageId: number;
  parent: string | undefined;
  runtime: RuntimeState;
  readonly contexts: Set<number>;
  autoAttach: boolean;
}

class Conn {
  discover = false;
  autoAttach = false;
  readonly sessions = new Map<string, SessionRef>();
  readonly childParents = new Map<string, string>();

  constructor(
    readonly id: number,
    readonly socket: HubSocket,
  ) {}

  sessionsFor(pageId: number, kind?: "tab" | "page"): string[] {
    const out: string[] = [];
    for (const [sessionId, ref] of this.sessions) {
      if (ref.pageId === pageId && (!kind || ref.kind === kind)) out.push(sessionId);
    }
    return out;
  }

  childParentFor(pageId: number): string | undefined {
    for (const [sessionId, ref] of this.sessions) {
      if (ref.pageId === pageId && ref.kind === "page" && ref.autoAttach) return sessionId;
    }
    return undefined;
  }
}

interface PageState {
  readonly page: HubPage;
  announced: boolean;
  attached: boolean;
  rootRuntime: Promise<void> | "on" | null;
  generation: number;
  readonly contexts: Map<number, Params>;
  readonly children: Map<string, { parent: string | undefined; event: Params }>;
  lastCommandAt: number;
}

const tabTargetId = (id: number) => `TAB${id}`;
const pageTargetId = (id: number) => `PAGE${id}`;
const BROWSER_TARGET_ID = "hunt-command-watch-browser";

function parseTargetId(targetId: unknown): { id: number; kind: "tab" | "page" } | null {
  if (typeof targetId !== "string") return null;
  const match = /^(TAB|PAGE)(\d+)$/.exec(targetId);
  if (!match) return null;
  return { id: Number(match[2]), kind: match[1] === "TAB" ? "tab" : "page" };
}

const PASSIVE_METHODS: Record<string, true> = {
  "Target.setAutoAttach": true,
  "Target.getTargetInfo": true,
  "Target.detachFromTarget": true,
  "Runtime.runIfWaitingForDebugger": true,
  "Runtime.enable": true,
  "Runtime.disable": true,
  "Page.enable": true,
  "Page.getFrameTree": true,
  "Page.setLifecycleEventsEnabled": true,
  "Network.enable": true,
  "Log.enable": true,
  "Performance.enable": true,
  "Security.enable": true,
};

export class CdpHub {
  readonly #host: HubHost;
  readonly #conns = new Map<number, Conn>();
  readonly #pages = new Map<number, PageState>();
  readonly #childPage = new Map<string, number>();
  #connSeq = 0;
  #sessionSeq = 0;

  constructor(host: HubHost) {
    this.#host = host;
    for (const page of host.pages()) this.#track(page);
  }

  get clientCount(): number {
    return this.#conns.size;
  }

  busyPageIds(windowMs: number, now = Date.now()): number[] {
    return [...this.#pages.values()]
      .filter((p) => now - p.lastCommandAt < windowMs)
      .map((p) => p.page.id);
  }

  versionInfo(wsUrl: string): Record<string, string> {
    const { product, userAgent } = this.#host.version();
    return {
      Browser: product,
      "Protocol-Version": "1.3",
      "User-Agent": userAgent,
      "V8-Version": "",
      "WebKit-Version": "",
      webSocketDebuggerUrl: wsUrl,
    };
  }

  listTargets(): Record<string, string>[] {
    return [...this.#pages.values()].map(({ page }) => ({
      id: pageTargetId(page.id),
      type: "page",
      title: page.title(),
      url: page.url() || "about:blank",
    }));
  }

  connect(socket: HubSocket): number {
    this.#host.onConnect?.();
    const id = ++this.#connSeq;
    this.#conns.set(id, new Conn(id, socket));
    this.#host.onActivity?.();
    return id;
  }

  disconnect(connId: number): void {
    const conn = this.#conns.get(connId);
    if (!conn) return;
    this.#conns.delete(connId);
    const touched = new Set<number>();
    for (const ref of conn.sessions.values()) touched.add(ref.pageId);
    conn.sessions.clear();
    conn.childParents.clear();
    for (const pageId of touched) this.#detachIfUnheld(pageId);
    this.#host.onActivity?.();
  }

  closeAll(): void {
    for (const conn of [...this.#conns.values()]) {
      this.disconnect(conn.id);
      conn.socket.close();
    }
  }

  message(connId: number, raw: string): void {
    const conn = this.#conns.get(connId);
    if (!conn) return;
    let msg: CdpCommand;
    try {
      msg = JSON.parse(raw) as CdpCommand;
    } catch {
      return;
    }
    if (
      typeof msg !== "object" ||
      msg === null ||
      typeof msg.id !== "number" ||
      typeof msg.method !== "string"
    ) {
      return;
    }
    if (
      msg.params !== undefined &&
      (typeof msg.params !== "object" || msg.params === null || Array.isArray(msg.params))
    ) {
      this.#replyError(conn, msg, "Invalid parameters");
      return;
    }
    if (msg.sessionId !== undefined && typeof msg.sessionId !== "string") {
      this.#replyError(conn, msg, "Invalid session id");
      return;
    }
    void this.#handle(conn, msg).catch((error) => {
      this.#replyError(conn, msg, error instanceof Error ? error.message : String(error));
    });
  }

  pageAdded(page: HubPage): void {
    if (this.#pages.has(page.id)) return;
    const state = this.#track(page);
    this.#announce(state);
  }

  pageUpdated(pageId: number): void {
    const state = this.#pages.get(pageId);
    if (!state?.announced) return;
    for (const conn of this.#conns.values()) {
      if (!conn.discover) continue;
      this.#emit(conn, "Target.targetInfoChanged", { targetInfo: this.#tabInfo(state) });
      this.#emit(conn, "Target.targetInfoChanged", { targetInfo: this.#pageInfo(state) });
    }
  }

  pageRemoved(pageId: number): void {
    const state = this.#pages.get(pageId);
    if (!state) return;
    this.#forgetChildren(state);
    this.#retract(state);
    this.#pages.delete(pageId);
  }

  pageDetached(pageId: number): void {
    const state = this.#pages.get(pageId);
    if (!state?.attached) return;
    state.attached = false;
    this.#resetRuntime(state);
    this.#forgetChildren(state);
    this.#retract(state);
    setTimeout(() => {
      if (this.#pages.get(pageId) === state && !state.announced) this.#announce(state);
    }, 0);
  }

  pageEvent(pageId: number, method: string, params: Params, sessionId?: string): void {
    const state = this.#pages.get(pageId);
    if (!state) return;
    if (sessionId) {
      this.#onChildEvent(state, sessionId, method, params);
      return;
    }
    if (method === "Target.attachedToTarget" || method === "Target.detachedFromTarget") {
      this.#onRootChildAttach(state, method, params);
      return;
    }
    if (method.startsWith("Runtime.")) {
      this.#onRuntimeEvent(state, method, params);
      return;
    }
    for (const conn of this.#conns.values()) {
      for (const session of conn.sessionsFor(pageId, "page")) {
        this.#emit(conn, method, params, session);
      }
    }
  }

  async #handle(conn: Conn, msg: CdpCommand): Promise<void> {
    const { sessionId } = msg;
    if (!sessionId) {
      await this.#handleBrowserCommand(conn, msg);
      return;
    }
    const ref = conn.sessions.get(sessionId);
    if (ref?.kind === "tab") {
      this.#handleTabCommand(conn, msg, ref);
      return;
    }
    if (ref?.kind === "page") {
      await this.#handlePageCommand(conn, msg, sessionId, ref);
      return;
    }
    const childPage = conn.childParents.has(sessionId)
      ? this.#childPage.get(sessionId)
      : undefined;
    const state = childPage === undefined ? undefined : this.#pages.get(childPage);
    if (!state) {
      this.#replyError(conn, msg, `Session with given id not found: ${sessionId}`);
      return;
    }
    const denied = deniedSessionCommand(msg.method, msg.params);
    if (denied) {
      this.#replyError(conn, msg, denied);
      return;
    }
    const scopedTarget =
      msg.method === "Target.createTarget" ||
      msg.method === "Target.closeTarget" ||
      msg.method === "Target.activateTarget" ||
      (msg.method === "Target.getTargetInfo" && msg.params?.targetId !== undefined);
    if (scopedTarget) {
      await this.#handleBrowserCommand(conn, msg);
      return;
    }
    this.#touch(state, msg.method);
    const result = await state.page.send(msg.method, msg.params, sessionId);
    if (msg.method === "Target.setAutoAttach" && msg.params?.autoAttach === true) {
      this.#announceChildren(conn, state, sessionId, sessionId);
    }
    this.#reply(conn, msg, (result as Params | undefined) ?? {});
  }

  async #handlePageCommand(
    conn: Conn,
    msg: CdpCommand,
    sessionId: string,
    ref: SessionRef,
  ): Promise<void> {
    const state = this.#pages.get(ref.pageId);
    if (!state) {
      this.#replyError(conn, msg, `Target closed: page ${ref.pageId}`);
      return;
    }
    const denied = deniedSessionCommand(msg.method, msg.params);
    if (denied) {
      this.#replyError(conn, msg, denied);
      return;
    }
    this.#touch(state, msg.method);
    switch (msg.method) {
      case "Runtime.enable":
        await this.#enableRuntime(conn, msg, sessionId, ref, state);
        return;
      case "Runtime.disable":
        ref.runtime = "disabled";
        ref.contexts.clear();
        this.#reply(conn, msg, {});
        return;
      case "Target.getTargetInfo": {
        const target = msg.params?.targetId;
        if (target === undefined || target === pageTargetId(state.page.id)) {
          this.#reply(conn, msg, { targetInfo: this.#pageInfo(state) });
          return;
        }
        await this.#handleBrowserCommand(conn, msg);
        return;
      }
      case "Target.createTarget":
      case "Target.closeTarget":
      case "Target.activateTarget":
        await this.#handleBrowserCommand(conn, msg);
        return;
      case "Target.detachFromTarget": {
        const child = msg.params?.sessionId;
        if (typeof child !== "string" || !conn.childParents.has(child)) {
          this.#replyError(conn, msg, "No session with given id");
          return;
        }
        break;
      }
      case "Target.setAutoAttach": {
        const previous = ref.autoAttach;
        ref.autoAttach = msg.params?.autoAttach === true;
        try {
          const result = await state.page.send(msg.method, msg.params);
          if (ref.autoAttach) this.#announceChildren(conn, state, undefined, sessionId);
          this.#reply(conn, msg, (result as Params | undefined) ?? {});
        } catch (error) {
          ref.autoAttach = previous;
          throw error;
        }
        return;
      }
    }
    const result = await state.page.send(msg.method, msg.params);
    this.#reply(conn, msg, (result as Params | undefined) ?? {});
  }

  #handleTabCommand(conn: Conn, msg: CdpCommand, ref: SessionRef): void {
    const state = this.#pages.get(ref.pageId);
    switch (msg.method) {
      case "Target.setAutoAttach": {
        if (!state) {
          this.#replyError(conn, msg, `Target closed: page ${ref.pageId}`);
          return;
        }
        const announced = [...conn.sessions.values()].some((other) => other.parent === msg.sessionId);
        if (msg.params?.autoAttach === true && !announced) {
          const pageSession = this.#mintSession(conn, "page", ref.pageId, msg.sessionId);
          this.#emit(
            conn,
            "Target.attachedToTarget",
            { sessionId: pageSession, targetInfo: this.#pageInfo(state), waitingForDebugger: false },
            msg.sessionId,
          );
        }
        this.#reply(conn, msg, {});
        return;
      }
      case "Runtime.runIfWaitingForDebugger":
        this.#reply(conn, msg, {});
        return;
      case "Target.detachFromTarget": {
        const child = msg.params?.sessionId;
        if (typeof child === "string") this.#releaseSession(conn, child, msg.sessionId);
        this.#reply(conn, msg, {});
        return;
      }
      case "Target.getTargetInfo":
        if (state) {
          this.#reply(conn, msg, { targetInfo: this.#tabInfo(state) });
          return;
        }
        this.#replyError(conn, msg, `Target closed: page ${ref.pageId}`);
        return;
      default:
        this.#replyError(
          conn,
          msg,
          `'${msg.method}' is not supported on a tab target`,
          CDP_ERROR_METHOD_NOT_FOUND,
        );
    }
  }

  async #handleBrowserCommand(conn: Conn, msg: CdpCommand): Promise<void> {
    const params = msg.params ?? {};
    switch (msg.method) {
      case "Browser.getVersion": {
        const { product, userAgent } = this.#host.version();
        this.#reply(conn, msg, {
          protocolVersion: "1.3",
          product,
          revision: "",
          userAgent,
          jsVersion: "",
        });
        return;
      }
      case "Browser.close":
      case "Browser.setDownloadBehavior":
        this.#reply(conn, msg, {});
        return;
      case "Target.getBrowserContexts":
        this.#reply(conn, msg, { browserContextIds: [] });
        return;
      case "Target.getTargets":
        this.#reply(conn, msg, {
          targetInfos: [...this.#pages.values()].map((state) => this.#pageInfo(state)),
        });
        return;
      case "Target.setDiscoverTargets": {
        const discover = params.discover === true;
        const wasDiscovering = conn.discover;
        conn.discover = discover;
        if (discover && !wasDiscovering) {
          for (const state of this.#pages.values()) {
            state.announced = true;
            this.#emit(conn, "Target.targetCreated", { targetInfo: this.#tabInfo(state) });
            this.#emit(conn, "Target.targetCreated", { targetInfo: this.#pageInfo(state) });
          }
        }
        this.#reply(conn, msg, {});
        return;
      }
      case "Target.setAutoAttach": {
        conn.autoAttach = params.autoAttach === true;
        if (conn.autoAttach) {
          for (const state of this.#pages.values()) {
            this.#ensureAttached(state);
            this.#emitTabAttached(conn, state);
          }
        }
        this.#reply(conn, msg, {});
        return;
      }
      case "Target.attachToTarget": {
        const parsed = parseTargetId(params.targetId);
        const state = parsed ? this.#pages.get(parsed.id) : undefined;
        if (!parsed || !state) {
          this.#replyError(conn, msg, "No target with given id found");
          return;
        }
        this.#ensureAttached(state);
        const sessionId = this.#mintSession(conn, parsed.kind, state.page.id, undefined);
        const targetInfo = parsed.kind === "tab" ? this.#tabInfo(state) : this.#pageInfo(state);
        this.#emit(conn, "Target.attachedToTarget", {
          sessionId,
          targetInfo,
          waitingForDebugger: false,
        });
        this.#reply(conn, msg, { sessionId });
        return;
      }
      case "Target.detachFromTarget": {
        const sessionId = params.sessionId;
        if (typeof sessionId !== "string" || !conn.sessions.has(sessionId)) {
          this.#replyError(conn, msg, "No session with given id");
          return;
        }
        this.#releaseSession(conn, sessionId, undefined);
        this.#reply(conn, msg, {});
        return;
      }
      case "Target.createTarget": {
        if (params.browserContextId !== undefined) {
          this.#replyError(conn, msg, "Browser contexts are denied in the Watch Browser");
          return;
        }
        const url =
          typeof params.url === "string" && params.url.length > 0 ? params.url : "about:blank";
        if (!this.#host.isOpenableUrl(url)) {
          this.#replyError(
            conn,
            msg,
            `Target URL '${url}' is outside the pinned 127.0.0.1 Watch Browser scope`,
          );
          return;
        }
        const page = await this.#host.createPage(url, { background: params.background === true });
        this.#reply(conn, msg, { targetId: pageTargetId(page.id) });
        return;
      }
      case "Target.closeTarget": {
        const parsed = parseTargetId(params.targetId);
        if (!parsed || !this.#pages.has(parsed.id)) {
          this.#replyError(conn, msg, "No target with given id found");
          return;
        }
        await this.#host.closePage(parsed.id);
        this.#reply(conn, msg, { success: true });
        return;
      }
      case "Target.activateTarget": {
        const parsed = parseTargetId(params.targetId);
        if (!parsed || !this.#pages.has(parsed.id)) {
          this.#replyError(conn, msg, "No target with given id found");
          return;
        }
        this.#host.activatePage(parsed.id);
        this.#reply(conn, msg, {});
        return;
      }
      case "Target.getTargetInfo": {
        const parsed = parseTargetId(params.targetId);
        const state = parsed ? this.#pages.get(parsed.id) : undefined;
        if (parsed && state) {
          this.#reply(conn, msg, {
            targetInfo: parsed.kind === "tab" ? this.#tabInfo(state) : this.#pageInfo(state),
          });
          return;
        }
        if (params.targetId !== undefined && params.targetId !== BROWSER_TARGET_ID) {
          this.#replyError(conn, msg, "No target with given id found");
          return;
        }
        this.#reply(conn, msg, {
          targetInfo: {
            targetId: BROWSER_TARGET_ID,
            type: "browser",
            title: "",
            url: "",
            attached: true,
            canAccessOpener: false,
          } satisfies TargetInfo,
        });
        return;
      }
      default:
        this.#replyError(conn, msg, `'${msg.method}' wasn't found`, CDP_ERROR_METHOD_NOT_FOUND);
    }
  }

  async #enableRuntime(
    conn: Conn,
    msg: CdpCommand,
    sessionId: string,
    ref: SessionRef,
    state: PageState,
  ): Promise<void> {
    const previous = ref.runtime;
    ref.runtime = "enabled";
    try {
      await this.#ensureRootRuntime(state);
    } catch (error) {
      ref.runtime = previous;
      throw error;
    }
    if (conn.sessions.get(sessionId) === ref && ref.runtime === "enabled") {
      for (const [contextId, params] of state.contexts) {
        if (ref.contexts.has(contextId)) continue;
        ref.contexts.add(contextId);
        this.#emit(conn, "Runtime.executionContextCreated", params, sessionId);
      }
    }
    this.#reply(conn, msg, {});
  }

  async #ensureRootRuntime(state: PageState): Promise<void> {
    if (state.rootRuntime === "on") return;
    if (state.rootRuntime) return await state.rootRuntime;
    const generation = state.generation;
    const enabling = state.page.send("Runtime.enable", undefined).then(() => {
      if (state.generation === generation) state.rootRuntime = "on";
    });
    state.rootRuntime = enabling;
    try {
      await enabling;
    } catch (error) {
      if (state.rootRuntime === enabling) state.rootRuntime = null;
      throw error;
    }
  }

  #onRuntimeEvent(state: PageState, method: string, params: Params): void {
    const context =
      method === "Runtime.executionContextCreated"
        ? (params.context as { id?: unknown } | undefined)
        : undefined;
    const createdId = typeof context?.id === "number" ? context.id : undefined;
    const destroyedId =
      method === "Runtime.executionContextDestroyed" &&
      typeof params.executionContextId === "number"
        ? params.executionContextId
        : undefined;
    if (createdId !== undefined) state.contexts.set(createdId, params);
    if (destroyedId !== undefined) state.contexts.delete(destroyedId);
    const cleared = method === "Runtime.executionContextsCleared";
    if (cleared) state.contexts.clear();
    for (const conn of this.#conns.values()) {
      for (const [session, ref] of conn.sessions) {
        if (ref.kind !== "page" || ref.pageId !== state.page.id) continue;
        if (destroyedId !== undefined) ref.contexts.delete(destroyedId);
        if (cleared) ref.contexts.clear();
        if (ref.runtime === "disabled") continue;
        if (createdId !== undefined) {
          if (ref.contexts.has(createdId)) continue;
          ref.contexts.add(createdId);
        }
        this.#emit(conn, method, params, session);
      }
    }
  }

  #onRootChildAttach(state: PageState, method: string, params: Params): void {
    const child = params.sessionId;
    if (typeof child !== "string") return;
    if (method === "Target.attachedToTarget") {
      state.children.set(child, { parent: undefined, event: params });
      this.#childPage.set(child, state.page.id);
    } else {
      state.children.delete(child);
      this.#childPage.delete(child);
    }
    for (const conn of this.#conns.values()) {
      let parent: string | undefined;
      if (method === "Target.attachedToTarget") {
        parent = conn.childParentFor(state.page.id);
        if (parent) conn.childParents.set(child, parent);
      } else {
        parent = conn.childParents.get(child);
        conn.childParents.delete(child);
      }
      if (parent) this.#emit(conn, method, params, parent);
    }
  }

  #onChildEvent(state: PageState, source: string, method: string, params: Params): void {
    const nested = typeof params.sessionId === "string" ? params.sessionId : undefined;
    if (nested && method === "Target.attachedToTarget") {
      state.children.set(nested, { parent: source, event: params });
      this.#childPage.set(nested, state.page.id);
    } else if (nested && method === "Target.detachedFromTarget") {
      state.children.delete(nested);
      this.#childPage.delete(nested);
    }
    for (const conn of this.#conns.values()) {
      if (!conn.childParents.has(source)) continue;
      this.#emit(conn, method, params, source);
      if (nested && method === "Target.attachedToTarget") conn.childParents.set(nested, source);
      else if (nested && method === "Target.detachedFromTarget") conn.childParents.delete(nested);
    }
  }

  #announceChildren(
    conn: Conn,
    state: PageState,
    parent: string | undefined,
    announceOn: string,
  ): void {
    for (const [child, known] of state.children) {
      if (known.parent !== parent || conn.childParents.has(child)) continue;
      conn.childParents.set(child, announceOn);
      this.#emit(conn, "Target.attachedToTarget", known.event, announceOn);
    }
  }

  #forgetChildren(state: PageState): void {
    for (const child of [...state.children.keys()].reverse()) {
      this.#childPage.delete(child);
      for (const conn of this.#conns.values()) {
        const parent = conn.childParents.get(child);
        if (parent === undefined) continue;
        conn.childParents.delete(child);
        this.#emit(conn, "Target.detachedFromTarget", { sessionId: child }, parent);
      }
    }
    state.children.clear();
  }

  #track(page: HubPage): PageState {
    const state: PageState = {
      page,
      announced: false,
      attached: false,
      rootRuntime: null,
      generation: 0,
      contexts: new Map(),
      children: new Map(),
      lastCommandAt: 0,
    };
    this.#pages.set(page.id, state);
    return state;
  }

  #announce(state: PageState): void {
    state.announced = true;
    for (const conn of this.#conns.values()) {
      if (conn.discover) {
        this.#emit(conn, "Target.targetCreated", { targetInfo: this.#tabInfo(state) });
        this.#emit(conn, "Target.targetCreated", { targetInfo: this.#pageInfo(state) });
      }
      if (conn.autoAttach) {
        this.#ensureAttached(state);
        this.#emitTabAttached(conn, state);
      }
    }
  }

  #retract(state: PageState): void {
    const tabId = tabTargetId(state.page.id);
    const pageId = pageTargetId(state.page.id);
    for (const conn of this.#conns.values()) {
      const sessions = [...conn.sessions].filter(([, ref]) => ref.pageId === state.page.id);
      sessions.sort(([, a], [, b]) => (a.kind === b.kind ? 0 : a.kind === "page" ? -1 : 1));
      for (const [sessionId, ref] of sessions) {
        conn.sessions.delete(sessionId);
        const targetId = ref.kind === "tab" ? tabId : pageId;
        this.#emit(conn, "Target.detachedFromTarget", { sessionId, targetId }, ref.parent);
      }
      if (state.announced && conn.discover) {
        this.#emit(conn, "Target.targetDestroyed", { targetId: pageId });
        this.#emit(conn, "Target.targetDestroyed", { targetId: tabId });
      }
    }
    state.announced = false;
    this.#host.onActivity?.();
  }

  #emitTabAttached(conn: Conn, state: PageState): void {
    if (conn.sessionsFor(state.page.id, "tab").length > 0) return;
    const sessionId = this.#mintSession(conn, "tab", state.page.id, undefined);
    this.#emit(conn, "Target.attachedToTarget", {
      sessionId,
      targetInfo: this.#tabInfo(state),
      waitingForDebugger: false,
    });
  }

  #mintSession(
    conn: Conn,
    kind: "tab" | "page",
    pageId: number,
    parent: string | undefined,
  ): string {
    const sessionId = `S${kind === "tab" ? "T" : "P"}${pageId}.${conn.id}.${++this.#sessionSeq}`;
    conn.sessions.set(sessionId, {
      kind,
      pageId,
      parent,
      runtime: "default",
      contexts: new Set(),
      autoAttach: false,
    });
    this.#host.onActivity?.();
    return sessionId;
  }

  #releaseSession(conn: Conn, sessionId: string, parentSessionId: string | undefined): void {
    const ref = conn.sessions.get(sessionId);
    if (!ref) return;
    for (const [child, childRef] of [...conn.sessions]) {
      if (childRef.parent === sessionId) this.#releaseSession(conn, child, sessionId);
    }
    conn.sessions.delete(sessionId);
    for (const [child, parent] of [...conn.childParents]) {
      if (parent === sessionId) conn.childParents.delete(child);
    }
    const targetId = ref.kind === "tab" ? tabTargetId(ref.pageId) : pageTargetId(ref.pageId);
    this.#emit(
      conn,
      "Target.detachedFromTarget",
      { sessionId, targetId },
      parentSessionId ?? ref.parent,
    );
    this.#detachIfUnheld(ref.pageId);
    this.#host.onActivity?.();
  }

  #ensureAttached(state: PageState): void {
    if (state.attached) return;
    state.page.attach();
    state.attached = true;
  }

  #detachIfUnheld(pageId: number): void {
    const state = this.#pages.get(pageId);
    if (!state?.attached) return;
    for (const conn of this.#conns.values()) {
      for (const ref of conn.sessions.values()) {
        if (ref.pageId === pageId) return;
      }
    }
    state.attached = false;
    this.#resetRuntime(state);
    state.children.clear();
    for (const [child, owner] of [...this.#childPage]) {
      if (owner === pageId) this.#childPage.delete(child);
    }
    state.page.detach();
  }

  #resetRuntime(state: PageState): void {
    state.generation += 1;
    state.rootRuntime = null;
    state.contexts.clear();
  }

  #touch(state: PageState, method: string): void {
    if (PASSIVE_METHODS[method] === true) return;
    state.lastCommandAt = Date.now();
    this.#host.onActivity?.();
  }

  #tabInfo(state: PageState): TargetInfo {
    return {
      targetId: tabTargetId(state.page.id),
      type: "tab",
      title: state.page.title(),
      url: state.page.url() || "about:blank",
      attached: this.#hasSession(state.page.id, "tab"),
      canAccessOpener: false,
    };
  }

  #pageInfo(state: PageState): TargetInfo {
    return {
      targetId: pageTargetId(state.page.id),
      type: "page",
      title: state.page.title(),
      url: state.page.url() || "about:blank",
      attached: this.#hasSession(state.page.id, "page"),
      canAccessOpener: false,
    };
  }

  #hasSession(pageId: number, kind: "tab" | "page"): boolean {
    for (const conn of this.#conns.values()) {
      if (conn.sessionsFor(pageId, kind).length > 0) return true;
    }
    return false;
  }

  #reply(conn: Conn, msg: CdpCommand, result: Params): void {
    const frame: Record<string, unknown> = { id: msg.id, result };
    if (msg.sessionId !== undefined) frame.sessionId = msg.sessionId;
    conn.socket.send(JSON.stringify(frame));
  }

  #replyError(conn: Conn, msg: CdpCommand, message: string, code = CDP_ERROR_SERVER): void {
    const frame: Record<string, unknown> = { id: msg.id, error: { code, message } };
    if (msg.sessionId !== undefined) frame.sessionId = msg.sessionId;
    conn.socket.send(JSON.stringify(frame));
  }

  #emit(conn: Conn, method: string, params: Params, sessionId?: string): void {
    const frame: Record<string, unknown> = { method, params };
    if (sessionId !== undefined) frame.sessionId = sessionId;
    conn.socket.send(JSON.stringify(frame));
  }
}
