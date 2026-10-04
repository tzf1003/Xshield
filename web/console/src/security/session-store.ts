import type { BrowserSession, ControlClient } from "../api.ts";
import { checkScope, type Scope, type ScopedResponse } from "./scope.ts";

/** Browser sessions end after 15 idle minutes (the server enforces the same limit). */
export const IDLE_MS = 15 * 60 * 1000;
export const idleNotice = "会话已因闲置断开，请重新连接。";
export const scopeNotice = "响应范围校验失败，连接已断开。";
export const unauthorizedNotice = "管理会话已失效，请重新登录。";

export type SessionState = Readonly<{
  status: "disconnected" | "connected";
  /** Increments on every connect and every disconnect; the identity of one session lifetime. */
  epoch: number;
  /** Why the last session ended, shown by the login screen. */
  notice: string | null;
  client: ControlClient | null;
  /** Server-confirmed tenant/site. `null` until a machine-login session sees its first reply. */
  scope: Scope | null;
  /** Server roles. `null` is the explicit local machine-login mode, never a browser session. */
  roles: readonly string[] | null;
  session: BrowserSession | null;
}>;

export type ConnectInput = {
  client: ControlClient;
  scope: Scope | null;
  roles: readonly string[] | null;
  session: BrowserSession | null;
};

export type DisconnectHook = (notice: string | null) => void;

export type Timers = {
  setTimeout: (callback: () => void, ms: number) => unknown;
  clearTimeout: (handle: unknown) => void;
};

const systemTimers: Timers = {
  setTimeout: (callback, ms) => {
    const handle = globalThis.setTimeout(callback, ms);
    // Node (tests, tooling) must not be kept alive by an idle countdown; browsers return a number.
    if (typeof handle === "object") handle.unref?.();
    return handle;
  },
  clearTimeout: (handle) => globalThis.clearTimeout(handle as ReturnType<typeof setTimeout>),
};

function disconnectedState(epoch: number, notice: string | null): SessionState {
  return Object.freeze({
    status: "disconnected",
    epoch,
    notice,
    client: null,
    scope: null,
    roles: null,
    session: null,
  });
}

function abortedController(): AbortController {
  const controller = new AbortController();
  controller.abort();
  return controller;
}

/**
 * The single owner of everything that identifies the operator's session: the ControlClient, the
 * confirmed scope, roles and the epoch. It is framework-free so every invariant (late responses,
 * scope mismatch, idle expiry) is unit-tested without a DOM, and React reads it through
 * `useSyncExternalStore`.
 *
 * Nothing here touches web storage: the state lives and dies with the JavaScript heap.
 */
export class SessionStore {
  #state: SessionState = disconnectedState(0, null);
  #controller: AbortController = abortedController();
  readonly #listeners = new Set<() => void>();
  readonly #hooks = new Set<DisconnectHook>();
  #idleHandle: unknown = null;
  readonly #idleMs: number;
  readonly #timers: Timers;

  constructor(options: { idleMs?: number; timers?: Timers } = {}) {
    this.#idleMs = options.idleMs ?? IDLE_MS;
    this.#timers = options.timers ?? systemTimers;
  }

  /** Stable between changes, as `useSyncExternalStore` requires. */
  getState = (): SessionState => this.#state;

  subscribe = (listener: () => void): (() => void) => {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  };

  /** Aborted when the session ends; already aborted while disconnected. */
  get signal(): AbortSignal {
    return this.#controller.signal;
  }

  isCurrent(epoch: number): boolean {
    return this.#state.status === "connected" && this.#state.epoch === epoch;
  }

  /** Runs inside `disconnect`, after in-flight requests were aborted and before listeners fire. */
  onDisconnect(hook: DisconnectHook): () => void {
    this.#hooks.add(hook);
    return () => this.#hooks.delete(hook);
  }

  connect(input: ConnectInput): number {
    // A new identity must never inherit the previous lifetime's caches or requests.
    if (this.#state.status === "connected") this.disconnect(null);
    const epoch = this.#state.epoch + 1;
    this.#controller = new AbortController();
    this.#state = Object.freeze({
      status: "connected",
      epoch,
      notice: null,
      client: input.client,
      scope: input.scope,
      roles: input.roles ? Object.freeze([...input.roles]) : null,
      session: input.session,
    });
    this.touch();
    this.#emit();
    return epoch;
  }

  /**
   * Ends the session: aborts every in-flight request, bumps the epoch, drops the client and
   * scope, then lets the registered hooks clear the caches that were derived from it.
   */
  disconnect(notice: string | null = null): void {
    const previous = this.#state;
    if (previous.status === "disconnected") {
      if (notice !== null && notice !== previous.notice) {
        this.#state = disconnectedState(previous.epoch, notice);
        this.#emit();
      }
      return;
    }
    this.#clearIdleTimer();
    this.#controller.abort();
    this.#controller = abortedController();
    this.#state = disconnectedState(previous.epoch + 1, notice);
    for (const hook of [...this.#hooks]) {
      try {
        hook(notice);
      } catch {
        // One failing cache must not keep the others from being cleared.
      }
    }
    this.#emit();
  }

  /** Drops a stale notice (for example once the operator started typing a new credential). */
  setNotice(notice: string | null): void {
    if (this.#state.notice === notice) return;
    this.#state = Object.freeze({ ...this.#state, notice });
    this.#emit();
  }

  /**
   * Checks a response against the confirmed scope. A cross-tenant or cross-site answer ends the
   * session immediately; the first answer of a machine-login session establishes the scope.
   */
  verifyScope(response: ScopedResponse, expectedSiteId?: string): "ok" | "wrong_site" | "mismatch" {
    const state = this.#state;
    if (state.status !== "connected") return "mismatch";
    const check = checkScope(state.scope, response, expectedSiteId);
    if (check.kind === "mismatch") {
      this.disconnect(scopeNotice);
      return "mismatch";
    }
    if (check.kind === "wrong_site") return "wrong_site";
    if (check.confirm) {
      this.#state = Object.freeze({ ...state, scope: check.confirm });
      this.#emit();
    }
    return "ok";
  }

  /** Server-provided session facts replaced by a fresh read (roles may change at any time). */
  updateSession(session: BrowserSession): void {
    const state = this.#state;
    if (state.status !== "connected") return;
    this.#state = Object.freeze({
      ...state,
      session,
      roles: Object.freeze([...session.roles]),
    });
    this.#emit();
  }

  /** Operator activity: restarts the idle countdown. */
  touch(): void {
    if (this.#state.status !== "connected") return;
    this.#clearIdleTimer();
    this.#idleHandle = this.#timers.setTimeout(() => this.disconnect(idleNotice), this.#idleMs);
  }

  #clearIdleTimer() {
    if (this.#idleHandle !== null) this.#timers.clearTimeout(this.#idleHandle);
    this.#idleHandle = null;
  }

  #emit() {
    for (const listener of [...this.#listeners]) listener();
  }
}
