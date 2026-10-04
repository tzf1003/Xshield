/**
 * In-place MFA step-up. The server refuses a high-risk request with CONTROL_STEP_UP_REQUIRED
 * before it touches any state. Instead of making the operator leave the page (a full-page OIDC
 * redirect would discard every frozen request held in memory), the coordinator pauses the
 * attempt, lets the operator verify in a separate window, re-reads the server session and then
 * lets the SAME frozen request go out again, with the same idempotency key and body.
 *
 * Framework-free: the browser pieces (window, channel, session read) are injected, so the state
 * machine is unit-tested without a DOM.
 */
import { isStepUpRequired } from "./errors.ts";

export type StepUpPhase = "idle" | "needed" | "opening" | "waiting" | "checking";
export type StepUpState = Readonly<{ phase: StepUpPhase; message: string | null }>;

export type StepUpWindow = {
  navigate(url: string): void;
  close(): void;
  isClosed(): boolean;
};

export type StepUpDeps = {
  /** A browser session can re-authenticate; a machine credential has no such path. */
  available: () => boolean;
  /** Synchronous, from a click: a blank verification window, or `null` when it was blocked. */
  openWindow: () => StepUpWindow | null;
  /** The identity provider's authorization URL for this session. */
  start: (signal: AbortSignal) => Promise<string>;
  /** Re-reads the server session: `true` when the step-up is valid right now. */
  check: (signal: AbortSignal) => Promise<boolean>;
  /** The returning window's same-origin hint. It is never proof; the session is always re-read. */
  listen: (listener: () => void) => () => void;
  /** Runs `tick` every `ms` until the returned stop function is called. */
  every?: (tick: () => void, ms: number) => () => void;
};

export class StepUpUnavailableError extends Error {
  constructor() {
    super("step-up is not available for this credential");
    this.name = "StepUpUnavailableError";
  }
}
export class StepUpCancelledError extends Error {
  constructor() {
    super("step-up was cancelled");
    this.name = "StepUpCancelledError";
  }
}

type Waiter = { resolve: () => void; reject: (error: Error) => void; release: () => void };

const idle: StepUpState = Object.freeze({ phase: "idle", message: null });
const blocked =
  "浏览器拦截了新窗口。请允许本站弹窗后重试，或使用顶栏的“重新验证高危操作”（会离开本页，未提交内容不保留）。";
const notYet = "再认证尚未生效。请在验证窗口完成 MFA 后点击“我已完成，重新检查”。";

function failureMessage(error: unknown): string {
  return error instanceof Error && error.message ? error.message : "无法完成再认证，请重试。";
}

function defaultEvery(tick: () => void, ms: number): () => void {
  const handle = setInterval(tick, ms);
  return () => clearInterval(handle);
}

export class StepUpCoordinator {
  readonly #deps: StepUpDeps;
  readonly #listeners = new Set<() => void>();
  readonly #waiters = new Set<Waiter>();
  #state: StepUpState = idle;
  #window: StepUpWindow | null = null;
  #controller: AbortController | null = null;
  #stopWatching: (() => void) | null = null;

  constructor(deps: StepUpDeps) {
    this.#deps = deps;
  }

  getState = (): StepUpState => this.#state;

  subscribe = (listener: () => void): (() => void) => {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  };

  /** Starts listening for the verification window's return; the disposer also cancels any wait. */
  attach(): () => void {
    const stop = this.#deps.listen(() => void this.recheck());
    return () => {
      stop();
      this.cancel();
    };
  }

  /**
   * Called by an attempt the server refused for want of a step-up. Resolves once the session is
   * verified; rejects when the operator cancels, the browser cannot step up, or `signal` aborts.
   * Concurrent callers share one verification.
   */
  require(signal: AbortSignal): Promise<void> {
    if (signal.aborted) return Promise.reject(new StepUpCancelledError());
    if (!this.#deps.available()) return Promise.reject(new StepUpUnavailableError());
    return new Promise<void>((resolve, reject) => {
      const onAbort = () => {
        this.#waiters.delete(waiter);
        reject(new StepUpCancelledError());
        if (this.#waiters.size === 0) this.#reset();
      };
      const waiter: Waiter = {
        resolve,
        reject,
        release: () => signal.removeEventListener("abort", onAbort),
      };
      signal.addEventListener("abort", onAbort, { once: true });
      this.#waiters.add(waiter);
      if (this.#state.phase === "idle") this.#set({ phase: "needed", message: null });
    });
  }

  /** Opens the verification window. Must run inside a click so the browser allows the window. */
  begin(): void {
    if (this.#state.phase !== "needed") return;
    const win = this.#deps.openWindow();
    if (win === null) {
      this.#set({ phase: "needed", message: blocked });
      return;
    }
    this.#window = win;
    const controller = new AbortController();
    this.#controller = controller;
    this.#set({ phase: "opening", message: null });
    this.#deps.start(controller.signal).then(
      (url) => {
        if (this.#controller !== controller) return;
        win.navigate(url);
        this.#set({ phase: "waiting", message: null });
        this.#watch(controller);
      },
      (error: unknown) => {
        if (this.#controller !== controller) return;
        this.#closeWindow();
        this.#set({ phase: "needed", message: failureMessage(error) });
      },
    );
  }

  /** Re-reads the server session; on success every paused attempt is released. */
  async recheck(): Promise<void> {
    const phase = this.#state.phase;
    // Nothing is paused, or a check is already running: a stray hint changes nothing.
    if (this.#waiters.size === 0 || phase === "idle" || phase === "checking") return;
    this.#stopWatch();
    const controller = new AbortController();
    this.#controller = controller;
    const resume: StepUpPhase = this.#window === null ? "needed" : "waiting";
    this.#set({ phase: "checking", message: null });
    try {
      const valid = await this.#deps.check(controller.signal);
      if (this.#controller !== controller) return;
      if (valid) this.#finish();
      else this.#set({ phase: resume, message: notYet });
    } catch (error) {
      if (this.#controller !== controller) return;
      this.#set({ phase: resume, message: failureMessage(error) });
    }
  }

  /** The operator gave up: every paused attempt ends with its original refusal. */
  cancel(): void {
    const waiters = [...this.#waiters];
    this.#waiters.clear();
    this.#reset();
    for (const waiter of waiters) {
      waiter.release();
      waiter.reject(new StepUpCancelledError());
    }
  }

  #finish(): void {
    const waiters = [...this.#waiters];
    this.#waiters.clear();
    this.#reset();
    for (const waiter of waiters) {
      waiter.release();
      waiter.resolve();
    }
  }

  #reset(): void {
    this.#controller?.abort();
    this.#controller = null;
    this.#stopWatch();
    this.#closeWindow();
    this.#set(idle);
  }

  #closeWindow(): void {
    try {
      this.#window?.close();
    } catch {
      // A window that is already gone needs no closing.
    }
    this.#window = null;
  }

  /** A window the operator closed without finishing is re-checked once, never polled. */
  #watch(controller: AbortController): void {
    const every = this.#deps.every ?? defaultEvery;
    const win = this.#window;
    this.#stopWatching = every(() => {
      if (this.#controller !== controller || !win?.isClosed()) return;
      this.#stopWatch();
      void this.recheck();
    }, 1000);
  }

  #stopWatch(): void {
    this.#stopWatching?.();
    this.#stopWatching = null;
  }

  #set(state: StepUpState): void {
    if (this.#state.phase === state.phase && this.#state.message === state.message) return;
    this.#state = Object.freeze(state);
    for (const listener of [...this.#listeners]) listener();
  }
}

/**
 * Runs `run`; when the server refuses it for want of a step-up, waits for the coordinator and
 * runs the very same closure once more. Anything else, a cancelled or impossible step-up
 * included, ends with the original refusal: nothing was written, and no second request is sent.
 */
export async function withStepUp<T>(
  coordinator: Pick<StepUpCoordinator, "require">,
  signal: AbortSignal,
  run: () => Promise<T>,
): Promise<T> {
  try {
    return await run();
  } catch (error) {
    if (!isStepUpRequired(error)) throw error;
    try {
      await coordinator.require(signal);
    } catch {
      throw error;
    }
    return await run();
  }
}
