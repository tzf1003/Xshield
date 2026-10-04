import type { ControlClient } from "../api.ts";
import { validIdempotencyKey } from "../cases.ts";
import { isKnownRejection, isStepUpRequired, type SafeError, safeError } from "./errors.ts";
import type { ScopedResponse } from "./scope.ts";

export type HttpMethod = "POST" | "PUT" | "PATCH" | "DELETE";

/**
 * `inflight`: sent, no verdict yet. `unknown`: the outcome cannot be established (network loss,
 * timeout, 5xx, contract failure, ...). `step_up`: the server refused before running anything
 * because the fresh MFA step-up is missing, so the outcome IS known (nothing happened) and the
 * identical request may be repeated once the operator re-verified. A confirmed success or a
 * deterministic server refusal resolves the operation and removes it.
 */
export type OperationPhase = "inflight" | "unknown" | "step_up";

export type OperationSnapshot = Readonly<{
  id: string;
  label: string;
  method: HttpMethod;
  /** Fixed same-origin API path, for example `/control/v1/cases`. */
  path: string;
  /** Exact request text that was frozen at submit time. */
  body: string | null;
  idempotencyKey: string;
  createdAt: number;
  phase: OperationPhase;
  attempts: number;
  lastError: SafeError | null;
}>;

export type FrozenWrite<T extends ScopedResponse = ScopedResponse> = {
  label: string;
  method: HttpMethod;
  path: string;
  /** Serialized once here; later retries reuse the identical text. */
  body?: unknown;
  /** Defaults to a random UUID. */
  idempotencyKey?: string;
  /** Multi-site writes answer for this site rather than the session's own site. */
  expectedSiteId?: string;
  /** Must only use values captured at freeze time (never live form state). */
  execute: (client: ControlClient, signal: AbortSignal, idempotencyKey: string) => Promise<T>;
};

export type AttemptStart = {
  snapshot: OperationSnapshot;
  execute: FrozenWrite["execute"];
  expectedSiteId: string | undefined;
};

type Entry = {
  snapshot: OperationSnapshot;
  execute: FrozenWrite["execute"];
  expectedSiteId: string | undefined;
  /** Once an attempt was ambiguous, a later refusal can never prove the first one did not commit. */
  hadUnknown: boolean;
};

export type PendingStoreOptions = {
  now?: () => number;
  newId?: () => string;
  newKey?: () => string;
};

const pathPattern = /^\/control\/v1\/[A-Za-z0-9/_.-]{1,200}(?![\s\S])/;

/**
 * In-memory registry of write operations whose outcome is not yet known. Entries freeze the
 * request (method, path, idempotency key, body) at submit time; the only way to continue an
 * `unknown` entry is `start()` followed by the identical frozen execute, so a retry reuses the
 * original key and body byte for byte.
 *
 * The store never touches web storage and exposes no serialization hook: a page reload, an idle
 * timeout or a 401 drops it, and the operator recovers from the values shown on screen.
 */
export class PendingOperationStore {
  readonly #entries = new Map<string, Entry>();
  readonly #listeners = new Set<() => void>();
  #snapshot: readonly OperationSnapshot[] = Object.freeze([]);
  readonly #now: () => number;
  readonly #newId: () => string;
  readonly #newKey: () => string;

  constructor(options: PendingStoreOptions = {}) {
    this.#now = options.now ?? (() => Date.now());
    this.#newId = options.newId ?? (() => globalThis.crypto.randomUUID());
    this.#newKey = options.newKey ?? (() => globalThis.crypto.randomUUID());
  }

  /** Stable between changes; ordered by creation time. */
  getSnapshot = (): readonly OperationSnapshot[] => this.#snapshot;

  subscribe = (listener: () => void): (() => void) => {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  };

  /**
   * Operations whose outcome is not established: in flight or unknown. A `step_up` entry is
   * not counted (the server did nothing), so the page-leave warning does not fire for the
   * very redirect that performs the re-verification.
   */
  get unresolvedCount(): number {
    let count = 0;
    for (const entry of this.#entries.values()) {
      if (entry.snapshot.phase !== "step_up") count += 1;
    }
    return count;
  }

  get(id: string): OperationSnapshot | null {
    return this.#entries.get(id)?.snapshot ?? null;
  }

  /** Registers a write before it is sent. The returned snapshot is deeply immutable. */
  freeze<T extends ScopedResponse>(input: FrozenWrite<T>): OperationSnapshot {
    if (!pathPattern.test(input.path) || input.path.includes("..") || input.path.includes("//")) {
      throw new TypeError("pending operations require a fixed /control/v1/ path");
    }
    if (input.label.length === 0 || input.label.length > 80) {
      throw new TypeError("pending operations require a short label");
    }
    const idempotencyKey = input.idempotencyKey ?? this.#newKey();
    if (!validIdempotencyKey(idempotencyKey)) {
      throw new TypeError("pending operations require a valid idempotency key");
    }
    const body =
      input.body === undefined || input.body === null
        ? null
        : typeof input.body === "string"
          ? input.body
          : JSON.stringify(input.body);
    const snapshot: OperationSnapshot = Object.freeze({
      id: this.#newId(),
      label: input.label,
      method: input.method,
      path: input.path,
      body,
      idempotencyKey,
      createdAt: this.#now(),
      phase: "inflight",
      attempts: 0,
      lastError: null,
    });
    this.#entries.set(snapshot.id, {
      snapshot,
      execute: input.execute as FrozenWrite["execute"],
      expectedSiteId: input.expectedSiteId,
      hadUnknown: false,
    });
    this.#publish();
    return snapshot;
  }

  /**
   * Marks one more attempt in flight and hands back the frozen request. A fresh entry may start
   * once; afterwards only an `unknown` entry may start again, and only with the same request.
   */
  start(id: string): AttemptStart {
    const entry = this.#entries.get(id);
    if (!entry) throw new Error("unknown pending operation");
    const { snapshot } = entry;
    const retryable =
      snapshot.phase === "unknown" || snapshot.phase === "step_up" || snapshot.attempts === 0;
    if (!retryable) throw new Error("operation is already in flight");
    entry.snapshot = Object.freeze({
      ...snapshot,
      phase: "inflight",
      attempts: snapshot.attempts + 1,
    });
    this.#publish();
    return {
      snapshot: entry.snapshot,
      execute: entry.execute,
      expectedSiteId: entry.expectedSiteId,
    };
  }

  /** A validated success: the operation is confirmed and leaves the registry. */
  resolve(id: string): void {
    if (this.#entries.delete(id)) this.#publish();
  }

  /**
   * The operator gives up an operation whose outcome they could not establish (typically after
   * re-reading the state). The frozen request is dropped; it can never be sent again.
   */
  abandon(id: string): boolean {
    if (!this.#entries.delete(id)) return false;
    this.#publish();
    return true;
  }

  /**
   * Classifies a failed attempt. A refusal because the MFA step-up is missing keeps the frozen
   * request for an exact retry (`step_up`); any other deterministic refusal of a first attempt
   * resolves the entry (`rejected`); everything else, and any refusal after an ambiguous
   * attempt, keeps it `unknown`.
   */
  fail(id: string, error: unknown): "rejected" | "unknown" | "step_up" {
    const entry = this.#entries.get(id);
    if (!entry) return "rejected";
    if (isStepUpRequired(error)) {
      entry.snapshot = Object.freeze({
        ...entry.snapshot,
        phase: "step_up",
        lastError: safeError(error),
      });
      this.#publish();
      return "step_up";
    }
    if (!entry.hadUnknown && isKnownRejection(error)) {
      this.#entries.delete(id);
      this.#publish();
      return "rejected";
    }
    entry.hadUnknown = true;
    entry.snapshot = Object.freeze({
      ...entry.snapshot,
      phase: "unknown",
      lastError: safeError(error),
    });
    this.#publish();
    return "unknown";
  }

  /** Session end: everything is dropped. Returns how many unresolved operations were lost. */
  clear(): number {
    const lost = this.#entries.size;
    if (lost > 0) {
      this.#entries.clear();
      this.#publish();
    }
    return lost;
  }

  #publish() {
    this.#snapshot = Object.freeze(
      [...this.#entries.values()]
        .map((entry) => entry.snapshot)
        .sort((a, b) => a.createdAt - b.createdAt),
    );
    for (const listener of [...this.#listeners]) listener();
  }
}

type UnloadTarget = {
  addEventListener(type: "beforeunload", listener: (event: BeforeUnloadEvent) => void): void;
  removeEventListener(type: "beforeunload", listener: (event: BeforeUnloadEvent) => void): void;
};

/**
 * Warns before the page is left while any operation is unresolved, and only then. Returns the
 * disposer. The warning text is the browser's own; `returnValue` is set for older engines.
 */
export function installBeforeUnloadGuard(
  store: PendingOperationStore,
  target: UnloadTarget,
): () => void {
  const warn = (event: BeforeUnloadEvent) => {
    event.preventDefault();
    event.returnValue = "";
  };
  let armed = false;
  const sync = () => {
    const needed = store.unresolvedCount > 0;
    if (needed && !armed) target.addEventListener("beforeunload", warn);
    else if (!needed && armed) target.removeEventListener("beforeunload", warn);
    armed = needed;
  };
  sync();
  const unsubscribe = store.subscribe(sync);
  return () => {
    unsubscribe();
    if (armed) target.removeEventListener("beforeunload", warn);
    armed = false;
  };
}
