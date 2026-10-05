/**
 * Where the plaintext of a freshly issued Agent API key waits until the operator has stored it,
 * and what this session learned about each key's scopes.
 *
 * The secret never enters TanStack Query, the pending-operation registry, a URL, a title, web
 * storage or a log: the write's `run` puts it here and hands the rest of the response (without
 * `api_key`) to the guarded write layer. It lives in this per-runtime slot only until the
 * operator confirms "我已保存" and closes the dialog, or until the session ends (idle, logout, 401,
 * scope violation, page hide), whichever comes first. JavaScript offers no reliable zeroing of
 * memory; dropping every reference is the most a browser page can do.
 *
 * The slot is per runtime rather than per page so that a reply arriving after the operator left
 * the page (or an exact retry finished elsewhere) is still shown once, the next time the API key
 * page is open, instead of being stranded in an unmounted component.
 *
 * The key list does not return scopes, so the scopes the console saw in this session's create
 * and rotate replies are remembered here (in memory, non-secret) to label those rows.
 */
import type { SessionRuntime } from "../security/runtime.ts";

export type IssuedScope = Readonly<{ site_id: string; capabilities: readonly string[] }>;

export type IssuedSecret = Readonly<{
  /** The session lifetime that received it; a secret is never shown in a later session. */
  epoch: number;
  kind: "created" | "rotated";
  apiKeyId: string;
  /** The key a rotation retired. */
  replaced: string | null;
  displayName: string;
  subject: string;
  keyPrefix: string;
  expiresAt: string;
  scopes: readonly IssuedScope[];
  secret: string;
}>;

type Snapshot = Readonly<{
  /** Secrets not yet acknowledged, oldest first. */
  pending: readonly IssuedSecret[];
  /** Scopes per key ID, as issued in this session. */
  scopes: ReadonlyMap<string, readonly IssuedScope[]>;
}>;

const empty: Snapshot = Object.freeze({ pending: Object.freeze([]), scopes: new Map() });

export class KeySecretStore {
  #snapshot: Snapshot = empty;
  readonly #listeners = new Set<() => void>();

  getSnapshot = (): Snapshot => this.#snapshot;

  subscribe = (listener: () => void): (() => void) => {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  };

  /** A key was issued: queue its plaintext for the one-time dialog and remember its scopes. */
  put(issued: IssuedSecret): void {
    const scopes = new Map(this.#snapshot.scopes);
    scopes.set(issued.apiKeyId, issued.scopes);
    this.#set({ pending: Object.freeze([...this.#snapshot.pending, issued]), scopes });
  }

  /** The operator stored it: the plaintext is dropped; the non-secret scopes stay. */
  acknowledge(apiKeyId: string): void {
    const pending = this.#snapshot.pending.filter((item) => item.apiKeyId !== apiKeyId);
    if (pending.length === this.#snapshot.pending.length) return;
    this.#set({ ...this.#snapshot, pending: Object.freeze(pending) });
  }

  /** Session end: everything goes. */
  clear(): void {
    if (this.#snapshot === empty) return;
    this.#set(empty);
  }

  #set(next: Snapshot): void {
    this.#snapshot = Object.freeze(next);
    for (const listener of [...this.#listeners]) listener();
  }
}

const stores = new WeakMap<SessionRuntime, KeySecretStore>();

/** One store per runtime; it clears itself whenever the session ends. */
export function keySecrets(runtime: SessionRuntime): KeySecretStore {
  let store = stores.get(runtime);
  if (!store) {
    store = new KeySecretStore();
    const fresh = store;
    runtime.store.onDisconnect(() => fresh.clear());
    stores.set(runtime, store);
  }
  return store;
}
