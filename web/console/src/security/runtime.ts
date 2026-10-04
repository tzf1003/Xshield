import type { QueryClient } from "@tanstack/react-query";
import { PendingOperationStore, type PendingStoreOptions } from "./pending-operations.ts";
import { createQueryClient, QUERY_GC_MS } from "./query-client.ts";
import { SessionStore, type Timers } from "./session-store.ts";

/**
 * The session, the query cache and the pending-operation registry are one unit: whatever ends
 * the session (idle timer, logout, page hide, 401, scope violation, the legacy host) clears all
 * three together, in this order: abort requests, drop the identity, clear caches.
 */
export type SessionRuntime = {
  readonly store: SessionStore;
  readonly queryClient: QueryClient;
  readonly pending: PendingOperationStore;
  /** How long an unobserved query response may stay in memory. */
  readonly queryGcMs: number;
};

export type RuntimeOptions = {
  idleMs?: number;
  timers?: Timers;
  queryClient?: QueryClient;
  queryGcMs?: number;
  pending?: PendingStoreOptions;
};

export function createSessionRuntime(options: RuntimeOptions = {}): SessionRuntime {
  const store = new SessionStore({ idleMs: options.idleMs, timers: options.timers });
  const queryClient = options.queryClient ?? createQueryClient();
  const pending = new PendingOperationStore(options.pending);
  store.onDisconnect(() => {
    queryClient.clear();
    pending.clear();
  });
  return { store, queryClient, pending, queryGcMs: options.queryGcMs ?? QUERY_GC_MS };
}
