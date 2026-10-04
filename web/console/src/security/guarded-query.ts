import type { ControlClient } from "../api.ts";
import { runGuardedRead } from "./guarded.ts";
import type { SessionRuntime } from "./runtime.ts";
import type { ScopedResponse } from "./scope.ts";

export type GuardedQuerySpec<T extends ScopedResponse> = {
  /** Domain key such as `["workbench", "overview"]`; the session epoch is prefixed for you. */
  key: readonly unknown[];
  fetch: (client: ControlClient, signal: AbortSignal) => Promise<T>;
  /**
   * Required on purpose. Every control read is audited server-side, so the norm is
   * `MANUAL_REFRESH` (never stale); a finite value is an explicit decision per query.
   */
  staleTime: number;
  /** Multi-site reads answer for this site instead of the session's own site. */
  expectedSiteId?: string;
  enabled?: boolean;
  gcTime?: number;
};

/** The epoch is part of the key, so entries of an earlier session can never be read again. */
export function guardedQueryKey(epoch: number, key: readonly unknown[]): readonly unknown[] {
  return ["xs", epoch, ...key];
}

/**
 * Options for `useQuery`/`fetchQuery` bound to the current session epoch:
 * epoch in the key, the abort signal passed through, every reply scope-checked, a late reply of
 * an older epoch dropped, 401 turned into a global disconnect + cache clear, and no automatic
 * retry, polling or focus/reconnect refetch.
 */
export function guardedQuery<T extends ScopedResponse>(
  runtime: SessionRuntime,
  spec: GuardedQuerySpec<T>,
) {
  const { store } = runtime;
  const state = store.getState();
  const epoch = state.epoch;
  return {
    queryKey: guardedQueryKey(epoch, spec.key),
    queryFn: ({ signal }: { signal: AbortSignal }) =>
      runGuardedRead(store, {
        fetch: spec.fetch,
        expectedSiteId: spec.expectedSiteId,
        epoch,
        signal,
      }),
    enabled: state.status === "connected" && spec.enabled !== false,
    staleTime: spec.staleTime,
    gcTime: spec.gcTime ?? runtime.queryGcMs,
    retry: 0,
    retryOnMount: false,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
    refetchInterval: false,
    networkMode: "always",
  } as const;
}
