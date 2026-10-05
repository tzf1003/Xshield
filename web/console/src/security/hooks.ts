import { type InfiniteData, useInfiniteQuery, useMutation, useQuery } from "@tanstack/react-query";
import { useCallback, useSyncExternalStore } from "react";
import type { ControlClient } from "../api";
import { runFrozenWrite, type WriteResult } from "./guarded.ts";
import {
  type GuardedInfiniteSpec,
  type GuardedQuerySpec,
  guardedInfiniteQuery,
  guardedQuery,
} from "./guarded-query.ts";
import type { HttpMethod, OperationSnapshot } from "./pending-operations.ts";
import type { ScopedResponse } from "./scope.ts";
import { useSession } from "./SessionProvider";

/**
 * A read bound to the current session epoch. Re-renders with a new key whenever the session
 * changes, so nothing from a previous session is ever shown.
 */
export function useGuardedQuery<T extends ScopedResponse>(spec: GuardedQuerySpec<T>) {
  const { runtime } = useSession(); // `state` changes re-render this hook with the new epoch
  return useQuery(guardedQuery(runtime, spec));
}

/**
 * A cursor-paginated read. `refresh` starts over from the first page (it never replays the
 * cursors of the pages that were loaded), which is what a "刷新" button means for a list.
 */
export function useGuardedInfiniteQuery<T extends ScopedResponse>(spec: GuardedInfiniteSpec<T>) {
  const { runtime } = useSession();
  const options = guardedInfiniteQuery(runtime, spec);
  const query = useInfiniteQuery(options);
  const { refetch } = query;
  const queryKey = options.queryKey;
  const refresh = useCallback(async () => {
    runtime.queryClient.setQueryData<InfiniteData<T, string | undefined>>(queryKey, (data) =>
      data ? { pages: data.pages.slice(0, 1), pageParams: data.pageParams.slice(0, 1) } : data,
    );
    return refetch();
  }, [runtime.queryClient, queryKey, refetch]);
  return { ...query, refresh };
}

/** Unresolved writes, for the "待确认操作" indicator and the pages that own them. */
export function usePendingOperations(): readonly OperationSnapshot[] {
  const { runtime } = useSession();
  return useSyncExternalStore(runtime.pending.subscribe, runtime.pending.getSnapshot);
}

export type GuardedMutationSpec<TVars, T extends ScopedResponse> = {
  label: string;
  method: HttpMethod;
  /** Fixed `/control/v1/...` path of the frozen request. */
  path: (vars: TVars) => string;
  body?: (vars: TVars) => unknown;
  expectedSiteId?: (vars: TVars) => string | undefined;
  /** Runs with a deep copy of the variables taken at submit time, never with live form state. */
  execute: (
    client: ControlClient,
    vars: TVars,
    context: { signal: AbortSignal; idempotencyKey: string },
  ) => Promise<T>;
};

/**
 * Submits a write through the session guard. The request is frozen in the pending-operation
 * registry before it is sent; an `unknown` result can only be continued with `retry`, which
 * resends the identical request under the original idempotency key.
 */
export function useGuardedMutation<TVars, T extends ScopedResponse>(
  spec: GuardedMutationSpec<TVars, T>,
) {
  const { runtime } = useSession();
  const mutation = useMutation<
    WriteResult<T>,
    Error,
    { vars: TVars; retryId?: undefined } | { retryId: string }
  >({
    retry: 0,
    networkMode: "always",
    mutationFn: async (input) => {
      if ("retryId" in input && input.retryId !== undefined) {
        return runFrozenWrite<T>(runtime.store, runtime.pending, input.retryId);
      }
      const vars = structuredClone((input as { vars: TVars }).vars);
      const frozen = runtime.pending.freeze<T>({
        label: spec.label,
        method: spec.method,
        path: spec.path(vars),
        body: spec.body?.(vars),
        expectedSiteId: spec.expectedSiteId?.(vars),
        execute: (client, signal, idempotencyKey) =>
          spec.execute(client, vars, { signal, idempotencyKey }),
      });
      return runFrozenWrite<T>(runtime.store, runtime.pending, frozen.id);
    },
  });
  return {
    submit: (vars: TVars) => mutation.mutateAsync({ vars }),
    retry: (operationId: string) => mutation.mutateAsync({ retryId: operationId }),
    isPending: mutation.isPending,
    result: mutation.data ?? null,
    reset: mutation.reset,
  };
}
