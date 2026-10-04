import { QueryClient } from "@tanstack/react-query";

/** Reads here are audit-bearing: they refresh only when the operator asks. */
export const MANUAL_REFRESH = Number.POSITIVE_INFINITY;

/**
 * Sensitive responses linger in memory only briefly after their view is gone. The whole cache is
 * dropped on logout, idle expiry, 401, scope mismatch and page hide in any case.
 */
export const QUERY_GC_MS = 60_000;

/**
 * No automatic retry, polling, window-focus or reconnect refetch, and `networkMode: "always"` so a
 * request is never parked and silently resumed when connectivity returns.
 */
export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: 0,
        retryOnMount: false,
        refetchOnWindowFocus: false,
        refetchOnReconnect: false,
        refetchInterval: false,
        staleTime: MANUAL_REFRESH,
        gcTime: QUERY_GC_MS,
        networkMode: "always",
      },
      mutations: {
        retry: 0,
        networkMode: "always",
        gcTime: QUERY_GC_MS,
      },
    },
  });
}
