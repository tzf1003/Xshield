import { useQueryClient } from "@tanstack/react-query";
import { useCallback } from "react";
import { useGuardedQuery } from "../../security/hooks.ts";
import { guardedQueryKey } from "../../security/guarded-query.ts";
import { MANUAL_REFRESH } from "../../security/query-client.ts";
import { useSession } from "../../security/SessionProvider.tsx";
import { siteKeys } from "./queries.ts";

/**
 * The reads behind one site's pages. Every one is epoch-keyed, scope-checked against the
 * requested site (a reply for another site throws instead of rendering), cancelled with its
 * view and never refetched by itself. Which of them an operator runs depends on the roles:
 * the configuration needs SystemAdmin, status/revisions/health need Observer.
 */
export function useSiteConfig(siteId: string, enabled: boolean) {
  return useGuardedQuery({
    key: siteKeys.config(siteId),
    enabled,
    expectedSiteId: siteId,
    staleTime: MANUAL_REFRESH,
    fetch: (client, signal) => client.siteConfig(siteId, signal),
  });
}

export function useSiteStatus(siteId: string, enabled: boolean) {
  return useGuardedQuery({
    key: siteKeys.status(siteId),
    enabled,
    expectedSiteId: siteId,
    staleTime: MANUAL_REFRESH,
    fetch: (client, signal) => client.siteStatus(siteId, signal),
  });
}

export function useSiteRevisions(siteId: string, enabled: boolean) {
  return useGuardedQuery({
    key: siteKeys.revisions(siteId),
    enabled,
    expectedSiteId: siteId,
    staleTime: MANUAL_REFRESH,
    fetch: (client, signal) => client.siteRevisions(siteId, signal),
  });
}

/**
 * Health is a manual read: each one is audited by the server and inserts a row, so the query is
 * disabled and only `read()` runs it. The previous observation is dropped before the new read,
 * so a failed read can never leave an old result on screen.
 */
export function useSiteHealth(siteId: string) {
  const { runtime } = useSession();
  const query = useGuardedQuery({
    key: siteKeys.health(siteId),
    enabled: false,
    expectedSiteId: siteId,
    staleTime: MANUAL_REFRESH,
    fetch: (client, signal) => client.siteHealth(siteId, signal),
  });
  const { refetch } = query;
  const read = useCallback(async () => {
    const epoch = runtime.store.getState().epoch;
    runtime.queryClient.removeQueries({
      queryKey: guardedQueryKey(epoch, siteKeys.health(siteId)),
    });
    await refetch();
  }, [runtime, siteId, refetch]);
  return { ...query, read };
}

/** Cache maintenance after a write that the server confirmed. Health is never re-read. */
export function useSiteCache(siteId: string) {
  const { runtime } = useSession();
  const queryClient = useQueryClient();
  /** Seeds the configuration read with a confirmed write's answer (for `target`, default this site). */
  const setConfig = useCallback(
    (response: unknown, target: string = siteId) => {
      const epoch = runtime.store.getState().epoch;
      queryClient.setQueryData(guardedQueryKey(epoch, siteKeys.config(target)), response);
    },
    [runtime, queryClient, siteId],
  );
  /** Re-read config, status and revisions that are on screen; mark the list stale for later. */
  const refreshDetail = useCallback(() => {
    const epoch = runtime.store.getState().epoch;
    for (const key of [
      siteKeys.config(siteId),
      siteKeys.status(siteId),
      siteKeys.revisions(siteId),
    ]) {
      void queryClient.invalidateQueries({ queryKey: guardedQueryKey(epoch, key) });
    }
    void queryClient.invalidateQueries({
      queryKey: guardedQueryKey(epoch, siteKeys.list),
      refetchType: "none",
    });
  }, [runtime, queryClient, siteId]);
  const dropSite = useCallback(() => {
    const epoch = runtime.store.getState().epoch;
    queryClient.removeQueries({ queryKey: guardedQueryKey(epoch, siteKeys.site(siteId)) });
    void queryClient.invalidateQueries({
      queryKey: guardedQueryKey(epoch, siteKeys.list),
      refetchType: "none",
    });
  }, [runtime, queryClient, siteId]);
  return { setConfig, refreshDetail, dropSite };
}
