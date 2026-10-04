import { useGuardedInfiniteQuery } from "../../security/hooks.ts";
import { MANUAL_REFRESH } from "../../security/query-client.ts";

/** Domain keys; the session epoch is prefixed by the guarded query helpers. */
export const siteKeys = {
  list: ["sites", "list"] as const,
  site: (siteId: string) => ["sites", siteId] as const,
  config: (siteId: string) => ["sites", siteId, "config"] as const,
  status: (siteId: string) => ["sites", siteId, "status"] as const,
  revisions: (siteId: string) => ["sites", siteId, "revisions"] as const,
  health: (siteId: string) => ["sites", siteId, "health"] as const,
};

/**
 * The tenant's sites, one signed-cursor page at a time. Pages are read when the operator
 * opens the list, presses refresh or asks for more; nothing polls.
 */
export function useSiteList() {
  return useGuardedInfiniteQuery({
    key: siteKeys.list,
    fetchPage: (client, signal, cursor) => client.siteList(signal, cursor),
    nextCursor: (page) => page.next_cursor,
    staleTime: MANUAL_REFRESH,
  });
}
