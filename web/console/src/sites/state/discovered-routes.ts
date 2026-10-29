import {
  type DiscoveredRoutesPlan,
  type DiscoveredRoutesResponse,
  validateDiscoveredRoutesPlan,
} from "../../api.ts";
import { useGuardedQuery } from "../../security/hooks.ts";
import { MANUAL_REFRESH } from "../../security/query-client.ts";
import type { UtcWindow } from "../../ui/time-range.ts";

export const DISCOVERED_ROUTES_PAGE_SIZES = [25, 50, 100, 200] as const;

/** Builds a validated plan for one submission; the validator is the single gate. */
export function buildDiscoveredRoutesPlan(window: UtcWindow, limit: number): DiscoveredRoutesPlan {
  return validateDiscoveredRoutesPlan({ ...window, limit });
}

/**
 * Discover one site's unmatched `(method, path_template)` groups. The read is manual: it only
 * runs once a plan has been submitted (`nonce` changes), because every call is an audited server
 * query, never a background poll. There is no cursor: a new submission replaces the page whole.
 */
export function useDiscoveredRoutes(
  siteId: string,
  plan: DiscoveredRoutesPlan | null,
  nonce: number,
) {
  return useGuardedQuery<DiscoveredRoutesResponse>({
    key: ["sites", siteId, "discovered-routes", nonce, plan?.start, plan?.end, plan?.limit],
    enabled: plan !== null,
    expectedSiteId: siteId,
    staleTime: MANUAL_REFRESH,
    fetch: (client, signal) => client.discoveredRoutes(siteId, plan, signal),
  });
}
