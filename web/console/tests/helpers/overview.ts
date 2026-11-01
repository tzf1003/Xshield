// Data for the overview spec (docs/06 6.4.2). Each builder starts from the shared fixtures and changes
// only what its warning reads, so a spec states the condition it tests and nothing else.

import type { GatewayProblem, SiteSummary, StatusResponse } from "../../src/api/types.ts";
import { sitesList, status } from "./fixtures.ts";

/** Every gateway instance online, no problem listed, and Jev healthy. */
export function healthyStatus(): StatusResponse {
  return {
    gateway: { light: "ok", edges: { online: 2, total: 3 }, problems: [] },
    jev: { ...status.jev, health: "ok", failures: {} },
  };
}

/** The healthy status with its gateway problems, or its Jev state, replaced. */
export function statusWith(changes: {
  problems?: GatewayProblem[];
  jev?: Partial<StatusResponse["jev"]>;
}): StatusResponse {
  const base = healthyStatus();
  const problems = changes.problems ?? [];
  return {
    gateway: { ...base.gateway, light: problems.length > 0 ? "warn" : "ok", problems },
    jev: { ...base.jev, ...changes.jev },
  };
}

/** Every site of the fixtures with its warning counters at zero, each in enforce mode. */
export function quietSites(): SiteSummary[] {
  return sitesList.sites.map((site) => ({
    ...site,
    mode: "enforce",
    observing_since_millis: null,
    would_block_24h: 0,
    unjudged_24h: 0,
    jev_timeouts_24h: 0,
    call_limits_24h: 0,
    suggestions: 0,
  }));
}

/** The list with one site's fields changed; the other sites are returned as they are. */
export function changeSite(
  list: SiteSummary[],
  name: string,
  changes: Partial<SiteSummary>,
): SiteSummary[] {
  return list.map((site) => (site.name === name ? { ...site, ...changes } : site));
}
