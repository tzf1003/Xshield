import type { SitePolicyConfig, SiteRouteConfig } from "../../api.ts";

/** The four approval reasons of the browser provenance flow (`FLOW_FACETS` of risk.rs). */
export type FlowToken =
  | "AUTH_ENTRY_CHANGED"
  | "SENSOR_HTML_CHANGED"
  | "PAGE_ACTIONS_CHANGED"
  | "RESOURCE_GRANT_CHANGED"
  | "QUERY_PAGINATION_CHANGED";

type Member = (policy: SitePolicyConfig, route: SiteRouteConfig) => boolean;

/**
 * Which routes take part in each facet. A facet compares its member routes whole, so a page
 * root's path or build is as much part of it as its `page_actions`, and a route can belong to
 * several facets (the list of the browser loop issues page actions and qualifies resources).
 * Shared by the approval reconstruction (risk.ts) and the diff (diff.ts), which names the facets
 * a changed route belongs to so the approval explanation can list the change under each.
 */
export const flowFacets: readonly (readonly [FlowToken, Member])[] = [
  [
    "AUTH_ENTRY_CHANGED",
    (_, route) =>
      route.security_entry === "auth_entry" ||
      route.auth_binding !== undefined ||
      route.auth_revoke !== undefined,
  ],
  [
    "SENSOR_HTML_CHANGED",
    (_, route) => route.response_mode === "SENSOR_HTML" || route.sensor_html !== undefined,
  ],
  [
    "PAGE_ACTIONS_CHANGED",
    (_, route) => route.page_actions !== undefined || route.issued_by !== undefined,
  ],
  [
    "RESOURCE_GRANT_CHANGED",
    (policy, route) =>
      route.resource_grant !== undefined ||
      policy.routes.some(
        (source) => source.resource_grant?.target_operation_id === route.operation_id,
      ),
  ],
  ["QUERY_PAGINATION_CHANGED", (_, route) => route.query_pagination !== undefined],
];

/** The facets `route` belongs to within `policy`, in facet order. */
export function routeFacets(policy: SitePolicyConfig, route: SiteRouteConfig): FlowToken[] {
  return flowFacets.filter(([, member]) => member(policy, route)).map(([token]) => token);
}
