/**
 * How the route drawer edits the browser provenance-flow blocks of one route (docs/29
 * “站点浏览器来源流程配置契约”), as pure functions so the editing rules are unit-tested and the
 * component only renders them.
 *
 * Invariants:
 * - A block is never dropped silently. The admission and the response mode are the only two
 *   controls that take blocks off a route (a block that no longer fits them cannot be served),
 *   and they park what they take in a stash that restores it when the route fits again, so a
 *   misclick costs nothing. Every other inconsistency stays on the route and is reported by
 *   validation.ts next to the block, where the operator can fix or remove it explicitly.
 * - New blocks start with bounded leases and capacities but with empty identifiers, pointers,
 *   digests and targets: those describe the operator's application and must be chosen, never
 *   guessed (validation refuses them until they are filled).
 * - Cross-route references are picked from the draft's routes, never typed.
 */
import type {
  RouteAdmission,
  SiteAuthBinding,
  SiteAuthRevoke,
  SiteIssuedBy,
  SitePageActions,
  SiteResourceGrant,
  SiteRouteConfig,
  SiteSensorHtmlAdapter,
  routeFlowKeys,
} from "../../api.ts";

export type FlowBlock = (typeof routeFlowKeys)[number];

/** Blocks an admission or response-mode switch took off the route, by block. */
export type FlowStash = Partial<Pick<SiteRouteConfig, FlowBlock>>;

type ResponseMode = SiteRouteConfig["response_mode"];

/** The blocks in the drawer's (and the diff's) words. */
export const flowBlockLabel: Readonly<Record<FlowBlock, string>> = {
  auth_binding: "身份建立",
  auth_revoke: "身份撤销",
  sensor_html: "SENSOR_HTML 页面构建",
  page_actions: "页面签发动作",
  issued_by: "由页面签发",
  resource_grant: "响应资源资格",
};

/** The item member the edge writes each issued reference into (the browser loop's spelling). */
export const DEFAULT_ACTION_REF_FIELD = "_xshield_action_ref";

/** Most approved page builds the edge accepts for one page (primary plus 15). */
export const MAX_SENSOR_BUILDS = 16;

export const emptyAuthBinding = (): SiteAuthBinding => ({
  success_status: 200,
  principal_pointer: "",
  authorization_context_pointer: "",
  bearer_pointer: "",
  credential_ttl_seconds: 1800,
  session_ttl_seconds: 3600,
});

export const emptyAuthRevoke = (): SiteAuthRevoke => ({ success_status: 200 });

/** A build whose digest and offset are still to be computed from the page. */
export const emptySensorBuild = (): SiteSensorHtmlAdapter => ({
  adapter_revision: "",
  origin_sha256: "",
  injection_offset: Number.NaN,
});

export const emptyPageActions = (): SitePageActions => ({
  mapping_revision: "",
  max_active_pages: 32,
});

export const emptyIssuedBy = (page = ""): SiteIssuedBy => ({
  page_operation_id: page,
  ttl_seconds: 600,
});

export const emptyResourceGrant = (target = ""): SiteResourceGrant => ({
  success_status: 200,
  items_pointer: "",
  resource_pointer: "",
  action_ref_field: DEFAULT_ACTION_REF_FIELD,
  target_operation_id: target,
  target_mapping_revision: "",
  ttl_seconds: 600,
  max_items: 50,
  max_active_grants: 500,
});

const routeOnly = (admission: RouteAdmission) => (route: SiteRouteConfig) =>
  route.security_entry === admission;
const notPage = (route: SiteRouteConfig) => route.response_mode !== "SENSOR_HTML";

/**
 * Where a block can be served, judged only by the two switching controls (admission and
 * response mode). The drawer offers a block's switch where it fits; a block that exists where it
 * does not fit is still shown, with validation's message, until it is fixed or removed.
 */
const fits: Readonly<Record<FlowBlock, (route: SiteRouteConfig) => boolean>> = {
  auth_binding: (route) => routeOnly("auth_entry")(route) && notPage(route),
  auth_revoke: (route) => routeOnly("authenticated_root")(route) && notPage(route),
  sensor_html: (route) => route.response_mode === "SENSOR_HTML",
  page_actions: (route) =>
    route.response_mode === "SENSOR_HTML" && routeOnly("authenticated_root")(route),
  issued_by: routeOnly("ui_action_required"),
  resource_grant: (route) =>
    (route.security_entry === "authenticated_root" ||
      route.security_entry === "ui_action_required") &&
    notPage(route),
};

export function blockFits(route: SiteRouteConfig, block: FlowBlock): boolean {
  return fits[block](route);
}

/** Whether a route binds a resource (any of its four resource fields is set). */
export const bindsResource = (route: SiteRouteConfig) =>
  [
    route.resource_type,
    route.view_profile,
    route.resource_query_parameter,
    route.resource_path_parameter,
  ].some((value) => value !== null && value !== "");

/**
 * Whether the drawer offers a block's switch: the block fits the admission and response mode,
 * and `issued_by` is not offered on a route that addresses a resource, because a page issues
 * first-hop actions only (such a route is reached through a list's resource grant instead).
 */
export function blockOffered(route: SiteRouteConfig, block: FlowBlock): boolean {
  return blockFits(route, block) && !(block === "issued_by" && bindsResource(route));
}

const blocks: readonly FlowBlock[] = [
  "auth_binding",
  "auth_revoke",
  "sensor_html",
  "page_actions",
  "issued_by",
  "resource_grant",
];

/** Sets (or, with `undefined`, removes) one block; the key disappears when removed. */
export function withBlock<K extends FlowBlock>(
  route: SiteRouteConfig,
  block: K,
  value: SiteRouteConfig[K] | undefined,
): SiteRouteConfig {
  const { [block]: _removed, ...rest } = route;
  return (value === undefined ? rest : { ...rest, [block]: value }) as SiteRouteConfig;
}

/**
 * Parks the blocks that no longer fit and restores parked blocks that fit again. `SENSOR_HTML`
 * carries its build in `sensor_html`, so that mode always gets one (an empty build if nothing
 * was parked) and validation asks for the digest and the offset.
 */
function settle(route: SiteRouteConfig, stash: FlowStash) {
  let next = route;
  const parked: FlowStash = { ...stash };
  for (const block of blocks) {
    const value = next[block];
    if (value !== undefined && !blockFits(next, block)) {
      parked[block] = value as never;
      next = withBlock(next, block, undefined);
    } else if (value === undefined && parked[block] !== undefined && blockFits(next, block)) {
      next = withBlock(next, block, parked[block]);
      delete parked[block];
    }
  }
  if (next.response_mode === "SENSOR_HTML" && next.sensor_html === undefined) {
    next = withBlock(next, "sensor_html", emptySensorBuild());
  }
  return { route: next, stash: parked };
}

/**
 * The admission radio. A UI-action route needs an operation source (a suggestion based on the
 * operation ID is filled in when there is none); every other admission has none.
 */
export function withAdmission(
  route: SiteRouteConfig,
  admission: RouteAdmission,
  stash: FlowStash,
): { route: SiteRouteConfig; stash: FlowStash } {
  const ui = admission === "ui_action_required";
  return settle(
    {
      ...route,
      security_entry: admission,
      source_action: ui ? route.source_action || `${route.operation_id || "route"}.open` : null,
    },
    stash,
  );
}

/** The response-mode radio. */
export function withResponseMode(
  route: SiteRouteConfig,
  mode: ResponseMode,
  stash: FlowStash,
): { route: SiteRouteConfig; stash: FlowStash } {
  return settle({ ...route, response_mode: mode }, stash);
}

/** Every approved build of a page, primary first (the drawer edits them as one list). */
export function sensorBuilds(route: SiteRouteConfig): SiteSensorHtmlAdapter[] {
  const sensor = route.sensor_html;
  if (!sensor) return [];
  const { additional_adapters: additional = [], ...primary } = sensor;
  return [primary, ...additional];
}

/** Writes the build list back; an empty additional list is omitted, as the server stores it. */
export function withSensorBuilds(
  route: SiteRouteConfig,
  builds: readonly SiteSensorHtmlAdapter[],
): SiteRouteConfig {
  const [primary, ...additional] = builds;
  if (!primary) return withBlock(route, "sensor_html", undefined);
  return withBlock(route, "sensor_html", {
    ...primary,
    ...(additional.length > 0 ? { additional_adapters: additional } : {}),
  });
}

export type RouteOption = Readonly<{
  value: string;
  label: string;
  /** Why choosing it will not satisfy the rule yet, or `null`. */
  note: string | null;
}>;

const describe = (route: SiteRouteConfig) =>
  `${route.operation_id} · ${route.method} ${route.path}`;

const others = (routes: readonly SiteRouteConfig[], self: number | null) =>
  routes.filter((route, index) => index !== self && route.operation_id !== "");

/**
 * The pages a UI action can be issued by: the draft's `SENSOR_HTML` routes. A page that does not
 * declare page actions yet is offered with a note, because choosing it is how an operator builds
 * the page and the action in either order; validation names what is still missing.
 */
export function pageRootOptions(
  routes: readonly SiteRouteConfig[],
  self: number | null,
): RouteOption[] {
  return others(routes, self)
    .filter((route) => route.response_mode === "SENSOR_HTML")
    .map((route) => ({
      value: route.operation_id,
      label: describe(route),
      note:
        route.page_actions === undefined
          ? "该页面还没有启用“页面签发动作”"
          : route.security_entry !== "authenticated_root"
            ? "该页面不是“已认证根”"
            : null,
    }));
}

/** The routes a list response can qualify resources for: UI-action routes bound to a resource. */
export function grantTargetOptions(
  routes: readonly SiteRouteConfig[],
  self: number | null,
): RouteOption[] {
  return others(routes, self)
    .filter(
      (route) =>
        route.security_entry === "ui_action_required" &&
        Boolean(route.resource_type) &&
        Boolean(route.source_action),
    )
    .map((route) => ({ value: route.operation_id, label: describe(route), note: null }));
}
