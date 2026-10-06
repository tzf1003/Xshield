import type { SiteRouteConfig } from "../../api.ts";
import { entryRoute, newRoute, type SiteConfigDraft } from "./config.ts";
import { DEFAULT_ACTION_REF_FIELD, emptySensorBuild } from "./route-flow.ts";

export type RouteTemplate = Readonly<{
  id: string;
  title: string;
  /** Said plainly: a template is an example to adapt, not a recommendation for this site. */
  description: string;
  /**
   * The template serves `SENSOR_HTML` pages, which the edge only injects into when the site's
   * browser sensor is on; applying it turns the sensor on, and the picker says so.
   */
  requiresSensor?: boolean;
  build: (draft: Pick<SiteConfigDraft, "entry_path" | "security_entry">) => SiteRouteConfig[];
}>;

/**
 * A typical single-page application: the page itself, a list, a detail read bound to a
 * resource ID in the path, and a write. Routes here are exact paths (the edge has no prefix
 * rules), so "API" means these representative endpoints; the operator renames and extends them.
 */
export const spaTemplate: RouteTemplate = {
  id: "spa-api",
  title: "单页应用入口 + API 示例",
  description:
    "示例，不是推荐：入口页面、一个列表接口、一个按资源 ID 读取的详情接口和一个写入接口。请把路径和操作 ID 改成你站点真实的接口。",
  build: (draft) => [
    entryRoute(draft),
    newRoute({
      operation_id: "api.items.list",
      method: "GET",
      path: "/api/items",
      security_entry: "authenticated_root",
    }),
    newRoute({
      operation_id: "api.items.get",
      method: "GET",
      path: "/api/items/{item_id}",
      security_entry: "ui_action_required",
      source_action: "api.items.open",
      resource_type: "item",
      view_profile: "default",
      resource_path_parameter: "item_id",
      response_mode: "BUFFERED_JSON",
    }),
    newRoute({
      operation_id: "api.items.create",
      method: "POST",
      path: "/api/items",
      security_entry: "authenticated_root",
    }),
  ],
};

/**
 * The browser UI-action provenance loop of docs/05 §5.3.1, route for route the topology of
 * scripts/test_browser_loop.sh (tests/site-config/browser-loop.json): a public login page, a
 * login API that establishes identity, an authenticated page that injects the sensor and issues
 * the list action, the list that qualifies each order for the detail action, the detail read by
 * path parameter, and a logout that revokes identity.
 *
 * The page build's digest and `</head>` offset are deliberately left empty: they pin the exact
 * bytes of the operator's own page, so validation blocks saving until they are computed from
 * that page (the drawer's “从页面源码计算”). Everything else is a placeholder to rename.
 */
export const browserLoopTemplate: RouteTemplate = {
  id: "browser-provenance-loop",
  title: "浏览器来源闭环（登录 → 页面 → 列表 → 详情）",
  description:
    "示例，用来改写：公开的登录页、建立身份的登录接口（认证入口）、注入探针并签发列表动作的应用页面（SENSOR_HTML）、为每个订单签发详情资格的列表、按路径参数读取的详情，以及撤销身份的登出。应用页面的摘要与注入偏移留空：在“应用页面”路由里用“从页面源码计算”填好后才能保存。",
  requiresSensor: true,
  build: () => [
    newRoute({ operation_id: "login.page", method: "GET", path: "/" }),
    newRoute({
      operation_id: "auth.login",
      method: "POST",
      path: "/api/login",
      security_entry: "auth_entry",
      response_mode: "BUFFERED_JSON",
      max_response_bytes: 1024,
      auth_binding: {
        success_status: 200,
        principal_pointer: "/identity/id",
        authorization_context_pointer: "/identity/authorization_context",
        bearer_pointer: "/access_token",
        credential_ttl_seconds: 1800,
        session_ttl_seconds: 3600,
      },
    }),
    newRoute({
      operation_id: "app.page",
      method: "GET",
      path: "/app",
      security_entry: "authenticated_root",
      response_mode: "SENSOR_HTML",
      max_response_bytes: 16_384,
      sensor_html: { ...emptySensorBuild(), adapter_revision: "app-r1" },
      page_actions: { mapping_revision: "app-map-r1", max_active_pages: 32 },
    }),
    newRoute({
      operation_id: "orders.list",
      method: "GET",
      path: "/orders",
      security_entry: "ui_action_required",
      source_action: "app.orders.list",
      response_mode: "BUFFERED_JSON",
      max_response_bytes: 4096,
      issued_by: { page_operation_id: "app.page", ttl_seconds: 600 },
      resource_grant: {
        success_status: 200,
        items_pointer: "/orders",
        resource_pointer: "/id",
        action_ref_field: DEFAULT_ACTION_REF_FIELD,
        target_operation_id: "orders.read",
        target_mapping_revision: "orders-map-r1",
        ttl_seconds: 600,
        max_items: 10,
        max_active_grants: 200,
      },
    }),
    newRoute({
      operation_id: "orders.read",
      method: "GET",
      path: "/orders/{order_id}",
      security_entry: "ui_action_required",
      source_action: "orders.open",
      resource_type: "order",
      view_profile: "customer_detail",
      resource_path_parameter: "order_id",
    }),
    newRoute({
      operation_id: "auth.logout",
      method: "POST",
      path: "/api/logout",
      security_entry: "authenticated_root",
      response_mode: "BUFFERED_JSON",
      max_response_bytes: 256,
      auth_revoke: { success_status: 200 },
    }),
  ],
};

export const routeTemplates: readonly RouteTemplate[] = [spaTemplate, browserLoopTemplate];

/**
 * Replaces the route list with the template's routes (the entry route follows the entry fields)
 * and, for a template with `SENSOR_HTML` pages, turns the browser sensor on. Nothing else of the
 * draft changes; both edits show in the change bar and the diff like any other.
 */
export function applyRouteTemplate(
  draft: SiteConfigDraft,
  template: RouteTemplate,
): SiteConfigDraft {
  return {
    ...draft,
    ...(template.requiresSensor ? { sensor_enabled: true } : {}),
    policy: { ...draft.policy, routes: template.build(draft) },
  };
}
