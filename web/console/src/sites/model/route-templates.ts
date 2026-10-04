import type { SiteRouteConfig } from "../../api.ts";
import { entryRoute, newRoute, type SiteConfigDraft } from "./config.ts";

export type RouteTemplate = Readonly<{
  id: string;
  title: string;
  /** Said plainly: a template is an example to adapt, not a recommendation for this site. */
  description: string;
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

export const routeTemplates: readonly RouteTemplate[] = [spaTemplate];

/** Replaces the route list with the template's routes (the entry route follows the entry fields). */
export function applyRouteTemplate(
  draft: SiteConfigDraft,
  template: RouteTemplate,
): SiteConfigDraft {
  return { ...draft, policy: { ...draft.policy, routes: template.build(draft) } };
}
