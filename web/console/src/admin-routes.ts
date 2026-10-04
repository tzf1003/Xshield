/** Browser paths select views only; every API independently authorizes its scope. */
export const siteSections = [
  ["overview", "概览"],
  ["network", "网络"],
  ["security-entry", "安全入口"],
  ["routes", "路由与操作"],
  ["identity", "身份"],
  ["crypto", "加密"],
  ["waf-limits", "WAF 与限流"],
  ["policies", "策略与健康"],
  ["releases", "发布"],
  ["audit", "审计"],
] as const;
export type SiteSection = (typeof siteSections)[number][0];
export type QueryKind =
  | "overview"
  | "session"
  | "request"
  | "model"
  | "agent"
  | "model-list"
  | "audit-health"
  | "calibration-report"
  | "grant"
  | "binding"
  | "search"
  | "case"
  | "access"
  | "hold"
  | "export"
  | "site-config"
  | "api-keys"
  | "jobs"
  | "not-found";
const paths: Record<string, QueryKind> = {
  "/": "overview",
  "/access/session": "session",
  "/sites": "site-config",
  "/admin/api-keys": "api-keys",
  "/investigation/requests": "request",
  "/investigation/models": "model-list",
  "/investigation/models/lookup": "model",
  "/investigation/agents": "agent",
  "/investigation/grants": "grant",
  "/investigation/bindings": "binding",
  "/investigation/calibration": "calibration-report",
  "/investigation/search": "search",
  "/cases": "case",
  "/evidence/access": "access",
  "/evidence/holds": "hold",
  "/evidence/exports": "export",
  "/operations/audit": "audit-health",
  "/operations/jobs": "jobs",
};
const targets: Partial<Record<QueryKind, RegExp>> = {
  request: new RegExp(
    "^/investigation/requests/(req_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$",
  ),
  model: new RegExp(
    "^/investigation/models/(mdl_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$",
  ),
  agent: new RegExp(
    "^/investigation/agents/(agt_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$",
  ),
  grant: new RegExp(
    "^/investigation/grants/(grant_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$",
  ),
  binding: new RegExp(
    "^/investigation/bindings/(auth_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$",
  ),
  "calibration-report": new RegExp(
    "^/investigation/calibration/(calr_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$",
  ),
};
export function siteRoute(
  pathname: string,
): { siteId: string; section: SiteSection; creating: boolean } | null {
  const match = new RegExp("^/sites/([A-Za-z0-9_.-]{1,128})/([a-z-]+)$").exec(pathname);
  if (!match?.[1] || !siteSections.some(([part]) => part === match[2])) return null;
  return { siteId: match[1], section: match[2] as SiteSection, creating: match[1] === "new" };
}
export function routeTarget(pathname: string, kind: QueryKind): string | null {
  return targets[kind]?.exec(pathname)?.[1] ?? null;
}
export function routeQueryKind(pathname: string): QueryKind {
  if (Object.hasOwn(paths, pathname)) return paths[pathname] ?? "not-found";
  if (siteRoute(pathname)) return "site-config";
  for (const kind of Object.keys(targets) as QueryKind[])
    if (routeTarget(pathname, kind)) return kind;
  return "not-found";
}
