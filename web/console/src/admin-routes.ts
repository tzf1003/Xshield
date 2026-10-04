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

/** The steps of /sites/new/{step}, in order. */
export const wizardSteps = [
  ["basics", "基本信息"],
  ["upstream", "上游与监听"],
  ["entry", "入口与模式"],
  ["routes", "首批路由"],
  ["review", "校验与保存"],
] as const;
export type WizardStep = (typeof wizardSteps)[number][0];

/** Before the wizard, a new site was created inside the section pages; those addresses still resolve. */
const wizardAliases: Readonly<Record<string, WizardStep>> = {
  overview: "basics",
  network: "basics",
  "security-entry": "entry",
  routes: "routes",
  identity: "review",
  crypto: "review",
  "waf-limits": "review",
  policies: "review",
  releases: "basics",
  audit: "basics",
};

/** The wizard step a slug names, or the step an older section address now lives in. */
export function canonicalWizardStep(part: string): WizardStep | null {
  if (wizardSteps.some(([key]) => key === part)) return part as WizardStep;
  return Object.hasOwn(wizardAliases, part) ? (wizardAliases[part] ?? null) : null;
}
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
  | "site-list"
  | "site-config"
  | "api-keys"
  | "jobs"
  | "not-found";
const paths: Record<string, QueryKind> = {
  "/": "overview",
  "/access/session": "session",
  "/sites": "site-list",
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
  request:
    /^\/investigation\/requests\/(req_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/,
  model:
    /^\/investigation\/models\/(mdl_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/,
  agent:
    /^\/investigation\/agents\/(agt_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/,
  grant:
    /^\/investigation\/grants\/(grant_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/,
  binding:
    /^\/investigation\/bindings\/(auth_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/,
  "calibration-report":
    /^\/investigation\/calibration\/(calr_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/,
};
export function siteRoute(
  pathname: string,
): { siteId: string; section: string; creating: boolean } | null {
  const match = /^\/sites\/([A-Za-z0-9_.-]{1,128})\/([a-z-]+)$/.exec(pathname);
  if (!match?.[1] || !match[2]) return null;
  // `new` is the wizard, whose steps (and the section names it replaced) are not site sections.
  if (match[1] === "new") {
    return canonicalWizardStep(match[2]) === null
      ? null
      : { siteId: "new", section: match[2], creating: true };
  }
  if (!siteSections.some(([part]) => part === match[2])) return null;
  return { siteId: match[1], section: match[2], creating: false };
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
