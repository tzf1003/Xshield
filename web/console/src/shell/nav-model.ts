import {
  canonicalWizardStep,
  type QueryKind,
  routeQueryKind,
  siteRoute,
  siteSections,
  wizardSteps,
} from "../admin-routes.ts";

/**
 * Navigation is a view aid only: hiding an entry is not authorization, the server authorizes
 * every request. The role rules below are the ones the previous shell used; the entries are
 * regrouped (Phase 0 information architecture) but keep their labels and URLs.
 */
export type IconKey =
  | "home"
  | "site"
  | "search-doc"
  | "model"
  | "agent"
  | "ledger"
  | "case"
  | "evidence"
  | "hold"
  | "export"
  | "jobs"
  | "audit"
  | "calibration"
  | "key"
  | "session";

export type NavItem = Readonly<{
  /** Stable menu key; equals the href. */
  key: string;
  href: string;
  label: string;
  /** Any one of these roles shows the entry; empty means visible to everyone. */
  roles: readonly string[];
  icon: IconKey;
  /** Extra search terms for the command palette (English names, abbreviations). */
  keywords: readonly string[];
  /** Pathname prefix that marks the entry as the current page. Defaults to `href`. */
  matchPrefix?: string;
}>;

export type NavGroup = Readonly<{ key: string; label: string; items: readonly NavItem[] }>;

const item = (
  href: string,
  label: string,
  roles: readonly string[],
  icon: IconKey,
  keywords: readonly string[] = [],
  matchPrefix?: string,
): NavItem => ({ key: href, href, label, roles, icon, keywords, matchPrefix });

const evidenceReaders = [
  "investigator",
  "sensitive_evidence_reader",
  "sensitive_evidence_approver",
] as const;

/** Every entry that can ever be shown, before role filtering. */
export const navCatalog: readonly NavGroup[] = [
  {
    key: "workbench",
    label: "工作台",
    items: [item("/", "概览", [], "home", ["workbench", "overview", "工作台", "运行概览"])],
  },
  {
    key: "sites",
    label: "站点",
    items: [
      item("/sites", "受保护站点", ["system_admin"], "site", [
        "site",
        "sites",
        "站点",
        "protected",
      ]),
    ],
  },
  {
    key: "traffic",
    label: "流量与调查",
    items: [
      item("/investigation/requests", "请求调查", ["observer", "investigator"], "search-doc", [
        "request",
        "req",
        "请求",
        "时间线",
      ]),
      item("/investigation/search", "结构化检索", ["investigator"], "search-doc", [
        "search",
        "event",
        "trace",
        "检索",
        "事件",
      ]),
      item("/investigation/grants", "资格与身份账本", ["investigator", "observer"], "ledger", [
        "grant",
        "ledger",
        "资格",
        "账本",
      ]),
      item("/investigation/bindings", "身份绑定", ["investigator", "observer"], "ledger", [
        "binding",
        "auth",
        "绑定",
      ]),
      item("/investigation/models", "模型调用列表", ["observer"], "model", [
        "model",
        "models",
        "list",
        "模型",
      ]),
      item("/investigation/models/lookup", "模型调用详情", ["observer"], "model", [
        "model",
        "mdl",
        "lookup",
        "详情",
      ]),
      item("/investigation/agents", "Agent 运行", ["observer"], "agent", ["agent", "agt", "运行"]),
    ],
  },
  {
    key: "cases",
    label: "案件与证据",
    items: [
      item("/cases", "案件工作台", ["investigator"], "case", ["case", "cases", "案件"]),
      item("/evidence/access", "证据访问", evidenceReaders, "evidence", [
        "evidence",
        "access",
        "artifact",
        "证据",
        "访问",
      ]),
      item("/evidence/holds", "证据保留", ["audit_administrator"], "hold", [
        "hold",
        "retention",
        "保留",
      ]),
      item("/evidence/exports", "调查导出", evidenceReaders, "export", [
        "export",
        "download",
        "导出",
      ]),
    ],
  },
  {
    key: "operations",
    label: "运维与治理",
    items: [
      item("/operations/jobs", "运行状态", ["investigator"], "jobs", [
        "job",
        "jobs",
        "task",
        "任务",
        "后台",
      ]),
      item("/operations/audit", "审计发布状态", ["audit_administrator"], "audit", [
        "audit",
        "health",
        "审计",
        "发布",
      ]),
      item("/investigation/calibration", "校准报告", ["audit_administrator"], "calibration", [
        "calibration",
        "calr",
        "校准",
      ]),
      item("/admin/api-keys", "API Key", ["system_admin", "key_administrator"], "key", [
        "api",
        "key",
        "token",
        "密钥",
      ]),
      item("/access/session", "权限中心", [], "session", [
        "session",
        "role",
        "permission",
        "权限",
        "会话",
      ]),
    ],
  },
];

/** `null` roles is the explicit local machine-login mode: everything is offered. */
export function isVisible(roles: readonly string[] | null, required: readonly string[]): boolean {
  if (required.length === 0 || roles === null) return true;
  return required.some((role) => roles.includes(role));
}

export const releaseRoles = ["policy_author", "policy_approver", "release_operator"] as const;

/** Per-site entries for operators who are not system administrators (scoped to the session site). */
export function siteEntries(roles: readonly string[] | null, siteId: string | null): NavItem[] {
  if (roles === null || roles.includes("system_admin") || siteId === null) return [];
  const entries: NavItem[] = [];
  if (roles.includes("observer")) {
    entries.push(
      item(
        `/sites/${siteId}/overview`,
        "站点状态",
        [],
        "site",
        ["site", "status", "站点"],
        `/sites/${siteId}/overview`,
      ),
    );
  }
  if (roles.some((role) => (releaseRoles as readonly string[]).includes(role))) {
    entries.push(
      item(
        `/sites/${siteId}/releases`,
        "站点发布",
        [],
        "site",
        ["release", "publish", "发布"],
        `/sites/${siteId}/releases`,
      ),
    );
  }
  return entries;
}

/** The groups this operator may see; empty groups disappear. */
export function visibleNav(roles: readonly string[] | null, siteId: string | null): NavGroup[] {
  return navCatalog
    .map((group) => {
      const items = group.items.filter((entry) => isVisible(roles, entry.roles));
      const injected = group.key === "sites" ? siteEntries(roles, siteId) : [];
      return { ...group, items: [...items, ...injected] };
    })
    .filter((group) => group.items.length > 0);
}

export function flattenNav(groups: readonly NavGroup[]): NavItem[] {
  return groups.flatMap((group) => group.items);
}

/** Longest matching entry wins, so `/investigation/models/lookup` beats `/investigation/models`. */
export function activeItem(pathname: string, items: readonly NavItem[]): NavItem | null {
  let best: NavItem | null = null;
  let bestLength = -1;
  for (const entry of items) {
    const prefix = entry.matchPrefix ?? entry.href;
    const matches =
      entry.href === "/"
        ? pathname === "/"
        : pathname === prefix || pathname.startsWith(`${prefix}/`);
    if (matches && prefix.length > bestLength) {
      best = entry;
      bestLength = prefix.length;
    }
  }
  return best;
}

export type PageMeta = Readonly<{ kind: QueryKind; title: string; lead: string }>;

const titles: Record<QueryKind, string> = {
  overview: "运行概览",
  session: "权限中心",
  request: "请求调查",
  model: "模型调用调查",
  agent: "Agent 运行调查",
  "model-list": "模型调用列表",
  "audit-health": "审计发布状态",
  "calibration-report": "校准报告调查",
  grant: "资格调查",
  binding: "身份绑定调查",
  search: "结构化事件检索",
  case: "案件工作台",
  access: "证据访问",
  hold: "证据保留",
  export: "调查导出",
  "site-list": "受保护站点",
  "site-config": "受保护站点",
  "api-keys": "管理 API Key",
  jobs: "后台任务",
  "not-found": "页面不存在",
};

const leads: Record<QueryKind, string> = {
  overview: "查看当前管理范围内的站点、审计和调查服务状态。",
  session: "查看当前主体、角色、站点范围和再认证状态。",
  request: "沿着请求时间线，核对每一次判定与证据。",
  model: "核对模型调用生命周期、版本与证据引用。",
  agent: "核对 Agent 脱敏生命周期与固定事件引用。",
  "model-list": "在固定 UTC 时间窗内分页发现模型调用；点击条目会重新读取详情并重新鉴权。",
  "audit-health": "按需读取配置审计日志到索引的发布快照。",
  "calibration-report": "读取受限校准报告的冻结元数据与正文保留观察。",
  grant: "核对当前账本的状态、代际与期限。",
  binding: "核对当前账本的状态、代际与期限。",
  search: "按时间与事件字段检索，核对直接引用的历史事实。",
  case: "建立本人调查案件，核对证据引用与案件状态。",
  access: "复核访问申请，通过独立审批后按需下载证据原文。",
  hold: "管理案件证据保留期限，核对创建与释放历史。",
  export: "申请经独立审批的案件与目录元数据包；下载需重新验证。",
  "site-list": "查看受保护站点的发布状态，搜索、筛选并进入站点配置与发布。",
  "site-config": "配置受保护网站、上游、安全入口与反向代理监听端口。",
  "api-keys": "创建和撤销绑定 tenant、site 与能力集合的 Agent API Key。",
  jobs: "按任务 ID 读取后台任务的当前状态与原因码。",
  "not-found": "",
};

export function pageMeta(pathname: string): PageMeta {
  const kind = routeQueryKind(pathname);
  return { kind, title: titles[kind], lead: leads[kind] };
}

/** Kinds whose content is still rendered by the legacy host rather than a routed page. */
export const legacyKinds: ReadonlySet<QueryKind> = new Set<QueryKind>([
  "request",
  "model",
  "agent",
  "model-list",
  "audit-health",
  "calibration-report",
  "grant",
  "binding",
  "search",
  "case",
  "access",
  "hold",
  "export",
  "api-keys",
  "jobs",
]);

export type Crumb = Readonly<{ label: string; href?: string }>;

/** Group > page, or site > section for per-site pages. */
export function breadcrumbs(pathname: string, groups: readonly NavGroup[]): Crumb[] {
  const meta = pageMeta(pathname);
  const site = siteRoute(pathname);
  if (site) {
    const section = site.creating
      ? (wizardSteps.find(([part]) => part === canonicalWizardStep(site.section))?.[1] ??
        site.section)
      : (siteSections.find(([part]) => part === site.section)?.[1] ?? site.section);
    return [
      { label: "站点" },
      site.creating
        ? { label: "新建站点" }
        : { label: site.siteId, href: `/sites/${site.siteId}/overview` },
      { label: section },
    ];
  }
  const current = activeItem(pathname, flattenNav(groups));
  const group = current ? groups.find((entry) => entry.items.includes(current)) : undefined;
  const trail: Crumb[] = [];
  if (group && group.key !== "workbench") trail.push({ label: group.label });
  trail.push({ label: meta.title });
  return trail;
}
