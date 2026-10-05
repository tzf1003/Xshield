/**
 * What each server role lets a person do, in one line, and the console pages it unlocks. The
 * pages come from the navigation catalogue itself, so this never drifts from what the sidebar
 * offers. A page being listed is a convenience, not authorization: the server decides each call.
 */
import { flattenNav, navCatalog, releaseRoles, visibleNav } from "../shell/nav-model.ts";

/** The server role names as the product documents them. */
export const roleNames: Readonly<Record<string, string>> = {
  observer: "Observer",
  investigator: "Investigator",
  sensitive_evidence_reader: "SensitiveEvidenceReader",
  sensitive_evidence_approver: "SensitiveEvidenceApprover",
  policy_author: "PolicyAuthor",
  policy_approver: "PolicyApprover",
  release_operator: "ReleaseOperator",
  audit_administrator: "AuditAdministrator",
  key_administrator: "KeyAdministrator",
  system_admin: "SystemAdmin",
};

export const roleName = (role: string): string => roleNames[role] ?? role;

export type RolePage = Readonly<{ label: string; href: string }>;
export type RoleView = Readonly<{
  role: string;
  name: string;
  summary: string;
  pages: readonly RolePage[];
}>;

const summaries: Readonly<Record<string, string>> = {
  observer:
    "只读查看脱敏摘要：请求调查、资格与身份账本、模型调用与 Agent 运行，以及当前站点的状态、健康与修订。",
  investigator: "执行受限的结构化检索，管理本人的案件，申请原文访问与导出，查看本人的任务。",
  sensitive_evidence_reader:
    "在独立批准的短时期限内下载本人申请的原文；每次下载都要两分钟内的 MFA 再认证。",
  sensitive_evidence_approver:
    "批准或拒绝他人提交的原文访问与导出申请；不能处理自己的申请，决定需要 MFA 再认证。",
  policy_author: "对站点已保存的配置执行服务端校验。",
  policy_approver: "独立批准需要审批的站点修订并触发应用；不能批准自己提交的修订。",
  release_operator: "应用站点的期望修订，或回滚到先前生效过的修订（回滚会创建新修订）。",
  audit_administrator: "读取审计发布状态与校准报告，按案件 ID 创建和释放证据保留锁。",
  key_administrator: "查看、撤销和轮换 Agent API Key；签发带权限的 Key 还需要对应的站点角色。",
  system_admin:
    "管理受保护站点（列表、新建、配置、删除）与 Agent API Key；不会因此获得原文读取等调查权限。",
};

/** Where an operator usually goes next from the workbench, most action-bearing first. */
const quickOrder: readonly string[] = [
  "/approvals",
  "/cases",
  "/investigation/search",
  "/investigation/requests",
  "/sites",
  "/operations/audit",
  "/admin/api-keys",
  "/operations/jobs",
];

/**
 * The workbench's quick links: the pages this operator's roles show in the navigation, the most
 * action-bearing first, at most `limit`. The per-site entries of non-administrators come first,
 * because the site list is not theirs to open.
 */
export function quickLinks(
  roles: readonly string[] | null,
  siteId: string | null,
  limit = 6,
): RolePage[] {
  const visible = flattenNav(visibleNav(roles, siteId));
  const site = visible.filter((item) => item.href.startsWith("/sites/"));
  const ranked = quickOrder.flatMap((href) => visible.filter((item) => item.href === href));
  return [...site, ...ranked]
    .slice(0, limit)
    .map((item) => ({ label: item.label, href: item.href }));
}

export function roleView(role: string, siteId: string | null): RoleView {
  const pages: RolePage[] = [];
  for (const group of navCatalog) {
    for (const item of group.items) {
      // Entries open to everyone (overview, the session page) are not unlocked by any one role.
      if (item.roles.includes(role)) pages.push({ label: item.label, href: item.href });
    }
  }
  if (siteId !== null && role === "observer") {
    pages.push({ label: "站点状态", href: `/sites/${siteId}/overview` });
  }
  if (siteId !== null && (releaseRoles as readonly string[]).includes(role)) {
    pages.push({ label: "站点发布", href: `/sites/${siteId}/releases` });
  }
  return {
    role,
    name: roleName(role),
    summary: summaries[role] ?? "控制台尚未收录这个角色的说明；服务端仍按它授权。",
    pages,
  };
}
