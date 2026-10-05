/**
 * "待我处理": what the workbench asks of this operator, merged from independent sources with the
 * approval center's model (`work/inbox.ts`): the site list (failed applies and revisions awaiting
 * approval), the evidence-access and export review queues, and the writes of this session whose
 * outcome is not known. Unknown writes and failed applies come first, then everything else newest
 * first. Pure; the page decides which sources its roles read.
 */
import type { SiteListItem } from "../api.ts";
import type { AccessList } from "../evidence-access.ts";
import type { ExportList } from "../exports.ts";
import type { OperationSnapshot } from "../security/pending-operations.ts";
import { reasonText } from "../ui/reason-codes.ts";
import {
  accessInboxItem,
  exportInboxItem,
  mergeInbox,
  siteInboxItem,
  siteNeedsApproval,
} from "../work/inbox.ts";
import { operationHome } from "./operation-home.ts";

export type TodoKind = "write" | "failed" | "site" | "access" | "export";

export type TodoItem = Readonly<{
  key: string;
  kind: TodoKind;
  /** Site, access request or export ID; the operation ID of a write. */
  id: string;
  title: string;
  detail: string;
  /** Who asked, when the source says. */
  requester: string | null;
  at: string | null;
  atMs: number;
  /** Where the item is handled; `null` when no page owns it. */
  href: string | null;
  search?: Readonly<Record<string, string>>;
  /** Writes only: the frozen request, for the exact retry. */
  operation?: OperationSnapshot;
}>;

/** Which sources this operator's roles read. `null` roles (machine login) read everything. */
export function todoSources(roles: readonly string[] | null): { sites: boolean; review: boolean } {
  const has = (role: string) => roles === null || roles.includes(role);
  return {
    // The server lets only SystemAdmin read the list; the others get a role hint from the 403.
    sites: has("system_admin") || has("policy_approver") || has("observer"),
    review: has("sensitive_evidence_approver"),
  };
}

export function siteTodos(sites: readonly SiteListItem[]): TodoItem[] {
  const items: TodoItem[] = [];
  for (const site of sites) {
    const href = `/sites/${site.site_id}/releases`;
    if (site.apply_state === "failed") {
      // A failed apply is the more urgent of the two; one row per site.
      const reason = reasonText(site.reason_code);
      items.push({
        key: `failed:${site.site_id}`,
        kind: "failed",
        id: site.site_id,
        title: `应用失败：${site.display_name}`,
        detail: `${reason.text}${siteNeedsApproval(site) ? " 该站点同时在等待审批。" : ""}`,
        requester: site.updated_by,
        at: site.updated_at,
        atMs: Date.parse(site.updated_at),
        href,
      });
    } else if (siteNeedsApproval(site)) {
      const inbox = siteInboxItem(site);
      items.push({
        key: inbox.key,
        kind: "site",
        id: site.site_id,
        title: `待审批修订：${site.display_name}`,
        detail: `${inbox.detail} · 在站点发布页审阅差异后批准`,
        requester: inbox.requester,
        at: inbox.at,
        atMs: inbox.atMs,
        href,
      });
    }
  }
  return items;
}

export function accessTodos(page: AccessList): TodoItem[] {
  return page.items.map((row) => {
    const inbox = accessInboxItem(row);
    return {
      key: inbox.key,
      kind: "access" as const,
      id: inbox.id,
      title: "原文访问申请待审批",
      detail: `案件 ${inbox.target} · 证据 ${inbox.detail}`,
      requester: inbox.requester,
      at: inbox.at,
      atMs: inbox.atMs,
      href: "/approvals",
      search: { item: inbox.id },
    };
  });
}

export function exportTodos(page: ExportList): TodoItem[] {
  return page.items.map((row) => {
    const inbox = exportInboxItem(row);
    return {
      key: inbox.key,
      kind: "export" as const,
      id: inbox.id,
      title: "导出申请待审批",
      detail: `案件 ${inbox.target}`,
      requester: inbox.requester,
      at: inbox.at,
      atMs: inbox.atMs,
      href: "/approvals",
      search: { item: inbox.id },
    };
  });
}

const phaseTitles: Record<OperationSnapshot["phase"], string> = {
  unknown: "结果未知",
  step_up: "等待再认证",
  inflight: "请求中",
};

export function writeTodos(operations: readonly OperationSnapshot[]): TodoItem[] {
  return operations.map((operation) => {
    const home = operationHome(operation);
    return {
      key: `write:${operation.id}`,
      kind: "write" as const,
      id: operation.id,
      title: `${phaseTitles[operation.phase]}：${operation.label}`,
      detail: `${operation.method} ${operation.path} · 幂等键 ${operation.idempotencyKey}`,
      requester: null,
      at: new Date(operation.createdAt).toISOString(),
      atMs: operation.createdAt,
      href: home?.to ?? null,
      ...(home?.search ? { search: home.search } : {}),
      operation,
    };
  });
}

const rank: Record<TodoKind, number> = { write: 0, failed: 1, site: 2, access: 2, export: 2 };

/** Urgent kinds first; within a rank the approval center's order (newest first, then key). */
export function orderTodos(...groups: readonly (readonly TodoItem[])[]): TodoItem[] {
  // Array.prototype.sort is stable, so the merge order survives inside each rank.
  return mergeInbox(...groups).sort((left, right) => rank[left.kind] - rank[right.kind]);
}
