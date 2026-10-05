import { Alert, Button } from "antd";
import type { WorkbenchOverviewResponse } from "../../api.ts";
import { deriveKpis, siteProjection } from "../../operations/kpis.ts";
import { RoleHint } from "../../operations/Parts";
import { type SourceState, sourceOf } from "../../operations/sources.ts";
import {
  accessTodos,
  exportTodos,
  orderTodos,
  siteTodos,
  todoSources,
  writeTodos,
} from "../../operations/todo.ts";
import { useGuardedQuery, usePendingOperations } from "../../security/hooks";
import { MANUAL_REFRESH } from "../../security/query-client.ts";
import { useSession } from "../../security/SessionProvider";
import { PageActions } from "../../shell/page-actions";
import { TimeStamp } from "../../ui/TimeStamp";
import { ErrorNotice } from "../../work/Parts";
import { specs } from "../../work/queries.ts";
import { useRoles } from "../../work/roles.ts";
import { KpiStrip } from "./KpiStrip";
import { SiteHealthCard } from "./SiteHealthCard";
import { AuditCard, DeniedCard, QuickLinks } from "./SideCards";
import { TodoCard, type TodoSource } from "./TodoCard";
import "../../operations/operations.css";
import "./workbench.css";

export const overviewKey = ["workbench", "overview"] as const;

/** Why a snapshot the server marked partial (or unavailable) is incomplete, as far as it is known. */
function completenessReasons(
  overview: WorkbenchOverviewResponse,
  roles: readonly string[] | null,
  sites: Parameters<typeof siteProjection>[2],
): string[] {
  const reasons: string[] = [];
  const projection = siteProjection(overview, roles, sites);
  if (!projection.projected) reasons.push(projection.reason);
  if (overview.sites.length >= 128) {
    reasons.push("站点数达到单次快照上限 128，可能还有站点没有列出。");
  }
  if (overview.audit.source_state !== "available") {
    reasons.push(
      roles !== null && !roles.includes("audit_administrator")
        ? "审计发布观察只对 AuditAdministrator 读取，快照不包含它。"
        : "快照没有包含审计发布观察：当前身份没有 AuditAdministrator，或该角色的读取失败。",
    );
  }
  if (reasons.length === 0) {
    reasons.push(
      "服务端把这份快照标为部分结果，例如上游健康观察读取失败；各来源的状态已在各自位置标明。",
    );
  }
  return reasons;
}

function SnapshotNotice({
  overview,
  roles,
  sites,
  onRetry,
  retrying,
}: {
  overview: SourceState<WorkbenchOverviewResponse>;
  roles: readonly string[] | null;
  sites: Parameters<typeof siteProjection>[2];
  onRetry: () => void;
  retrying: boolean;
}) {
  if (overview.status === "denied") {
    return (
      <RoleHint title="工作台快照被服务端拒绝">
        读取快照需要 Observer、Investigator、AuditAdministrator 或 SystemAdmin
        之一；下面的待办来源各自独立读取。
      </RoleHint>
    );
  }
  if (overview.status === "failed") {
    return (
      <ErrorNotice
        error={overview.error}
        title="工作台快照读取失败"
        action={
          <Button size="small" loading={retrying} onClick={onRetry}>
            重试
          </Button>
        }
      />
    );
  }
  if (overview.status !== "ok" || overview.data.completeness === "complete") return null;
  const unavailable = overview.data.completeness === "unavailable";
  return (
    <Alert
      type={unavailable ? "warning" : "info"}
      showIcon
      title={unavailable ? "快照不可用" : "这份快照是部分结果"}
      description={
        <ul className="xs-wb-reasons">
          {completenessReasons(overview.data, roles, sites).map((reason) => (
            <li key={reason}>{reason}</li>
          ))}
        </ul>
      }
    />
  );
}

/**
 * The landing page: what needs this operator and whether anything is on fire. It opens with one
 * workbench snapshot read plus the "待我处理" sources this operator's roles read, each failing on
 * its own. Nothing refreshes by itself: every read is audited server-side, so the page reads on
 * arrival and when the operator presses a refresh button, never on a timer or on focus.
 */
export function Workbench() {
  const { roles } = useRoles();
  const { state } = useSession();
  const siteId = state.session?.site_id ?? null;
  const plan = todoSources(roles);
  const overviewQuery = useGuardedQuery({
    key: overviewKey,
    staleTime: MANUAL_REFRESH,
    fetch: (client, signal) => client.workbenchOverview(signal),
  });
  const sitesQuery = useGuardedQuery(specs.siteApprovals(plan.sites));
  const accessQuery = useGuardedQuery(specs.accessList("review", undefined, plan.review));
  const exportQuery = useGuardedQuery(specs.exportList("review", undefined, plan.review));
  const pending = usePendingOperations();

  const overview = sourceOf(overviewQuery, true);
  const sites = sourceOf(sitesQuery, plan.sites);
  const access = sourceOf(accessQuery, plan.review);
  const exports = sourceOf(exportQuery, plan.review);
  const kpis = deriveKpis({ overview, sites, roles });
  const investigator = roles === null || roles.includes("investigator");

  const items = orderTodos(
    writeTodos(pending),
    sites.status === "ok" ? siteTodos(sites.data.sites) : [],
    access.status === "ok" ? accessTodos(access.data) : [],
    exports.status === "ok" ? exportTodos(exports.data) : [],
  );
  const sources: TodoSource[] = [
    {
      key: "sites",
      label: "站点清单",
      state: sites,
      deniedHint:
        "失败的应用和待审批修订来自站点清单，服务端只允许 SystemAdmin 读取；它们不在下面的列表里。",
      count: sites.status === "ok" ? siteTodos(sites.data.sites).length : 0,
      more: sites.status === "ok" && sites.data.truncated,
      retry: () => void sitesQuery.refetch(),
      busy: sitesQuery.isFetching,
    },
    {
      key: "access",
      label: "原文访问待办",
      state: access,
      deniedHint: "原文访问待办需要 SensitiveEvidenceApprover。",
      count: access.status === "ok" ? access.data.items.length : 0,
      more: access.status === "ok" && access.data.truncated,
      retry: () => void accessQuery.refetch(),
      busy: accessQuery.isFetching,
    },
    {
      key: "exports",
      label: "导出待办",
      state: exports,
      deniedHint: "导出待办需要 SensitiveEvidenceApprover。",
      count: exports.status === "ok" ? exports.data.items.length : 0,
      more: exports.status === "ok" && exports.data.truncated,
      retry: () => void exportQuery.refetch(),
      busy: exportQuery.isFetching,
    },
  ];

  function refreshTodos() {
    void Promise.allSettled([
      plan.sites ? sitesQuery.refetch() : undefined,
      plan.review ? accessQuery.refetch() : undefined,
      plan.review ? exportQuery.refetch() : undefined,
    ]);
  }

  return (
    <div className="xs-wb">
      {overview.status === "ok" && (
        <PageActions>
          <span className="xs-observed">
            快照观察于 <TimeStamp value={overview.data.as_of} compact />
          </span>
        </PageActions>
      )}
      <KpiStrip kpis={kpis} />
      <SnapshotNotice
        overview={overview}
        roles={roles}
        sites={sites}
        onRetry={() => void overviewQuery.refetch()}
        retrying={overviewQuery.isFetching}
      />
      <div className="xs-wb-grid">
        <div className="xs-wb-column">
          <TodoCard items={items} sources={sources} onRefresh={refreshTodos} />
          <SiteHealthCard
            overview={overview}
            sites={sites}
            roles={roles}
            sessionSiteId={siteId}
            onRefresh={() => void overviewQuery.refetch()}
            refreshing={overviewQuery.isFetching}
          />
        </div>
        <div className="xs-wb-column">
          <AuditCard overview={overview} roles={roles} />
          {investigator && <DeniedCard />}
          <QuickLinks roles={roles} siteId={siteId} />
        </div>
      </div>
    </div>
  );
}
