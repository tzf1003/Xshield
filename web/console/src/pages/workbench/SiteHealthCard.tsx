import { HeartOutlined, ReloadOutlined } from "@ant-design/icons";
import { Button, Empty, Skeleton, Table, type TableColumnsType } from "antd";
import type { ReactNode } from "react";
import type {
  SiteListItem,
  SiteListResponse,
  WorkbenchOverviewResponse,
  WorkbenchSite,
} from "../../api.ts";
import { siteProjection } from "../../operations/kpis.ts";
import { ObservationPill, RoleHint } from "../../operations/Parts";
import type { SourceState } from "../../operations/sources.ts";
import { safeError } from "../../security/errors.ts";
import { siteAccess } from "../../sites/access.ts";
import { configStatusLabel } from "../../sites/list-model.ts";
import { securityEntryLabel } from "../../sites/model/config.ts";
import { useSiteHealth } from "../../sites/state/detail-queries.ts";
import { reasonText } from "../../ui/reason-codes.ts";
import { StatePill } from "../../ui/StatePill";
import { type ApplyStateValue, siteDisplayState } from "../../ui/state-model.ts";
import { TimeStamp } from "../../ui/TimeStamp";
import { RouteLink, useGo } from "../../work/nav";
import { labelled } from "../../work/Parts";

const applyStates: readonly string[] = ["active", "pending", "failed", "paused"];

type Row = WorkbenchSite & { listed: SiteListItem | null };

/**
 * The "刷新健康" action of one row: one audited health read of that site, which the server also
 * stores as the newest upstream observation. The answer is shown next to the snapshot's (older)
 * value with its own time; the snapshot itself is not re-read.
 */
function HealthRefresh({ site, allowed }: { site: Row; allowed: boolean }) {
  const health = useSiteHealth(site.site_id);
  if (!allowed) {
    return <small className="xs-wb-live">刷新健康需要 Observer 角色</small>;
  }
  const facts = (health.data?.edge_health ?? {}) as Record<string, unknown>;
  return (
    <>
      <Button
        size="small"
        icon={<HeartOutlined aria-hidden="true" />}
        loading={health.isFetching}
        aria-label={`刷新 ${site.display_name || site.site_id} 的健康（写入一条审计与观察记录）`}
        title="读取一次健康：服务端会写入一条审计记录和一条观察记录"
        onClick={(event) => {
          event.stopPropagation();
          void health.read();
        }}
      >
        刷新健康
      </Button>
      {health.isError && !health.isFetching && (
        <small className="xs-w-error">
          健康读取失败 · <span className="mono">{safeError(health.error).code}</span>
        </small>
      )}
      {health.data && !health.isError && (
        <span className="xs-wb-live">
          本次读取：源站 <StatePill kind="health" value={facts.upstream_state} size="sm" /> ·{" "}
          <TimeStamp value={health.dataUpdatedAt} compact />
          （控制台收到响应的时间）
        </span>
      )}
    </>
  );
}

function ApplyCell({ row }: { row: Row }) {
  const known = applyStates.includes(row.apply_state);
  const state = siteDisplayState({
    apply_state: known ? (row.apply_state as ApplyStateValue) : null,
    requires_approval: row.listed?.requires_approval ?? null,
    status: row.listed?.status ?? null,
  });
  const reason = reasonText(row.reason_code);
  return (
    <span title={`${reason.text}（${row.reason_code}）`}>
      <StatePill kind="apply" state={state} size="sm" />
      {!known && <code className="mono xs-wb-live"> {row.apply_state}</code>}
    </span>
  );
}

/**
 * 站点健康: one row per site of the snapshot. Edge and its audit barrier were probed live when the
 * snapshot was read; the upstream column is the last stored health read, with its own time.
 */
export function SiteHealthCard({
  overview,
  sites,
  roles,
  sessionSiteId,
  onRefresh,
  refreshing,
}: {
  overview: SourceState<WorkbenchOverviewResponse>;
  sites: SourceState<SiteListResponse>;
  roles: readonly string[] | null;
  sessionSiteId: string | null;
  onRefresh: () => void;
  refreshing: boolean;
}) {
  const go = useGo();
  const access = siteAccess(roles);
  const listed = new Map(
    sites.status === "ok" ? sites.data.sites.map((site) => [site.site_id, site] as const) : [],
  );
  const columns: TableColumnsType<Row> = [
    {
      title: "站点",
      key: "site",
      onCell: labelled("站点"),
      render: (_, row) => (
        <span className="xs-wb-site">
          <RouteLink to={`/sites/${row.site_id}/overview`}>
            {row.display_name || row.site_id}
          </RouteLink>
          <small className="mono">{row.site_id}</small>
        </span>
      ),
    },
    {
      title: "模式 / 状态",
      key: "mode",
      onCell: labelled("模式/状态"),
      render: (_, row) =>
        row.listed ? (
          <span className="xs-wb-site">
            <span>{securityEntryLabel[row.listed.security_entry]}</span>
            <small>{configStatusLabel[row.listed.status]}</small>
          </span>
        ) : (
          <span className="xs-w-muted" title="模式与配置状态来自站点清单（需要 SystemAdmin）">
            —
          </span>
        ),
    },
    {
      title: "Edge",
      key: "edge",
      onCell: labelled("Edge"),
      render: (_, row) => <ObservationPill observation={row.edge} kind="edge" />,
    },
    {
      title: "源站",
      key: "upstream",
      onCell: labelled("源站"),
      render: (_, row) => (
        <span className="xs-wb-upstream">
          <ObservationPill observation={row.upstream} kind="upstream" />
          <HealthRefresh site={row} allowed={access.canObserve} />
        </span>
      ),
    },
    {
      title: "审计屏障",
      key: "audit",
      onCell: labelled("审计屏障"),
      render: (_, row) => <ObservationPill observation={row.audit} kind="audit" />,
    },
    {
      title: "正在服务",
      key: "revision",
      onCell: labelled("正在服务"),
      render: (_, row) =>
        row.current_revision === null ? (
          <span className="xs-w-muted">从未生效</span>
        ) : (
          <span className="mono">r{row.current_revision}</span>
        ),
    },
    {
      title: "应用状态",
      key: "apply",
      onCell: labelled("应用状态"),
      render: (_, row) => <ApplyCell row={row} />,
    },
  ];

  let body: ReactNode;
  if (overview.status === "loading" || overview.status === "skipped") {
    body = (
      <div aria-busy="true">
        <Skeleton active paragraph={{ rows: 3 }} title={false} />
      </div>
    );
  } else if (overview.status !== "ok") {
    body = <p className="xs-w-muted">工作台快照不可用，见页面顶部的提示。</p>;
  } else {
    const projection = siteProjection(overview.data, roles, sites);
    if (!projection.projected) {
      body = (
        <RoleHint title="快照没有站点列表">
          {projection.reason}
          {sessionSiteId !== null && access.canObserve && (
            <>
              {" "}
              当前会话站点的状态可在{" "}
              <RouteLink to={`/sites/${sessionSiteId}/overview`}>站点状态</RouteLink> 查看。
            </>
          )}
        </RoleHint>
      );
    } else if (overview.data.sites.length === 0) {
      body = (
        <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="当前范围内没有受保护站点。" />
      );
    } else {
      const rows: Row[] = overview.data.sites.map((site) => ({
        ...site,
        listed: listed.get(site.site_id) ?? null,
      }));
      body = (
        <Table<Row>
          className="xs-w-table xs-w-clickable"
          rowKey="site_id"
          size="middle"
          columns={columns}
          dataSource={rows}
          pagination={false}
          onRow={(row) => ({
            onClick: (event) => {
              // Links and buttons inside the row do their own thing.
              if ((event.target as HTMLElement).closest("a, button")) return;
              go(`/sites/${row.site_id}/overview`);
            },
          })}
        />
      );
    }
  }

  return (
    <section className="xs-w-card" aria-labelledby="wb-sites-title">
      <div className="xs-wb-head">
        <div>
          <h2 id="wb-sites-title">站点健康</h2>
          <p className="xs-wb-sub">
            Edge
            与审计屏障是读取快照时的实时探测；源站是最近一次健康读取的结果，带有它自己的观察时间。
          </p>
          {overview.status === "ok" && (
            <p className="xs-wb-sub">
              快照观察于 <TimeStamp value={overview.data.as_of} /> · 管理请求{" "}
              <span className="mono">{overview.data.request_id}</span>
            </p>
          )}
        </div>
        <Button
          icon={<ReloadOutlined aria-hidden="true" />}
          loading={refreshing}
          onClick={onRefresh}
        >
          刷新快照
        </Button>
      </div>
      {body}
    </section>
  );
}
