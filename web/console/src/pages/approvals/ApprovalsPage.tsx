import { ReloadOutlined } from "@ant-design/icons";
import type { UseQueryResult } from "@tanstack/react-query";
import { useRouterState, useSearch } from "@tanstack/react-router";
import {
  Alert,
  Button,
  Drawer,
  Empty,
  Segmented,
  Space,
  Table,
  type TableColumnsType,
  Tabs,
} from "antd";
import { type ComponentProps, type ReactNode, useEffect, useState } from "react";
import type { SiteListItem, SiteListResponse } from "../../api.ts";
import type { AccessList } from "../../evidence-access.ts";
import type { ExportList } from "../../exports.ts";
import { useGuardedQuery } from "../../security/hooks";
import { useSession } from "../../security/SessionProvider";
import { PageActions } from "../../shell/page-actions";
import { useMediaQuery } from "../../shell/use-media-query";
import { AccessDetail } from "../../work/AccessDetail";
import { badgeStore } from "../../work/approval-badge.ts";
import { ExportDetail } from "../../work/ExportDetail";
import { formatAge } from "../../work/format.ts";
import { type BadgeSource, filterInbox, type InboxKind, mergeInbox } from "../../work/inbox.ts";
import { RouteLink, useGo } from "../../work/nav";
import {
  ErrorNotice,
  Facts,
  IdChip,
  IdText,
  labelled,
  Observed,
  Pager,
  StatePill,
  Time,
  TonePill,
  usePager,
} from "../../work/Parts";
import { specs } from "../../work/queries.ts";
import { role, useRoles } from "../../work/roles.ts";
import { accessPill, exportPill } from "../../work/status.ts";
import { WorkRoot } from "../../work/WorkRoot";
import {
  accessRows,
  exportRows,
  policyRows,
  type Row,
  rowSelection,
  type Selection,
  selectionFromItem,
} from "./rows.ts";

type Kind = "all" | InboxKind;
type MineKind = "all" | "access" | "export";

const kindNames: Record<
  InboxKind,
  { label: string; tone: ComponentProps<typeof TonePill>["tone"] }
> = {
  access: { label: "原文", tone: "processing" },
  export: { label: "导出", tone: "brand" },
  site: { label: "策略", tone: "default" },
};

const moved: Record<string, { title: string; text: string }> = {
  access: {
    title: "“证据访问”已并入审批中心",
    text: "待你审批的原文访问、导出和策略修订，以及你自己的申请，都在这里。申请原文访问请在案件详情的“访问申请”页签中提交。",
  },
};

export function ApprovalsPage() {
  return (
    <WorkRoot>
      <ApprovalsBody />
    </WorkRoot>
  );
}

/** The object of a row: a site and its revision, or the case and the evidence it concerns. */
function Target({ row }: { row: Row }) {
  if (row.kind === "site") {
    return (
      <div>
        <div className="xs-w-text">{row.target}</div>
        <small className="xs-w-muted">
          {row.id} · {row.detail}
        </small>
      </div>
    );
  }
  return (
    <div className="xs-w-case">
      <span>
        <span className="xs-w-muted">案件</span> <IdText id={row.target} />
      </span>
      {row.detail && (
        <span>
          <span className="xs-w-muted">证据</span> <IdText id={row.detail} />
        </span>
      )}
    </div>
  );
}

function KindTag({ kind }: { kind: InboxKind }) {
  const meta = kindNames[kind];
  return <TonePill tone={meta.tone} label={meta.label} />;
}

function ApprovalsBody() {
  const { has, roles } = useRoles();
  const { runtime } = useSession();
  const go = useGo();
  const compact = useMediaQuery("(max-width: 1279px)");
  const pathname = useRouterState({ select: (router) => router.location.pathname });
  const search = useSearch({ strict: false }) as { item?: unknown; moved?: unknown };
  const mineTab = pathname === "/approvals/mine";
  const approver = has(role.approver);
  const policy = has(role.policyApprover);
  const anyRole = approver || policy || has(role.investigator) || has(role.reader);
  const hint =
    typeof search.moved === "string" && Object.hasOwn(moved, search.moved)
      ? moved[search.moved]
      : undefined;

  // The first page of every source this operator's roles can see loads when the page opens.
  const reviewAccess = useGuardedQuery({ ...specs.accessList("review"), enabled: approver });
  const reviewExport = useGuardedQuery({ ...specs.exportList("review"), enabled: approver });
  const sites = useGuardedQuery({ ...specs.siteApprovals(), enabled: policy });

  // The navigation badge shows what these first pages found. It changes only when they are read.
  const accessSettled = reviewAccess.isSuccess || reviewAccess.isError;
  const exportSettled = reviewExport.isSuccess || reviewExport.isError;
  const sitesSettled = sites.isSuccess || sites.isError;
  const accessFailed = reviewAccess.isError;
  const exportFailed = reviewExport.isError;
  const sitesFailed = sites.isError;
  const accessCount = reviewAccess.data?.items.length ?? 0;
  const accessMore = reviewAccess.data?.truncated ?? false;
  const exportCount = reviewExport.data?.items.length ?? 0;
  const exportMore = reviewExport.data?.truncated ?? false;
  const siteCount = policyRows(sites.data?.sites, Number.NaN).length;
  const siteMore = sites.data?.truncated ?? false;
  useEffect(() => {
    if ((approver && (!accessSettled || !exportSettled)) || (policy && !sitesSettled)) return;
    const sources: BadgeSource[] = [];
    if (approver) {
      sources.push({ loaded: !accessFailed, count: accessCount, truncated: accessMore });
      sources.push({ loaded: !exportFailed, count: exportCount, truncated: exportMore });
    }
    if (policy) sources.push({ loaded: !sitesFailed, count: siteCount, truncated: siteMore });
    if (sources.length > 0) badgeStore(runtime).publish(sources);
  }, [
    runtime,
    approver,
    policy,
    accessSettled,
    exportSettled,
    sitesSettled,
    accessFailed,
    exportFailed,
    sitesFailed,
    accessCount,
    exportCount,
    siteCount,
    accessMore,
    exportMore,
    siteMore,
  ]);

  // A site revision has no address of its own, so its selection stays in the page; access
  // requests and exports are named in the URL (`?item=`) and survive a reload of the address.
  const [siteSelected, setSiteSelected] = useState<string | null>(null);
  const fromUrl = selectionFromItem(search.item);
  const selected: Selection | null =
    fromUrl ?? (siteSelected ? { kind: "site", id: siteSelected } : null);

  function select(next: Selection | null) {
    if (next === null || next.kind === "site") {
      setSiteSelected(next?.id ?? null);
      go(pathname, { replace: true });
    } else {
      setSiteSelected(null);
      go(pathname, { replace: true, search: { item: next.id } });
    }
  }

  function refresh() {
    void Promise.allSettled([
      approver ? reviewAccess.refetch() : undefined,
      approver ? reviewExport.refetch() : undefined,
      policy ? sites.refetch() : undefined,
    ]);
  }
  const busy = reviewAccess.isFetching || reviewExport.isFetching || sites.isFetching;

  const detail = selected ? (
    <DetailPane
      bare={compact}
      selected={selected}
      sites={sites.data?.sites}
      ownership={mineTab ? undefined : ownershipOf(selected, reviewAccess.data, reviewExport.data)}
      observedAt={reviewExport.data?.as_of}
      onClose={() => select(null)}
    />
  ) : (
    <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="选择左侧一项，查看详情并处理。" />
  );
  const split = (list: ReactNode, label: string) => (
    <div className={compact ? undefined : "xs-w-split"}>
      {list}
      {!compact && (
        <section className="xs-w-card xs-w-pane" aria-label={label}>
          {detail}
        </section>
      )}
    </div>
  );

  return (
    <div className="xs-w-stack">
      {anyRole && (
        <PageActions>
          <Button icon={<ReloadOutlined aria-hidden="true" />} loading={busy} onClick={refresh}>
            刷新待办
          </Button>
        </PageActions>
      )}
      {hint && (
        <Alert
          type="info"
          showIcon
          closable={{ onClose: () => go("/approvals", { replace: true }) }}
          title={hint.title}
          description={hint.text}
        />
      )}
      {roles !== null && !anyRole ? (
        <Alert
          type="info"
          showIcon
          title="当前角色没有审批或申请权限"
          description="审批中心面向 Investigator、SensitiveEvidenceReader、SensitiveEvidenceApprover 和 PolicyApprover。服务端对每个请求独立授权。"
        />
      ) : (
        <Tabs
          activeKey={mineTab ? "mine" : "inbox"}
          onChange={(key) => go(key === "mine" ? "/approvals/mine" : "/approvals")}
          items={[
            {
              key: "inbox",
              label: "待我审批",
              children: mineTab
                ? null
                : split(
                    <Inbox
                      approver={approver}
                      policy={policy}
                      reviewAccess={reviewAccess}
                      reviewExport={reviewExport}
                      sites={sites}
                      selected={selected}
                      onSelect={select}
                    />,
                    "审批详情",
                  ),
            },
            {
              key: "mine",
              label: "我的申请",
              children: mineTab
                ? split(<Mine selected={selected} onSelect={select} />, "申请详情")
                : null,
            },
          ]}
        />
      )}
      {compact && (
        <Drawer
          title={selected ? detailTitle(selected) : "详情"}
          open={selected !== null}
          onClose={() => select(null)}
          size={560}
          destroyOnHidden
        >
          {detail}
        </Drawer>
      )}
    </div>
  );
}

/** What the lists say about whose request this is; `undefined` when the item is in neither. */
function ownershipOf(
  selected: Selection,
  access: AccessList | undefined,
  exports: ExportList | undefined,
): "others" | undefined {
  if (
    selected.kind === "access" &&
    access?.items.some((row) => row.access_request_id === selected.id)
  )
    return "others";
  if (selected.kind === "export" && exports?.items.some((row) => row.export_id === selected.id))
    return "others";
  return undefined;
}

function SourceError({
  label,
  query,
  extra,
}: {
  label: string;
  query: Pick<UseQueryResult, "isError" | "error" | "refetch" | "isFetching">;
  extra?: ReactNode;
}) {
  if (!query.isError) return null;
  return (
    <div className="xs-w-stack">
      <ErrorNotice
        error={query.error}
        title={`${label}读取失败`}
        action={
          <Button size="small" loading={query.isFetching} onClick={() => void query.refetch()}>
            重试
          </Button>
        }
      />
      {extra}
    </div>
  );
}

function Inbox({
  approver,
  policy,
  reviewAccess,
  reviewExport,
  sites,
  selected,
  onSelect,
}: {
  approver: boolean;
  policy: boolean;
  reviewAccess: UseQueryResult<AccessList, Error>;
  reviewExport: UseQueryResult<ExportList, Error>;
  sites: UseQueryResult<SiteListResponse, Error>;
  selected: Selection | null;
  onSelect: (next: Selection | null) => void;
}) {
  const { state } = useSession();
  const [kind, setKind] = useState<Kind>("all");
  // Each source pages on its own, bound to the filter it was read under: changing the filter
  // starts every pager over, so a cursor is never replayed against another query.
  const accessPager = usePager(`review-access:${kind}`);
  const exportPager = usePager(`review-export:${kind}`);
  const accessPaged = useGuardedQuery({
    ...specs.accessList("review", accessPager.cursor),
    enabled: approver && kind === "access" && accessPager.cursor !== undefined,
  });
  const exportPaged = useGuardedQuery({
    ...specs.exportList("review", exportPager.cursor),
    enabled: approver && kind === "export" && exportPager.cursor !== undefined,
  });
  const accessPage =
    kind === "access" && accessPager.cursor !== undefined ? accessPaged : reviewAccess;
  const exportPage =
    kind === "export" && exportPager.cursor !== undefined ? exportPaged : reviewExport;

  const rows = mergeInbox<Row>(
    kind === "all" || kind === "access" ? accessRows(accessPage.data, "others") : [],
    kind === "all" || kind === "export" ? exportRows(exportPage.data, "others") : [],
    kind === "all" || kind === "site" ? policyRows(sites.data?.sites, Number.NaN) : [],
  );
  const visibleKinds: [Kind, string][] = [
    ...(approver
      ? ([
          ["access", "原文"],
          ["export", "导出"],
        ] as [Kind, string][])
      : []),
    ...(policy ? ([["site", "策略"]] as [Kind, string][]) : []),
  ];
  const queries: UseQueryResult[] = [
    ...(approver ? [reviewAccess, reviewExport] : []),
    ...(policy ? [sites] : []),
  ];
  const loading = queries.length > 0 && queries.every((query) => query.isPending);
  const siteId = state.scope?.site_id;

  const columns: TableColumnsType<Row> = [
    {
      title: "类型",
      key: "kind",
      onCell: labelled("类型"),
      render: (_, row) => <KindTag kind={row.kind} />,
    },
    { title: "申请人", dataIndex: "requester", key: "requester", onCell: labelled("申请人") },
    {
      title: "对象",
      key: "target",
      onCell: labelled("对象"),
      render: (_, row) => <Target row={row} />,
    },
    {
      title: "等待",
      key: "age",
      onCell: labelled("等待"),
      render: (_, row) => (
        <span className="xs-w-nowrap" title={`提交于 ${row.at}`}>
          {Number.isFinite(row.asOfMs) ? formatAge(row.asOfMs - row.atMs) : "—"}
        </span>
      ),
    },
    {
      title: "操作",
      key: "actions",
      onCell: labelled("操作"),
      render: (_, row) => (
        <Button
          size="small"
          type={selected?.id === row.id ? "primary" : "default"}
          aria-label={`${row.kind === "site" ? "查看" : "处理"} ${row.id}`}
          onClick={() => onSelect(rowSelection(row))}
        >
          {row.kind === "site" ? "查看" : "处理"}
        </Button>
      ),
    },
  ];

  if (!approver && !policy) {
    return (
      <Alert
        type="info"
        showIcon
        title="待我审批只对审批角色开放"
        description="原文访问和导出的审批需要 SensitiveEvidenceApprover，策略修订需要 PolicyApprover。你自己的申请在“我的申请”页签。"
      />
    );
  }
  const more =
    (approver && (reviewAccess.data?.truncated || reviewExport.data?.truncated)) ||
    (policy && sites.data?.truncated);
  return (
    <div className="xs-w-stack">
      <div className="xs-w-between xs-w-toolbar">
        <Segmented<Kind>
          aria-label="待办类型筛选"
          value={kind}
          onChange={setKind}
          options={[
            { label: "全部", value: "all" },
            ...visibleKinds.map(([value, label]) => ({ label, value })),
          ]}
        />
        {approver && reviewAccess.data && (
          <Observed asOf={reviewAccess.data.as_of} requestId={reviewAccess.data.request_id} />
        )}
      </div>
      {approver && <SourceError label="原文访问待办" query={reviewAccess} />}
      {approver && <SourceError label="导出待办" query={reviewExport} />}
      {policy && (
        <SourceError
          label="策略修订"
          query={sites}
          extra={
            <Alert
              type="info"
              showIcon
              title="策略修订来自站点清单"
              description="读取站点清单需要 SystemAdmin；只有 PolicyApprover 时请直接打开站点发布页审批。审批决定在站点页提交，审批中心不提交策略决定。"
              action={
                siteId ? (
                  <RouteLink to={`/sites/${siteId}/releases`}>打开站点发布页</RouteLink>
                ) : undefined
              }
            />
          }
        />
      )}
      <Table<Row>
        className="xs-w-table xs-w-clickable"
        rowKey="key"
        size="middle"
        pagination={false}
        columns={columns}
        loading={loading}
        dataSource={filterInbox(rows, kind)}
        rowClassName={(row) => (selected?.id === row.id ? "xs-w-selected" : "")}
        onRow={(row) => ({
          onClick: (event) => {
            if ((event.target as HTMLElement).closest("a,button")) return;
            onSelect(rowSelection(row));
          },
        })}
        locale={{
          emptyText: queries.some((query) => query.isError)
            ? "没有读取到待办；上方列出了读取失败的来源。"
            : "没有待审批事项。列表不会自动刷新，点击“刷新待办”重新读取。",
        }}
      />
      {kind === "all" && more && (
        <Alert
          type="warning"
          showIcon
          title="还有更多待办未显示"
          description="“全部”只显示各来源的第一页。切换到“原文”或“导出”筛选，可逐页读取该来源的全部待办。"
        />
      )}
      {kind === "access" && accessPage.data && (
        <Pager
          pager={accessPager}
          count={accessPage.data.items.length}
          nextCursor={accessPage.data.next_cursor}
          busy={accessPage.isFetching}
          noun="条待办"
        />
      )}
      {kind === "export" && exportPage.data && (
        <Pager
          pager={exportPager}
          count={exportPage.data.items.length}
          nextCursor={exportPage.data.next_cursor}
          busy={exportPage.isFetching}
          noun="条待办"
        />
      )}
      <p className="xs-w-muted">
        列表只发现、不授权：批准或拒绝由独立审批人在右侧详情中提交，服务端重新校验角色、主体与状态。每次读取都会被审计，页面不自动轮询。
      </p>
    </div>
  );
}

function Mine({
  selected,
  onSelect,
}: {
  selected: Selection | null;
  onSelect: (next: Selection | null) => void;
}) {
  const { has } = useRoles();
  const [kind, setKind] = useState<MineKind>("all");
  const allowed = has(role.investigator) || has(role.reader) || has(role.approver);
  const accessPager = usePager(`mine-access:${kind}`);
  const exportPager = usePager(`mine-export:${kind}`);
  const accessQuery = useGuardedQuery({
    ...specs.accessList("mine", accessPager.cursor),
    enabled: allowed && kind !== "export",
  });
  const exportQuery = useGuardedQuery({
    ...specs.exportList("mine", exportPager.cursor),
    enabled: allowed && kind !== "access",
  });
  const rows = mergeInbox<Row>(
    kind === "export" ? [] : accessRows(accessQuery.data, "mine"),
    kind === "access" ? [] : exportRows(exportQuery.data, "mine"),
  );
  const reading: UseQueryResult[] = [
    ...(kind !== "export" ? [accessQuery] : []),
    ...(kind !== "access" ? [exportQuery] : []),
  ];

  const columns: TableColumnsType<Row> = [
    {
      title: "类型",
      key: "kind",
      onCell: labelled("类型"),
      render: (_, row) => <KindTag kind={row.kind} />,
    },
    {
      title: "对象",
      key: "target",
      onCell: labelled("对象"),
      render: (_, row) => <Target row={row} />,
    },
    {
      title: "状态",
      key: "status",
      onCell: labelled("状态"),
      render: (_, row) => (
        <StatePill
          pill={
            row.kind === "access"
              ? accessPill[row.status as keyof typeof accessPill]
              : exportPill(row.status as Parameters<typeof exportPill>[0], row.lapsed)
          }
        />
      ),
    },
    {
      title: "提交时间",
      key: "at",
      onCell: labelled("提交时间"),
      render: (_, row) => <Time value={row.at} stacked />,
    },
    {
      title: "到期",
      key: "expires",
      onCell: labelled("到期"),
      render: (_, row) => <Time value={row.expiresAt} stacked />,
    },
    {
      title: "操作",
      key: "actions",
      onCell: labelled("操作"),
      render: (_, row) => {
        const downloadable =
          (row.kind === "access" && row.status === "approved") ||
          (row.kind === "export" && row.status === "ready" && !row.lapsed);
        return (
          <Button
            size="small"
            type={selected?.id === row.id ? "primary" : "default"}
            aria-label={`${downloadable ? "查看并下载" : "详情"} ${row.id}`}
            onClick={() => onSelect(rowSelection(row))}
          >
            {downloadable ? "查看并下载" : "详情"}
          </Button>
        );
      },
    },
  ];

  if (!allowed) {
    return (
      <Alert
        type="info"
        showIcon
        title="当前角色没有“我的申请”"
        description="“我的申请”需要 Investigator、SensitiveEvidenceReader 或 SensitiveEvidenceApprover。"
      />
    );
  }
  return (
    <div className="xs-w-stack">
      <div className="xs-w-between xs-w-toolbar">
        <Segmented<MineKind>
          aria-label="申请类型筛选"
          value={kind}
          onChange={setKind}
          options={[
            { label: "全部", value: "all" },
            { label: "原文", value: "access" },
            { label: "导出", value: "export" },
          ]}
        />
        {accessQuery.data && kind !== "export" && (
          <Observed asOf={accessQuery.data.as_of} requestId={accessQuery.data.request_id} />
        )}
      </div>
      <SourceError label="原文访问申请" query={accessQuery} />
      <SourceError label="导出申请" query={exportQuery} />
      <Table<Row>
        className="xs-w-table xs-w-clickable"
        rowKey="key"
        size="middle"
        pagination={false}
        columns={columns}
        dataSource={rows}
        loading={reading.length > 0 && reading.every((query) => query.isPending)}
        rowClassName={(row) => (selected?.id === row.id ? "xs-w-selected" : "")}
        onRow={(row) => ({
          onClick: (event) => {
            if ((event.target as HTMLElement).closest("a,button")) return;
            onSelect(rowSelection(row));
          },
        })}
        locale={{ emptyText: "没有申请记录。" }}
      />
      {kind === "all" && (accessQuery.data?.truncated || exportQuery.data?.truncated) && (
        <Alert
          type="warning"
          showIcon
          title="还有更早的申请未显示"
          description="“全部”只显示各来源的第一页。切换到“原文”或“导出”筛选，可逐页读取该来源的全部历史。"
        />
      )}
      {kind === "access" && accessQuery.data && (
        <Pager
          pager={accessPager}
          count={accessQuery.data.items.length}
          nextCursor={accessQuery.data.next_cursor}
          busy={accessQuery.isFetching}
          noun="条申请"
        />
      )}
      {kind === "export" && exportQuery.data && (
        <Pager
          pager={exportPager}
          count={exportQuery.data.items.length}
          nextCursor={exportQuery.data.next_cursor}
          busy={exportQuery.isFetching}
          noun="条申请"
        />
      )}
      <Space className="xs-w-muted">
        状态以数据库观察为准；已批准的原文与就绪的导出包需要 MFA 再认证后才能下载。
      </Space>
    </div>
  );
}

function detailTitle(selected: Selection): string {
  return selected.kind === "access"
    ? "原文访问申请"
    : selected.kind === "export"
      ? "元数据导出"
      : "策略修订";
}

function DetailPane({
  bare,
  selected,
  sites,
  ownership,
  observedAt,
  onClose,
}: {
  /** Inside the drawer, whose own title and close button replace the pane's header. */
  bare: boolean;
  selected: Selection;
  sites: readonly SiteListItem[] | undefined;
  ownership: "others" | undefined;
  observedAt: string | undefined;
  onClose: () => void;
}) {
  const site =
    selected.kind === "site" ? sites?.find((item) => item.site_id === selected.id) : undefined;
  return (
    <div className="xs-w-stack">
      {!bare && (
        <div className="xs-w-between">
          <h3 className="xs-w-title">{detailTitle(selected)}</h3>
          <Button size="small" onClick={onClose}>
            关闭详情
          </Button>
        </div>
      )}
      {selected.kind === "access" && (
        <AccessDetail key={selected.id} accessId={selected.id} ownership={ownership} />
      )}
      {selected.kind === "export" && (
        <ExportDetail
          key={selected.id}
          exportId={selected.id}
          ownership={ownership}
          observedAt={observedAt}
        />
      )}
      {selected.kind === "site" &&
        (site ? (
          <SitePane site={site} />
        ) : (
          <Alert type="warning" showIcon title="该站点修订已不在待办列表中" />
        ))}
    </div>
  );
}

function SitePane({ site }: { site: SiteListItem }) {
  return (
    <div className="xs-w-stack">
      <Space wrap>
        <TonePill tone="warning" label="等待独立审批" />
        <IdChip id={site.site_id} label="站点 ID" />
      </Space>
      <Facts
        rows={[
          ["站点", site.display_name],
          [
            "公开入口",
            <span key="o" className="mono">
              {site.public_origin}
            </span>,
          ],
          ["期望修订", `${site.desired_revision}（已生效修订：${site.active_revision ?? "无"}）`],
          ["提交者", site.updated_by],
          ["提交时间", <Time key="u" value={site.updated_at} />],
          ["应用状态", `${site.apply_state}（${site.reason_code}）`],
          [
            "配置摘要",
            <span key="d" className="mono">
              {site.config_digest}
            </span>,
          ],
        ]}
      />
      <Alert
        type="info"
        showIcon
        title="策略决定在站点发布页提交"
        description="批准会绑定你所审阅的修订与配置摘要，并需要 PolicyApprover 与最近的 MFA 再认证。审批中心只定位待办，不提交策略决定。"
      />
      <RouteLink to={`/sites/${site.site_id}/releases`}>前往站点发布页审阅并决定</RouteLink>
    </div>
  );
}
