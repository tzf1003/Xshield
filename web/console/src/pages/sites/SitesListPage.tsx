import { PlusOutlined, ReloadOutlined, SearchOutlined } from "@ant-design/icons";
import { useRouter } from "@tanstack/react-router";
import { Alert, Button, Empty, Input, Table, type TableColumnsType, Tag } from "antd";
import { type MouseEvent, useMemo, useState } from "react";
import type { SiteListItem } from "../../api";
import { safeError } from "../../security/errors.ts";
import { useSession } from "../../security/SessionProvider";
import { siteAccess } from "../../sites/access.ts";
import {
  configStatusLabel,
  dedupeSites,
  filterSites,
  listItemState,
  revisionsText,
  type StatusFilter,
  statusFilterOrder,
  summarize,
} from "../../sites/list-model.ts";
import { takeListNotice } from "../../sites/state/list-flash.ts";
import { useSiteList } from "../../sites/state/queries.ts";
import type { Outcome } from "../../sites/outcome.ts";
import { PageActions } from "../../shell/page-actions";
import { busy } from "./fields";
import { IdChip } from "../../ui/IdChip";
import { ProblemAlert } from "../../ui/ProblemAlert";
import { StatePill, applyStateSpec } from "../../ui/StatePill";
import { TimeStamp } from "../../ui/TimeStamp";
import "../../ui/ui.css";
import "./sites.css";

const NEW_SITE_PATH = "/sites/new/basics";

/**
 * 受保护站点: the tenant's sites as a searchable table. Search and the status chips only
 * look at rows that were already read; "加载更多" reads the next signed-cursor page.
 */
export function SitesListPage() {
  const router = useRouter();
  const { state } = useSession();
  const access = siteAccess(state.roles);
  const query = useSiteList();
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<StatusFilter>("all");
  // What happened on the page the operator just left (a deleted site), shown once.
  const [notice, setNotice] = useState<Outcome | null>(takeListNotice);

  const sites = useMemo(
    () => dedupeSites(query.data?.pages.flatMap((page) => page.sites) ?? []),
    [query.data],
  );
  const summary = useMemo(() => summarize(sites), [sites]);
  const visible = useMemo(() => filterSites(sites, search, filter), [sites, search, filter]);
  const refreshing = query.isFetching && !query.isFetchingNextPage;

  function open(path: string) {
    void router.navigate({ to: path } as never);
  }
  function openSite(event: MouseEvent, siteId: string) {
    if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) {
      return;
    }
    event.preventDefault();
    open(`/sites/${siteId}/overview`);
  }

  const columns: TableColumnsType<SiteListItem> = [
    {
      title: "站点",
      key: "site",
      sorter: (a, b) => a.display_name.localeCompare(b.display_name, "zh"),
      render: (_, site) => (
        <div className="xs-site-cell">
          <a
            className="xs-site-name"
            href={`/sites/${site.site_id}/overview`}
            onClick={(event) => openSite(event, site.site_id)}
          >
            {site.display_name}
          </a>
          <IdChip value={site.site_id} label="站点 ID" maxLength={36} />
          <span className="xs-site-origin xs-only-narrow mono">{site.public_origin}</span>
        </div>
      ),
    },
    {
      title: "公网入口",
      dataIndex: "public_origin",
      responsive: ["lg"],
      render: (origin: string) => <span className="mono xs-wrap">{origin}</span>,
    },
    {
      title: "监听端口",
      dataIndex: "listen_port",
      responsive: ["lg"],
      width: 100,
      render: (port: number) => <span className="mono">{port}</span>,
    },
    {
      title: "配置状态",
      dataIndex: "status",
      responsive: ["md"],
      width: 100,
      render: (status: SiteListItem["status"]) => <Tag>{configStatusLabel[status]}</Tag>,
    },
    {
      title: "应用状态",
      key: "apply",
      render: (_, site) => (
        <div className="xs-apply-cell">
          <StatePill kind="apply" state={listItemState(site)} />
          <span className="mono xs-revisions">{revisionsText(site)}</span>
        </div>
      ),
    },
    {
      title: "更新",
      key: "updated",
      responsive: ["md"],
      width: 150,
      sorter: (a, b) => a.updated_at.localeCompare(b.updated_at),
      render: (_, site) => (
        <div className="xs-updated-cell">
          <TimeStamp value={site.updated_at} compact />
          <small className="muted xs-wrap">{site.updated_by}</small>
        </div>
      ),
    },
  ];

  const hasRows = sites.length > 0;
  const emptyNode = query.isPending ? (
    <span />
  ) : query.isError && !hasRows ? (
    <span />
  ) : hasRows ? (
    <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="没有符合条件的已加载站点">
      <Button
        onClick={() => {
          setSearch("");
          setFilter("all");
        }}
      >
        清除搜索与筛选
      </Button>
      {query.hasNextPage && (
        <p className="muted xs-empty-note">还有未加载的站点：先点击“加载更多”再继续搜索。</p>
      )}
    </Empty>
  ) : (
    <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无受保护站点">
      {access.canConfigure ? (
        <>
          <p className="muted xs-empty-note">点击“新建站点”，按向导填写网络配置并保存为草稿。</p>
          <Button type="primary" onClick={() => open(NEW_SITE_PATH)}>
            新建站点
          </Button>
        </>
      ) : (
        <p className="muted xs-empty-note">当前范围内没有站点，或当前身份无权查看。</p>
      )}
    </Empty>
  );

  return (
    <section className="xs-sites-page" aria-label="受保护站点列表">
      <PageActions>
        {query.dataUpdatedAt > 0 && !query.isError && (
          <span className="xs-observed">
            读取于 <TimeStamp value={query.dataUpdatedAt} compact />
          </span>
        )}
        <Button
          icon={<ReloadOutlined aria-hidden="true" />}
          loading={busy(refreshing)}
          onClick={() => void query.refresh()}
        >
          刷新
        </Button>
        {access.canConfigure && (
          <Button
            type="primary"
            icon={<PlusOutlined aria-hidden="true" />}
            onClick={() => open(NEW_SITE_PATH)}
          >
            新建站点
          </Button>
        )}
      </PageActions>

      {notice && (
        <div className="xs-sites-problem">
          <Alert
            type={notice.tone}
            showIcon
            role="status"
            title={notice.title}
            description={notice.detail ?? undefined}
            closable={{ onClose: () => setNotice(null), "aria-label": "关闭提示" }}
          />
        </div>
      )}

      {query.isError && (
        <div className="xs-sites-problem">
          <ProblemAlert problem={safeError(query.error)} />
        </div>
      )}

      {hasRows && (
        <section className="xs-sites-summary" aria-label="已加载站点统计">
          <dl>
            <div>
              <dt>已加载站点</dt>
              <dd>{summary.total}</dd>
            </div>
            <div>
              <dt>已生效</dt>
              <dd>{summary.counts.active}</dd>
            </div>
            <div>
              <dt>待审批</dt>
              <dd>{summary.counts.awaiting_approval}</dd>
            </div>
            <div>
              <dt>应用失败</dt>
              <dd>{summary.counts.failed}</dd>
            </div>
          </dl>
          <p>
            统计基于已加载的 {summary.total} 个站点
            {query.hasNextPage ? "，还有更多未加载" : "（已加载全部）"}。
          </p>
        </section>
      )}

      {(hasRows || search !== "" || filter !== "all") && (
        <div className="xs-sites-tools">
          <Input
            allowClear
            prefix={<SearchOutlined aria-hidden="true" />}
            placeholder="搜索已加载的站点：名称、站点 ID、域名"
            aria-label="搜索已加载的站点"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
          <fieldset className="xs-sites-chips">
            <legend className="xs-visually-hidden">按状态筛选</legend>
            <Button
              size="small"
              type={filter === "all" ? "primary" : "default"}
              aria-pressed={filter === "all"}
              onClick={() => setFilter("all")}
            >
              全部 {summary.total}
            </Button>
            {statusFilterOrder
              .filter((name) => summary.counts[name] > 0 || filter === name)
              .map((name) => (
                <Button
                  key={name}
                  size="small"
                  type={filter === name ? "primary" : "default"}
                  aria-pressed={filter === name}
                  onClick={() => setFilter(name)}
                >
                  {applyStateSpec[name].label} {summary.counts[name]}
                </Button>
              ))}
          </fieldset>
        </div>
      )}

      {!(query.isError && !hasRows) && (
        <Table<SiteListItem>
          className="xs-sites-table"
          rowKey="site_id"
          size="middle"
          columns={columns}
          dataSource={visible}
          loading={query.isPending}
          locale={{ emptyText: emptyNode }}
          pagination={{ pageSize: 25, hideOnSinglePage: true, showSizeChanger: false }}
          onRow={(site) => ({
            onClick: (event) => {
              if ((event.target as HTMLElement).closest("a,button")) return;
              open(`/sites/${site.site_id}/overview`);
            },
          })}
          rowClassName={() => "xs-site-row"}
          scroll={{ x: 340 }}
        />
      )}

      {query.hasNextPage && (
        <div className="xs-sites-more">
          <Button loading={query.isFetchingNextPage} onClick={() => void query.fetchNextPage()}>
            加载更多
          </Button>
          <span className="muted">已加载 {sites.length} 个站点</span>
        </div>
      )}
    </section>
  );
}
