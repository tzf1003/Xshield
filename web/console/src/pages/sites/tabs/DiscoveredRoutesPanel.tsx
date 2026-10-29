import { CompassOutlined, SearchOutlined } from "@ant-design/icons";
import { App as AntdApp, Button, Collapse, Select, Table, type TableColumnsType } from "antd";
import { useState } from "react";
import type { DiscoveredRouteGroup, SiteRouteConfig } from "../../../api.ts";
import { ApiError } from "../../../api-contract.ts";
import {
  buildDiscoveredRoutesPlan,
  DISCOVERED_ROUTES_PAGE_SIZES,
  useDiscoveredRoutes,
} from "../../../sites/state/discovered-routes.ts";
import { effectivePolicy, newRoute } from "../../../sites/model/config.ts";
import { CompletenessBanner } from "../../../ui/CompletenessBanner";
import { EventTime } from "../../../ui/EventTime";
import { EmptyState, ErrorState, LoadingState } from "../../../ui/states";
import { checkedResolution, TimeRangePicker } from "../../../ui/TimeRangePicker";
import type { RangeIntent } from "../../../ui/time-range.ts";
import type { WorkspaceApi } from "../workspace/use-workspace.ts";
import { uniqueId, withRoutes } from "./RoutesTab";

const ROUTE_METHODS = new Set<SiteRouteConfig["method"]>(["GET", "POST", "PUT", "PATCH", "DELETE"]);

function isImportableMethod(method: string): method is SiteRouteConfig["method"] {
  return ROUTE_METHODS.has(method as SiteRouteConfig["method"]);
}

/** A template holding `{id}` is a hint only; only a literal path with a route-capable method
 * can become a one-click import, so this console never guesses a resource type. */
function importable(route: DiscoveredRouteGroup): boolean {
  return isImportableMethod(route.method) && !route.path_template.includes("{");
}

function rowKey(route: DiscoveredRouteGroup): string {
  return `${route.method} ${route.path_template}`;
}

/** A short, readable operation ID derived from the discovered path; `uniqueId` still
 * guarantees it does not collide with an existing route. */
function operationIdFromPath(path: string): string {
  const slug = path
    .toLowerCase()
    .replace(/^\/+/, "")
    .replace(/\/+/g, ".")
    .replace(/[^a-z0-9_.-]/g, "-")
    .replace(/^[.-]+|[.-]+$/g, "")
    .slice(0, 100);
  return slug === "" ? "discovered" : slug;
}

type Applied = Readonly<{ start: string; end: string; limit: number; nonce: number }>;

let submissions = 0;

/**
 * 从观察流量导入路由: an operator-triggered discovery of `(method, path_template)` groups the
 * gateway admitted but could not match to any configured operation (docs/30 §30.7, docs/29
 * §29.42). Only literal paths with a route-capable method ever become one-click imports; a
 * templated hint (containing `{id}`) stays read-only so this console never guesses a resource
 * type. Importing only edits the draft — nothing is sent until the workspace is saved.
 */
export function DiscoveredRoutesPanel({ ws, siteId }: { ws: WorkspaceApi; siteId: string }) {
  const { message } = AntdApp.useApp();
  const [range, setRange] = useState<RangeIntent>({ kind: "preset", preset: "24h" });
  const [limit, setLimit] = useState<number>(50);
  const [applied, setApplied] = useState<Applied | null>(null);
  const [formError, setFormError] = useState<unknown>(null);
  const [rangeNotice, setRangeNotice] = useState<string | null>(null);
  const [selected, setSelected] = useState<readonly string[]>([]);

  const editable = ws.access.canConfigure && !ws.locked;
  const query = useDiscoveredRoutes(
    siteId,
    applied && { start: applied.start, end: applied.end, limit: applied.limit },
    applied?.nonce ?? 0,
  );

  function acceptsWindow(window: { start: string; end: string }): boolean {
    try {
      buildDiscoveredRoutesPlan(window, 10);
      return true;
    } catch {
      return false;
    }
  }

  function submit() {
    const resolution = checkedResolution(range, Date.now(), acceptsWindow);
    if (!resolution.window) {
      setApplied(null);
      if (resolution.problem === "missing" || resolution.problem === "incomplete") {
        setFormError(null);
        setRangeNotice("请先选择完整的时间范围。");
      } else {
        setRangeNotice(null);
        setFormError(new ApiError("CONTROL_DISCOVERED_ROUTES_REQUEST_INVALID"));
      }
      return;
    }
    try {
      const plan = buildDiscoveredRoutesPlan(resolution.window, limit);
      submissions += 1;
      setFormError(null);
      setRangeNotice(null);
      setSelected([]);
      setApplied({ ...plan, nonce: submissions });
    } catch (error) {
      setApplied(null);
      setFormError(error);
    }
  }

  const routes = query.data?.routes ?? [];
  const importCandidates = routes.filter(
    (route) => selected.includes(rowKey(route)) && importable(route),
  );

  function importSelected() {
    if (importCandidates.length === 0) return;
    const count = importCandidates.length;
    ws.update((current) => {
      const existing = effectivePolicy(current).routes;
      const taken = new Set(existing.map((route) => route.operation_id));
      const additions = importCandidates.map((group) => {
        const operationId = uniqueId(operationIdFromPath(group.path_template), taken);
        taken.add(operationId);
        return newRoute({
          operation_id: operationId,
          method: group.method as SiteRouteConfig["method"],
          path: group.path_template,
        });
      });
      return withRoutes(current, [...existing, ...additions]);
    });
    setSelected([]);
    void message.success(`已导入 ${count} 条到草稿，保存后生效。`);
  }

  const columns: TableColumnsType<DiscoveredRouteGroup> = [
    {
      title: "方法",
      key: "method",
      width: 92,
      render: (_, route) => <span className="mono">{route.method}</span>,
    },
    {
      title: "路径模板",
      key: "path",
      render: (_, route) => (
        <span className="xs-wrap">
          <span className="mono">{route.path_template}</span>
          {route.path_template.includes("{") && (
            <small className="muted"> · 含参数，仅供参考，不自动导入</small>
          )}
          {!importable(route) && !route.path_template.includes("{") && (
            <small className="muted"> · 该方法不受路由支持，不可导入</small>
          )}
        </span>
      ),
    },
    { title: "命中", key: "hits", width: 90, render: (_, route) => route.hits },
    {
      title: "首次出现",
      key: "first_seen",
      width: 168,
      render: (_, route) => <EventTime value={route.first_seen} precision="second" />,
    },
    {
      title: "最近出现",
      key: "last_seen",
      width: 168,
      render: (_, route) => <EventTime value={route.last_seen} precision="second" />,
    },
  ];

  return (
    <Collapse
      className="xs-discovered-routes"
      items={[
        {
          key: "discovered-routes",
          label: (
            <span>
              <CompassOutlined aria-hidden="true" /> 从观察流量导入路由
            </span>
          ),
          children: (
            <section aria-label="从观察流量导入路由">
              <p className="muted">
                按窗口聚合网关已放行但未匹配任一已配置操作的流量，供发现与一键导入；只是提示，不是鉴权或路由依据，也不证明该端点当前仍未覆盖。
              </p>
              <div className="xs-routes-tools">
                <TimeRangePicker value={range} accepts={acceptsWindow} onChange={setRange} />
                <Select
                  aria-label="每页条数"
                  value={limit}
                  onChange={setLimit}
                  options={DISCOVERED_ROUTES_PAGE_SIZES.map((value) => ({
                    value,
                    label: String(value),
                  }))}
                />
                <Button
                  type="primary"
                  icon={<SearchOutlined aria-hidden="true" />}
                  onClick={submit}
                >
                  发现
                </Button>
              </div>
              {rangeNotice ? (
                <p className="xs-field-error" role="alert">
                  {rangeNotice}
                </p>
              ) : null}
              {formError ? <ErrorState error={formError} title="发现条件未通过校验" /> : null}
              {applied ? (
                <>
                  {query.error ? (
                    <ErrorState error={query.error} onRetry={() => void query.refetch()} />
                  ) : null}
                  {query.isLoading ? <LoadingState label="正在发现未覆盖端点" /> : null}
                  {query.data ? (
                    <>
                      <CompletenessBanner
                        label="未覆盖端点发现索引状态"
                        note="结果相对已确认审计发布可能滞后；空结果不证明该窗口内没有未覆盖流量。"
                        input={{
                          hasGaps: query.data.has_gaps,
                          pendingSegments: query.data.pending_segments,
                          observations: [
                            {
                              label: "本页",
                              asOf: query.data.as_of,
                              watermark: query.data.index_watermark,
                              scope: query.data.watermark_scope,
                            },
                          ],
                        }}
                      />
                      <div className="xs-routes-tools">
                        <Button
                          disabled={!editable || importCandidates.length === 0}
                          onClick={importSelected}
                        >
                          导入所选（{importCandidates.length}）
                        </Button>
                        {!editable && <span className="muted">只读，不能导入</span>}
                      </div>
                      <Table<DiscoveredRouteGroup>
                        size="small"
                        rowKey={rowKey}
                        columns={columns}
                        dataSource={routes}
                        pagination={false}
                        rowSelection={{
                          selectedRowKeys: [...selected],
                          onChange: (keys) => setSelected(keys as string[]),
                          getCheckboxProps: (route) => ({
                            disabled: !editable || !importable(route),
                          }),
                        }}
                        locale={{
                          emptyText: (
                            <EmptyState title="当前窗口内没有未覆盖的端点" icon="search">
                              当前窗口和作用域内没有未匹配任何已配置操作的流量；这不证明覆盖完整或索引已追平。
                            </EmptyState>
                          ),
                        }}
                      />
                      {routes.length > 0 && (
                        <p className="muted">
                          {routes.length} 组
                          {query.data.truncated &&
                            "，已达到本次页大小上限，可缩小窗口或增大每页条数"}
                          。
                        </p>
                      )}
                    </>
                  ) : null}
                </>
              ) : null}
            </section>
          ),
        },
      ]}
    />
  );
}
