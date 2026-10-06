import {
  CopyOutlined,
  DeleteOutlined,
  EditOutlined,
  GlobalOutlined,
  LoginOutlined,
  PlusOutlined,
  SafetyCertificateOutlined,
  SearchOutlined,
  ShareAltOutlined,
  UserOutlined,
} from "@ant-design/icons";
import { Button, Input, Popconfirm, Select, Table, type TableColumnsType, Tooltip } from "antd";
import { type ReactNode, useMemo, useState } from "react";
import type { SiteRouteConfig } from "../../../api.ts";
import {
  effectivePolicy,
  ENTRY_OPERATION_ID,
  MAX_ROUTES,
  newRoute,
  type SiteConfigDraft,
} from "../../../sites/model/config.ts";
import { flowParts } from "../../../sites/model/diff.ts";
import { formatBytes } from "../../../sites/model/units.ts";
import type { WorkspaceApi } from "../workspace/use-workspace.ts";
import { type DrawerMode, RouteDrawer } from "./RouteDrawer";
import { RoutesTemplateButton } from "./RouteTemplatePicker";

type Row = { route: SiteRouteConfig; index: number };

const methodTone: Record<SiteRouteConfig["method"], string> = {
  GET: "info",
  POST: "allow",
  PUT: "observe",
  PATCH: "observe",
  DELETE: "deny",
};

const admission: Record<
  SiteRouteConfig["security_entry"],
  { label: string; tone: string; icon: ReactNode }
> = {
  ui_action_required: { label: "界面来源", tone: "allow", icon: <SafetyCertificateOutlined /> },
  authenticated_root: { label: "已认证根", tone: "info", icon: <UserOutlined /> },
  auth_entry: { label: "认证入口", tone: "observe", icon: <LoginOutlined /> },
  share_entry: { label: "分享入口", tone: "info", icon: <ShareAltOutlined /> },
  public: { label: "公开", tone: "observe", icon: <GlobalOutlined /> },
};

function resourceText(route: SiteRouteConfig): string {
  const binding = route.resource_path_parameter
    ? `路径 {${route.resource_path_parameter}}`
    : route.resource_query_parameter
      ? `查询 ?${route.resource_query_parameter}`
      : null;
  if (!route.resource_type && !route.view_profile && !binding) return "—";
  return [route.resource_type, route.view_profile, binding].filter(Boolean).join(" · ");
}

function uniqueId(base: string, taken: ReadonlySet<string>): string {
  if (!taken.has(base)) return base;
  for (let n = 2; n < 10_000; n += 1) if (!taken.has(`${base}.${n}`)) return `${base}.${n}`;
  return `${base}.${Date.now()}`;
}

/** The entry fields and the `protected.entry` route describe one door: keep them together. */
function withRoutes(draft: SiteConfigDraft, routes: SiteRouteConfig[]): SiteConfigDraft {
  const next = { ...draft, policy: { ...draft.policy, routes } };
  const entry = routes.find((route) => route.operation_id === ENTRY_OPERATION_ID);
  // The site entry is never an authentication or share entry; such a route keeps the site's own.
  return entry && entry.security_entry !== "auth_entry" && entry.security_entry !== "share_entry"
    ? { ...next, entry_path: entry.path, security_entry: entry.security_entry }
    : next;
}

/**
 * 路由与操作: every operation the edge allows, as a searchable table (a site may have up to 256
 * routes). Rows are edited in a drawer; nothing reaches the draft until 应用到草稿. `templates`
 * offers 套用示例 here; the new-site wizard turns it off because its own card offers them.
 */
export function RoutesTab({ ws, templates = true }: { ws: WorkspaceApi; templates?: boolean }) {
  const draft = ws.draft;
  const [search, setSearch] = useState("");
  const [method, setMethod] = useState("all");
  const [entry, setEntry] = useState("all");
  const [drawer, setDrawer] = useState<{
    mode: DrawerMode;
    index: number | null;
    route: SiteRouteConfig;
    key: number;
  } | null>(null);

  const routes = useMemo(() => (draft ? effectivePolicy(draft).routes : []), [draft]);
  const rows: Row[] = useMemo(() => {
    const terms = search.trim().toLowerCase().split(/\s+/).filter(Boolean);
    return routes
      .map((route, index) => ({ route, index }))
      .filter(({ route }) => {
        if (method !== "all" && route.method !== method) return false;
        if (entry !== "all" && route.security_entry !== entry) return false;
        const haystack = [
          route.operation_id,
          route.path,
          route.resource_type,
          route.view_profile,
          route.source_action,
        ]
          .join("\n")
          .toLowerCase();
        return terms.every((term) => haystack.includes(term));
      });
  }, [routes, search, method, entry]);

  const problems = useMemo(() => {
    const counts = new Map<string, number>();
    for (const issue of ws.issues) {
      const match = /^routes\[(.*?)\](?:\.|$)/.exec(issue.path);
      if (match?.[1] !== undefined) counts.set(match[1], (counts.get(match[1]) ?? 0) + 1);
    }
    return counts;
  }, [ws.issues]);

  if (!draft) return null;
  const editable = ws.access.canConfigure && !ws.locked;
  const full = routes.length >= MAX_ROUTES;
  const limits = {
    max_response_body_bytes: draft.policy.limits.max_response_body_bytes,
    max_request_body_bytes: draft.policy.limits.max_request_body_bytes,
  };
  const taken = new Set(routes.map((route) => route.operation_id));

  function open(mode: DrawerMode, index: number | null, route: SiteRouteConfig) {
    setDrawer({ mode, index, route, key: Date.now() });
  }
  function add() {
    const id = uniqueId("route", taken);
    open(
      "add",
      null,
      newRoute({
        operation_id: id,
        path: `/${id.replace(/\./g, "-")}`,
        security_entry: "ui_action_required",
        source_action: `${id}.open`,
      }),
    );
  }
  function duplicate(route: SiteRouteConfig) {
    const id = uniqueId(`${route.operation_id || "route"}.copy`, taken);
    open("duplicate", null, { ...structuredClone(route), operation_id: id });
  }
  function apply(route: SiteRouteConfig) {
    if (!drawer) return;
    const next =
      drawer.mode === "edit" && drawer.index !== null
        ? routes.map((item, at) => (at === drawer.index ? route : item))
        : [...routes, route];
    ws.update((current) => withRoutes(current, next));
    setDrawer(null);
  }
  function remove(index: number) {
    ws.update((current) =>
      withRoutes(
        current,
        routes.filter((_, at) => at !== index),
      ),
    );
  }

  const columns: TableColumnsType<Row> = [
    {
      title: "方法",
      key: "method",
      width: 92,
      sorter: (a, b) => a.route.method.localeCompare(b.route.method),
      render: (_, { route }) => (
        <span className={`xs-pill xs-pill--sm xs-pill--${methodTone[route.method]}`}>
          {route.method}
        </span>
      ),
    },
    {
      title: "路径",
      key: "path",
      width: 240,
      sorter: (a, b) => a.route.path.localeCompare(b.route.path),
      render: (_, { route }) => (
        <div className="xs-route-cell">
          <span className="mono xs-wrap">{route.path}</span>
          {(problems.get(route.operation_id) ?? 0) > 0 && (
            <small className="xs-route-problem">
              有 {problems.get(route.operation_id)} 项问题，打开编辑查看
            </small>
          )}
        </div>
      ),
    },
    {
      title: "操作 ID",
      key: "operation",
      width: 170,
      responsive: ["lg"],
      sorter: (a, b) => a.route.operation_id.localeCompare(b.route.operation_id),
      render: (_, { route }) => <span className="mono xs-wrap">{route.operation_id || "—"}</span>,
    },
    {
      title: "准入",
      key: "admission",
      width: 118,
      render: (_, { route }) => {
        const item = admission[route.security_entry];
        return (
          <span className={`xs-pill xs-pill--sm xs-pill--${item.tone}`}>
            <span className="xs-pill-icon" aria-hidden="true">
              {item.icon}
            </span>
            {item.label}
          </span>
        );
      },
    },
    {
      title: "资源绑定",
      key: "resource",
      width: 200,
      responsive: ["xl"],
      render: (_, { route }) => <span className="xs-wrap">{resourceText(route)}</span>,
    },
    {
      title: "响应",
      key: "response",
      responsive: ["xl"],
      width: 170,
      render: (_, { route }) => (
        <span className="xs-wrap">
          {route.response_mode === "" ? "透传" : route.response_mode}
          <small className="muted"> · ≤ {formatBytes(route.max_response_bytes)}</small>
          {(route.request_crypto || route.response_crypto) && (
            <small className="muted"> · 加密</small>
          )}
          {flowParts(route, false).map((part) => (
            <small key={part} className="muted">
              {" "}
              · {part}
            </small>
          ))}
        </span>
      ),
    },
    {
      title: "操作",
      key: "actions",
      width: 120,
      render: (_, { route, index }) => {
        const name = route.operation_id || `#${index + 1}`;
        return (
          <span className="xs-row-actions">
            <Tooltip title={editable ? "编辑" : "只读"}>
              <Button
                type="text"
                icon={<EditOutlined aria-hidden="true" />}
                aria-label={`编辑路由 ${name}`}
                onClick={() => open("edit", index, structuredClone(route))}
              />
            </Tooltip>
            <Tooltip title={full ? `最多 ${MAX_ROUTES} 条路由` : "复制"}>
              <Button
                type="text"
                disabled={!editable || full}
                icon={<CopyOutlined aria-hidden="true" />}
                aria-label={`复制路由 ${name}`}
                onClick={() => duplicate(route)}
              />
            </Tooltip>
            <Popconfirm
              title={`移除路由 ${name}？`}
              description="移除只改动草稿，保存后才生效。"
              okText="移除"
              cancelText="取消"
              okButtonProps={{ danger: true }}
              onConfirm={() => remove(index)}
            >
              <Button
                type="text"
                danger
                disabled={!editable}
                icon={<DeleteOutlined aria-hidden="true" />}
                aria-label={`移除路由 ${name}`}
              />
            </Popconfirm>
          </span>
        );
      },
    },
  ];

  return (
    <section className="xs-card xs-routes" aria-label="路由与操作">
      <div className="xs-routes-tools">
        <Input
          allowClear
          prefix={<SearchOutlined aria-hidden="true" />}
          placeholder="搜索路径、操作 ID、资源类型"
          aria-label="搜索路由"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
        />
        <Select
          aria-label="按方法筛选"
          value={method}
          onChange={setMethod}
          options={[
            { value: "all", label: "全部方法" },
            ...["GET", "POST", "PUT", "PATCH", "DELETE"].map((value) => ({ value, label: value })),
          ]}
        />
        <Select
          aria-label="按准入筛选"
          value={entry}
          onChange={setEntry}
          options={[
            { value: "all", label: "全部准入" },
            { value: "ui_action_required", label: "界面来源" },
            { value: "authenticated_root", label: "已认证根" },
            { value: "auth_entry", label: "认证入口" },
            { value: "share_entry", label: "分享入口" },
            { value: "public", label: "公开" },
          ]}
        />
        <Tooltip title={full ? `最多 ${MAX_ROUTES} 条路由` : undefined}>
          <Button
            type="primary"
            icon={<PlusOutlined aria-hidden="true" />}
            disabled={!editable || full}
            onClick={add}
          >
            新增路由
          </Button>
        </Tooltip>
        {templates && <RoutesTemplateButton ws={ws} disabled={!editable} />}
      </div>
      <p className="muted xs-routes-note">
        共 {routes.length} 条路由（最多 {MAX_ROUTES}）
        {rows.length !== routes.length && `，筛选出 ${rows.length} 条`}。未声明的 HTTP
        操作继续被拒绝；没有任何路由时，edge 使用入口路径与安全入口生成的默认路由
        protected.entry。路由、方法、准入和资源约束随同一份策略原子发布。
      </p>
      <Table<Row>
        size="small"
        rowKey={(row) => `${row.index}`}
        columns={columns}
        dataSource={rows}
        pagination={{
          defaultPageSize: 20,
          pageSizeOptions: [20, 50, 100],
          showSizeChanger: true,
          showTotal: (total) => `共 ${total} 条`,
          hideOnSinglePage: rows.length <= 20,
        }}
        locale={{ emptyText: "没有符合条件的路由。" }}
        scroll={{ x: 420 }}
      />
      {drawer && (
        <RouteDrawer
          key={drawer.key}
          open
          mode={drawer.mode}
          initial={drawer.route}
          routes={routes}
          index={drawer.index}
          limits={limits}
          readOnly={!editable}
          onApply={apply}
          onClose={() => setDrawer(null)}
        />
      )}
    </section>
  );
}
