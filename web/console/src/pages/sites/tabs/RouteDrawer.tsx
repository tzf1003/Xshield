import { Button, Drawer, Form, Input, Radio } from "antd";
import { useMemo, useRef, useState } from "react";
import type { RouteAdmission, SiteRouteConfig } from "../../../api.ts";
import {
  emptyAuthBinding,
  emptyAuthRevoke,
  emptyIssuedBy,
  emptyPageActions,
  emptyResourceGrant,
  emptySensorBuild,
  type FlowBlock,
  flowBlockLabel,
  type FlowStash,
  withAdmission,
  withBlock,
  withResponseMode,
  withSensorBuilds,
} from "../../../sites/model/route-flow.ts";
import { formatBytes } from "../../../sites/model/units.ts";
import {
  type Issue,
  type RouteIssue,
  validateFlowReferences,
  validateRoute,
  validateRouteSet,
} from "../../../sites/model/validation.ts";
import { Field, NumInput } from "../fields";
import { CryptoEditor } from "./route-crypto";
import {
  AuthBindingGroup,
  AuthRevokeGroup,
  type FlowGroupProps,
  IssuedByGroup,
  PageActionsGroup,
  ResourceGrantGroup,
  SensorHtmlGroup,
} from "./route-flow-groups";

export type DrawerMode = "add" | "edit" | "duplicate";

type Props = {
  open: boolean;
  mode: DrawerMode;
  initial: SiteRouteConfig;
  /** All routes of the draft; for `edit`, `index` is the one being edited. */
  routes: readonly SiteRouteConfig[];
  index: number | null;
  limits: { max_response_body_bytes: number; max_request_body_bytes: number };
  /** The draft cannot be changed now (role, or a write still unresolved): view only. */
  readOnly?: boolean;
  onApply: (route: SiteRouteConfig) => void;
  onClose: () => void;
};

const titles: Record<DrawerMode, string> = {
  add: "新增路由",
  edit: "编辑路由",
  duplicate: "复制路由",
};

const methods = ["GET", "POST", "PUT", "PATCH", "DELETE"] as const;
const admissions: readonly (readonly [RouteAdmission, string, string])[] = [
  ["ui_action_required", "必须有界面操作来源", "请求须带有页面上的操作来源，适合业务页面。"],
  ["authenticated_root", "已认证根", "访问者须持有有效的已认证根凭证。"],
  [
    "auth_entry",
    "认证入口",
    "登录、代码兑换或认证回调：成功验证之前访问者仍是匿名的；开启下方“身份建立”后，成功的登录响应在 edge 建立身份。",
  ],
  ["public", "公开", "任何人都可以访问，不做身份校验。"],
];

/** Defaults a switched-on block starts from (the values typed before switching it off win). */
const fresh: { [K in FlowBlock]: () => NonNullable<SiteRouteConfig[K]> } = {
  auth_binding: emptyAuthBinding,
  auth_revoke: emptyAuthRevoke,
  sensor_html: emptySensorBuild,
  page_actions: emptyPageActions,
  issued_by: () => emptyIssuedBy(),
  resource_grant: () => emptyResourceGrant(),
};

/** Section heading inside the drawer. */
function Group({
  title,
  note,
  children,
}: {
  title: string;
  note?: string;
  children: React.ReactNode;
}) {
  return (
    <section className="xs-drawer-group" aria-label={title}>
      <h4>{title}</h4>
      {note && <p className="muted">{note}</p>}
      {children}
    </section>
  );
}

const key = (issue: RouteIssue) => `${issue.field}\n${issue.message}`;

/** What validation says about the edited route, and what applying it would do to the others. */
function useFindings(
  route: SiteRouteConfig,
  routes: readonly SiteRouteConfig[],
  index: number | null,
  mode: DrawerMode,
  limits: Props["limits"],
) {
  const before = useMemo(
    () => ({ set: validateRouteSet(routes), flow: validateFlowReferences(routes) }),
    [routes],
  );
  return useMemo(() => {
    const editing = mode === "edit" && index !== null;
    const candidate = editing ? index : routes.length;
    const all = editing
      ? routes.map((item, at) => (at === index ? route : item))
      : [...routes, route];
    const set = validateRouteSet(all);
    const flow = validateFlowReferences(all);
    const own: RouteIssue[] = [...validateRoute(route, limits), ...(flow.get(candidate) ?? [])];
    // Conflicts this edit creates on another route block it as much as its own: a duplicate
    // path is reported on the later of the two routes, which may be the other one.
    const conflicts = [...(set.get(candidate) ?? [])];
    const elsewhere: string[] = [];
    all.forEach((item, at) => {
      if (at === candidate) return;
      const name = item.operation_id || `#${at + 1}`;
      const had = new Set(before.set.get(at) ?? []);
      for (const message of set.get(at) ?? []) {
        if (!had.has(message)) conflicts.push(`路由 ${name}：${message}`);
      }
      const hadFlow = new Set((before.flow.get(at) ?? []).map(key));
      for (const issue of flow.get(at) ?? []) {
        if (!hadFlow.has(key(issue))) elsewhere.push(`路由 ${name}：${issue.message}`);
      }
    });
    return {
      own,
      conflicts,
      elsewhere,
      crossFields: new Set((flow.get(candidate) ?? []).map(key)),
    };
  }, [route, routes, index, mode, limits, before]);
}

/**
 * The route editor. It edits a copy: nothing reaches the draft until 应用到草稿, and the same
 * rules the server applies (per route and across routes) are shown as you type, each next to the
 * control that fixes it. Errors on this route and conflicts with other routes block 应用到草稿;
 * the browser provenance-flow references between routes do not, because a page and the actions
 * it issues name each other and are built one route at a time (they still block saving).
 */
export function RouteDrawer({
  open,
  mode,
  initial,
  routes,
  index,
  limits,
  readOnly = false,
  onApply,
  onClose,
}: Props) {
  const [route, setRoute] = useState<SiteRouteConfig>(initial);
  // Blocks the admission or response mode took off the route, restored when it fits again.
  const parked = useRef<FlowStash>({});
  // Values of blocks the operator switched off, so switching back on restores what was typed.
  const typed = useRef<FlowStash>({});
  const patch = (change: Partial<SiteRouteConfig>) =>
    setRoute((current) => ({ ...current, ...change }));

  const { own, conflicts, elsewhere, crossFields } = useFindings(
    route,
    routes,
    index,
    mode,
    limits,
  );
  const issueFor = (field: string): Issue | undefined => {
    const found = own.find((item) => item.field === field);
    return found && { path: field, group: "routes", ...found };
  };
  const blocking =
    own.filter((item) => item.severity === "error" && !crossFields.has(key(item))).length +
    conflicts.length;
  const pending = own.filter((item) => crossFields.has(key(item))).length;
  const ui = route.security_entry === "ui_action_required";
  const self = mode === "edit" ? index : null;
  // Read on every render: each admission or mode switch also sets the route, so this is fresh.
  const parkedLabels = (Object.keys(parked.current) as FlowBlock[]).map(
    (block) => flowBlockLabel[block],
  );

  const flow: FlowGroupProps = {
    route,
    routes,
    self,
    issueFor,
    disabled: readOnly,
    onToggle: (block, on) => {
      if (on) {
        setRoute(withBlock(route, block, typed.current[block] ?? fresh[block]()));
        return;
      }
      typed.current = { ...typed.current, [block]: route[block] };
      setRoute(withBlock(route, block, undefined));
    },
    onBlock: (block, value) => setRoute((current) => withBlock(current, block, value)),
    onBuilds: (builds) => setRoute((current) => withSensorBuilds(current, builds)),
  };

  return (
    <Drawer
      open={open}
      title={titles[mode]}
      size={600}
      // Like the other drawers of the console: never wider than a phone screen.
      styles={{ wrapper: { maxWidth: "100vw" } }}
      destroyOnHidden
      onClose={onClose}
      footer={
        <div className="xs-drawer-footer">
          {pending > 0 && !readOnly && (
            <span className="xs-drawer-pending">
              还有 {pending} 项跨路由问题，可以先应用，保存前须解决
            </span>
          )}
          <Button onClick={onClose}>{readOnly ? "关闭" : "取消"}</Button>
          {!readOnly && (
            <Button type="primary" disabled={blocking > 0} onClick={() => onApply(route)}>
              应用到草稿
            </Button>
          )}
        </div>
      }
    >
      <Form layout="vertical" className="xs-form" disabled={readOnly}>
        {conflicts.length > 0 && (
          <ul className="xs-issue-list" aria-label="路由冲突">
            {conflicts.map((message) => (
              <li key={message}>{message}</li>
            ))}
          </ul>
        )}
        {elsewhere.length > 0 && (
          <div className="xs-drawer-elsewhere">
            <p>应用后其他路由会出现的问题（保存前须解决）：</p>
            <ul className="xs-issue-list" aria-label="对其他路由的影响">
              {elsewhere.map((message) => (
                <li key={message}>{message}</li>
              ))}
            </ul>
          </div>
        )}
        {parkedLabels.length > 0 && (
          <p className="xs-drawer-parked" role="note">
            已收起不适用于当前准入或响应模式的设置：{parkedLabels.join("、")}
            。应用到草稿时它们不会保存；切回原来的准入或响应模式即可恢复。
          </p>
        )}
        <Group title="匹配" note="哪些请求命中这条路由。未声明的 HTTP 操作继续被拒绝。">
          <Field id="route-method" group label="方法" issue={issueFor("method")}>
            <Radio.Group
              aria-label="方法"
              value={route.method}
              onChange={(event) => patch({ method: event.target.value })}
            >
              {methods.map((method) => (
                <Radio.Button key={method} value={method}>
                  {method}
                </Radio.Button>
              ))}
            </Radio.Group>
          </Field>
          <Field
            id="route-path"
            label="路径"
            required
            issue={issueFor("path")}
            hint="固定路径，例如 /api/orders。按资源路径绑定时以 {参数} 结尾，例如 /api/orders/{order_id}（并填写下方“资源路径字段”）。只能是可打印 ASCII，不含 ? 或 #。"
          >
            <Input
              value={route.path}
              maxLength={256}
              spellCheck={false}
              onChange={(event) => patch({ path: event.target.value })}
            />
          </Field>
          <Field
            id="route-operation"
            label="操作 ID"
            required
            issue={issueFor("operation_id")}
            hint="路由的稳定标识，审计和调查里按它引用，例如 orders.get；字母、数字和 _ . -，不能与其他路由重复。其他路由的签发页面与资源资格目标按它引用这条路由。"
          >
            <Input
              value={route.operation_id}
              maxLength={128}
              spellCheck={false}
              onChange={(event) => patch({ operation_id: event.target.value })}
            />
          </Field>
        </Group>

        <Group
          title="准入"
          note="请求要满足什么才能进入。降低准入（例如改为公开）属于安全相关变更，需要审批。切换准入时，不适用的流程设置会暂时收起，切回来即恢复。"
        >
          <Field id="route-admission" group label="安全入口" issue={issueFor("security_entry")}>
            <Radio.Group
              aria-label="路由安全入口"
              className="xs-choice"
              value={route.security_entry}
              onChange={(event) => {
                const next = withAdmission(route, event.target.value, parked.current);
                parked.current = next.stash;
                setRoute(next.route);
              }}
            >
              {admissions.map(([value, title, hint]) => (
                <Radio key={value} value={value}>
                  <span className="xs-choice-title">{title}</span>
                  <span className="xs-choice-hint">{hint}</span>
                </Radio>
              ))}
            </Radio.Group>
          </Field>
          <Field
            id="route-source"
            label="操作来源"
            required={ui}
            issue={issueFor("source_action")}
            hint="界面操作来源标识，例如 orders.open。只有“必须有界面操作来源”的路由才有，其他准入留空。"
          >
            <Input
              disabled={!ui}
              value={route.source_action ?? ""}
              maxLength={128}
              spellCheck={false}
              onChange={(event) => patch({ source_action: event.target.value || null })}
            />
          </Field>
        </Group>

        <AuthBindingGroup {...flow} />

        <Group
          title="资源"
          note="可选：把请求绑定到一类业务对象。绑定时路由必须是 GET + 必须有界面操作来源，同时填写资源类型与视图 profile，且查询字段与路径字段二选一。清空四项即不绑定。"
        >
          <Field
            id="route-resource-type"
            label="资源类型"
            issue={issueFor("resource_type")}
            hint="例如 order：被访问对象的类型。"
          >
            <Input
              value={route.resource_type ?? ""}
              maxLength={128}
              spellCheck={false}
              onChange={(event) => patch({ resource_type: event.target.value || null })}
            />
          </Field>
          <Field
            id="route-view-profile"
            label="视图 profile"
            issue={issueFor("view_profile")}
            hint="例如 customer：以哪种视图呈现和校验该资源。"
          >
            <Input
              value={route.view_profile ?? ""}
              maxLength={128}
              spellCheck={false}
              onChange={(event) => patch({ view_profile: event.target.value || null })}
            />
          </Field>
          <Field
            id="route-query-parameter"
            label="资源查询字段"
            issue={issueFor("resource_query_parameter")}
            hint="资源 ID 出现在查询串里的字段名，例如 order_id（与路径字段二选一）。"
          >
            <Input
              value={route.resource_query_parameter ?? ""}
              maxLength={128}
              spellCheck={false}
              onChange={(event) => patch({ resource_query_parameter: event.target.value || null })}
            />
          </Field>
          <Field
            id="route-path-parameter"
            label="资源路径字段"
            issue={issueFor("resource_path_parameter")}
            hint="资源 ID 出现在路径 {参数} 里的参数名，例如 order_id；路径必须以 {order_id} 结尾。"
          >
            <Input
              value={route.resource_path_parameter ?? ""}
              maxLength={128}
              spellCheck={false}
              onChange={(event) => patch({ resource_path_parameter: event.target.value || null })}
            />
          </Field>
        </Group>

        <IssuedByGroup {...flow} />

        <Group
          title="响应"
          note="edge 如何处理源站的响应。SENSOR_HTML 只放行预先批准、按摘要固定的静态页面，并注入浏览器探针。"
        >
          <Field id="route-response-mode" group label="响应模式" issue={issueFor("response_mode")}>
            <Radio.Group
              aria-label="响应模式"
              value={route.response_mode}
              onChange={(event) => {
                const next = withResponseMode(route, event.target.value, parked.current);
                parked.current = next.stash;
                setRoute(next.route);
              }}
            >
              <Radio.Button value="">透传</Radio.Button>
              <Radio.Button value="BUFFERED_JSON">BUFFERED_JSON</Radio.Button>
              <Radio.Button value="SENSOR_HTML">SENSOR_HTML</Radio.Button>
            </Radio.Group>
          </Field>
          <Field
            id="route-max-response"
            label="响应上限"
            issue={issueFor("max_response_bytes")}
            hint={`1 字节到 16 MiB，且不超过站点响应体上限（${formatBytes(limits.max_response_body_bytes)}）。当前 = ${formatBytes(route.max_response_bytes)}。`}
          >
            <NumInput
              value={route.max_response_bytes}
              min={1}
              max={16_777_216}
              unit="字节"
              onChange={(value) => patch({ max_response_bytes: value })}
            />
          </Field>
        </Group>

        <SensorHtmlGroup {...flow} />
        <PageActionsGroup {...flow} />
        <ResourceGrantGroup {...flow} />
        <AuthRevokeGroup {...flow} />

        <Group
          title="加密"
          note="请求体解密与响应加密。仅在需要时启用；密钥正文由部署侧提供，这里只填标识。"
        >
          <CryptoEditor
            kind="request"
            value={route.request_crypto}
            maxResponseBytes={route.max_response_bytes}
            maxRequestBytes={limits.max_request_body_bytes}
            issue={issueFor("request_crypto")}
            onChange={(next) => patch({ request_crypto: next })}
          />
          <CryptoEditor
            kind="response"
            value={route.response_crypto}
            maxResponseBytes={route.max_response_bytes}
            maxRequestBytes={limits.max_request_body_bytes}
            issue={issueFor("response_crypto")}
            onChange={(next) => patch({ response_crypto: next })}
          />
        </Group>
      </Form>
    </Drawer>
  );
}
