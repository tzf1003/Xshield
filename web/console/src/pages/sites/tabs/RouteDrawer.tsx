import { Button, Drawer, Form, Input, Radio } from "antd";
import { useMemo, useState } from "react";
import type { SiteRouteConfig } from "../../../api.ts";
import { formatBytes } from "../../../sites/model/units.ts";
import { type Issue, validateRoute, validateRouteSet } from "../../../sites/model/validation.ts";
import { Field, NumInput } from "../fields";

export type DrawerMode = "add" | "edit" | "duplicate";

type Props = {
  open: boolean;
  mode: DrawerMode;
  initial: SiteRouteConfig;
  /** All routes of the draft; for `edit`, `index` is the one being edited. */
  routes: readonly SiteRouteConfig[];
  index: number | null;
  limits: { max_response_body_bytes: number; max_request_body_bytes: number };
  onApply: (route: SiteRouteConfig) => void;
  onClose: () => void;
};

const titles: Record<DrawerMode, string> = {
  add: "新增路由",
  edit: "编辑路由",
  duplicate: "复制路由",
};

const methods = ["GET", "POST", "PUT", "PATCH", "DELETE"] as const;
const admissions = [
  ["ui_action_required", "必须有界面操作来源", "请求须带有页面上的操作来源，适合业务页面。"],
  ["authenticated_root", "已认证根", "访问者须持有有效的已认证根凭证。"],
  ["public", "公开", "任何人都可以访问，不做身份校验。"],
] as const;

const seconds = (value: unknown) => {
  const n = typeof value === "number" ? value : Number.NaN;
  return Number.isFinite(n) && n >= 0 && n < 8.64e12 / 1000
    ? `${new Date(n * 1000).toISOString().slice(0, 19).replace("T", " ")} UTC`
    : "—";
};
const num = (value: unknown): number => (typeof value === "number" ? value : Number.NaN);
const str = (value: unknown): string => (typeof value === "string" ? value : "");

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

type Crypto = Record<string, unknown> | null;

/** Request/response encryption: a mode, then only the fields that mode has. */
function CryptoEditor({
  kind,
  value,
  maxResponseBytes,
  maxRequestBytes,
  issue,
  onChange,
}: {
  kind: "request" | "response";
  value: Crypto;
  maxResponseBytes: number;
  maxRequestBytes: number;
  issue: Issue | undefined;
  onChange: (next: Crypto) => void;
}) {
  const now = Math.floor(Date.now() / 1000);
  const mode = value === null ? "NONE" : str(value.mode) || "DIRECT_ENCRYPT";
  const patch = (change: Record<string, unknown>) => onChange({ ...(value ?? {}), ...change });
  const base = kind === "request" ? "req" : "res";
  function choose(next: string) {
    if (next === "NONE") onChange(null);
    else if (next === "OBSERVE") onChange({ mode: "OBSERVE", adapter_revision: "" });
    else if (next === "DIRECT_DECRYPT") {
      onChange({
        mode: "DIRECT_DECRYPT",
        adapter_revision: "",
        key_id: "",
        key_not_before: now,
        key_expires_at: now + 365 * 86_400,
        max_envelope_bytes: Math.min(65_536, maxRequestBytes),
        max_plaintext_bytes: Math.min(32_768, Math.floor(maxRequestBytes / 2)),
        max_message_age_seconds: 300,
        max_future_skew_seconds: 30,
        max_active_messages: 1000,
      });
    } else {
      onChange({
        mode: "DIRECT_ENCRYPT",
        adapter_revision: "",
        key_id: "",
        key_not_before: now,
        key_expires_at: now + 365 * 86_400,
        message_ttl_seconds: 300,
        max_envelope_bytes: maxResponseBytes * 2 + 1024,
      });
    }
  }
  const options =
    kind === "request"
      ? ([
          ["NONE", "无"],
          ["OBSERVE", "仅观察信封"],
          ["DIRECT_DECRYPT", "直接解密"],
        ] as const)
      : ([
          ["NONE", "无"],
          ["DIRECT_ENCRYPT", "直接加密"],
        ] as const);
  return (
    <>
      <Field
        id={`${base}-crypto-mode`}
        group
        label={kind === "request" ? "请求加密" : "响应加密"}
        issue={issue}
      >
        <Radio.Group
          aria-label={kind === "request" ? "请求加密" : "响应加密"}
          value={mode}
          onChange={(event) => choose(event.target.value)}
        >
          {options.map(([option, label]) => (
            <Radio.Button key={option} value={option}>
              {label}
            </Radio.Button>
          ))}
        </Radio.Group>
      </Field>
      {value !== null && (
        <div className="xs-crypto-fields">
          <Field
            id={`${base}-crypto-adapter`}
            label="适配器版本"
            hint="字母、数字和 _ . -，例如 envelope-v1。"
          >
            <Input
              value={str(value.adapter_revision)}
              spellCheck={false}
              onChange={(event) => patch({ adapter_revision: event.target.value })}
            />
          </Field>
          {mode !== "OBSERVE" && (
            <>
              <Field
                id={`${base}-crypto-key`}
                label="Key ID"
                hint="部署侧管理的密钥标识；每站点最多一把请求解密密钥和一把响应加密密钥，且不得共用。"
              >
                <Input
                  value={str(value.key_id)}
                  spellCheck={false}
                  onChange={(event) => patch({ key_id: event.target.value })}
                />
              </Field>
              <Field
                id={`${base}-crypto-from`}
                label="密钥生效时间"
                hint={`Unix 秒。= ${seconds(value.key_not_before)}`}
              >
                <NumInput
                  value={num(value.key_not_before)}
                  min={0}
                  unit="秒"
                  onChange={(next) => patch({ key_not_before: next })}
                />
              </Field>
              <Field
                id={`${base}-crypto-until`}
                label="密钥失效时间"
                hint={`Unix 秒，须晚于生效时间。= ${seconds(value.key_expires_at)}`}
              >
                <NumInput
                  value={num(value.key_expires_at)}
                  min={0}
                  unit="秒"
                  onChange={(next) => patch({ key_expires_at: next })}
                />
              </Field>
              <Field
                id={`${base}-crypto-envelope`}
                label="信封上限"
                hint={
                  kind === "request"
                    ? `最大 64 KiB 且不超过请求体上限。当前 = ${formatBytes(num(value.max_envelope_bytes))}。`
                    : `不小于两倍响应上限加 1024 字节（${formatBytes(maxResponseBytes * 2 + 1024)}）。当前 = ${formatBytes(num(value.max_envelope_bytes))}。`
                }
              >
                <NumInput
                  value={num(value.max_envelope_bytes)}
                  min={1}
                  unit="字节"
                  onChange={(next) => patch({ max_envelope_bytes: next })}
                />
              </Field>
            </>
          )}
          {mode === "DIRECT_DECRYPT" && (
            <>
              <Field
                id="req-crypto-plain"
                label="明文上限"
                hint="不超过信封的一半，也不超过请求体上限。"
              >
                <NumInput
                  value={num(value.max_plaintext_bytes)}
                  min={1}
                  unit="字节"
                  onChange={(next) => patch({ max_plaintext_bytes: next })}
                />
              </Field>
              <Field id="req-crypto-age" label="消息有效期" hint="1–3600 秒。">
                <NumInput
                  value={num(value.max_message_age_seconds)}
                  min={1}
                  max={3600}
                  unit="秒"
                  onChange={(next) => patch({ max_message_age_seconds: next })}
                />
              </Field>
              <Field
                id="req-crypto-skew"
                label="允许的未来偏差"
                hint="0–300 秒，容忍客户端时钟快于服务端的时间。"
              >
                <NumInput
                  value={num(value.max_future_skew_seconds)}
                  min={0}
                  max={300}
                  unit="秒"
                  onChange={(next) => patch({ max_future_skew_seconds: next })}
                />
              </Field>
              <Field
                id="req-crypto-active"
                label="同时有效的消息数"
                hint="1–1,000,000，用于重放保护的容量。"
              >
                <NumInput
                  value={num(value.max_active_messages)}
                  min={1}
                  max={1_000_000}
                  onChange={(next) => patch({ max_active_messages: next })}
                />
              </Field>
            </>
          )}
          {mode === "DIRECT_ENCRYPT" && (
            <Field id="res-crypto-ttl" label="消息有效期" hint="1–3600 秒。">
              <NumInput
                value={num(value.message_ttl_seconds)}
                min={1}
                max={3600}
                unit="秒"
                onChange={(next) => patch({ message_ttl_seconds: next })}
              />
            </Field>
          )}
        </div>
      )}
    </>
  );
}

/**
 * The route editor. It edits a copy: nothing reaches the draft until 应用到草稿, and the same
 * rules the server applies (per route and across routes) are shown as you type.
 */
export function RouteDrawer({
  open,
  mode,
  initial,
  routes,
  index,
  limits,
  onApply,
  onClose,
}: Props) {
  const [route, setRoute] = useState<SiteRouteConfig>(initial);
  const patch = (change: Partial<SiteRouteConfig>) =>
    setRoute((current) => ({ ...current, ...change }));

  const { issues, crossIssues } = useMemo(() => {
    const candidate = mode === "edit" && index !== null ? index : routes.length;
    const all =
      mode === "edit" && index !== null
        ? routes.map((item, at) => (at === index ? route : item))
        : [...routes, route];
    const per: Issue[] = validateRoute(route, limits).map((item) => ({
      path: item.field,
      group: "routes",
      severity: item.severity,
      message: item.message,
    }));
    const across: Issue[] = (validateRouteSet(all).get(candidate) ?? []).map((message) => ({
      path: "set",
      group: "routes",
      severity: "error",
      message,
    }));
    return { issues: per, crossIssues: across };
  }, [route, routes, index, mode, limits]);
  const issueFor = (field: string) => issues.find((item) => item.path === field);
  const blocking = issues.filter((item) => item.severity === "error").length + crossIssues.length;
  const ui = route.security_entry === "ui_action_required";

  return (
    <Drawer
      open={open}
      title={titles[mode]}
      size={560}
      destroyOnHidden
      onClose={onClose}
      footer={
        <div className="xs-drawer-footer">
          <Button onClick={onClose}>取消</Button>
          <Button type="primary" disabled={blocking > 0} onClick={() => onApply(route)}>
            应用到草稿
          </Button>
        </div>
      }
    >
      <Form layout="vertical" className="xs-form">
        {crossIssues.length > 0 && (
          <ul className="xs-issue-list" aria-label="路由冲突">
            {crossIssues.map((item) => (
              <li key={item.message}>{item.message}</li>
            ))}
          </ul>
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
            hint="路由的稳定标识，审计和调查里按它引用，例如 orders.get；字母、数字和 _ . : -，不能与其他路由重复。"
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
          note="请求要满足什么才能进入。降低准入（例如改为公开）属于安全相关变更，需要审批。"
        >
          <Field id="route-admission" group label="安全入口" issue={issueFor("security_entry")}>
            <Radio.Group
              aria-label="路由安全入口"
              className="xs-choice"
              value={route.security_entry}
              onChange={(event) => {
                const security_entry = event.target.value as SiteRouteConfig["security_entry"];
                patch({
                  security_entry,
                  source_action:
                    security_entry === "ui_action_required"
                      ? route.source_action || `${route.operation_id || "route"}.open`
                      : null,
                });
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

        <Group title="响应" note="edge 如何处理源站的响应。">
          <Field id="route-response-mode" group label="响应模式" issue={issueFor("response_mode")}>
            <Radio.Group
              aria-label="响应模式"
              value={route.response_mode}
              onChange={(event) => patch({ response_mode: event.target.value })}
            >
              <Radio.Button value="">透传</Radio.Button>
              <Radio.Button value="BUFFERED_JSON">BUFFERED_JSON</Radio.Button>
              {route.response_mode === "SENSOR_HTML" && (
                <Radio.Button value="SENSOR_HTML">SENSOR_HTML</Radio.Button>
              )}
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
