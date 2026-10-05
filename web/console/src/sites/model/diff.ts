import type { SiteRouteConfig, SiteSecretReference } from "../../api.ts";
import type { RiskToken } from "../../ui/reason-codes.ts";
import {
  canonicalJson,
  effectivePolicy,
  routeAdmissionLabel,
  type SiteConfigDraft,
  securityEntryLabel,
  statusLabel,
} from "./config.ts";
import { formatBytes, formatMillis, formatSeconds } from "./units.ts";

/** The editor tab that owns a field; the change bar groups unsaved edits by it. */
export type ChangeGroup =
  | "network"
  | "security-entry"
  | "routes"
  | "identity"
  | "crypto"
  | "waf-limits"
  | "policies";

export const groupLabel: Record<ChangeGroup, string> = {
  network: "网络",
  "security-entry": "安全入口",
  routes: "路由与操作",
  identity: "身份",
  crypto: "加密",
  "waf-limits": "WAF 与限流",
  policies: "策略与健康",
};

export type FieldChange = Readonly<{
  /** Stable key, for example `public_origin` or `routes[orders.get].path`. */
  id: string;
  group: ChangeGroup;
  /** The field in operators' words. */
  label: string;
  before: string;
  after: string;
  kind: "changed" | "added" | "removed";
  /**
   * The approval reason this field falls under (`assess_change_risk` categories), or `null` for
   * the fields that may change freely: the display name, the policy label and ordering.
   */
  risk: RiskToken | null;
}>;

type Scalar = string | number | boolean | string[] | null;
const EMPTY = "（空）";

const text = (value: Scalar): string =>
  value === null || value === "" ? EMPTY : Array.isArray(value) ? list(value) : String(value);
const list = (value: Scalar): string =>
  Array.isArray(value) && value.length > 0 ? value.join("、") : EMPTY;
const onOff = (value: Scalar): string => (value === true ? "启用" : "停用");
const bytes = (value: Scalar): string =>
  typeof value === "number" ? formatBytes(value) : text(value);
const seconds = (value: Scalar): string =>
  typeof value === "number" ? formatSeconds(value) : text(value);
const millis = (value: Scalar): string =>
  typeof value === "number" ? formatMillis(value) : text(value);

type Spec = Readonly<{
  id: string;
  label: string;
  group: ChangeGroup;
  risk: RiskToken | null;
  get: (draft: SiteConfigDraft) => Scalar;
  format: (value: Scalar) => string;
}>;

const spec = (
  id: string,
  label: string,
  group: ChangeGroup,
  risk: RiskToken | null,
  get: Spec["get"],
  format: Spec["format"] = text,
): Spec => ({ id, label, group, risk, get, format });

const entryText = (value: Scalar) =>
  typeof value === "string" && value in securityEntryLabel
    ? securityEntryLabel[value as keyof typeof securityEntryLabel]
    : text(value);

const scalarSpecs: readonly Spec[] = [
  spec("display_name", "站点名称", "network", null, (d) => d.display_name),
  spec("public_origin", "公网入口", "network", "ORIGIN_CHANGED", (d) => d.public_origin),
  spec("upstream_address", "源站地址", "network", "UPSTREAM_CHANGED", (d) => d.upstream_address),
  spec(
    "upstream_server_name",
    "源站 Server Name",
    "network",
    "UPSTREAM_CHANGED",
    (d) => d.upstream_server_name,
  ),
  spec("upstream_tls", "上游 TLS", "network", "UPSTREAM_CHANGED", (d) => d.upstream_tls, onOff),
  spec(
    "listen_port",
    "监听端口",
    "network",
    "LISTEN_PORT_CHANGED",
    (d) => d.listen_port,
    (v) => (v === 0 ? "自动分配" : text(v)),
  ),
  spec("entry_path", "入口路径", "network", "ENTRY_CHANGED", (d) => d.entry_path),
  spec(
    "security_entry",
    "安全入口",
    "security-entry",
    "ENTRY_CHANGED",
    (d) => d.security_entry,
    entryText,
  ),
  spec(
    "sensor_enabled",
    "浏览器探针",
    "security-entry",
    "SENSOR_CHANGED",
    (d) => d.sensor_enabled,
    onOff,
  ),
  spec("policy_revision", "策略版本", "security-entry", null, (d) => d.policy_revision),
  spec(
    "status",
    "站点状态",
    "security-entry",
    null,
    (d) => d.status,
    (v) =>
      typeof v === "string" && v in statusLabel
        ? statusLabel[v as keyof typeof statusLabel]
        : text(v),
  ),
  spec(
    "identity.enabled",
    "启用身份绑定",
    "identity",
    "IDENTITY_CHANGED",
    (d) => d.policy.identity.enabled,
    onOff,
  ),
  spec(
    "identity.profile",
    "身份 profile",
    "identity",
    "IDENTITY_CHANGED",
    (d) => d.policy.identity.profile,
  ),
  spec(
    "identity.cookie_name",
    "会话 Cookie",
    "identity",
    "IDENTITY_CHANGED",
    (d) => d.policy.identity.cookie_name,
  ),
  spec(
    "identity.credential_header",
    "业务凭证头",
    "identity",
    "IDENTITY_CHANGED",
    (d) => d.policy.identity.credential_header,
  ),
  spec(
    "identity.session_ttl_seconds",
    "会话期限",
    "identity",
    "IDENTITY_CHANGED",
    (d) => d.policy.identity.session_ttl_seconds,
    seconds,
  ),
  spec(
    "identity.generation",
    "身份代际",
    "identity",
    "IDENTITY_CHANGED",
    (d) => d.policy.identity.generation,
  ),
  spec(
    "crypto.adapter_revision",
    "协议适配器",
    "crypto",
    "CRYPTO_CHANGED",
    (d) => d.policy.crypto.adapter_revision,
  ),
  spec(
    "crypto.failure_strategy",
    "失败策略",
    "crypto",
    "CRYPTO_CHANGED",
    (d) => d.policy.crypto.failure_strategy,
    (v) => (v === "fail_closed" ? "严格拒绝" : v === "observe" ? "仅观察" : text(v)),
  ),
  spec(
    "crypto.protocol_version",
    "协议版本",
    "crypto",
    "CRYPTO_CHANGED",
    (d) => d.policy.crypto.protocol_version,
  ),
  spec(
    "waf.enabled",
    "启用基础 WAF",
    "waf-limits",
    "WAF_CHANGED",
    (d) => d.policy.waf.enabled,
    onOff,
  ),
  spec(
    "waf.blocked_headers",
    "拦截请求头",
    "waf-limits",
    "WAF_CHANGED",
    (d) => d.policy.waf.blocked_headers,
    list,
  ),
  spec(
    "waf.blocked_query_fragments",
    "查询阻断片段",
    "waf-limits",
    "WAF_CHANGED",
    (d) => d.policy.waf.blocked_query_fragments,
    list,
  ),
  spec(
    "waf.max_cookie_bytes",
    "Cookie 上限",
    "waf-limits",
    "WAF_CHANGED",
    (d) => d.policy.waf.max_cookie_bytes,
    bytes,
  ),
  spec(
    "limits.max_request_body_bytes",
    "请求体上限",
    "waf-limits",
    "LIMITS_CHANGED",
    (d) => d.policy.limits.max_request_body_bytes,
    bytes,
  ),
  spec(
    "limits.max_response_body_bytes",
    "响应体上限",
    "waf-limits",
    "LIMITS_CHANGED",
    (d) => d.policy.limits.max_response_body_bytes,
    bytes,
  ),
  spec(
    "limits.requests_per_second",
    "每秒请求数",
    "waf-limits",
    "LIMITS_CHANGED",
    (d) => d.policy.limits.requests_per_second,
  ),
  spec("limits.burst", "突发容量", "waf-limits", "LIMITS_CHANGED", (d) => d.policy.limits.burst),
  spec(
    "health_check.path",
    "健康检查路径",
    "policies",
    "HEALTH_CHECK_CHANGED",
    (d) => d.policy.health_check.path,
  ),
  spec(
    "health_check.interval_seconds",
    "检查间隔",
    "policies",
    "HEALTH_CHECK_CHANGED",
    (d) => d.policy.health_check.interval_seconds,
    seconds,
  ),
  spec(
    "health_check.timeout_ms",
    "检查超时",
    "policies",
    "HEALTH_CHECK_CHANGED",
    (d) => d.policy.health_check.timeout_ms,
    millis,
  ),
  spec(
    "health_check.expected_status",
    "期望状态码",
    "policies",
    "HEALTH_CHECK_CHANGED",
    (d) => d.policy.health_check.expected_status,
  ),
  spec(
    "static_asset_max_path_depth",
    "静态资源兜底深度",
    "policies",
    "STATIC_ASSET_POLICY_CHANGED",
    (d) => d.policy.static_asset_max_path_depth,
    (v) => (v === 0 ? "关闭" : text(v)),
  ),
  spec(
    "origin_object_access_enforced",
    "源站对象级校验标记",
    "policies",
    "OBJECT_ACCESS_CHANGED",
    (d) => d.policy.origin_object_access_enforced,
    onOff,
  ),
];

const summarizeCrypto = (value: Record<string, unknown> | null): string => {
  if (value === null) return "（无）";
  const mode = typeof value.mode === "string" ? value.mode : "";
  const adapter = typeof value.adapter_revision === "string" ? value.adapter_revision : "";
  const key = typeof value.key_id === "string" ? value.key_id : "";
  return [mode, adapter, key && `Key ${key}`].filter(Boolean).join(" · ") || canonicalJson(value);
};

const modeLabel = (mode: string) => (mode === "" ? "透传" : mode);

const none = "（无）";

/** One-line summaries of the provenance-flow blocks; the raw JSON is shown when they tie. */
const summarizeBinding = (r: SiteRouteConfig) =>
  r.auth_binding
    ? `${r.auth_binding.success_status} · 凭证 ${formatSeconds(r.auth_binding.credential_ttl_seconds)} · 会话 ${formatSeconds(r.auth_binding.session_ttl_seconds)}`
    : none;
const summarizeRevoke = (r: SiteRouteConfig) =>
  r.auth_revoke ? `成功状态 ${r.auth_revoke.success_status}` : none;
const summarizeSensor = (r: SiteRouteConfig) =>
  r.sensor_html
    ? `${r.sensor_html.adapter_revision} · ${r.sensor_html.origin_sha256.slice(0, 12)}… · 共 ${1 + (r.sensor_html.additional_adapters?.length ?? 0)} 个构建`
    : none;
const summarizePage = (r: SiteRouteConfig) =>
  r.page_actions
    ? `映射 ${r.page_actions.mapping_revision} · 活动页面 ≤ ${r.page_actions.max_active_pages}`
    : none;
const summarizeIssued = (r: SiteRouteConfig) =>
  r.issued_by
    ? `${r.issued_by.page_operation_id} · ${formatSeconds(r.issued_by.ttl_seconds)}`
    : none;
const summarizeGrant = (r: SiteRouteConfig) =>
  r.resource_grant
    ? `→ ${r.resource_grant.target_operation_id}（${r.resource_grant.target_mapping_revision}）· ≤ ${r.resource_grant.max_items} 项 · ${formatSeconds(r.resource_grant.ttl_seconds)}`
    : none;

type RouteSpec = Readonly<{
  id: keyof SiteRouteConfig;
  label: string;
  format: (route: SiteRouteConfig) => string;
  /** The facet a change of this field falls under; `ROUTES_CHANGED` when absent. */
  risk?: RiskToken;
}>;
/**
 * Every route field the server stores. Keep in step with `SiteRouteConfig`: a field missing
 * here would change without ever appearing in a diff or an approval summary.
 */
const routeSpecs: readonly RouteSpec[] = [
  { id: "method", label: "方法", format: (r) => r.method },
  { id: "path", label: "路径", format: (r) => r.path },
  { id: "security_entry", label: "准入", format: (r) => routeAdmissionLabel[r.security_entry] },
  { id: "source_action", label: "操作来源", format: (r) => text(r.source_action) },
  { id: "resource_type", label: "资源类型", format: (r) => text(r.resource_type) },
  { id: "view_profile", label: "视图 profile", format: (r) => text(r.view_profile) },
  {
    id: "resource_query_parameter",
    label: "资源查询字段",
    format: (r) => text(r.resource_query_parameter),
  },
  {
    id: "resource_path_parameter",
    label: "资源路径字段",
    format: (r) => text(r.resource_path_parameter),
  },
  { id: "request_crypto", label: "请求加密", format: (r) => summarizeCrypto(r.request_crypto) },
  { id: "response_crypto", label: "响应加密", format: (r) => summarizeCrypto(r.response_crypto) },
  { id: "response_mode", label: "响应模式", format: (r) => modeLabel(r.response_mode) },
  { id: "max_response_bytes", label: "响应上限", format: (r) => formatBytes(r.max_response_bytes) },
  {
    id: "auth_binding",
    label: "身份建立",
    format: summarizeBinding,
    risk: "AUTH_ENTRY_CHANGED",
  },
  { id: "auth_revoke", label: "身份撤销", format: summarizeRevoke, risk: "AUTH_ENTRY_CHANGED" },
  {
    id: "sensor_html",
    label: "SENSOR_HTML 页面构建",
    format: summarizeSensor,
    risk: "SENSOR_HTML_CHANGED",
  },
  { id: "page_actions", label: "页面签发", format: summarizePage, risk: "PAGE_ACTIONS_CHANGED" },
  { id: "issued_by", label: "签发页面", format: summarizeIssued, risk: "PAGE_ACTIONS_CHANGED" },
  {
    id: "resource_grant",
    label: "响应资源资格",
    format: summarizeGrant,
    risk: "RESOURCE_GRANT_CHANGED",
  },
];

const routeSummary = (route: SiteRouteConfig) =>
  `${route.method} ${route.path} · ${routeAdmissionLabel[route.security_entry]}`;

const secretKindLabel: Record<SiteSecretReference["kind"], string> = {
  tls: "TLS",
  session_hmac: "会话 HMAC",
  request_crypto: "请求加密",
  response_crypto: "响应加密",
  model: "模型",
};

const secretSpecs: readonly (readonly [keyof SiteSecretReference, string])[] = [
  ["secret_ref", "引用"],
  ["key_id", "Key ID"],
  ["state", "状态"],
];

const secretSummary = (secret: SiteSecretReference) =>
  `${secret.secret_ref} · ${secret.key_id} · ${secret.state}`;

/** What serving means for the approval rules: only `active` configurations are served. */
export const isServing = (draft: Pick<SiteConfigDraft, "status">) => draft.status === "active";

function statusRisk(before: SiteConfigDraft, after: SiteConfigDraft): RiskToken | null {
  if (isServing(after) && !isServing(before)) return "ACTIVATION";
  if (!isServing(after) && isServing(before)) return "TAKEDOWN";
  return null;
}

/**
 * Field-level differences between two configurations, in operators' words. Routes are matched
 * by operation ID and secret references by kind (their order is cosmetic, as it is for the
 * server's approval rule); the entry route that the server derives when no route is configured
 * is compared like any other. Used for the unsaved-edit summary, the save diff and the release
 * explanation, so all three always agree.
 */
export function diffConfigs(before: SiteConfigDraft, after: SiteConfigDraft): FieldChange[] {
  const changes: FieldChange[] = [];
  for (const field of scalarSpecs) {
    const was = field.get(before);
    const now = field.get(after);
    if (canonicalJson(was) === canonicalJson(now)) continue;
    changes.push({
      id: field.id,
      group: field.group,
      label: field.label,
      before: field.format(was),
      after: field.format(now),
      kind: "changed",
      risk: field.id === "status" ? statusRisk(before, after) : field.risk,
    });
  }

  const oldRoutes = new Map(
    effectivePolicy(before).routes.map((route) => [route.operation_id, route]),
  );
  const newRoutes = new Map(
    effectivePolicy(after).routes.map((route) => [route.operation_id, route]),
  );
  for (const [id, route] of newRoutes) {
    const previous = oldRoutes.get(id);
    const name = id === "" ? "（未命名路由）" : id;
    if (!previous) {
      changes.push({
        id: `routes[${id}]`,
        group: "routes",
        label: `路由 ${name}`,
        before: "（无）",
        after: routeSummary(route),
        kind: "added",
        risk: "ROUTES_CHANGED",
      });
      continue;
    }
    for (const field of routeSpecs) {
      // Compare the raw values: a summary (crypto) can read the same while a field it omits moved.
      if (canonicalJson(previous[field.id]) === canonicalJson(route[field.id])) continue;
      let was = field.format(previous);
      let now = field.format(route);
      if (was === now) {
        was = canonicalJson(previous[field.id]);
        now = canonicalJson(route[field.id]);
      }
      changes.push({
        id: `routes[${id}].${field.id}`,
        group: "routes",
        label: `路由 ${name} · ${field.label}`,
        before: was,
        after: now,
        kind: "changed",
        risk: field.risk ?? "ROUTES_CHANGED",
      });
    }
  }
  for (const [id, route] of oldRoutes) {
    if (!newRoutes.has(id)) {
      changes.push({
        id: `routes[${id}]`,
        group: "routes",
        label: `路由 ${id === "" ? "（未命名路由）" : id}`,
        before: routeSummary(route),
        after: "（已移除）",
        kind: "removed",
        risk: "ROUTES_CHANGED",
      });
    }
  }

  const oldSecrets = new Map(before.policy.secret_refs.map((secret) => [secret.kind, secret]));
  const newSecrets = new Map(after.policy.secret_refs.map((secret) => [secret.kind, secret]));
  for (const [kind, secret] of newSecrets) {
    const previous = oldSecrets.get(kind);
    const name = `密钥引用 ${secretKindLabel[kind]}`;
    if (!previous) {
      changes.push({
        id: `secret_refs[${kind}]`,
        group: "crypto",
        label: name,
        before: "（无）",
        after: secretSummary(secret),
        kind: "added",
        risk: "SECRET_REFS_CHANGED",
      });
      continue;
    }
    for (const [key, label] of secretSpecs) {
      if (previous[key] === secret[key]) continue;
      changes.push({
        id: `secret_refs[${kind}].${key}`,
        group: "crypto",
        label: `${name} · ${label}`,
        before: text(previous[key]),
        after: text(secret[key]),
        kind: "changed",
        risk: "SECRET_REFS_CHANGED",
      });
    }
  }
  for (const [kind, secret] of oldSecrets) {
    if (!newSecrets.has(kind)) {
      changes.push({
        id: `secret_refs[${kind}]`,
        group: "crypto",
        label: `密钥引用 ${secretKindLabel[kind]}`,
        before: secretSummary(secret),
        after: "（已移除）",
        kind: "removed",
        risk: "SECRET_REFS_CHANGED",
      });
    }
  }
  return changes;
}

export function groupChanges(changes: readonly FieldChange[]): Map<ChangeGroup, FieldChange[]> {
  const grouped = new Map<ChangeGroup, FieldChange[]>();
  for (const change of changes)
    grouped.set(change.group, [...(grouped.get(change.group) ?? []), change]);
  return grouped;
}
