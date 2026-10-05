import type { SiteRouteConfig } from "../../api.ts";
import { effectivePolicy, MAX_ROUTES, MAX_SECRET_REFS, type SiteConfigDraft } from "./config.ts";
import type { ChangeGroup } from "./diff.ts";
import { checkServerName, checkUpstreamAddress } from "./upstream.ts";

/**
 * Client-side mirror of the rules in `xshield_core::site` (SiteConfig::validate and
 * SitePolicyConfig::validate). It guides the operator while they type; the server validates
 * every write again and stays the authority. A mirrored rule that the server later relaxes can
 * therefore only ever cost a save attempt, so errors here disable nothing that the server alone
 * could allow except the wizard's own "next" button.
 */
export type Issue = Readonly<{
  /** Stable field path, for example `public_origin` or `routes[orders.get].path`. */
  path: string;
  severity: "error" | "warning";
  message: string;
  group: ChangeGroup;
}>;

const MIB = 1024 * 1024;

/** Cc category: C0 controls, DEL and C1 controls (what Rust's `char::is_control` refuses). */
function hasControl(value: string): boolean {
  for (const char of value) {
    const code = char.codePointAt(0) ?? 0;
    if (code < 0x20 || (code >= 0x7f && code <= 0x9f)) return true;
  }
  return false;
}

export function checkSiteId(id: string): string | null {
  if (id === "") return "请填写站点 ID。";
  if (id === "new") return "“new” 是保留字，请换一个站点 ID。";
  if (!/^[A-Za-z0-9_.-]+$/.test(id)) return "站点 ID 只能包含字母、数字和 _ . -。";
  // The edge derives its audit producer name as `edge-` + site ID and caps it at 128 bytes.
  if (id.length > 123) return "站点 ID 最长 123 个字符。";
  return null;
}

export function checkDisplayName(name: string): string | null {
  if (name.trim() === "") return "请填写站点名称。";
  if (name !== name.trim()) return "站点名称首尾不能有空白。";
  if (name.length > 128) return "站点名称最长 128 个字符。";
  if (hasControl(name)) return "站点名称不能包含控制字符。";
  return null;
}

export function checkPolicyRevision(value: string): string | null {
  if (value === "") return "请填写策略版本标签。";
  if (value.length > 128 || !/^[A-Za-z0-9._-]+$/.test(value)) {
    return "策略版本只能包含字母、数字和 . _ -，最长 128 个字符。";
  }
  return null;
}

export function checkListenPort(port: number): string | null {
  if (!Number.isInteger(port)) return "监听端口必须是整数。";
  if (port !== 0 && (port < 6100 || port > 65535)) {
    return "监听端口填 0（自动分配），或 6100–65535 之间的端口。";
  }
  return null;
}

/** The public origin rules of `validate_public_origin`, in the server's order. */
export function checkPublicOrigin(origin: string, sensorEnabled: boolean): string | null {
  if (origin === "") return "请填写公网入口，例如 https://www.example.com。";
  const sep = origin.indexOf("://");
  if (sep < 0) return "需要完整的 origin：协议://域名[:端口]，例如 https://www.example.com。";
  const scheme = origin.slice(0, sep);
  if (scheme !== "https" && scheme !== "http")
    return "公网入口只能使用 https（本地靶场可用 http）。";
  const https = scheme === "https";
  const rest = origin.slice(sep + 3);
  const trailingSlash = rest.endsWith("/");
  const authority = trailingSlash ? rest.slice(0, -1) : rest;
  if (authority === "" || origin.length > 512 || !/^[\x21-\x7e]+$/.test(authority)) {
    return "公网入口只能是 协议://域名[:端口]，不含空格或路径。";
  }
  if (/[/?#@\\[\]%]/.test(authority) || (https && trailingSlash)) {
    return "公网入口不能含路径、查询、账号或 IPv6 字面量，https 入口末尾也不能有 /。";
  }
  const colon = authority.lastIndexOf(":");
  const host = colon >= 0 ? authority.slice(0, colon) : authority;
  const port = colon >= 0 ? authority.slice(colon + 1) : null;
  const labelOk = (label: string) => /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label);
  if (host === "" || host.includes(":") || host.length > 253 || !host.split(".").every(labelOk)) {
    return "公网入口的域名不合法：每段只含字母、数字和连字符，不超过 63 个字符。";
  }
  if (port !== null && (!/^\d{1,5}$/.test(port) || Number(port) < 1 || Number(port) > 65535)) {
    return "公网入口的端口必须是 1–65535。";
  }
  if (!https) {
    const loopback =
      host.toLowerCase() === "localhost" || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
    if (!loopback) return "明文 http 只允许 localhost 或 127.x 本地靶场；生产入口请使用 https。";
    if (sensorEnabled && host !== "localhost" && host !== "127.0.0.1") {
      return "启用浏览器探针时，明文 http 只允许 localhost 与 127.0.0.1。";
    }
  }
  return null;
}

/** Printable ASCII, rooted, no query, fragment or edge-internal namespace. */
export function checkEntryPath(path: string): string | null {
  if (path === "") return "请填写入口路径，例如 /。";
  if (!path.startsWith("/")) return "入口路径必须以 / 开头。";
  if (!/^[\x21-\x7e]+$/.test(path) || /[?#\\]/.test(path)) {
    return "入口路径只能是可打印 ASCII，不含空格、? 或 #。";
  }
  if (path.startsWith("/__xshield/")) return "/__xshield/ 是 edge 自用命名空间。";
  if (path.length > 256) return "入口路径最长 256 个字符。";
  if (path.split("/").some((segment) => segment === "." || segment === "..")) {
    return "入口路径不能含 . 或 .. 段。";
  }
  return null;
}

const scoped = /^[A-Za-z0-9_.-]{1,128}$/;
const operationId = /^[A-Za-z0-9_.:-]{1,128}$/;

type RouteIssue = Readonly<{ field: string; severity: "error" | "warning"; message: string }>;

/** Per-route rules of `SitePolicyConfig::validate`; cross-route rules are in `validateRouteSet`. */
export function validateRoute(
  route: SiteRouteConfig,
  limits: { max_response_body_bytes: number; max_request_body_bytes?: number },
): RouteIssue[] {
  const issues: RouteIssue[] = [];
  const add = (field: string, message: string, severity: RouteIssue["severity"] = "error") =>
    issues.push({ field, severity, message });
  if (!operationId.test(route.operation_id)) {
    add("operation_id", "操作 ID 只能含字母、数字和 _ . : -，1–128 个字符。");
  }
  const parameter = route.resource_path_parameter;
  const path = route.path;
  const pathProblem = (() => {
    if (path === "" || !path.startsWith("/")) return "路径必须以 / 开头。";
    if (path.length > 256) return "路径最长 256 个字符。";
    if (!/^[\x21-\x7e]+$/.test(path) || /[?#\\]/.test(path))
      return "路径只能是可打印 ASCII，不含空格、? 或 #。";
    if (path.startsWith("/__xshield/")) return "/__xshield/ 是 edge 自用命名空间。";
    if (path.split("/").some((segment) => segment === "." || segment === "..")) {
      return "路径不能含 . 或 .. 段。";
    }
    if (parameter === null || parameter === "") {
      return /[{}]/.test(path) ? "只有“资源路径字段”不为空时，路径才能以 {参数} 结尾。" : null;
    }
    const marker = `{${parameter}}`;
    const prefix = path.endsWith(marker) ? path.slice(0, -marker.length) : null;
    if (
      prefix === null ||
      prefix === "" ||
      !prefix.endsWith("/") ||
      /[{}%]/.test(prefix) ||
      prefix.includes("//")
    ) {
      return `路径必须以 /前缀/${marker} 结尾，前缀不含 { } % 或连续的 /。`;
    }
    return null;
  })();
  if (pathProblem) add("path", pathProblem);
  const ui = route.security_entry === "ui_action_required";
  const source = route.source_action;
  if (ui && (source === null || source === "")) {
    add("source_action", "“必须有界面操作来源”的路由需要填写操作来源。");
  } else if (!ui && source !== null && source !== "") {
    add("source_action", "只有“必须有界面操作来源”的路由才有操作来源；请清空它或改变准入。");
  } else if (source !== null && !scoped.test(source)) {
    add("source_action", "操作来源只能含字母、数字和 _ . -，最长 128 个字符。");
  }
  const hasResource = [
    route.resource_type,
    route.view_profile,
    route.resource_query_parameter,
    route.resource_path_parameter,
  ].some((value) => value !== null && value !== "");
  if (hasResource) {
    if (route.method !== "GET") add("method", "绑定资源的路由只能是 GET。");
    if (!ui) add("security_entry", "绑定资源的路由必须是“必须有界面操作来源”。");
    if (!route.resource_type) add("resource_type", "绑定资源时必须填写资源类型。");
    if (!route.view_profile) add("view_profile", "绑定资源时必须填写视图 profile。");
    const query = route.resource_query_parameter;
    const bound = (query ? 1 : 0) + (route.resource_path_parameter ? 1 : 0);
    if (bound !== 1)
      add("resource_query_parameter", "资源查询字段与资源路径字段必须二选一，且只填一个。");
    for (const [field, value] of [
      ["resource_type", route.resource_type],
      ["view_profile", route.view_profile],
      ["resource_query_parameter", query],
      ["resource_path_parameter", route.resource_path_parameter],
    ] as const) {
      if (value && !scoped.test(value)) add(field, "只能含字母、数字和 _ . -，最长 128 个字符。");
    }
  }
  if (route.response_mode === "SENSOR_HTML") {
    add(
      "response_mode",
      "SENSOR_HTML 无法由路由表达，控制面会拒绝；请选择“透传”或 BUFFERED_JSON。",
    );
  }
  if (route.max_response_bytes < 1 || route.max_response_bytes > 16 * MIB) {
    add("max_response_bytes", "响应上限必须在 1 字节到 16 MiB 之间。");
  } else if (route.max_response_bytes > limits.max_response_body_bytes) {
    add("max_response_bytes", "路由的响应上限不能超过站点的响应体上限。");
  }
  if (route.request_crypto !== null && (!["POST", "PUT", "PATCH"].includes(route.method) || ui)) {
    add("request_crypto", "请求加密只用于 POST/PUT/PATCH，且不能用于界面来源的路由。");
  }
  for (const message of cryptoProblems(route, limits.max_request_body_bytes ?? MIB)) {
    add(message.field, message.text);
  }
  return issues;
}

const scopedValue = /^[A-Za-z0-9_.-]{1,128}$/;
const num = (value: unknown): number => (typeof value === "number" ? value : Number.NaN);
const text = (value: unknown): string => (typeof value === "string" ? value : "");

/** The edge's request/response crypto contracts (`route_*_crypto_contract_holds`). */
function cryptoProblems(
  route: SiteRouteConfig,
  maxRequestBody: number,
): { field: "request_crypto" | "response_crypto"; text: string }[] {
  const found: { field: "request_crypto" | "response_crypto"; text: string }[] = [];
  const request = route.request_crypto;
  if (request !== null) {
    if (request.mode === "OBSERVE") {
      if (!scopedValue.test(text(request.adapter_revision))) {
        found.push({
          field: "request_crypto",
          text: "请求加密的适配器版本只能含字母、数字和 _ . -。",
        });
      }
      if (route.response_crypto !== null) {
        found.push({ field: "request_crypto", text: "仅观察请求时不能同时改写响应（响应加密）。" });
      }
    } else if (request.mode === "DIRECT_DECRYPT") {
      const envelope = num(request.max_envelope_bytes);
      const plaintext = num(request.max_plaintext_bytes);
      const ok =
        scopedValue.test(text(request.adapter_revision)) &&
        scopedValue.test(text(request.key_id)) &&
        num(request.key_not_before) < num(request.key_expires_at) &&
        envelope >= 1 &&
        envelope <= 64 * 1024 &&
        envelope <= maxRequestBody &&
        plaintext >= 1 &&
        plaintext <= Math.floor(envelope / 2) &&
        plaintext <= maxRequestBody &&
        num(request.max_message_age_seconds) >= 1 &&
        num(request.max_message_age_seconds) <= 3600 &&
        num(request.max_future_skew_seconds) >= 0 &&
        num(request.max_future_skew_seconds) <= 300 &&
        num(request.max_active_messages) >= 1 &&
        num(request.max_active_messages) <= 1_000_000;
      if (!ok) {
        found.push({
          field: "request_crypto",
          text: "请求解密参数不合法：标识为字母数字和 _ . -，密钥生效时间早于失效时间，信封 1–64 KiB 且不超过请求体上限，明文不超过信封的一半，有效期 1–3600 秒，时钟偏差 ≤ 300 秒。",
        });
      }
    } else {
      found.push({
        field: "request_crypto",
        text: "请求加密模式只能是 OBSERVE 或 DIRECT_DECRYPT。",
      });
    }
  }
  const response = route.response_crypto;
  if (response !== null) {
    const envelope = num(response.max_envelope_bytes);
    const minimum = route.max_response_bytes * 2 + 1024;
    const ok =
      (response.mode === undefined || response.mode === "DIRECT_ENCRYPT") &&
      scopedValue.test(text(response.adapter_revision)) &&
      scopedValue.test(text(response.key_id)) &&
      num(response.key_not_before) < num(response.key_expires_at) &&
      num(response.message_ttl_seconds) >= 1 &&
      num(response.message_ttl_seconds) <= 3600 &&
      envelope >= minimum &&
      envelope <= 2 * 16 * MIB + 4096;
    if (!ok) {
      found.push({
        field: "response_crypto",
        text: "响应加密参数不合法：标识为字母数字和 _ . -，密钥生效时间早于失效时间，有效期 1–3600 秒，信封不小于两倍响应上限加 1024 字节。",
      });
    }
  }
  return found;
}

/** Cross-route rules of the edge compiler (`validate_route_set` and the uniqueness checks). */
export function validateRouteSet(routes: readonly SiteRouteConfig[]): Map<number, string[]> {
  const found = new Map<number, string[]>();
  const add = (index: number, message: string) =>
    found.set(index, [...(found.get(index) ?? []), message]);
  const seenOperations = new Map<string, number>();
  const seenPaths = new Map<string, number>();
  routes.forEach((route, index) => {
    if (route.operation_id !== "" && seenOperations.has(route.operation_id)) {
      add(index, `操作 ID “${route.operation_id}”重复。`);
    }
    seenOperations.set(route.operation_id, index);
    const key = `${route.method} ${route.path}`;
    if (seenPaths.has(key)) add(index, `${route.method} ${route.path} 已被另一条路由占用。`);
    seenPaths.set(key, index);
  });
  const parameterized = routes
    .map((route, index) => ({ route, index }))
    .filter(({ route }) => route.resource_path_parameter)
    .map(({ route, index }) => ({
      index,
      method: route.method,
      prefix: route.path.endsWith(`{${route.resource_path_parameter}}`)
        ? route.path.slice(0, -`{${route.resource_path_parameter}}`.length)
        : null,
    }))
    .filter(
      (entry): entry is { index: number; method: SiteRouteConfig["method"]; prefix: string } =>
        entry.prefix !== null,
    );
  if (parameterized.length > 64) {
    for (const entry of parameterized.slice(64))
      add(entry.index, "每个站点最多 64 条 {参数} 路由。");
  }
  parameterized.forEach((entry, position) => {
    if (
      parameterized
        .slice(position + 1)
        .some((other) => other.method === entry.method && other.prefix === entry.prefix)
    ) {
      add(entry.index, "同方法、同前缀的 {参数} 路由重复（不论参数名）。");
    }
    routes.forEach((route, index) => {
      const segment = route.path.startsWith(entry.prefix)
        ? route.path.slice(entry.prefix.length)
        : null;
      if (
        !route.resource_path_parameter &&
        route.method === entry.method &&
        segment &&
        !segment.includes("/")
      ) {
        add(index, `该固定路径会被 {参数} 路由 ${entry.prefix}{…} 同方法匹配，永远不会命中。`);
      }
    });
  });
  return found;
}

const hasWhitespaceOrControl = (value: string) => /\s/.test(value) || hasControl(value);

/** Everything the console can check before the server does, grouped by the tab that owns it. */
export function validateDraft(
  draft: SiteConfigDraft,
  options: { creating?: boolean; siteId?: string } = {},
): Issue[] {
  const issues: Issue[] = [];
  const add = (
    path: string,
    group: ChangeGroup,
    message: string | null,
    severity: Issue["severity"] = "error",
  ) => {
    if (message) issues.push({ path, group, message, severity });
  };
  if (options.creating) add("site_id", "network", checkSiteId(options.siteId ?? ""));
  add("display_name", "network", checkDisplayName(draft.display_name));
  add("public_origin", "network", checkPublicOrigin(draft.public_origin, draft.sensor_enabled));
  const upstream = checkUpstreamAddress(draft.upstream_address);
  if (upstream.severity !== "ok")
    add("upstream_address", "network", upstream.message, upstream.severity);
  add("upstream_server_name", "network", checkServerName(draft.upstream_server_name));
  add("listen_port", "network", checkListenPort(draft.listen_port));
  add("entry_path", "network", checkEntryPath(draft.entry_path));
  add("policy_revision", "security-entry", checkPolicyRevision(draft.policy_revision));

  const policy = effectivePolicy(draft);
  const routes = policy.routes;
  if (routes.length > MAX_ROUTES) add("routes", "routes", `路由最多 ${MAX_ROUTES} 条。`);
  const crossRoute = validateRouteSet(routes);
  routes.forEach((route, index) => {
    const label = route.operation_id === "" ? `#${index + 1}` : route.operation_id;
    for (const issue of validateRoute(route, policy.limits)) {
      add(
        `routes[${label}].${issue.field}`,
        "routes",
        `路由 ${label}：${issue.message}`,
        issue.severity,
      );
    }
    for (const message of crossRoute.get(index) ?? [])
      add(`routes[${label}]`, "routes", `路由 ${label}：${message}`);
  });

  const { identity, crypto, waf, limits, health_check: health, secret_refs: secrets } = policy;
  if (identity.session_ttl_seconds < 1 || identity.session_ttl_seconds > 86_400) {
    add("identity.session_ttl_seconds", "identity", "会话期限必须在 1–86400 秒之间。");
  }
  if (!Number.isInteger(identity.generation) || identity.generation < 1) {
    add("identity.generation", "identity", "身份代际必须是不小于 1 的整数。");
  }
  if (identity.profile.trim() === "" || identity.profile.length > 128) {
    add("identity.profile", "identity", "身份 profile 不能为空，最长 128 个字符。");
  }
  if (!["fail_closed", "observe"].includes(crypto.failure_strategy)) {
    add("crypto.failure_strategy", "crypto", "失败策略只能是“严格拒绝”或“仅观察”。");
  }
  if (crypto.adapter_revision === "" || crypto.adapter_revision.length > 128) {
    add("crypto.adapter_revision", "crypto", "协议适配器不能为空，最长 128 个字符。");
  }
  if (secrets.length > MAX_SECRET_REFS)
    add("secret_refs", "crypto", `密钥引用最多 ${MAX_SECRET_REFS} 条。`);
  const kinds = new Set<string>();
  secrets.forEach((secret, index) => {
    const label = `密钥引用 ${index + 1}`;
    if (kinds.has(secret.kind))
      add(`secret_refs[${index}].kind`, "crypto", `${label}：每种用途只能有一条引用。`);
    kinds.add(secret.kind);
    if (!secret.secret_ref.startsWith("secret://") || secret.secret_ref === "secret://") {
      add(
        `secret_refs[${index}].secret_ref`,
        "crypto",
        `${label}：引用必须以 secret:// 开头并带有名称。`,
      );
    } else if (secret.secret_ref.length > 512 || hasWhitespaceOrControl(secret.secret_ref)) {
      add(
        `secret_refs[${index}].secret_ref`,
        "crypto",
        `${label}：引用不能含空白，最长 512 个字符。`,
      );
    }
    if (
      secret.key_id === "" ||
      secret.key_id.length > 128 ||
      hasWhitespaceOrControl(secret.key_id)
    ) {
      add(
        `secret_refs[${index}].key_id`,
        "crypto",
        `${label}：Key ID 不能为空或含空白，最长 128 个字符。`,
      );
    }
  });

  if (waf.max_cookie_bytes < 1 || waf.max_cookie_bytes > MIB) {
    add("waf.max_cookie_bytes", "waf-limits", "Cookie 上限必须在 1 字节到 1 MiB 之间。");
  }
  const lowerHeaders = waf.blocked_headers.map((header) => header.toLowerCase());
  if (waf.blocked_headers.length > 64)
    add("waf.blocked_headers", "waf-limits", "拦截请求头最多 64 个。");
  if (waf.blocked_headers.some((header) => !/^[A-Za-z0-9_-]{1,128}$/.test(header))) {
    add("waf.blocked_headers", "waf-limits", "请求头名只能含字母、数字、- 和 _。");
  }
  if (new Set(lowerHeaders).size !== lowerHeaders.length) {
    add("waf.blocked_headers", "waf-limits", "请求头名不区分大小写，不能重复。");
  }
  const fragments = waf.blocked_query_fragments;
  const lowerFragments = fragments.map((fragment) => fragment.toLowerCase());
  if (fragments.length > 32)
    add("waf.blocked_query_fragments", "waf-limits", "查询阻断片段最多 32 条。");
  if (
    fragments.some(
      (fragment) =>
        fragment.length < 3 || fragment.length > 128 || !/^[\x20-\x7e]+$/.test(fragment),
    )
  ) {
    add("waf.blocked_query_fragments", "waf-limits", "每条片段为 3–128 个 ASCII 字符。");
  }
  if (new Set(lowerFragments).size !== lowerFragments.length) {
    add("waf.blocked_query_fragments", "waf-limits", "查询阻断片段不区分大小写，不能重复。");
  }
  for (const [path, value, max] of [
    ["limits.max_request_body_bytes", limits.max_request_body_bytes, 16 * MIB],
    ["limits.max_response_body_bytes", limits.max_response_body_bytes, 16 * MIB],
    ["limits.requests_per_second", limits.requests_per_second, 1_000_000],
    ["limits.burst", limits.burst, 2_000_000],
  ] as const) {
    if (!Number.isInteger(value) || value < 1 || value > max) {
      add(path, "waf-limits", `取值必须在 1 到 ${max.toLocaleString("en-US")} 之间。`);
    }
  }
  if (limits.burst < limits.requests_per_second) {
    add("limits.burst", "waf-limits", "突发容量不能小于每秒请求数。");
  }

  const path = health.path;
  if (
    !path.startsWith("/") ||
    /[?#\\]/.test(path) ||
    hasControl(path) ||
    path.split("/").some((segment) => segment === "." || segment === "..")
  ) {
    add("health_check.path", "policies", "健康检查路径必须以 / 开头，不含 ? # 反斜杠或 . .. 段。");
  }
  if (health.interval_seconds < 1 || health.interval_seconds > 3600) {
    add("health_check.interval_seconds", "policies", "检查间隔必须在 1–3600 秒之间。");
  }
  if (health.timeout_ms < 100 || health.timeout_ms > 30_000) {
    add("health_check.timeout_ms", "policies", "超时必须在 100–30000 毫秒之间。");
  }
  if (health.expected_status < 100 || health.expected_status > 599) {
    add("health_check.expected_status", "policies", "期望状态码必须在 100–599 之间。");
  }
  if (
    !Number.isInteger(policy.static_asset_max_path_depth) ||
    policy.static_asset_max_path_depth < 0 ||
    policy.static_asset_max_path_depth > 16
  ) {
    add(
      "static_asset_max_path_depth",
      "policies",
      "静态资源兜底深度必须在 0–16 之间（0 表示关闭）。",
    );
  }
  return issues;
}

export function issuesByPath(issues: readonly Issue[]): Map<string, Issue> {
  const map = new Map<string, Issue>();
  for (const issue of issues) if (!map.has(issue.path)) map.set(issue.path, issue);
  return map;
}
