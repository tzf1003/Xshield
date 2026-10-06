import type { SiteRouteConfig } from "../../api.ts";
import { effectivePolicy, MAX_ROUTES, MAX_SECRET_REFS, type SiteConfigDraft } from "./config.ts";
import type { ChangeGroup } from "./diff.ts";
import { formatBytes } from "./units.ts";
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
/** The edge parses operation IDs as `OperationId`, whose alphabet has no `:`. */
const operationId = scoped;
const sha256Hex = /^[0-9a-f]{64}$/;
const utf8 = new TextEncoder();

/** Gateway `valid_json_pointer`: rooted, ≤ 512 bytes, no ASCII control, only `~0`/`~1` escapes. */
function validPointer(value: string): boolean {
  return (
    value.startsWith("/") &&
    utf8.encode(value).length <= 512 &&
    ![...value].some((char) => {
      const code = char.codePointAt(0) ?? 0;
      return code < 0x20 || code === 0x7f;
    }) &&
    !/~(?![01])/.test(value)
  );
}

const inRange = (value: number, min: number, max: number) =>
  Number.isInteger(value) && value >= min && value <= max;
const successStatus = (status: number) => inRange(status, 200, 299) && status !== 204;
const hasResourceBinding = (route: SiteRouteConfig) =>
  [
    route.resource_type,
    route.view_profile,
    route.resource_query_parameter,
    route.resource_path_parameter,
  ].some((value) => value !== null && value !== "");

/** Whether releasing the response encrypts, changes identity or qualifies resources. */
const responseHasSideEffects = (route: SiteRouteConfig) =>
  route.response_crypto !== null ||
  route.resource_grant !== undefined ||
  route.auth_binding !== undefined ||
  route.auth_revoke !== undefined;

/** Field-level messages of the flow rules, shared by the drawer and the save path. */
const flowText = {
  status: "成功状态码须为 2xx，且不能是 204（204 没有正文，edge 无从读取）。",
  revokeStatus: "成功状态码须为 2xx，且不能是 204–206：edge 要看到完整正文才撤销身份。",
  pointer:
    "JSON 指针须以 / 开头，不超过 512 字节，不含控制字符；~ 只能写作 ~0（表示 ~）或 ~1（表示 /）。",
  pointerTaken: "三个 JSON 指针必须互不相同。",
  ttl: (what: string) => `${what}须为 1–86400 秒（最长一天）。`,
  scoped: (what: string) => `${what}只能含字母、数字和 _ . -，1–128 个字符。`,
  pick: (what: string) => `请选择${what}。`,
} as const;

/**
 * The per-route browser provenance-flow rules of `xshield_core::site::flow` (cross-route ones
 * are in `validateFlowReferences`). Placement problems are reported on the block (`auth_binding`),
 * value problems on the member (`auth_binding.bearer_pointer`), so the drawer can put each message
 * next to the control that fixes it; the save path reports the same text.
 */
function flowProblems(route: SiteRouteConfig): { field: string; text: string }[] {
  const found: { field: string; text: string }[] = [];
  const add = (field: string, text: string) => found.push({ field, text });
  const ttl = (field: string, value: number, what: string) => {
    if (!inRange(value, 1, 86_400)) add(field, flowText.ttl(what));
  };
  const { auth_binding: binding, auth_revoke: revoke, sensor_html: sensor } = route;
  if (binding) {
    if (route.security_entry !== "auth_entry") {
      add("auth_binding", "身份建立（auth_binding）只能用于“认证入口”路由。");
    } else {
      if (!successStatus(binding.success_status)) {
        add("auth_binding.success_status", flowText.status);
      }
      const seen = new Set<string>();
      for (const key of [
        "principal_pointer",
        "authorization_context_pointer",
        "bearer_pointer",
      ] as const) {
        const value = binding[key];
        if (!validPointer(value)) add(`auth_binding.${key}`, flowText.pointer);
        else if (seen.has(value)) add(`auth_binding.${key}`, flowText.pointerTaken);
        seen.add(value);
      }
      ttl("auth_binding.session_ttl_seconds", binding.session_ttl_seconds, "会话期限");
      if (!inRange(binding.credential_ttl_seconds, 1, 86_400)) {
        add("auth_binding.credential_ttl_seconds", flowText.ttl("凭证期限"));
      } else if (binding.credential_ttl_seconds > binding.session_ttl_seconds) {
        add("auth_binding.credential_ttl_seconds", "凭证期限不能长于会话期限。");
      }
    }
  }
  if (revoke) {
    if (route.security_entry !== "authenticated_root") {
      add("auth_revoke", "身份撤销（auth_revoke）只能用于“已认证根”路由。");
    } else if (
      !inRange(revoke.success_status, 200, 299) ||
      inRange(revoke.success_status, 204, 206)
    ) {
      add("auth_revoke.success_status", flowText.revokeStatus);
    }
  }
  if ((route.response_mode === "SENSOR_HTML") !== (sensor !== undefined)) {
    add("response_mode", "SENSOR_HTML 响应模式与页面构建适配（sensor_html）必须同时出现。");
  } else if (sensor) {
    const additional = sensor.additional_adapters ?? [];
    if (
      route.method !== "GET" ||
      route.response_crypto !== null ||
      route.resource_grant !== undefined ||
      binding !== undefined ||
      revoke !== undefined
    ) {
      add(
        "sensor_html",
        "SENSOR_HTML 页面只能是 GET，且不能同时加密响应、签发资格或建立/撤销身份。",
      );
    }
    if (additional.length > 15) {
      add("sensor_html", "一个页面最多 16 个已批准构建（主构建加 15 个附加构建）。");
    }
    const revisions = new Set<string>();
    const digests = new Set<string>();
    [sensor, ...additional].forEach((build, index) => {
      const at = index === 0 ? "sensor_html" : `sensor_html.additional_adapters.${index - 1}`;
      if (!scoped.test(build.adapter_revision)) {
        add(`${at}.adapter_revision`, flowText.scoped("构建版本"));
      } else if (revisions.has(build.adapter_revision)) {
        add(`${at}.adapter_revision`, "构建版本与另一个构建重复。");
      }
      revisions.add(build.adapter_revision);
      if (build.origin_sha256 === "") {
        add(
          `${at}.origin_sha256`,
          "请填写页面摘要（64 位小写十六进制的 SHA-256），可用“从页面源码计算”得到。",
        );
      } else if (!sha256Hex.test(build.origin_sha256)) {
        add(`${at}.origin_sha256`, "页面摘要须是 64 位小写十六进制（SHA-256）。");
      } else if (digests.has(build.origin_sha256)) {
        add(`${at}.origin_sha256`, "页面摘要与另一个构建重复。");
      }
      digests.add(build.origin_sha256);
      if (!Number.isFinite(build.injection_offset)) {
        add(
          `${at}.injection_offset`,
          "请填写注入偏移（</head> 在页面字节中的位置），可用“从页面源码计算”得到。",
        );
      } else if (!inRange(build.injection_offset, 0, route.max_response_bytes - 1)) {
        add(
          `${at}.injection_offset`,
          `注入偏移须是小于响应上限（${formatBytes(route.max_response_bytes)}）的非负整数。`,
        );
      }
    });
  }
  const page = route.page_actions;
  if (page) {
    if (
      route.response_mode !== "SENSOR_HTML" ||
      route.method !== "GET" ||
      route.security_entry !== "authenticated_root"
    ) {
      add(
        "page_actions",
        "页面签发动作（page_actions）只能用于“已认证根”的 GET SENSOR_HTML 页面。",
      );
    } else {
      if (!scoped.test(page.mapping_revision)) {
        add("page_actions.mapping_revision", flowText.scoped("映射修订"));
      }
      if (!inRange(page.max_active_pages, 1, 1_000)) {
        add("page_actions.max_active_pages", "活动页面上限须为 1–1000。");
      }
    }
  }
  const issued = route.issued_by;
  if (issued) {
    if (route.security_entry !== "ui_action_required" || hasResourceBinding(route)) {
      add("issued_by", "由页面签发（issued_by）只能用于不绑定资源的“必须有界面操作来源”路由。");
    } else {
      if (issued.page_operation_id === "") {
        add("issued_by.page_operation_id", flowText.pick("签发这个动作的页面"));
      } else if (!scoped.test(issued.page_operation_id)) {
        add("issued_by.page_operation_id", flowText.scoped("签发页面的操作 ID"));
      }
      ttl("issued_by.ttl_seconds", issued.ttl_seconds, "动作期限");
    }
  }
  const paging = route.query_pagination;
  if (paging) {
    const applicable =
      route.method === "GET" &&
      (route.security_entry === "authenticated_root"
        ? route.resource_grant !== undefined
        : route.security_entry === "ui_action_required" && !hasResourceBinding(route));
    if (!applicable) {
      add(
        "query_pagination",
        "分页参数（query_pagination）只能用于发放响应资源资格的“已认证根”GET 列表，或不绑定资源的“必须有界面操作来源”GET 路由。",
      );
    }
    if (paging.parameters.length < 1 || paging.parameters.length > 4) {
      add("query_pagination", "分页参数须声明 1–4 个。");
    }
    const names = new Set<string>();
    paging.parameters.forEach((parameter, at) => {
      const field = `query_pagination.parameters.${at}`;
      if (!/^[a-z_]{1,32}$/.test(parameter.name)) {
        add(`${field}.name`, "参数名只能含小写字母 a–z 和下划线，1–32 个字符。");
      } else if (names.has(parameter.name)) {
        add(`${field}.name`, "参数名与另一个参数重复。");
      }
      names.add(parameter.name);
      if (parameter.kind === "page_size") {
        if (parameter.max_value !== undefined && !inRange(parameter.max_value, 1, 1_000)) {
          add(`${field}.max_value`, "页长上限须为 1–1000（默认 200）。");
        }
      } else if (parameter.max_value !== undefined) {
        add(`${field}.max_value`, "只有页长（page_size）可以设置上限；页码与偏移的范围固定。");
      }
    });
  }
  const grant = route.resource_grant;
  if (grant) {
    if (
      route.security_entry !== "authenticated_root" &&
      route.security_entry !== "ui_action_required"
    ) {
      add("resource_grant", "响应资源资格只能用于“已认证根”或“必须有界面操作来源”的路由。");
    } else {
      if (!successStatus(grant.success_status)) {
        add("resource_grant.success_status", flowText.status);
      }
      for (const key of ["items_pointer", "resource_pointer"] as const) {
        if (!validPointer(grant[key])) add(`resource_grant.${key}`, flowText.pointer);
      }
      if (!scoped.test(grant.action_ref_field)) {
        add("resource_grant.action_ref_field", flowText.scoped("动作引用字段"));
      }
      if (grant.target_operation_id === "") {
        add("resource_grant.target_operation_id", flowText.pick("资格指向的详情路由"));
      } else if (!scoped.test(grant.target_operation_id)) {
        add("resource_grant.target_operation_id", flowText.scoped("目标操作 ID"));
      }
      if (!scoped.test(grant.target_mapping_revision)) {
        add("resource_grant.target_mapping_revision", flowText.scoped("目标映射修订"));
      }
      ttl("resource_grant.ttl_seconds", grant.ttl_seconds, "资格期限");
      if (!inRange(grant.max_items, 1, 1_000)) {
        add("resource_grant.max_items", "单次最多签发项数须为 1–1000。");
      }
      if (!inRange(grant.max_active_grants, 1, 5_000)) {
        add("resource_grant.max_active_grants", "活动资格上限须为 1–5000。");
      }
    }
  }
  if (
    (grant !== undefined ? 1 : 0) +
      (binding !== undefined ? 1 : 0) +
      (revoke !== undefined ? 1 : 0) >
    1
  ) {
    add(
      "resource_grant",
      "同一路由的响应最多只能有一种身份或资格效果（身份建立、身份撤销或资源资格选其一）。",
    );
  }
  return found;
}

/**
 * A finding on one route. `field` names the control that fixes it: a route field (`path`), a
 * flow block (`auth_binding`) or one member of it (`auth_binding.bearer_pointer`, and for page
 * builds `sensor_html.additional_adapters.0.origin_sha256`).
 */
export type RouteIssue = Readonly<{
  field: string;
  severity: "error" | "warning";
  message: string;
}>;

/** Per-route rules of `SitePolicyConfig::validate`; cross-route rules are in `validateRouteSet`. */
export function validateRoute(
  route: SiteRouteConfig,
  limits: { max_response_body_bytes: number; max_request_body_bytes?: number },
): RouteIssue[] {
  const issues: RouteIssue[] = [];
  const add = (field: string, message: string, severity: RouteIssue["severity"] = "error") =>
    issues.push({ field, severity, message });
  if (!operationId.test(route.operation_id)) {
    add("operation_id", "操作 ID 只能含字母、数字和 _ . -，1–128 个字符。");
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
  for (const problem of flowProblems(route)) add(problem.field, problem.text);
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
      if (responseHasSideEffects(route)) {
        found.push({
          field: "request_crypto",
          text: "仅观察请求时，响应不能加密、建立或撤销身份、签发资格。",
        });
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

/**
 * Route-set integrity rules of the edge compiler (`validate_route_set` of site.rs and the
 * uniqueness checks): operation IDs and `method path` pairs are unique and `{parameter}` routes
 * neither collide nor shadow fixed routes. The browser provenance-flow rules across routes are
 * `validateFlowReferences`; `validateDraft` applies both.
 */
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

/**
 * The cross-route browser provenance-flow rules of `xshield_core::site::flow::validate_route_set`,
 * per route index and field. A page and the actions it issues reference each other, so while a
 * flow is being built route by route these are expected to be open for a moment: the drawer
 * shows them without blocking 应用到草稿, and `validateDraft` reports them, which blocks saving.
 */
export function validateFlowReferences(
  routes: readonly SiteRouteConfig[],
): Map<number, RouteIssue[]> {
  const found = new Map<number, RouteIssue[]>();
  const add = (index: number, field: string, message: string) =>
    found.set(index, [...(found.get(index) ?? []), { field, severity: "error", message }]);
  const name = (index: number) => routes[index]?.operation_id || `#${index + 1}`;
  const byId = new Map(routes.map((route) => [route.operation_id, route]));
  const issued = new Map<string, number>();
  for (const route of routes) if (route.page_actions) issued.set(route.operation_id, 0);
  routes.forEach((route, index) => {
    const page = route.issued_by?.page_operation_id;
    if (page === undefined || page === "") return;
    const count = issued.get(page);
    if (count === undefined) {
      add(
        index,
        "issued_by.page_operation_id",
        `签发页面“${page}”不是声明了“页面签发动作”的 SENSOR_HTML 页面根。`,
      );
    } else {
      issued.set(page, count + 1);
    }
  });
  routes.forEach((route, index) => {
    const count = route.page_actions ? (issued.get(route.operation_id) ?? 0) : null;
    if (count === 0) {
      add(
        index,
        "page_actions",
        "页面根须签发 1–16 个动作，当前没有：在列表等“必须有界面操作来源”路由的“由页面签发”中选择这个页面。",
      );
    } else if (count !== null && count > 16) {
      add(index, "page_actions", `页面根最多签发 16 个动作，当前 ${count} 个。`);
    }
  });
  routes.forEach((route, index) => {
    const grant = route.resource_grant;
    if (!grant || grant.target_operation_id === "") return;
    const target = byId.get(grant.target_operation_id);
    if (
      !target ||
      target.security_entry !== "ui_action_required" ||
      !target.source_action ||
      !target.resource_type
    ) {
      add(
        index,
        "resource_grant.target_operation_id",
        `资源资格目标“${grant.target_operation_id}”必须是已存在、绑定资源的“必须有界面操作来源”路由。`,
      );
    }
  });
  // A pagination name must never double as a resource selector of any route (case-folded).
  const resourceNames = new Set(
    routes.flatMap((route) =>
      [route.resource_query_parameter, route.resource_path_parameter].flatMap((value) =>
        value ? [value.toLowerCase()] : [],
      ),
    ),
  );
  routes.forEach((route, index) => {
    route.query_pagination?.parameters.forEach((parameter, at) => {
      if (resourceNames.has(parameter.name.toLowerCase())) {
        add(
          index,
          `query_pagination.parameters.${at}.name`,
          `参数名“${parameter.name}”与某条路由的资源参数同名（不区分大小写），调用者可能借它选择对象。`,
        );
      }
    });
  });
  const indexes = (pick: (route: SiteRouteConfig) => boolean) =>
    routes.flatMap((route, index) => (pick(route) ? [index] : []));
  for (const index of indexes((route) => route.resource_grant !== undefined).slice(64)) {
    add(index, "resource_grant", "每个站点最多 64 条响应资源资格。");
  }
  for (const index of indexes(
    (route) => route.auth_binding !== undefined || route.auth_revoke !== undefined,
  ).slice(64)) {
    add(
      index,
      routes[index]?.auth_binding ? "auth_binding" : "auth_revoke",
      "每个站点最多 64 条建立或撤销身份的路由。",
    );
  }
  // One (action, mapping revision) has one meaning, whoever provisions the descriptors.
  const meanings = new Map<string, { meaning: string; index: number }>();
  const derive = (
    index: number,
    field: string,
    action: string,
    mapping: string,
    meaning: unknown[],
  ) => {
    const key = JSON.stringify([action, mapping]);
    const existing = meanings.get(key);
    if (existing === undefined) {
      meanings.set(key, { meaning: JSON.stringify(meaning), index });
    } else if (existing.meaning !== JSON.stringify(meaning)) {
      add(
        index,
        field,
        `操作来源“${action}”在映射修订“${mapping}”下与路由 ${name(existing.index)} 含义不同：换用另一个操作来源或映射修订。`,
      );
    }
  };
  routes.forEach((route, index) => {
    const page = route.issued_by ? byId.get(route.issued_by.page_operation_id) : undefined;
    if (route.source_action && page?.page_actions) {
      derive(index, "source_action", route.source_action, page.page_actions.mapping_revision, [
        page.operation_id,
        route.operation_id,
        route.method,
        route.path,
        null,
        null,
        "none",
      ]);
    }
  });
  routes.forEach((route, index) => {
    const grant = route.resource_grant;
    const target = grant ? byId.get(grant.target_operation_id) : undefined;
    if (grant && target?.source_action && target.view_profile) {
      derive(
        index,
        "resource_grant.target_mapping_revision",
        target.source_action,
        grant.target_mapping_revision,
        [
          target.operation_id,
          target.operation_id,
          target.method,
          target.path,
          target.resource_type,
          target.resource_query_parameter ?? target.resource_path_parameter,
          target.view_profile,
        ],
      );
    }
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
  const references = validateFlowReferences(routes);
  routes.forEach((route, index) => {
    const label = route.operation_id === "" ? `#${index + 1}` : route.operation_id;
    for (const issue of [
      ...validateRoute(route, policy.limits),
      ...(references.get(index) ?? []),
    ]) {
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
  if (!draft.sensor_enabled && routes.some((route) => route.response_mode === "SENSOR_HTML")) {
    add(
      "sensor_enabled",
      "security-entry",
      "有 SENSOR_HTML 页面路由时必须启用浏览器探针，edge 才会注入并放行这些页面。",
    );
  }

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
