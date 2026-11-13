// The condition syntax of the request filter bar (docs/06 6.4.3, 07.9.3). Parsing and
// serialising are inverse operations for every valid input: tests/filter-dsl.test.ts checks the
// round trip. Keys in one term are "or"ed by commas; different keys are "and"ed by spaces.

import type { UnknownApiReason } from "../api/types.ts";

export type FilterParams = Record<string, string>;

export type FilterError = { term: string; index: number; message: string };

export type ParsedFilter = { params: FilterParams; errors: FilterError[] };

const OUTCOMES = ["allowed", "blocked", "would_block", "unjudged"];
const DECISIONS = [
  "bypass",
  "fast_allow",
  "cached_allow",
  "jev_allow",
  "jev_deny",
  "jev_unavailable",
  "no_session",
  "body_not_inspectable",
  "unknown_site",
];
const FAILURES = [
  "JEV_TIMEOUT",
  "JEV_RATE_LIMITED",
  "JEV_TRANSPORT",
  "JEV_HTTP_ERROR",
  "JEV_RESPONSE_TOO_LARGE",
  "JEV_RESPONSE_INVALID",
  "JEV_UNKNOWN",
  "JEV_LOW_CONFIDENCE",
  "JEV_STATE_TOO_LARGE",
  "JEV_CALL_LIMIT",
];
const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
/** The reason codes of unknown interface names (types.ts), as `api:unknown:<code>` takes them. */
const UNKNOWN_REASONS: readonly UnknownApiReason[] = [
  "missing",
  "repeated",
  "conflict",
  "invalid_name",
  "body_unsupported",
  "body_not_json",
  "body_too_large",
  "route_subpath",
];
/** An interface name, or a part of one: letters, digits, `.`, `_`, `-` and `/`, at most 64 characters. */
const API_NAME_PATTERN = /^[A-Za-z0-9._/-]{1,64}$/;
/** An object class id, such as `doctor`. */
const CLASS_ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;

export function isUnknownReason(value: string): value is UnknownApiReason {
  return UNKNOWN_REASONS.some((reason) => reason === value);
}

/** A name the `api:` condition may hold. `unknown` alone is the condition for unknown names, so it is not one. */
export function isApiName(value: string): boolean {
  return API_NAME_PATTERN.test(value) && value !== "unknown";
}

export function isClassId(value: string): boolean {
  return CLASS_ID_PATTERN.test(value);
}

/** Key names the bar accepts, in the order the "＋条件" menu lists them. */
export const FILTER_KEYS = [
  "outcome",
  "decision",
  "path",
  "api",
  "object",
  "method",
  "status",
  "session",
  "client",
  "id",
  "access",
  "attack",
  "failure",
  "conf",
  "ms",
  "version",
  "entry",
  "site",
] as const;

export type FilterKey = (typeof FILTER_KEYS)[number];

/** DSL key to the API query parameter it fills. `api:unknown` fills `api_unknown` instead (see parseKeyed). */
const API_NAME: Record<FilterKey, string> = {
  outcome: "outcome",
  decision: "decision_path",
  path: "path",
  api: "api",
  object: "object",
  method: "method",
  status: "status",
  session: "session",
  client: "client",
  id: "request_id",
  access: "jev_access",
  attack: "jev_attack",
  failure: "jev_failure",
  conf: "max_confidence",
  ms: "min_ms",
  version: "site_version",
  entry: "entry",
  site: "site",
};

function listOf(value: string, allowed: string[]): string | null {
  const items = value.split(",");
  if (items.some((item) => item.length === 0)) return null;
  if (!items.every((item) => allowed.includes(item))) return null;
  return items.join(",");
}

function explainBadList(value: string, allowed: string[], label: string): string {
  const bad = value.split(",").find((item) => item.length === 0 || !allowed.includes(item));
  return `${label}无效：${bad ?? value}（可用值：${allowed.join("、")}）`;
}

/** Parses one `key:value` term. Returns the API parameter or an error message. */
function parseKeyed(
  key: string,
  value: string,
): { name: string; value: string } | { error: string } {
  switch (key) {
    case "outcome": {
      const list = listOf(value, OUTCOMES);
      return list
        ? { name: "outcome", value: list }
        : { error: explainBadList(value, OUTCOMES, "结论") };
    }
    case "decision": {
      const list = listOf(value, DECISIONS);
      return list
        ? { name: "decision_path", value: list }
        : { error: explainBadList(value, DECISIONS, "判定路径") };
    }
    case "path": {
      if (!value.startsWith("/")) return { error: "路径必须以 / 开头" };
      if (value.length > 256) return { error: "路径过长" };
      return { name: "path", value };
    }
    case "api": {
      if (value === "unknown") return { name: "api_unknown", value: "any" };
      if (value.startsWith("unknown:")) {
        const reason = value.slice("unknown:".length);
        return isUnknownReason(reason)
          ? { name: "api_unknown", value: reason }
          : { error: `未知接口原因无效：${reason}（可用值：${UNKNOWN_REASONS.join("、")}）` };
      }
      return isApiName(value)
        ? { name: "api", value }
        : { error: "接口名为 1 到 64 个字符，只能用字母、数字、. _ - /" };
    }
    case "object": {
      return isClassId(value)
        ? { name: "object", value }
        : { error: "类别 id 为 1 到 64 个字母、数字、_ 或 -" };
    }
    case "method": {
      const upper = value.toUpperCase();
      return METHODS.includes(upper)
        ? { name: "method", value: upper }
        : { error: `未知方法：${value}` };
    }
    case "status": {
      if (/^[1-5]xx$/i.test(value) || /^[1-5][0-9]{2}$/.test(value)) {
        return { name: "status", value: value.toLowerCase() };
      }
      return { error: "状态码应为 3 位数字或 4xx 这样的类别" };
    }
    case "session": {
      return /^[0-9a-f]{16}$/.test(value)
        ? { name: "session", value }
        : { error: "会话标签为 16 位十六进制" };
    }
    case "client": {
      return /^[0-9A-Fa-f.:]{3,45}$/.test(value)
        ? { name: "client", value }
        : { error: "客户端地址格式不正确" };
    }
    case "id": {
      return /^req_[0-9a-f]{32}$/.test(value)
        ? { name: "request_id", value }
        : { error: "请求 ID 为 req_ 加 32 位十六进制" };
    }
    case "access": {
      const upper = value.toUpperCase();
      return ["ALLOW", "DENY", "UNKNOWN"].includes(upper)
        ? { name: "jev_access", value: upper }
        : { error: "访问结论应为 ALLOW、DENY 或 UNKNOWN" };
    }
    case "attack": {
      const upper = value.toUpperCase();
      return ["BENIGN", "ATTACK", "UNKNOWN"].includes(upper)
        ? { name: "jev_attack", value: upper }
        : { error: "攻击结论应为 BENIGN、ATTACK 或 UNKNOWN" };
    }
    case "failure": {
      return FAILURES.includes(value.toUpperCase())
        ? { name: "jev_failure", value: value.toUpperCase() }
        : { error: "未知的 Jev 失败码" };
    }
    case "version": {
      return /^[0-9]{1,9}$/.test(value)
        ? { name: "site_version", value }
        : { error: "配置版本应为整数" };
    }
    case "entry": {
      return value === "true" || value === "false"
        ? { name: "entry", value }
        : { error: "entry 只能是 true 或 false" };
    }
    case "site": {
      return /^[a-z0-9_-]{1,64}$/.test(value) ? { name: "site", value } : { error: "站点名不合法" };
    }
    default:
      return { error: `不认识的条件：${key}` };
  }
}

/** Parses `conf<0.7`, `conf<70%` and `ms>1000`. */
function parseComparison(
  key: "conf" | "ms",
  operator: "<" | ">",
  value: string,
): { name: string; value: string } | { error: string } {
  if (key === "conf") {
    if (operator !== "<") return { error: "conf 只支持 < （置信度上限）" };
    const percent = /^([0-9]{1,3})%$/.exec(value);
    const number = percent ? Number(percent[1]) / 100 : Number(value);
    if (!Number.isFinite(number) || number <= 0 || number > 1 || value.length === 0) {
      return { error: "置信度上限为 0 到 1 之间的小数或百分比" };
    }
    return { name: "max_confidence", value: String(number) };
  }
  if (operator !== ">") return { error: "ms 只支持 > （耗时下限）" };
  if (!/^[0-9]{1,9}$/.test(value)) return { error: "耗时下限为毫秒整数" };
  return { name: "min_ms", value };
}

/** Parses the bar's text into API parameters. Errors come with the term that caused them. */
export function parseFilter(input: string): ParsedFilter {
  const params: FilterParams = {};
  const errors: FilterError[] = [];
  const pattern = /\S+/g;
  for (const match of input.matchAll(pattern)) {
    const term = match[0];
    const index = match.index ?? 0;
    const fail = (message: string) => {
      errors.push({ term, index, message });
    };
    const comparison = /^(conf|ms)([<>])(.+)$/.exec(term);
    if (comparison) {
      const [, key, operator, value] = comparison;
      const parsed = parseComparison(key as "conf" | "ms", operator as "<" | ">", value ?? "");
      if ("error" in parsed) fail(parsed.error);
      else if (params[parsed.name] !== undefined) fail(`${key} 只能出现一次`);
      else params[parsed.name] = parsed.value;
      continue;
    }
    const keyed = /^([a-z_]+):(.*)$/.exec(term);
    if (keyed) {
      const key = keyed[1] ?? "";
      const value = keyed[2] ?? "";
      if (!(key in API_NAME)) {
        fail(`不认识的条件：${key}`);
        continue;
      }
      const parsed = parseKeyed(key, value);
      if ("error" in parsed) fail(parsed.error);
      else if (params[parsed.name] !== undefined) fail(`${key} 只能出现一次，多个值用逗号隔开`);
      else params[parsed.name] = parsed.value;
      continue;
    }
    // Bare words are recognised by shape: a path, a request id, a session label or a method.
    if (term.startsWith("/")) {
      const parsed = parseKeyed("path", term);
      if ("error" in parsed) fail(parsed.error);
      else if (params.path !== undefined) fail("路径只能出现一次");
      else params.path = parsed.value;
      continue;
    }
    if (term.startsWith("req_")) {
      const parsed = parseKeyed("id", term);
      if ("error" in parsed) fail(parsed.error);
      else params.request_id = parsed.value;
      continue;
    }
    if (/^[0-9a-f]{16}$/.test(term)) {
      params.session = term;
      continue;
    }
    if (METHODS.includes(term.toUpperCase())) {
      params.method = term.toUpperCase();
      continue;
    }
    fail(`无法识别：${term}。路径以 / 开头，条件写成 键:值`);
  }
  return { params, errors };
}

/** Writes API parameters back as the bar's text. `parseFilter(serializeFilter(p)).params` equals `p`. */
export function serializeFilter(params: FilterParams): string {
  const terms: string[] = [];
  for (const key of FILTER_KEYS) {
    if (key === "api" && params.api_unknown) {
      // `api:` also writes the unknown-name condition, which is `api:unknown` for any reason.
      const reason = params.api_unknown;
      terms.push(reason === "any" ? "api:unknown" : `api:unknown:${reason}`);
    }
    const name = API_NAME[key];
    const value = params[name];
    if (value === undefined || value === "") continue;
    if (key === "conf") terms.push(`conf<${value}`);
    else if (key === "ms") terms.push(`ms>${value}`);
    else terms.push(`${key}:${value}`);
  }
  return terms.join(" ");
}
