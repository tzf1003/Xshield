// Local checks that mirror the server's SITE_CONFIG_* rules (docs/07 7.6.2, 7.9.12) so the form
// can point at the field that is wrong. The server remains the authority: its error codes are
// still shown when a save is refused. Messages here never echo more than the field name.

import type { Advanced, RouteRule, SiteSpec } from "../api/types.ts";
import { ruleFor, splitSource } from "./logical-path.ts";
import { type ParsedPattern, parsePattern } from "./patterns.ts";
import { isSiteName } from "./ids.ts";

export type FieldGroup =
  | "basics"
  | "session"
  | "routes"
  | "entries"
  | "bypass"
  | "mode"
  | "advanced";

export type FieldIssue = { group: FieldGroup; field: string; message: string };

export const BUILTIN_SECRET_WORDS = [
  "password",
  "passwd",
  "pwd",
  "secret",
  "token",
  "otp",
  "credential",
  "authorization",
  "cvv",
] as const;

export const BUILTIN_SYNONYMS: ReadonlyArray<readonly [string, string]> = [["payment", "card"]];

/** Words that name an object in many field names; a secret word that matches them hides ids. */
const OBJECT_WORDS = [
  "id",
  "card",
  "user",
  "owner",
  "account",
  "order",
  "file",
  "basket",
  "address",
  "coupon",
  "product",
  "record",
  "item",
  "no",
  "code",
];

const HOST_MAX = 253;

export function validHost(host: string): boolean {
  return (
    host.length > 0 &&
    host.length <= HOST_MAX &&
    !/^[.-]/.test(host) &&
    !/[.-]$/.test(host) &&
    !host.includes("..") &&
    /^[A-Za-z0-9.-]+$/.test(host)
  );
}

/** `http(s)://host[:port]` with no path, query or credentials (docs/07 7.9.1, config.rs). */
export function validOrigin(origin: string): boolean {
  const match = /^https?:\/\/(.+)$/.exec(origin);
  if (!match) return false;
  const rest = match[1] ?? "";
  const colon = rest.lastIndexOf(":");
  const host = colon >= 0 ? rest.slice(0, colon) : rest;
  const port = colon >= 0 ? rest.slice(colon + 1) : null;
  if (!validHost(host)) return false;
  // One to five digits, as config.rs reads it; the gateway does not range-check the number.
  return port === null || /^[0-9]{1,5}$/.test(port);
}

/** Cookie names and header names: RFC 7230 token characters. */
export function validToken(name: string): boolean {
  return name.length > 0 && name.length <= 64 && /^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/.test(name);
}

function intIn(value: number, min: number, max: number): boolean {
  return Number.isInteger(value) && value >= min && value <= max;
}

function validateAdvanced(advanced: Advanced | undefined): FieldIssue[] {
  const issues: FieldIssue[] = [];
  const add = (field: string, message: string) => {
    issues.push({ group: "advanced", field, message });
  };
  if (!advanced) return issues;
  if (advanced.jev_timeout_ms !== undefined && !intIn(advanced.jev_timeout_ms, 100, 30000)) {
    add("jev_timeout_ms", "Jev 超时需在 100–30000 ms 之间");
  }
  if (
    advanced.session_calls_per_minute !== undefined &&
    !intIn(advanced.session_calls_per_minute, 1, 600)
  ) {
    add("session_calls_per_minute", "会话调用上限需在 1–600 次之间");
  }
  if (
    advanced.address_calls_per_minute !== undefined &&
    !intIn(advanced.address_calls_per_minute, 1, 600)
  ) {
    add("address_calls_per_minute", "地址调用上限需在 1–600 次之间");
  }
  if (advanced.allow_cache_minutes !== undefined && !intIn(advanced.allow_cache_minutes, 0, 60)) {
    add("allow_cache_minutes", "放行缓存时长需在 0–60 分钟之间");
  }
  const words = advanced.secret_fields ?? [];
  if (words.length > 32) add("secret_fields", "追加脱敏词最多 32 个");
  const seenWords = new Set<string>();
  for (const word of words) {
    if (!/^[a-z0-9_-]{3,32}$/.test(word)) {
      add("secret_fields", `脱敏词 “${word}” 需为 3–32 个小写字母、数字、_ 或 -`);
    } else if ((BUILTIN_SECRET_WORDS as readonly string[]).includes(word) || seenWords.has(word)) {
      add("secret_fields", `脱敏词 “${word}” 与内置词或已有词重复`);
    }
    seenWords.add(word);
  }
  const groups = advanced.synonyms ?? [];
  if (groups.length > 32) add("synonyms", "同义词最多 32 组");
  const seenGroups = new Set<string>();
  for (const [a, b] of groups) {
    const ok = /^[a-z]{3,24}$/.test(a) && /^[a-z]{3,24}$/.test(b);
    if (!ok) {
      add("synonyms", `同义词 “${a} ↔ ${b}” 每个词需为 3–24 个小写字母`);
      continue;
    }
    if (a === b) add("synonyms", `同义词 “${a} ↔ ${b}” 两个词不能相同`);
    const key = [a, b].sort().join("|");
    if (seenGroups.has(key)) add("synonyms", `同义词 “${a} ↔ ${b}” 重复`);
    seenGroups.add(key);
  }
  return issues;
}

const isMap = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);

/** YAML reads `123` as a number, so a text field that holds one says how to quote it. */
const quoteHint = (value: unknown): string =>
  typeof value === "number" ? "，纯数字的值要加引号" : "";

/** The advanced parameters that take a number. */
const ADVANCED_NUMBERS = [
  "jev_timeout_ms",
  "session_calls_per_minute",
  "address_calls_per_minute",
  "allow_cache_minutes",
] as const;

/**
 * The type of each field, checked before any rule judges a value (docs/06 6.4.9, docs/07 7.10.8). A key
 * that is written with no value is an error, except under `advanced`, where an empty parameter means its
 * default. Each message names the field, so a YAML or JSON text can point at it.
 */
export function shapeIssues(input: unknown): FieldIssue[] {
  if (!isMap(input)) return [{ group: "basics", field: "name", message: "配置必须是一个对象" }];
  const issues: FieldIssue[] = [];
  const add = (group: FieldGroup, field: string, message: string): void => {
    issues.push({ group, field, message });
  };
  // True when there is nothing to check: the key is absent, or it is written with no value.
  const skip = (
    group: FieldGroup,
    key: string,
    value: unknown,
    required: boolean,
    emptyOk = false,
  ): boolean => {
    if (value === undefined) {
      if (required) add(group, key, `缺少必填字段 ${key}`);
      return true;
    }
    if (value === null) {
      if (!emptyOk) add(group, key, `${key} 写了键却没有值`);
      return true;
    }
    return false;
  };
  const text = (
    group: FieldGroup,
    key: string,
    value: unknown,
    required: boolean,
    emptyOk = false,
  ): void => {
    if (skip(group, key, value, required, emptyOk) || typeof value === "string") return;
    add(group, key, `${key} 要写成文本${quoteHint(value)}`);
  };
  const textList = (
    group: FieldGroup,
    key: string,
    value: unknown,
    required: boolean,
    emptyOk = false,
  ): void => {
    if (skip(group, key, value, required, emptyOk)) return;
    if (!Array.isArray(value)) {
      add(group, key, `${key} 要写成文本列表`);
      return;
    }
    const index = value.findIndex((item) => typeof item !== "string");
    if (index >= 0) add(group, key, `${key} 的每一项要写成文本${quoteHint(value[index])}`);
  };
  text("basics", "name", input.name, true);
  text("basics", "origin", input.origin, true);
  textList("basics", "hosts", input.hosts, true);
  textList("entries", "entries", input.entries, true);
  textList("bypass", "bypass", input.bypass, false);
  text("mode", "mode", input.mode, false);
  text("basics", "on_jev_unavailable", input.on_jev_unavailable, false);
  const session = input.session;
  if (!skip("session", "session", session, true)) {
    if (!isMap(session)) add("session", "session", "session 要写成键值");
    else {
      text("session", "cookie", session.cookie, false);
      text("session", "header", session.header, false);
    }
  }
  issues.push(...routeShapeIssues(input.routes));
  const advanced = input.advanced;
  if (!skip("advanced", "advanced", advanced, false, true)) {
    if (!isMap(advanced)) add("advanced", "advanced", "advanced 要写成键值");
    else {
      for (const key of ADVANCED_NUMBERS) {
        const value = advanced[key];
        if (value !== undefined && value !== null && typeof value !== "number") {
          add("advanced", key, `${key} 要写成数字`);
        }
      }
      textList("advanced", "secret_fields", advanced.secret_fields, false, true);
      const groups = advanced.synonyms;
      const pairOk = (pair: unknown): boolean =>
        Array.isArray(pair) && pair.length === 2 && pair.every((word) => typeof word === "string");
      if (
        groups !== undefined &&
        groups !== null &&
        (!Array.isArray(groups) || !groups.every(pairOk))
      ) {
        add("advanced", "synonyms", "synonyms 要写成两个词一组的列表");
      }
    }
  }
  return issues;
}

/** Errors block saving; warnings are shown beside the field and do not block. */
export function validateSpec(input: unknown): { errors: FieldIssue[]; warnings: FieldIssue[] } {
  // A field of the wrong type is reported by its type alone. No rule below reads it, so nothing throws.
  const shape = shapeIssues(input);
  if (shape.length > 0) return { errors: shape, warnings: [] };
  const spec = input as SiteSpec;
  const errors: FieldIssue[] = [];
  const warnings: FieldIssue[] = [];
  if (!isSiteName(spec.name)) {
    errors.push({
      group: "basics",
      field: "name",
      message: "站点名只能用小写字母、数字、-、_，最长 64 个字符",
    });
  }
  if (spec.hosts.length === 0 || spec.hosts.length > 16 || !spec.hosts.every(validHost)) {
    errors.push({
      group: "basics",
      field: "hosts",
      message: "Host 不能为空，最多 16 个，每个必须是有效的主机名",
    });
  }
  if (!validOrigin(spec.origin)) {
    errors.push({
      group: "basics",
      field: "origin",
      message: "源站地址必须是 http://主机[:端口] 或 https://主机[:端口]，不带路径",
    });
  }
  const credential = spec.session.cookie ?? spec.session.header ?? "";
  const credentialOk =
    Number(spec.session.cookie !== undefined) + Number(spec.session.header !== undefined) === 1 &&
    validToken(credential);
  if (!credentialOk) {
    errors.push({
      group: "session",
      field: "session",
      message: "会话凭证需要一个有效的 Cookie 名或请求头名",
    });
  }
  errors.push(...validateRules("entries", spec.entries, 1));
  errors.push(...validateRules("bypass", spec.bypass ?? [], 0));
  errors.push(...validateRoutes(spec.routes ?? []));
  warnings.push(...unreachableRules(spec));
  for (const raw of spec.entries) {
    const parsed = parsePattern(raw);
    if (
      parsed.ok &&
      parsed.value.prefix &&
      parsed.value.literal.split("/").filter(Boolean).length <= 1
    ) {
      warnings.push({
        group: "entries",
        field: raw,
        message: "前缀入口会放大无会话可达的范围",
      });
    }
  }
  for (const word of spec.advanced?.secret_fields ?? []) {
    if (OBJECT_WORDS.includes(word)) {
      warnings.push({
        group: "advanced",
        field: "secret_fields",
        message: `“${word}” 会让 ${word}Id 这类对象引用也被脱敏，Jev 无法判断越权`,
      });
    }
  }
  errors.push(...validateAdvanced(spec.advanced));
  return { errors, warnings };
}

function validateRules(
  group: "entries" | "bypass",
  rules: string[],
  minimum: number,
): FieldIssue[] {
  const issues: FieldIssue[] = [];
  if (rules.length < minimum) {
    issues.push({
      group,
      field: group,
      message: group === "entries" ? "入口至少一条" : "绕过规则不能为空",
    });
  }
  if (rules.length > 64) {
    issues.push({ group, field: group, message: "最多 64 条" });
  }
  rules.forEach((raw, index) => {
    const parsed = parsePattern(raw);
    if (!parsed.ok) {
      issues.push({ group, field: `${group}[${index}]`, message: parsed.reason });
    }
  });
  return issues;
}

// ------------------------------------------------------------------ interface-name rules (header-routes-design 2, 3)

const ROUTE_KINDS: readonly string[] = ["header", "query", "body"];
/** The gateway reads at most this many rules (site.rs, validate_route_set). */
const ROUTE_MAX = 256;
const QUERY_NAME = /^[A-Za-z0-9._-]{1,64}$/;
const BODY_KEY = /^[A-Za-z0-9_-]{1,64}$/;

/** The shape of the rules, checked before any of their values are read (the same order as shapeIssues). */
function routeShapeIssues(value: unknown): FieldIssue[] {
  const issues: FieldIssue[] = [];
  const add = (field: string, message: string): void => {
    issues.push({ group: "routes", field, message });
  };
  if (value === undefined) return issues;
  if (value === null) {
    add("routes", "routes 写了键却没有值");
    return issues;
  }
  if (!Array.isArray(value)) {
    add("routes", "routes 要写成规则列表");
    return issues;
  }
  const rules: unknown[] = value;
  rules.forEach((rule, index) => {
    const at = `routes[${index}]`;
    if (!isMap(rule)) {
      add(at, "每条规则要写成 path 和 name_from 两个键");
      return;
    }
    if (typeof rule.path !== "string") {
      add(`${at}.path`, rule.path === undefined ? "缺少必填字段 path" : "path 要写成文本");
    }
    const names: unknown = rule.name_from;
    if (!Array.isArray(names)) {
      add(
        `${at}.name_from`,
        names === undefined ? "缺少必填字段 name_from" : "name_from 要写成列表",
      );
      return;
    }
    const segments: unknown[] = names;
    segments.forEach((segment, position) => {
      const list: unknown = segment;
      const ok = Array.isArray(list) && list.every((item: unknown) => typeof item === "string");
      if (!ok)
        add(`${at}.name_from[${position}]`, "每一段要写成位置列表，例如 [header.X-Service-Id]");
    });
  });
  return issues;
}

/** The checks of the rules: the path, the segments and their locations, and overlaps with an earlier rule. */
function validateRoutes(routes: RouteRule[]): FieldIssue[] {
  const issues: FieldIssue[] = [];
  const add = (field: string, message: string): void => {
    issues.push({ group: "routes", field, message });
  };
  if (routes.length > ROUTE_MAX) add("routes", `接口名规则最多 ${ROUTE_MAX} 条`);
  const parsedAll = routes.map((rule) => parsePattern(rule.path));
  routes.forEach((rule, index) => {
    const at = `routes[${index}]`;
    const parsed = parsedAll[index];
    if (parsed && !parsed.ok) add(`${at}.path`, parsed.reason);
    else if (rule.path.endsWith("/")) add(`${at}.path`, "路径不能以 / 结尾");
    if (rule.name_from.length === 0) add(`${at}.name_from`, "接口名至少一段");
    if (rule.name_from.length > 4) add(`${at}.name_from`, "接口名最多 4 段");
    rule.name_from.forEach((group, position) => {
      const field = `${at}.name_from[${position}]`;
      if (group.length === 0) add(field, `第 ${position + 1} 段至少写一个位置`);
      const seen = new Set<string>();
      for (const source of group) {
        const problem = sourceProblem(source);
        if (problem !== null) add(field, problem);
        const key = locationKey(source);
        if (seen.has(key)) add(field, `第 ${position + 1} 段的位置不能重复`);
        seen.add(key);
      }
    });
    if (parsed?.ok) {
      const mine = parsed.value;
      const clash = parsedAll
        .slice(0, index)
        .findIndex((other) => other.ok && patternsOverlap(mine, other.value));
      if (clash >= 0) add(`${at}.path`, `与第 ${clash + 1} 条规则的路径重叠`);
    }
  });
  return issues;
}

/** Whether some path matches both patterns: equal exact paths, or a prefix that the other path starts with. */
function patternsOverlap(a: ParsedPattern, b: ParsedPattern): boolean {
  if (!a.prefix && !b.prefix) return a.literal === b.literal;
  if (!a.prefix) return a.literal.startsWith(b.literal);
  if (!b.prefix) return b.literal.startsWith(a.literal);
  return a.literal.startsWith(b.literal) || b.literal.startsWith(a.literal);
}

/** What is wrong with one location, or null. Each kind has its own name rules (header-routes-design 3). */
function sourceProblem(source: string): string | null {
  const { kind, name } = splitSource(source);
  if (!ROUTE_KINDS.includes(kind)) return "来源只能是请求头、查询参数或正文字段";
  if (name.length === 0) return "名称不能为空";
  if (name.length > 64) return "名称最长 64 个字符";
  if (kind === "header") {
    return validToken(name) ? null : "请求头名只能含 HTTP 头名的字符：字母、数字和 - _ . 等";
  }
  if (kind === "query") {
    return QUERY_NAME.test(name) ? null : "参数名只能含字母、数字、. _ -，最长 64 个字符";
  }
  if (/[[\]]/.test(name)) return "正文字段不支持数组下标，批量调用按未知接口处理";
  return name.split(".").every((part) => BODY_KEY.test(part))
    ? null
    : "正文字段写成 a.b.c，每段只能含字母、数字、_ 和 -";
}

/** Two locations of one segment are the same when the gateway reads the same thing (header names fold case). */
function locationKey(source: string): string {
  const { kind, name } = splitSource(source);
  return kind === "header" ? `header.${name.toLowerCase()}` : source;
}

/**
 * Entries and bypass rules that name an exact path a route rule now covers. Their requests are named by the
 * rule from now on, so the rule no longer hits them: a warning, not a save error (header-routes-design 2).
 */
function unreachableRules(spec: SiteSpec): FieldIssue[] {
  const routes = spec.routes ?? [];
  if (routes.length === 0) return [];
  const issues: FieldIssue[] = [];
  const lists: Array<["entries" | "bypass", string[]]> = [
    ["entries", spec.entries],
    ["bypass", spec.bypass ?? []],
  ];
  for (const [group, rules] of lists) {
    rules.forEach((raw, index) => {
      const parsed = parsePattern(raw);
      if (!parsed.ok || parsed.value.prefix || ruleFor(routes, raw) === null) return;
      const message =
        group === "entries"
          ? "入口不再命中：这条路径有接口名规则，请求按逻辑路径判定，要改写为逻辑路径才能命中"
          : "绕过不再命中：这条路径有接口名规则，请求按逻辑路径判定，要改写为逻辑路径才能命中";
      issues.push({ group, field: `${group}[${index}]`, message });
    });
  }
  return issues;
}
