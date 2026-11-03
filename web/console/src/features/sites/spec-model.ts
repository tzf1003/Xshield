// Helpers for a site draft (docs/06 6.4.9, 6.4.10, 7.6): reading YAML or JSON into a configuration with
// the line and column of a mistake, the three-way merge used when a save meets a newer version, applying
// a suggestion to a draft, and how a value reads in words. Pure functions: no React, no requests.

import { parseDocument } from "yaml";
import type {
  Advanced,
  LearningSettings,
  ObjectsSpec,
  RouteRule,
  SessionCredential,
  SiteSpec,
  SuggestionAction,
} from "../../api/types.ts";
import {
  declarationKey,
  declarationsOf,
  learningText,
  parseLearning,
  parseObjects,
} from "../../lib/objects-validate.ts";
import { isRecord } from "../../lib/storage.ts";
import { parseSiteText } from "../../lib/yaml.ts";
import { PARAM_INFO } from "../../lib/vocab.ts";

export const SESSION_NAMES = [
  "JSESSIONID",
  "SESSIONID",
  "connect.sid",
  "token",
  "Authorization",
] as const;
export const LOGIN_PATHS = ["/login", "/api/login", "/rest/user/login"] as const;
export const STATIC_PATHS = ["/static/*", "/assets/*", "/favicon.ico"] as const;

export const NUMERIC_ADVANCED = [
  "jev_timeout_ms",
  "session_calls_per_minute",
  "address_calls_per_minute",
  "allow_cache_minutes",
] as const;
export type NumericAdvanced = (typeof NUMERIC_ADVANCED)[number];

/** The configuration a new site starts from. Name and hosts are empty, so validation asks for them. */
export function emptySpec(): SiteSpec {
  return {
    name: "",
    hosts: [],
    origin: "",
    session: { cookie: "" },
    entries: [],
    bypass: [],
    mode: "observe",
    on_jev_unavailable: "deny",
  };
}

export function sameJson(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

/** The list with the new items appended, skipping any already present. */
export function addUnique(list: readonly string[], items: readonly string[]): string[] {
  const out = [...list];
  for (const item of items) if (!out.includes(item)) out.push(item);
  return out;
}

export function withAdvanced(spec: SiteSpec, advanced: Advanced | undefined): SiteSpec {
  return { ...spec, advanced };
}

export function sessionKind(spec: SiteSpec): "cookie" | "header" {
  return spec.session.header !== undefined ? "header" : "cookie";
}

export function sessionName(spec: SiteSpec): string {
  return spec.session.header ?? spec.session.cookie ?? "";
}

/** Exactly one of cookie or header is written, as the gateway requires. */
export function withSession(spec: SiteSpec, kind: "cookie" | "header", name: string): SiteSpec {
  const session: SessionCredential = kind === "cookie" ? { cookie: name } : { header: name };
  return { ...spec, session };
}

/** Plain-word labels of the set advanced parameters, e.g. `Jev 超时 3000 ms`. */
export function customAdvanced(advanced: Advanced | undefined): string[] {
  const labels: string[] = [];
  if (!advanced) return labels;
  for (const key of NUMERIC_ADVANCED) {
    const value = advanced[key];
    if (value !== undefined)
      labels.push(`${PARAM_INFO[key].label} ${value} ${PARAM_INFO[key].unit}`);
  }
  if (advanced.secret_fields !== undefined)
    labels.push(`追加脱敏词 ${advanced.secret_fields.length} 个`);
  if (advanced.synonyms !== undefined) labels.push(`同义词 ${advanced.synonyms.length} 组`);
  return labels;
}

/** What applying a suggestion changes, in the words of the save dialog. */
export function actionLines(action: SuggestionAction): string[] {
  const lines: string[] = [];
  if (action.add_entry) lines.push(`入口 ＋ ${action.add_entry}`);
  if (action.add_bypass) lines.push(`绕过 ＋ ${action.add_bypass}`);
  if (action.add_secret_field) lines.push(`追加脱敏词 ＋ ${action.add_secret_field}`);
  const set = action.set_advanced;
  if (set) {
    for (const key of NUMERIC_ADVANCED) {
      const value = set[key];
      if (value !== undefined)
        lines.push(`${PARAM_INFO[key].label} → ${value} ${PARAM_INFO[key].unit}`);
    }
  }
  return lines;
}

/** Applies one suggested change to a configuration; the input is not changed. */
export function applyAction(spec: SiteSpec, action: SuggestionAction): SiteSpec {
  let next: SiteSpec = { ...spec };
  if (action.add_entry) next = { ...next, entries: addUnique(next.entries, [action.add_entry]) };
  if (action.add_bypass)
    next = { ...next, bypass: addUnique(next.bypass ?? [], [action.add_bypass]) };
  const advanced: Advanced = { ...(next.advanced ?? {}) };
  if (action.add_secret_field) {
    advanced.secret_fields = addUnique(advanced.secret_fields ?? [], [action.add_secret_field]);
  }
  const set = action.set_advanced;
  if (set) {
    for (const key of NUMERIC_ADVANCED) {
      const value = set[key];
      if (value !== undefined) advanced[key] = value;
    }
  }
  next = { ...next, advanced };
  return next;
}

type Check<T> = { ok: true; value: T } | { ok: false; message: string };

const fail = (message: string): { ok: false; message: string } => ({ ok: false, message });

function textOf(value: unknown, label: string): Check<string> {
  if (value === undefined || value === null) return { ok: true, value: "" };
  if (typeof value === "string") return { ok: true, value };
  if (typeof value === "number") return { ok: true, value: String(value) };
  return fail(`${label} 应为文字`);
}

function listOf(value: unknown, label: string, example: string): Check<string[]> {
  if (value === undefined || value === null) return { ok: true, value: [] };
  if (Array.isArray(value) && value.every((item) => typeof item === "string")) {
    return { ok: true, value: value as string[] };
  }
  return fail(`${label} 应为列表，例如 ${example}`);
}

function enumOf<T extends string>(
  value: unknown,
  options: readonly T[],
  label: string,
): Check<T | undefined> {
  if (value === undefined || value === null) return { ok: true, value: undefined };
  const found = options.find((option) => option === value);
  if (found === undefined) return fail(`${label} 只能是 ${options.join(" 或 ")}`);
  return { ok: true, value: found };
}

function sessionOf(value: unknown): Check<SessionCredential> {
  if (value === undefined || value === null) return { ok: true, value: { cookie: "" } };
  if (!isRecord(value)) return fail("会话凭证应写成 cookie 或 header");
  const hasCookie = value.cookie !== undefined;
  const hasHeader = value.header !== undefined;
  if (hasCookie === hasHeader) return fail("会话凭证需要写 cookie 或 header 其中一个");
  if (hasCookie) {
    const cookie = textOf(value.cookie, "Cookie 名");
    if (!cookie.ok) return cookie;
    return { ok: true, value: { cookie: cookie.value } };
  }
  const header = textOf(value.header, "请求头名");
  if (!header.ok) return header;
  return { ok: true, value: { header: header.value } };
}

/** The interface-name rules of a YAML or JSON configuration: each rule has a path and its segments. */
function routesOf(value: unknown): Check<RouteRule[] | undefined> {
  if (value === undefined || value === null) return { ok: true, value: undefined };
  if (!Array.isArray(value)) return fail("接口名规则应写成列表，每条有 path 和 name_from");
  const rules: RouteRule[] = [];
  const items: unknown[] = value;
  for (const item of items) {
    if (!isRecord(item) || typeof item.path !== "string" || !Array.isArray(item.name_from)) {
      return fail("接口名规则每条要写成 path 和 name_from 两个键");
    }
    const segments: unknown[] = item.name_from;
    const groups: string[][] = [];
    for (const segment of segments) {
      const locations: unknown[] = Array.isArray(segment) ? segment : [];
      const texts = locations.filter(
        (location): location is string => typeof location === "string",
      );
      if (!Array.isArray(segment) || texts.length !== locations.length) {
        return fail("name_from 每一段要写成位置列表，例如 [header.X-Service-Id]");
      }
      groups.push(texts);
    }
    rules.push({ path: item.path, name_from: groups });
  }
  return { ok: true, value: rules };
}

function advancedOf(value: unknown): Check<Advanced | undefined> {
  if (value === undefined || value === null) return { ok: true, value: undefined };
  if (!isRecord(value)) return fail("高级判定参数应写成 名称: 值 的形式");
  const out: Advanced = {};
  for (const key of NUMERIC_ADVANCED) {
    const raw = value[key];
    if (raw === undefined || raw === null) continue;
    if (typeof raw !== "number") return fail(`${key} 应为数字`);
    out[key] = raw;
  }
  if (value.secret_fields !== undefined && value.secret_fields !== null) {
    const words = listOf(value.secret_fields, "secret_fields", "[idcard, ssn]");
    if (!words.ok) return words;
    out.secret_fields = words.value;
  }
  if (value.synonyms !== undefined && value.synonyms !== null) {
    if (!Array.isArray(value.synonyms))
      return fail("synonyms 应为词组列表，例如 [[payment, card]]");
    const pairs: Array<[string, string]> = [];
    for (const pair of value.synonyms) {
      if (
        !Array.isArray(pair) ||
        pair.length !== 2 ||
        typeof pair[0] !== "string" ||
        typeof pair[1] !== "string"
      ) {
        return fail("synonyms 每组应为两个词，例如 [payment, card]");
      }
      pairs.push([pair[0], pair[1]]);
    }
    out.synonyms = pairs;
  }
  if (value.field_kinds !== undefined && value.field_kinds !== null) {
    const declarations = declarationsOf(value.field_kinds);
    if (!declarations.ok) return declarations;
    out.field_kinds = declarations.value;
  }
  return { ok: true, value: out };
}

/**
 * Checks the shape of a parsed object so the form can rely on it: lists are lists, the session has one
 * credential, and advanced values are numbers. Field validity (ranges, names) is left to validateSpec.
 */
export function normalizeSpec(raw: unknown): Check<SiteSpec> {
  if (!isRecord(raw)) return fail("配置必须是一个对象");
  const name = textOf(raw.name, "站点名");
  if (!name.ok) return name;
  const hosts = listOf(raw.hosts, "Host", "[a.example.com]");
  if (!hosts.ok) return hosts;
  const origin = textOf(raw.origin, "源站地址");
  if (!origin.ok) return origin;
  const session = sessionOf(raw.session);
  if (!session.ok) return session;
  const entries = listOf(raw.entries, "入口", "[/login]");
  if (!entries.ok) return entries;
  const bypass = listOf(raw.bypass, "绕过", "[/static/*]");
  if (!bypass.ok) return bypass;
  const mode = enumOf(raw.mode, ["observe", "enforce"] as const, "模式");
  if (!mode.ok) return mode;
  const unavailable = enumOf(raw.on_jev_unavailable, ["deny", "allow"] as const, "Jev 不可用时");
  if (!unavailable.ok) return unavailable;
  const advanced = advancedOf(raw.advanced);
  if (!advanced.ok) return advanced;
  const routes = routesOf(raw.routes);
  if (!routes.ok) return routes;
  const objects = parseObjects(raw.objects);
  if (!objects.ok) return fail(objects.message);
  const spec: SiteSpec = {
    name: name.value,
    hosts: hosts.value,
    origin: origin.value,
    session: session.value,
    entries: entries.value,
    bypass: bypass.value,
  };
  if (mode.value !== undefined) spec.mode = mode.value;
  if (unavailable.value !== undefined) spec.on_jev_unavailable = unavailable.value;
  if (advanced.value !== undefined) spec.advanced = advanced.value;
  if (routes.value !== undefined && routes.value.length > 0) spec.routes = routes.value;
  if (objects.value !== undefined) spec.objects = objects.value;
  return { ok: true, value: spec };
}

export type SpecText =
  | { ok: true; spec: SiteSpec }
  | { ok: false; line: number | null; column: number | null; message: string };

/**
 * Reads YAML or JSON pasted or typed by the user. A YAML syntax error carries its line and column, so the
 * editor can mark the exact place (docs/06 6.4.9: "YAML 第 12 行有错误").
 */
export function parseSpecText(text: string): SpecText {
  const parsed = parseSiteText(text);
  if (!parsed.ok) {
    if (!text.trim().startsWith("{")) {
      const first = parseDocument(text).errors[0];
      const position = first?.linePos?.[0];
      if (position) {
        const { line, col } = position;
        return { ok: false, line, column: col, message: `YAML 第 ${line} 行第 ${col} 列有错误` };
      }
    }
    return { ok: false, line: parsed.line, column: null, message: parsed.message };
  }
  const shaped = normalizeSpec(parsed.value);
  if (!shaped.ok) return { ok: false, line: null, column: null, message: shaped.message };
  return { ok: true, spec: shaped.value };
}

export type Conflict = { field: string; label: string; mine: unknown; theirs: unknown };
export type Choices = Record<string, "mine" | "theirs">;

const CONFLICT_LABELS: Record<string, string> = {
  origin: "源站地址",
  session: "会话凭证",
  mode: "模式",
  on_jev_unavailable: "Jev 不可用时",
  "advanced.jev_timeout_ms": "Jev 超时",
  "advanced.session_calls_per_minute": "会话调用上限",
  "advanced.address_calls_per_minute": "地址调用上限",
  "advanced.allow_cache_minutes": "放行缓存时长",
  "objects.learning": "学习设置",
};

/**
 * Lists merge without conflict: what this draft removed is removed from the latest list, and what it added
 * is appended. Keys identify items (a rule, a host, or a pair of synonyms).
 */
function mergeList<T>(base: T[], mine: T[], latest: T[], key: (item: T) => string): T[] {
  const baseKeys = new Set(base.map(key));
  const mineKeys = new Set(mine.map(key));
  const removed = new Set([...baseKeys].filter((item) => !mineKeys.has(item)));
  const merged = latest.filter((item) => !removed.has(key(item)));
  const seen = new Set(merged.map(key));
  for (const item of mine) {
    const id = key(item);
    if (baseKeys.has(id) || seen.has(id)) continue;
    seen.add(id);
    merged.push(item);
  }
  return merged;
}

/**
 * Re-applies the changes of a draft (`mine`, made on top of `base`) to a newer version (`latest`).
 * A scalar field changed on both sides is a conflict; the caller shows it and passes the choice back in
 * `choices`. Until a conflict is chosen, the latest value is used.
 */
export function rebaseSpec(
  base: SiteSpec,
  mine: SiteSpec,
  latest: SiteSpec,
  choices: Choices = {},
): { spec: SiteSpec; conflicts: Conflict[] } {
  const conflicts: Conflict[] = [];
  const pick = <T>(field: string, b: T, m: T, l: T): T => {
    if (sameJson(m, b)) return l;
    if (sameJson(l, b) || sameJson(l, m)) return m;
    conflicts.push({ field, label: CONFLICT_LABELS[field] ?? field, mine: m, theirs: l });
    return choices[field] === "mine" ? m : l;
  };
  const advanced: Advanced = {};
  for (const key of NUMERIC_ADVANCED) {
    const value = pick<number | undefined>(
      `advanced.${key}`,
      base.advanced?.[key],
      mine.advanced?.[key],
      latest.advanced?.[key],
    );
    if (value !== undefined) advanced[key] = value;
  }
  const secrets = mergeList(
    base.advanced?.secret_fields ?? [],
    mine.advanced?.secret_fields ?? [],
    latest.advanced?.secret_fields ?? [],
    (word) => word,
  );
  if (secrets.length > 0) advanced.secret_fields = secrets;
  const synonyms = mergeList(
    base.advanced?.synonyms ?? [],
    mine.advanced?.synonyms ?? [],
    latest.advanced?.synonyms ?? [],
    (pair) => `${pair[0]}|${pair[1]}`,
  );
  if (synonyms.length > 0) advanced.synonyms = synonyms;
  const learning = pick<LearningSettings | undefined>(
    "objects.learning",
    base.objects?.learning,
    mine.objects?.learning,
    latest.objects?.learning,
  );
  const declarations = mergeList(
    base.advanced?.field_kinds ?? [],
    mine.advanced?.field_kinds ?? [],
    latest.advanced?.field_kinds ?? [],
    declarationKey,
  );
  if (declarations.length > 0) advanced.field_kinds = declarations;
  // The object map's classes and confirmed positions are lists the draft adds to and removes from (console design
  // 4.3), so they merge like the other lists; the learning settings are one value.
  const classes = mergeList(
    base.objects?.classes ?? [],
    mine.objects?.classes ?? [],
    latest.objects?.classes ?? [],
    (item) => item.id,
  );
  const slots = mergeList(
    base.objects?.slots ?? [],
    mine.objects?.slots ?? [],
    latest.objects?.slots ?? [],
    (item) => item.key,
  );
  const objects: ObjectsSpec | undefined =
    learning === undefined && classes.length === 0 && slots.length === 0
      ? undefined
      : {
          ...(learning === undefined ? {} : { learning }),
          ...(classes.length === 0 ? {} : { classes }),
          ...(slots.length === 0 ? {} : { slots }),
        };
  const spec: SiteSpec = {
    name: latest.name,
    hosts: mergeList(base.hosts, mine.hosts, latest.hosts, (host) => host),
    origin: pick("origin", base.origin, mine.origin, latest.origin),
    session: pick("session", base.session, mine.session, latest.session),
    entries: mergeList(base.entries, mine.entries, latest.entries, (rule) => rule),
    bypass: mergeList(base.bypass ?? [], mine.bypass ?? [], latest.bypass ?? [], (rule) => rule),
    mode: pick("mode", base.mode, mine.mode, latest.mode),
    on_jev_unavailable: pick(
      "on_jev_unavailable",
      base.on_jev_unavailable,
      mine.on_jev_unavailable,
      latest.on_jev_unavailable,
    ),
    advanced: Object.keys(advanced).length > 0 ? advanced : undefined,
    objects,
  };
  // A rule is identified by its whole text: an edited rule is a removal and an addition.
  const routes = mergeList(base.routes ?? [], mine.routes ?? [], latest.routes ?? [], (rule) =>
    JSON.stringify(rule),
  );
  if (routes.length > 0) spec.routes = routes;
  return { spec, conflicts };
}

const VALUE_UNITS: Record<string, string> = {
  "advanced.jev_timeout_ms": " ms",
  "advanced.session_calls_per_minute": " 次/分钟",
  "advanced.address_calls_per_minute": " 次/分钟",
  "advanced.allow_cache_minutes": " 分钟",
};

/** A configuration value in words, for the conflict choices and the change summaries. */
export function valueText(field: string, value: unknown): string {
  if (value === undefined || value === null) return "默认";
  if (field === "objects.learning") {
    const learning = parseLearning(value);
    return learning.ok ? learningText(learning.value) : "无法显示";
  }
  if (field === "session" && isRecord(value)) {
    if (typeof value.cookie === "string") return `Cookie ${value.cookie}`;
    if (typeof value.header === "string") return `请求头 ${value.header}`;
  }
  if (field === "mode") return value === "enforce" ? "拦截" : "观察";
  if (field === "on_jev_unavailable") return value === "allow" ? "放行" : "拒绝";
  if (Array.isArray(value)) {
    const items = value.map((item) => (Array.isArray(item) ? item.join(" ↔ ") : String(item)));
    return items.length > 0 ? items.join("、") : "无";
  }
  return `${String(value)}${VALUE_UNITS[field] ?? ""}`;
}
