// Differences between two site configurations: a line diff for the YAML text, and a list of
// human-readable changes for the version history and the save dialog (docs/06 6.4.9).

import type { FieldKindDeclaration, LearningSettings, RouteRule, SiteSpec } from "../api/types.ts";
import { OBJECT_KIND_LABEL } from "./vocab.ts";
import { orderSpec, specToYaml } from "./yaml.ts";

export type LineOp = { op: "eq" | "add" | "del"; text: string };

/** Longest-common-subsequence line diff. Configurations are small, so O(n·m) is fine. */
export function lineDiff(before: string, after: string): LineOp[] {
  const a = before.length === 0 ? [] : before.split("\n");
  const b = after.length === 0 ? [] : after.split("\n");
  const n = a.length;
  const m = b.length;
  const table: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i -= 1) {
    for (let j = m - 1; j >= 0; j -= 1) {
      const row = table[i];
      const below = table[i + 1];
      if (!row || !below) continue;
      row[j] = a[i] === b[j] ? (below[j + 1] ?? 0) + 1 : Math.max(below[j] ?? 0, row[j + 1] ?? 0);
    }
  }
  const ops: LineOp[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      ops.push({ op: "eq", text: a[i] ?? "" });
      i += 1;
      j += 1;
    } else if ((table[i + 1]?.[j] ?? 0) >= (table[i]?.[j + 1] ?? 0)) {
      ops.push({ op: "del", text: a[i] ?? "" });
      i += 1;
    } else {
      ops.push({ op: "add", text: b[j] ?? "" });
      j += 1;
    }
  }
  while (i < n) {
    ops.push({ op: "del", text: a[i] ?? "" });
    i += 1;
  }
  while (j < m) {
    ops.push({ op: "add", text: b[j] ?? "" });
    j += 1;
  }
  return ops;
}

export function yamlDiff(before: SiteSpec | null, after: SiteSpec | null): LineOp[] {
  const left = before ? specToYaml(before) : "";
  const right = after ? specToYaml(after) : "";
  return lineDiff(left, right);
}

const MODE_TEXT: Record<string, string> = { observe: "观察", enforce: "拦截" };
const UNAVAILABLE_TEXT: Record<string, string> = { deny: "拒绝", allow: "放行" };
const ADVANCED_TEXT: Record<string, { label: string; unit: string }> = {
  jev_timeout_ms: { label: "Jev 超时", unit: " ms" },
  session_calls_per_minute: { label: "会话调用上限", unit: " 次/分钟" },
  address_calls_per_minute: { label: "地址调用上限", unit: " 次/分钟" },
  allow_cache_minutes: { label: "放行缓存时长", unit: " 分钟" },
};
const DEFAULTS: Record<string, string> = {
  jev_timeout_ms: "默认",
  session_calls_per_minute: "默认",
  address_calls_per_minute: "默认",
  allow_cache_minutes: "默认",
};

function setDiff(before: string[], after: string[]): { added: string[]; removed: string[] } {
  const left = new Set(before);
  const right = new Set(after);
  return {
    added: after.filter((item) => !left.has(item)),
    removed: before.filter((item) => !right.has(item)),
  };
}

const onOff = (value: boolean): string => (value ? "开" : "关");

/** The learning settings in words, in the order the settings sheet lists them (docs/06 6.4.9). */
const LEARNING_TEXT: Array<[label: string, read: (settings: LearningSettings) => string]> = [
  ["自动学习", (settings) => onOff(settings.auto_learn)],
  ["自动收紧", (settings) => onOff(settings.auto_tighten)],
  ["自动暂停", (settings) => onOff(settings.auto_pause)],
  ["agent", (settings) => onOff(settings.agent.enabled)],
  ["agent 每日上限", (settings) => `${settings.agent.daily_limit} 次`],
  [
    "学习阈值",
    (settings) => `${settings.thresholds.uses} 次 / ${settings.thresholds.sessions} 个会话`,
  ],
];

/** Route rules by path: a rule added or removed, or one whose interface-name sources changed. */
function routeChanges(before: RouteRule[], after: RouteRule[]): string[] {
  const left = new Map(before.map((rule): [string, RouteRule] => [rule.path, rule]));
  const right = new Map(after.map((rule): [string, RouteRule] => [rule.path, rule]));
  const changes: string[] = [];
  for (const rule of after) {
    if (!left.has(rule.path)) changes.push(`接口名规则 ＋1：${rule.path}`);
  }
  for (const rule of before) {
    if (!right.has(rule.path)) changes.push(`接口名规则 －1：${rule.path}`);
  }
  for (const rule of after) {
    const old = left.get(rule.path);
    if (old && JSON.stringify(old.name_from) !== JSON.stringify(rule.name_from)) {
      changes.push(`接口名规则 改动：${rule.path}`);
    }
  }
  return changes;
}

/** The scope of a field-kind declaration in words, e.g. `/api/appointments*`; empty for the whole site. */
function scopeOf(declaration: FieldKindDeclaration): string {
  return declaration.in && declaration.in.length > 0 ? declaration.in.join("、") : "";
}

/**
 * Field-kind declarations by field and scope: one added or removed, or one whose class changed. A changed class
 * reads as the position and the move, e.g. `响应 /api/appointments* [].doc_id 从医生改为文档`.
 */
function fieldKindChanges(before: FieldKindDeclaration[], after: FieldKindDeclaration[]): string[] {
  const keyOf = (item: FieldKindDeclaration): string => JSON.stringify([item.field, item.in ?? []]);
  const left = new Map(before.map((item): [string, FieldKindDeclaration] => [keyOf(item), item]));
  const right = new Map(after.map((item): [string, FieldKindDeclaration] => [keyOf(item), item]));
  const changes: string[] = [];
  for (const item of after) {
    const old = left.get(keyOf(item));
    const scope = scopeOf(item);
    if (old === undefined) {
      const where = scope ? `（仅 ${scope}）` : "";
      changes.push(`字段归类 ＋1：${item.field} 归为${classOf(item.kind)}${where}`);
    } else if (old.kind !== item.kind) {
      const where = scope ? `响应 ${scope} ${item.field}` : `字段 ${item.field}`;
      changes.push(`${where} 从${classOf(old.kind)}改为${classOf(item.kind)}`);
    }
  }
  for (const item of before) {
    if (right.has(keyOf(item))) continue;
    const scope = scopeOf(item);
    changes.push(`字段归类 －1：${item.field}${scope ? `（仅 ${scope}）` : ""}`);
  }
  return changes;
}

function classOf(kind: string): string {
  return OBJECT_KIND_LABEL[kind] ?? kind;
}

/** Each learning setting that moved; a configuration with no learning settings reads as the defaults. */
function learningChanges(
  before: LearningSettings | undefined,
  after: LearningSettings | undefined,
): string[] {
  const changes: string[] = [];
  for (const [label, read] of LEARNING_TEXT) {
    const old = before === undefined ? "默认" : read(before);
    const next = after === undefined ? "默认" : read(after);
    if (old !== next) changes.push(`学习 ${label} ${old} → ${next}`);
  }
  return changes;
}

/** Human-readable changes, e.g. `入口 ＋1：/rest/admin/application-configuration`. */
export function semanticChanges(before: SiteSpec | null, after: SiteSpec | null): string[] {
  if (!before && after) return ["创建站点"];
  if (before && !after) return ["删除站点"];
  if (!before || !after) return [];
  const changes: string[] = [];
  const entries = setDiff(before.entries, after.entries);
  for (const rule of entries.added) changes.push(`入口 ＋1：${rule}`);
  for (const rule of entries.removed) changes.push(`入口 －1：${rule}`);
  const bypass = setDiff(before.bypass ?? [], after.bypass ?? []);
  for (const rule of bypass.added) changes.push(`绕过 ＋1：${rule}`);
  for (const rule of bypass.removed) changes.push(`绕过 －1：${rule}`);
  changes.push(...routeChanges(before.routes ?? [], after.routes ?? []));
  if (before.hosts.join(",") !== after.hosts.join(",")) {
    changes.push(`Host ${before.hosts.join("、")} → ${after.hosts.join("、")}`);
  }
  if (before.origin !== after.origin) changes.push(`源站 ${before.origin} → ${after.origin}`);
  const oldCred = before.session.cookie
    ? `Cookie ${before.session.cookie}`
    : `请求头 ${before.session.header ?? ""}`;
  const newCred = after.session.cookie
    ? `Cookie ${after.session.cookie}`
    : `请求头 ${after.session.header ?? ""}`;
  if (oldCred !== newCred) changes.push(`会话凭证 ${oldCred} → ${newCred}`);
  const oldMode = before.mode ?? "observe";
  const newMode = after.mode ?? "observe";
  if (oldMode !== newMode) {
    changes.push(`模式 ${MODE_TEXT[oldMode] ?? oldMode} → ${MODE_TEXT[newMode] ?? newMode}`);
  }
  const oldUnavail = before.on_jev_unavailable ?? "deny";
  const newUnavail = after.on_jev_unavailable ?? "deny";
  if (oldUnavail !== newUnavail) {
    changes.push(
      `Jev 不可用时 ${UNAVAILABLE_TEXT[oldUnavail] ?? oldUnavail} → ${UNAVAILABLE_TEXT[newUnavail] ?? newUnavail}`,
    );
  }
  const oldAdv = before.advanced ?? {};
  const newAdv = after.advanced ?? {};
  for (const key of Object.keys(ADVANCED_TEXT)) {
    const info = ADVANCED_TEXT[key];
    const a = (oldAdv as Record<string, unknown>)[key];
    const b = (newAdv as Record<string, unknown>)[key];
    if (a === b || !info) continue;
    const show = (value: unknown) =>
      value === undefined ? (DEFAULTS[key] ?? "默认") : `${String(value)}${info.unit}`;
    changes.push(`${info.label} ${show(a)} → ${show(b)}`);
  }
  const secretsOld = oldAdv.secret_fields ?? [];
  const secretsNew = newAdv.secret_fields ?? [];
  const secretDiff = setDiff(secretsOld, secretsNew);
  for (const word of secretDiff.added) changes.push(`追加脱敏词 ＋${word}`);
  for (const word of secretDiff.removed) changes.push(`追加脱敏词 －${word}`);
  const pairKey = (pair: readonly [string, string]) => `${pair[0]} ↔ ${pair[1]}`;
  const synDiff = setDiff(
    (oldAdv.synonyms ?? []).map(pairKey),
    (newAdv.synonyms ?? []).map(pairKey),
  );
  for (const pair of synDiff.added) changes.push(`同义词 ＋${pair}`);
  for (const pair of synDiff.removed) changes.push(`同义词 －${pair}`);
  changes.push(...routeChanges(before.routes ?? [], after.routes ?? []));
  const oldObjects = before.objects ?? {};
  const newObjects = after.objects ?? {};
  changes.push(...fieldKindChanges(oldObjects.field_kinds ?? [], newObjects.field_kinds ?? []));
  changes.push(...learningChanges(oldObjects.learning, newObjects.learning));
  return changes;
}

/** Stable serialisation used to decide whether a draft differs from the saved version. */
export function canonical(spec: SiteSpec | null): string {
  return spec ? JSON.stringify(orderSpec(spec)) : "";
}
