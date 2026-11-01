import type { SiteSpecJson } from "./types.ts";

export interface FieldChange {
  field: string;
  before: unknown;
  after: unknown;
}

const FIELD_ORDER: (keyof SiteSpecJson)[] = [
  "name",
  "hosts",
  "origin",
  "session",
  "entries",
  "bypass",
  "mode",
  "on_jev_unavailable",
];

/**
 * A simple top-level field diff between two site configs (or null, meaning "did not exist" —
 * site creation has `before: null`, site deletion has `after: null`). Good enough for a compact
 * before/after list; it does not diff inside arrays or objects field-by-field.
 */
export function diffSiteSpec(
  before: SiteSpecJson | null,
  after: SiteSpecJson | null,
): FieldChange[] {
  if (before === null && after === null) return [];
  if (before === null) {
    return FIELD_ORDER.map((field) => ({ field, before: undefined, after: after?.[field] }));
  }
  if (after === null) {
    return FIELD_ORDER.map((field) => ({ field, before: before?.[field], after: undefined }));
  }
  const changes: FieldChange[] = [];
  for (const field of FIELD_ORDER) {
    const beforeValue = before[field];
    const afterValue = after[field];
    if (JSON.stringify(beforeValue) !== JSON.stringify(afterValue)) {
      changes.push({ field, before: beforeValue, after: afterValue });
    }
  }
  return changes;
}

/** Human labels for the diff's field names, used by the history panel. */
export const FIELD_LABELS: Record<string, string> = {
  name: "站点名",
  hosts: "域名",
  origin: "源站地址",
  session: "会话凭证",
  entries: "入口路径",
  bypass: "跳过路径",
  mode: "模式",
  on_jev_unavailable: "Jev 不可用时",
};

export function formatFieldValue(value: unknown): string {
  if (value === undefined) return "（不存在）";
  if (value === null) return "（无）";
  if (Array.isArray(value)) return value.length ? value.join(", ") : "（空）";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}
