// Rules of the Jev page (docs/06 6.4.6, docs/07 7.9.3 and 7.9.7), kept free of React so they can be
// read in one place: what each quick chip adds to the request list, the number it shows, the words a
// row gets for Jev's own conclusion, and the labels of the hourly bars.

import { qs } from "../../api/client.ts";
import type { DecisionPath, JevStats, RequestRow } from "../../api/types.ts";
import type { JevChip } from "../../app/search-schema.ts";
import type { Scope } from "../../app/scope.ts";
import { type FilterError, parseFilter } from "../../lib/filter-dsl.ts";
import { CONCLUSION_LABEL, FAILURE_INFO } from "../../lib/vocab.ts";

/** The 70 % line of the confidence histogram, and the threshold of the "置信度低" chip. */
export const CONFIDENCE_LINE = 0.7;

/** Every failure code, joined: the "失败" chip lists them all (7.9.3 `jev_failure`). */
const ALL_FAILURES = Object.keys(FAILURE_INFO).join(",");

export const JEV_CHIP_INFO: Record<JevChip, { label: string; title: string }> = {
  all: { label: "全部", title: "全部 Jev 调用" },
  blocked: { label: "拒绝", title: "Jev 判定越权或攻击（Jev 拒绝）" },
  allowed: { label: "通过", title: "Jev 判定访问有依据、内容无攻击（Jev 通过）" },
  failed: { label: "失败", title: "没有得到判定：超时、出错、达到上限或答不上来" },
  low: { label: "置信度低", title: "两个问题中较小的置信度低于 70%" },
  slow: { label: "慢于 p95", title: "耗时不低于这段时间的 p95" },
  trimmed: { label: "裁剪过", title: "为满足 8 KiB 上限，状态被裁剪过的调用" },
};

/** What a chip adds to the list. Null while the chip has no threshold (no p95 without a success). */
function chipParams(chip: JevChip, p95: number | null): Record<string, string> | null {
  switch (chip) {
    case "all":
      return {};
    case "blocked":
      return { decision_path: "jev_deny" };
    case "allowed":
      return { decision_path: "jev_allow" };
    case "failed":
      return { jev_failure: ALL_FAILURES };
    case "low":
      return { max_confidence: String(CONFIDENCE_LINE) };
    case "slow":
      return p95 === null ? null : { min_jev_ms: String(Math.round(p95)) };
    case "trimmed":
      return { jev_trimmed: "true" };
  }
}

export type JevListPlan = {
  query: string;
  errors: FilterError[];
  /** The chip and the filter text ask for different answers, so no row can match both. */
  impossible: boolean;
  /** The "慢于 p95" chip has no threshold yet. */
  noThreshold: boolean;
};

function intersect(a: string, b: string): string[] {
  const other = b.split(",");
  return a.split(",").filter((value) => other.includes(value));
}

/**
 * The query of the Jev list: rows that carry a Jev exchange, the chip, and the filter text, which
 * combine with AND. The text names keys the same way the request list does (docs/06 6.4.3).
 */
export function planJevList(input: {
  q: string;
  chip: JevChip;
  scope: Scope;
  p95: number | null;
}): JevListPlan {
  const { q, chip, scope, p95 } = input;
  const parsed = parseFilter(q);
  const chosen = chipParams(chip, p95);
  const merged: Record<string, string> = { has_jev: "true", ...chosen };
  let impossible = false;

  for (const [key, value] of Object.entries(parsed.params)) {
    const existing = merged[key];
    if ((key === "outcome" || key === "decision_path") && existing !== undefined) {
      const both = intersect(existing, value);
      if (both.length === 0) impossible = true;
      merged[key] = both.join(",");
    } else {
      merged[key] = value;
    }
  }

  return {
    query: qs({
      ...merged,
      site: merged.site ?? scope.site,
      since_millis: scope.since,
      until_millis: scope.until,
    }),
    errors: parsed.errors,
    impossible,
    noThreshold: chosen === null,
  };
}

/**
 * Calls whose confidence is below 70 %: the histogram buckets under the line (0.0–0.1 up to 0.6–0.7),
 * so the count is exact at the histogram's own resolution.
 */
export function lowConfidenceCount(stats: JevStats): number {
  return stats.confidence_histogram.counts
    .slice(0, Math.round(CONFIDENCE_LINE * 10))
    .reduce((sum, count) => sum + count, 0);
}

/**
 * The number a chip shows, from the statistics of the same window. Undefined while the statistics
 * load; null when the statistics carry no count for the chip (the contract has none for "慢于 p95"
 * and "裁剪过" yet), so the chip shows its name alone.
 */
export function chipCount(chip: JevChip, stats: JevStats | undefined): number | null | undefined {
  if (stats === undefined) return undefined;
  switch (chip) {
    case "all":
      return stats.calls;
    case "blocked":
      return stats.by_conclusion.deny ?? 0;
    case "allowed":
      return stats.by_conclusion.allow ?? 0;
    case "failed":
      return Object.values(stats.by_failure).reduce((sum, count) => sum + (count ?? 0), 0);
    case "low":
      return lowConfidenceCount(stats);
    case "slow":
    case "trimmed":
      return null;
  }
}

const CONCLUSION_OF: Partial<Record<DecisionPath, string>> = {
  jev_allow: CONCLUSION_LABEL.allow,
  jev_deny: CONCLUSION_LABEL.deny,
  jev_unavailable: CONCLUSION_LABEL.unknown,
  cached_allow: `${CONCLUSION_LABEL.allow}（缓存）`,
};

/** Jev's own answer for a row (docs/06 6.6.3); null when the row carries no answer. */
export function conclusionText(row: RequestRow): string | null {
  return CONCLUSION_OF[row.decision_path] ?? null;
}

const pad = (value: number): string => String(value).padStart(2, "0");

/** The label of one hourly bar: the hour, with the date when the window spans more than a day. */
export function hourLabel(ms: number, withDate: boolean): string {
  const date = new Date(ms);
  const hour = `${pad(date.getHours())}:00`;
  return withDate ? `${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${hour}` : hour;
}

/** Only the first characters of the instruction version, as the health card shows them. */
export function shortPrompt(prompt: string): string {
  return `${prompt.slice(0, 8)}…`;
}
