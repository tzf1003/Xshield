// Turns the page's state (filter text, quick chip, the switch for bypass and unknown-site rows, the
// window) into the query strings the API takes (docs/06 6.4.3, docs/07 7.9.3). Chips and the filter
// text combine with AND; when both name the outcome, the lists are intersected, and an empty
// intersection shows no rows. The default list leaves out bypass and unknown-site rows (scope judged);
// scope=all brings them back. A lookup by request ID, session or exact path always includes them.

import { qs } from "../../api/client.ts";
import type { RequestCounts } from "../../api/types.ts";
import type { ChipId } from "../../app/search-schema.ts";
import type { Scope } from "../../app/scope.ts";
import { type FilterError, type FilterParams, parseFilter } from "../../lib/filter-dsl.ts";

export const CHIPS: ReadonlyArray<{ id: ChipId; label: string }> = [
  { id: "judged", label: "已判定" },
  { id: "attention", label: "需要关注" },
  { id: "blocked", label: "拦截" },
  { id: "would_block", label: "本应拦截" },
  { id: "unjudged", label: "未经判定" },
  { id: "jev", label: "Jev 调用" },
  { id: "no_session", label: "无会话" },
  { id: "bypass", label: "绕过" },
];

/** What each chip adds to the list. "已判定" adds nothing: the default list already leaves those rows out. */
const CHIP_FILTER: Record<ChipId, FilterParams> = {
  judged: {},
  attention: { outcome: "blocked,would_block,unjudged" },
  blocked: { outcome: "blocked" },
  would_block: { outcome: "would_block" },
  unjudged: { outcome: "unjudged" },
  jev: { has_jev: "true" },
  no_session: { decision_path: "no_session" },
  bypass: { decision_path: "bypass" },
};

/** The terms the "＋条件" menu adds, so a user never has to remember the syntax (docs/06 6.4.3). */
export const CONDITION_MENU: ReadonlyArray<{ term: string; label: string }> = [
  { term: "outcome:blocked", label: "结论：拦截" },
  { term: "outcome:would_block", label: "结论：本应拦截" },
  { term: "outcome:unjudged", label: "结论：未经判定" },
  { term: "outcome:allowed", label: "结论：放行" },
  { term: "decision:jev_deny", label: "判定：Jev 拒绝" },
  { term: "decision:jev_unavailable", label: "判定：Jev 不可用" },
  { term: "decision:no_session", label: "判定：无会话" },
  { term: "access:DENY", label: "Jev 访问：越权" },
  { term: "attack:ATTACK", label: "Jev 内容：攻击" },
  { term: "failure:JEV_TIMEOUT", label: "Jev 失败：超时" },
  { term: "conf<70%", label: "Jev 置信度低于 70%" },
  { term: "ms>1000", label: "耗时超过 1000 ms" },
  { term: "status:4xx", label: "状态码：4xx" },
  { term: "method:POST", label: "方法：POST" },
  { term: "entry:true", label: "命中入口" },
];

export type ListPlan = {
  query: string;
  errors: FilterError[];
  impossible: boolean;
  /** True when the list includes bypass and unknown-site rows (the switch, or a lookup). */
  includesAll: boolean;
};

function intersect(a: string, b: string): string[] {
  const other = b.split(",");
  return a.split(",").filter((value) => other.includes(value));
}

/** A lookup by one request, session or exact path finds bypass and unknown-site rows too (docs/06 6.4.3). */
function isLookup(params: FilterParams): boolean {
  if (params.request_id !== undefined || params.session !== undefined) return true;
  return params.path !== undefined && !params.path.endsWith("*");
}

export function planList(input: { q: string; chip: ChipId; all: boolean; scope: Scope }): ListPlan {
  const { q, chip, all, scope } = input;
  const parsed = parseFilter(q);
  const merged: FilterParams = { ...CHIP_FILTER[chip] };
  let impossible = false;

  for (const [key, value] of Object.entries(parsed.params)) {
    const existing = merged[key];
    if (key === "outcome" && existing !== undefined) {
      const both = intersect(existing, value);
      if (both.length === 0) impossible = true;
      merged[key] = both.join(",");
    } else {
      merged[key] = value;
    }
  }

  const includesAll = all || isLookup(merged);
  const params: Record<string, string | number | undefined> = {
    ...merged,
    site: merged.site ?? scope.site,
    since_millis: scope.since,
    until_millis: scope.until,
    scope: includesAll ? "all" : undefined,
  };
  return { query: qs(params), errors: parsed.errors, impossible, includesAll };
}

/** The counts behind the chips: the filter text and window without the chip, counting every row. */
export function planCounts(q: string, scope: Scope): string {
  const parsed = parseFilter(q);
  return qs({
    ...parsed.params,
    site: parsed.params.site ?? scope.site,
    since_millis: scope.since,
    until_millis: scope.until,
    scope: "all",
  });
}

/** The number a chip shows, from the counts of the same filters; null while they are loading. */
export function chipCount(id: ChipId, counts: RequestCounts | undefined): number | null {
  if (!counts) return null;
  const outcome = counts.by_outcome;
  const path = counts.by_decision_path;
  switch (id) {
    case "judged":
      return counts.total - (path.bypass ?? 0) - (path.unknown_site ?? 0);
    case "attention":
      return (outcome.blocked ?? 0) + (outcome.would_block ?? 0) + (outcome.unjudged ?? 0);
    case "blocked":
      return outcome.blocked ?? 0;
    case "would_block":
      return outcome.would_block ?? 0;
    case "unjudged":
      return outcome.unjudged ?? 0;
    case "jev":
      return counts.jev_calls;
    case "no_session":
      return path.no_session ?? 0;
    case "bypass":
      return path.bypass ?? 0;
  }
}

/** Unknown-site rows among the counted rows; the default list hides them (docs/06 6.4.3). */
export function unknownSiteCount(counts: RequestCounts | undefined): number {
  return counts?.by_decision_path.unknown_site ?? 0;
}
