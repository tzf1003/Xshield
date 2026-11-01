// The hourly chart of the overview (docs/06 6.4.2): the buckets of GET /api/stats/timeseries, stacked
// in three coloured groups with the neutral 其他 group on top (bypass is left out). Each column keeps the
// count of every decision path inside it, for the hover card and the table, so nothing shown depends on
// colour alone. Pure functions.

import type { DecisionPath, TimeseriesBucket } from "../../api/types.ts";
import { DECISION_INFO } from "../../lib/vocab.ts";

export type TrendGroup = {
  key: "free" | "jev" | "none" | "other";
  name: string;
  cls: "s1" | "s2" | "s3" | "neutral";
  paths: DecisionPath[];
};

/**
 * Bottom to top. 其他 holds body_not_inspectable and unknown_site: neither a Jev judgement nor a
 * sessionless decision. TrendChart draws that group only where some column has a count in it.
 */
export const TREND_GROUPS: TrendGroup[] = [
  { key: "free", name: "免调用放行", cls: "s1", paths: ["fast_allow", "cached_allow"] },
  { key: "jev", name: "Jev 判定", cls: "s2", paths: ["jev_allow", "jev_deny", "jev_unavailable"] },
  { key: "none", name: "无会话", cls: "s3", paths: ["no_session"] },
  { key: "other", name: "其他", cls: "neutral", paths: ["body_not_inspectable", "unknown_site"] },
];

export type GroupCount = {
  group: TrendGroup;
  total: number;
  detail: Array<{ name: string; count: number }>;
};

export type TrendColumn = { at: number; total: number; groups: GroupCount[] };

export function trendColumns(buckets: TimeseriesBucket[]): TrendColumn[] {
  return [...buckets]
    .sort((a, b) => a.at_millis - b.at_millis)
    .map((bucket) => {
      const groups: GroupCount[] = TREND_GROUPS.map((group) => {
        const detail = group.paths
          .map((path) => ({ name: DECISION_INFO[path].name, count: bucket.counts[path] ?? 0 }))
          .filter((item) => item.count > 0);
        const total = group.paths.reduce((sum, path) => sum + (bucket.counts[path] ?? 0), 0);
        return { group, total, detail };
      });
      return {
        at: bucket.at_millis,
        total: groups.reduce((sum, entry) => sum + entry.total, 0),
        groups,
      };
    });
}
