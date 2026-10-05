/**
 * "最近被拒绝的请求": one bounded structured search, run only when the operator asks for it. A
 * search is an audited Investigator query that spends index budget, so the workbench never runs
 * it on its own. Pure helpers; unit-tested.
 */
import type { SearchPlan, SearchResponse } from "../search.ts";

export const DENIED_WINDOW_MS = 24 * 60 * 60 * 1000;
export const DENIED_LIMIT = 10;

/** `2026-10-05T08:00:00Z`: the plan takes whole UTC seconds only. */
function wholeSecond(ms: number): string {
  return new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(".000Z", "Z");
}

/** Terminal request events with a DENY outcome in the last 24 hours, newest first, 10 rows. */
export function deniedRequestsPlan(nowMs: number): SearchPlan {
  const end = Math.floor(nowMs / 1000) * 1000;
  return {
    schema_version: 3,
    start: wholeSecond(end - DENIED_WINDOW_MS),
    end: wholeSecond(end),
    filters: [
      { kind: "text", field: "event_type", value: "request.completed" },
      { kind: "outcome", value: "DENY" },
    ],
    sort: "occurred_at_desc",
    limit: DENIED_LIMIT,
  };
}

export type ScanStats = Readonly<{ rows: string; bytes: string }>;

/** An unknown statistic is not zero: the server may not report one. */
export function scanStats(response: Pick<SearchResponse, "scanned_rows" | "scanned_bytes">) {
  const count = (value: number | null, unit: string) =>
    value === null ? "未知" : `${value.toLocaleString("zh-CN")} ${unit}`;
  return {
    rows: count(response.scanned_rows, "行"),
    bytes: count(response.scanned_bytes, "字节"),
  } satisfies ScanStats;
}
