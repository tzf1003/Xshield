// The queries behind the interface-name rules: what a rule names over the last day, and the examples and
// completions read from the newest rows. The same query text is used everywhere, so the cache is shared.

import { qs } from "../../api/client.ts";
import { fmtInt } from "../../lib/format.ts";
import { ROUTE_RECORD_WINDOW } from "../../lib/vocab.ts";

export const DAY_MS = 24 * 60 * 60 * 1000;

/** Rows read for examples and completions. A list that stops at this many is labelled as recent records. */
export const RECENT_ROWS = 500;

/** The judged rows of the last day (bypass included) whose logical path starts with the rule's literal part. */
export function namedCountQuery(site: string, base: string, now: number): string {
  return qs({
    site,
    path: `${base}*`,
    scope: "all",
    since_millis: now - DAY_MS,
    until_millis: now,
  });
}

/** The newest rows of the last day under the rule's literal part: examples and completions come from these. */
export function namedRowsQuery(site: string, base: string, now: number): string {
  return qs({
    site,
    path: `${base}*`,
    scope: "all",
    since_millis: now - DAY_MS,
    until_millis: now,
    limit: RECENT_ROWS,
  });
}

/** The newest rows of the last day whose interface name could not be read. Any rule's unknown rows. */
export function unknownRowsQuery(site: string, now: number): string {
  return qs({
    site,
    api_unknown: "any",
    scope: "all",
    since_millis: now - DAY_MS,
    until_millis: now,
    limit: RECENT_ROWS,
  });
}

/** "24 小时 N 次", or "最近 500 条记录里 N 次" when the rows were cut at the limit. */
export function windowText(count: number, partial: boolean): string {
  return partial ? `${ROUTE_RECORD_WINDOW}里 ${fmtInt(count)} 次` : `24 小时 ${fmtInt(count)} 次`;
}
