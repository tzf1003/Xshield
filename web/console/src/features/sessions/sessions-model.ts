// Rules of the session pages (docs/06 6.4.7, docs/07 7.9.6) without React: the timeline's gap rows, the
// running total of learned values behind its sparkline, the choices of the "只看" selector, and the
// label prefix match of the list.

import type { EdgeStatus, TimelineRow } from "../../api/types.ts";
import { isSessionPrefix } from "../../lib/ids.ts";

/** The session list returns at most this many sessions, the most recently active first (7.9.6). */
export const SESSION_LIMIT = 200;

/** A pause longer than this between two requests is shown as a gap row (docs/06 6.4.7). */
export const GAP_MS = 5 * 60 * 1000;

/** The sessions the timeline can be narrowed to. Without a choice the timeline shows judged requests. */
export const TIMELINE_ONLY: ReadonlyArray<{ value: "judged" | "jev" | "blocks"; label: string }> = [
  { value: "judged", label: "只看已判定" },
  { value: "jev", label: "只看 Jev 调用" },
  { value: "blocks", label: "只看拦截与本应拦截" },
];

/** Whether a session label starts with the typed prefix; an empty prefix matches everything. */
export function matchesPrefix(label: string, prefix: string): boolean {
  return prefix.length === 0 || label.startsWith(prefix);
}

/** The prefix as typed, lower-cased and trimmed, and whether it can be a prefix of a label at all. */
export function normalisePrefix(text: string): { prefix: string; valid: boolean } {
  const prefix = text.trim().toLowerCase();
  return { prefix, valid: prefix.length === 0 || isSessionPrefix(prefix) };
}

export type TimelineItem =
  | { kind: "row"; key: string; row: TimelineRow }
  | { kind: "gap"; key: string; ms: number; from: number; to: number };

/** The timeline in order, with a gap row wherever two requests are more than five minutes apart. */
export function withGaps(rows: TimelineRow[]): TimelineItem[] {
  const items: TimelineItem[] = [];
  let previous: TimelineRow | null = null;
  for (const row of rows) {
    if (previous !== null) {
      const ms = row.at_millis - previous.at_millis;
      if (ms > GAP_MS) {
        items.push({
          kind: "gap",
          key: `gap-${row.request_id}`,
          ms,
          from: previous.at_millis,
          to: row.at_millis,
        });
      }
    }
    items.push({ kind: "row", key: row.request_id, row });
    previous = row;
  }
  return items;
}

/** A loss window of one gateway that cost decision records (docs/07 7.7.4), with its gateway's name. */
export type LostWindow = {
  edge: string;
  from_ms: number;
  to_ms: number;
  dropped: number;
  write_errors: number;
};

/**
 * The loss windows that cost decision records, of every gateway. A window that only dropped bypass
 * records cost no decision, so it is left out.
 */
export function lostWindows(edges: ReadonlyArray<Pick<EdgeStatus, "edge" | "gaps">>): LostWindow[] {
  return edges.flatMap((edge) =>
    edge.gaps
      .filter((gap) => gap.dropped + gap.write_errors > 0)
      .map((gap) => ({
        edge: edge.edge,
        from_ms: gap.from_ms,
        to_ms: gap.to_ms,
        dropped: gap.dropped,
        write_errors: gap.write_errors,
      })),
  );
}

/**
 * The first loss window that overlaps the quiet time between two requests, or null. The overlap is open
 * at both ends, as the prototype has it: a window that only touches an end of the quiet time does not count.
 */
export function lostWindowBetween(
  windows: readonly LostWindow[],
  from: number,
  to: number,
): LostWindow | null {
  return windows.find((window) => window.to_ms > from && window.from_ms < to) ?? null;
}

/** Values the session has learned up to and including each row (`learned` is null when unknown). */
export function runningTotal(rows: TimelineRow[]): number[] {
  let total = 0;
  return rows.map((row) => {
    total += row.learned ?? 0;
    return total;
  });
}

/** Evenly spaced indices into a list of `length`, at most `max` of them, always with the last one. */
export function sampleIndices(length: number, max: number): number[] {
  if (length <= max) return Array.from({ length }, (_, index) => index);
  const step = (length - 1) / (max - 1);
  return Array.from({ length: max }, (_, index) => Math.round(index * step));
}
