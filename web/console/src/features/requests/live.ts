// Live mode (docs/06 6.4.3, docs/07 7.9.3). Every two seconds the list is fetched again for the rows
// written in the minute before the newest row on screen (`since_millis`, at most 200 rows). The page
// matches rows by request ID, so a row that arrives twice is shown once. The poll stops by itself after
// ten minutes without any interaction, and resumes with one click. A hidden tab is not polled.

import { useEffect, useRef, useState } from "react";
import { api } from "../../api/client.ts";
import type { RequestRow } from "../../api/types.ts";

export const LIVE_POLL_MS = 2_000;
export const LIVE_IDLE_MS = 10 * 60 * 1000;
/** Records are written after their response ends, so each poll looks back this far (docs/07 7.9.3). */
export const LIVE_LOOKBACK_MS = 60_000;
export const LIVE_LIMIT = 200;

/** Where a poll starts: a minute before the newest row on screen, and never before the window. */
export function liveSince(query: string, newestMillis: number | null, now: number): number {
  const windowStart = Number(
    new URLSearchParams(query.replace(/^\?/, "")).get("since_millis") ?? "0",
  );
  return Math.max(windowStart, (newestMillis ?? now) - LIVE_LOOKBACK_MS);
}

/** The list query of one poll: the page's filters, the start from `liveSince`, and the limit. */
export function liveQuery(query: string, since: number): string {
  const params = new URLSearchParams(query.replace(/^\?/, ""));
  params.set("since_millis", String(since));
  params.set("limit", String(LIVE_LIMIT));
  params.delete("cursor");
  return `?${params.toString()}`;
}

/** Whether a poll hit its limit before reaching `since`, so rows inside its window may be missing. */
export function liveOverflow(rows: readonly { at_millis: number }[], since: number): boolean {
  const oldest = rows.reduce((min, row) => Math.min(min, row.at_millis), Number.POSITIVE_INFINITY);
  return rows.length >= LIVE_LIMIT && oldest > since;
}

export type LivePoll = { paused: boolean; resume: () => void };

/**
 * Polls while `enabled`. `query` is the list query of the page without paging; `newestMillis` is the
 * time of the newest row on screen. `onRows` gets each poll's rows, and `overflow` is true when the
 * poll hit the limit inside its window, so some rows may be missing.
 */
export function useLivePoll(input: {
  enabled: boolean;
  query: string;
  newestMillis: number | null;
  onRows: (rows: RequestRow[], overflow: boolean) => void;
}): LivePoll {
  const { enabled, query, newestMillis, onRows } = input;
  const [paused, setPaused] = useState(false);
  const lastTouch = useRef(Date.now());
  const newest = useRef(newestMillis);
  const handler = useRef(onRows);

  useEffect(() => {
    newest.current = newestMillis;
  }, [newestMillis]);
  useEffect(() => {
    handler.current = onRows;
  });

  useEffect(() => {
    if (!enabled || paused) return undefined;
    let current = true;
    let busy = false;
    const timer = window.setInterval(() => {
      if (Date.now() - lastTouch.current > LIVE_IDLE_MS) {
        setPaused(true);
        return;
      }
      if (document.hidden) return;
      if (busy) return;
      const since = liveSince(query, newest.current, Date.now());
      busy = true;
      api
        .requests(liveQuery(query, since))
        .then((page) => {
          // A poll that answers after the filter changed belongs to the old list and is dropped.
          if (!current) return;
          handler.current(page.rows, liveOverflow(page.rows, since));
        })
        // A failed poll is simply tried again on the next tick.
        .catch(() => undefined)
        .finally(() => {
          busy = false;
        });
    }, LIVE_POLL_MS);
    return () => {
      current = false;
      window.clearInterval(timer);
    };
  }, [enabled, paused, query]);

  useEffect(() => {
    if (!enabled) return undefined;
    const touch = () => {
      lastTouch.current = Date.now();
    };
    window.addEventListener("keydown", touch);
    window.addEventListener("pointerdown", touch);
    window.addEventListener("wheel", touch);
    return () => {
      window.removeEventListener("keydown", touch);
      window.removeEventListener("pointerdown", touch);
      window.removeEventListener("wheel", touch);
    };
  }, [enabled]);

  return {
    paused,
    resume: () => {
      lastTouch.current = Date.now();
      setPaused(false);
    },
  };
}
