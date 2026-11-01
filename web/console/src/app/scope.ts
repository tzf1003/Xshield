// The global scope every page shares (docs/06 6.2.2): the site, the time range, and the custom
// bounds. Pages read it from the URL, so a copied link opens the same window.

import { useNavigate, useSearch } from "@tanstack/react-router";
import { useCallback, useEffect, useMemo, useState } from "react";
import { qs } from "../api/client.ts";
import { DEFAULT_RANGE, type RangeParam, windowFor, presetWindow } from "../lib/time-range.ts";
import { type GlobalSearch, validateGlobal } from "./search-schema.ts";

export type Scope = {
  site: string | undefined;
  range: RangeParam;
  since: number;
  until: number;
};

/** The current time, bucketed so query keys stay still between refreshes (every 30 s). */
export function useNowBucket(stepMs = 30_000): number {
  const [now, setNow] = useState(() => Math.floor(Date.now() / stepMs) * stepMs);
  useEffect(() => {
    const timer = window.setInterval(() => {
      const next = Math.floor(Date.now() / stepMs) * stepMs;
      setNow((previous) => (previous === next ? previous : next));
    }, stepMs);
    return () => window.clearInterval(timer);
  }, [stepMs]);
  return now;
}

/** The global search of the current location, validated. */
export function useGlobalSearch(): GlobalSearch {
  return useSearch({
    strict: false,
    select: (search) => validateGlobal(search as Record<string, unknown>),
  });
}

export function useScope(): Scope {
  const global = useGlobalSearch();
  const now = useNowBucket();
  const { site, range, since, until } = global;
  return useMemo(() => {
    const chosen = range ?? DEFAULT_RANGE;
    const window =
      windowFor(chosen, since ?? null, until ?? null, now) ?? presetWindow(DEFAULT_RANGE, now);
    return { site, range: chosen, since: window.since, until: window.until };
  }, [site, range, since, until, now]);
}

/** Query parameters every list and statistics call takes from the scope. */
export function scopeParams(scope: Scope): Record<string, string | number | undefined> {
  return { site: scope.site, since_millis: scope.since, until_millis: scope.until };
}

export function scopeQuery(
  scope: Scope,
  extra: Record<string, string | number | boolean | undefined> = {},
): string {
  return qs({ ...scopeParams(scope), ...extra });
}

/** Returns the current location's search with `patch` applied; `undefined` removes a key. */
export function patchSearch(
  previous: Record<string, unknown>,
  patch: Record<string, string | number | boolean | undefined>,
): Record<string, unknown> {
  const next: Record<string, unknown> = { ...previous };
  for (const [key, value] of Object.entries(patch)) {
    if (value === undefined || value === "" || value === false) delete next[key];
    else next[key] = value;
  }
  return next;
}

/** Keeps only the global part of a search, for links that should carry the scope along. */
export function keepScope(previous: Record<string, unknown>): GlobalSearch {
  return validateGlobal(previous);
}

/**
 * A setter for the search of the current page: `setSearch({ q: "outcome:blocked" })`. It builds the
 * next address from the current one, so it works on every route without a typed target. `undefined`,
 * `""` and `false` remove a key.
 */
export function useSetSearch() {
  const navigate = useNavigate();
  return useCallback(
    (patch: Record<string, string | number | boolean | undefined>, replace = false) => {
      const next = new URLSearchParams(window.location.search);
      for (const [key, value] of Object.entries(patch)) {
        if (value === undefined || value === "" || value === false) next.delete(key);
        else next.set(key, String(value));
      }
      const text = next.toString();
      void navigate({
        href: `${window.location.pathname}${text.length > 0 ? `?${text}` : ""}`,
        replace,
      });
    },
    [navigate],
  );
}
