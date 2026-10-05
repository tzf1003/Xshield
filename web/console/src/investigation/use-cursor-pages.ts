import { useQueries, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import type { ControlClient } from "../api.ts";
import { guardedQuery, guardedQueryKey } from "../security/guarded-query.ts";
import { MANUAL_REFRESH } from "../security/query-client.ts";
import type { ScopedResponse } from "../security/scope.ts";
import { useSession } from "../security/SessionProvider";

export type CursorPage = ScopedResponse & { next_cursor: string | null };

export type CursorPages<T> = Readonly<{
  /** Loaded pages in order. A page appears only after its response passed the scope check. */
  pages: readonly T[];
  /** The first page is in flight and nothing is loaded yet. */
  loading: boolean;
  loadingMore: boolean;
  firstError: unknown;
  /** Error of the page after the last loaded one, when its read failed. */
  moreError: unknown;
  hasMore: boolean;
  /** `maxPages` reached while the server still has more. */
  capped: boolean;
  loadMore: () => void;
  retryMore: () => void;
  /** Drops every loaded page and reads the first one again (one audited read). */
  refresh: () => void;
}>;

type Options<T> = {
  /** Domain key of the plan; the epoch and cursor are added for you. */
  key: readonly unknown[];
  fetchPage: (client: ControlClient, cursor: string | undefined, signal: AbortSignal) => Promise<T>;
  enabled?: boolean;
  maxPages?: number;
  /**
   * Drop the loaded pages when the caller unmounts, so the next mount reads the server again
   * instead of reusing the short-lived cache. For dialogs that must show the current state, such as
   * the cases an operator may just have created on another page.
   */
  discardOnUnmount?: boolean;
};

/**
 * Cursor pagination on top of guarded reads. Each page is its own epoch-keyed, scope-verified
 * query, so a reply that arrives after the plan changed, the page unmounted or the session ended
 * can never populate anything. The state belongs to one plan: give the calling component a React
 * `key` that changes with the plan so a new plan starts from an empty first page. Pages are read
 * only on mount, on `loadMore` and on `refresh`; nothing polls or refetches on focus.
 */
export function useCursorPages<T extends CursorPage>({
  key,
  fetchPage,
  enabled = true,
  maxPages = 20,
  discardOnUnmount = false,
}: Options<T>): CursorPages<T> {
  const { runtime } = useSession();
  const queryClient = useQueryClient();
  const [cursors, setCursors] = useState<readonly (string | undefined)[]>([undefined]);
  const [generation, setGeneration] = useState(0);
  const keyText = JSON.stringify(key);

  useEffect(() => {
    if (!discardOnUnmount) return undefined;
    return () => {
      const { epoch } = runtime.store.getState();
      queryClient.removeQueries({
        queryKey: guardedQueryKey(epoch, JSON.parse(keyText) as readonly unknown[]),
      });
    };
  }, [discardOnUnmount, keyText, queryClient, runtime]);

  const results = useQueries({
    queries: cursors.map((cursor) =>
      guardedQuery(runtime, {
        key: [...key, generation, cursor ?? "first"],
        fetch: (client, signal) => fetchPage(client, cursor, signal),
        staleTime: MANUAL_REFRESH,
        enabled,
      }),
    ),
  });

  const pages: T[] = [];
  for (const result of results) {
    if (result.data === undefined) break;
    pages.push(result.data);
  }
  const last = pages.at(-1);
  const next = results[pages.length];
  const hasMore = last?.next_cursor != null && cursors.length === pages.length;
  const capped = hasMore && pages.length >= maxPages;

  return {
    pages,
    loading: pages.length === 0 && (results[0]?.isFetching ?? false),
    loadingMore: pages.length > 0 && (next?.isFetching ?? false),
    firstError: pages.length === 0 ? results[0]?.error : null,
    moreError: pages.length > 0 ? next?.error : null,
    hasMore: hasMore && !capped,
    capped,
    loadMore: () => {
      const cursor = last?.next_cursor;
      if (cursor == null || !hasMore || capped) return;
      setCursors((current) => (current.length === pages.length ? [...current, cursor] : current));
    },
    retryMore: () => void next?.refetch(),
    refresh: () => {
      const { epoch } = runtime.store.getState();
      queryClient.removeQueries({ queryKey: guardedQueryKey(epoch, [...key, generation]) });
      setCursors([undefined]);
      setGeneration((value) => value + 1);
    },
  };
}
