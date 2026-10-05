import { useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { runFrozenWrite, type WriteResult } from "../security/guarded.ts";
import { guardedQueryKey } from "../security/guarded-query.ts";
import { useSession } from "../security/SessionProvider";

/**
 * The exact retry of a frozen write from a page that does not own it (the workbench). It is the
 * same call `useGuardedMutation().retry` makes: the registry hands back the original method,
 * path, idempotency key and body, and nothing about the request can be changed here.
 *
 * A confirmed retry marks every read of this session stale without re-reading anything now (a
 * read is audited, so it happens when the owning page is opened), so no page keeps showing the
 * state from before the write.
 */
export function useFrozenRetry() {
  const { runtime } = useSession();
  const queryClient = useQueryClient();
  const [busy, setBusy] = useState<string | null>(null);
  // A ref closes the gap between a click and the next paint: a double click sends one request.
  const latch = useRef(false);

  async function retry(operationId: string): Promise<WriteResult<unknown> | null> {
    if (latch.current) return null;
    latch.current = true;
    setBusy(operationId);
    try {
      let result: WriteResult<unknown>;
      try {
        result = await runFrozenWrite(runtime.store, runtime.pending, operationId);
      } catch {
        // The operation left the registry or is already in flight (its own page retried it).
        return null;
      }
      if (result.kind === "confirmed") {
        const epoch = runtime.store.getState().epoch;
        void queryClient.invalidateQueries({
          queryKey: guardedQueryKey(epoch, []),
          refetchType: "none",
        });
      }
      return result;
    } finally {
      latch.current = false;
      setBusy(null);
    }
  }

  return { retry, busy };
}
