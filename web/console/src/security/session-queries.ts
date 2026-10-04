import { type BrowserSession, bootstrapBrowserSession } from "../api.ts";
import { guardedQuery } from "./guarded-query.ts";
import type { SessionRuntime } from "./runtime.ts";
import { isStaleSessionError } from "./errors.ts";

/**
 * Re-reads `GET /control/v1/session` through the guard and refreshes the roles and step-up facts
 * held by the store. The first read of a page load happens in `SessionProvider`, before any epoch
 * exists; this is the explicit "refresh session info" path. A superseded or cancelled read
 * resolves to `null`.
 */
export async function refreshSessionInfo(runtime: SessionRuntime): Promise<BrowserSession | null> {
  try {
    const session = await runtime.queryClient.fetchQuery(
      guardedQuery(runtime, {
        key: ["session", "info"],
        staleTime: 0,
        fetch: (_client, signal) => bootstrapBrowserSession(signal),
      }),
    );
    runtime.store.updateSession(session);
    return session;
  } catch (error) {
    if (isStaleSessionError(error) || (error instanceof Error && error.name === "CancelledError")) {
      return null;
    }
    throw error;
  }
}
