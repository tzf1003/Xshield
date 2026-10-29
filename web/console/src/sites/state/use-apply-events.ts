import { useEffect } from "react";
import { useSession } from "../../security/SessionProvider.tsx";
import { APPLY_EVENTS_PATH, invalidateApplyEvent } from "./apply-events.ts";

/**
 * Subscribes to the server's apply-state push while the session is connected, so the sites list
 * and an open site's status/config/revisions catch a change (including one `reconcile_local_edge`
 * made on its own, with no console write involved) without the operator having to press refresh.
 *
 * The pushed event is only ever a hint to re-read, never the state itself: receiving one does
 * nothing but invalidate the same guarded queries `useSiteCache().refreshDetail` already
 * invalidates after a write this console made, so the actual read stays the normal audited,
 * scope-checked one through `ControlClient` — this never becomes a second, unaudited read path.
 * Mount this only from the pages that show a changeable apply/release state (the sites list and
 * a site's own workspace), not the app shell: an operator looking at, say, the investigation
 * pages has no use for it, and every connected tab otherwise holding one open server-side stream
 * it will never need is exactly the kind of always-on channel this project avoids by default.
 */
export function useApplyEventsSubscription(enabled: boolean = true): void {
  const { runtime, state } = useSession();
  const connected = enabled && state.status === "connected";
  const epoch = state.epoch;

  useEffect(() => {
    if (!connected) return undefined;
    const source = new EventSource(APPLY_EVENTS_PATH);
    source.addEventListener("site_apply_changed", (message: MessageEvent<string>) => {
      // A late event from a session this tab has since moved past (a reconnect bumped the
      // epoch) would invalidate keys nothing reads anymore; the check is defensive, not load-
      // bearing, since the server only ever signals, it never answers from this listener.
      if (!runtime.store.isCurrent(epoch)) return;
      invalidateApplyEvent(runtime, epoch, message.data);
    });
    // No reconnect loop of our own: the browser's native EventSource retry on a transient
    // drop is enough, and a terminal auth failure is caught by the session's own 401 handling
    // on the next ordinary read, not by anything watched here.
    return () => source.close();
  }, [connected, epoch, runtime]);
}
