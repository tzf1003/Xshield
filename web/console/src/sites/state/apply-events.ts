import { guardedQueryKey } from "../../security/guarded-query.ts";
import type { SessionRuntime } from "../../security/runtime.ts";
import { siteKeys } from "./site-keys.ts";

export const APPLY_EVENTS_PATH = "/control/v1/sites/apply-events";

type SiteApplyChangedPayload = {
  site_id?: unknown;
};

function parsedSiteId(raw: string): string | null {
  try {
    const payload = JSON.parse(raw) as SiteApplyChangedPayload;
    return typeof payload.site_id === "string" && payload.site_id.length > 0
      ? payload.site_id
      : null;
  } catch {
    return null;
  }
}

/**
 * The `site_apply_changed` handler's logic, kept free of React and `EventSource` so a test can
 * drive it with a real `QueryClient` alone. Never reads anything itself: a malformed or
 * unparseable frame is dropped, never retried or surfaced, since the next real read still catches
 * up on its own.
 */
export function invalidateApplyEvent(runtime: SessionRuntime, epoch: number, raw: string): void {
  const siteId = parsedSiteId(raw);
  if (siteId === null) return;
  for (const key of [
    siteKeys.config(siteId),
    siteKeys.status(siteId),
    siteKeys.revisions(siteId),
  ]) {
    void runtime.queryClient.invalidateQueries({ queryKey: guardedQueryKey(epoch, key) });
  }
  void runtime.queryClient.invalidateQueries({
    queryKey: guardedQueryKey(epoch, siteKeys.list),
    refetchType: "none",
  });
}
