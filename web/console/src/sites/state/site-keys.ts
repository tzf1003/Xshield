/**
 * Domain keys; the session epoch is prefixed by the guarded query helpers. Kept free of any
 * hook import so non-React code (the apply-events invalidation logic, its tests) can use these
 * keys without pulling in `SessionProvider.tsx`.
 */
export const siteKeys = {
  list: ["sites", "list"] as const,
  site: (siteId: string) => ["sites", siteId] as const,
  config: (siteId: string) => ["sites", siteId, "config"] as const,
  status: (siteId: string) => ["sites", siteId, "status"] as const,
  revisions: (siteId: string) => ["sites", siteId, "revisions"] as const,
  health: (siteId: string) => ["sites", siteId, "health"] as const,
  rolloutReport: (siteId: string, revision: string, start: string, end: string) =>
    ["sites", siteId, "rollout-report", revision, start, end] as const,
};
