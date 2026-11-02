// The reads the "需要处理" rows need beyond the status and the site list (docs/06 6.4.2). The site
// detail is read only for a site with unjudged requests, because on_jev_unavailable is not in the
// list; the insights only for a site whose row shows a breakdown (observation misses, suggestions); the
// evidence only for a site whose evidence row shows.
// Both use the query keys of the site pages, so a page that has read them already shares the answer.

import { useQueries } from "@tanstack/react-query";
import { api } from "../../api/client.ts";
import { keys } from "../../api/queries.ts";
import type { Evidence, Insights, OnJevUnavailable, SiteSummary } from "../../api/types.ts";
import { isSiteName } from "../../lib/ids.ts";
import { evidenceRowShows } from "./attention.ts";

export type AttentionReads = {
  /** on_jev_unavailable of each site with unjudged requests whose detail has loaded. */
  onJevUnavailable: ReadonlyMap<string, OnJevUnavailable>;
  /** Insights of each site that needs a breakdown and has loaded them. */
  insights: ReadonlyMap<string, Insights>;
  /** Evidence of each site whose evidence row shows and has loaded it. The row shows without it. */
  evidence: ReadonlyMap<string, Evidence>;
  /** A detail that a row depends on is still loading, so that row cannot be judged yet. */
  pending: boolean;
  /** A detail that a row depends on failed to load; the card says which rows are missing. */
  failed: boolean;
  retry: () => void;
};

/** A site whose row shows a breakdown: observation misses to split, or suggestions to name. */
export function needsInsights(site: SiteSummary): boolean {
  return (site.mode === "observe" && site.would_block_24h > 0) || site.suggestions > 0;
}

export function useAttentionReads(sites: SiteSummary[]): AttentionReads {
  const detailSites = sites.filter((site) => site.unjudged_24h > 0 && isSiteName(site.name));
  const insightSites = sites.filter((site) => needsInsights(site) && isSiteName(site.name));

  const details = useQueries({
    queries: detailSites.map((site) => ({
      queryKey: keys.site(site.name),
      queryFn: () => api.site(site.name),
      staleTime: 5_000,
    })),
  });
  const insightReads = useQueries({
    queries: insightSites.map((site) => ({
      queryKey: keys.insights(site.name),
      queryFn: () => api.insights(site.name),
      staleTime: 30_000,
    })),
  });
  const evidenceSites = sites.filter((site) => evidenceRowShows(site) && isSiteName(site.name));
  const evidenceReads = useQueries({
    queries: evidenceSites.map((site) => ({
      queryKey: keys.evidence(site.name),
      queryFn: () => api.evidence(site.name),
      staleTime: 60_000,
    })),
  });

  const onJevUnavailable = new Map<string, OnJevUnavailable>();
  detailSites.forEach((site, index) => {
    const read = details[index];
    // An absent setting is the default, deny (docs/03).
    if (read?.data) onJevUnavailable.set(site.name, read.data.spec.on_jev_unavailable ?? "deny");
  });
  const insights = new Map<string, Insights>();
  insightSites.forEach((site, index) => {
    const read = insightReads[index];
    if (read?.data) insights.set(site.name, read.data);
  });
  const evidence = new Map<string, Evidence>();
  evidenceSites.forEach((site, index) => {
    const read = evidenceReads[index];
    if (read?.data) evidence.set(site.name, read.data);
  });

  const retry = () => {
    for (const read of details) {
      if (read.isError) void read.refetch();
    }
  };

  return {
    onJevUnavailable,
    insights,
    evidence,
    pending: details.some((read) => read.isPending),
    failed: details.some((read) => read.isError),
    retry,
  };
}
