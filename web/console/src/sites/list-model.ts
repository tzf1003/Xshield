import type { SiteListItem } from "../api.ts";
import { type SiteDisplayState, siteDisplayState } from "../ui/state-model.ts";

export type StatusFilter = "all" | SiteDisplayState;

export const statusFilterOrder: readonly SiteDisplayState[] = [
  "active",
  "awaiting_approval",
  "pending",
  "failed",
  "draft",
  "paused",
];

export function listItemState(site: SiteListItem): SiteDisplayState | null {
  return siteDisplayState({
    apply_state: site.apply_state,
    requires_approval: site.requires_approval,
    status: site.status,
  });
}

/** Pages are signed-cursor slices; a site can only appear twice if the data moved between reads. */
export function dedupeSites(sites: readonly SiteListItem[]): SiteListItem[] {
  const seen = new Set<string>();
  const result: SiteListItem[] = [];
  for (const site of sites) {
    if (seen.has(site.site_id)) continue;
    seen.add(site.site_id);
    result.push(site);
  }
  return result;
}

/** Every whitespace-separated term must occur in the name, ID, origin, author or policy label. */
export function matchesSearch(site: SiteListItem, query: string): boolean {
  const terms = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (terms.length === 0) return true;
  const haystack = [
    site.display_name,
    site.site_id,
    site.public_origin,
    site.updated_by,
    site.policy_revision,
  ]
    .join("\n")
    .toLowerCase();
  return terms.every((term) => haystack.includes(term));
}

export function filterSites(
  sites: readonly SiteListItem[],
  query: string,
  filter: StatusFilter,
): SiteListItem[] {
  return sites.filter(
    (site) => matchesSearch(site, query) && (filter === "all" || listItemState(site) === filter),
  );
}

export type ListSummary = Readonly<{
  total: number;
  counts: Readonly<Record<SiteDisplayState, number>>;
}>;

/** Counts over the rows that are loaded. They say nothing about pages that were not read. */
export function summarize(sites: readonly SiteListItem[]): ListSummary {
  const counts: Record<SiteDisplayState, number> = {
    draft: 0,
    pending: 0,
    awaiting_approval: 0,
    active: 0,
    failed: 0,
    paused: 0,
  };
  for (const site of sites) {
    const state = listItemState(site);
    if (state) counts[state] += 1;
  }
  return { total: sites.length, counts };
}

export const configStatusLabel: Record<SiteListItem["status"], string> = {
  draft: "草稿",
  active: "启用",
  paused: "暂停",
};

/** `desired r3 · active r2`; a site the edge has never served shows `active —`. */
export function revisionsText(site: Pick<SiteListItem, "desired_revision" | "active_revision">) {
  return `desired r${site.desired_revision} · active ${
    site.active_revision === null ? "—" : `r${site.active_revision}`
  }`;
}
