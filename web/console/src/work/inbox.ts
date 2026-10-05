/**
 * The approval center merges three independently loaded sources into one list: evidence access
 * requests, metadata exports and site revisions that await a policy decision. Each source keeps
 * its own page, error and observation time; this module only normalises, sorts and counts.
 */
import type { SiteListItem } from "../api.ts";
import type { AccessList } from "../evidence-access.ts";
import type { ExportListItem } from "../exports.ts";

export type InboxKind = "access" | "export" | "site";

export type InboxItem = Readonly<{
  /** Unique across kinds: `access:access_…`. */
  key: string;
  kind: InboxKind;
  id: string;
  requester: string;
  at: string;
  atMs: number;
  /** The case for access and export rows, the site's display name for policy rows. */
  target: string;
  /** The artifact for access rows, the desired revision for policy rows, empty for exports. */
  detail: string;
  status: string;
}>;

type AccessRow = AccessList["items"][number];

export function accessInboxItem(row: AccessRow): InboxItem {
  return {
    key: `access:${row.access_request_id}`,
    kind: "access",
    id: row.access_request_id,
    requester: row.requested_by,
    at: row.requested_at,
    atMs: Date.parse(row.requested_at),
    target: row.case_id,
    detail: row.artifact_id,
    status: row.stored_status,
  };
}

export function exportInboxItem(row: ExportListItem): InboxItem {
  return {
    key: `export:${row.export_id}`,
    kind: "export",
    id: row.export_id,
    requester: row.requested_by,
    at: row.requested_at,
    atMs: Date.parse(row.requested_at),
    target: row.case_id,
    detail: "",
    status: row.status,
  };
}

/**
 * A site revision waits for a policy decision when the server says it requires approval. The
 * overview projection spells the same state `awaiting_approval`; both are accepted here.
 */
export function siteNeedsApproval(
  site: Pick<SiteListItem, "requires_approval" | "apply_state">,
): boolean {
  return site.requires_approval === true || (site.apply_state as string) === "awaiting_approval";
}

export function siteInboxItem(site: SiteListItem): InboxItem {
  return {
    key: `site:${site.site_id}`,
    kind: "site",
    id: site.site_id,
    requester: site.updated_by,
    at: site.updated_at,
    atMs: Date.parse(site.updated_at),
    target: site.display_name,
    detail: `修订 ${site.desired_revision}`,
    status: site.apply_state,
  };
}

/** Rows of the site list that await a decision; the decision itself happens on the site page. */
export function siteApprovals(sites: readonly SiteListItem[]): InboxItem[] {
  return sites.filter(siteNeedsApproval).map(siteInboxItem);
}

/** Newest first; rows without a usable time sink to the end; ties break on the key. */
export function mergeInbox<T extends InboxItem>(...groups: readonly (readonly T[])[]): T[] {
  return groups.flat().sort((left, right) => {
    const a = Number.isFinite(left.atMs) ? left.atMs : Number.NEGATIVE_INFINITY;
    const b = Number.isFinite(right.atMs) ? right.atMs : Number.NEGATIVE_INFINITY;
    if (a !== b) return b > a ? 1 : -1;
    return left.key < right.key ? -1 : left.key > right.key ? 1 : 0;
  });
}

export function filterInbox<T extends InboxItem>(
  items: readonly T[],
  kind: InboxKind | "all",
): T[] {
  return kind === "all" ? [...items] : items.filter((item) => item.kind === kind);
}

/** What one source contributed to the badge: its first page, or nothing when it failed. */
export type BadgeSource = Readonly<{ loaded: boolean; count: number; truncated: boolean }>;
export type BadgeCount = Readonly<{
  count: number;
  /** At least one source has more rows than the first page shows. */
  more: boolean;
  /** At least one source could not be read, so the number may be too low. */
  partial: boolean;
}>;

export function badgeCount(sources: readonly BadgeSource[]): BadgeCount {
  let count = 0;
  let more = false;
  let partial = false;
  for (const source of sources) {
    if (!source.loaded) {
      partial = true;
      continue;
    }
    count += source.count;
    more ||= source.truncated;
  }
  return { count, more, partial };
}

/** `99+` style label; a trailing `+` marks a lower bound. */
export function badgeLabel(value: BadgeCount, overflow = 99): string {
  const shown = value.count > overflow ? overflow : value.count;
  return value.count > overflow || value.more || value.partial ? `${shown}+` : String(shown);
}
