/**
 * The rows of the approval center: access requests, exports and site revisions, normalised so one
 * table can show them. Pure; the page only decides which sources to read and which tab to show.
 */
import type { SiteListItem } from "../../api.ts";
import { type AccessList, accessPattern } from "../../evidence-access.ts";
import { type ExportList, exportPattern } from "../../exports.ts";
import {
  accessInboxItem,
  exportInboxItem,
  type InboxItem,
  type InboxKind,
  siteApprovals,
} from "../../work/inbox.ts";
import { exportLapsed } from "../../work/status.ts";

export type Row = InboxItem &
  Readonly<{
    /** Whose request this is, according to the list it came from. */
    ownership: "mine" | "others";
    /** The database observation time of the page the row was read in. */
    asOfMs: number;
    /** The package expiry of an approved or ready export. */
    expiresAt: string | null;
    /** An approved or ready export past its expiry on that observation. */
    lapsed: boolean;
  }>;

export type Selection = Readonly<{ kind: InboxKind; id: string }>;

/** `?item=` names an access request or an export; anything else is ignored. */
export function selectionFromItem(item: unknown): Selection | null {
  if (typeof item !== "string") return null;
  if (accessPattern.test(item)) return { kind: "access", id: item };
  if (exportPattern.test(item)) return { kind: "export", id: item };
  return null;
}

export function accessRows(page: AccessList | undefined, ownership: Row["ownership"]): Row[] {
  if (!page) return [];
  const asOfMs = Date.parse(page.as_of);
  return page.items.map((row) => ({
    ...accessInboxItem(row),
    ownership,
    asOfMs,
    expiresAt: null,
    lapsed: false,
  }));
}

export function exportRows(page: ExportList | undefined, ownership: Row["ownership"]): Row[] {
  if (!page) return [];
  const asOfMs = Date.parse(page.as_of);
  return page.items.map((row) => ({
    ...exportInboxItem(row),
    ownership,
    asOfMs,
    expiresAt: row.expires_at,
    lapsed: exportLapsed(row, asOfMs),
  }));
}

/** Site revisions that await a policy decision. The decision itself is made on the site page. */
export function policyRows(sites: readonly SiteListItem[] | undefined, observedMs: number): Row[] {
  return siteApprovals(sites ?? []).map((item) => ({
    ...item,
    ownership: "others" as const,
    asOfMs: observedMs,
    expiresAt: null,
    lapsed: false,
  }));
}

export function rowSelection(row: Row): Selection {
  return { kind: row.kind, id: row.id };
}
