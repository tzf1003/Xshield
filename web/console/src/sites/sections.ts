import { type SiteSection, siteSections } from "../admin-routes.ts";
import type { SiteAccess } from "./access.ts";
import type { ChangeGroup } from "./model/diff.ts";

/** The sections that edit configuration (they exist only for SystemAdmin). */
export const configSections: readonly ChangeGroup[] = [
  "network",
  "security-entry",
  "routes",
  "identity",
  "crypto",
  "waf-limits",
  "policies",
];

export const sectionLabel: Record<SiteSection, string> = Object.fromEntries(siteSections) as Record<
  SiteSection,
  string
>;

/**
 * Which sections a role set is offered, in the order of `siteSections`. The URLs of the others
 * keep resolving (and explain that the role is missing); hiding is a convenience, the server
 * authorizes every read and write.
 *
 *  - SystemAdmin reads and edits the configuration (all sections);
 *  - Observer reads status, health, revisions: overview, policies (health), releases, audit;
 *  - release roles (author, approver, operator) see the release page, whose actions the server
 *    authorizes one by one, even without an Observer role to read state with.
 *
 * While creating a site only the configuration sections exist: there is nothing to release yet.
 */
export function visibleSections(access: SiteAccess, creating: boolean): SiteSection[] {
  return siteSections
    .map(([key]) => key)
    .filter((key) => {
      if (creating) return configSections.includes(key as ChangeGroup);
      if (configSections.includes(key as ChangeGroup)) {
        // The health read lives on the policies page, so observers get that one page.
        return access.canConfigure || (key === "policies" && access.canObserve);
      }
      if (key === "releases") return access.canConfigure || access.canObserve || access.canRelease;
      return access.canConfigure || access.canObserve; // overview, audit
    });
}
