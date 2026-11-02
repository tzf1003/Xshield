// URL search parameters of every route (docs/06 6.2.2, docs/07 7.10.3). Each route's validator keeps
// the global scope (site, range, since, until) and its own parameters, drops anything else, and never
// trusts a value it cannot name: an unknown option reads as absent, so a hand-edited link still opens.
// Every key is optional, so a link names only what it needs, and any route accepts the global scope.

import { isSiteName } from "../lib/ids.ts";
import type { RangeParam } from "../lib/time-range.ts";
import { isRangeParam, parseMillis } from "../lib/time-range.ts";

export type GlobalSearch = {
  site?: string;
  range?: RangeParam;
  since?: number;
  until?: number;
};

/** Search values arrive as strings; the router does not coerce them. */
export function str(raw: unknown): string | undefined {
  return typeof raw === "string" && raw.length > 0 ? raw : undefined;
}

export function oneOf<T extends string>(raw: unknown, options: readonly T[]): T | undefined {
  return options.find((option) => option === raw);
}

/** A flag written as `1`; any other value reads as absent. */
export function flag(raw: unknown): "1" | undefined {
  return raw === "1" ? "1" : undefined;
}

/** A small non-negative integer, such as a value index; anything else reads as absent. */
export function index(raw: unknown): number | undefined {
  return typeof raw === "string" && /^[0-9]{1,4}$/.test(raw) ? Number(raw) : undefined;
}

export function validateGlobal(raw: Record<string, unknown>): GlobalSearch {
  const out: GlobalSearch = {};
  if (typeof raw.site === "string" && isSiteName(raw.site)) out.site = raw.site;
  if (isRangeParam(raw.range)) out.range = raw.range;
  if (out.range === "custom") {
    const since = parseMillis(raw.since);
    const until = parseMillis(raw.until);
    if (since !== null) out.since = since;
    if (until !== null) out.until = until;
  }
  return out;
}

export const CHIP_IDS = [
  "judged",
  "attention",
  "blocked",
  "would_block",
  "unjudged",
  "jev",
  "no_session",
  "bypass",
] as const;
export type ChipId = (typeof CHIP_IDS)[number];

export type RequestsSearch = GlobalSearch & {
  q?: string;
  chip?: ChipId;
  /** `all` also lists bypass and unknown-site requests (docs/06 6.4.3). */
  scope?: "all";
  peek?: string;
  live?: "1";
  batch?: "1";
};

export function validateRequests(raw: Record<string, unknown>): RequestsSearch {
  return {
    ...validateGlobal(raw),
    q: str(raw.q),
    chip: oneOf(raw.chip, CHIP_IDS),
    scope: oneOf(raw.scope, ["all"] as const),
    peek: str(raw.peek),
    live: flag(raw.live),
    batch: flag(raw.batch),
  };
}

export const DETAIL_TABS = ["pipeline", "values", "jev", "session", "raw"] as const;
export type DetailTab = (typeof DETAIL_TABS)[number];
export const JEV_VIEWS = ["structured", "json", "raw", "prompt"] as const;
export type JevView = (typeof JEV_VIEWS)[number];
export const JEV_DOCS = ["state", "body", "response"] as const;
export type JevDoc = (typeof JEV_DOCS)[number];

export type DetailSearch = GlobalSearch & {
  tab?: DetailTab;
  jev_view?: JevView;
  jev_doc?: JevDoc;
  /** The highlighted value, by its position in the trace (docs/06 6.4.4). */
  hl?: number;
};

export function validateDetail(raw: Record<string, unknown>): DetailSearch {
  return {
    ...validateGlobal(raw),
    tab: oneOf(raw.tab, DETAIL_TABS),
    jev_view: oneOf(raw.jev_view, JEV_VIEWS),
    jev_doc: oneOf(raw.jev_doc, JEV_DOCS),
    hl: index(raw.hl),
  };
}

export type SessionsSearch = GlobalSearch & {
  flag?: "blocked" | "jev";
  q?: string;
};

export function validateSessions(raw: Record<string, unknown>): SessionsSearch {
  return {
    ...validateGlobal(raw),
    flag: oneOf(raw.flag, ["blocked", "jev"] as const),
    q: str(raw.q),
  };
}

export type TimelineSearch = GlobalSearch & {
  only?: "judged" | "jev" | "blocks";
  /** The request to scroll to. */
  at?: string;
};

export function validateTimeline(raw: Record<string, unknown>): TimelineSearch {
  return {
    ...validateGlobal(raw),
    only: oneOf(raw.only, ["judged", "jev", "blocks"] as const),
    at: str(raw.at),
  };
}

export const JEV_CHIPS = ["all", "blocked", "allowed", "failed", "low", "slow", "trimmed"] as const;
export type JevChip = (typeof JEV_CHIPS)[number];

export type JevSearch = GlobalSearch & {
  q?: string;
  chip?: JevChip;
};

export function validateJev(raw: Record<string, unknown>): JevSearch {
  return {
    ...validateGlobal(raw),
    q: str(raw.q),
    chip: oneOf(raw.chip, JEV_CHIPS),
  };
}

export const SITE_TABS = ["overview", "config", "insights", "history"] as const;
export type SiteTab = (typeof SITE_TABS)[number];

export type SiteSearch = GlobalSearch & {
  tab?: SiteTab;
  edit?: "form" | "yaml";
  group?: string;
  /** The version to compare with the current one, in the history tab. */
  diff?: string;
  /** A path for a new interface-name rule in the configuration tab (`route=/gw/path`). */
  route?: string;
};

export function validateSite(raw: Record<string, unknown>): SiteSearch {
  return {
    ...validateGlobal(raw),
    tab: oneOf(raw.tab, SITE_TABS),
    edit: oneOf(raw.edit, ["form", "yaml"] as const),
    group: str(raw.group),
    diff: str(raw.diff),
    route: str(raw.route),
  };
}

export type WizardSearch = GlobalSearch & {
  step?: number;
  from?: "yaml";
};

export function validateWizard(raw: Record<string, unknown>): WizardSearch {
  const step = Number(raw.step);
  return {
    ...validateGlobal(raw),
    step: Number.isInteger(step) && step >= 1 && step <= 4 ? step : undefined,
    from: oneOf(raw.from, ["yaml"] as const),
  };
}

export const SYSTEM_TABS = ["edges", "storage", "params", "import"] as const;
export type SystemTab = (typeof SYSTEM_TABS)[number];

export type SystemSearch = GlobalSearch & {
  tab?: SystemTab;
};

export function validateSystem(raw: Record<string, unknown>): SystemSearch {
  return {
    ...validateGlobal(raw),
    tab: oneOf(raw.tab, SYSTEM_TABS),
  };
}

export type LoginSearch = {
  next?: string;
};

export function validateLogin(raw: Record<string, unknown>): LoginSearch {
  // Only a path inside the console may be a destination after login (docs/06 6.4.1).
  const next =
    typeof raw.next === "string" && raw.next.startsWith("/") && !raw.next.startsWith("//")
      ? raw.next
      : undefined;
  return { next };
}

/** The default range, exported so pages and links agree on what "no range" means. */
export { DEFAULT_RANGE as FALLBACK_RANGE } from "../lib/time-range.ts";
