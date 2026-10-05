/**
 * Display states shared by the site list, the site header and the release page. The server
 * reports `apply_state` (active, pending, failed, paused), a separate `requires_approval` flag
 * and the configured `status`; operators think in one word, so this derives it in one place.
 */
export type SiteDisplayState =
  | "draft"
  | "pending"
  | "awaiting_approval"
  | "active"
  | "failed"
  | "paused";

export type ApplyStateValue = "active" | "pending" | "failed" | "paused";
export type ConfigStatusValue = "draft" | "active" | "paused";

export type DisplayStateInput = Readonly<{
  apply_state: ApplyStateValue | null | undefined;
  requires_approval: boolean | null | undefined;
  /** The configured status of the desired revision, when the response carries it. */
  status?: ConfigStatusValue | null;
}>;

/**
 * Precedence: a failed apply is always shown as failed; an unapproved change is "awaiting
 * approval" even though the server still says `pending`; a configured draft is a draft whatever
 * its apply bookkeeping says (drafts are never applied); then the server's own apply state.
 */
export function siteDisplayState(input: DisplayStateInput): SiteDisplayState | null {
  if (input.apply_state === "failed") return "failed";
  if (input.requires_approval === true) return "awaiting_approval";
  if (input.status === "draft") return "draft";
  switch (input.apply_state) {
    case "paused":
      return "paused";
    case "pending":
      return "pending";
    case "active":
      return "active";
    default:
      return null;
  }
}

export type HealthValue = "healthy" | "degraded" | "unavailable" | "unconfigured" | "unknown";

const healthValues: readonly string[] = ["healthy", "degraded", "unavailable", "unconfigured"];

/** Anything the server sends that is not one of the bounded states is "unknown". */
export function healthValue(raw: unknown): HealthValue {
  return typeof raw === "string" && healthValues.includes(raw) ? (raw as HealthValue) : "unknown";
}
