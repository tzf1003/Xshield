import { validateSearchPlan } from "../search.ts";

/**
 * A single prefilled search condition handed from another page (the command palette, a detail
 * page, a ledger snapshot). It only ever fills the search form; the operator chooses the time
 * range and submits, so nothing is queried on arrival.
 */
export const presetKinds = [
  "request_id",
  "event_id",
  "trace_id",
  "caused_by_event_id",
  "grant_id",
  "auth_binding_id",
  "case_id",
  "artifact_id",
  "calibration_report_id",
  "evidence_access_request_id",
  "evidence_hold_id",
  "model_call_id",
  "agent_run_id",
  "job_id",
  "share_grant_id",
] as const;

export type SearchPresetKind = (typeof presetKinds)[number];

export type SearchPreset = {
  kind: SearchPresetKind;
  value: string;
};

export const SEARCH_PATH = "/investigation/search";

/** The router search parameter that carries a preset: `trace_id:018f2a3b…`. */
export const PREFILL_PARAM = "prefill";

export function encodePrefill(preset: SearchPreset): string {
  return `${preset.kind}:${preset.value}`;
}

/** A window that is valid on its own, so only the condition under test can fail the validator. */
const PROBE_WINDOW = { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" } as const;

/** Whether the allowlisted validator accepts this one condition (the single gate). */
export function filterAccepted(filter: unknown): boolean {
  try {
    validateSearchPlan({
      schema_version: 3,
      ...PROBE_WINDOW,
      filters: [filter],
      sort: "occurred_at_desc",
      limit: 1,
    });
    return true;
  } catch {
    return false;
  }
}

/**
 * Reads the `prefill` parameter of the search route. Anything that is not a known kind with a
 * canonical value is ignored, so a crafted link can neither smuggle a free-text condition nor
 * trigger a query.
 */
export function decodePrefill(raw: unknown): SearchPreset | null {
  if (typeof raw !== "string") return null;
  const index = raw.indexOf(":");
  if (index <= 0) return null;
  const kind = raw.slice(0, index);
  const value = raw.slice(index + 1);
  if (!(presetKinds as readonly string[]).includes(kind)) return null;
  if (!filterAccepted({ kind, value })) return null;
  return { kind: kind as SearchPresetKind, value };
}

let handOvers = 0;

/**
 * Route location of the search page with a preset, for `router.navigate`. Every hand-over carries
 * its own history state, so handing the same condition over twice is still a navigation (the form
 * is refilled) instead of the router treating the identical address as "already there".
 */
export function searchLocation(preset: SearchPreset): {
  to: typeof SEARCH_PATH;
  search: Record<string, string>;
  state: { handOver: number };
} {
  handOvers += 1;
  return {
    to: SEARCH_PATH,
    search: { [PREFILL_PARAM]: encodePrefill(preset) },
    state: { handOver: handOvers },
  };
}
