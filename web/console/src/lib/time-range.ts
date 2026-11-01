// Time windows of the console (docs/06 6.3.2). Presets are relative to "now"; a custom window is
// two Unix-millisecond bounds in the URL. The retention limit is seven days.

export type RangePreset = "15m" | "1h" | "6h" | "24h" | "7d";
export type RangeParam = RangePreset | "custom";

export const PRESETS: RangePreset[] = ["15m", "1h", "6h", "24h", "7d"];
export const DEFAULT_RANGE: RangePreset = "24h";
export const RETENTION_MS = 7 * 24 * 60 * 60 * 1000;

const PRESET_MS: Record<RangePreset, number> = {
  "15m": 15 * 60 * 1000,
  "1h": 60 * 60 * 1000,
  "6h": 6 * 60 * 60 * 1000,
  "24h": 24 * 60 * 60 * 1000,
  "7d": RETENTION_MS,
};

export function isRangeParam(value: unknown): value is RangeParam {
  return value === "custom" || PRESETS.includes(value as RangePreset);
}

/** The window a preset covers, ending at `now`. */
export function presetWindow(preset: RangePreset, now: number): { since: number; until: number } {
  return { since: now - PRESET_MS[preset], until: now };
}

/** Bounds that are valid as a custom window: ordered, inside retention, at most seven days. */
export function validCustom(since: number, until: number, now: number): boolean {
  return (
    Number.isFinite(since) &&
    Number.isFinite(until) &&
    since < until &&
    until - since <= RETENTION_MS &&
    now - since <= RETENTION_MS
  );
}

/** The API window for a range parameter, or null for a custom window that is not valid. */
export function windowFor(
  range: RangeParam,
  since: number | null,
  until: number | null,
  now: number,
): { since: number; until: number } | null {
  if (range === "custom") {
    if (since === null || until === null || !validCustom(since, until, now)) return null;
    return { since, until };
  }
  return presetWindow(range, now);
}

/** Parses a number from a URL parameter; anything else is null. */
export function parseMillis(value: unknown): number | null {
  if (typeof value === "number") return Number.isFinite(value) ? Math.trunc(value) : null;
  if (typeof value !== "string" || !/^[0-9]{1,16}$/.test(value)) return null;
  return Number(value);
}
