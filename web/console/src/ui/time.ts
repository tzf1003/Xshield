/**
 * Time formatting for operators: local wall-clock time as the primary reading, UTC on hover,
 * and a relative phrase next to it. Pure functions with an injectable clock and zone so the
 * unit tests are deterministic. Nothing here schedules a timer: relative text is computed at
 * render time only, so a page never refreshes itself behind the operator's back.
 */
export function parseTimestamp(value: string | number | null | undefined): number | null {
  if (value === null || value === undefined || value === "") return null;
  const ms = typeof value === "number" ? value : Date.parse(value);
  return Number.isFinite(ms) ? ms : null;
}

const pad = (n: number) => String(n).padStart(2, "0");

/** `2026-09-20 16:10:30` in the given zone (the browser's zone by default). */
export function formatLocal(ms: number, timeZone?: string): string {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone,
    hourCycle: "h23",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).formatToParts(new Date(ms));
  const get = (type: string) => parts.find((part) => part.type === type)?.value ?? "";
  return `${get("year")}-${get("month")}-${get("day")} ${get("hour")}:${get("minute")}:${get("second")}`;
}

/** `2026-09-20 08:10:30 UTC`. */
export function formatUtc(ms: number): string {
  const d = new Date(ms);
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} UTC`;
}

/** `3 分钟前`, `2 小时后`, `刚刚`; falls back to a date once the distance reaches 30 days. */
export function relativeTime(ms: number, nowMs: number, timeZone?: string): string {
  const diff = nowMs - ms;
  const future = diff < 0;
  const seconds = Math.abs(diff) / 1000;
  if (seconds < 45) return future ? "即将" : "刚刚";
  const minutes = seconds / 60;
  let value: number;
  let unit: string;
  if (minutes < 60) {
    value = minutes;
    unit = "分钟";
  } else if (minutes < 60 * 24) {
    value = minutes / 60;
    unit = "小时";
  } else {
    const days = minutes / (60 * 24);
    if (days >= 30) return formatLocal(ms, timeZone).slice(0, 10);
    value = days;
    unit = "天";
  }
  const rounded = Math.max(1, Math.round(value));
  return future ? `${rounded} ${unit}后` : `${rounded} ${unit}前`;
}

export type TimeView = Readonly<{
  /** Machine-readable value for `<time dateTime>`. */
  iso: string;
  local: string;
  utc: string;
  relative: string;
}>;

/** `null` when the value is not a parseable time (the caller shows "—"). */
export function timeView(
  value: string | number | null | undefined,
  nowMs: number,
  timeZone?: string,
): TimeView | null {
  const ms = parseTimestamp(value);
  if (ms === null) return null;
  return {
    iso: new Date(ms).toISOString(),
    local: formatLocal(ms, timeZone),
    utc: formatUtc(ms),
    relative: relativeTime(ms, nowMs, timeZone),
  };
}
