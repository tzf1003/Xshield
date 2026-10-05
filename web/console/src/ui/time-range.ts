/**
 * Time handling shared by the investigation pages.
 *
 * The server speaks UTC whole-second half-open windows `[start, end)`. Operators think in local
 * time, so the UI shows local time (UTC on hover) and converts here. This module never decides
 * whether a window is acceptable to the server: `validateSearchPlan`, `validateModelCallListPlan`
 * and `validateCausalityPlan` stay the single gate. The hints below only explain a rejection in
 * words and are checked against those validators in tests/time-range.test.ts.
 */

export type RangePreset = "15m" | "1h" | "24h" | "7d";

export const rangePresets: readonly Readonly<{ id: RangePreset; label: string; ms: number }>[] = [
  { id: "15m", label: "15 分钟", ms: 15 * 60_000 },
  { id: "1h", label: "1 小时", ms: 60 * 60_000 },
  { id: "24h", label: "24 小时", ms: 24 * 60 * 60_000 },
  { id: "7d", label: "7 天", ms: 7 * 24 * 60 * 60_000 },
];

/** What the operator chose. Presets are relative, so they resolve when the query is submitted. */
export type RangeIntent =
  | Readonly<{ kind: "preset"; preset: RangePreset }>
  /** `datetime-local` strings in the browser's local time zone. */
  | Readonly<{ kind: "custom"; start: string; end: string }>
  /** Nothing chosen yet, for example after a preset arrived from another page. */
  | Readonly<{ kind: "none" }>;

/** A server-ready window: whole-second RFC 3339 UTC strings. */
export type UtcWindow = Readonly<{ start: string; end: string }>;

export type RangeProblem = "missing" | "incomplete" | "invalid" | "order" | "too_long" | "bounds";

export type RangeResolution =
  | Readonly<{ window: UtcWindow; problem: null }>
  | Readonly<{ window: null; problem: RangeProblem }>;

export const rangeProblemText: Record<RangeProblem, string> = {
  missing: "请选择时间范围。",
  incomplete: "请填写开始和结束时间。",
  invalid: "时间格式无法识别。",
  order: "结束时间必须晚于开始时间。",
  too_long: "时间范围不能超过 31 天。",
  bounds: "时间必须在 1970 年至 2300 年之间。",
};

/** Mirrors the validators' limits for the explanatory hints only. */
export const MAX_WINDOW_MS = 31 * 24 * 60 * 60 * 1000;
export const MIN_INSTANT_MS = 0;
export const MAX_INSTANT_MS = 10_413_792_000_000;

export const DEFAULT_PRESET: RangePreset = "1h";

export function presetMs(preset: RangePreset): number {
  return rangePresets.find((entry) => entry.id === preset)?.ms ?? 60 * 60_000;
}

/** `2026-09-20T08:10:30Z`, exactly the shape the plans require. */
export function toUtcSecond(ms: number): string {
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");
}

const localInput = /^(\d{4,6})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?$/;

/**
 * Reads a `datetime-local` value as local wall-clock time. Seconds are optional because browsers
 * drop them when they are zero. A wall-clock time that does not exist (spring-forward gap) lands
 * after the gap, and an ambiguous one (fall-back overlap) takes its first occurrence; both are the
 * platform's own rules, and the resulting instant is always what the UI then shows in UTC.
 */
export function parseLocalInput(value: string): number | null {
  const match = localInput.exec(value);
  if (!match) return null;
  const [, year, month, day, hour, minute, second] = match;
  const parts = [year, month, day, hour, minute, second ?? "0"].map(Number);
  const [y, mo, d, h, mi, s] = parts as [number, number, number, number, number, number];
  // `new Date(y, ...)` maps years 0-99 to 19xx, and none of them is a valid range bound anyway.
  if (y < 100 || mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || s > 59) return null;
  const date = new Date(y, mo - 1, d, h, mi, s, 0);
  // Reject calendar overflow such as 31 June, which `Date` would silently roll into July.
  if (date.getFullYear() !== y || date.getMonth() !== mo - 1 || date.getDate() !== d) return null;
  const time = date.getTime();
  return Number.isFinite(time) ? time : null;
}

function pad(value: number, length = 2): string {
  return String(value).padStart(length, "0");
}

/** The `datetime-local` value (local wall time, whole seconds) for an instant. */
export function toLocalInput(ms: number): string {
  const date = new Date(ms);
  return (
    `${pad(date.getFullYear(), 4)}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}` +
    `T${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
  );
}

function checkInstants(startMs: number, endMs: number): RangeProblem | null {
  if (
    startMs < MIN_INSTANT_MS ||
    endMs > MAX_INSTANT_MS ||
    endMs < MIN_INSTANT_MS ||
    startMs > MAX_INSTANT_MS
  ) {
    return "bounds";
  }
  if (endMs <= startMs) return "order";
  if (endMs - startMs > MAX_WINDOW_MS) return "too_long";
  return null;
}

/** Whole-second UTC window for two instants, or the reason it is not representable. */
export function windowFromInstants(startMs: number, endMs: number): RangeResolution {
  if (!Number.isFinite(startMs) || !Number.isFinite(endMs))
    return { window: null, problem: "invalid" };
  const start = Math.floor(startMs / 1000) * 1000;
  const end = Math.floor(endMs / 1000) * 1000;
  const problem = checkInstants(start, end);
  if (problem) return { window: null, problem };
  return { window: { start: toUtcSecond(start), end: toUtcSecond(end) }, problem: null };
}

/**
 * Resolves the operator's choice against `nowMs`. A preset ends at the next whole second so that
 * an event recorded in the current second is inside the half-open window.
 */
export function resolveRange(intent: RangeIntent, nowMs: number): RangeResolution {
  if (intent.kind === "none") return { window: null, problem: "missing" };
  if (intent.kind === "preset") {
    const end = Math.ceil(nowMs / 1000) * 1000;
    return windowFromInstants(end - presetMs(intent.preset), end);
  }
  if (intent.start === "" || intent.end === "") return { window: null, problem: "incomplete" };
  const start = parseLocalInput(intent.start);
  const end = parseLocalInput(intent.end);
  if (start === null || end === null) return { window: null, problem: "invalid" };
  return windowFromInstants(start, end);
}

/** A window centred on an event: `[floor(t) - spread, floor(t) + spread + 1 s)`, root included. */
export function windowAround(centerMs: number, spreadMs: number): RangeResolution {
  if (!Number.isFinite(centerMs)) return { window: null, problem: "invalid" };
  const center = Math.floor(centerMs / 1000) * 1000;
  return windowFromInstants(center - spreadMs, center + spreadMs + 1000);
}

// ---------------------------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------------------------

const rfc3339 = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(?:Z|\+00:00)$/;

/** Fractional-second digits of a UTC RFC 3339 string, padded to microseconds (6 digits). */
export function microsOf(iso: string): string {
  const match = rfc3339.exec(iso);
  return ((match?.[3] ?? "") + "000000").slice(0, 6);
}

/**
 * Unix microseconds (the request-timeline wire shape) as UTC RFC 3339 with microseconds, without
 * going through a millisecond `Date` for the sub-millisecond digits.
 */
export function microsToIso(micros: number): string {
  const ms = Math.floor(micros / 1000);
  const remainder = micros - ms * 1000;
  const base = new Date(ms);
  if (Number.isNaN(base.getTime())) return "";
  const fraction = pad(base.getUTCMilliseconds(), 3) + pad(remainder, 3);
  return `${base.toISOString().slice(0, 19)}.${fraction}Z`;
}

/** Epoch milliseconds for an RFC 3339 UTC string, or null when it does not parse. */
export function isoToMs(iso: string): number | null {
  const ms = Date.parse(iso);
  return Number.isFinite(ms) ? ms : null;
}

export type TimePrecision = "second" | "millisecond" | "microsecond";

function fractionFor(iso: string, precision: TimePrecision): string {
  if (precision === "second") return "";
  const micros = microsOf(iso);
  return `.${precision === "millisecond" ? micros.slice(0, 3) : micros}`;
}

/** `2026-09-20 16:10:30.123456` in the browser's local time zone. */
export function formatLocal(iso: string, precision: TimePrecision = "second"): string {
  const ms = isoToMs(iso);
  if (ms === null) return "时间不可用";
  const date = new Date(ms);
  return (
    `${pad(date.getFullYear(), 4)}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ` +
    `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}` +
    fractionFor(iso, precision)
  );
}

/** `2026-09-20 08:10:30.123456 UTC`. */
export function formatUtc(iso: string, precision: TimePrecision = "second"): string {
  const ms = isoToMs(iso);
  if (ms === null) return "时间不可用";
  return `${new Date(ms).toISOString().slice(0, 19).replace("T", " ")}${fractionFor(iso, precision)} UTC`;
}

/** Offset label of the browser's zone at an instant, for example `UTC+8`. */
export function localOffsetLabel(ms: number): string {
  const offset = -new Date(ms).getTimezoneOffset();
  const sign = offset >= 0 ? "+" : "-";
  const abs = Math.abs(offset);
  const hours = Math.floor(abs / 60);
  const minutes = abs % 60;
  return `UTC${sign}${hours}${minutes === 0 ? "" : `:${pad(minutes)}`}`;
}

/** Human duration for microseconds: `84 µs`, `12.4 ms`, `1.25 s`. */
export function formatDuration(micros: number): string {
  if (micros < 1000) return `${micros} µs`;
  if (micros < 1_000_000) return `${(micros / 1000).toFixed(micros < 10_000 ? 2 : 1)} ms`;
  return `${(micros / 1_000_000).toFixed(2)} s`;
}

/** Distance between two instants for lag hints: `42 秒`, `3 分钟`, `5 小时`, `2 天`. */
export function formatSpan(ms: number): string {
  const seconds = Math.max(0, Math.round(ms / 1000));
  if (seconds < 60) return `${seconds} 秒`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} 分钟`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours} 小时`;
  return `${Math.round(hours / 24)} 天`;
}
