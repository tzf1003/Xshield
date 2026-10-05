/**
 * Retention-hold deadlines. The server accepts a deadline in the future and at most 720 hours
 * after its own clock, as canonical UTC milliseconds. The browser only ever estimates the
 * server's clock from the last observation it received, so every limit here keeps a margin.
 */
import { validHoldUntil } from "../evidence-holds.ts";
import type { HoldRecord } from "../evidence-holds.ts";
import type { HoldState } from "./status.ts";

export const HOLD_MAX_HOURS = 720;
const HOUR_MS = 3_600_000;
/** Slack against the browser-versus-database clock estimate, at both ends of the window. */
export const HOLD_MARGIN_MS = 2 * 60_000;

export type HoldWindow = Readonly<{ minMs: number; maxMs: number }>;

export function holdWindow(serverNowMs: number): HoldWindow {
  return {
    minMs: serverNowMs + HOLD_MARGIN_MS,
    maxMs: serverNowMs + HOLD_MAX_HOURS * HOUR_MS - HOLD_MARGIN_MS,
  };
}

export type HoldPreset = "1d" | "7d" | "max";
export const HOLD_PRESETS: readonly { key: HoldPreset; label: string }[] = [
  { key: "1d", label: "1 天" },
  { key: "7d", label: "7 天" },
  { key: "max", label: "30 天（上限）" },
];

export function presetDeadlineMs(preset: HoldPreset, serverNowMs: number): number {
  if (preset === "max") return holdWindow(serverNowMs).maxMs;
  return serverNowMs + (preset === "1d" ? 24 : 24 * 7) * HOUR_MS;
}

/** The server's clock, extrapolated from a database observation and the time since it arrived. */
export function estimateServerNowMs(asOf: string, receivedAtMs: number, nowMs: number): number {
  return Date.parse(asOf) + Math.max(0, nowMs - receivedAtMs);
}

const inputPattern = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})(?::(\d{2})(?:\.(\d{1,3}))?)?$/;

/** The text of a `datetime-local` field, read as UTC (the console never uses local time). */
export function parseUtcInput(value: string): number | null {
  const match = inputPattern.exec(value);
  if (!match) return null;
  const [, date, minutes, seconds = "00", fraction = "0"] = match;
  if (!date || !minutes) return null;
  const ms = Date.parse(`${date}T${minutes}:${seconds}.${fraction.padEnd(3, "0")}Z`);
  if (!Number.isFinite(ms)) return null;
  // Date.parse normalises impossible calendar days; the round trip catches them.
  const rebuilt = new Date(ms).toISOString();
  return rebuilt.startsWith(`${date}T${minutes}`) ? ms : null;
}

/** `YYYY-MM-DDTHH:mm:ss` for a `datetime-local` value (UTC). */
export function formatUtcInput(ms: number): string {
  return new Date(ms).toISOString().slice(0, 19);
}

/** Canonical `YYYY-MM-DDTHH:mm:ss.sssZ`, the only form the server accepts. */
export function holdUntilOf(ms: number): string {
  const value = new Date(ms).toISOString();
  if (!validHoldUntil(value)) throw new RangeError("hold deadline is out of range");
  return value;
}

export function holdUntilProblem(ms: number | null, serverNowMs: number): string | null {
  if (ms === null || !Number.isFinite(ms)) return "请选择有效的保留截止时间（UTC）";
  const window = holdWindow(serverNowMs);
  if (ms < window.minMs) return "截止时间须晚于服务端当前时间至少 2 分钟";
  if (ms > window.maxMs) {
    return `截止时间最多为服务端当前时间之后 ${HOLD_MAX_HOURS} 小时（含 2 分钟安全余量）`;
  }
  return null;
}

function micros(value: string): string {
  return value.replace(/\.(\d+)Z$/, (_, part: string) => `.${part.padEnd(6, "0")}Z`);
}

/** Released wins; otherwise the deadline is compared with the database observation, with microseconds. */
export function holdState(record: HoldRecord, asOf: string): HoldState {
  if (record.released_at !== null) return "released";
  return micros(record.hold_until) <= micros(asOf) ? "expired" : "active";
}
