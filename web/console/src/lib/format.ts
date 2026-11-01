// Display formatting (docs/06 6.6.6): thousands separators, units, integer percentages and local
// time with UTC on hover. Pure functions so the unit tests can pin them.

const pad = (value: number, width = 2): string => String(value).padStart(width, "0");

/** Local clock time, `HH:mm:ss.SSS`. */
export function fmtClock(ms: number): string {
  const date = new Date(ms);
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}.${pad(date.getMilliseconds(), 3)}`;
}

/** Local date and clock time, `YYYY-MM-DD HH:mm:ss.SSS`. */
export function fmtLocalDateTime(ms: number): string {
  const date = new Date(ms);
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${fmtClock(ms)}`;
}

/** UTC time for tooltips, `YYYY-MM-DD HH:mm:ss.SSS UTC`. */
export function fmtUtc(ms: number): string {
  const date = new Date(ms);
  return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())}.${pad(date.getUTCMilliseconds(), 3)} UTC`;
}

export function fmtInt(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  return value.toLocaleString("en-US");
}

/** Integer percentage of a 0 to 1 probability. */
export function pct(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  return `${Math.round(value * 100)}%`;
}

export function fmtMs(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  return `${fmtInt(value)} ms`;
}

export function fmtBytes(value: number): string {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / 1024 / 1024).toFixed(1)} MiB`;
}

/** Elapsed time as a short phrase, e.g. `11 分钟`. */
export function fmtElapsed(seconds: number): string {
  if (seconds < 60) return `${Math.max(0, Math.round(seconds))} 秒`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} 分钟`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)} 小时`;
  return `${Math.round(seconds / 86400)} 天`;
}

/** Relative time against a given "now", e.g. `3 分钟前`. Used for status lines only. */
export function fmtAgo(ms: number, now: number): string {
  const seconds = Math.round((now - ms) / 1000);
  if (seconds < 60) return `${Math.max(0, seconds)} 秒前`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} 分钟前`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)} 小时前`;
  return `${Math.round(seconds / 86400)} 天前`;
}

/** Shortens text for one-line summaries; the full text stays in the title attribute. */
export function clip(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

export function plural(count: number, one: string, many: string): string {
  return count === 1 ? one : many.replace("{n}", fmtInt(count));
}
