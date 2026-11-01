// Clock helpers of the system page. Partitions are named for their UTC day (docs/07 7.8.2), so their
// dates are UTC and say so; everything else a person reads is local time (docs/06 6.6.6).

const pad = (value: number): string => String(value).padStart(2, "0");

/** Local clock time, `HH:mm`. */
export function hm(ms: number): string {
  const date = new Date(ms);
  return `${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

/** Local date and clock time without the year, `MM-DD HH:mm:ss`. */
export function shortDateTime(ms: number): string {
  const date = new Date(ms);
  return `${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

/** The UTC calendar day, `YYYY-MM-DD`. */
export function utcDay(ms: number): string {
  const date = new Date(ms);
  return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())}`;
}

/** A timestamp from an RFC 3339 string, or null when it does not parse. */
export function parseTime(text: string): number | null {
  const ms = Date.parse(text);
  return Number.isNaN(ms) ? null : ms;
}
