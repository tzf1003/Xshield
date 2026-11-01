// Clock labels for the overview, in local time (docs/06 6.6.6): the time of day, and a column label
// that adds the date when the window spans more than one day.

const pad = (value: number): string => String(value).padStart(2, "0");

/** Local clock time, `HH:mm`. */
export function hm(ms: number): string {
  const date = new Date(ms);
  return `${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

/** Local clock time, `HH:mm:ss`. */
export function hms(ms: number): string {
  const date = new Date(ms);
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

/** A label for one slot of a trend: `HH:mm`, or `MM-DD HH:mm` when the window crosses midnight. */
export function slotLabel(ms: number, multiDay: boolean): string {
  if (!multiDay) return hm(ms);
  const date = new Date(ms);
  return `${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${hm(ms)}`;
}
