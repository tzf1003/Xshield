// Conversions between Unix milliseconds and the value of an `<input type="datetime-local">`, which
// is local time without an offset (docs/06 6.3.2: custom ranges are local, the API takes milliseconds).

const pad = (value: number) => String(value).padStart(2, "0");

export function toLocalInput(ms: number): string {
  const date = new Date(ms);
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

/** Parses a datetime-local value; null when it is empty or malformed. */
export function fromLocalInput(value: string): number | null {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(value)) return null;
  const ms = new Date(value).getTime();
  return Number.isFinite(ms) ? ms : null;
}
