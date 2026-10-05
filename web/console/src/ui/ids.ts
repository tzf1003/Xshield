/**
 * Display helpers for object IDs. The full value is always what is copied, titled and announced;
 * the abbreviation only saves width in dense tables.
 */
const HEAD = 12;
const TAIL = 6;

/** `req_018f2a3b-4c5d-7000-8000-000000000001` -> `req_018f2a3b…000001`. */
export function abbreviateId(value: string): string {
  return value.length <= HEAD + TAIL + 2 ? value : `${value.slice(0, HEAD)}…${value.slice(-TAIL)}`;
}

/** The ID prefix before the first underscore (`req`, `mdl`, `grant`, ...), if any. */
export function idPrefix(value: string): string | null {
  const index = value.indexOf("_");
  return index > 0 ? value.slice(0, index) : null;
}
