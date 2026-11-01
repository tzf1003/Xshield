// Identifiers the console links to. Every link is built from a value that passes one of these
// checks, never from a field of a record (docs/07 7.10.6).

const REQUEST_ID = /^req_[0-9a-f]{32}$/;
const REQUEST_ID_IN_TEXT = /req_[0-9a-f]{32}/g;
const SESSION_LABEL = /^[0-9a-f]{16}$/;
const SESSION_PREFIX = /^[0-9a-f]{1,16}$/;
const SITE_NAME = /^[a-z0-9_-]{1,64}$/;
const SITE_NAME_LOOSE = /^[a-z0-9_-]+$/;

export function isRequestId(value: string): boolean {
  return REQUEST_ID.test(value);
}

export function isSessionLabel(value: string): boolean {
  return SESSION_LABEL.test(value);
}

export function isSessionPrefix(value: string): boolean {
  return SESSION_PREFIX.test(value);
}

export function isSiteName(value: string): boolean {
  return SITE_NAME.test(value);
}

/** Lower-case site name shape without the length limit, used while a name is still being typed. */
export function looksLikeSiteName(value: string): boolean {
  return SITE_NAME_LOOSE.test(value);
}

/** Unix milliseconds encoded in the first 12 hex digits after `req_` (7.3.1), or null. */
export function requestIdMillis(id: string): number | null {
  if (!isRequestId(id)) return null;
  return Number.parseInt(id.slice(4, 16), 16);
}

/** How many request ids a text holds before duplicates are removed (docs/06 6.4.3). */
export function countRequestIds(text: string): number {
  return [...text.matchAll(REQUEST_ID_IN_TEXT)].length;
}

/** Every distinct request id in a text, in order of first appearance. */
export function findRequestIds(text: string): string[] {
  const seen = new Set<string>();
  const found: string[] = [];
  for (const match of text.matchAll(REQUEST_ID_IN_TEXT)) {
    const id = match[0];
    if (!seen.has(id)) {
      seen.add(id);
      found.push(id);
    }
  }
  return found;
}

/** The short form shown in tables: the last eight digits, which differ within one time slot. */
export function shortRequestId(id: string): string {
  return `…${id.slice(-8)}`;
}

export function shortSession(label: string): string {
  return label.slice(0, 8);
}
