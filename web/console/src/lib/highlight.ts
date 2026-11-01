// Splits text around a search term for highlighting. The result is plain data: the caller renders
// each part as a text node, never as markup (docs/07 7.10.6).

export type Part = { text: string; hit: boolean };

/** Parts of `text` in order; the matched runs are `hit`. Matching ignores case. */
export function splitHighlight(text: string, query: string): Part[] {
  const needle = query.trim().toLowerCase();
  if (needle.length === 0 || text.length === 0) return [{ text, hit: false }];
  const lower = text.toLowerCase();
  const parts: Part[] = [];
  let cursor = 0;
  let found = lower.indexOf(needle);
  while (found !== -1) {
    if (found > cursor) parts.push({ text: text.slice(cursor, found), hit: false });
    parts.push({ text: text.slice(found, found + needle.length), hit: true });
    cursor = found + needle.length;
    found = lower.indexOf(needle, cursor);
  }
  if (cursor < text.length) parts.push({ text: text.slice(cursor), hit: false });
  return parts;
}

/** How many places in `text` the term occurs (case-insensitive). */
export function countHits(text: string, query: string): number {
  return splitHighlight(text, query).filter((part) => part.hit).length;
}
