// Splits text around a search term for highlighting. The result is plain data: the caller renders
// each part as a text node, never as markup (docs/07 7.10.6).

export type Part = { text: string; hit: boolean };

/** Parts of `text` in order; the matched runs are `hit`. Matching ignores case. */
export function splitHighlight(text: string, query: string): Part[] {
  const needle = query.trim();
  if (needle.length === 0 || text.length === 0) return [{ text, hit: false }];
  // The search runs on the original text. A lowercased copy can change length ("İ" becomes two
  // code units), which would move every later part out of place.
  const pattern = new RegExp(escapeRegExp(needle), "giu");
  const parts: Part[] = [];
  let cursor = 0;
  for (let found = pattern.exec(text); found !== null; found = pattern.exec(text)) {
    const [matched = ""] = found;
    const start = found.index;
    if (start > cursor) parts.push({ text: text.slice(cursor, start), hit: false });
    parts.push({ text: matched, hit: true });
    cursor = start + matched.length;
  }
  if (cursor < text.length) parts.push({ text: text.slice(cursor), hit: false });
  return parts;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** How many places in `text` the term occurs (case-insensitive). */
export function countHits(text: string, query: string): number {
  return splitHighlight(text, query).filter((part) => part.hit).length;
}
