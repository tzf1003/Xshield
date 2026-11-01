// Builds an in-app address that keeps the global scope (site, range and custom bounds) of the page
// the user is on. Used where the target is not a typed route link: the palette, the chord keys, and
// dynamic addresses built from data.

const SCOPE_KEYS = ["site", "range", "since", "until"] as const;

export function hrefFor(path: string, search: Record<string, string> = {}): string {
  const current = new URLSearchParams(window.location.search);
  // The bounds belong to a custom range only: they are carried when the range carried is custom, and a
  // target that names its own range keeps its own (docs/06 6.2.2).
  const range = search.range ?? current.get("range");
  const params = new URLSearchParams();
  for (const key of SCOPE_KEYS) {
    if ((key === "since" || key === "until") && range !== "custom") continue;
    const value = current.get(key);
    if (value !== null) params.set(key, value);
  }
  for (const [key, value] of Object.entries(search)) params.set(key, value);
  const text = params.toString();
  return text.length > 0 ? `${path}?${text}` : path;
}
