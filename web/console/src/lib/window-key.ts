// A list's query string names its filter and its time window. A preset window moves with the clock, so the same
// list gets a new query string every refresh step. These helpers tell that case from a change of filter.

/** The query string without its window bounds, with the remaining parameters in a fixed order. */
export function withoutWindow(query: string): string {
  const params = new URLSearchParams(query);
  params.delete("since_millis");
  params.delete("until_millis");
  params.sort();
  return params.toString();
}

/** True when two query strings ask for the same list and differ at most in the window. */
export function sameListOtherWindow(a: string, b: string): boolean {
  return withoutWindow(a) === withoutWindow(b);
}
