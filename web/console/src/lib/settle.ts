// Runs one call per item and waits for all of them, so a refused item does not stop the ones after it.

/** Sends every item; when any was refused, rejects with the first refusal after all have settled. */
export async function sendAll<T>(
  items: readonly T[],
  send: (item: T) => Promise<unknown>,
): Promise<void> {
  const results = await Promise.allSettled(items.map((item) => send(item)));
  const refused = results.find((result) => result.status === "rejected");
  if (refused !== undefined) throw refused.reason;
}
