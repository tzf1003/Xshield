import type { Outcome } from "../outcome.ts";

/**
 * A confirmed result that outlives the page it happened on: deleting a site leaves its own page,
 * and the list it lands on says what happened. Memory only, read once, never persisted.
 */
let pending: Outcome | null = null;

export function leaveListNotice(outcome: Outcome): void {
  pending = outcome;
}

export function takeListNotice(): Outcome | null {
  const outcome = pending;
  pending = null;
  return outcome;
}
