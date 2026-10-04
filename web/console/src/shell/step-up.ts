import type { BrowserSession } from "../api.ts";

/** The server honours a browser MFA step-up for two minutes (see the evidence/export workflows). */
export const STEP_UP_WINDOW_MS = 120_000;

export type StepUpStatus = Readonly<{
  valid: boolean;
  /** Milliseconds until it lapses; `null` when the server said "valid" without a usable timestamp. */
  remainingMs: number | null;
}>;

/**
 * Advisory status derived from the session facts the server returned. The server remains the
 * authority on every high-risk call; this only tells the operator when to re-verify.
 */
export function stepUpStatus(
  session: Pick<BrowserSession, "step_up_valid" | "last_reauthenticated_at">,
  nowMs: number,
): StepUpStatus {
  if (!session.step_up_valid) return { valid: false, remainingMs: 0 };
  const reauthenticatedAt = session.last_reauthenticated_at
    ? Date.parse(session.last_reauthenticated_at)
    : Number.NaN;
  if (Number.isNaN(reauthenticatedAt)) return { valid: true, remainingMs: null };
  const remaining = reauthenticatedAt + STEP_UP_WINDOW_MS - nowMs;
  if (remaining <= 0) return { valid: false, remainingMs: 0 };
  return { valid: true, remainingMs: Math.min(remaining, STEP_UP_WINDOW_MS) };
}

/** `m:ss`, rounded up so the chip never reads 0:00 while still valid. */
export function formatRemaining(remainingMs: number): string {
  const seconds = Math.max(0, Math.ceil(remainingMs / 1000));
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;
}
