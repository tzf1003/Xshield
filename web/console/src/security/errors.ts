import { ApiError } from "../api-contract.ts";

/**
 * Raised when a response belongs to a session that no longer exists: the epoch moved on, the
 * server session ended (401) or the scope check failed. Callers must treat it as "drop silently";
 * the session layer has already disconnected and cleared every cache.
 */
export class StaleSessionError extends Error {
  readonly reason: "epoch" | "scope" | "unauthorized" | "disconnected";
  constructor(reason: StaleSessionError["reason"]) {
    super(`session response dropped: ${reason}`);
    this.name = "StaleSessionError";
    this.reason = reason;
  }
}

export function isStaleSessionError(error: unknown): error is StaleSessionError {
  return error instanceof StaleSessionError;
}

/**
 * Refusals that mean "a fresh MFA step-up is missing". The server checks this before it does
 * anything, so the request did not run and the session is still good. Approving a site answers
 * it with 401 (the other flows use 403), which must not be mistaken for a dead session.
 */
const stepUpCodes: readonly string[] = [
  "CONTROL_STEP_UP_REQUIRED",
  "CONTROL_SITE_DELETE_STEP_UP_REQUIRED",
  "CONTROL_EXPORT_STEP_UP_REQUIRED",
];

export function isStepUpRequired(error: unknown): boolean {
  return (
    error instanceof ApiError &&
    (error.status === 401 || error.status === 403) &&
    stepUpCodes.includes(error.code)
  );
}

/** A 401 ends the session, except the step-up refusal above (the session is fine, MFA lapsed). */
export function isUnauthorized(error: unknown): boolean {
  return error instanceof ApiError && error.status === 401 && !isStepUpRequired(error);
}

/** Deterministic server refusals. Anything else leaves a write's outcome unknown. */
export const knownRejectionStatuses: readonly number[] = [400, 403, 404, 409, 422, 429];

export function isKnownRejection(error: unknown): boolean {
  return (
    error instanceof ApiError &&
    error.code.startsWith("CONTROL_") &&
    knownRejectionStatuses.includes(error.status)
  );
}

/** Diagnostics that are safe to show next to a pending operation (no body, no credentials). */
export type SafeError = Readonly<{ code: string; status: number; requestId: string | null }>;

export function safeError(error: unknown): SafeError {
  if (error instanceof ApiError) {
    return { code: error.code, status: error.status, requestId: error.requestId };
  }
  return { code: "CONSOLE_REQUEST_FAILED", status: 0, requestId: null };
}
