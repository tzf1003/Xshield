import type { ControlClient } from "../api.ts";
import { ApiError } from "../api-contract.ts";
import { isUnauthorized, StaleSessionError } from "./errors.ts";
import type { PendingOperationStore } from "./pending-operations.ts";
import type { ScopedResponse } from "./scope.ts";
import { type SessionStore, unauthorizedNotice } from "./session-store.ts";

export type ReadCall<T extends ScopedResponse> = {
  fetch: (client: ControlClient, signal: AbortSignal) => Promise<T>;
  /** Multi-site reads answer for this site instead of the session's own site. */
  expectedSiteId?: string;
  /** The epoch the caller was built for. A different current epoch drops the call. */
  epoch?: number;
  /** Per-request cancellation, for example TanStack Query's abort signal. */
  signal?: AbortSignal;
};

/**
 * Runs one read through the session guard:
 *  - never starts for a session that is not the caller's epoch,
 *  - aborts with the session (idle, logout, 401, scope violation),
 *  - discards a reply that arrives after the epoch moved on,
 *  - verifies the reply's tenant/site against the confirmed scope and disconnects on mismatch,
 *  - turns a 401 into a global disconnect (which also clears every cache).
 */
export async function runGuardedRead<T extends ScopedResponse>(
  store: SessionStore,
  call: ReadCall<T>,
): Promise<T> {
  const state = store.getState();
  if (state.status !== "connected" || state.client === null) {
    throw new StaleSessionError("disconnected");
  }
  if (call.epoch !== undefined && call.epoch !== state.epoch) throw new StaleSessionError("epoch");
  const epoch = state.epoch;
  const signal = call.signal ? AbortSignal.any([call.signal, store.signal]) : store.signal;
  let response: T;
  try {
    response = await call.fetch(state.client, signal);
  } catch (error) {
    if (!store.isCurrent(epoch)) throw new StaleSessionError("epoch");
    if (isUnauthorized(error)) {
      store.disconnect(unauthorizedNotice);
      throw new StaleSessionError("unauthorized");
    }
    throw error;
  }
  if (!store.isCurrent(epoch)) throw new StaleSessionError("epoch");
  if (call.signal?.aborted) throw new ApiError("REQUEST_ABORTED");
  const verdict = store.verifyScope(response, call.expectedSiteId);
  if (verdict === "mismatch") throw new StaleSessionError("scope");
  if (verdict === "wrong_site") throw new ApiError("INVALID_RESPONSE", 200);
  return response;
}

export type WriteResult<T> =
  | { kind: "confirmed"; response: T }
  /** A deterministic server refusal of a first attempt; nothing was written. */
  | { kind: "rejected"; error: unknown }
  /** The outcome cannot be established; only an exact retry of the frozen request is allowed. */
  | { kind: "unknown"; error: unknown }
  /**
   * Refused before anything ran because the fresh MFA step-up is missing. The frozen request is
   * kept: once the operator re-verified, the identical request (same key, same body) is retried.
   */
  | { kind: "step_up"; error: unknown }
  /** The session ended while the request was in flight. State was cleared, nothing to show. */
  | { kind: "stale" };

/**
 * Sends (or exactly resends) a frozen operation. Writes are bound to the session lifetime only;
 * navigating between pages must never abort a request that may already have reached the server.
 */
export async function runFrozenWrite<T extends ScopedResponse = ScopedResponse>(
  store: SessionStore,
  pending: PendingOperationStore,
  id: string,
): Promise<WriteResult<T>> {
  const state = store.getState();
  if (state.status !== "connected" || state.client === null) return { kind: "stale" };
  const epoch = state.epoch;
  const attempt = pending.start(id);
  let response: T;
  try {
    response = (await attempt.execute(
      state.client,
      store.signal,
      attempt.snapshot.idempotencyKey,
    )) as T;
  } catch (error) {
    if (!store.isCurrent(epoch)) return { kind: "stale" };
    if (isUnauthorized(error)) {
      store.disconnect(unauthorizedNotice);
      return { kind: "stale" };
    }
    return { kind: pending.fail(id, error), error };
  }
  if (!store.isCurrent(epoch)) return { kind: "stale" };
  const verdict = store.verifyScope(response, attempt.expectedSiteId);
  if (verdict === "mismatch") return { kind: "stale" };
  if (verdict === "wrong_site") {
    // The server answered, but not for the site this write targeted: the write may have landed.
    const error = new ApiError("INVALID_RESPONSE", 200);
    return { kind: pending.fail(id, error), error };
  }
  pending.resolve(id);
  return { kind: "confirmed", response };
}
