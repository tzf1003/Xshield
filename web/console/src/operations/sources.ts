/**
 * One read of the workbench as the page sees it: not read for this role, loading, answered,
 * refused because of the role (a hint, not an error) or failed. Each source is shown on its own,
 * so one failure never hides what the other sources answered.
 */
import { ApiError } from "../api-contract.ts";
import { isStaleSessionError } from "../security/errors.ts";

export type SourceState<T> =
  /** This operator's roles do not read the source at all. */
  | Readonly<{ status: "skipped" }>
  | Readonly<{ status: "loading" }>
  /** `receivedAt` is the browser time the reply arrived, for sources without a server time. */
  | Readonly<{ status: "ok"; data: T; receivedAt: number }>
  /** 403: the server refused this identity; the page shows a role hint, not an error. */
  | Readonly<{ status: "denied"; error: unknown }>
  | Readonly<{ status: "failed"; error: unknown }>;

/** The parts of a TanStack query result this needs; kept structural so it is unit-testable. */
export type QueryLike<T> = Readonly<{
  data: T | undefined;
  error: unknown;
  isSuccess: boolean;
  isError: boolean;
  dataUpdatedAt: number;
}>;

export function isRoleRefusal(error: unknown): boolean {
  return error instanceof ApiError && error.status === 403;
}

export function sourceOf<T>(query: QueryLike<T>, enabled: boolean): SourceState<T> {
  if (!enabled) return { status: "skipped" };
  if (query.isSuccess && query.data !== undefined) {
    return { status: "ok", data: query.data, receivedAt: query.dataUpdatedAt };
  }
  // A session that ended drops its replies; the login screen replaces the page anyway.
  if (query.isError && !isStaleSessionError(query.error)) {
    return isRoleRefusal(query.error)
      ? { status: "denied", error: query.error }
      : { status: "failed", error: query.error };
  }
  return { status: "loading" };
}
