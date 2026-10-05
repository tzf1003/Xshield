import { ApiError } from "../api-contract.ts";
import { isStaleSessionError } from "../security/errors.ts";

/**
 * What the console may show about a failed read: the fixed local message, the stable error code
 * and the management request ID. Server prose, response bodies and transport details never get
 * this far (the API boundary already replaced them with `messages[code]`).
 */
export type SafeProblem = Readonly<{
  message: string;
  code: string;
  status: number | null;
  requestId: string | null;
}>;

export const GENERIC_PROBLEM: SafeProblem = {
  message: "查询未完成，请稍后重试。",
  code: "CONSOLE_REQUEST_FAILED",
  status: null,
  requestId: null,
};

/**
 * `null` means "nothing to show": the session ended (the sign-in screen replaces the page) or
 * the request was cancelled because the operator moved on.
 */
export function projectError(error: unknown): SafeProblem | null {
  if (error === null || error === undefined) return null;
  if (isStaleSessionError(error)) return null;
  if (error instanceof Error && error.name === "CancelledError") return null;
  if (error instanceof ApiError) {
    if (error.code === "REQUEST_ABORTED") return null;
    return {
      message: error.message,
      code: error.code,
      status: error.status === 0 ? null : error.status,
      requestId: error.requestId,
    };
  }
  return GENERIC_PROBLEM;
}
