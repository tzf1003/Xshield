/** Safe, operator-facing descriptions of control API failures. Nothing server-written is echoed. */
import { ApiError, type ErrorCode, messages } from "../api-contract.ts";

export type ErrorView = Readonly<{
  message: string;
  code: string;
  status: number;
  requestId: string | null;
  /** What the operator can do about it, when the code says so. */
  hint: string | null;
}>;

const stepUpCodes: readonly string[] = [
  "CONTROL_STEP_UP_REQUIRED",
  "CONTROL_EXPORT_STEP_UP_REQUIRED",
];
const selfApprovalCodes: readonly string[] = [
  "CONTROL_EVIDENCE_ACCESS_SELF_APPROVAL_DENIED",
  "CONTROL_EXPORT_SELF_APPROVAL",
];

/**
 * The server refused because no recent MFA step-up backs the session. It does so before it
 * touches any state, so the very same request may be sent again once the step-up is done.
 */
export function isStepUpRequired(error: unknown): boolean {
  return error instanceof ApiError && error.status === 403 && stepUpCodes.includes(error.code);
}

/** The same test on a stable code, for a failure remembered by the pending-operation registry. */
export function isStepUpCode(code: string): boolean {
  return stepUpCodes.includes(code);
}

export function isSelfApproval(code: string): boolean {
  return selfApprovalCodes.includes(code);
}

function hintFor(code: string, status: number): string | null {
  if (selfApprovalCodes.includes(code)) {
    return "职责分离：申请人不能批准或拒绝自己提交的申请，请由另一位具备审批权限的主体处理。";
  }
  if (stepUpCodes.includes(code)) {
    return "此操作需要最近 2 分钟内的 MFA 再认证；机器凭证无法完成再认证。";
  }
  if (code === "CONTROL_SCOPE_DENIED" && status === 403) {
    return "当前角色或作用域没有此操作的权限。导航隐藏只是提示，服务端才是最终判断。";
  }
  if (code === "CONTROL_IDEMPOTENCY_CONFLICT") {
    return "同一幂等键只能对应同一份请求；请核对原请求，不要更换参数。";
  }
  return null;
}

/** Describes a stable error code, for example one kept by the pending-operation registry. */
export function describeCode(code: string, status = 0, requestId: string | null = null): ErrorView {
  const known = Object.hasOwn(messages, code) ? messages[code as ErrorCode] : null;
  return {
    message: known ?? "请求未完成，请核对结果后重试。",
    code,
    status,
    requestId,
    hint: hintFor(code, status),
  };
}

/** An already described failure (for example one rebuilt from the pending-operation registry). */
export function isErrorView(value: unknown): value is ErrorView {
  if (typeof value !== "object" || value === null) return false;
  const row = value as Record<string, unknown>;
  return (
    typeof row.code === "string" &&
    typeof row.message === "string" &&
    typeof row.status === "number" &&
    "hint" in row
  );
}

export function errorView(error: unknown): ErrorView {
  if (isErrorView(error)) return error;
  if (error instanceof ApiError) return describeCode(error.code, error.status, error.requestId);
  return describeCode("CONSOLE_REQUEST_FAILED");
}
