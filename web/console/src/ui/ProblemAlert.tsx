import { Alert } from "antd";
import type { ReactNode } from "react";
import type { SafeError } from "../security/errors.ts";
import { reasonText } from "./reason-codes.ts";

type Props = {
  problem: SafeError;
  /** Replaces the dictionary text as the headline (the text is still shown below it). */
  title?: string;
  /** A retry or navigation action offered next to the message. */
  action?: ReactNode;
};

/**
 * One way to show a failure: what happened, what to do, and the stable code, HTTP status and
 * management request ID that support needs. Nothing from the response body is rendered.
 */
export function ProblemAlert({ problem, title, action }: Props) {
  const reason = reasonText(problem.code);
  const type = reason.tone === "warning" ? "warning" : reason.tone === "info" ? "info" : "error";
  return (
    <Alert
      type={type}
      showIcon
      role="alert"
      title={title ?? reason.text}
      action={action}
      description={
        <div className="xs-problem">
          {title && <span>{reason.text}</span>}
          <span>建议：{reason.action}</span>
          <small className="mono">
            {problem.code}
            {problem.status ? ` · HTTP ${problem.status}` : ""}
            {problem.requestId ? ` · ${problem.requestId}` : ""}
          </small>
        </div>
      }
    />
  );
}
