import { InboxOutlined, ReloadOutlined, SearchOutlined } from "@ant-design/icons";
import { Alert, Button, Skeleton } from "antd";
import type { ReactNode } from "react";
import { ObjectId } from "./ObjectId";
import { projectError } from "./error-projection.ts";
import "./kit.css";

type EmptyProps = {
  title: string;
  /** What this does and does not prove. */
  children?: ReactNode;
  /** `search`: a lookup that found nothing; `inbox`: a list with no rows. */
  icon?: "search" | "inbox";
  action?: ReactNode;
};

/** A calm "nothing here" with the reason it is not an error. */
export function EmptyState({ title, children, icon = "inbox", action }: EmptyProps) {
  return (
    <div className="xs-state" role="status">
      {icon === "search" ? (
        <SearchOutlined className="xs-state-icon" aria-hidden="true" />
      ) : (
        <InboxOutlined className="xs-state-icon" aria-hidden="true" />
      )}
      <h3>{title}</h3>
      {children ? <p>{children}</p> : null}
      {action}
    </div>
  );
}

type ErrorProps = {
  error: unknown;
  onRetry?: () => void;
  retryLabel?: string;
  retrying?: boolean;
  /** Replaces the fixed message headline when the page can say what it was doing. */
  title?: string;
};

/**
 * A failed read, shown through the safe projection only: the fixed local message, the stable
 * error code and the management request ID. Retrying is always the operator's choice.
 * Renders nothing for a cancelled request or an ended session.
 */
export function ErrorState({
  error,
  onRetry,
  retryLabel = "重新读取",
  retrying,
  title,
}: ErrorProps) {
  const problem = projectError(error);
  if (!problem) return null;
  return (
    <Alert
      type="error"
      showIcon
      role="alert"
      title={title ?? problem.message}
      description={
        <div className="xs-fault">
          {title ? <span>{problem.message}</span> : null}
          <div className="xs-fault-meta">
            <span>
              错误码 <code className="mono">{problem.code}</code>
            </span>
            {problem.requestId ? (
              <span>
                管理请求 ID <ObjectId value={problem.requestId} quietCopy />
              </span>
            ) : null}
          </div>
        </div>
      }
      action={
        onRetry ? (
          <Button
            size="small"
            icon={<ReloadOutlined aria-hidden="true" />}
            disabled={retrying}
            onClick={onRetry}
          >
            {retryLabel}
          </Button>
        ) : undefined
      }
    />
  );
}

/** Placeholder rows while a read is in flight. */
export function LoadingState({ label = "正在读取…" }: { label?: string }) {
  return (
    <div className="xs-state" role="status" aria-busy="true" aria-label={label}>
      <Skeleton active paragraph={{ rows: 3 }} title={false} />
    </div>
  );
}
