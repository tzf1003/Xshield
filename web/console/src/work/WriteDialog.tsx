import { Alert, Button, Modal, Space } from "antd";
import type { ReactNode } from "react";
import type { OperationSnapshot } from "../security/pending-operations.ts";
import type { ScopedResponse } from "../security/scope.ts";
import { viewOperation } from "./operations.ts";
import { ErrorNotice } from "./Parts";
import type { Write } from "./use-write.ts";

async function copyText(value: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    // The request is shown on screen; copying is only a convenience.
  }
}

/**
 * The frozen request of an unresolved write, exactly as it will be sent again: method and path,
 * the framework-generated idempotency key and the original body. The only way forward is an exact
 * retry; a later refusal never proves that an earlier unknown attempt did not commit.
 */
export function FrozenOperation({
  operation,
  busy,
  onRetry,
}: {
  operation: OperationSnapshot;
  busy: boolean;
  onRetry: () => void;
}) {
  const view = viewOperation(operation);
  const waiting = view.phase === "inflight";
  return (
    <div className="xs-w-stack xs-w-frozen">
      <Alert
        type={waiting ? "info" : "warning"}
        showIcon
        title={view.phaseLabel}
        description={
          waiting
            ? "请求已发出，正在等待服务端回复。"
            : view.phase === "step-up"
              ? "此请求被要求先完成 MFA 再认证，尚未成功发送。完成验证后原请求会被原样重发。"
              : "服务端可能已经提交。只能用相同的路径、幂等键和正文原样重试来确认结果；其后的拒绝不能证明先前的尝试没有提交。刷新页面、闲置或退出会清除这些信息。"
        }
      />
      {view.error && <ErrorNotice error={view.error} />}
      <dl className="xs-w-facts">
        <div>
          <dt>冻结的请求</dt>
          <dd className="mono">{view.request}</dd>
        </div>
        <div>
          <dt>幂等键</dt>
          <dd className="mono">{view.key}</dd>
        </div>
        <div>
          <dt>已尝试</dt>
          <dd>{view.attempts} 次</dd>
        </div>
      </dl>
      {view.body && (
        <>
          <div className="xs-w-muted">冻结的请求正文</div>
          <pre className="xs-w-pre mono">{view.body}</pre>
        </>
      )}
      <Space wrap>
        <Button type="primary" loading={busy} disabled={waiting} onClick={onRetry}>
          原样重试
        </Button>
        <Button
          onClick={() =>
            void copyText(
              JSON.stringify({
                method: operation.method,
                path: operation.path,
                idempotency_key: operation.idempotencyKey,
                body: operation.body === null ? null : JSON.parse(operation.body),
              }),
            )
          }
        >
          复制冻结请求
        </Button>
      </Space>
    </div>
  );
}

type Props<TVars, T extends ScopedResponse> = {
  title: string;
  open: boolean;
  onClose: () => void;
  write: Write<TVars, T>;
  /** Called by the primary button of the idle form. */
  onSubmit: () => void;
  /** Called by "原样重试" of the recovery view. */
  onRetry: () => void;
  submitText: string;
  danger?: boolean;
  /** The reason the form cannot be submitted yet, or `null`. Shown as the button's tooltip. */
  blocked: string | null;
  /** The idle form. */
  children: ReactNode;
  width?: number;
};

/**
 * A form that writes. While nothing is unresolved it shows the form (a refusal appears above it
 * and the form stays editable: nothing was written). Once a request is in flight or its outcome
 * is unknown it shows the frozen request instead, so the operator can neither change it nor send
 * a different one under the same intent.
 */
export function WriteDialog<TVars, T extends ScopedResponse>({
  title,
  open,
  onClose,
  write,
  onSubmit,
  onRetry,
  submitText,
  danger = false,
  blocked,
  children,
  width = 560,
}: Props<TVars, T>) {
  const operation = write.operation;
  return (
    <Modal
      open={open}
      title={title}
      onCancel={onClose}
      width={width}
      destroyOnHidden
      mask={{ closable: false }}
      footer={
        operation ? (
          <Button onClick={onClose}>稍后处理</Button>
        ) : (
          <Space>
            <Button onClick={onClose}>取消</Button>
            <Button
              type="primary"
              danger={danger}
              loading={write.busy}
              disabled={blocked !== null}
              title={blocked ?? undefined}
              onClick={onSubmit}
            >
              {submitText}
            </Button>
          </Space>
        )
      }
    >
      {operation ? (
        <FrozenOperation operation={operation} busy={write.busy} onRetry={onRetry} />
      ) : (
        <div className="xs-w-stack">
          {write.rejection !== null && <ErrorNotice error={write.rejection} />}
          {children}
        </div>
      )}
    </Modal>
  );
}

/** A banner for pages whose unresolved write is not currently open in a dialog. */
export function PendingNotice({
  operation,
  label,
  onOpen,
}: {
  operation: OperationSnapshot | null;
  label: string;
  onOpen: () => void;
}) {
  if (!operation) return null;
  const view = viewOperation(operation);
  return (
    <Alert
      type="warning"
      showIcon
      title={`${label}：${view.phaseLabel}`}
      description="该写入已冻结在内存中，只能原样重试；离开本页不会丢失，刷新页面则会丢失。"
      action={
        <Button size="small" onClick={onOpen}>
          查看并处理
        </Button>
      }
    />
  );
}
