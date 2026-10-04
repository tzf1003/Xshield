import { Alert, Button, Popconfirm } from "antd";
import { useState } from "react";
import { refreshSessionInfo } from "../../../security/session-queries.ts";
import { useSession } from "../../../security/SessionProvider";
import { stepUpStatus } from "../../../shell/step-up.ts";
import { operationKind, writeKindLabel } from "../../../sites/state/write-kinds.ts";
import { ProblemAlert } from "../../../ui/ProblemAlert";
import type { WorkspaceApi } from "./use-workspace.ts";

/**
 * Writes whose outcome is not established. The frozen request is shown exactly as it will be
 * sent again: the only way forward is the identical retry (same method, path, body and
 * idempotency key); the operator may instead give the write up explicitly.
 */
export function PendingBanner({ ws }: { ws: WorkspaceApi }) {
  const { runtime, reauthenticate } = useSession();
  const [stepUpNote, setStepUpNote] = useState<string | null>(null);

  async function recheckStepUp(operation: (typeof ws.own)[number]) {
    setStepUpNote(null);
    const session = await refreshSessionInfo(runtime);
    if (session && stepUpStatus(session, Date.now()).valid) {
      await ws.retry(operation);
      return;
    }
    setStepUpNote("尚未检测到有效的 MFA 再认证，请先完成再认证。");
  }

  if (ws.own.length === 0) return null;
  return (
    <div className="xs-pending-banners">
      {ws.own.map((operation) => {
        const kind = operationKind(operation);
        const name = kind ? writeKindLabel[kind] : operation.label;
        if (operation.phase === "inflight") {
          return (
            <p key={operation.id} className="xs-inflight">
              {name}正在提交，请稍候…
            </p>
          );
        }
        const frozen = (
          <small className="mono">
            {operation.method} {operation.path} · 幂等键 {operation.idempotencyKey} · 已尝试{" "}
            {operation.attempts} 次
          </small>
        );
        if (operation.phase === "step_up") {
          return (
            <Alert
              key={operation.id}
              type="warning"
              showIcon
              role="alert"
              title={`${name}需要先完成 MFA 再认证（请求没有执行）。`}
              description={
                <div className="xs-problem">
                  <span>完成再认证后，将用原请求（同一幂等键、同一内容）重试。</span>
                  {frozen}
                  {stepUpNote && <span>{stepUpNote}</span>}
                  <span className="xs-pending-actions">
                    <Button
                      type="primary"
                      disabled={ws.running}
                      onClick={() => void reauthenticate()}
                    >
                      重新验证高危操作
                    </Button>
                    <Button disabled={ws.running} onClick={() => void recheckStepUp(operation)}>
                      已完成再认证，检查并重试
                    </Button>
                    <Button disabled={ws.running} onClick={() => ws.abandon(operation)}>
                      放弃该操作
                    </Button>
                  </span>
                </div>
              }
            />
          );
        }
        return (
          <Alert
            key={operation.id}
            type="warning"
            showIcon
            role="alert"
            title={`${name}的结果待确认。重试将使用原有参数和幂等键。`}
            description={
              <div className="xs-problem">
                {frozen}
                {operation.lastError && (
                  <small className="mono">
                    {operation.lastError.code}
                    {operation.lastError.status ? ` · HTTP ${operation.lastError.status}` : ""}
                    {operation.lastError.requestId ? ` · ${operation.lastError.requestId}` : ""}
                  </small>
                )}
                <span className="xs-pending-actions">
                  <Button
                    type="primary"
                    disabled={ws.running}
                    onClick={() => void ws.retry(operation)}
                  >
                    确认后原样重试
                  </Button>
                  <Popconfirm
                    title="放弃这次写入？"
                    description="放弃后将无法再用原幂等键重试。请先重新读取站点，确认写入是否已经生效。"
                    okText="放弃并重新读取"
                    cancelText="继续等待"
                    okButtonProps={{ danger: true }}
                    onConfirm={() => ws.abandon(operation)}
                  >
                    <Button disabled={ws.running}>放弃并重新读取</Button>
                  </Popconfirm>
                </span>
              </div>
            }
          />
        );
      })}
    </div>
  );
}

/** The result of the last write: a confirmed outcome, or the refusal with its diagnostics. */
export function NoticeBanner({ ws }: { ws: WorkspaceApi }) {
  const { notice } = ws;
  if (!notice) return null;
  if (notice.kind === "problem") {
    return (
      <div className="xs-notice">
        <ProblemAlert problem={notice.problem} title={notice.title} />
      </div>
    );
  }
  return (
    <div className="xs-notice">
      <Alert
        type={notice.tone}
        showIcon
        role="status"
        title={notice.title}
        description={notice.detail ?? undefined}
        closable={{ onClose: () => ws.setNotice(null), "aria-label": "关闭提示" }}
      />
    </div>
  );
}
