import { SafetyCertificateOutlined } from "@ant-design/icons";
import { Alert, Button } from "antd";
import { formatRemaining } from "../../../../shell/step-up.ts";
import { busy } from "../../fields";
import type { StepUpAdvice } from "./use-step-up.ts";

/**
 * Whether the MFA re-verification this action needs is on record, and what to do if it is not.
 * Advisory: the action stays available because the server decides, and a refusal keeps the
 * request (nothing was executed) so it can be repeated unchanged after re-verifying.
 * `machine` is what to say to the local machine credential, which has no step-up at all
 * (nothing, when the action does not need one from it).
 */
export function StepUpNotice({
  advice,
  action,
  machine = null,
}: {
  advice: StepUpAdvice;
  action: string;
  machine?: string | null;
}) {
  if (!advice.applicable) {
    return machine ? <p className="xs-stepup-line">{machine}</p> : null;
  }
  if (advice.status.valid) {
    const remaining =
      advice.status.remainingMs === null ? null : formatRemaining(advice.status.remainingMs);
    return (
      <p className="xs-stepup-line">
        <SafetyCertificateOutlined aria-hidden="true" /> MFA 再认证有效
        {remaining ? `，剩余 ${remaining}` : ""}。
      </p>
    );
  }
  return (
    <Alert
      type="warning"
      showIcon
      role="note"
      title={`${action}需要 2 分钟内完成的 MFA 再认证，当前未检测到。`}
      description={
        <div className="xs-problem">
          <span>
            请先重新验证：页面会跳转到身份提供方，返回后重新打开这个操作。如果已经在别的窗口完成，请重新读取会话。
          </span>
          {advice.note && <span>{advice.note}</span>}
          <span className="xs-pending-actions">
            <Button type="primary" onClick={advice.reauthenticate}>
              重新验证高危操作
            </Button>
            <Button loading={busy(advice.checking)} onClick={() => void advice.recheck()}>
              已完成再认证，重新读取会话
            </Button>
          </span>
        </div>
      }
    />
  );
}
