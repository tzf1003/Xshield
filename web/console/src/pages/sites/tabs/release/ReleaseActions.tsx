import { Button } from "antd";
import { useId, useState } from "react";
import type { Gate } from "../../../../sites/model/release.ts";
import type { WorkspaceApi } from "../../workspace/use-workspace.ts";
import { ApplyModal, ApproveModal, RollbackModal } from "./ReleaseModals";
import type { Release } from "./use-release.ts";

type Dialog = "approve" | "apply" | "rollback";

function ActionRow({
  gate,
  disabled,
  type,
  onClick,
  children,
}: {
  gate: Gate;
  disabled: boolean;
  type?: "primary";
  onClick: () => void;
  children: string;
}) {
  const hintId = useId();
  return (
    <li className="xs-action-row">
      <Button
        type={type}
        disabled={disabled || !gate.enabled}
        aria-describedby={hintId}
        onClick={onClick}
      >
        {children}
      </Button>
      <span id={hintId} className="muted xs-action-hint">
        {gate.hint}
      </span>
    </li>
  );
}

/**
 * The release actions the roles allow. Validation changes nothing and runs at once; approving,
 * applying and rolling back each open a dialog first that shows what changes and what happens
 * next. Every one is a frozen write (`ws.run`): the dialogs only decide whether to submit.
 */
export function ReleaseActions({ ws, release }: { ws: WorkspaceApi; release: Release }) {
  const { access } = ws;
  // Locked while a write is unresolved, and while the facts these actions rest on are still loading.
  const locked = ws.locked || release.loading;
  const [dialog, setDialog] = useState<Dialog | null>(null);
  if (!access.canRelease) return null;
  const close = () => setDialog(null);
  const { gates } = release;
  return (
    <section className="xs-card" aria-label="发布操作">
      <h3>发布操作</h3>
      {ws.dirty && (
        <p className="xs-release-dirty">
          你有 {ws.changes.length} 项未保存的修改，它们不会随发布操作生效：这些操作针对已保存的{" "}
          {ws.view.desired_revision === null ? "修订" : `r${ws.view.desired_revision}`}
          。保存会生成新修订。
        </p>
      )}
      <ul className="xs-actions">
        {access.canValidate && (
          <ActionRow
            gate={gates.validate}
            disabled={locked}
            onClick={() => void ws.run("validate", () => ws.writes.validate.submit({}))}
          >
            验证配置
          </ActionRow>
        )}
        {access.canApprove && (
          <ActionRow
            type="primary"
            gate={gates.approve}
            disabled={locked}
            onClick={() => setDialog("approve")}
          >
            批准并应用
          </ActionRow>
        )}
        {access.canApply && (
          <ActionRow
            type="primary"
            gate={gates.apply}
            disabled={locked}
            onClick={() => setDialog("apply")}
          >
            应用期望版本
          </ActionRow>
        )}
        {access.canApply && (
          <ActionRow gate={gates.rollback} disabled={locked} onClick={() => setDialog("rollback")}>
            回滚上一版本
          </ActionRow>
        )}
      </ul>
      <ApproveModal ws={ws} release={release} open={dialog === "approve"} onClose={close} />
      <ApplyModal ws={ws} release={release} open={dialog === "apply"} onClose={close} />
      <RollbackModal ws={ws} release={release} open={dialog === "rollback"} onClose={close} />
    </section>
  );
}
