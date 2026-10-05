import { LoadingOutlined, ReloadOutlined } from "@ant-design/icons";
import { useSyncExternalStore } from "react";
import { useSession } from "../security/SessionProvider";
import { badgeStore, refreshBadge } from "../work/approval-badge.ts";
import { badgeLabel } from "../work/inbox.ts";
import { hasRole, role } from "../work/roles.ts";

/**
 * The count beside "审批中心": how many pending items the last read of the approval center (or
 * this button) found. Nothing polls. Pressing it reads the first page of each source again,
 * which the server audits like any other read; until something has been read there is no number,
 * only the refresh affordance. Operators without an approval role have nothing to count.
 */
export function ApprovalNavBadge() {
  const { runtime, state } = useSession();
  const store = badgeStore(runtime);
  const snapshot = useSyncExternalStore(store.subscribe, store.getSnapshot);
  const roles = state.roles;
  if (!hasRole(roles, role.approver) && !hasRole(roles, role.policyApprover)) return null;
  const { known, busy, value } = snapshot;
  const label = known ? badgeLabel(value) : "";
  const name = busy
    ? "正在读取审批待办数量"
    : known
      ? `审批待办 ${label} 项${value.partial ? "（有来源读取失败）" : ""}，点击重新读取`
      : "读取审批待办数量";
  return (
    <button
      type="button"
      className={`xs-nav-badge${known && value.count > 0 ? " is-pending" : ""}`}
      aria-label={name}
      title={name}
      disabled={busy}
      onClick={(event) => {
        // The button sits inside a menu entry: pressing it must not also navigate.
        event.preventDefault();
        event.stopPropagation();
        void refreshBadge(runtime, roles);
      }}
    >
      {busy ? (
        <LoadingOutlined aria-hidden="true" />
      ) : known ? (
        label
      ) : (
        <ReloadOutlined aria-hidden="true" />
      )}
    </button>
  );
}
