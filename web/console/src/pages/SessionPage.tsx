import { ReloadOutlined } from "@ant-design/icons";
import { Button } from "antd";
import { useState } from "react";
import { ApiError } from "../api-contract.ts";
import { useSession } from "../security/SessionProvider";
import { refreshSessionInfo } from "../security/session-queries.ts";
import { PageActions } from "../shell/page-actions";

/** 权限中心: the signed-in subject, the roles the server granted and the step-up state. */
export function SessionPage() {
  const { state, runtime } = useSession();
  const session = state.session;
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);

  async function refresh() {
    setBusy(true);
    setFailure(null);
    try {
      await refreshSessionInfo(runtime);
    } catch (error) {
      setFailure(error instanceof ApiError ? error.message : "会话信息读取未完成，请稍后重试。");
    } finally {
      setBusy(false);
    }
  }

  if (!session) {
    return (
      <section className="panel empty-state legacy">
        <h2>当前权限中心</h2>
        <p className="muted">此页面只读展示当前会话和服务端角色。</p>
      </section>
    );
  }
  return (
    <>
      <PageActions>
        <Button icon={<ReloadOutlined />} loading={busy} onClick={() => void refresh()}>
          刷新会话信息
        </Button>
      </PageActions>
      {failure && (
        <div className="notice danger legacy" aria-live="polite">
          {failure}
        </div>
      )}
      <section className="panel session-panel legacy" aria-labelledby="session-title">
        <h2 id="session-title">当前管理会话</h2>
        <dl className="session-grid">
          <div>
            <dt>主体</dt>
            <dd className="mono">{session.subject}</dd>
          </div>
          <div>
            <dt>租户</dt>
            <dd className="mono">{session.tenant_id}</dd>
          </div>
          <div>
            <dt>站点范围</dt>
            <dd className="mono">{session.site_id}</dd>
          </div>
          <div>
            <dt>角色</dt>
            <dd>{session.roles.join("、") || "无"}</dd>
          </div>
          <div>
            <dt>绝对到期</dt>
            <dd>{session.session_expires_at}</dd>
          </div>
          <div>
            <dt>闲置到期</dt>
            <dd>{session.idle_expires_at}</dd>
          </div>
          <div>
            <dt>最近再认证</dt>
            <dd>{session.last_reauthenticated_at ?? "尚未再认证"}</dd>
          </div>
          <div>
            <dt>Step-up</dt>
            <dd>{session.step_up_valid ? "有效" : "未生效"}</dd>
          </div>
        </dl>
      </section>
    </>
  );
}
