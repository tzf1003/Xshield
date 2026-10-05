import { ReloadOutlined, SafetyCertificateOutlined } from "@ant-design/icons";
import { Alert, Button, Descriptions, Tag } from "antd";
import { useEffect, useState } from "react";
import { ApiError } from "../../api-contract.ts";
import { roleView } from "../../operations/roles.ts";
import { useSession } from "../../security/SessionProvider";
import { refreshSessionInfo } from "../../security/session-queries.ts";
import { PageActions } from "../../shell/page-actions";
import { formatRemaining, stepUpStatus } from "../../shell/step-up.ts";
import { TimeStamp } from "../../ui/TimeStamp";
import { RouteLink } from "../../work/nav";
import { TonePill } from "../../work/Parts";
import "../../work/work.css";
import "../../operations/operations.css";
import "./session.css";

/** Step-up validity with a live countdown; advisory, every high-risk call is re-checked. */
function StepUp({
  stepUpValid,
  lastReauthenticatedAt,
}: {
  stepUpValid: boolean;
  lastReauthenticatedAt: string | null;
}) {
  const [now, setNow] = useState(() => Date.now());
  const status = stepUpStatus(
    { step_up_valid: stepUpValid, last_reauthenticated_at: lastReauthenticatedAt },
    now,
  );
  const counting = status.valid && status.remainingMs !== null;
  useEffect(() => {
    if (!counting) return;
    // A local countdown only: nothing is read from the server while it runs.
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [counting]);
  if (!status.valid) {
    return (
      <span className="xs-session-stepup">
        <TonePill tone="warning" label="未生效" />
        <small className="xs-w-muted">
          原文下载、导出审批与下载、站点批准与删除需要两分钟内的 MFA
          再认证；可在顶栏或用户菜单“重新验证高危操作”。
        </small>
      </span>
    );
  }
  return (
    <span className="xs-session-stepup">
      <TonePill
        tone="success"
        label={
          status.remainingMs === null
            ? "有效"
            : `有效 · 剩余 ${formatRemaining(status.remainingMs)}`
        }
      />
      <small className="xs-w-muted">
        按本机时钟倒计时，仅作提示；服务端在每个高危请求上重新校验。
      </small>
    </span>
  );
}

/**
 * 权限中心 (`/access/session`): who is signed in, for which scope, until when, with which roles,
 * and what each role lets this person do. It shows no secret (the CSRF token stays in memory and
 * is never rendered). "刷新会话信息" re-reads the server session through the guarded layer.
 */
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
      <section className="xs-w-card" aria-labelledby="session-title">
        <h2 id="session-title" className="xs-op-title">
          当前管理会话
        </h2>
        <Alert
          type="info"
          showIcon
          title="机器凭证测试模式"
          description="这是本地测试用的机器凭证连接：没有浏览器会话，服务端不返回角色，所以导航显示全部页面，服务端仍逐次授权；没有 MFA 再认证路径，也不能管理 API Key 或读取原文。"
        />
        <Descriptions
          column={1}
          size="small"
          bordered
          items={[
            {
              key: "scope",
              label: "范围",
              children: state.scope ? (
                <span className="mono">
                  {state.scope.tenant_id} / {state.scope.site_id}
                </span>
              ) : (
                "等待第一次响应确认"
              ),
            },
          ]}
        />
      </section>
    );
  }

  const roles = session.roles.map((role) => roleView(role, session.site_id));
  return (
    <div className="xs-w-stack">
      <PageActions>
        <Button
          icon={<ReloadOutlined aria-hidden="true" />}
          loading={busy}
          onClick={() => void refresh()}
        >
          刷新会话信息
        </Button>
      </PageActions>
      {failure && <Alert type="error" showIcon title={failure} />}
      <section className="xs-w-card" aria-labelledby="session-title">
        <h2 id="session-title" className="xs-op-title">
          当前管理会话
        </h2>
        <Descriptions
          column={{ xs: 1, sm: 1, md: 2 }}
          size="small"
          bordered
          items={[
            {
              key: "subject",
              label: "主体",
              children: <span className="mono">{session.subject}</span>,
            },
            {
              key: "kind",
              label: "会话类型",
              children: "浏览器 OIDC 会话（HttpOnly Cookie，写请求带 CSRF）",
            },
            {
              key: "tenant",
              label: "租户",
              children: <span className="mono">{session.tenant_id}</span>,
            },
            {
              key: "site",
              label: "站点范围",
              children: <span className="mono">{session.site_id}</span>,
            },
            {
              key: "absolute",
              label: "绝对到期",
              children: <TimeStamp value={session.session_expires_at} />,
            },
            {
              key: "idle",
              label: "闲置到期",
              children: (
                <span className="xs-session-stepup">
                  <TimeStamp value={session.idle_expires_at} />
                  <small className="xs-w-muted">
                    上次读取会话时的值；15 分钟无操作会断开，控制台也会在本地同样计时。
                  </small>
                </span>
              ),
            },
            {
              key: "reauth",
              label: "最近再认证",
              children: session.last_reauthenticated_at ? (
                <TimeStamp value={session.last_reauthenticated_at} />
              ) : (
                "尚未再认证"
              ),
            },
            {
              key: "stepup",
              label: (
                <span>
                  <SafetyCertificateOutlined aria-hidden="true" /> MFA 再认证
                </span>
              ),
              children: (
                <StepUp
                  stepUpValid={session.step_up_valid}
                  lastReauthenticatedAt={session.last_reauthenticated_at}
                />
              ),
            },
            {
              key: "roles",
              label: "角色（服务端原样）",
              span: "filled",
              children: <span className="mono">{session.roles.join("、") || "无"}</span>,
            },
          ]}
        />
      </section>
      <section className="xs-w-card" aria-labelledby="roles-title">
        <h2 id="roles-title" className="xs-op-title">
          角色与可用页面
        </h2>
        <p className="xs-w-muted">
          角色只来自部署侧为该主体配置的清单。侧栏只显示角色可用的页面，这只是便利：服务端对每个请求独立授权。
        </p>
        {roles.length === 0 ? (
          <Alert
            type="info"
            showIcon
            title="服务端没有为当前主体分配角色"
            description="只能查看概览和本页；需要其他功能时请管理员在部署配置中为该主体分配角色。"
          />
        ) : (
          <ul className="xs-session-roles" aria-label="角色">
            {roles.map((view) => (
              <li key={view.role}>
                <div className="xs-session-role-head">
                  <Tag className="xs-session-role">{view.name}</Tag>
                  <code className="mono xs-w-muted">{view.role}</code>
                </div>
                <p>{view.summary}</p>
                {view.pages.length > 0 && (
                  <p className="xs-session-pages">
                    <span className="xs-w-muted">可用页面：</span>
                    {view.pages.map((page) => (
                      <RouteLink key={page.href} to={page.href}>
                        {page.label}
                      </RouteLink>
                    ))}
                  </p>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
