import { SafetyCertificateOutlined } from "@ant-design/icons";
import { Button, Input } from "antd";
import { type FormEvent, useState } from "react";
import { useSession } from "../security/SessionProvider";
import { ThemeMenu } from "../theme/ThemeMenu";

/**
 * Full-page sign-in, shown at whatever URL the operator arrived on (nothing is redirected, so
 * the deep link is still there after sign-in). Browser sessions use the enterprise OIDC flow;
 * the Bearer form exists only in the explicitly enabled local test build.
 */
export function LoginScreen() {
  const { state, authReady, machineLoginEnabled, connectWithToken } = useSession();
  const [token, setToken] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const notice = formError ?? state.notice;

  function connect(event: FormEvent) {
    event.preventDefault();
    if (!connectWithToken(token)) {
      setFormError("请输入有效的管理凭证。");
      return;
    }
    setToken("");
    setFormError(null);
  }

  return (
    <main className="xs-login" id="main-content">
      <div className="xs-login-tools">
        <ThemeMenu />
      </div>
      <div className="xs-login-inner">
        <div className="xs-login-brand">
          <span className="xs-brand-mark" aria-hidden="true">
            X
          </span>
          <div>
            <strong>Xshield</strong>
            <span>管理控制台</span>
          </div>
        </div>
        {notice && (
          <div className="notice" role="status">
            {notice}
          </div>
        )}
        <section className="xs-login-card" aria-labelledby="connect-title">
          <h1 id="connect-title">{machineLoginEnabled ? "连接管理服务" : "企业身份登录"}</h1>
          {machineLoginEnabled ? (
            <>
              <p className="muted">
                自动化测试专用的机器凭证入口。生产控制台仅使用企业 OIDC 身份。
              </p>
              <form onSubmit={connect} className="xs-login-form">
                <label htmlFor="token">管理凭证</label>
                <Input
                  id="token"
                  type="password"
                  value={token}
                  onChange={(event) => {
                    setToken(event.target.value);
                    setFormError(null);
                  }}
                  autoComplete="off"
                  spellCheck={false}
                  maxLength={4096}
                  required
                />
                <Button type="primary" htmlType="submit">
                  连接
                </Button>
              </form>
              <p className="footnote">此入口仅在显式开启的本地 Playwright 测试环境可用。</p>
            </>
          ) : !authReady ? (
            <p className="empty" role="status">
              正在恢复管理会话…
            </p>
          ) : (
            <>
              <p className="muted">
                使用企业身份提供方完成 MFA。访问角色与站点范围由服务端部署映射决定。
              </p>
              <div className="xs-login-actions">
                <Button
                  type="primary"
                  size="large"
                  icon={<SafetyCertificateOutlined />}
                  onClick={() => window.location.assign("/control/v1/auth/oidc/start")}
                >
                  使用企业身份登录
                </Button>
                {notice && (
                  <Button size="large" onClick={() => window.location.reload()}>
                    重试会话检查
                  </Button>
                )}
              </div>
              <p className="footnote">
                浏览器只持有 HttpOnly 服务端会话 Cookie；闲置 15 分钟或达到 8
                小时绝对时限后须重新登录。
              </p>
            </>
          )}
        </section>
      </div>
    </main>
  );
}
