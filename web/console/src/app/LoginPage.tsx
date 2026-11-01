// The sign-in page (docs/06 6.4.1): one password, no user name (single administrator). A notice
// explains when the browser will not keep the session because the page is not on HTTPS or localhost.

import { useNavigate, useSearch } from "@tanstack/react-router";
import type { FormEvent } from "react";
import { useState } from "react";
import { ApiError } from "../api/client.ts";
import { useLogin } from "../api/queries.ts";
import { errorText } from "../lib/vocab.ts";

export function LoginPage() {
  const search = useSearch({ from: "/login" });
  const navigate = useNavigate();
  const login = useLogin();
  const [password, setPassword] = useState("");

  const submit = (event: FormEvent) => {
    event.preventDefault();
    login.mutate(password, {
      onSuccess: () => {
        void navigate({ href: search.next ?? "/", replace: true });
      },
    });
  };

  const error = login.error instanceof ApiError ? errorText(login.error.code) : null;

  return (
    <main className="login-page">
      <div className="stack" style={{ width: "min(380px, 100%)" }}>
        {window.isSecureContext ? null : (
          <div className="notice" role="note">
            控制台需要经 HTTPS 或 localhost 访问，否则浏览器不会保存登录状态。可以用 SSH
            隧道把控制台端口转发到本机。
          </div>
        )}
        <form className="login-card" onSubmit={submit}>
          <h1>Xshield 控制台</h1>
          <p className="muted" style={{ margin: "0 0 18px" }}>
            输入管理口令。
          </p>
          <label className="field">
            <span className="field-label">口令</span>
            <input
              className="native-input"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
          </label>
          {error ? (
            <div className="field-error" role="alert">
              {error}
            </div>
          ) : null}
          <div style={{ marginTop: 16 }}>
            <button
              type="submit"
              className="btn-primary fill"
              disabled={password.length === 0 || login.isPending}
            >
              {login.isPending ? "正在登录…" : "登录"}
            </button>
          </div>
        </form>
      </div>
    </main>
  );
}
