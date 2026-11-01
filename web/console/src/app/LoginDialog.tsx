// Shown over the current page when a request comes back 401 (docs/06 6.4.1, 6.7.3): the page, and any
// unsaved draft on it, stay where they are. A successful sign-in refreshes what is on screen.

import { Modal } from "antd";
import type { FormEvent } from "react";
import { useState } from "react";
import { ApiError } from "../api/client.ts";
import { useLogin } from "../api/queries.ts";
import { queryClient } from "../api/query-client.ts";
import { errorText } from "../lib/vocab.ts";

type Props = {
  open: boolean;
  onClose: () => void;
};

export function LoginDialog({ open, onClose }: Props) {
  const login = useLogin();
  const [password, setPassword] = useState("");

  const submit = (event: FormEvent) => {
    event.preventDefault();
    login.mutate(password, {
      onSuccess: () => {
        setPassword("");
        onClose();
        void queryClient.invalidateQueries();
      },
    });
  };

  const error = login.error instanceof ApiError ? errorText(login.error.code) : null;

  return (
    <Modal open={open} title="登录已过期" footer={null} onCancel={onClose}>
      <form className="stack" onSubmit={submit}>
        <p className="muted" style={{ margin: 0 }}>
          请重新输入口令。未保存的配置草稿仍在页面上，登录后可以再次保存。
        </p>
        <label className="field" style={{ margin: 0 }}>
          <span className="field-label">口令</span>
          <input
            className="native-input"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />
        </label>
        {error ? <div className="field-error">{error}</div> : null}
        <div className="row" style={{ justifyContent: "flex-end" }}>
          <button type="submit" className="btn-primary" disabled={password.length === 0 || login.isPending}>
            {login.isPending ? "正在登录…" : "登录"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
