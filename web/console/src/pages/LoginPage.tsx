import { useState } from "react";
import { Alert, Button, Form, Input } from "antd";
import { useNavigate } from "@tanstack/react-router";
import { useMutation } from "@tanstack/react-query";
import { api, describeApiError } from "../api.ts";

export function LoginPage() {
  const navigate = useNavigate();
  const [password, setPassword] = useState("");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: (value: string) => api.login(value),
    onSuccess: () => {
      navigate({ to: "/sites" });
    },
    onError: (error) => {
      setErrorMessage(describeApiError(error));
    },
  });

  function handleSubmit() {
    setErrorMessage(null);
    mutation.mutate(password);
  }

  return (
    <main className="xs-login-page">
      <div className="xs-login-card">
        <h1>Xshield 管理控制台</h1>
        {errorMessage && (
          <Alert
            type="error"
            title={errorMessage}
            style={{ marginBottom: 16 }}
            showIcon
            role="alert"
          />
        )}
        <Form layout="vertical" name="login" onFinish={handleSubmit}>
          <Form.Item label="管理员口令" htmlFor="password" required>
            <Input.Password
              id="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoFocus
              autoComplete="current-password"
            />
          </Form.Item>
          <Form.Item>
            <Button type="primary" htmlType="submit" block loading={mutation.isPending}>
              登录
            </Button>
          </Form.Item>
        </Form>
      </div>
    </main>
  );
}
