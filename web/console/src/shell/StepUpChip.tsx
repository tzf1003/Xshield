import { SafetyCertificateOutlined } from "@ant-design/icons";
import { Button, Tag } from "antd";
import { useEffect, useState } from "react";
import type { BrowserSession } from "../api";
import { formatRemaining, stepUpStatus } from "./step-up.ts";

/**
 * MFA step-up validity with a live countdown, plus the existing "重新验证高危操作" action when
 * it has lapsed. Purely advisory: each high-risk request is re-checked by the server.
 * Label length is switched by CSS (`xs-long` / `xs-short`) so a resized window never overflows;
 * on narrow screens the action lives in the user menu instead.
 */
export function StepUpChip({
  session,
  onReauthenticate,
}: {
  session: BrowserSession;
  onReauthenticate: () => void;
}) {
  const [now, setNow] = useState(() => Date.now());
  const status = stepUpStatus(session, now);
  const counting = status.valid && status.remainingMs !== null;

  useEffect(() => {
    if (!counting) return;
    setNow(Date.now());
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [counting]);

  if (status.valid) {
    const remaining = status.remainingMs === null ? null : formatRemaining(status.remainingMs);
    return (
      <Tag
        className="xs-chip"
        color="success"
        icon={<SafetyCertificateOutlined />}
        title="MFA 再认证有效"
      >
        <span className="xs-long">MFA 再认证有效{remaining ? ` · 剩余 ${remaining}` : ""}</span>
        <span className="xs-short">{remaining ?? "有效"}</span>
      </Tag>
    );
  }
  return (
    <>
      <Tag
        className="xs-chip"
        color="warning"
        icon={<SafetyCertificateOutlined />}
        title="高危操作需要 MFA 再认证"
      >
        <span className="xs-long">高危操作需要 MFA 再认证</span>
        <span className="xs-short">需再认证</span>
      </Tag>
      <Button size="small" className="xs-reauth" onClick={onReauthenticate}>
        重新验证高危操作
      </Button>
    </>
  );
}
