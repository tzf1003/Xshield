import { Button, Tag } from "antd";
import type { ReactNode } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./api.ts";

function JevStatusBadge() {
  const { data } = useQuery({
    queryKey: ["jev-status"],
    queryFn: () => api.jevStatus(),
    staleTime: 30_000,
    refetchInterval: 30_000,
  });
  const status = data?.status ?? "unknown";
  const color = status === "unknown" ? "default" : status === "ok" ? "success" : "error";
  return <Tag color={color}>Jev 连通状态：{status}</Tag>;
}

export function Shell({ children }: { children: ReactNode }) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  async function handleLogout() {
    try {
      await api.logout();
    } finally {
      queryClient.clear();
      navigate({ to: "/login" });
    }
  }

  return (
    <div className="xs-shell">
      <header className="xs-topbar">
        <span className="xs-topbar-brand">Xshield 管理控制台</span>
        <nav className="xs-topbar-nav">
          <Link to="/sites" activeProps={{ className: "active" }}>
            站点
          </Link>
          <Link to="/decisions" activeProps={{ className: "active" }}>
            判定日志
          </Link>
        </nav>
        <div className="xs-topbar-right">
          <JevStatusBadge />
          <Button onClick={handleLogout}>退出登录</Button>
        </div>
      </header>
      <main className="xs-content">{children}</main>
    </div>
  );
}
