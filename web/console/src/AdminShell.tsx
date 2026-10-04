import { useState, type MouseEvent, type ReactNode } from "react";
import {
  ApartmentOutlined,
  AuditOutlined,
  DatabaseOutlined,
  ExperimentOutlined,
  FileSearchOutlined,
  FolderOpenOutlined,
  HomeOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  SafetyCertificateOutlined,
  SettingOutlined,
  TeamOutlined,
} from "@ant-design/icons";
import { siteSections } from "./admin-routes";
import { ThemeMenu } from "./theme/ThemeMenu";

type SessionView = {
  subject: string;
  tenant_id: string;
  site_id: string;
  roles: string[];
  session_expires_at?: string;
  idle_expires_at?: string;
  last_reauthenticated_at?: string | null;
  step_up_valid?: boolean;
};

type AdminShellProps = {
  children: ReactNode;
  connected: boolean;
  pathname: string;
  title: string;
  scope: string;
  roles: string[] | null;
  session: SessionView | null;
  machineLoginEnabled: boolean;
  onNavigate: (path: string) => void;
  onLogout: () => void;
  onReauthenticate: () => void;
  onRefresh?: () => void;
  refreshing?: boolean;
  observedAt?: string | null;
};

const navGroups = [
  { label: "", items: [{ href: "/", label: "概览", roles: [], icon: HomeOutlined }] },
  {
    label: "防护",
    items: [
      { href: "/sites", label: "受保护站点", roles: ["system_admin"], icon: ApartmentOutlined },
      {
        href: "/operations/jobs",
        label: "运行状态",
        roles: ["investigator"],
        icon: DatabaseOutlined,
      },
    ],
  },
  {
    label: "调查",
    items: [
      {
        href: "/investigation/requests",
        label: "请求调查",
        roles: ["observer", "investigator"],
        icon: FileSearchOutlined,
      },
      {
        href: "/investigation/models",
        label: "模型调用列表",
        roles: ["observer"],
        icon: ExperimentOutlined,
      },
      {
        href: "/investigation/models/lookup",
        label: "模型调用详情",
        roles: ["observer"],
        icon: ExperimentOutlined,
      },
      {
        href: "/investigation/agents",
        label: "Agent 运行",
        roles: ["observer"],
        icon: SafetyCertificateOutlined,
      },
      {
        href: "/investigation/search",
        label: "结构化检索",
        roles: ["investigator"],
        icon: FileSearchOutlined,
      },
      {
        href: "/investigation/grants",
        label: "资格与身份账本",
        roles: ["investigator", "observer"],
        icon: TeamOutlined,
      },
      {
        href: "/investigation/bindings",
        label: "身份绑定",
        roles: ["investigator", "observer"],
        icon: TeamOutlined,
      },
    ],
  },
  {
    label: "案件与证据",
    items: [
      { href: "/cases", label: "案件工作台", roles: ["investigator"], icon: FolderOpenOutlined },
      {
        href: "/evidence/access",
        label: "证据访问",
        roles: ["investigator", "sensitive_evidence_reader", "sensitive_evidence_approver"],
        icon: SafetyCertificateOutlined,
      },
      {
        href: "/evidence/holds",
        label: "证据保留",
        roles: ["audit_administrator"],
        icon: FolderOpenOutlined,
      },
      {
        href: "/evidence/exports",
        label: "调查导出",
        roles: ["investigator", "sensitive_evidence_reader", "sensitive_evidence_approver"],
        icon: DatabaseOutlined,
      },
    ],
  },
  {
    label: "治理",
    items: [
      {
        href: "/investigation/calibration",
        label: "校准报告",
        roles: ["audit_administrator"],
        icon: AuditOutlined,
      },
      {
        href: "/operations/audit",
        label: "审计发布状态",
        roles: ["audit_administrator"],
        icon: AuditOutlined,
      },
      { href: "/access/session", label: "权限中心", roles: [], icon: SettingOutlined },
    ],
  },
] as const;

function visible(roles: string[] | null, required: readonly string[]) {
  if (required.length === 0 || roles === null) return true;
  return required.some((role) => roles.includes(role));
}

function active(pathname: string, href: string) {
  if (href === "/") return pathname === "/";
  return pathname === href || pathname.startsWith(`${href}/`);
}

function navigate(event: MouseEvent<HTMLAnchorElement>, onNavigate: (path: string) => void) {
  if (
    event.defaultPrevented ||
    event.button !== 0 ||
    event.metaKey ||
    event.ctrlKey ||
    event.shiftKey ||
    event.altKey
  )
    return;
  event.preventDefault();
  onNavigate(event.currentTarget.pathname + event.currentTarget.search);
}

export function AdminShell({
  children,
  connected,
  pathname,
  title,
  scope,
  roles,
  session,
  machineLoginEnabled,
  onNavigate,
  onLogout,
  onReauthenticate,
  onRefresh,
  refreshing = false,
  observedAt,
}: AdminShellProps) {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  return (
    <div
      className={`legacy ${connected ? "admin-layout" : "admin-layout disconnected"}${collapsed ? " sidebar-collapsed" : ""}${mobileOpen ? " mobile-nav-open" : ""}`}
    >
      <a className="skip-link" href="#main-content">
        跳到主要内容
      </a>
      {connected && (
        <aside className="sidebar" aria-label="后台导航">
          <div className="sidebar-brand">
            <span className="brand-mark">X</span>
            <span className="brand-wordmark">Xshield</span>
          </div>
          <div className="sidebar-context">
            <span className="sidebar-context-dot" />
            <span>管理控制台</span>
          </div>
          <nav className="nav-groups">
            {navGroups.map((group) => {
              const items = group.items.filter((item) => visible(roles, item.roles));
              if (!items.length) return null;
              return (
                <div className="nav-group" key={group.label || "overview"}>
                  {group.label && <div className="nav-group-label">{group.label}</div>}
                  {items.map((item) => {
                    const Icon = item.icon;
                    return (
                      <a
                        key={item.href}
                        className={active(pathname, item.href) ? "active" : ""}
                        aria-current={pathname === item.href ? "page" : undefined}
                        href={item.href}
                        onClick={(event) => {
                          setMobileOpen(false);
                          navigate(event, onNavigate);
                        }}
                      >
                        <Icon className="nav-icon" aria-hidden="true" />
                        <span>{item.label}</span>
                      </a>
                    );
                  })}
                </div>
              );
            })}
            {session && !roles?.includes("system_admin") && roles?.includes("observer") && (
              <a
                className={
                  pathname.startsWith(`/sites/${session.site_id}/overview`) ? "active" : ""
                }
                href={`/sites/${session.site_id}/overview`}
                onClick={(event) => {
                  setMobileOpen(false);
                  navigate(event, onNavigate);
                }}
              >
                <ApartmentOutlined className="nav-icon" aria-hidden="true" />
                <span>站点状态</span>
              </a>
            )}
            {session &&
              !roles?.includes("system_admin") &&
              roles?.some((role) =>
                ["policy_author", "policy_approver", "release_operator"].includes(role),
              ) && (
                <a
                  className={
                    pathname.startsWith(`/sites/${session.site_id}/releases`) ? "active" : ""
                  }
                  href={`/sites/${session.site_id}/releases`}
                  onClick={(event) => {
                    setMobileOpen(false);
                    navigate(event, onNavigate);
                  }}
                >
                  <SettingOutlined className="nav-icon" aria-hidden="true" />
                  <span>站点发布</span>
                </a>
              )}
          </nav>
          <button
            className="sidebar-collapse"
            type="button"
            aria-label={collapsed ? "展开导航" : "收起导航"}
            onClick={() => setCollapsed((value) => !value)}
          >
            {collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />}
            <span>{collapsed ? "展开菜单" : "收起菜单"}</span>
          </button>
          {roles?.includes("system_admin") !== false && pathname.startsWith("/sites/") && (
            <nav className="sidebar-subnav" aria-label="站点配置">
              {siteSections.map(([part, label]) => {
                const siteId = pathname.split("/")[2] || session?.site_id || "";
                const href = `/sites/${siteId}/${part}`;
                return (
                  <a
                    key={href}
                    className={pathname === href ? "active" : ""}
                    href={href}
                    onClick={(event) => navigate(event, onNavigate)}
                  >
                    {label}
                  </a>
                );
              })}
            </nav>
          )}
        </aside>
      )}
      <div className="admin-content">
        <header className="topbar">
          <button
            className="mobile-nav-trigger"
            type="button"
            aria-label="打开导航"
            onClick={() => setMobileOpen(true)}
          >
            <MenuUnfoldOutlined />
          </button>
          <div className="breadcrumbs">
            <span className="breadcrumb-root">Xshield</span>
            <span className="breadcrumb-separator">/</span>
            <strong>{title}</strong>
          </div>
          <div className="topbar-scope">
            <span className="scope-label">当前范围</span>
            <span className="mono scope">{connected ? scope : "尚未连接"}</span>
          </div>
          <div className="connection">
            <ThemeMenu />
            {observedAt && <span className="observed-at">观察于 {observedAt}</span>}
            {connected && onRefresh && (
              <button
                className="topbar-refresh"
                type="button"
                onClick={onRefresh}
                disabled={refreshing}
              >
                {refreshing ? "读取中…" : "刷新快照"}
              </button>
            )}
            {connected && session && (
              <span className="session-user">
                <span className="session-avatar">{session.subject.slice(0, 1).toUpperCase()}</span>
                <span className="session-user-name" title={session.subject}>
                  {session.subject}
                </span>
              </span>
            )}
            {connected &&
              (machineLoginEnabled ? (
                <button className="outline" onClick={onLogout}>
                  断开连接
                </button>
              ) : (
                <>
                  <span className="muted step-up-status" role="status">
                    {session?.step_up_valid ? "MFA 再认证有效" : "高危操作需要 MFA 再认证"}
                  </span>
                  <button className="outline" onClick={onReauthenticate}>
                    重新验证高危操作
                  </button>
                  <button className="outline" onClick={onLogout}>
                    安全退出
                  </button>
                </>
              ))}
          </div>
        </header>
        <main id="main-content" tabIndex={-1}>
          {children}
        </main>
      </div>
      {connected && mobileOpen && (
        <button
          className="mobile-nav-backdrop"
          type="button"
          aria-label="关闭导航"
          onClick={() => setMobileOpen(false)}
        />
      )}
    </div>
  );
}
