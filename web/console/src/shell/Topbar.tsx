import { MenuOutlined, SearchOutlined } from "@ant-design/icons";
import { Breadcrumb, Button, Tag } from "antd";
import type { BrowserSession } from "../api";
import { ThemeMenu } from "../theme/ThemeMenu";
import type { Crumb } from "./nav-model.ts";
import { PendingOperationsChip } from "./PendingOperationsChip";
import { StepUpChip } from "./StepUpChip";
import { UserMenu } from "./UserMenu";

type Props = {
  crumbs: readonly Crumb[];
  scope: string;
  session: BrowserSession | null;
  machineLogin: boolean;
  shortcutLabel: string;
  onOpenNav: () => void;
  onOpenPalette: () => void;
  onNavigate: (to: string) => void;
  onReauthenticate: () => void;
  onLogout: () => void;
};

export function Topbar({
  crumbs,
  scope,
  session,
  machineLogin,
  shortcutLabel,
  onOpenNav,
  onOpenPalette,
  onNavigate,
  onReauthenticate,
  onLogout,
}: Props) {
  return (
    <div className="xs-topbar">
      <Button
        type="text"
        icon={<MenuOutlined />}
        aria-label="打开导航"
        onClick={onOpenNav}
        className="xs-nav-trigger"
      />
      <Breadcrumb
        className="xs-breadcrumb"
        items={crumbs.map((crumb) => ({
          title: crumb.href ? (
            <a
              href={crumb.href}
              onClick={(event) => {
                if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey) return;
                event.preventDefault();
                if (crumb.href) onNavigate(crumb.href);
              }}
            >
              {crumb.label}
            </a>
          ) : (
            crumb.label
          ),
        }))}
      />
      <div className="xs-topbar-end">
        <Tag className="xs-scope" title="服务端确认的 tenant / site 范围">
          <span className="xs-scope-label">当前范围</span> <span className="mono">{scope}</span>
        </Tag>
        <Button
          size="small"
          icon={<SearchOutlined />}
          onClick={onOpenPalette}
          aria-label="打开命令面板"
          className="xs-palette-trigger"
        >
          <span className="xs-palette-label">搜索页面或粘贴 ID</span>{" "}
          <kbd className="xs-palette-label">{shortcutLabel}</kbd>
        </Button>
        {session && !machineLogin && (
          <StepUpChip session={session} onReauthenticate={onReauthenticate} />
        )}
        <PendingOperationsChip />
        <ThemeMenu />
        {machineLogin || !session ? (
          <Button onClick={onLogout}>断开连接</Button>
        ) : (
          <UserMenu
            session={session}
            scope={scope}
            onOpenSession={() => onNavigate("/access/session")}
            onReauthenticate={onReauthenticate}
            onLogout={onLogout}
          />
        )}
      </div>
    </div>
  );
}
