import {
  DownOutlined,
  LogoutOutlined,
  SafetyCertificateOutlined,
  SettingOutlined,
} from "@ant-design/icons";
import { Avatar, Button, Dropdown, type MenuProps } from "antd";
import type { BrowserSession } from "../api";
import {
  densityChoiceItems,
  handleThemeMenuClick,
  selectedThemeKeys,
  themeChoiceItems,
} from "../theme/ThemeMenu";
import { useTheme } from "../theme/ThemeProvider";

type Props = {
  session: BrowserSession;
  scope: string;
  onOpenSession: () => void;
  onReauthenticate: () => void;
  onLogout: () => void;
};

/** 权限中心, 主题, 密度, 重新验证高危操作, 安全退出. */
export function UserMenu({ session, scope, onOpenSession, onReauthenticate, onLogout }: Props) {
  const theme = useTheme();
  const items: MenuProps["items"] = [
    { key: "scope", label: `当前范围 ${scope}`, disabled: true },
    { type: "divider" },
    { key: "session", icon: <SettingOutlined />, label: "权限中心" },
    { key: "theme", label: "主题", children: themeChoiceItems() },
    { key: "density", label: "密度", children: densityChoiceItems() },
    { type: "divider" },
    { key: "reauth", icon: <SafetyCertificateOutlined />, label: "重新验证高危操作" },
    { key: "logout", icon: <LogoutOutlined />, label: "安全退出", danger: true },
  ];
  return (
    <Dropdown
      trigger={["click"]}
      menu={{
        items,
        selectedKeys: selectedThemeKeys(theme),
        onClick: ({ key }) => {
          if (key === "session") onOpenSession();
          else if (key === "reauth") onReauthenticate();
          else if (key === "logout") onLogout();
          else handleThemeMenuClick(theme, key);
        },
      }}
    >
      <Button type="text" aria-label="用户菜单" className="xs-user-button">
        <Avatar size={24} className="xs-avatar">
          {session.subject.slice(0, 1).toUpperCase()}
        </Avatar>
        <span className="xs-user-name" title={session.subject}>
          {session.subject}
        </span>
        <DownOutlined aria-hidden="true" />
      </Button>
    </Dropdown>
  );
}
