import { Menu, type MenuProps } from "antd";
import type { MouseEvent } from "react";
import { ApprovalNavBadge } from "./ApprovalNavBadge";
import { navIcon } from "./icons";
import { activeItem, flattenNav, type NavGroup } from "./nav-model.ts";

type Props = {
  groups: readonly NavGroup[];
  pathname: string;
  collapsed?: boolean;
  onNavigate: (to: string) => void;
};

function isModified(
  event: Pick<MouseEvent, "button" | "metaKey" | "ctrlKey" | "shiftKey" | "altKey">,
) {
  return event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey;
}

/**
 * Grouped navigation. Every entry is a real link (so it can be opened in a new tab), while a
 * plain click or the Enter key goes through the router.
 */
export function SidebarNav({ groups, pathname, collapsed = false, onNavigate }: Props) {
  const current = activeItem(pathname, flattenNav(groups));
  const items: MenuProps["items"] = groups.map((group) => ({
    type: "group",
    key: group.key,
    label: collapsed ? null : group.label,
    children: group.items.map((entry) => ({
      key: entry.key,
      icon: navIcon(entry.icon),
      title: entry.label,
      label: (
        <span className="xs-nav-label">
          <a
            href={entry.href}
            aria-current={current?.key === entry.key ? "page" : undefined}
            onClick={(event) => {
              if (!isModified(event)) event.preventDefault();
            }}
          >
            {entry.label}
          </a>
          {entry.badge === "approvals" && !collapsed && <ApprovalNavBadge />}
        </span>
      ),
    })),
  }));
  return (
    <nav aria-label="主导航" className="xs-nav">
      <Menu
        theme="dark"
        mode="inline"
        inlineCollapsed={collapsed}
        selectedKeys={current ? [current.key] : []}
        items={items}
        onClick={({ key, domEvent }) => {
          if ("button" in domEvent && isModified(domEvent as unknown as MouseEvent)) return;
          onNavigate(key);
        }}
      />
    </nav>
  );
}
