// The left navigation (docs/06 6.2.1): six pages in order of use, the site modes at the foot, and
// the shortcut and sign-out actions. Collapsed, it keeps the glyphs and shows the names on hover.

import { Link } from "@tanstack/react-router";
import { useSites } from "../api/queries.ts";
import { keepScope } from "./scope.ts";
import { useLogoutAction } from "./session-actions.ts";

const NAV = [
  { to: "/", label: "总览", glyph: "▦", exact: true },
  { to: "/requests", label: "请求追溯", glyph: "≡", exact: false },
  { to: "/sessions", label: "会话", glyph: "◎", exact: false },
  { to: "/jev", label: "Jev 调用", glyph: "✦", exact: false },
  { to: "/sites", label: "站点", glyph: "⚙", exact: false },
  { to: "/system", label: "系统", glyph: "▤", exact: false },
] as const;

type Props = {
  collapsed: boolean;
  onToggle: () => void;
  onHelp: () => void;
  onOpenSites: () => void;
};

export function Sidebar({ collapsed, onToggle, onHelp, onOpenSites }: Props) {
  const sites = useSites();
  const logout = useLogoutAction();
  const list = sites.data?.sites ?? [];
  const observing = list.filter((site) => site.mode === "observe").length;
  const enforcing = list.filter((site) => site.mode === "enforce").length;

  return (
    <aside className="side" aria-label="主导航">
      <div className="brand">
        <button
          type="button"
          className="iconbtn"
          onClick={onToggle}
          aria-label={collapsed ? "展开导航" : "折叠导航"}
          title={collapsed ? "展开导航" : "折叠导航"}
        >
          {collapsed ? "»" : "«"}
        </button>
        <span className="brand-mark" aria-hidden="true">
          ◆
        </span>
        <span className="brand-name">Xshield</span>
      </div>
      <nav className="nav">
        {NAV.map((item) => (
          <Link
            key={item.to}
            to={item.to}
            search={keepScope}
            activeOptions={{ exact: item.exact }}
            className="nav-item"
            title={item.label}
          >
            <span className="nav-glyph" aria-hidden="true">
              {item.glyph}
            </span>
            <span className="nav-label">{item.label}</span>
          </Link>
        ))}
      </nav>
      <div className="nav-foot">
        <button type="button" className="nav-item" onClick={onOpenSites} title="按模式查看站点">
          <span className="nav-glyph" aria-hidden="true">
            ●
          </span>
          <span className="nav-count">
            观察 {observing} · 拦截 {enforcing}
          </span>
        </button>
        <button type="button" className="nav-item" onClick={onHelp} title="快捷键">
          <span className="nav-glyph" aria-hidden="true">
            ?
          </span>
          <span className="nav-label">快捷键</span>
        </button>
        <button type="button" className="nav-item" onClick={() => void logout()} title="退出登录">
          <span className="nav-glyph" aria-hidden="true">
            ⎋
          </span>
          <span className="nav-label">退出</span>
        </button>
      </div>
    </aside>
  );
}
