// The frame every signed-in page shares: navigation on the left, the top bar, the page, and the
// dialogs that can open from anywhere (command palette, shortcuts, custom range, login).

import { Outlet, useNavigate } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import { onUnauthorized } from "../api/client.ts";
import { useSites } from "../api/queries.ts";
import { readText, writeText } from "../lib/storage.ts";
import { CommandPalette } from "./CommandPalette.tsx";
import { hrefFor } from "./href.ts";
import { isTypingTarget, useKeys } from "./keys.ts";
import { LoginDialog } from "./LoginDialog.tsx";
import { RangeDialog } from "./RangeDialog.tsx";
import { ShortcutHelp } from "./ShortcutHelp.tsx";
import { Sidebar } from "./Sidebar.tsx";
import { Topbar } from "./Topbar.tsx";
import { useGlobalSearch, useSetSearch } from "./scope.ts";

export type DialogName = "palette" | "help" | "range" | "login";

const NAV_KEY = "xshield.console.nav";
const SITE_KEY = "xshield.console.site";
/** The `g` chord (docs/06 6.3.4): `g` then a letter jumps to a page within a second. */
const CHORDS: Record<string, string> = {
  o: "/",
  r: "/requests",
  s: "/sessions",
  j: "/jev",
  c: "/sites",
  y: "/system",
};

export function Shell() {
  const navigate = useNavigate();
  const global = useGlobalSearch();
  const setSearch = useSetSearch();
  const sites = useSites();
  const [collapsed, setCollapsed] = useState(() => readText(NAV_KEY) === "collapsed");
  const [dialog, setDialog] = useState<DialogName | null>(null);
  const restored = useRef(false);

  // The last site chosen is remembered and restored when a page opens without one (docs/06 6.3.2).
  useEffect(() => {
    if (restored.current || !sites.data) return;
    restored.current = true;
    if (global.site) {
      writeText(SITE_KEY, global.site);
      return;
    }
    const last = readText(SITE_KEY);
    if (last && sites.data.sites.some((site) => site.name === last)) {
      setSearch({ site: last }, true);
    }
  }, [sites.data, global.site, setSearch]);

  useEffect(() => onUnauthorized(() => setDialog((open) => open ?? "login")), []);

  useEffect(() => {
    let pendingAt = 0;
    const onKey = (event: KeyboardEvent) => {
      if (event.metaKey || event.ctrlKey || event.altKey || isTypingTarget(event.target)) return;
      if (event.key === "g") {
        pendingAt = Date.now();
        return;
      }
      if (pendingAt > 0 && Date.now() - pendingAt < 1000) {
        pendingAt = 0;
        const path = CHORDS[event.key];
        if (path) {
          event.preventDefault();
          void navigate({ href: hrefFor(path) });
        }
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [navigate]);

  useKeys({
    "Mod+k": (event) => {
      event.preventDefault();
      setDialog((open) => (open === "palette" ? null : "palette"));
    },
    "?": () => setDialog("help"),
    "/": (event) => {
      const field = document.querySelector<HTMLInputElement>("[data-filter]");
      if (field) {
        event.preventDefault();
        field.focus();
      }
    },
  });

  const toggleNav = () => {
    setCollapsed((value) => {
      writeText(NAV_KEY, value ? "expanded" : "collapsed");
      return !value;
    });
  };

  return (
    <div className={collapsed ? "app collapsed" : "app"}>
      <Sidebar
        collapsed={collapsed}
        onToggle={toggleNav}
        onHelp={() => setDialog("help")}
        onOpenSites={() => void navigate({ href: hrefFor("/sites") })}
      />
      <main className="main">
        <Topbar
          onOpenPalette={() => setDialog("palette")}
          onCustomRange={() => setDialog("range")}
        />
        <div className="page-scroll">
          <Outlet />
        </div>
      </main>
      <CommandPalette
        open={dialog === "palette"}
        onClose={() => setDialog(null)}
        onHelp={() => setDialog("help")}
      />
      <ShortcutHelp open={dialog === "help"} onClose={() => setDialog(null)} />
      <RangeDialog open={dialog === "range"} onClose={() => setDialog(null)} />
      <LoginDialog open={dialog === "login"} onClose={() => setDialog(null)} />
    </div>
  );
}
