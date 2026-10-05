import { MenuFoldOutlined, MenuUnfoldOutlined } from "@ant-design/icons";
import { Outlet, useRouter, useRouterState } from "@tanstack/react-router";
import { App as AntdApp, Button, Layout } from "antd";
import { lazy, Suspense, useCallback, useEffect, useMemo, useState } from "react";
import { NotFoundPage } from "../pages/NotFoundPage";
import { useSession } from "../security/SessionProvider";
import type { SearchPreset } from "../SearchPanel";
import { Brand } from "./Brand";
import { breadcrumbs, legacyKinds, pageMeta, visibleNav } from "./nav-model.ts";
import type { PaletteResult } from "./palette-classifier.ts";
import { isPaletteShortcut } from "./shortcut.ts";
import { PageActionsTarget } from "./page-actions";
import { PageTitleSetter } from "./page-title";
import { SidebarNav } from "./SidebarNav";
import { Topbar } from "./Topbar";
import { MOBILE_QUERY, useMediaQuery } from "./use-media-query";

// The legacy pages (and their heavy panels) load on first use, not with the shell.
const LegacyHost = lazy(() => import("../legacy/LegacyHost"));
// Overlays load on first use (the palette is also fetched when the browser is idle, so the first
// Ctrl+K is instant); neither is needed to render the shell.
const loadPalette = () => import("./CommandPalette");
const CommandPalette = lazy(() =>
  loadPalette().then((module) => ({ default: module.CommandPalette })),
);
const MobileDrawer = lazy(() =>
  import("./MobileDrawer").then((module) => ({ default: module.MobileDrawer })),
);

export type SearchIntent = { preset: SearchPreset; nonce: number };

const isMac = /Mac|iPhone|iPad/.test(globalThis.navigator?.platform ?? "");

export function ShellLayout() {
  const router = useRouter();
  const pathname = useRouterState({ select: (state) => state.location.pathname });
  const session = useSession();
  const { message } = AntdApp.useApp();
  const { state } = session;
  const roles = state.roles;
  const sessionInfo = state.session;
  const siteId = sessionInfo?.site_id ?? null;
  const groups = useMemo(() => visibleNav(roles, siteId), [roles, siteId]);
  const meta = pageMeta(pathname);
  const crumbs = useMemo(() => breadcrumbs(pathname, groups), [pathname, groups]);
  const mobile = useMediaQuery(MOBILE_QUERY);
  const [collapsed, setCollapsed] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [paletteMounted, setPaletteMounted] = useState(false);
  const [drawerMounted, setDrawerMounted] = useState(false);
  const [actionsTarget, setActionsTarget] = useState<HTMLElement | null>(null);
  const [titleOverride, setTitleOverride] = useState<string | null>(null);
  const [searchIntent, setSearchIntent] = useState<SearchIntent | null>(null);
  const showsLegacy = legacyKinds.has(meta.kind);
  // Once mounted the legacy host stays: it owns unconfirmed writes that must survive navigation.
  const [legacyMounted, setLegacyMounted] = useState(showsLegacy);
  useEffect(() => {
    if (showsLegacy) setLegacyMounted(true);
  }, [showsLegacy]);

  const navigate = useCallback(
    (to: string, options?: { completed?: boolean }) => {
      if (to === window.location.pathname + window.location.search) return;
      void router.navigate({ to, ignoreBlocker: options?.completed } as never);
    },
    [router],
  );

  useEffect(() => {
    // A new page starts at the top; focus moves to the content without scrolling it under the
    // sticky header.
    void pathname;
    window.scrollTo(0, 0);
    document.getElementById("main-content")?.focus({ preventScroll: true });
  }, [pathname]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (!isPaletteShortcut(event)) return;
      event.preventDefault();
      setPaletteMounted(true);
      setPaletteOpen((open) => !open);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  useEffect(() => {
    const idle =
      window.requestIdleCallback ?? ((callback: () => void) => window.setTimeout(callback, 1500));
    const handle = idle(() => void loadPalette());
    return () => {
      if (window.cancelIdleCallback) window.cancelIdleCallback(handle);
      else window.clearTimeout(handle);
    };
  }, []);

  useEffect(() => {
    if (!mobile) setDrawerOpen(false);
  }, [mobile]);

  const runPalette = useCallback(
    (result: PaletteResult) => {
      if (result.action.type === "navigate") navigate(result.action.to);
      else {
        setLegacyMounted(true);
        setSearchIntent({ preset: result.action.preset, nonce: Date.now() });
      }
    },
    [navigate],
  );

  const scope = state.scope
    ? `${state.scope.tenant_id} / ${state.scope.site_id}`
    : "等待查询验证范围";
  const nav = (
    <SidebarNav
      groups={groups}
      pathname={pathname}
      collapsed={!mobile && collapsed}
      onNavigate={(to) => {
        setDrawerOpen(false);
        navigate(to);
      }}
    />
  );

  return (
    <PageActionsTarget.Provider value={actionsTarget}>
      <PageTitleSetter.Provider value={setTitleOverride}>
        <Layout className="xs-shell" hasSider={!mobile}>
          {/* biome-ignore lint/a11y/useValidAnchor: in-page skip link; focus moves without touching router history */}
          <a
            className="skip-link"
            href="#main-content"
            onClick={(event) => {
              event.preventDefault();
              document.getElementById("main-content")?.focus();
            }}
          >
            跳到主要内容
          </a>
          {!mobile && (
            <Layout.Sider
              className="xs-sider"
              width={248}
              collapsedWidth={68}
              collapsed={collapsed}
              trigger={null}
              theme="dark"
              aria-label="后台导航"
            >
              <Brand collapsed={collapsed} />
              {nav}
              <Button
                type="text"
                className="xs-collapse"
                aria-label={collapsed ? "展开导航" : "收起导航"}
                icon={collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />}
                onClick={() => setCollapsed((value) => !value)}
              >
                {!collapsed && "收起菜单"}
              </Button>
            </Layout.Sider>
          )}
          <Layout className="xs-body">
            <Layout.Header className="xs-header">
              <Topbar
                crumbs={crumbs}
                scope={scope}
                session={sessionInfo}
                machineLogin={session.machineLoginEnabled}
                shortcutLabel={isMac ? "⌘K" : "Ctrl K"}
                onOpenNav={() => {
                  setDrawerMounted(true);
                  setDrawerOpen(true);
                }}
                onOpenPalette={() => {
                  setPaletteMounted(true);
                  setPaletteOpen(true);
                }}
                onNavigate={navigate}
                onReauthenticate={() => {
                  void session.reauthenticate().then((failure) => {
                    if (failure) message.warning(failure);
                  });
                }}
                onLogout={() => void session.logout()}
              />
            </Layout.Header>
            <Layout.Content id="main-content" tabIndex={-1} className="xs-main">
              <div className="xs-page-head">
                <div>
                  <h1>{titleOverride ?? meta.title}</h1>
                  {titleOverride === null && meta.lead && <p className="xs-lead">{meta.lead}</p>}
                </div>
                <div className="xs-page-actions" ref={setActionsTarget} />
              </div>
              {meta.kind === "not-found" ? <NotFoundPage /> : <Outlet />}
              {legacyMounted && (
                <Suspense fallback={showsLegacy ? <p className="empty">正在加载页面…</p> : null}>
                  <div hidden={!showsLegacy}>
                    <LegacyHost
                      pathname={pathname}
                      navigate={navigate}
                      searchIntent={searchIntent}
                      onSearchIntentConsumed={() => setSearchIntent(null)}
                    />
                  </div>
                </Suspense>
              )}
              <footer className="xs-footer">
                历史记录用于调查，当前访问资格由服务端独立校验。
              </footer>
            </Layout.Content>
          </Layout>
          {drawerMounted && (
            <Suspense fallback={null}>
              <MobileDrawer
                open={drawerOpen}
                onClose={() => setDrawerOpen(false)}
                nav={nav}
                scope={scope}
              />
            </Suspense>
          )}
          {paletteMounted && (
            <Suspense fallback={null}>
              <CommandPalette
                open={paletteOpen}
                onClose={() => setPaletteOpen(false)}
                roles={roles}
                siteId={siteId}
                onRun={runPalette}
              />
            </Suspense>
          )}
        </Layout>
      </PageTitleSetter.Provider>
    </PageActionsTarget.Provider>
  );
}
