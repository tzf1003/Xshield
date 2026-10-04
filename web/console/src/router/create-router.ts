import { createRouter, type RouterHistory } from "@tanstack/react-router";
import type { SessionRuntime } from "../security/runtime.ts";
import { createAppRouteTree, type RouteComponents } from "./route-tree.ts";

/**
 * Strict matching mirrors the hand-written router it replaces: paths are case-sensitive, a
 * trailing slash is not rewritten (the shell renders "page not found" for it), no search or
 * scroll state is stored anywhere (TanStack's scroll restoration uses sessionStorage, so it
 * must stay off), and no route data is preloaded.
 */
export function createAppRouter(
  components: RouteComponents,
  options: { history?: RouterHistory; runtime?: SessionRuntime } = {},
) {
  const { routeTree, pages } = createAppRouteTree(components);
  const router = createRouter({
    routeTree,
    history: options.history,
    context: { runtime: options.runtime as SessionRuntime },
    caseSensitive: true,
    trailingSlash: "preserve",
    scrollRestoration: false,
    defaultPreload: false,
    defaultPendingMs: 150,
    defaultPendingMinMs: 0,
  });
  return { router, pages };
}

export type AppRouter = ReturnType<typeof createAppRouter>["router"];
