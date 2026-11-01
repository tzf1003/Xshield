import {
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
  redirect,
} from "@tanstack/react-router";
import type { QueryClient } from "@tanstack/react-query";
import type { ReactElement } from "react";
import { api } from "./api.ts";
import { Shell } from "./Shell.tsx";
import { LoginPage } from "./pages/LoginPage.tsx";
import { SitesListPage } from "./pages/SitesListPage.tsx";
import { SiteNewPage } from "./pages/SiteNewPage.tsx";
import { SiteDetailPage } from "./pages/SiteDetailPage.tsx";
import { DecisionsPage } from "./pages/DecisionsPage.tsx";

export interface RouterContext {
  queryClient: QueryClient;
}

/** A redirect() thrown by @tanstack/react-router is an object carrying `to`; everything else is a real error. */
function isRedirect(value: unknown): value is { to: string } {
  return typeof value === "object" && value !== null && "to" in value;
}

/** Any failure to confirm the session (401, network error, ...) sends the operator to /login. */
async function requireSession(): Promise<void> {
  try {
    const session = await api.session();
    if (!session.authenticated) throw redirect({ to: "/login" });
  } catch (error) {
    if (isRedirect(error)) throw error;
    throw redirect({ to: "/login" });
  }
}

function protectedPage(Page: () => ReactElement) {
  return function ProtectedPage() {
    return (
      <Shell>
        <Page />
      </Shell>
    );
  };
}

const rootRoute = createRootRoute({
  component: () => <Outlet />,
});

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  beforeLoad: async () => {
    try {
      const session = await api.session();
      throw redirect({ to: session.authenticated ? "/sites" : "/login" });
    } catch (error) {
      if (isRedirect(error)) throw error;
      throw redirect({ to: "/login" });
    }
  },
});

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/login",
  component: LoginPage,
});

const sitesListRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/sites",
  beforeLoad: requireSession,
  component: protectedPage(SitesListPage),
});

const siteNewRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/sites/new",
  beforeLoad: requireSession,
  component: protectedPage(SiteNewPage),
});

const siteDetailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/sites/$name",
  beforeLoad: requireSession,
  component: protectedPage(SiteDetailPage),
});

const decisionsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/decisions",
  beforeLoad: requireSession,
  component: protectedPage(DecisionsPage),
});

const routeTree = rootRoute.addChildren([
  indexRoute,
  loginRoute,
  sitesListRoute,
  siteNewRoute,
  siteDetailRoute,
  decisionsRoute,
]);

export function createAppRouter(context: RouterContext) {
  return createRouter({
    routeTree,
    context,
    defaultPreload: false,
    scrollRestoration: false,
  });
}

export type AppRouter = ReturnType<typeof createAppRouter>;

declare module "@tanstack/react-router" {
  interface Register {
    router: AppRouter;
  }
}
