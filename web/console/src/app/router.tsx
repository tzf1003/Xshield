// The route tree (docs/07 7.10.3). The root layout frames every page with the shell except the login
// page, and the root's guard sends a visitor without a session to the login page, remembering where
// they were going. Search parameters are validated per route (search-schema.ts), so a link carries
// its filters, tabs and view modes. Search strings stay strings: nothing is JSON-coerced, so a session
// label of digits or a search for "null" reads back as typed.

import type { QueryClient } from "@tanstack/react-query";
import {
  createRootRouteWithContext,
  createRoute,
  createRouter,
  Outlet,
  parseSearchWith,
  redirect,
  stringifySearchWith,
  useRouterState,
} from "@tanstack/react-router";
import { api } from "../api/client.ts";
import { keys } from "../api/queries.ts";
import { queryClient } from "../api/query-client.ts";
import { JevPage } from "../features/jev/JevPage.tsx";
import { OverviewPage } from "../features/overview/OverviewPage.tsx";
import { RequestDetailPage } from "../features/request-detail/RequestDetailPage.tsx";
import { RequestsPage } from "../features/requests/RequestsPage.tsx";
import { SessionTimelinePage } from "../features/sessions/SessionTimelinePage.tsx";
import { SessionsPage } from "../features/sessions/SessionsPage.tsx";
import { SiteDetailPage } from "../features/sites/SiteDetailPage.tsx";
import { SitesPage } from "../features/sites/SitesPage.tsx";
import { SiteWizardPage } from "../features/sites/SiteWizardPage.tsx";
import { SystemPage } from "../features/system/SystemPage.tsx";
import { LoginPage } from "./LoginPage.tsx";
import { NotFoundPage } from "./NotFoundPage.tsx";
import { Shell } from "./Shell.tsx";
import {
  validateDetail,
  validateGlobal,
  validateJev,
  validateLogin,
  validateRequests,
  validateSessions,
  validateSite,
  validateSystem,
  validateTimeline,
  validateWizard,
} from "./search-schema.ts";

type RouterContext = { queryClient: QueryClient };

const LOGIN_PATH = "/login";

/** Sends a visitor without a session to the login page, remembering where they were going. */
async function requireSession(client: QueryClient, href: string): Promise<void> {
  const state = await client.ensureQueryData({ queryKey: keys.session, queryFn: api.session });
  if (!state.authenticated) throw redirect({ to: "/login", search: { next: href } });
}

/** The login page stands alone; every other page is framed by the shell (docs/06 6.3.1). */
function RootLayout() {
  const pathname = useRouterState({ select: (state) => state.location.pathname });
  return pathname === LOGIN_PATH ? <Outlet /> : <Shell />;
}

const rootRoute = createRootRouteWithContext<RouterContext>()({
  beforeLoad: async ({ context, location }) => {
    if (location.pathname === LOGIN_PATH) return;
    await requireSession(context.queryClient, location.href);
  },
  component: RootLayout,
  notFoundComponent: NotFoundPage,
});

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: LOGIN_PATH,
  validateSearch: validateLogin,
  beforeLoad: async ({ context, search }) => {
    const state = await context.queryClient.ensureQueryData({
      queryKey: keys.session,
      queryFn: api.session,
    });
    if (state.authenticated) throw redirect({ href: search.next ?? "/", replace: true });
  },
  component: LoginPage,
});

const overviewRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  validateSearch: validateGlobal,
  component: OverviewPage,
});

const requestsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/requests",
  validateSearch: validateRequests,
  component: RequestsPage,
});

const requestDetailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/requests/$requestId",
  validateSearch: validateDetail,
  component: RequestDetailPage,
});

const sessionsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/sessions",
  validateSearch: validateSessions,
  component: SessionsPage,
});

const sessionTimelineRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/sessions/$label",
  validateSearch: validateTimeline,
  component: SessionTimelinePage,
});

const jevRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/jev",
  validateSearch: validateJev,
  component: JevPage,
});

const sitesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/sites",
  validateSearch: validateGlobal,
  component: SitesPage,
});

const siteWizardRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/sites/new",
  validateSearch: validateWizard,
  component: SiteWizardPage,
});

const siteDetailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/sites/$name",
  validateSearch: validateSite,
  component: SiteDetailPage,
});

const systemRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/system",
  validateSearch: validateSystem,
  component: SystemPage,
});

const routeTree = rootRoute.addChildren([
  loginRoute,
  overviewRoute,
  requestsRoute,
  requestDetailRoute,
  sessionsRoute,
  sessionTimelineRoute,
  jevRoute,
  sitesRoute,
  siteWizardRoute,
  siteDetailRoute,
  systemRoute,
]);

export const router = createRouter({
  routeTree,
  context: { queryClient },
  defaultPreload: "intent",
  parseSearch: parseSearchWith((value) => value),
  stringifySearch: stringifySearchWith(JSON.stringify),
});

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
