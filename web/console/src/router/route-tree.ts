import {
  type AnyRoute,
  createRootRouteWithContext,
  createRoute,
  lazyRouteComponent,
  notFound,
} from "@tanstack/react-router";
import type { ReactNode } from "react";
import { type QueryKind, siteSections } from "../admin-routes.ts";
import {
  agentRunPattern,
  bindingPattern,
  calibrationReportPattern,
  grantPattern,
  modelCallPattern,
  requestPattern,
} from "../api-contract.ts";
import type { SessionRuntime } from "../security/runtime.ts";

export type RouterContext = { runtime: SessionRuntime };

export type RouteComponents = {
  /** Session gate: the login screen until a session exists, otherwise the matched route. */
  Root: () => ReactNode;
  /** Navigation chrome around every signed-in page. */
  Shell: () => ReactNode;
  /** Shown inside the shell for unknown addresses and malformed IDs. */
  NotFound: () => ReactNode;
  /** Shown while a lazily loaded page chunk is fetched. */
  Pending: () => ReactNode;
  /** Shown when a page throws while rendering. */
  Failure: (props: { error: unknown }) => ReactNode;
};

export type PageRoute = Readonly<{ kind: QueryKind; path: string; route: AnyRoute }>;

const siteIdPattern = /^[A-Za-z0-9_.-]{1,128}(?![\s\S])/;
const sectionNames: readonly string[] = siteSections.map(([part]) => part);

/** Browser paths select views only; every API call is independently authorized by the server. */
export function createAppRouteTree(components: RouteComponents) {
  const root = createRootRouteWithContext<RouterContext>()({
    component: components.Root,
    pendingComponent: components.Pending,
    errorComponent: components.Failure,
    notFoundComponent: components.NotFound,
  });
  const shell = createRoute({
    getParentRoute: () => root,
    id: "shell",
    component: components.Shell,
  });

  const pages: PageRoute[] = [];
  // The legacy host renders the content of most pages itself (it stays mounted so unconfirmed
  // writes survive navigation), so those routes carry no component of their own.
  function page(
    kind: QueryKind,
    path: string,
    options: { component?: unknown; params?: unknown } = {},
  ): AnyRoute {
    // A malformed ID or section throws notFound() while the route is matched. Each page route
    // renders its own "not found" so the failure stays inside the shell: with only an ancestor
    // handler the router would replace the whole shell (navigation included) with it.
    const route = createRoute({
      getParentRoute: () => shell,
      path,
      notFoundComponent: components.NotFound,
      ...options,
    } as never) as AnyRoute;
    pages.push({ kind, path, route });
    return route;
  }

  const idParams = (name: string, pattern: RegExp) => ({
    parse: (raw: Record<string, string>) => {
      const value = raw[name];
      if (typeof value !== "string" || !pattern.test(value)) throw notFound();
      return { [name]: value };
    },
    stringify: (params: Record<string, string>) => ({ [name]: params[name] }),
  });

  const children = [
    page("overview", "/", {
      component: lazyRouteComponent(() => import("../pages/OverviewPage"), "OverviewPage"),
    }),
    page("session", "access/session", {
      component: lazyRouteComponent(() => import("../pages/SessionPage"), "SessionPage"),
    }),
    page("site-list", "sites", {
      component: lazyRouteComponent(() => import("../pages/sites/SitesListPage"), "SitesListPage"),
    }),
    page("site-config", "sites/$siteId/$section", {
      params: {
        parse: (raw: Record<string, string>) => {
          const { siteId, section } = raw;
          if (
            typeof siteId !== "string" ||
            typeof section !== "string" ||
            !siteIdPattern.test(siteId) ||
            !sectionNames.includes(section)
          ) {
            throw notFound();
          }
          return { siteId, section };
        },
        stringify: (params: Record<string, string>) => ({
          siteId: params.siteId,
          section: params.section,
        }),
      },
    }),
    page("api-keys", "admin/api-keys"),
    page("request", "investigation/requests"),
    page("request", "investigation/requests/$requestId", {
      params: idParams("requestId", requestPattern),
    }),
    page("model-list", "investigation/models"),
    page("model", "investigation/models/lookup"),
    page("model", "investigation/models/$modelCallId", {
      params: idParams("modelCallId", modelCallPattern),
    }),
    page("agent", "investigation/agents"),
    page("agent", "investigation/agents/$agentRunId", {
      params: idParams("agentRunId", agentRunPattern),
    }),
    page("grant", "investigation/grants"),
    page("grant", "investigation/grants/$grantId", {
      params: idParams("grantId", grantPattern),
    }),
    page("binding", "investigation/bindings"),
    page("binding", "investigation/bindings/$bindingId", {
      params: idParams("bindingId", bindingPattern),
    }),
    page("calibration-report", "investigation/calibration"),
    page("calibration-report", "investigation/calibration/$reportId", {
      params: idParams("reportId", calibrationReportPattern),
    }),
    page("search", "investigation/search"),
    page("case", "cases"),
    page("access", "evidence/access"),
    page("hold", "evidence/holds"),
    page("export", "evidence/exports"),
    page("audit-health", "operations/audit"),
    page("jobs", "operations/jobs"),
    // Anything the table above does not describe.
    page("not-found", "$", { component: components.NotFound }),
  ];

  return { routeTree: root.addChildren([shell.addChildren(children)]), pages };
}
