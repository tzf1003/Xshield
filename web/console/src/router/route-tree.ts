import {
  type AnyRoute,
  createRootRouteWithContext,
  createRoute,
  lazyRouteComponent,
  notFound,
  redirect,
} from "@tanstack/react-router";
import type { ReactNode } from "react";
import { canonicalWizardStep, caseTabs, type QueryKind, siteSections } from "../admin-routes.ts";
import {
  agentRunPattern,
  bindingPattern,
  calibrationReportPattern,
  grantPattern,
  jobPattern,
  modelCallPattern,
  requestPattern,
} from "../api-contract.ts";
import { casePattern } from "../cases.ts";
import { accessPattern } from "../evidence-access.ts";
import { exportPattern } from "../exports.ts";
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

/** A retired address: leave at once for the page that took its place, with a one-time hint. */
const movedTo = (to: string, moved: string) => () => {
  throw redirect({ to, search: { moved }, replace: true } as never);
};

/** `?item=` selects one access request or export; `?moved=` carries a retired address's hint. */
const approvalsSearch = (search: Record<string, unknown>) => ({
  item:
    typeof search.item === "string" &&
    (accessPattern.test(search.item) || exportPattern.test(search.item))
      ? search.item
      : undefined,
  moved: search.moved === "access" ? "access" : undefined,
});

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
    options: {
      component?: unknown;
      params?: unknown;
      validateSearch?: unknown;
      beforeLoad?: unknown;
    } = {},
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
    // The new-site wizard. Its slugs are static (`new` outranks the `$siteId` pattern below); an
    // address from before the wizard, such as /sites/new/network, redirects to the step it became.
    page("site-config", "sites/new/$step", {
      component: lazyRouteComponent(() => import("../pages/sites/NewSiteRoute"), "NewSiteRoute"),
      params: {
        parse: (raw: Record<string, string>) => {
          const step = typeof raw.step === "string" ? canonicalWizardStep(raw.step) : null;
          if (step === null) throw notFound();
          return { step: raw.step as string };
        },
        stringify: (params: Record<string, string>) => ({ step: params.step }),
      },
      beforeLoad: ({ params }: { params: { step: string } }) => {
        const step = canonicalWizardStep(params.step);
        if (step !== null && step !== params.step) {
          throw redirect({ to: `/sites/new/${step}`, replace: true } as never);
        }
      },
    }),
    page("site-config", "sites/$siteId/$section", {
      component: lazyRouteComponent(
        () => import("../pages/sites/SiteDetailPage"),
        "SiteDetailPage",
      ),
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
    page("case", "cases", {
      component: lazyRouteComponent(() => import("../pages/cases/CasesPage"), "CasesPage"),
      validateSearch: (search: Record<string, unknown>) => ({
        moved: search.moved === "holds" || search.moved === "exports" ? search.moved : undefined,
      }),
    }),
    page("case", "cases/jobs/$jobId", {
      params: idParams("jobId", jobPattern),
      component: lazyRouteComponent(() => import("../pages/cases/CasesPage"), "CasesPage"),
    }),
    page("case", "cases/$caseId", {
      params: idParams("caseId", casePattern),
      component: lazyRouteComponent(
        () => import("../pages/cases/CaseDetailPage"),
        "CaseDetailPage",
      ),
    }),
    page("case", "cases/$caseId/$tab", {
      params: {
        parse: (raw: Record<string, string>) => {
          const { caseId, tab } = raw;
          if (
            typeof caseId !== "string" ||
            typeof tab !== "string" ||
            !casePattern.test(caseId) ||
            !(caseTabs as readonly string[]).includes(tab)
          ) {
            throw notFound();
          }
          return { caseId, tab };
        },
        stringify: (params: Record<string, string>) => ({
          caseId: params.caseId,
          tab: params.tab,
        }),
      },
      component: lazyRouteComponent(
        () => import("../pages/cases/CaseDetailPage"),
        "CaseDetailPage",
      ),
    }),
    page("approvals", "approvals", {
      component: lazyRouteComponent(
        () => import("../pages/approvals/ApprovalsPage"),
        "ApprovalsPage",
      ),
      validateSearch: approvalsSearch,
    }),
    page("approvals", "approvals/mine", {
      component: lazyRouteComponent(
        () => import("../pages/approvals/ApprovalsPage"),
        "ApprovalsPage",
      ),
      validateSearch: approvalsSearch,
    }),
    page("approvals", "evidence/access", { beforeLoad: movedTo("/approvals", "access") }),
    // Retired addresses: the pages moved into the case center, so the old bookmarks keep working.
    page("case", "evidence/holds", { beforeLoad: movedTo("/cases", "holds") }),
    page("case", "evidence/exports", { beforeLoad: movedTo("/cases", "exports") }),
    page("audit-health", "operations/audit"),
    page("jobs", "operations/jobs"),
    // Anything the table above does not describe.
    page("not-found", "$", { component: components.NotFound }),
  ];

  return { routeTree: root.addChildren([shell.addChildren(children)]), pages };
}
