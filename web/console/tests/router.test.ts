import assert from "node:assert/strict";
import { test } from "node:test";
import { createMemoryHistory } from "@tanstack/react-router";
import { type QueryKind, routeQueryKind, siteSections } from "../src/admin-routes.ts";
import { createAppRouter } from "../src/router/create-router.ts";

const blank = () => null;
const components = { Root: blank, Shell: blank, NotFound: blank, Pending: blank, Failure: blank };

/** The page kind the TanStack route tree resolves a path to, or "not-found". */
function routerKind(path: string): QueryKind {
  const { router, pages } = createAppRouter(components, {
    history: createMemoryHistory({ initialEntries: [path] }),
  });
  const matches = router.matchRoutes(path);
  if (matches.some((match) => match.paramsError !== undefined)) return "not-found";
  const leaf = matches.at(-1);
  return pages.find((page) => page.route.id === leaf?.routeId)?.kind ?? "not-found";
}

const uuid = (n: number) => `018f2a3b-4c5d-7000-8000-${String(n).padStart(12, "0")}`;
const ids = {
  req: `req_${uuid(1)}`,
  mdl: `mdl_${uuid(2)}`,
  agt: `agt_${uuid(3)}`,
  grant: `grant_${uuid(4)}`,
  auth: `auth_${uuid(5)}`,
  calr: `calr_${uuid(6)}`,
};

const valid = [
  "/",
  "/access/session",
  "/sites",
  "/sites/new/network",
  "/sites/new/basics",
  "/sites/new/review",
  "/sites/site_alpha.v2-1/overview",
  ...siteSections.map(([section]) => `/sites/site_a/${section}`),
  "/admin/api-keys",
  "/investigation/requests",
  "/investigation/models",
  "/investigation/models/lookup",
  "/investigation/agents",
  "/investigation/grants",
  "/investigation/bindings",
  "/investigation/calibration",
  "/investigation/search",
  `/investigation/requests/${ids.req}`,
  `/investigation/models/${ids.mdl}`,
  `/investigation/agents/${ids.agt}`,
  `/investigation/grants/${ids.grant}`,
  `/investigation/bindings/${ids.auth}`,
  `/investigation/calibration/${ids.calr}`,
  "/cases",
  "/evidence/access",
  "/evidence/holds",
  "/evidence/exports",
  "/operations/audit",
  "/operations/jobs",
];

const malformed = [
  "/sites/a/unknown",
  "/sites/%2f/network",
  "/sites/a%2Fb/network",
  "/sites/a/network/extra",
  `/sites/${"a".repeat(129)}/network`,
  "/investigation/models-extra",
  "/investigation/models/lookup/extra",
  `/investigation/requests/${ids.req}/suffix`,
  `/investigation/requests/${ids.req.toUpperCase()}`,
  `/investigation/requests/${ids.mdl}`,
  "/investigation/requests/req_123",
  `/investigation/models/${ids.req}`,
  `/investigation/agents/${ids.auth}`,
  `/investigation/calibration/${ids.grant}`,
  "/constructor",
  "/__proto__",
  "/unknown",
  "/Cases",
  "/INVESTIGATION/requests",
  "/cases/extra",
];

test("every current path resolves to the same page kind as the hand-written router did", () => {
  for (const path of valid) {
    assert.notEqual(routeQueryKind(path), "not-found", `oracle accepts ${path}`);
    assert.equal(routerKind(path), routeQueryKind(path), path);
  }
});

test("malformed addresses, bad IDs and case changes are not found, as before", () => {
  for (const path of malformed) {
    assert.equal(routeQueryKind(path), "not-found", `oracle rejects ${path}`);
    assert.equal(routerKind(path), "not-found", path);
  }
});

test("the router tolerates a trailing slash; the strict oracle the shell consults first does not", () => {
  // TanStack matches `/cases/` to the cases route and, with `trailingSlash: "preserve"`, leaves
  // the URL alone. The shell asks routeQueryKind() before rendering and shows "page not found",
  // exactly as the hand-written router did (e2e: tests/shell.spec.ts).
  for (const path of ["/cases/", "/sites/", "/investigation/requests/"]) {
    assert.notEqual(routerKind(path), "not-found", `router is lenient for ${path}`);
    assert.equal(routeQueryKind(path), "not-found", `oracle is strict for ${path}`);
  }
});

test("every page kind the shell knows is reachable through exactly the declared routes", () => {
  const { pages } = createAppRouter(components);
  const kinds = new Set(pages.map((page) => page.kind));
  for (const kind of [
    "overview",
    "session",
    "site-list",
    "site-config",
    "api-keys",
    "request",
    "model",
    "model-list",
    "agent",
    "grant",
    "binding",
    "calibration-report",
    "search",
    "case",
    "access",
    "hold",
    "export",
    "audit-health",
    "jobs",
  ] as QueryKind[]) {
    assert.ok(kinds.has(kind), `no route renders ${kind}`);
  }
});

test("the router stores nothing in the browser and restores no scroll state", () => {
  const { router } = createAppRouter(components);
  assert.equal(router.options.scrollRestoration ?? false, false);
  assert.equal(router.options.caseSensitive, true);
  assert.equal(router.options.trailingSlash, "preserve");
});
