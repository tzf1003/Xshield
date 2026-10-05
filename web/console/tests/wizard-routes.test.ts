import assert from "node:assert/strict";
import { test } from "node:test";
import { isRedirect } from "@tanstack/react-router";
import {
  canonicalWizardStep,
  routeQueryKind,
  siteRoute,
  siteSections,
  wizardSteps,
} from "../src/admin-routes.ts";
import { createAppRouter } from "../src/router/create-router.ts";
import { breadcrumbs, visibleNav } from "../src/shell/nav-model.ts";

const blank = () => null;
const components = { Root: blank, Shell: blank, NotFound: blank, Pending: blank, Failure: blank };

test("the wizard has five steps, in the order of the product's flow", () => {
  assert.deepEqual(
    wizardSteps.map(([key]) => key),
    ["basics", "upstream", "entry", "routes", "review"],
  );
  assert.deepEqual(
    wizardSteps.map(([, title]) => title),
    ["基本信息", "上游与监听", "入口与模式", "首批路由", "校验与保存"],
  );
});

test("every wizard slug and every address from before the wizard maps to a step", () => {
  for (const [key] of wizardSteps) assert.equal(canonicalWizardStep(key), key);
  const expected: Record<string, string> = {
    overview: "basics",
    network: "basics",
    "security-entry": "entry",
    routes: "routes",
    identity: "review",
    crypto: "review",
    "waf-limits": "review",
    policies: "review",
    releases: "basics",
    audit: "basics",
  };
  // Every old section name has an answer, so no bookmark of the old flow can 404.
  for (const [section] of siteSections) {
    assert.equal(canonicalWizardStep(section), expected[section], section);
  }
  for (const bad of ["", "Basics", "basics ", "constructor", "__proto__", "toString", "x"]) {
    assert.equal(canonicalWizardStep(bad), null, JSON.stringify(bad));
  }
});

test("only wizard steps and the old section names resolve under /sites/new", () => {
  for (const [key] of wizardSteps) {
    assert.deepEqual(siteRoute(`/sites/new/${key}`), {
      siteId: "new",
      section: key,
      creating: true,
    });
    assert.equal(routeQueryKind(`/sites/new/${key}`), "site-config");
  }
  for (const [section] of siteSections) {
    assert.equal(siteRoute(`/sites/new/${section}`)?.creating, true, section);
  }
  for (const bad of [
    "/sites/new/unknown",
    "/sites/new/basics/extra",
    "/sites/new/",
    "/sites/new",
  ]) {
    assert.equal(routeQueryKind(bad), "not-found", bad);
  }
  // An ordinary site is not a wizard, and a wizard step is not one of its sections.
  assert.deepEqual(siteRoute("/sites/site_a/network"), {
    siteId: "site_a",
    section: "network",
    creating: false,
  });
  assert.equal(siteRoute("/sites/site_a/basics"), null);
});

test("the wizard route redirects an address from before the wizard to the step it became", () => {
  const { pages } = createAppRouter(components);
  const wizard = pages.find((page) => page.path === "sites/new/$step");
  assert.ok(wizard);
  const beforeLoad = (
    wizard.route.options as { beforeLoad?: (context: { params: { step: string } }) => void }
  ).beforeLoad;
  assert.ok(beforeLoad, "the wizard route has a beforeLoad hook");
  for (const [old, now] of [
    ["network", "basics"],
    ["security-entry", "entry"],
    ["waf-limits", "review"],
    ["overview", "basics"],
  ] as const) {
    assert.throws(
      () => beforeLoad({ params: { step: old } }),
      (error: unknown) =>
        isRedirect(error) &&
        (error.options as { to?: string; replace?: boolean }).to === `/sites/new/${now}` &&
        (error.options as { replace?: boolean }).replace === true,
      old,
    );
  }
  // A current slug, and a slug that already is its own step, are left alone.
  for (const current of ["basics", "upstream", "entry", "routes", "review"]) {
    assert.doesNotThrow(() => beforeLoad({ params: { step: current } }), current);
  }
});

test("the wizard route outranks a site named new, and an unknown step is not found", () => {
  const { router, pages } = createAppRouter(components);
  const leaf = (path: string) => router.matchRoutes(path).at(-1);
  const wizard = pages.find((page) => page.path === "sites/new/$step");
  assert.ok(wizard, "the wizard route is declared");
  assert.equal(leaf("/sites/new/basics")?.routeId, wizard.route.id);
  assert.notEqual(leaf("/sites/other/basics")?.routeId, wizard.route.id);
  assert.ok(
    router.matchRoutes("/sites/new/unknown").some((match) => match.paramsError !== undefined),
  );
});

test("breadcrumbs name the wizard and its step", () => {
  const groups = visibleNav(null, "site_demo");
  assert.deepEqual(breadcrumbs("/sites/new/review", groups), [
    { label: "站点" },
    { label: "新建站点" },
    { label: "校验与保存" },
  ]);
  // The old address keeps a sensible trail until the redirect lands.
  assert.deepEqual(breadcrumbs("/sites/new/network", groups).at(-1), { label: "基本信息" });
  assert.deepEqual(breadcrumbs("/sites/site_a/network", groups).at(-1), { label: "网络" });
});
