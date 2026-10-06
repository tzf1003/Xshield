import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import type { SiteRouteConfig } from "../src/api.ts";
import { emptyDraft, ENTRY_OPERATION_ID, type SiteConfigDraft } from "../src/sites/model/config.ts";
import { digestPageBytes } from "../src/sites/model/page-digest.ts";
import {
  applyRouteTemplate,
  browserLoopTemplate,
  routeTemplates,
  spaTemplate,
} from "../src/sites/model/route-templates.ts";
import {
  validateDraft,
  validateFlowReferences,
  validateRoute,
  validateRouteSet,
} from "../src/sites/model/validation.ts";

const repo = (path: string) => new URL(`../../../${path}`, import.meta.url);
/** The real-browser loop as the control plane stores it, and as it projects it for the edge. */
const LOOP = JSON.parse(readFileSync(repo("tests/site-config/browser-loop.json"), "utf8")) as {
  policy: { routes: SiteRouteConfig[] };
};
const LOOP_EDGE = JSON.parse(
  readFileSync(repo("tests/site-config/browser-loop.gateway.json"), "utf8"),
) as { operations: Record<string, unknown>[] };
/** The page the loop's origin serves (scripts/test_browser_loop.sh pins its digest and offset). */
const APP_HTML = new Uint8Array(readFileSync(repo("tests/browser-loop/app.html")));

const filled = (): SiteConfigDraft => ({
  ...emptyDraft(),
  display_name: "Demo",
  public_origin: "https://demo.example.com",
  upstream_address: "8.8.8.8:443",
  upstream_server_name: "origin.example.com",
});

const errors = (draft: SiteConfigDraft) => validateDraft(draft).map((issue) => issue.path);

/** What the drawer's “从页面源码计算” does to the app page: digest and offset of the real page. */
async function computePage(draft: SiteConfigDraft): Promise<SiteConfigDraft> {
  const result = await digestPageBytes(APP_HTML);
  assert.ok(result.ok);
  return {
    ...draft,
    policy: {
      ...draft.policy,
      routes: draft.policy.routes.map((route) =>
        route.sensor_html
          ? {
              ...route,
              sensor_html: {
                ...route.sensor_html,
                origin_sha256: result.digest.sha256,
                injection_offset: result.digest.injectionOffset,
              },
            }
          : route,
      ),
    },
  };
}

/**
 * `SiteConfig::gateway_config`'s per-route projection (crates/xshield-core/src/site/projection.rs):
 * unset members are omitted, an empty response mode without blocks emits no response rule, and
 * the SENSOR_HTML build is flattened into the response. The console has no projection of its
 * own, so the template is compared with the edge configuration structurally, through this.
 */
function project(route: SiteRouteConfig): Record<string, unknown> {
  const admission = {
    public: "PUBLIC",
    auth_entry: "AUTH_ENTRY",
    authenticated_root: "AUTHENTICATED_ROOT",
    ui_action_required: "UI_ACTION_REQUIRED",
    share_entry: "SHARE_ENTRY",
  }[route.security_entry];
  const present = <T>(key: string, value: T | null | undefined) =>
    value === null || value === undefined ? {} : { [key]: value };
  const sensor = route.sensor_html;
  const anyBlock =
    route.response_crypto !== null ||
    [route.resource_grant, route.auth_binding, route.auth_revoke, route.page_actions, sensor].some(
      (block) => block !== undefined,
    );
  const response =
    route.response_mode === "" && !anyBlock
      ? undefined
      : {
          mode: route.response_mode === "" ? "BUFFERED_JSON" : route.response_mode,
          max_bytes: route.max_response_bytes,
          ...present("adapter_revision", sensor?.adapter_revision),
          ...present("origin_sha256", sensor?.origin_sha256),
          ...present("injection_offset", sensor?.injection_offset),
          ...present("additional_adapters", sensor?.additional_adapters),
          ...present("page_actions", route.page_actions),
          ...present("crypto", route.response_crypto),
          ...present("resource_grant", route.resource_grant),
          ...present("auth_binding", route.auth_binding),
          ...present("auth_revoke", route.auth_revoke),
        };
  return {
    operation_id: route.operation_id,
    method: route.method,
    path: route.path,
    admission,
    ...present("source_action", route.source_action),
    ...present("resource_type", route.resource_type),
    ...present("view_profile", route.view_profile),
    ...present("resource_query_parameter", route.resource_query_parameter),
    ...present("resource_path_parameter", route.resource_path_parameter),
    ...present("request_crypto", route.request_crypto),
    ...present("issued_by", route.issued_by),
    ...present("response", response),
  };
}

test("the single-page example is valid by the server's own route rules as it stands", () => {
  const routes = spaTemplate.build({ entry_path: "/", security_entry: "ui_action_required" });
  assert.ok(routes.length > 0 && routes.length <= 256);
  const limits = emptyDraft().policy.limits;
  for (const route of routes) {
    assert.deepEqual(validateRoute(route, limits), [], route.operation_id);
  }
  assert.equal(validateRouteSet(routes).size, 0);
  assert.equal(validateFlowReferences(routes).size, 0);
  assert.deepEqual(validateDraft(applyRouteTemplate(filled(), spaTemplate)), []);
});

test("the browser loop example blocks saving until its page build is computed, and only then", () => {
  assert.deepEqual(
    routeTemplates.map((template) => template.id),
    ["spa-api", "browser-provenance-loop"],
  );
  const applied = applyRouteTemplate(filled(), browserLoopTemplate);
  // Exactly the two numbers that pin the operator's own page are missing; every other rule,
  // including each cross-route reference, already holds.
  assert.deepEqual(errors(applied), [
    "routes[app.page].sensor_html.origin_sha256",
    "routes[app.page].sensor_html.injection_offset",
  ]);
  const messages = validateDraft(applied).map((issue) => issue.message);
  assert.ok(
    messages.every((message) => message.includes("从页面源码计算")),
    messages.join("\n"),
  );
});

test("once computed from the page, the loop example passes validation and is the golden loop", async () => {
  const draft = await computePage(applyRouteTemplate(filled(), browserLoopTemplate));
  assert.deepEqual(validateDraft(draft), []);
  // Route for route, field for field and in the server's member order: the stored loop.
  assert.deepEqual(draft.policy.routes, LOOP.policy.routes);
  assert.equal(JSON.stringify(draft.policy.routes), JSON.stringify(LOOP.policy.routes));
  // And the operations the edge would compile are those of scripts/test_browser_loop.sh.
  assert.deepEqual(draft.policy.routes.map(project), LOOP_EDGE.operations);
});

test("applying a template replaces only the routes, and turns the sensor on for SENSOR_HTML pages", () => {
  assert.match(spaTemplate.description, /示例/);
  assert.match(spaTemplate.description, /不是推荐/);
  assert.match(browserLoopTemplate.description, /示例/);
  assert.match(browserLoopTemplate.description, /从页面源码计算/);
  const before = filled();
  const strip = (draft: SiteConfigDraft) => ({
    ...draft,
    sensor_enabled: false,
    policy: { ...draft.policy, routes: [] },
  });
  const spa = applyRouteTemplate(before, spaTemplate);
  assert.equal(spa.sensor_enabled, false, "the single-page example needs no sensor");
  assert.deepEqual(strip(spa), strip(before));
  const loop = applyRouteTemplate(before, browserLoopTemplate);
  assert.equal(loop.sensor_enabled, true);
  assert.deepEqual(strip(loop), strip(before));
  assert.equal(before.policy.routes.length, 0, "the input is not mutated");
  assert.equal(before.sensor_enabled, false, "the input is not mutated");
  // Without the sensor the SENSOR_HTML page could not be served, and validation says so.
  const withoutSensor = { ...loop, sensor_enabled: false };
  assert.ok(errors(withoutSensor).includes("sensor_enabled"));
});

test("the template's entry route is the draft's entry route, whatever its path and admission", () => {
  for (const [path, entry] of [
    ["/", "ui_action_required"],
    ["/app", "authenticated_root"],
    ["/start", "public"],
  ] as const) {
    const applied = applyRouteTemplate(
      { ...filled(), entry_path: path, security_entry: entry },
      spaTemplate,
    );
    const first = applied.policy.routes[0];
    assert.equal(first?.operation_id, ENTRY_OPERATION_ID);
    assert.equal(first?.path, path);
    assert.equal(first?.security_entry, entry);
    assert.equal(first?.source_action, entry === "ui_action_required" ? "protected.entry" : null);
    assert.deepEqual(validateDraft(applied), []);
  }
});
