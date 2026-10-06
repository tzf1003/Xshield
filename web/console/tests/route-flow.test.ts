import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { ControlClient, type SiteRouteConfig } from "../src/api.ts";
import {
  canonicalJson,
  draftFromConfig,
  newRoute,
  type SiteConfigDraft,
} from "../src/sites/model/config.ts";
import { diffConfigs } from "../src/sites/model/diff.ts";
import {
  assessChangeRisk,
  explainApproval,
  needsIndependentApproval,
} from "../src/sites/model/risk.ts";
import {
  blockFits,
  blockOffered,
  emptyAuthBinding,
  emptyAuthRevoke,
  emptyIssuedBy,
  emptyPageActions,
  emptyResourceGrant,
  type FlowStash,
  grantTargetOptions,
  pageRootOptions,
  sensorBuilds,
  withAdmission,
  withBlock,
  withResponseMode,
  withSensorBuilds,
} from "../src/sites/model/route-flow.ts";
import { validateDraft } from "../src/sites/model/validation.ts";
import { REQUEST_ID, TOKEN } from "./fixtures.ts";

const LOOP_TEXT = readFileSync(
  new URL("../../../tests/site-config/browser-loop.json", import.meta.url),
  "utf8",
).trimEnd();
const loop = (): SiteConfigDraft => JSON.parse(LOOP_TEXT);
const DIGEST = "b2".repeat(32);
const KEY = "0123456789abcdef0123";

const route = (draft: SiteConfigDraft, id: string): SiteRouteConfig => {
  const found = draft.policy.routes.find((item) => item.operation_id === id);
  assert.ok(found, id);
  return found;
};
const replace = (draft: SiteConfigDraft, next: SiteRouteConfig): SiteConfigDraft => ({
  ...draft,
  policy: {
    ...draft.policy,
    routes: draft.policy.routes.map((item) =>
      item.operation_id === next.operation_id ? next : item,
    ),
  },
});
const byId = (routes: readonly SiteRouteConfig[]) =>
  Object.fromEntries(routes.map((item) => [item.operation_id, item]));

test("blocks are offered only where the contract lets the edge serve them", () => {
  const draft = loop();
  const fits = (id: string) =>
    (
      [
        "auth_binding",
        "auth_revoke",
        "sensor_html",
        "page_actions",
        "issued_by",
        "resource_grant",
      ] as const
    )
      .filter((block) => blockFits(route(draft, id), block))
      .join(",");
  assert.equal(fits("login.page"), "");
  assert.equal(fits("auth.login"), "auth_binding");
  assert.equal(fits("app.page"), "sensor_html,page_actions");
  assert.equal(fits("orders.list"), "issued_by,resource_grant");
  assert.equal(fits("auth.logout"), "auth_revoke,resource_grant");
  // A page issues first-hop actions only: a resource route is not offered “由页面签发”.
  assert.equal(blockOffered(route(draft, "orders.read"), "issued_by"), false);
  assert.equal(blockOffered(route(draft, "orders.list"), "issued_by"), true);
});

test("switching the admission parks what no longer fits and restores it when switched back", () => {
  const login = route(loop(), "auth.login");
  const publicRoute = withAdmission(login, "public", {});
  assert.equal(publicRoute.route.auth_binding, undefined);
  assert.equal("auth_binding" in publicRoute.route, false, "the key goes, not just the value");
  assert.deepEqual(publicRoute.stash.auth_binding, login.auth_binding);
  const ui = withAdmission(publicRoute.route, "ui_action_required", publicRoute.stash);
  assert.equal(ui.route.source_action, "auth.login.open", "a UI action gets a source to edit");
  const back = withAdmission(ui.route, "auth_entry", ui.stash);
  assert.deepEqual(back.route, login);
  assert.deepEqual(back.stash, {});
});

test("SENSOR_HTML always brings a build to compute, and leaving it parks the page settings", () => {
  const page = route(loop(), "app.page");
  const json = withResponseMode(page, "BUFFERED_JSON", {});
  assert.equal(json.route.sensor_html, undefined);
  assert.equal(json.route.page_actions, undefined);
  assert.deepEqual(Object.keys(json.stash).sort(), ["page_actions", "sensor_html"]);
  assert.deepEqual(withResponseMode(json.route, "SENSOR_HTML", json.stash).route, page);

  const fresh = withResponseMode(newRoute({ operation_id: "p", path: "/p" }), "SENSOR_HTML", {});
  assert.deepEqual(sensorBuilds(fresh.route), [
    { adapter_revision: "", origin_sha256: "", injection_offset: Number.NaN },
  ]);
  // A page cannot also establish identity or qualify resources: those are parked, not lost.
  const list = route(loop(), "orders.list");
  const misclick = withResponseMode(list, "SENSOR_HTML", {});
  assert.equal(misclick.route.resource_grant, undefined);
  assert.deepEqual(withResponseMode(misclick.route, "BUFFERED_JSON", misclick.stash).route, list);
});

test("the build list writes back exactly what the server stores", () => {
  const page = route(loop(), "app.page");
  const builds = sensorBuilds(page);
  assert.equal(builds.length, 1);
  assert.equal("additional_adapters" in (withSensorBuilds(page, builds).sensor_html ?? {}), false);
  const two = withSensorBuilds(page, [
    ...builds,
    { adapter_revision: "app-r2", origin_sha256: "c".repeat(64), injection_offset: 120 },
  ]);
  assert.equal(two.sensor_html?.additional_adapters?.length, 1);
  assert.deepEqual(withSensorBuilds(two, sensorBuilds(two).slice(0, 1)), page);
});

test("cross-route choices come from the draft, never from free text", () => {
  const routes = loop().policy.routes;
  const self = routes.findIndex((item) => item.operation_id === "orders.list");
  assert.deepEqual(pageRootOptions(routes, self), [
    { value: "app.page", label: "app.page · GET /app", note: null },
  ]);
  assert.deepEqual(grantTargetOptions(routes, self), [
    { value: "orders.read", label: "orders.read · GET /orders/{order_id}", note: null },
  ]);
  // A SENSOR_HTML page without page actions is offered, with what it still lacks.
  const bare = routes.map((item) =>
    item.operation_id === "app.page" ? withBlock(item, "page_actions", undefined) : item,
  );
  assert.match(pageRootOptions(bare, self)[0]?.note ?? "", /页面签发动作/);
  // A route never chooses itself.
  const pageIndex = routes.findIndex((item) => item.operation_id === "app.page");
  assert.deepEqual(pageRootOptions(routes, pageIndex), []);
});

/**
 * The whole loop built the way the drawer builds it: every route starts as RoutesTab's “新增路由”
 * route and changes only through the drawer's edit functions, in an order an operator can follow
 * (a page before the actions it issues, a detail route before the list that qualifies it).
 */
function buildLoopThroughDrawer(page: { sha256: string; offset: number }): SiteRouteConfig[] {
  // Each drawer session has its own stash; a new route opens a new session.
  let stash: FlowStash = {};
  const added = (id: string, path: string) => {
    stash = {};
    return newRoute({
      operation_id: id,
      path,
      security_entry: "ui_action_required",
      source_action: `${id}.open`,
    });
  };
  const admit = (item: SiteRouteConfig, admission: SiteRouteConfig["security_entry"]) => {
    const next = withAdmission(item, admission, stash);
    stash = next.stash;
    return next.route;
  };
  const mode = (item: SiteRouteConfig, value: SiteRouteConfig["response_mode"]) => {
    const next = withResponseMode(item, value, stash);
    stash = next.stash;
    return next.route;
  };

  const login = admit(added("login.page", "/"), "public");

  let auth: SiteRouteConfig = {
    ...admit(added("auth.login", "/api/login"), "auth_entry"),
    method: "POST",
  };
  auth = mode({ ...auth, max_response_bytes: 1024 }, "BUFFERED_JSON");
  auth = withBlock(auth, "auth_binding", {
    ...emptyAuthBinding(),
    principal_pointer: "/identity/id",
    authorization_context_pointer: "/identity/authorization_context",
    bearer_pointer: "/access_token",
  });

  let app = mode(
    { ...admit(added("app.page", "/app"), "authenticated_root"), max_response_bytes: 16_384 },
    "SENSOR_HTML",
  );
  app = withSensorBuilds(app, [
    { adapter_revision: "app-r1", origin_sha256: page.sha256, injection_offset: page.offset },
  ]);
  app = withBlock(app, "page_actions", { ...emptyPageActions(), mapping_revision: "app-map-r1" });

  const read: SiteRouteConfig = {
    ...added("orders.read", "/orders/{order_id}"),
    source_action: "orders.open",
    resource_type: "order",
    view_profile: "customer_detail",
    resource_path_parameter: "order_id",
  };

  let list = mode(
    {
      ...added("orders.list", "/orders"),
      source_action: "app.orders.list",
      max_response_bytes: 4096,
    },
    "BUFFERED_JSON",
  );
  list = withBlock(list, "issued_by", emptyIssuedBy("app.page"));
  list = withBlock(list, "resource_grant", {
    ...emptyResourceGrant("orders.read"),
    items_pointer: "/orders",
    resource_pointer: "/id",
    target_mapping_revision: "orders-map-r1",
    max_items: 10,
    max_active_grants: 200,
  });

  let logout: SiteRouteConfig = {
    ...admit(added("auth.logout", "/api/logout"), "authenticated_root"),
    method: "POST",
  };
  logout = withBlock(
    mode({ ...logout, max_response_bytes: 256 }, "BUFFERED_JSON"),
    "auth_revoke",
    emptyAuthRevoke(),
  );

  return [login, auth, app, read, list, logout];
}

test("building the loop route by route through the drawer's edits gives exactly the golden loop", () => {
  const golden = loop();
  const sensor = route(golden, "app.page").sensor_html;
  assert.ok(sensor);
  const routes = buildLoopThroughDrawer({
    sha256: sensor.origin_sha256,
    offset: sensor.injection_offset,
  });
  // Route order is cosmetic to the server (no approval reason); the content is the loop's.
  assert.deepEqual(byId(routes), byId(golden.policy.routes));
  const draft = { ...golden, policy: { ...golden.policy, routes } };
  assert.deepEqual(validateDraft(draft), []);
  assert.deepEqual(diffConfigs(golden, draft), []);
  assert.deepEqual(assessChangeRisk(golden, draft), []);
});

const response = (value: unknown) =>
  new Response(JSON.stringify(value), {
    status: 200,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
const configBody = (config: unknown) => ({
  request_id: REQUEST_ID,
  tenant_id: "tenant_loop",
  site_id: "site_loop",
  found: true,
  desired_revision: 1,
  active_revision: 1,
  apply_state: "active",
  apply_id: "apply_1",
  reason_code: "EDGE_APPLY_CONFIRMED",
  requires_approval: false,
  config_digest: DIGEST,
  config: {
    ...(config as object),
    revision: 1,
    config_digest: DIGEST,
    updated_by: "author",
    created_at: "2026-10-06T08:00:00.000Z",
    updated_at: "2026-10-06T08:00:00.000Z",
    gateway_config: null,
  },
});

test("a block edited through the drawer is saved; every block it did not touch is sent as read", async (t) => {
  t.mock.method(globalThis, "fetch", async () => response(configBody(JSON.parse(LOOP_TEXT))));
  const read = await new ControlClient(TOKEN).siteConfig("site_loop");
  assert.ok(read.config);
  const draft = draftFromConfig(read.config);
  // The operator opens orders.list, shortens the issued action's lease and saves.
  const list = route(draft, "orders.list");
  assert.ok(list.issued_by);
  const edited = replace(
    draft,
    withBlock(list, "issued_by", { ...list.issued_by, ttl_seconds: 300 }),
  );
  let sent = "";
  t.mock.method(globalThis, "fetch", async (_path: string, options: RequestInit) => {
    sent = String(options.body);
    return response(configBody(JSON.parse(LOOP_TEXT)));
  });
  await new ControlClient(TOKEN).saveSiteConfig("site_loop", edited, KEY);
  const expected = JSON.parse(LOOP_TEXT) as SiteConfigDraft;
  const stored = route(expected, "orders.list");
  assert.ok(stored.issued_by);
  stored.issued_by.ttl_seconds = 300;
  assert.equal(canonicalJson(JSON.parse(sent)), canonicalJson(expected));
  // Every other route goes out byte for byte as it was read, in the server's member order.
  const sentRoutes = (JSON.parse(sent) as SiteConfigDraft).policy.routes;
  for (const [at, item] of (JSON.parse(LOOP_TEXT) as SiteConfigDraft).policy.routes.entries()) {
    if (item.operation_id === "orders.list") continue;
    assert.equal(JSON.stringify(sentRoutes[at]), JSON.stringify(item), item.operation_id);
  }
});

test("drawer edits show in the diff in operator words and under the right approval reasons", () => {
  const served = loop();
  let staged = served;
  const login = route(staged, "auth.login");
  assert.ok(login.auth_binding);
  staged = replace(
    staged,
    withBlock(login, "auth_binding", { ...login.auth_binding, credential_ttl_seconds: 900 }),
  );
  const app = route(staged, "app.page");
  staged = replace(
    staged,
    withSensorBuilds(app, [
      ...sensorBuilds(app),
      { adapter_revision: "app-r2", origin_sha256: "c".repeat(64), injection_offset: 120 },
    ]),
  );
  staged = replace(staged, { ...route(staged, "orders.read"), view_profile: "full" });
  staged = replace(staged, withBlock(route(staged, "auth.logout"), "auth_revoke", undefined));
  // A new first-hop action issued by the page.
  staged = {
    ...staged,
    policy: {
      ...staged.policy,
      routes: [
        ...staged.policy.routes,
        withBlock(
          newRoute({
            operation_id: "orders.export",
            // Not /orders/export: the {order_id} route would match it first.
            path: "/orders-export",
            security_entry: "ui_action_required",
            source_action: "app.orders.export",
          }),
          "issued_by",
          emptyIssuedBy("app.page"),
        ),
      ],
    },
  };
  assert.deepEqual(validateDraft(staged), []);

  const changes = diffConfigs(served, staged);
  const row = (id: string) => {
    const found = changes.find((change) => change.id === id);
    assert.ok(found, id);
    return found;
  };
  assert.equal(row("routes[auth.login].auth_binding").label, "路由 auth.login · 身份建立");
  assert.match(row("routes[auth.login].auth_binding").before, /凭证 30 分钟/);
  assert.match(row("routes[auth.login].auth_binding").after, /凭证 15 分钟/);
  assert.match(row("routes[app.page].sensor_html").after, /共 2 个构建/);
  assert.deepEqual(row("routes[orders.read].view_profile").facets, ["RESOURCE_GRANT_CHANGED"]);
  assert.equal(row("routes[auth.logout].auth_revoke").after, "（无）");
  const added = row("routes[orders.export]");
  assert.equal(added.kind, "added");
  assert.match(added.after, /由 app\.page 签发/);
  assert.deepEqual(added.facets, ["PAGE_ACTIONS_CHANGED"]);

  const explained = explainApproval(served, staged);
  const listed = (token: string) =>
    explained.reasons.find((reason) => reason.token === token)?.changes.map((change) => change.id);
  assert.deepEqual(
    explained.reasons.map((reason) => reason.token),
    [
      "ROUTES_CHANGED",
      "AUTH_ENTRY_CHANGED",
      "SENSOR_HTML_CHANGED",
      "PAGE_ACTIONS_CHANGED",
      "RESOURCE_GRANT_CHANGED",
    ],
  );
  assert.deepEqual(listed("AUTH_ENTRY_CHANGED"), [
    "routes[auth.login].auth_binding",
    "routes[auth.logout].auth_revoke",
  ]);
  // The page root is a member of both page facets, so its new build is listed under both.
  assert.deepEqual(listed("SENSOR_HTML_CHANGED"), ["routes[app.page].sensor_html"]);
  assert.deepEqual(listed("PAGE_ACTIONS_CHANGED"), [
    "routes[app.page].sensor_html",
    "routes[orders.export]",
  ]);
  assert.deepEqual(listed("RESOURCE_GRANT_CHANGED"), ["routes[orders.read].view_profile"]);
  assert.equal(listed("ROUTES_CHANGED")?.length, 5);
  assert.deepEqual(
    explained.reasons.filter((reason) => needsIndependentApproval(reason.token)).length,
    4,
  );
});
