import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { ApiError, ControlClient, type SiteRouteConfig } from "../src/api.ts";
import {
  canonicalJson,
  configFromStored,
  draftFromConfig,
  type SiteConfigDraft,
} from "../src/sites/model/config.ts";
import { diffConfigs } from "../src/sites/model/diff.ts";
import {
  assessChangeRisk,
  explainApproval,
  independentApprovalTokens,
} from "../src/sites/model/risk.ts";
import { validateDraft, validateRoute } from "../src/sites/model/validation.ts";
import { REQUEST_ID, TOKEN } from "./fixtures.ts";

/**
 * The real-browser loop topology exactly as the server stores and returns it (serde field order,
 * unset blocks omitted). The Rust tests pin these bytes to `serde_json::to_string_pretty`.
 */
const LOOP_TEXT = readFileSync(
  new URL("../../../tests/site-config/browser-loop.json", import.meta.url),
  "utf8",
).trimEnd();
const loop = (): Record<string, unknown> => JSON.parse(LOOP_TEXT);

const DIGEST = "b2".repeat(32);
const KEY = "0123456789abcdef0123";

const response = (value: unknown, status = 200) =>
  new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });

/** `GET /sites/{id}/config` for a stored configuration. */
function configBody(config: Record<string, unknown>) {
  return {
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
      ...config,
      revision: 1,
      config_digest: DIGEST,
      updated_by: "author",
      created_at: "2026-10-06T08:00:00.000Z",
      updated_at: "2026-10-06T08:00:00.000Z",
      gateway_config: null,
    },
  };
}

async function readDraft(t: test.TestContext, config: Record<string, unknown>) {
  t.mock.method(globalThis, "fetch", async () => response(configBody(config)));
  const read = await new ControlClient(TOKEN).siteConfig("site_loop");
  assert.ok(read.config);
  return draftFromConfig(read.config);
}

const route = (draft: SiteConfigDraft, id: string): SiteRouteConfig => {
  const found = draft.policy.routes.find((item) => item.operation_id === id);
  assert.ok(found, id);
  return found;
};

test("the loop topology round-trips byte for byte through decode, draft and save", async (t) => {
  const draft = await readDraft(t, loop());
  // The draft is the stored configuration, in the server's own serialization.
  assert.equal(JSON.stringify(draft, null, 2), LOOP_TEXT);
  let sent = "";
  t.mock.method(globalThis, "fetch", async (_path: string, options: RequestInit) => {
    sent = String(options.body);
    return response(configBody(loop()));
  });
  await new ControlClient(TOKEN).saveSiteConfig("site_loop", draft, KEY);
  assert.equal(sent, JSON.stringify(loop()), "the save sends exactly what was read");
});

test("editing other fields or routes never drops or defaults a flow block", async (t) => {
  const draft = await readDraft(t, loop());
  const edited: SiteConfigDraft = structuredClone({ ...draft, display_name: "Renamed" });
  // The route drawer edits a structured clone and spreads its changes over it.
  const list = route(edited, "orders.list");
  edited.policy.routes = edited.policy.routes.map((item) =>
    item === list ? { ...structuredClone(item), path: "/orders-all" } : item,
  );
  const sent = JSON.parse(JSON.stringify(edited));
  const stored = loop() as { policy: { routes: Record<string, unknown>[] } };
  stored.policy.routes[3] = { ...stored.policy.routes[3], path: "/orders-all" };
  assert.deepEqual(sent.policy, stored.policy);
  for (const key of ["issued_by", "resource_grant"] as const) {
    assert.deepEqual(route(edited, "orders.list")[key], route(draft, "orders.list")[key]);
  }
});

test("a stored revision is read with every flow block and in the same order", () => {
  const stored = configFromStored(loop());
  assert.ok(stored);
  assert.equal(JSON.stringify(stored, null, 2), LOOP_TEXT);
  // `auth_entry` was read back as `public` before; the approval explanation then lied.
  assert.equal(route(stored, "auth.login").security_entry, "auth_entry");
});

test("the decoder refuses members it does not model instead of dropping them on save", async (t) => {
  const refuses = async (mutate: (config: Record<string, unknown>) => void) => {
    const config = loop();
    mutate(config);
    t.mock.method(globalThis, "fetch", async () => response(configBody(config)));
    await assert.rejects(
      new ControlClient(TOKEN).siteConfig("site_loop"),
      (error: unknown) => error instanceof ApiError && error.code === "INVALID_RESPONSE",
    );
  };
  const routes = (config: Record<string, unknown>) =>
    (config.policy as { routes: Record<string, Record<string, unknown>>[] }).routes;
  await refuses((config) => {
    (routes(config)[3] as Record<string, unknown>).share_issue = { success_status: 200 };
  });
  await refuses((config) => {
    (routes(config)[1] as Record<string, Record<string, unknown>>).auth_binding = {
      ...(routes(config)[1]?.auth_binding ?? {}),
      scope: "all",
    };
  });
  await refuses((config) => {
    const page = routes(config)[2] as Record<string, Record<string, unknown>>;
    page.sensor_html = { ...page.sensor_html, additional_adapters: [] };
  });
  await refuses((config) => {
    (config.policy as Record<string, unknown>).future_policy_member = true;
  });
  await refuses((config) => {
    (routes(config)[0] as Record<string, unknown>).security_entry = "service_identity";
  });
});

test("the loop topology has no validation finding: every flow block is editable in the console", async (t) => {
  const draft = await readDraft(t, loop());
  // The "only through the API" warning is gone with the editor: nothing is left to warn about.
  assert.deepEqual(validateDraft(draft), []);
});

test("the console mirrors the flow rules of xshield_core::site::flow", async (t) => {
  const base = await readDraft(t, loop());
  const errors = (mutate: (draft: SiteConfigDraft) => void) => {
    const draft = structuredClone(base);
    mutate(draft);
    return validateDraft(draft)
      .filter((issue) => issue.severity === "error")
      .map((issue) => issue.path);
  };
  const cases: [string, (draft: SiteConfigDraft) => void, string][] = [
    [
      "binding on a root",
      (d) => {
        route(d, "auth.login").security_entry = "authenticated_root";
      },
      "routes[auth.login].auth_binding",
    ],
    [
      "shared pointer",
      (d) => {
        const binding = route(d, "auth.login").auth_binding;
        assert.ok(binding);
        binding.bearer_pointer = binding.principal_pointer;
      },
      "routes[auth.login].auth_binding.bearer_pointer",
    ],
    [
      "pointer with a bare ~",
      (d) => {
        const binding = route(d, "auth.login").auth_binding;
        assert.ok(binding);
        binding.principal_pointer = "/identity/~2id";
      },
      "routes[auth.login].auth_binding.principal_pointer",
    ],
    [
      "credential outlives the session",
      (d) => {
        const binding = route(d, "auth.login").auth_binding;
        assert.ok(binding);
        binding.credential_ttl_seconds = 7200;
      },
      "routes[auth.login].auth_binding.credential_ttl_seconds",
    ],
    [
      "binding without a body",
      (d) => {
        const binding = route(d, "auth.login").auth_binding;
        assert.ok(binding);
        binding.success_status = 204;
      },
      "routes[auth.login].auth_binding.success_status",
    ],
    [
      "revoke status 205",
      (d) => {
        route(d, "auth.logout").auth_revoke = { success_status: 205 };
      },
      "routes[auth.logout].auth_revoke.success_status",
    ],
    [
      "revoke on an authentication entry",
      (d) => {
        route(d, "auth.login").auth_revoke = { success_status: 200 };
      },
      "routes[auth.login].auth_revoke",
    ],
    [
      "sensor mode without adapter",
      (d) => {
        delete route(d, "app.page").sensor_html;
      },
      "routes[app.page].response_mode",
    ],
    [
      "offset at the limit",
      (d) => {
        const sensor = route(d, "app.page").sensor_html;
        assert.ok(sensor);
        sensor.injection_offset = 16_384;
      },
      "routes[app.page].sensor_html.injection_offset",
    ],
    [
      "offset not computed yet",
      (d) => {
        const sensor = route(d, "app.page").sensor_html;
        assert.ok(sensor);
        sensor.injection_offset = Number.NaN;
      },
      "routes[app.page].sensor_html.injection_offset",
    ],
    [
      "uppercase digest",
      (d) => {
        const sensor = route(d, "app.page").sensor_html;
        assert.ok(sensor);
        sensor.origin_sha256 = sensor.origin_sha256.toUpperCase();
      },
      "routes[app.page].sensor_html.origin_sha256",
    ],
    [
      "a second build repeats the digest",
      (d) => {
        const sensor = route(d, "app.page").sensor_html;
        assert.ok(sensor);
        sensor.additional_adapters = [
          { adapter_revision: "app-r2", origin_sha256: sensor.origin_sha256, injection_offset: 10 },
        ];
      },
      "routes[app.page].sensor_html.additional_adapters.0.origin_sha256",
    ],
    [
      "sixteen additional builds",
      (d) => {
        const sensor = route(d, "app.page").sensor_html;
        assert.ok(sensor);
        sensor.additional_adapters = Array.from({ length: 16 }, (_, index) => ({
          adapter_revision: `app-x${index}`,
          origin_sha256: index.toString(16).padStart(64, "0"),
          injection_offset: 10,
        }));
      },
      "routes[app.page].sensor_html",
    ],
    [
      "a page that also qualifies resources",
      (d) => {
        const list = route(d, "orders.list").resource_grant;
        assert.ok(list);
        route(d, "app.page").resource_grant = structuredClone(list);
      },
      "routes[app.page].sensor_html",
    ],
    [
      "no live page allowed",
      (d) => {
        const page = route(d, "app.page").page_actions;
        assert.ok(page);
        page.max_active_pages = 0;
      },
      "routes[app.page].page_actions.max_active_pages",
    ],
    [
      "sensor disabled",
      (d) => {
        d.sensor_enabled = false;
      },
      "sensor_enabled",
    ],
    [
      "public page root",
      (d) => {
        route(d, "app.page").security_entry = "public";
      },
      "routes[app.page].page_actions",
    ],
    [
      "issued resource route",
      (d) => {
        route(d, "orders.read").issued_by = { page_operation_id: "app.page", ttl_seconds: 60 };
      },
      "routes[orders.read].issued_by",
    ],
    [
      "issued action lease of zero",
      (d) => {
        route(d, "orders.list").issued_by = { page_operation_id: "app.page", ttl_seconds: 0 };
      },
      "routes[orders.list].issued_by.ttl_seconds",
    ],
    [
      "unknown page",
      (d) => {
        route(d, "orders.list").issued_by = { page_operation_id: "missing", ttl_seconds: 60 };
      },
      "routes[orders.list].issued_by.page_operation_id",
    ],
    [
      "page chosen that issues nothing",
      (d) => {
        delete route(d, "app.page").page_actions;
      },
      "routes[orders.list].issued_by.page_operation_id",
    ],
    [
      "unused page actions",
      (d) => {
        delete route(d, "orders.list").issued_by;
      },
      "routes[app.page].page_actions",
    ],
    [
      "grant on a public route",
      (d) => {
        const list = route(d, "orders.list");
        list.security_entry = "public";
        list.source_action = null;
        delete list.issued_by;
        delete route(d, "app.page").page_actions;
      },
      "routes[orders.list].resource_grant",
    ],
    [
      "missing grant target",
      (d) => {
        const grant = route(d, "orders.list").resource_grant;
        assert.ok(grant);
        grant.target_operation_id = "orders.gone";
      },
      "routes[orders.list].resource_grant.target_operation_id",
    ],
    [
      "grant target without a resource",
      (d) => {
        const target = route(d, "orders.read");
        target.resource_type = null;
        target.view_profile = null;
        target.resource_path_parameter = null;
        target.path = "/orders/all";
      },
      "routes[orders.list].resource_grant.target_operation_id",
    ],
    [
      "grant with a bare ~ in the item pointer",
      (d) => {
        const grant = route(d, "orders.list").resource_grant;
        assert.ok(grant);
        grant.items_pointer = "/orders~";
      },
      "routes[orders.list].resource_grant.items_pointer",
    ],
    [
      "grant of zero items",
      (d) => {
        const grant = route(d, "orders.list").resource_grant;
        assert.ok(grant);
        grant.max_items = 0;
      },
      "routes[orders.list].resource_grant.max_items",
    ],
    [
      "a logout that also qualifies resources",
      (d) => {
        const grant = route(d, "orders.list").resource_grant;
        assert.ok(grant);
        route(d, "auth.logout").resource_grant = structuredClone(grant);
      },
      "routes[auth.logout].resource_grant",
    ],
    [
      "one action with two meanings",
      (d) => {
        d.policy.routes.push({
          ...structuredClone(route(d, "orders.list")),
          operation_id: "orders.list.shadow",
          path: "/orders-shadow",
          resource_grant: undefined,
        });
      },
      "routes[orders.list.shadow].source_action",
    ],
    [
      "one target action with two meanings",
      (d) => {
        // A second grant names the detail action under the page's own mapping revision, where
        // `app.orders.list` already means the page-issued list; reusing the list's action for
        // the detail gives one key two meanings.
        route(d, "orders.read").source_action = "app.orders.list";
        const grant = route(d, "orders.list").resource_grant;
        assert.ok(grant);
        grant.target_mapping_revision = "app-map-r1";
      },
      "routes[orders.list].resource_grant.target_mapping_revision",
    ],
    [
      "operation id outside the edge alphabet",
      (d) => {
        route(d, "login.page").operation_id = "login:page";
      },
      "routes[login:page].operation_id",
    ],
  ];
  assert.deepEqual(
    errors(() => {}),
    [],
  );
  for (const [label, mutate, path] of cases) {
    assert.ok(errors(mutate).includes(path), `${label}: ${errors(mutate).join(", ")}`);
  }
  // An observed request body cannot feed a response with identity effects.
  const login = structuredClone(route(base, "auth.login"));
  login.request_crypto = { mode: "OBSERVE", adapter_revision: "observe-v1" };
  assert.ok(
    validateRoute(login, { max_response_body_bytes: 16_777_216 }).some(
      (issue) => issue.field === "request_crypto" && issue.severity === "error",
    ),
  );
});

test("flow changes name their facet like assess_change_risk, in both directions", async (t) => {
  const base = await readDraft(t, loop());
  assert.deepEqual(assessChangeRisk(null, base), [
    "ACTIVATION",
    "AUTH_ENTRY_CHANGED",
    "SENSOR_HTML_CHANGED",
    "PAGE_ACTIONS_CHANGED",
    "RESOURCE_GRANT_CHANGED",
  ]);
  assert.deepEqual(independentApprovalTokens, [
    "AUTH_ENTRY_CHANGED",
    "SENSOR_HTML_CHANGED",
    "PAGE_ACTIONS_CHANGED",
    "RESOURCE_GRANT_CHANGED",
    "QUERY_PAGINATION_CHANGED",
    "SHARE_ISSUE_CHANGED",
  ]);
  // The cases of risk.rs `flow_route_changes_name_their_facet_in_both_directions`.
  const cases: [string, (draft: SiteConfigDraft) => void, string[]][] = [
    [
      "credential lease",
      (d) => {
        const binding = route(d, "auth.login").auth_binding;
        assert.ok(binding);
        binding.credential_ttl_seconds = 900;
      },
      ["ROUTES_CHANGED", "AUTH_ENTRY_CHANGED"],
    ],
    [
      "logout no longer revokes",
      (d) => {
        delete route(d, "auth.logout").auth_revoke;
      },
      ["ROUTES_CHANGED", "AUTH_ENTRY_CHANGED"],
    ],
    [
      "approved page build",
      (d) => {
        const sensor = route(d, "app.page").sensor_html;
        assert.ok(sensor);
        sensor.origin_sha256 = "a".repeat(64);
      },
      ["ROUTES_CHANGED", "SENSOR_HTML_CHANGED", "PAGE_ACTIONS_CHANGED"],
    ],
    [
      "grant item bound",
      (d) => {
        const grant = route(d, "orders.list").resource_grant;
        assert.ok(grant);
        grant.max_items = 50;
      },
      ["ROUTES_CHANGED", "PAGE_ACTIONS_CHANGED", "RESOURCE_GRANT_CHANGED"],
    ],
    [
      "pagination added to the grant-issuing list",
      (d) => {
        route(d, "orders.list").query_pagination = {
          parameters: [{ name: "page", kind: "page" }],
        };
      },
      [
        "ROUTES_CHANGED",
        "PAGE_ACTIONS_CHANGED",
        "RESOURCE_GRANT_CHANGED",
        "QUERY_PAGINATION_CHANGED",
      ],
    ],
    [
      "grant target view",
      (d) => {
        route(d, "orders.read").view_profile = "full";
      },
      ["ROUTES_CHANGED", "RESOURCE_GRANT_CHANGED"],
    ],
    [
      "the public login page",
      (d) => {
        route(d, "login.page").max_response_bytes = 4096;
      },
      ["ROUTES_CHANGED"],
    ],
  ];
  for (const [label, mutate, expected] of cases) {
    const changed = structuredClone(base);
    mutate(changed);
    assert.deepEqual(assessChangeRisk(base, changed), expected, `${label}, forwards`);
    assert.deepEqual(assessChangeRisk(changed, base), expected, `${label}, backwards`);
  }
  const reordered = structuredClone(base);
  reordered.policy.routes.reverse();
  assert.deepEqual(assessChangeRisk(base, reordered), []);
});

test("a flow block change shows in the diff and under both approval reasons", async (t) => {
  const base = await readDraft(t, loop());
  const changed = structuredClone(base);
  const grant = route(changed, "orders.list").resource_grant;
  assert.ok(grant);
  grant.max_items = 20;
  const changes = diffConfigs(base, changed);
  assert.deepEqual(
    changes.map((change) => [change.id, change.risk]),
    [["routes[orders.list].resource_grant", "RESOURCE_GRANT_CHANGED"]],
  );
  assert.match(changes[0]?.before ?? "", /≤ 10 项/);
  assert.match(changes[0]?.after ?? "", /≤ 20 项/);
  const explained = explainApproval(base, changed);
  const listed = (token: string) =>
    explained.reasons.find((reason) => reason.token === token)?.changes.map((change) => change.id);
  assert.deepEqual(listed("RESOURCE_GRANT_CHANGED"), ["routes[orders.list].resource_grant"]);
  assert.deepEqual(listed("ROUTES_CHANGED"), ["routes[orders.list].resource_grant"]);
  // A cleared block and one that was never set are the same configuration.
  const cleared = structuredClone(base);
  route(cleared, "login.page").auth_binding = undefined;
  assert.equal(canonicalJson(cleared), canonicalJson(base));
  assert.deepEqual(diffConfigs(base, cleared), []);
});
