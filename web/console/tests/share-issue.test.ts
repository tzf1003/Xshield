import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { ApiError, ControlClient, type SiteRouteConfig } from "../src/api.ts";
import {
  configFromStored,
  draftFromConfig,
  type SiteConfigDraft,
} from "../src/sites/model/config.ts";
import { diffConfigs } from "../src/sites/model/diff.ts";
import { assessChangeRisk, needsIndependentApproval } from "../src/sites/model/risk.ts";
import {
  blockOffered,
  emptyShareIssue,
  shareTargetOptions,
  withAdmission,
  withBlock,
} from "../src/sites/model/route-flow.ts";
import { validateDraft } from "../src/sites/model/validation.ts";
import { REQUEST_ID, TOKEN } from "./fixtures.ts";

const SHARE_TEXT = readFileSync(
  new URL("../../../tests/site-config/share-flow.json", import.meta.url),
  "utf8",
).trimEnd();
const share = (): Record<string, unknown> => JSON.parse(SHARE_TEXT);
const DIGEST = "b3".repeat(32);
const KEY = "0123456789abcdef0123";

const response = (value: unknown) =>
  new Response(JSON.stringify(value), {
    status: 200,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });

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

const issuer = (draft: SiteConfigDraft) => {
  const block = route(draft, "records.share.issue").share_issue;
  assert.ok(block);
  return block;
};

test("a stored share scope round-trips byte for byte through decode, draft and save", async (t) => {
  const stored = share();
  const draft = await readDraft(t, stored);
  assert.equal(route(draft, "records.share.read").security_entry, "share_entry");
  let sent = "";
  t.mock.method(globalThis, "fetch", async (_path: string, options: RequestInit) => {
    sent = String(options.body);
    return response(configBody(stored));
  });
  await new ControlClient(TOKEN).saveSiteConfig("site_loop", draft, KEY);
  assert.deepEqual(JSON.parse(sent).policy, stored.policy);
  assert.equal(
    JSON.stringify(JSON.parse(sent).policy.routes),
    JSON.stringify((stored.policy as { routes: unknown[] }).routes),
    "member order is the server's",
  );
  // The approval reconstruction reads the same blocks from the stored revision.
  const fromStored = configFromStored(stored);
  assert.ok(fromStored);
  assert.deepEqual(issuer(fromStored), issuer(draft));
  assert.equal(route(fromStored, "records.share.read").security_entry, "share_entry");
  // The fixture is the server's canonical form.
  assert.equal(JSON.stringify(JSON.parse(SHARE_TEXT), null, 2), SHARE_TEXT);
});

test("the decoder refuses a share block or admission it does not model", async (t) => {
  const refuses = async (mutate: (route: Record<string, unknown>) => void, id: string) => {
    const config = share();
    const found = (config.policy as { routes: Record<string, unknown>[] }).routes.find(
      (item) => item.operation_id === id,
    );
    assert.ok(found);
    mutate(found);
    t.mock.method(globalThis, "fetch", async () => response(configBody(config)));
    await assert.rejects(
      new ControlClient(TOKEN).siteConfig("site_loop"),
      (error: unknown) => error instanceof ApiError && error.code === "INVALID_RESPONSE",
    );
  };
  const block = (found: Record<string, unknown>) => found.share_issue as Record<string, unknown>;
  await refuses((found) => {
    block(found).cursor = true;
  }, "records.share.issue");
  await refuses((found) => {
    delete block(found).issuance_rule_id;
  }, "records.share.issue");
  await refuses((found) => {
    block(found).max_active_shares = 0;
  }, "records.share.issue");
  await refuses((found) => {
    block(found).ttl_seconds = 86_401;
  }, "records.share.issue");
  await refuses((found) => {
    found.security_entry = "service_identity";
  }, "records.share.read");
});

test("the console mirrors the share rules of xshield_core::site::share", async (t) => {
  const base = await readDraft(t, share());
  const problems = (draft: SiteConfigDraft) =>
    validateDraft(draft).filter((issue) => issue.severity === "error");
  assert.deepEqual(problems(base), []);
  const errors = (mutate: (draft: SiteConfigDraft) => void) => {
    const draft = structuredClone(base);
    mutate(draft);
    return problems(draft).map((issue) => issue.path);
  };
  const sharing = (d: SiteConfigDraft) => issuer(d);
  const issuerRoute = (d: SiteConfigDraft) => route(d, "records.share.issue");
  const entryRoute = (d: SiteConfigDraft) => route(d, "records.share.read");
  const at = "routes[records.share.issue].share_issue";
  const cases: [string, (d: SiteConfigDraft) => void, string][] = [
    ["status 204", (d) => (sharing(d).success_status = 204), `${at}.success_status`],
    ["status 205", (d) => (sharing(d).success_status = 205), `${at}.success_status`],
    ["status 206", (d) => (sharing(d).success_status = 206), `${at}.success_status`],
    ["status 199", (d) => (sharing(d).success_status = 199), `${at}.success_status`],
    ["status 300", (d) => (sharing(d).success_status = 300), `${at}.success_status`],
    ["lease of zero", (d) => (sharing(d).ttl_seconds = 0), `${at}.ttl_seconds`],
    ["lease above a day", (d) => (sharing(d).ttl_seconds = 86_401), `${at}.ttl_seconds`],
    ["no live shares", (d) => (sharing(d).max_active_shares = 0), `${at}.max_active_shares`],
    ["5001 live shares", (d) => (sharing(d).max_active_shares = 5_001), `${at}.max_active_shares`],
    ["empty token field", (d) => (sharing(d).token_field = ""), `${at}.token_field`],
    ["token field with a space", (d) => (sharing(d).token_field = "a b"), `${at}.token_field`],
    ["token field of 129", (d) => (sharing(d).token_field = "f".repeat(129)), `${at}.token_field`],
    ["empty rule", (d) => (sharing(d).issuance_rule_id = ""), `${at}.issuance_rule_id`],
    ["rule with a colon", (d) => (sharing(d).issuance_rule_id = "a:b"), `${at}.issuance_rule_id`],
    ["unpicked target", (d) => (sharing(d).target_operation_id = ""), `${at}.target_operation_id`],
    [
      "unknown target",
      (d) => (sharing(d).target_operation_id = "records.gone"),
      `${at}.target_operation_id`,
    ],
    [
      "target that is not a share entry",
      (d) => (sharing(d).target_operation_id = "orders.read"),
      `${at}.target_operation_id`,
    ],
    [
      "target that is the issuer",
      (d) => (sharing(d).target_operation_id = "records.share.issue"),
      `${at}.target_operation_id`,
    ],
    [
      "target of another resource type",
      (d) => (entryRoute(d).resource_type = "other"),
      `${at}.target_operation_id`,
    ],
    [
      "target located by a path segment",
      (d) => {
        const entry = entryRoute(d);
        entry.path = "/shared/{record_id}";
        entry.resource_query_parameter = null;
        entry.resource_path_parameter = "record_id";
      },
      `${at}.target_operation_id`,
    ],
    [
      "issuer without a resource",
      (d) => {
        const found = issuerRoute(d);
        found.resource_type = null;
        found.view_profile = null;
        found.resource_query_parameter = null;
      },
      at,
    ],
    [
      "issuer on a root",
      (d) => {
        const found = issuerRoute(d);
        found.security_entry = "authenticated_root";
        found.source_action = null;
      },
      at,
    ],
    [
      "issuer with response encryption",
      (d) => {
        issuerRoute(d).response_crypto = {
          mode: "DIRECT_ENCRYPT",
          adapter_revision: "r1",
          key_id: "k1",
          key_not_before: 1,
          key_expires_at: 2,
          message_ttl_seconds: 60,
          max_envelope_bytes: 4_096,
        };
      },
      at,
    ],
    [
      "issuer that also qualifies resources",
      (d) => {
        issuerRoute(d).resource_grant = structuredClone(route(d, "records.list").resource_grant);
      },
      "routes[records.share.issue].resource_grant",
    ],
    [
      "share entry without a resource",
      (d) => {
        const entry = entryRoute(d);
        entry.resource_type = null;
        entry.view_profile = null;
        entry.resource_query_parameter = null;
      },
      "routes[records.share.read].resource_type",
    ],
    [
      "share entry with a source action",
      (d) => (entryRoute(d).source_action = "records.read"),
      "routes[records.share.read].source_action",
    ],
    [
      "share entry that is not a GET",
      (d) => (entryRoute(d).method = "POST"),
      "routes[records.share.read].method",
    ],
    [
      "paginated share entry",
      (d) => (entryRoute(d).query_pagination = { parameters: [{ name: "page", kind: "page" }] }),
      "routes[records.share.read].query_pagination",
    ],
    [
      "share issuer served as a page",
      (d) => {
        const found = issuerRoute(d);
        found.response_mode = "SENSOR_HTML";
        found.sensor_html = structuredClone(route(d, "app.page").sensor_html);
      },
      "routes[records.share.issue].sensor_html",
    ],
  ];
  for (const [label, mutate, path] of cases) {
    assert.ok(errors(mutate).includes(path), `${label}: ${errors(mutate).join(", ")}`);
  }
  // The bounds themselves are accepted.
  for (const mutate of [
    (d: SiteConfigDraft) => {
      sharing(d).ttl_seconds = 86_400;
      sharing(d).max_active_shares = 5_000;
      sharing(d).success_status = 299;
    },
    (d: SiteConfigDraft) => {
      sharing(d).ttl_seconds = 1;
      sharing(d).max_active_shares = 1;
      sharing(d).success_status = 201;
      sharing(d).token_field = "f".repeat(128);
    },
  ]) {
    assert.deepEqual(errors(mutate), []);
  }
});

test("a valid share scope warns about the rule row and an ungranted issuer, never errors", async (t) => {
  const base = await readDraft(t, share());
  const warnings = validateDraft(base).filter((issue) => issue.severity === "warning");
  assert.ok(
    warnings.some(
      (issue) => issue.path === "routes[records.share.issue].share_issue.issuance_rule_id",
    ),
  );
  // The fixture's list grants the issuer, so there is no "nobody grants it" warning.
  assert.ok(!warnings.some((issue) => issue.path === "routes[records.share.issue].share_issue"));
  const ungranted = structuredClone(base);
  ungranted.policy.routes = ungranted.policy.routes.filter(
    (item) => item.operation_id !== "records.list",
  );
  const found = validateDraft(ungranted);
  assert.ok(
    found.some(
      (issue) =>
        issue.severity === "warning" && issue.path === "routes[records.share.issue].share_issue",
    ),
  );
  assert.deepEqual(
    found.filter((issue) => issue.severity === "error" && issue.path.includes("share")),
    [],
  );
});

test("the drawer offers sharing only on a resource-bound UI action GET", async (t) => {
  const draft = await readDraft(t, share());
  const offered = (id: string) => blockOffered(route(draft, id), "share_issue");
  assert.equal(offered("records.share.issue"), true);
  assert.equal(offered("orders.read"), true, "any resource-bound UI action");
  assert.equal(offered("records.list"), false, "no resource binding");
  assert.equal(offered("records.share.read"), false, "share entry");
  assert.equal(offered("app.page"), false);
  assert.equal(offered("auth.login"), false);
  assert.equal(
    blockOffered({ ...route(draft, "records.share.issue"), method: "POST" }, "share_issue"),
    false,
  );
  // Targets are the draft's share entries; a path-located one is offered with its problem.
  const options = shareTargetOptions(
    draft.policy.routes,
    draft.policy.routes.findIndex((item) => item.operation_id === "records.share.issue"),
  );
  assert.deepEqual(
    options.map((option) => [option.value, option.note]),
    [["records.share.read", null]],
  );
});

test("a switch of admission parks the share block and restores it on the way back", async (t) => {
  const draft = await readDraft(t, share());
  const start = route(draft, "records.share.issue");
  const away = withAdmission(start, "authenticated_root", {});
  assert.equal(away.route.share_issue, undefined);
  assert.deepEqual(away.stash.share_issue, start.share_issue);
  const back = withAdmission(away.route, "ui_action_required", away.stash);
  assert.deepEqual(back.route.share_issue, start.share_issue);
  assert.equal(back.stash.share_issue, undefined);
  // A route becoming a share entry has no source action and keeps its resource binding.
  const entry = withAdmission(start, "share_entry", {});
  assert.equal(entry.route.source_action, null);
  assert.equal(entry.route.resource_type, "record");
  assert.deepEqual(emptyShareIssue("t").target_operation_id, "t");
});

test("share changes need an independent approver and name their own reason", async (t) => {
  const before = await readDraft(t, share());
  assert.equal(needsIndependentApproval("SHARE_ISSUE_CHANGED"), true);
  const retune = (mutate: (d: SiteConfigDraft) => void) => {
    const after = structuredClone(before);
    mutate(after);
    return assessChangeRisk(before, after);
  };
  // The issuer is also a grant target, so its changes name that facet too.
  assert.deepEqual(
    retune((d) => {
      issuer(d).ttl_seconds = 600;
    }),
    ["ROUTES_CHANGED", "RESOURCE_GRANT_CHANGED", "SHARE_ISSUE_CHANGED"],
  );
  assert.deepEqual(
    retune((d) => {
      route(d, "records.share.read").path = "/shared";
    }),
    ["ROUTES_CHANGED", "SHARE_ISSUE_CHANGED"],
  );
  assert.deepEqual(
    retune((d) => {
      d.policy.routes = d.policy.routes.map((item) =>
        item.operation_id === "records.share.issue"
          ? withBlock(item, "share_issue", undefined)
          : item,
      );
    }),
    ["ROUTES_CHANGED", "RESOURCE_GRANT_CHANGED", "SHARE_ISSUE_CHANGED"],
  );
  // An unrelated route stays outside the facet.
  assert.deepEqual(
    retune((d) => {
      route(d, "login.page").max_response_bytes = 4_096;
    }),
    ["ROUTES_CHANGED"],
  );
  // Going live names it as well.
  assert.ok(assessChangeRisk(null, before).includes("SHARE_ISSUE_CHANGED"));
  const changed = structuredClone(before);
  issuer(changed).token_field = "token";
  const row = diffConfigs(before, changed).find((item) => item.risk === "SHARE_ISSUE_CHANGED");
  assert.ok(row, "the block has its own diff row under its own reason");
  assert.match(row.label, /分享凭据发放/);
  assert.match(row.after, /token/);
});
