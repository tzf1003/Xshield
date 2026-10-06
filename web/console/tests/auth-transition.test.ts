import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  ApiError,
  ControlClient,
  type SiteAuthTransition,
  type SiteRouteConfig,
} from "../src/api.ts";
import {
  configFromStored,
  draftFromConfig,
  type SiteConfigDraft,
} from "../src/sites/model/config.ts";
import { diffConfigs } from "../src/sites/model/diff.ts";
import { assessChangeRisk, needsIndependentApproval } from "../src/sites/model/risk.ts";
import {
  blockOffered,
  emptyAuthTransition,
  withAdmission,
  withBlock,
} from "../src/sites/model/route-flow.ts";
import { validateDraft } from "../src/sites/model/validation.ts";
import { REQUEST_ID, TOKEN } from "./fixtures.ts";

const TEXT = readFileSync(
  new URL("../../../tests/site-config/auth-transition-flow.json", import.meta.url),
  "utf8",
).trimEnd();
const stored = (): Record<string, unknown> => JSON.parse(TEXT);
const DIGEST = "b4".repeat(32);
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
const refresh = (d: SiteConfigDraft): SiteAuthTransition => {
  const block = route(d, "auth.refresh").auth_refresh;
  assert.ok(block);
  return block;
};
const sw = (d: SiteConfigDraft): SiteAuthTransition => {
  const block = route(d, "auth.context.switch").auth_context_switch;
  assert.ok(block);
  return block;
};

test("stored refresh and switch blocks round-trip byte for byte through decode, draft and save", async (t) => {
  const config = stored();
  const draft = await readDraft(t, config);
  let sent = "";
  t.mock.method(globalThis, "fetch", async (_path: string, options: RequestInit) => {
    sent = String(options.body);
    return response(configBody(config));
  });
  await new ControlClient(TOKEN).saveSiteConfig("site_loop", draft, KEY);
  assert.deepEqual(JSON.parse(sent).policy, config.policy);
  assert.equal(
    JSON.stringify(JSON.parse(sent).policy.routes),
    JSON.stringify((config.policy as { routes: unknown[] }).routes),
  );
  const fromStored = configFromStored(config);
  assert.ok(fromStored);
  assert.deepEqual(refresh(fromStored), refresh(draft));
  assert.deepEqual(sw(fromStored), sw(draft));
  assert.equal(JSON.stringify(JSON.parse(TEXT), null, 2), TEXT);
});

test("the decoder refuses a transition block it does not model", async (t) => {
  const refuses = async (mutate: (block: Record<string, unknown>) => void, key: string) => {
    const config = stored();
    const found = (config.policy as { routes: Record<string, unknown>[] }).routes.find(
      (item) => item[key] !== undefined,
    );
    assert.ok(found);
    mutate(found[key] as Record<string, unknown>);
    t.mock.method(globalThis, "fetch", async () => response(configBody(config)));
    await assert.rejects(
      new ControlClient(TOKEN).siteConfig("site_loop"),
      (error: unknown) => error instanceof ApiError && error.code === "INVALID_RESPONSE",
    );
  };
  for (const key of ["auth_refresh", "auth_context_switch"]) {
    await refuses((block) => {
      block.session_ttl_seconds = 3600;
    }, key);
    await refuses((block) => {
      delete block.bearer_pointer;
    }, key);
    await refuses((block) => {
      block.credential_ttl_seconds = 86_401;
    }, key);
    await refuses((block) => {
      block.bearer_pointer = "access_token";
    }, key);
  }
});

test("the console mirrors the transition rules of xshield_core::site::flow", async (t) => {
  const base = await readDraft(t, stored());
  const problems = (draft: SiteConfigDraft) =>
    validateDraft(draft).filter((issue) => issue.severity === "error");
  assert.deepEqual(problems(base), []);
  const errors = (mutate: (draft: SiteConfigDraft) => void) => {
    const draft = structuredClone(base);
    mutate(draft);
    return problems(draft).map((issue) => issue.path);
  };
  for (const [id, key, block] of [
    ["auth.refresh", "auth_refresh", refresh],
    ["auth.context.switch", "auth_context_switch", sw],
  ] as const) {
    const at = `routes[${id}].${key}`;
    const bad: [string, (d: SiteConfigDraft) => void, string][] = [
      ["status 199", (d) => (block(d).success_status = 199), `${at}.success_status`],
      ["status 204", (d) => (block(d).success_status = 204), `${at}.success_status`],
      ["status 300", (d) => (block(d).success_status = 300), `${at}.success_status`],
      ["lease 0", (d) => (block(d).credential_ttl_seconds = 0), `${at}.credential_ttl_seconds`],
      [
        "lease 86401",
        (d) => (block(d).credential_ttl_seconds = 86_401),
        `${at}.credential_ttl_seconds`,
      ],
      ["unrooted pointer", (d) => (block(d).bearer_pointer = "token"), `${at}.bearer_pointer`],
      ["empty pointer", (d) => (block(d).bearer_pointer = ""), `${at}.bearer_pointer`],
      ["bad escape", (d) => (block(d).bearer_pointer = "/a~2b"), `${at}.bearer_pointer`],
      ["trailing tilde", (d) => (block(d).bearer_pointer = "/a~"), `${at}.bearer_pointer`],
      [
        "pointer of 513",
        (d) => (block(d).bearer_pointer = `/${"a".repeat(512)}`),
        `${at}.bearer_pointer`,
      ],
      ["control byte", (d) => (block(d).bearer_pointer = "/a\u0007b"), `${at}.bearer_pointer`],
      [
        "bearer equal to the principal",
        (d) => (block(d).bearer_pointer = block(d).principal_pointer),
        `${at}.bearer_pointer`,
      ],
      [
        "context equal to the principal",
        (d) => (block(d).authorization_context_pointer = block(d).principal_pointer),
        `${at}.authorization_context_pointer`,
      ],
      [
        "on a public route",
        (d) => (route(d, id).security_entry = "public"),
        `routes[${id}].${key}`,
      ],
      [
        "on an auth entry",
        (d) => (route(d, id).security_entry = "auth_entry"),
        `routes[${id}].${key}`,
      ],
      [
        "also revoking",
        (d) => {
          route(d, id).auth_revoke = { success_status: 200 };
        },
        `routes[${id}].resource_grant`,
      ],
      [
        "an observed request body",
        (d) => (route(d, id).request_crypto = { mode: "OBSERVE", adapter_revision: "o1" }),
        `routes[${id}].request_crypto`,
      ],
    ];
    for (const [label, mutate, path] of bad) {
      assert.ok(errors(mutate).includes(path), `${id} ${label}: ${errors(mutate).join(", ")}`);
    }
    // Accepted: 205 and 206 (unlike a revoke), the bounds, rooted non-ASCII and escaped pointers.
    for (const mutate of [
      (d: SiteConfigDraft) => (block(d).success_status = 205),
      (d: SiteConfigDraft) => (block(d).success_status = 299),
      (d: SiteConfigDraft) => (block(d).credential_ttl_seconds = 1),
      (d: SiteConfigDraft) => (block(d).credential_ttl_seconds = 86_400),
      (d: SiteConfigDraft) => (block(d).bearer_pointer = `/${"a".repeat(511)}`),
      (d: SiteConfigDraft) => (block(d).bearer_pointer = "/a~1b~0c"),
      (d: SiteConfigDraft) => (block(d).bearer_pointer = "/名前"),
    ]) {
      assert.deepEqual(errors(mutate), [], `${id} accepted case`);
    }
  }
  // Both blocks on one route, a grant beside a refresh, and a page carrying one.
  assert.ok(
    errors((d) => {
      route(d, "auth.refresh").auth_context_switch = structuredClone(sw(d));
    }).includes("routes[auth.refresh].resource_grant"),
  );
  assert.ok(
    errors((d) => {
      route(d, "auth.refresh").resource_grant = structuredClone(
        route(d, "orders.list").resource_grant,
      );
    }).includes("routes[auth.refresh].resource_grant"),
  );
  assert.ok(
    errors((d) => {
      const found = route(d, "auth.refresh");
      found.method = "GET";
      found.response_mode = "SENSOR_HTML";
      found.sensor_html = structuredClone(route(d, "app.page").sensor_html);
    }).includes("routes[auth.refresh].sensor_html"),
  );
  // A decrypted request body may sit in front of a transition.
  assert.deepEqual(
    errors((d) => {
      route(d, "auth.context.switch").request_crypto = {
        mode: "DIRECT_DECRYPT",
        adapter_revision: "r1",
        key_id: "k1",
        key_not_before: 1,
        key_expires_at: 2,
        max_envelope_bytes: 4_096,
        max_plaintext_bytes: 1_024,
        max_message_age_seconds: 60,
        max_future_skew_seconds: 30,
        max_active_messages: 100,
      };
    }),
    [],
  );
});

test("the sensor's 64 identity-change routes count switches, not refreshes", async (t) => {
  const base = await readDraft(t, stored());
  const withRoutes = (count: number, kind: "auth_refresh" | "auth_context_switch") => {
    const draft = structuredClone(base);
    draft.policy.routes = draft.policy.routes.filter(
      (item) => item.operation_id !== "auth.refresh" && item.operation_id !== "auth.context.switch",
    );
    for (let index = 0; index < count; index += 1) {
      draft.policy.routes.push({
        ...route(base, "auth.refresh"),
        operation_id: `auth.${kind}.${index}`,
        path: `/${kind}/${index}`,
        auth_refresh: undefined,
        auth_context_switch: undefined,
        [kind]: emptyAuthTransition(),
      } as SiteRouteConfig);
      const added = draft.policy.routes.at(-1);
      assert.ok(added);
      Object.assign(added[kind] as SiteAuthTransition, {
        principal_pointer: "/a",
        authorization_context_pointer: "/b",
        bearer_pointer: "/c",
      });
      for (const key of ["auth_refresh", "auth_context_switch"] as const) {
        if (added[key] === undefined) delete added[key];
      }
    }
    return validateDraft(draft).filter((issue) => issue.severity === "error");
  };
  // The loop already has a login binding and a logout revoke: 62 switches make 64.
  assert.deepEqual(withRoutes(62, "auth_context_switch"), []);
  assert.ok(withRoutes(63, "auth_context_switch").length > 0);
  assert.deepEqual(withRoutes(80, "auth_refresh"), []);
});

test("the drawer offers the blocks only on an authenticated root and parks them", async (t) => {
  const draft = await readDraft(t, stored());
  for (const block of ["auth_refresh", "auth_context_switch"] as const) {
    assert.equal(blockOffered(route(draft, "auth.logout"), block), true);
    assert.equal(blockOffered(route(draft, "auth.login"), block), false);
    assert.equal(blockOffered(route(draft, "orders.list"), block), false);
    assert.equal(blockOffered(route(draft, "app.page"), block), false, "a SENSOR_HTML page");
  }
  const start = route(draft, "auth.refresh");
  const away = withAdmission(start, "public", {});
  assert.equal(away.route.auth_refresh, undefined);
  assert.deepEqual(away.stash.auth_refresh, start.auth_refresh);
  const back = withAdmission(away.route, "authenticated_root", away.stash);
  assert.deepEqual(back.route.auth_refresh, start.auth_refresh);
  assert.equal(back.stash.auth_refresh, undefined);
  assert.deepEqual(emptyAuthTransition().bearer_pointer, "");
});

test("transition changes need an independent approver and name their own reason", async (t) => {
  const before = await readDraft(t, stored());
  assert.equal(needsIndependentApproval("AUTH_TRANSITION_CHANGED"), true);
  const change = (mutate: (d: SiteConfigDraft) => void) => {
    const after = structuredClone(before);
    mutate(after);
    return assessChangeRisk(before, after);
  };
  assert.deepEqual(
    change((d) => {
      refresh(d).credential_ttl_seconds = 60;
    }),
    ["ROUTES_CHANGED", "AUTH_TRANSITION_CHANGED"],
  );
  assert.deepEqual(
    change((d) => {
      sw(d).authorization_context_pointer = "/identity/account";
    }),
    ["ROUTES_CHANGED", "AUTH_TRANSITION_CHANGED"],
  );
  assert.deepEqual(
    change((d) => {
      d.policy.routes = d.policy.routes.map((item) =>
        item.operation_id === "auth.context.switch"
          ? withBlock(item, "auth_context_switch", undefined)
          : item,
      );
    }),
    ["ROUTES_CHANGED", "AUTH_TRANSITION_CHANGED"],
  );
  assert.deepEqual(
    change((d) => {
      route(d, "login.page").max_response_bytes = 4_096;
    }),
    ["ROUTES_CHANGED"],
  );
  assert.ok(assessChangeRisk(null, before).includes("AUTH_TRANSITION_CHANGED"));
  const changed = structuredClone(before);
  refresh(changed).credential_ttl_seconds = 60;
  const row = diffConfigs(before, changed).find((item) => item.risk === "AUTH_TRANSITION_CHANGED");
  assert.ok(row, "the block has its own diff row under its own reason");
  assert.match(row.label, /刷新凭证/);
});
