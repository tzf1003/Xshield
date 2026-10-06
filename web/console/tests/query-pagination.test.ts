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
import { blockOffered, withBlock, withQueryParameter } from "../src/sites/model/route-flow.ts";
import { validateDraft } from "../src/sites/model/validation.ts";
import { REQUEST_ID, TOKEN } from "./fixtures.ts";

const LOOP_TEXT = readFileSync(
  new URL("../../../tests/site-config/browser-loop.json", import.meta.url),
  "utf8",
).trimEnd();
const loop = (): Record<string, unknown> => JSON.parse(LOOP_TEXT);
const DIGEST = "b2".repeat(32);
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

/** The loop with pagination declared on its grant-issuing list, as the server would store it. */
function pagedLoop(): Record<string, unknown> {
  const config = loop() as { policy: { routes: Record<string, unknown>[] } };
  const list = config.policy.routes.find((item) => item.operation_id === "orders.list");
  assert.ok(list);
  list.query_pagination = {
    parameters: [
      { name: "page", kind: "page" },
      { name: "page_size", kind: "page_size", max_value: 50 },
      { name: "offset", kind: "offset" },
    ],
  };
  return config;
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

test("query_pagination round-trips byte for byte, with an unset bound staying unset", async (t) => {
  const stored = pagedLoop();
  const draft = await readDraft(t, stored);
  assert.equal(
    JSON.stringify(route(draft, "orders.list").query_pagination),
    JSON.stringify(
      (stored.policy as { routes: { query_pagination?: unknown }[] }).routes[3]?.query_pagination,
    ),
  );
  let sent = "";
  t.mock.method(globalThis, "fetch", async (_path: string, options: RequestInit) => {
    sent = String(options.body);
    return response(configBody(stored));
  });
  await new ControlClient(TOKEN).saveSiteConfig("site_loop", draft, KEY);
  assert.deepEqual(JSON.parse(sent).policy, stored.policy);
  // The approval reconstruction reads the same block.
  const fromStored = configFromStored(stored);
  assert.ok(fromStored);
  assert.deepEqual(
    route(fromStored, "orders.list").query_pagination,
    route(draft, "orders.list").query_pagination,
  );
});

test("the decoder refuses a pagination block it does not model", async (t) => {
  const refuses = async (mutate: (block: Record<string, unknown>) => void) => {
    const config = pagedLoop();
    const list = (config.policy as { routes: Record<string, Record<string, unknown>>[] }).routes[3];
    assert.ok(list?.query_pagination);
    mutate(list.query_pagination);
    t.mock.method(globalThis, "fetch", async () => response(configBody(config)));
    await assert.rejects(
      new ControlClient(TOKEN).siteConfig("site_loop"),
      (error: unknown) => error instanceof ApiError && error.code === "INVALID_RESPONSE",
    );
  };
  await refuses((block) => {
    block.cursor = true;
  });
  await refuses((block) => {
    (block.parameters as Record<string, unknown>[])[0] = { name: "c", kind: "cursor" };
  });
  await refuses((block) => {
    (block.parameters as Record<string, unknown>[])[0] = { name: "p", kind: "page", extra: 1 };
  });
  await refuses((block) => {
    block.parameters = [1, 2, 3, 4, 5].map((n) => ({ name: `p${n}`, kind: "page" }));
  });
});

test("the console mirrors the pagination rules of xshield_core::query_pagination", async (t) => {
  const base = await readDraft(t, pagedLoop());
  assert.deepEqual(validateDraft(base), []);
  const errors = (mutate: (draft: SiteConfigDraft) => void) => {
    const draft = structuredClone(base);
    mutate(draft);
    return validateDraft(draft)
      .filter((issue) => issue.severity === "error")
      .map((issue) => issue.path);
  };
  const list = (d: SiteConfigDraft) => {
    const found = route(d, "orders.list").query_pagination;
    assert.ok(found);
    return found.parameters;
  };
  const cases: [string, (d: SiteConfigDraft) => void, string][] = [
    [
      "uppercase name",
      (d) => {
        const first = list(d)[0];
        assert.ok(first);
        first.name = "Page";
      },
      "routes[orders.list].query_pagination.parameters.0.name",
    ],
    [
      "empty name",
      (d) => {
        const first = list(d)[0];
        assert.ok(first);
        first.name = "";
      },
      "routes[orders.list].query_pagination.parameters.0.name",
    ],
    [
      "name of 33 characters",
      (d) => {
        const first = list(d)[0];
        assert.ok(first);
        first.name = "a".repeat(33);
      },
      "routes[orders.list].query_pagination.parameters.0.name",
    ],
    [
      "duplicate name",
      (d) => {
        const second = list(d)[1];
        assert.ok(second);
        second.name = "page";
      },
      "routes[orders.list].query_pagination.parameters.1.name",
    ],
    [
      "bound above the ceiling",
      (d) => {
        const second = list(d)[1];
        assert.ok(second);
        second.max_value = 1001;
      },
      "routes[orders.list].query_pagination.parameters.1.max_value",
    ],
    [
      "bound of zero",
      (d) => {
        const second = list(d)[1];
        assert.ok(second);
        second.max_value = 0;
      },
      "routes[orders.list].query_pagination.parameters.1.max_value",
    ],
    [
      "bound on a page number",
      (d) => {
        const first = list(d)[0];
        assert.ok(first);
        first.max_value = 5;
      },
      "routes[orders.list].query_pagination.parameters.0.max_value",
    ],
    [
      "five parameters",
      (d) => {
        list(d).push({ name: "a", kind: "page" }, { name: "b", kind: "page" });
      },
      "routes[orders.list].query_pagination",
    ],
    [
      "no parameters",
      (d) => {
        route(d, "orders.list").query_pagination = { parameters: [] };
      },
      "routes[orders.list].query_pagination",
    ],
    [
      "name equal to a resource parameter, case folded",
      (d) => {
        const first = list(d)[0];
        assert.ok(first);
        first.name = "order_id";
      },
      "routes[orders.list].query_pagination.parameters.0.name",
    ],
    [
      "on a resource route",
      (d) => {
        route(d, "orders.read").query_pagination = { parameters: [{ name: "page", kind: "page" }] };
      },
      "routes[orders.read].query_pagination",
    ],
    [
      "on a page root",
      (d) => {
        route(d, "app.page").query_pagination = { parameters: [{ name: "page", kind: "page" }] };
      },
      "routes[app.page].query_pagination",
    ],
    [
      "on a public route",
      (d) => {
        route(d, "login.page").query_pagination = { parameters: [{ name: "page", kind: "page" }] };
      },
      "routes[login.page].query_pagination",
    ],
    [
      "not a GET",
      (d) => {
        route(d, "orders.list").method = "POST";
      },
      "routes[orders.list].query_pagination",
    ],
  ];
  for (const [label, mutate, path] of cases) {
    assert.ok(errors(mutate).includes(path), `${label}: ${errors(mutate).join(", ")}`);
  }
  // 32 characters and the highest page-size bound are the edge's limits, still accepted.
  assert.deepEqual(
    errors((d) => {
      const first = list(d)[0];
      const second = list(d)[1];
      assert.ok(first && second);
      first.name = "a".repeat(32);
      second.max_value = 1000;
    }),
    [],
  );
});

test("the drawer offers pagination only where the edge enforces it", async (t) => {
  const draft = await readDraft(t, loop());
  const offered = (id: string) => blockOffered(route(draft, id), "query_pagination");
  // A non-resource UI action that qualifies resources.
  assert.equal(offered("orders.list"), true);
  assert.equal(offered("orders.read"), false, "resource route");
  assert.equal(offered("app.page"), false, "page root");
  assert.equal(offered("login.page"), false, "public");
  assert.equal(offered("auth.login"), false, "auth entry");
  // An authenticated root needs a grant to be offered.
  const root = {
    ...structuredClone(route(draft, "orders.list")),
    security_entry: "authenticated_root" as const,
  };
  assert.equal(blockOffered(root, "query_pagination"), true);
  const { resource_grant: _removed, ...noGrant } = root;
  assert.equal(blockOffered(noGrant, "query_pagination"), false);
  assert.equal(blockOffered({ ...root, method: "POST" }, "query_pagination"), false);
});

test("editing a parameter keeps the block lossless and drops a bound the kind cannot carry", () => {
  const block = {
    parameters: [{ name: "n", kind: "page_size" as const, max_value: 50 }],
  };
  assert.deepEqual(withQueryParameter(block, 0, { kind: "page" }).parameters, [
    { name: "n", kind: "page" },
  ]);
  assert.deepEqual(withQueryParameter(block, 0, { max_value: 10 }).parameters, [
    { name: "n", kind: "page_size", max_value: 10 },
  ]);
  const unchanged = withQueryParameter(block, 5, { name: "x" });
  assert.deepEqual(unchanged, block);
});

test("pagination changes need an independent approver and show in the diff", async (t) => {
  const before = await readDraft(t, loop());
  assert.equal(needsIndependentApproval("QUERY_PAGINATION_CHANGED"), true);
  const after = structuredClone(before);
  const list = route(after, "orders.list");
  after.policy.routes = after.policy.routes.map((item) =>
    item === list
      ? withBlock(item, "query_pagination", { parameters: [{ name: "page", kind: "page" }] })
      : item,
  );
  assert.deepEqual(assessChangeRisk(before, after), [
    "ROUTES_CHANGED",
    "PAGE_ACTIONS_CHANGED",
    "RESOURCE_GRANT_CHANGED",
    "QUERY_PAGINATION_CHANGED",
  ]);
  const change = diffConfigs(before, after).find(
    (item) => item.risk === "QUERY_PAGINATION_CHANGED",
  );
  assert.ok(change, "the block has its own diff row under its own reason");
  assert.match(change.after, /page/);
});
