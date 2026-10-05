import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiError, ControlClient } from "../src/api.ts";
import { errorFixture, REQUEST_ID, TOKEN } from "./fixtures.ts";

const response = (value: unknown, status = 200) =>
  new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
const envelope = (siteId = "site_a") => ({
  request_id: REQUEST_ID,
  tenant_id: "tenant_a",
  site_id: siteId,
});
const KEY = "0123456789abcdef0123";
const DIGEST = "a1".repeat(32);

function configBody(policy: Record<string, unknown> | undefined) {
  return {
    ...envelope(),
    found: true,
    desired_revision: 2,
    active_revision: 1,
    apply_state: "pending",
    apply_id: "apply_1",
    reason_code: "CONTROL_SITE_APPROVAL_REQUIRED",
    requires_approval: true,
    config_digest: DIGEST,
    config: {
      display_name: "A",
      public_origin: "https://a.example.test",
      upstream_address: "8.8.8.8:443",
      upstream_server_name: "o.example.test",
      upstream_tls: true,
      listen_port: 6100,
      entry_path: "/",
      security_entry: "public",
      sensor_enabled: false,
      policy_revision: "policy-v1",
      status: "active",
      ...(policy === undefined ? {} : { policy }),
      revision: 2,
      config_digest: DIGEST,
      updated_by: "author",
      created_at: "2026-09-20T08:10:30.000Z",
      updated_at: "2026-09-20T08:10:30.000Z",
      gateway_config: {},
    },
  };
}

test("the two policy fields the server owns survive a read, so a save cannot reset them", async (t) => {
  t.mock.method(globalThis, "fetch", async () =>
    response(configBody({ static_asset_max_path_depth: 0, origin_object_access_enforced: true })),
  );
  const read = await new ControlClient(TOKEN).siteConfig("site_a");
  assert.equal(read.config?.policy.static_asset_max_path_depth, 0);
  assert.equal(read.config?.policy.origin_object_access_enforced, true);

  // Absent means the server's defaults, and for the static fallback that default is off (core
  // and docs/15): reading it as on would silently re-enable it on the next save.
  t.mock.method(globalThis, "fetch", async () => response(configBody({ routes: [] })));
  const defaults = await new ControlClient(TOKEN).siteConfig("site_a");
  assert.equal(defaults.config?.policy.static_asset_max_path_depth, 0);
  assert.equal(defaults.config?.policy.origin_object_access_enforced, false);

  t.mock.method(globalThis, "fetch", async () =>
    response(configBody({ static_asset_max_path_depth: 17 })),
  );
  await assert.rejects(
    new ControlClient(TOKEN).siteConfig("site_a"),
    (error: unknown) => error instanceof ApiError && error.code === "INVALID_RESPONSE",
  );
  t.mock.method(globalThis, "fetch", async () =>
    response(configBody({ origin_object_access_enforced: "yes" })),
  );
  await assert.rejects(
    new ControlClient(TOKEN).siteConfig("site_a"),
    (error: unknown) => error instanceof ApiError && error.code === "INVALID_RESPONSE",
  );
});

test("a save sends both fields back exactly as read", async (t) => {
  let body = "";
  t.mock.method(globalThis, "fetch", async (_path: string, options: RequestInit) => {
    body = String(options.body);
    return response(configBody({ origin_object_access_enforced: true }));
  });
  const client = new ControlClient(TOKEN);
  const read = await client.siteConfig("site_a");
  const {
    revision: _r,
    config_digest: _d,
    updated_by: _u,
    created_at: _c,
    updated_at: _a,
    gateway_config: _g,
    ...draft
  } = read.config as NonNullable<typeof read.config>;
  await client.saveSiteConfig("site_a", draft, KEY);
  const sent = JSON.parse(body) as { policy: Record<string, unknown> };
  assert.equal(sent.policy.origin_object_access_enforced, true);
  // The stored row carries no depth, so the save sends the default (off) and never turns it on.
  assert.equal(sent.policy.static_asset_max_path_depth, 0);
});

test("a failed validation is an answer, not a transport error", async (t) => {
  const calls: { path: string; key: string | null; method: string | undefined }[] = [];
  t.mock.method(globalThis, "fetch", async (path: string, options: RequestInit) => {
    calls.push({
      path,
      key: new Headers(options.headers).get("Idempotency-Key"),
      method: options.method,
    });
    return response(
      {
        ...envelope(),
        revision: 2,
        config_digest: DIGEST,
        valid: false,
        reason_code: "CONTROL_SITE_CONFIG_REQUEST_INVALID",
      },
      422,
    );
  });
  const result = await new ControlClient(TOKEN).validateSite("site_a", undefined, KEY);
  assert.equal(result.valid, false);
  assert.equal(result.reason_code, "CONTROL_SITE_CONFIG_REQUEST_INVALID");
  assert.deepEqual(calls, [
    { path: "/control/v1/sites/site_a/validate", key: KEY, method: "POST" },
  ]);

  // 403 and the like stay errors.
  t.mock.method(globalThis, "fetch", async () =>
    response(errorFixture("CONTROL_SCOPE_DENIED"), 403),
  );
  await assert.rejects(
    new ControlClient(TOKEN).validateSite("site_a"),
    (error: unknown) =>
      error instanceof ApiError && error.code === "CONTROL_SCOPE_DENIED" && error.status === 403,
  );
  // A 422 that is not a validation answer is still rejected by the strict decoder.
  t.mock.method(globalThis, "fetch", async () => response({ nonsense: true }, 422));
  await assert.rejects(
    new ControlClient(TOKEN).validateSite("site_a"),
    (error: unknown) => error instanceof ApiError && error.code === "INVALID_RESPONSE",
  );
  await assert.rejects(
    new ControlClient(TOKEN).validateSite("site_a", undefined, "short"),
    (error: unknown) =>
      error instanceof ApiError && error.code === "CONTROL_IDEMPOTENCY_KEY_INVALID",
  );
});

const applyBody = {
  ...envelope(),
  listen_port: 6100,
  desired_revision: 2,
  active_revision: 2,
  config_digest: DIGEST,
  apply_state: "active",
  apply_id: "apply_1",
  reason_code: "EDGE_APPLY_CONFIRMED",
  requires_approval: false,
};

test("an approval is pinned to the digest of the revision that was reviewed", async (t) => {
  const seen: { digest: string | null; key: string | null; body: unknown }[] = [];
  t.mock.method(globalThis, "fetch", async (_path: string, options: RequestInit) => {
    const headers = new Headers(options.headers);
    seen.push({
      digest: headers.get("X-Xshield-Expected-Config-Digest"),
      key: headers.get("Idempotency-Key"),
      body: options.body,
    });
    return response(applyBody);
  });
  const client = new ControlClient(TOKEN);
  await client.approveSite("site_a", KEY, undefined, DIGEST);
  await client.approveSite("site_a", KEY);
  assert.deepEqual(seen, [
    { digest: DIGEST, key: KEY, body: "" },
    { digest: null, key: KEY, body: "" },
  ]);
  // A malformed digest never leaves the browser.
  const network = t.mock.method(globalThis, "fetch", async () => response(applyBody));
  for (const bad of ["", "A".repeat(64), "a".repeat(63), "a".repeat(65), `${"a".repeat(63)}g`]) {
    await assert.rejects(
      client.approveSite("site_a", KEY, undefined, bad),
      (error: unknown) => error instanceof ApiError,
    );
  }
  assert.equal(network.mock.callCount(), 0);
});

test("the revision conflict of an approval keeps its stable code", async (t) => {
  t.mock.method(globalThis, "fetch", async () =>
    response(errorFixture("CONTROL_SITE_APPROVAL_REVISION_MISMATCH"), 409),
  );
  await assert.rejects(
    new ControlClient(TOKEN).approveSite("site_a", KEY, undefined, DIGEST),
    (error: unknown) => {
      assert.ok(error instanceof ApiError);
      assert.equal(error.code, "CONTROL_SITE_APPROVAL_REVISION_MISMATCH");
      assert.equal(error.status, 409);
      assert.ok(!error.message.includes("Synthetic server detail"));
      return true;
    },
  );
});
