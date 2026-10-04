/** Run by the ignored Rust Axum contract test against its isolated PostgreSQL fixture. */
import assert from "node:assert/strict";
import { ApiError, ControlClient } from "../src/api.ts";

// Stable exit phases keep credentials and server response bodies out of diagnostics.
let phase = 1;
try {
  const loopback = (value: string | undefined) => {
    const url = new URL(value ?? "");
    assert.equal(url.protocol, "http:");
    assert.equal(url.hostname, "127.0.0.1");
    assert.equal(url.pathname, "/");
    assert.equal(url.username + url.password + url.search + url.hash, "");
    assert.ok(url.port);
    return url;
  };
  let origin = loopback(process.env.XSHIELD_CONSOLE_TEST_ORIGIN);
  const deniedOrigin = loopback(process.env.XSHIELD_CONSOLE_TEST_OBSERVER_ORIGIN);
  const id = (kind: string, suffix: string) => `${kind}_018f2a3b-4c5d-7000-8000-00000000${suffix}`;
  const grantId = id("grant", "e101");
  const bindingId = id("auth", "e102");
  const requestIds = new Set<string>();
  const networkFetch = globalThis.fetch;
  globalThis.fetch = async (input, options) => {
    assert.equal(typeof input, "string");
    assert.match(String(input), /^\/control\/v1\/(grants\/grant_|auth-bindings\/auth_)[0-9a-f-]+$/);
    assert.equal(options?.method, "GET");
    assert.equal(options?.body, undefined);
    assert.equal(options?.credentials, "omit");
    assert.equal(options?.cache, "no-store");
    assert.equal(options?.redirect, "error");
    assert.equal(options?.referrerPolicy, "no-referrer");
    const response = await networkFetch(new URL(String(input), origin), options);
    assert.equal(response.headers.get("cache-control"), "private, no-store");
    const raw = await response.clone().json();
    assert.match(raw.request_id, /^req_[0-9a-f-]+$/);
    assert.ok(!requestIds.has(raw.request_id));
    requestIds.add(raw.request_id);
    if (response.ok) {
      assert.equal(raw.schema_version, 3);
      assert.equal(raw.tenant_id, "tenant_console_ledger_wire");
      assert.equal(raw.site_id, "site_a");
      const kind = String(input).includes("/grants/") ? "grant" : "binding";
      assert.deepEqual(
        Object.keys(raw).sort(),
        [
          "schema_version",
          "request_id",
          "tenant_id",
          "site_id",
          `source_${kind}_id`,
          "found",
          "as_of",
          kind,
        ].sort(),
      );
      assert.equal(raw[`source_${kind}_id`], String(input).split("/").at(-1));
      const serialized = JSON.stringify(raw);
      for (const excluded of [
        "principal_ref",
        "authorization_context",
        "fingerprint",
        "waf_sid",
        "resource_key_hmac",
        "issuance_key",
        "action_ref",
        "constraints",
        "payload_json",
        "eligible",
      ]) {
        assert.equal(serialized.includes(excluded), false);
      }
    } else if (response.status === 503) {
      assert.equal(raw.retryable, true);
      assert.equal(raw.next_action, "retry_later");
      assert.equal(Object.hasOwn(raw, "grant"), false);
      assert.equal(Object.hasOwn(raw, "binding"), false);
    }
    return response;
  };
  const client = new ControlClient(process.env.XSHIELD_CONSOLE_TEST_TOKEN ?? "");
  const timestamp = (value: string | null) => {
    assert.ok(value);
    assert.match(value, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/);
    assert.ok(Number.isFinite(Date.parse(value)));
  };
  const failure = (code: string, status: number) => (error: unknown) => {
    assert.ok(error instanceof ApiError);
    assert.equal(error.code, code);
    assert.equal(error.status, status);
    assert.ok(error.requestId && requestIds.has(error.requestId));
    return true;
  };
  phase = 2;
  const active = await client.grant(grantId, new AbortController().signal);
  assert.equal(active.found, true);
  assert.equal(active.source_grant_id, grantId);
  assert.ok(active.grant);
  timestamp(active.as_of);
  timestamp(active.grant.issued_at);
  timestamp(active.grant.expires_at);
  timestamp(active.grant.binding.expires_at);
  assert.deepEqual(active.grant, {
    grant_id: grantId,
    auth_epoch: 4,
    stored_status: "active",
    time_expired: false,
    issued_at: active.grant.issued_at,
    expires_at: active.grant.expires_at,
    resource_type: "order",
    operation_id: "orders.read",
    view_id: "customer_detail",
    policy_revision: "inspection-r1",
    source_event_id: id("ev", "e104"),
    source_request_id: id("req", "e103"),
    binding: {
      binding_id: bindingId,
      current_auth_epoch: 4,
      epoch_matches_grant: true,
      stored_status: "active",
      time_expired: false,
      expires_at: active.grant.binding.expires_at,
    },
  });
  phase = 3;
  const binding = await client.binding(bindingId, new AbortController().signal);
  assert.equal(binding.source_binding_id, bindingId);
  assert.equal(binding.found, true);
  assert.ok(binding.binding);
  timestamp(binding.as_of);
  timestamp(binding.binding.expires_at);
  timestamp(binding.binding.updated_at);
  assert.deepEqual(binding.binding, {
    binding_id: bindingId,
    current_auth_epoch: 4,
    credential_generation: 2,
    stored_status: "active",
    time_expired: false,
    expires_at: binding.binding.expires_at,
    updated_at: binding.binding.updated_at,
  });
  phase = 4;
  const missingGrant = await client.grant(id("grant", "ffff"));
  assert.equal(missingGrant.found, false);
  assert.equal(missingGrant.grant, null);
  assert.equal(missingGrant.as_of, null);
  phase = 5;
  const missingBinding = await client.binding(id("auth", "ffff"));
  assert.equal(missingBinding.found, false);
  assert.equal(missingBinding.binding, null);
  assert.equal(missingBinding.as_of, null);
  for (const [suffix, status, expired] of [
    ["e201", "expired", true],
    ["e202", "revoked", false],
    ["e203", "active", true],
  ] as const) {
    phase += 1;
    const historical = await client.grant(id("grant", suffix));
    assert.equal(historical.found, true);
    assert.equal(historical.grant?.stored_status, status);
    assert.equal(historical.grant?.time_expired, expired);
    assert.equal(historical.grant?.source_event_id, id("ev", "e104"));
    assert.equal(historical.grant?.source_request_id, id("req", "e103"));
  }
  phase = 9;
  const changed = await client.grant(id("grant", "e204"));
  assert.equal(changed.grant?.auth_epoch, 4);
  assert.equal(changed.grant?.stored_status, "active");
  assert.equal(changed.grant?.time_expired, false);
  assert.equal(changed.grant?.binding.binding_id, id("auth", "e203"));
  assert.equal(changed.grant?.binding.current_auth_epoch, 5);
  assert.equal(changed.grant?.binding.epoch_matches_grant, false);
  assert.equal(changed.grant?.binding.stored_status, "revoked");
  assert.equal(changed.grant?.binding.time_expired, true);
  for (const [suffix, status, epoch, generation, expired] of [
    ["e201", "anonymous", 0, 0, false],
    ["e202", "active", 4, 2, true],
    ["e203", "revoked", 5, 3, true],
    ["e204", "expired", 4, 2, true],
  ] as const) {
    phase += 1;
    const historical = await client.binding(id("auth", suffix));
    assert.equal(historical.found, true);
    assert.equal(historical.binding?.stored_status, status);
    assert.equal(historical.binding?.current_auth_epoch, epoch);
    assert.equal(historical.binding?.credential_generation, generation);
    assert.equal(historical.binding?.time_expired, expired);
    assert.ok(historical.binding);
    timestamp(historical.binding.updated_at);
    if (expired)
      assert.ok(
        Date.parse(historical.binding.updated_at) > Date.parse(historical.binding.expires_at),
      );
  }
  phase = 14;
  await assert.rejects(
    client.grant(id("grant", "e205")),
    failure("CONTROL_GRANT_STORE_UNAVAILABLE", 503),
  );
  phase = 15;
  await assert.rejects(
    client.binding(id("auth", "e205")),
    failure("CONTROL_BINDING_STORE_UNAVAILABLE", 503),
  );
  phase = 16;
  const foreignGrant = await client.grant(id("grant", "e301"));
  assert.equal(foreignGrant.found, false);
  assert.equal(foreignGrant.grant, null);
  assert.equal(foreignGrant.as_of, null);
  phase = 17;
  const foreignBinding = await client.binding(id("auth", "e301"));
  assert.equal(foreignBinding.found, false);
  assert.equal(foreignBinding.binding, null);
  assert.equal(foreignBinding.as_of, null);
  const invalid = new ControlClient("synthetic-invalid-management-token-000000000000");
  phase = 18;
  await assert.rejects(invalid.grant(grantId), failure("CONTROL_AUTH_REQUIRED", 401));
  phase = 19;
  await assert.rejects(invalid.binding(bindingId), failure("CONTROL_AUTH_REQUIRED", 401));
  origin = deniedOrigin;
  const investigator = new ControlClient(process.env.XSHIELD_CONSOLE_TEST_TOKEN ?? "");
  phase = 20;
  await assert.rejects(investigator.grant(grantId), failure("CONTROL_SCOPE_DENIED", 403));
  phase = 21;
  await assert.rejects(investigator.binding(bindingId), failure("CONTROL_SCOPE_DENIED", 403));
  assert.equal(requestIds.size, 20);
} catch {
  process.exitCode = phase;
}
