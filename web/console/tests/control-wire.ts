/** Called by the ignored Rust HTTP contract test against its owned loopback server. */
import assert from "node:assert/strict";
import { ApiError, ControlClient } from "../src/api.ts";

// Exit phases identify test failures without printing response bodies or credentials.
let phase = 1;
try {
  const origin = new URL(process.env.XSHIELD_CONSOLE_TEST_ORIGIN ?? "");
  assert.equal(origin.protocol, "http:");
  assert.equal(origin.hostname, "127.0.0.1");
  assert.equal(origin.pathname, "/");
  assert.equal(
    origin.username + origin.password + origin.search + origin.hash,
    "",
  );
  assert.ok(origin.port);
  const networkFetch = globalThis.fetch;
  globalThis.fetch = async (input, options) => {
    assert.equal(typeof input, "string");
    assert.ok(String(input).startsWith("/control/v1/"));
    assert.equal(options?.method, "GET");
    const url = new URL(String(input), origin);
    assert.equal(url.origin, origin.origin);
    return networkFetch(url, options);
  };
  const client = new ControlClient(
    process.env.XSHIELD_CONSOLE_TEST_TOKEN ?? "",
  );
  const request = "req_018f2a3b-4c5d-7000-8000-000000000001";
  phase = 2;
  const summary = await client.summary(request);
  assert.equal(summary.tenant_id, "tenant_a");
  assert.equal(summary.site_id, "site_a");
  assert.equal(summary.source_request_id, request);
  assert.equal(summary.completeness, "complete");
  assert.equal(
    summary.summary?.first_occurred_at,
    "2026-09-20T08:10:30.123456Z",
  );
  assert.equal(summary.summary?.method, "POST");
  assert.equal(summary.summary?.status, 201);
  assert.equal(summary.summary?.stages[0]?.confidence, null);
  phase = 3;
  const events = await client.events(request);
  assert.equal(events.events.length, 1);
  assert.equal(
    events.events[0]?.occurred_at,
    Date.parse("2026-09-20T08:10:30Z") * 1000 + 123456,
  );
  assert.equal(events.events[0]?.model_revision, "");
  assert.equal(
    events.events[0]?.evidence_refs[1],
    "stg_018f2a3b-4c5d-7000-8000-000000000012",
  );
  assert.equal(events.truncated, true);
  assert.ok(events.next_cursor);
  phase = 4;
  const next = await client.events(request, events.next_cursor);
  assert.equal(next.events[0]?.request_seq, 2);
  assert.equal(next.events[0]?.outcome, "response_received");
  assert.equal(next.events[0]?.proof_kind, "");
  assert.equal(next.next_cursor, null);
  phase = 5;
  const failure = (code: string, status: number) => (error: unknown) => {
    assert.ok(error instanceof ApiError);
    assert.equal(error.code, code);
    assert.equal(error.status, status);
    assert.match(error.requestId ?? "", /^req_[0-9a-f-]+$/);
    return true;
  };
  await assert.rejects(
    client.evidence(request),
    failure("CONTROL_CATALOG_UNAVAILABLE", 503),
  );
  phase = 6;
  await assert.rejects(
    client.artifact("artifact_018f2a3b-4c5d-7000-8000-000000000011"),
    failure("CONTROL_CATALOG_UNAVAILABLE", 503),
  );
  phase = 7;
  const unauthorized = new ControlClient(
    "synthetic-invalid-management-token-000000000000",
  );
  await assert.rejects(
    unauthorized.summary(request),
    failure("CONTROL_AUTH_REQUIRED", 401),
  );
} catch {
  process.exitCode = phase;
}
