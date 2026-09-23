/** Called by the ignored Rust HTTP contract test with synthetic ClickHouse rows. */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { ApiError, ControlClient } from "../src/api.ts";
import type { SearchPlan } from "../src/search.ts";

// Exit phases identify failures without printing response bodies or credentials.
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
  const observerOrigin = loopback(
    process.env.XSHIELD_CONSOLE_TEST_OBSERVER_ORIGIN,
  );
  const grant = "grant_018f2a3b-4c5d-7000-8000-000000000101";
  const binding = "auth_018f2a3b-4c5d-7000-8000-000000000102";
  const trace = "018f2a3b4c5d70008000000000000003";
  const plan: SearchPlan = {
    schema_version: 3,
    start: "2026-09-20T08:10:00Z",
    end: "2026-09-20T08:11:00Z",
    filters: [
      { kind: "trace_id", value: trace },
      { kind: "text", field: "event_type", value: "grant.issued" },
      { kind: "grant_id", value: grant },
      { kind: "auth_binding_id", value: binding },
    ],
    sort: "occurred_at_asc",
    limit: 2,
  };
  const originalPlan = JSON.stringify(plan);
  let expectedPlan = plan;
  let expectedCursor: string | undefined;
  const requestIds = new Set<string>();
  const networkFetch = globalThis.fetch;
  globalThis.fetch = async (input, options) => {
    assert.equal(input, "/control/v1/search");
    assert.equal(options?.method, "POST");
    assert.equal(options?.credentials, "omit");
    assert.equal(options?.cache, "no-store");
    assert.equal(options?.redirect, "error");
    assert.equal(options?.referrerPolicy, "no-referrer");
    assert.equal(
      new Headers(options?.headers).get("content-type"),
      "application/json",
    );
    assert.equal(typeof options?.body, "string");
    assert.deepEqual(JSON.parse(String(options?.body)), {
      ...expectedPlan,
      ...(expectedCursor === undefined ? {} : { cursor: expectedCursor }),
    });
    const response = await networkFetch(
      new URL(String(input), origin),
      options,
    );
    assert.equal(response.headers.get("cache-control"), "private, no-store");
    const raw = await response.clone().json();
    assert.match(raw.request_id, /^req_[0-9a-f-]+$/);
    assert.ok(!requestIds.has(raw.request_id));
    requestIds.add(raw.request_id);
    if (response.ok) {
      assert.equal(raw.tenant_id, "tenant_a");
      assert.equal(raw.site_id, "site_a");
    } else if (raw.error_code === "CONTROL_QUERY_BUDGET_EXCEEDED") {
      assert.equal(raw.retryable, false);
      assert.equal(raw.next_action, "narrow_query");
    }
    return response;
  };
  const client = new ControlClient(
    process.env.XSHIELD_CONSOLE_TEST_TOKEN ?? "",
  );
  const event = (suffix: string) =>
    `ev_018f2a3b-4c5d-7000-8000-00000000000${suffix}`;
  const digest = (order: "asc" | "desc") =>
    createHash("sha256")
      .update(
        `${Date.parse(plan.start) / 1000}|${Date.parse(plan.end) / 1000}|${order}|2` +
          `|trace_id=${trace}|event_type=grant.issued|grant_id=${grant}|auth_binding_id=${binding}`,
      )
      .digest("hex");
  phase = 2;
  const first = await client.search(
    plan,
    undefined,
    new AbortController().signal,
  );
  assert.equal(first.schema_version, 3);
  assert.equal(first.tenant_id, "tenant_a");
  assert.equal(first.site_id, "site_a");
  assert.equal(first.query_digest, digest("asc"));
  assert.equal(first.has_gaps, false);
  assert.equal(first.pending_segments, 0);
  assert.equal(first.index_watermark, null);
  assert.equal(first.scanned_rows, 42);
  assert.equal(first.scanned_bytes, 512);
  assert.ok(Number.isFinite(Date.parse(first.as_of)));
  assert.deepEqual(
    first.events.map((row) => row.event_id),
    [event("3"), event("1")],
  );
  assert.deepEqual(
    first.events.map((row) => row.occurred_at),
    ["2026-09-20T08:10:30.123456Z", "2026-09-20T08:10:30.123789Z"],
  );
  assert.ok(first.events.every((row) => row.trace_id === trace));
  const nullableEvent = first.events[0];
  assert.ok(nullableEvent);
  for (const field of [
    "request_id",
    "stage",
    "outcome",
    "reason_code",
    "proof_kind",
    "confidence",
    "confidence_status",
    "model_revision",
  ] as const) {
    assert.equal(nullableEvent[field], null);
  }
  assert.equal(Object.hasOwn(nullableEvent, "payload_json"), false);
  assert.equal(first.truncated, true);
  assert.ok(first.next_cursor);
  assert.equal(first.next_cursor.split(".")[1], "1789891830123789");
  assert.equal(first.next_cursor.split(".")[2], event("1"));
  phase = 3;
  expectedCursor = first.next_cursor;
  const next = await client.search(plan, expectedCursor);
  assert.equal(next.query_digest, first.query_digest);
  assert.deepEqual(
    next.events.map((row) => row.event_id),
    [event("2")],
  );
  assert.equal(next.events[0]?.occurred_at, "2026-09-20T08:10:30.123789Z");
  assert.equal(
    next.events[0]?.request_id,
    "req_018f2a3b-4c5d-7000-8000-000000000001",
  );
  assert.equal(next.scanned_rows, null);
  assert.equal(next.scanned_bytes, null);
  assert.equal(next.truncated, false);
  assert.equal(next.next_cursor, null);
  phase = 4;
  expectedPlan = { ...plan, sort: "occurred_at_desc" };
  expectedCursor = undefined;
  const descending = await client.search(expectedPlan);
  assert.equal(descending.query_digest, digest("desc"));
  assert.deepEqual(
    descending.events.map((row) => row.event_id),
    [event("2"), event("1")],
  );
  assert.ok(descending.next_cursor);
  phase = 5;
  expectedCursor = descending.next_cursor;
  const previous = await client.search(expectedPlan, expectedCursor);
  assert.equal(previous.query_digest, descending.query_digest);
  assert.deepEqual(
    previous.events.map((row) => row.event_id),
    [event("3")],
  );
  assert.equal(previous.next_cursor, null);
  assert.equal(previous.truncated, false);
  const failure = (code: string, status: number) => (error: unknown) => {
    assert.ok(error instanceof ApiError);
    assert.equal(error.code, code);
    assert.equal(error.status, status);
    assert.ok(error.requestId && requestIds.has(error.requestId));
    return true;
  };
  phase = 6;
  expectedPlan = plan;
  expectedCursor = undefined;
  await assert.rejects(
    client.search(plan),
    failure("CONTROL_QUERY_BUDGET_EXCEEDED", 429),
  );
  phase = 7;
  expectedCursor =
    first.next_cursor.slice(0, -1) +
    (first.next_cursor.endsWith("0") ? "1" : "0");
  await assert.rejects(
    client.search(plan, expectedCursor),
    failure("CONTROL_CURSOR_INVALID", 400),
  );
  phase = 8;
  origin = observerOrigin;
  expectedCursor = undefined;
  const observer = new ControlClient(
    process.env.XSHIELD_CONSOLE_TEST_TOKEN ?? "",
  );
  await assert.rejects(
    observer.search(plan),
    failure("CONTROL_SCOPE_DENIED", 403),
  );
  assert.equal(requestIds.size, 7);
  assert.equal(JSON.stringify(plan), originalPlan);
} catch {
  process.exitCode = phase;
}
