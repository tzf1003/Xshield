import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiError, ControlClient } from "../src/api.ts";
import type { AccessListView } from "../src/evidence-access.ts";
import { TOKEN, errorFixture } from "./fixtures.ts";
import { ACCESS_ID, accessListFixture } from "./access-fixtures.ts";

const cursor = `v1.${ACCESS_ID}.${"a".repeat(64)}`;
const earlier = ACCESS_ID.slice(0, -2) + "40";
const response = (value: unknown, status = 200) => new Response(JSON.stringify(value), {
  status, headers: { "Content-Type": "application/json" },
});
const errorIs = (code: string) => (error: unknown) => {
  assert.ok(error instanceof ApiError);
  assert.equal(error.code, code);
  assert.ok(!error.message.includes(TOKEN));
  return true;
};

test("access lists use fixed GET routes and retain projected historical metadata", async (t) => {
  const fixtures = [accessListFixture(), accessListFixture("review")];
  fixtures[0]!.items[0]!.stored_status = "revoked";
  fixtures[1]!.items[0]!.access_request_id = earlier;
  let calls = 0;
  t.mock.method(globalThis, "fetch", async (path: string, init: RequestInit) => {
    const index = calls++;
    assert.equal(path, `/control/v1/evidence-access-requests?view=${index === 0 ? "mine" : `review&cursor=${cursor}`}`);
    assert.equal(init.method, "GET");
    assert.equal(init.body, undefined);
    assert.equal(new Headers(init.headers).get("Authorization"), `Bearer ${TOKEN}`);
    assert.equal(new Headers(init.headers).get("Idempotency-Key"), null);
    assert.equal(init.credentials, "omit");
    assert.equal(init.cache, "no-store");
    assert.equal(init.redirect, "error");
    assert.equal(init.referrerPolicy, "no-referrer");
    return response({ ...fixtures[index]!, private_key: "synthetic-private",
      items: fixtures[index]!.items.map((item) => ({ ...item, locator: "synthetic-private", justification: "not-listed" })) });
  });
  const client = new ControlClient(TOKEN);
  assert.deepEqual(await client.evidenceAccessList("mine"), fixtures[0]!);
  assert.deepEqual(await client.evidenceAccessList("review", cursor), fixtures[1]!);
  assert.equal(calls, 2);
});

test("invalid views and cursor shapes reject before network and aborted reads stay aborted", async (t) => {
  const calls = t.mock.method(globalThis, "fetch", async () => { throw new Error("unexpected"); });
  const client = new ControlClient(TOKEN);
  for (const view of ["all", "mine\n", "review&view=mine", "", null])
    await assert.rejects(client.evidenceAccessList(view as AccessListView), errorIs("CONTROL_EVIDENCE_ACCESS_LIST_REQUEST_INVALID"));
  for (const value of ["", cursor + "\n", cursor.toUpperCase(), cursor + "&view=review", cursor.replace("v1", "v2"), `v1.${ACCESS_ID}.${"a".repeat(63)}`])
    await assert.rejects(client.evidenceAccessList("mine", value), errorIs("CONTROL_CURSOR_INVALID"));
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(client.evidenceAccessList("mine", undefined, controller.signal), errorIs("REQUEST_ABORTED"));
  assert.equal(calls.mock.callCount(), 0);
});

test("access list bounds, scope, ordering, view and cursor edges are validated", async (t) => {
  let value: unknown;
  t.mock.method(globalThis, "fetch", async () => response(value));
  const client = new ControlClient(TOKEN);
  value = accessListFixture();
  await client.evidenceAccessList("mine");
  const mutations: Array<(row: ReturnType<typeof accessListFixture>) => void> = [
    (row) => { row.schema_version = 4 as 3; },
    (row) => { row.view = "review"; },
    (row) => { row.tenant_id = "../tenant"; },
    (row) => { row.site_id = "../site"; },
    (row) => { row.as_of = "2026-02-30T08:00:00.000000Z"; },
    (row) => { row.as_of = "2026-09-20T08:00:00.000Z"; },
    (row) => { row.items[0]!.requested_at = "2026-09-20T08:00:00.000Z"; },
    (row) => { row.items[0]!.access_request_id += "\n"; },
    (row) => { row.items[0]!.case_id = "bad"; },
    (row) => { row.items[0]!.artifact_id = "bad"; },
    (row) => { row.items[0]!.requested_event_id = "bad"; },
    (row) => { row.items[0]!.requested_by = " leading"; },
    (row) => { row.items[0]!.requested_by = "x".repeat(257); },
    (row) => { row.items[0]!.stored_status = "other" as "pending"; },
    (row) => { row.items.push({ ...row.items[0]! }); },
    (row) => { row.items.unshift({ ...row.items[0]!, access_request_id: earlier }); },
    (row) => { row.items = Array.from({ length: 129 }, () => ({ ...row.items[0]! })); },
    (row) => { row.truncated = true; },
    (row) => { row.next_cursor = cursor; },
    (row) => { row.truncated = true; row.next_cursor = cursor + "\n"; },
    (row) => { row.truncated = true; row.next_cursor = cursor.replace(ACCESS_ID, earlier); },
    (row) => { row.truncated = true; row.next_cursor = cursor; row.items = []; },
  ];
  for (const mutate of mutations) {
    const row = accessListFixture(); mutate(row); value = row;
    await assert.rejects(client.evidenceAccessList("mine"), (error) => error instanceof ApiError);
  }
  const valid = accessListFixture();
  valid.truncated = true; valid.next_cursor = cursor;
  value = valid;
  assert.deepEqual(await client.evidenceAccessList("mine"), valid);
  await assert.rejects(client.evidenceAccessList("mine", cursor), errorIs("INVALID_RESPONSE"));
  valid.items[0]!.access_request_id = earlier;
  valid.next_cursor = cursor.replace(ACCESS_ID, earlier);
  assert.deepEqual(await client.evidenceAccessList("mine", cursor), valid);
});

test("mine accepts complete history and review accepts pending only; empty is explicit", async (t) => {
  let fixture = accessListFixture();
  t.mock.method(globalThis, "fetch", async () => response(fixture));
  const client = new ControlClient(TOKEN);
  for (const status of ["pending", "approved", "denied", "expired", "revoked"] as const) {
    fixture.items[0]!.stored_status = status;
    assert.equal((await client.evidenceAccessList("mine")).items[0]!.stored_status, status);
  }
  fixture = accessListFixture("review");
  assert.equal((await client.evidenceAccessList("review")).items.length, 1);
  fixture.items[0]!.stored_status = "approved";
  await assert.rejects(client.evidenceAccessList("review"), errorIs("INVALID_RESPONSE"));
  fixture.items = [];
  assert.deepEqual((await client.evidenceAccessList("review")).items, []);
});

test("role denials and list failure reasons retain safe structured errors", async (t) => {
  let code = "CONTROL_SCOPE_DENIED";
  t.mock.method(globalThis, "fetch", async () => response(errorFixture(code), 403));
  for (const next of ["CONTROL_SCOPE_DENIED", "CONTROL_CURSOR_INVALID", "CONTROL_EVIDENCE_ACCESS_LIST_REQUEST_INVALID",
    "CONTROL_EVIDENCE_ACCESS_BUSY", "CONTROL_EVIDENCE_ACCESS_READ_STORE_UNAVAILABLE"]) {
    code = next;
    await assert.rejects(new ControlClient(TOKEN).evidenceAccessList("review"), errorIs(code));
  }
});
