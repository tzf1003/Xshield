/** Actual ControlClient against the Rust-owned loopback HTTP/PostgreSQL fixture. */
import assert from "node:assert/strict";
import { ApiError, ControlClient } from "../src/api.ts";

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
  const artifacts = (process.env.XSHIELD_CONSOLE_TEST_ARTIFACTS ?? "")
    .split(",")
    .sort();
  assert.equal(artifacts.length, 2);
  const first = artifacts[0]!;
  const second = artifacts[1]!;
  const foreignCase = process.env.XSHIELD_CONSOLE_TEST_FOREIGN_CASE!;
  const network = globalThis.fetch;
  const requestIds = new Set<string>();
  globalThis.fetch = async (input, options) => {
    assert.match(
      String(input),
      /^\/control\/v1\/cases(?:\/case_[a-f0-9-]+\/(?:items|close)(?:\?cursor=[a-zA-Z0-9_.-]+)?)?$/,
    );
    assert.equal(options?.credentials, "omit");
    assert.equal(options?.redirect, "error");
    assert.equal(options?.cache, "no-store");
    assert.equal(options?.referrerPolicy, "no-referrer");
    const response = await network(new URL(String(input), origin), options);
    assert.equal(response.headers.get("cache-control"), "private, no-store");
    const raw = await response.clone().json();
    assert.ok(!requestIds.has(raw.request_id));
    requestIds.add(raw.request_id);
    for (const excluded of [
      "locator",
      "key_ref",
      "content_base64",
      "idempotency_digest",
      "request_digest",
      "payload_json",
    ])
      assert.ok(!JSON.stringify(raw).includes(excluded));
    return response;
  };
  const client = new ControlClient(
    process.env.XSHIELD_CONSOLE_TEST_TOKEN ?? "",
  );
  const fails = (code: string, status: number) => (error: unknown) => {
    assert.ok(error instanceof ApiError);
    assert.equal(error.code, code);
    assert.equal(error.status, status);
    assert.ok(error.requestId && requestIds.has(error.requestId));
    return true;
  };
  phase = 2;
  const recovered = await client.createCase(
    "Recover disconnected creation",
    "case-wire-disconnect-key",
  );
  assert.equal(recovered.replayed, true);
  phase = 3;
  const created = await client.createCase(
    "Wire investigation",
    "case-wire-create-key",
  );
  assert.equal(created.replayed, false);
  assert.equal(created.status, "open");
  const id = created.case_id;
  const replay = await client.createCase(
    "Wire investigation",
    "case-wire-create-key",
  );
  assert.equal(replay.case_id, id);
  assert.equal(replay.created_at, created.created_at);
  assert.equal(replay.replayed, true);
  await assert.rejects(
    client.createCase("Changed purpose", "case-wire-create-key"),
    fails("CONTROL_IDEMPOTENCY_CONFLICT", 409),
  );
  phase = 4;
  assert.deepEqual((await client.caseItems(id)).items, []);
  const added = await client.addCaseItem(id, first, "case-wire-first-item");
  assert.equal(added.artifact_id, first);
  assert.equal(added.replayed, false);
  const addedReplay = await client.addCaseItem(
    id,
    first,
    "case-wire-first-item",
  );
  assert.equal(addedReplay.added_at, added.added_at);
  assert.equal(addedReplay.replayed, true);
  await client.addCaseItem(id, second, "case-wire-second-item");
  await assert.rejects(
    client.addCaseItem(id, first, "case-wire-another-item"),
    fails("CONTROL_CASE_EVIDENCE_CONFLICT", 409),
  );
  phase = 5;
  const page = await client.caseItems(id);
  assert.equal(page.items.length, 1);
  assert.equal(page.items[0]?.artifact_id, first);
  assert.equal(page.items[0]?.catalog_status, "active");
  assert.ok(page.next_cursor);
  const last = await client.caseItems(id, page.next_cursor);
  assert.equal(last.items[0]?.artifact_id, second);
  assert.equal(last.next_cursor, null);
  const tampered =
    page.next_cursor.slice(0, -1) +
    (page.next_cursor.endsWith("0") ? "1" : "0");
  await assert.rejects(
    client.caseItems(id, tampered),
    fails("CONTROL_CURSOR_INVALID", 400),
  );
  await assert.rejects(
    client.caseItems(foreignCase),
    fails("CONTROL_CASE_NOT_AVAILABLE", 404),
  );
  phase = 6;
  const closed = await client.closeCase(
    id,
    "Review complete",
    "case-wire-close-key",
  );
  assert.equal(closed.replayed, false);
  assert.equal(closed.status, "closed");
  const closedReplay = await client.closeCase(
    id,
    "Review complete",
    "case-wire-close-key",
  );
  assert.equal(closedReplay.closed_at, closed.closed_at);
  assert.equal(closedReplay.replayed, true);
  await assert.rejects(
    client.closeCase(id, "Changed reason", "case-wire-close-key"),
    fails("CONTROL_CASE_CLOSE_CONFLICT", 409),
  );
  await assert.rejects(
    client.addCaseItem(id, first, "case-wire-first-item"),
    fails("CONTROL_CASE_EVIDENCE_TARGET_UNAVAILABLE", 404),
  );
  assert.equal((await client.caseItems(id)).case.status, "closed");
  assert.equal(
    (await client.createCase("Wire investigation", "case-wire-create-key"))
      .status,
    "closed",
  );
  phase = 7;
  const invalid = new ControlClient(
    "synthetic-invalid-management-token-000000000000",
  );
  await assert.rejects(
    invalid.caseItems(id),
    fails("CONTROL_AUTH_REQUIRED", 401),
  );
  phase = 8;
  origin = observerOrigin;
  for (const action of [
    () => client.createCase("Review", "case-wire-denied-key"),
    () => client.caseItems(id),
    () => client.addCaseItem(id, first, "case-wire-denied-key"),
    () => client.closeCase(id, "Review", "case-wire-denied-key"),
  ])
    await assert.rejects(action(), fails("CONTROL_SCOPE_DENIED", 403));
  assert.equal(requestIds.size, 24);
} catch {
  // Only the phase leaves this process; never dump credentials or server data.
  process.exitCode = phase;
}
