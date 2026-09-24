import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiError, ControlClient } from "../src/api.ts";
import { TOKEN } from "./fixtures.ts";
import {
  EXPORT_ARTIFACT_ID,
  EXPORT_CASE_ID,
  EXPORT_ID,
  EXPORT_KEY,
  EXPORT_PACKAGE_REQUEST_ID,
  exportDownloadHeaders,
  exportFixture,
} from "./export-fixtures.ts";

const json = (value: unknown, status = 200) =>
  new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json" },
  });
const errorIs = (code: string) => (error: unknown) => {
  assert.ok(error instanceof ApiError);
  assert.equal(error.code, code);
  return true;
};

test("export methods bind fixed routes, exact bodies and replay status", async (t) => {
  const pending = exportFixture();
  const replay = exportFixture("pending_approval", true);
  const ready = exportFixture("ready");
  assert.equal(ready.package_request_id, EXPORT_PACKAGE_REQUEST_ID);
  const rejected = exportFixture("rejected");
  const replies = [pending, replay, ready, ready, rejected];
  const paths = [
    `exports`,
    `exports`,
    `exports/${EXPORT_ID}`,
    `exports/${EXPORT_ID}/approve`,
    `exports/${EXPORT_ID}/deny`,
  ];
  const bodies: unknown[] = [
    { case_id: EXPORT_CASE_ID, purpose: "核对案件元数据" },
    { case_id: EXPORT_CASE_ID, purpose: "核对案件元数据" },
    undefined,
    { reason: "独立复核通过" },
    { reason: "独立复核通过" },
  ];
  let index = 0;
  t.mock.method(globalThis, "fetch", async (path: string, init: RequestInit) => {
    const current = index++;
    assert.equal(path, `/control/v1/${paths[current]}`);
    assert.equal(init.method, current === 2 ? "GET" : "POST");
    assert.deepEqual(
      init.body === undefined ? undefined : JSON.parse(String(init.body)),
      bodies[current],
    );
    const headers = new Headers(init.headers);
    assert.equal(headers.get("Authorization"), `Bearer ${TOKEN}`);
    assert.equal(headers.get("Idempotency-Key"), current === 2 ? null : EXPORT_KEY);
    return json(replies[current], current === 0 ? 202 : 200);
  });
  const client = new ControlClient(TOKEN);
  assert.deepEqual(
    await client.requestExport(EXPORT_CASE_ID, "核对案件元数据", EXPORT_KEY),
    pending,
  );
  assert.deepEqual(
    await client.requestExport(EXPORT_CASE_ID, "核对案件元数据", EXPORT_KEY),
    replay,
  );
  assert.deepEqual(await client.exportStatus(EXPORT_ID), ready);
  assert.deepEqual(
    await client.decideExport(EXPORT_ID, "approve", "独立复核通过", EXPORT_KEY),
    ready,
  );
  assert.deepEqual(
    await client.decideExport(EXPORT_ID, "deny", "独立复核通过", EXPORT_KEY),
    rejected,
  );
  assert.equal(index, 5);
});

test("export input validation rejects invalid IDs, text and keys before fetch", async (t) => {
  const network = t.mock.method(globalThis, "fetch", async () => {
    throw new Error("unexpected fetch");
  });
  const client = new ControlClient(TOKEN);
  for (const bad of [EXPORT_ID + "\n", EXPORT_ID.toUpperCase(), "../export"])
    await assert.rejects(client.exportStatus(bad), errorIs("CONTROL_EXPORT_ID_INVALID"));
  await assert.rejects(
    client.requestExport(EXPORT_CASE_ID, "", EXPORT_KEY),
    errorIs("CONTROL_EXPORT_INPUT_INVALID"),
  );
  await assert.rejects(
    client.requestExport(EXPORT_CASE_ID + "\n", "用途", EXPORT_KEY),
    errorIs("CONTROL_CASE_ID_INVALID"),
  );
  await assert.rejects(
    client.requestExport(EXPORT_CASE_ID, "用途", "short"),
    errorIs("CONTROL_IDEMPOTENCY_KEY_INVALID"),
  );
  await assert.rejects(
    client.decideExport(EXPORT_ID, "approve", "用途", "short"),
    errorIs("CONTROL_IDEMPOTENCY_KEY_INVALID"),
  );
  assert.equal(network.mock.callCount(), 0);
});

test("export decoder rejects scope drift, malformed pointers and impossible state", async (t) => {
  let fixture: unknown = exportFixture("ready");
  t.mock.method(globalThis, "fetch", async () => json(fixture));
  const client = new ControlClient(TOKEN);
  for (const mutate of [
    (row: ReturnType<typeof exportFixture>) => { row.kind = "wrong" as "metadata_only"; },
    (row: ReturnType<typeof exportFixture>) => { row.package_digest = "B".repeat(64); },
    (row: ReturnType<typeof exportFixture>) => { row.package_artifact_id = null; },
    (row: ReturnType<typeof exportFixture>) => { row.download_count = 3; },
  ]) {
    const invalid = exportFixture("ready");
    mutate(invalid);
    fixture = invalid;
    await assert.rejects(client.exportStatus(EXPORT_ID), errorIs("INVALID_RESPONSE"));
  }
  fixture = exportFixture("pending_approval");
  assert.equal((await client.exportStatus(EXPORT_ID)).status, "pending_approval");
});

test("export download binds headers, exact bytes and bounded Blob", async (t) => {
  const bytes = new TextEncoder().encode('{"kind":"metadata_only"}');
  t.mock.method(globalThis, "fetch", async (path: string, init: RequestInit) => {
    assert.equal(path, `/control/v1/exports/${EXPORT_ID}/download`);
    assert.equal(init.method, "GET");
    assert.equal(new Headers(init.headers).get("Accept"), "application/json");
    return new Response(bytes, {
      headers: exportDownloadHeaders(bytes.byteLength),
    });
  });
  const result = await new ControlClient(TOKEN).downloadExport(
    EXPORT_ID,
    EXPORT_ARTIFACT_ID,
    bytes.byteLength,
  );
  assert.equal(result.export_id, EXPORT_ID);
  assert.equal(result.artifact_id, EXPORT_ARTIFACT_ID);
  assert.equal(result.bytes, bytes.byteLength);
  assert.equal(result.blob.type, "application/json");
  assert.deepEqual(new Uint8Array(await result.blob.arrayBuffer()), bytes);
});

test("export download rejects a package that differs from the inspected ready metadata", async (t) => {
  const bytes = new TextEncoder().encode('{"kind":"metadata_only"}');
  t.mock.method(globalThis, "fetch", async () => new Response(bytes, {
    headers: exportDownloadHeaders(bytes.byteLength),
  }));
  const client = new ControlClient(TOKEN);
  await assert.rejects(
    client.downloadExport(EXPORT_ID, "artifact_018f2a3b-4c5d-7000-8000-000000000073", bytes.byteLength),
    errorIs("INVALID_RESPONSE"),
  );
  await assert.rejects(
    client.downloadExport(EXPORT_ID, EXPORT_ARTIFACT_ID, bytes.byteLength + 1),
    errorIs("INVALID_RESPONSE"),
  );
  const missingNosniff = exportDownloadHeaders(bytes.byteLength);
  delete missingNosniff["X-Content-Type-Options"];
  t.mock.restoreAll();
  t.mock.method(globalThis, "fetch", async () => new Response(bytes, {
    headers: missingNosniff,
  }));
  await assert.rejects(
    client.downloadExport(EXPORT_ID, EXPORT_ARTIFACT_ID, bytes.byteLength),
    errorIs("INVALID_RESPONSE"),
  );
});
