import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiError, ControlClient } from "../src/api.ts";
import { TOKEN, ARTIFACT_ID, OTHER_ARTIFACT_ID } from "./fixtures.ts";
import {
  ACCESS_ID,
  ACCESS_CASE_ID,
  ACCESS_KEY,
  accessRequestedFixture,
  accessInspectionFixture,
  accessDecisionFixture,
  downloadHeaders,
} from "./access-fixtures.ts";

const response = (value: unknown, status = 200) =>
  new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json" },
  });
const errorIs = (code: string, status?: number) => (error: unknown) => {
  assert.ok(error instanceof ApiError);
  assert.equal(error.code, code);
  if (status !== undefined) assert.equal(error.status, status);
  assert.ok(!error.message.includes(TOKEN));
  return true;
};

test("access methods use fixed scoped routes and exact mutation bodies, with explicit replay", async (t) => {
  const initial = accessRequestedFixture();
  const replay = { ...initial, status: "approved", replayed: true };
  const fixtures = [
    initial,
    replay,
    accessInspectionFixture(),
    accessDecisionFixture(),
    accessDecisionFixture("revoked", true),
    accessDecisionFixture("denied"),
  ];
  const paths = [
    `artifacts/${ARTIFACT_ID}/access`,
    `artifacts/${ARTIFACT_ID}/access`,
    `evidence-access-requests/${ACCESS_ID}`,
    `evidence-access-requests/${ACCESS_ID}/approve`,
    `evidence-access-requests/${ACCESS_ID}/approve`,
    `evidence-access-requests/${ACCESS_ID}/deny`,
  ];
  const bodies = [
    { case_id: ACCESS_CASE_ID, access_kind: "sensitive_raw", justification: "核查证据" },
    { case_id: ACCESS_CASE_ID, access_kind: "sensitive_raw", justification: "核查证据" },
    undefined,
    { reason: "同意用途", ttl_seconds: 600 },
    { reason: "同意用途", ttl_seconds: 600 },
    { reason: "用途不足" },
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
    assert.equal(headers.get("Idempotency-Key"), current === 2 ? null : ACCESS_KEY);
    assert.equal(headers.get("Accept"), "application/json");
    assert.equal(init.credentials, "omit");
    assert.equal(init.cache, "no-store");
    assert.equal(init.redirect, "error");
    assert.equal(init.referrerPolicy, "no-referrer");
    return response(
      { ...fixtures[current], storage_key: "synthetic-private-value" },
      current === 0 ? 201 : 200,
    );
  });
  const client = new ControlClient(TOKEN);
  assert.deepEqual(
    await client.requestEvidenceAccess(ARTIFACT_ID, ACCESS_CASE_ID, "核查证据", ACCESS_KEY),
    initial,
  );
  assert.deepEqual(
    await client.requestEvidenceAccess(ARTIFACT_ID, ACCESS_CASE_ID, "核查证据", ACCESS_KEY),
    replay,
  );
  assert.deepEqual(await client.evidenceAccess(ACCESS_ID), accessInspectionFixture());
  assert.deepEqual(
    await client.decideEvidenceAccess(ACCESS_ID, "approve", "同意用途", 600, ACCESS_KEY),
    accessDecisionFixture(),
  );
  assert.deepEqual(
    await client.decideEvidenceAccess(ACCESS_ID, "approve", "同意用途", 600, ACCESS_KEY),
    accessDecisionFixture("revoked", true),
  );
  assert.deepEqual(
    await client.decideEvidenceAccess(ACCESS_ID, "deny", "用途不足", null, ACCESS_KEY),
    accessDecisionFixture("denied"),
  );
  assert.equal(index, 6);
});

test("access input validation rejects noncanonical IDs, text, keys and decision TTL before fetch", async (t) => {
  const network = t.mock.method(globalThis, "fetch", async () => {
    throw new Error("unexpected fetch");
  });
  const client = new ControlClient(TOKEN);
  for (const bad of [ACCESS_ID + "\n", ACCESS_ID.toUpperCase(), "../access", ACCESS_ID + "?q=1"])
    await assert.rejects(client.evidenceAccess(bad), errorIs("CONTROL_EVIDENCE_ACCESS_ID_INVALID"));
  for (const bad of ["", " leading", "trailing\u0085", "控制\u0001", "字".repeat(171), "\ud800"])
    await assert.rejects(
      client.requestEvidenceAccess(ARTIFACT_ID, ACCESS_CASE_ID, bad, ACCESS_KEY),
      errorIs("CONTROL_EVIDENCE_ACCESS_REQUEST_INVALID"),
    );
  await assert.rejects(
    client.requestEvidenceAccess(OTHER_ARTIFACT_ID + "\n", ACCESS_CASE_ID, "用途", ACCESS_KEY),
    errorIs("CONTROL_ARTIFACT_ID_INVALID"),
  );
  await assert.rejects(
    client.requestEvidenceAccess(ARTIFACT_ID, ACCESS_CASE_ID + "\n", "用途", ACCESS_KEY),
    errorIs("CONTROL_CASE_ID_INVALID"),
  );
  await assert.rejects(
    client.requestEvidenceAccess(ARTIFACT_ID, ACCESS_CASE_ID, "用途", "short"),
    errorIs("CONTROL_IDEMPOTENCY_KEY_INVALID"),
  );
  for (const ttl of [null, 0, -1, 1.5, 86401, NaN, Infinity])
    await assert.rejects(
      client.decideEvidenceAccess(ACCESS_ID, "approve", "理由", ttl, ACCESS_KEY),
      errorIs("CONTROL_EVIDENCE_ACCESS_DECISION_INVALID"),
    );
  await assert.rejects(
    client.decideEvidenceAccess(ACCESS_ID, "deny", "理由", 1, ACCESS_KEY),
    errorIs("CONTROL_EVIDENCE_ACCESS_DECISION_INVALID"),
  );
  await assert.rejects(
    client.decideEvidenceAccess(ACCESS_ID, "approve", " 理由", 1, ACCESS_KEY),
    errorIs("CONTROL_EVIDENCE_ACCESS_DECISION_INVALID"),
  );
  await assert.rejects(
    client.downloadEvidence(ARTIFACT_ID, ACCESS_ID + "\r"),
    errorIs("CONTROL_EVIDENCE_ACCESS_ID_INVALID"),
  );
  assert.equal(network.mock.callCount(), 0);
});

test("inspection enforces state, explicit nulls, targets and exact microsecond lease consistency", async (t) => {
  let fixture: unknown;
  t.mock.method(globalThis, "fetch", async () => response(fixture));
  const client = new ControlClient(TOKEN);
  for (const status of ["pending", "approved", "denied", "expired", "revoked"] as const) {
    const valid = accessInspectionFixture(status);
    fixture = valid;
    assert.deepEqual(await client.evidenceAccess(ACCESS_ID), valid);
  }
  const micro = accessInspectionFixture("approved");
  micro.as_of = "2026-09-20T08:10:01.000001Z";
  micro.access_request.access_expires_at = "2026-09-20T08:10:01.000002Z";
  micro.access_request.decided_at = "2026-09-20T08:00:01.000002Z";
  fixture = micro;
  assert.equal(
    (await client.evidenceAccess(ACCESS_ID)).access_request.capability_time_expired,
    false,
  );
  micro.as_of = micro.access_request.access_expires_at;
  micro.access_request.capability_time_expired = true;
  micro.access_request.case_status = "closed";
  micro.access_request.artifact_status = "deleted";
  fixture = micro;
  assert.equal(
    (await client.evidenceAccess(ACCESS_ID)).access_request.capability_time_expired,
    true,
  );
  const mutations: Array<(row: ReturnType<typeof accessInspectionFixture>) => void> = [
    (row) => {
      row.schema_version = 4 as 3;
    },
    (row) => {
      row.access_request.access_request_id += "\n";
    },
    (row) => {
      row.access_request.artifact_id = "bad";
    },
    (row) => {
      row.access_request.requested_by = " spaced ";
    },
    (row) => {
      row.access_request.justification = "字".repeat(171);
    },
    (row) => {
      row.access_request.decided_by = row.access_request.requested_by;
    },
    (row) => {
      row.access_request.decision_event_id = row.access_request.requested_event_id;
    },
    (row) => {
      row.access_request.decision_reason = null;
    },
    (row) => {
      row.access_request.decision_ttl_seconds = 0;
    },
    (row) => {
      row.access_request.access_expires_at = row.access_request.decided_at;
    },
    (row) => {
      row.access_request.artifact_expires_at = "2026-09-20T08:01:00.000001Z";
    },
    (row) => {
      row.access_request.decision_ttl_seconds = 599;
    },
    (row) => {
      row.access_request.capability_time_expired = true;
    },
    (row) => {
      row.access_request.artifact_time_expired = true;
    },
    (row) => {
      row.access_request.stored_status = "pending";
    },
    (row) => {
      row.access_request.stored_status = "denied";
    },
    (row) => {
      row.access_request.requested_at = "2026-02-30T08:00:00.000000Z";
    },
    (row) => {
      row.as_of = "2026-09-20T08:01:00.000Z";
    },
    (row) => {
      row.max_approval_ttl_seconds = 86401;
    },
  ];
  for (const mutate of mutations) {
    const invalid = accessInspectionFixture("approved");
    mutate(invalid);
    fixture = invalid;
    await assert.rejects(client.evidenceAccess(ACCESS_ID), errorIs("INVALID_RESPONSE", 200));
  }
  const pending = accessInspectionFixture();
  const missing = { ...pending.access_request } as Record<string, unknown>;
  delete missing.decided_at;
  fixture = { ...pending, access_request: missing };
  await assert.rejects(client.evidenceAccess(ACCESS_ID), errorIs("INVALID_RESPONSE"));
  fixture = {
    ...pending,
    hidden: TOKEN,
    access_request: { ...pending.access_request, locator: TOKEN },
  };
  assert.deepEqual(await client.evidenceAccess(ACCESS_ID), pending);
  const boundary = accessInspectionFixture();
  boundary.access_request.artifact_expires_at = "2262-04-11T23:47:16.854775Z";
  fixture = boundary;
  assert.equal(
    (await client.evidenceAccess(ACCESS_ID)).access_request.artifact_expires_at,
    boundary.access_request.artifact_expires_at,
  );
  boundary.access_request.artifact_expires_at = "2262-04-11T23:47:16.854776Z";
  await assert.rejects(client.evidenceAccess(ACCESS_ID), errorIs("INVALID_RESPONSE"));
});

test("mutation decoders correlate status, replay, targets, independent actors and lease", async (t) => {
  let fixture: unknown;
  let status = 201;
  t.mock.method(globalThis, "fetch", async () => response(fixture, status));
  const client = new ControlClient(TOKEN);
  for (const update of [
    { artifact_id: OTHER_ARTIFACT_ID },
    { case_id: "bad" },
    { access_kind: "raw" },
    { status: "approved" },
    { replayed: true },
    { requested_at: null },
  ]) {
    fixture = { ...accessRequestedFixture(), ...update };
    await assert.rejects(
      client.requestEvidenceAccess(ARTIFACT_ID, ACCESS_CASE_ID, "理由", ACCESS_KEY),
      errorIs("INVALID_RESPONSE"),
    );
  }
  status = 200;
  for (const update of [
    { status: "revoked" },
    { requested_by: "synthetic-approver" },
    { access_expires_at: null },
    { access_expires_at: "2026-09-20T08:20:01.000Z" },
    { decided_at: "2026-09-20T08:11:01.000Z" },
    { access_request_id: ACCESS_ID + "\n" },
  ]) {
    fixture = { ...accessDecisionFixture(), ...update };
    await assert.rejects(
      client.decideEvidenceAccess(ACCESS_ID, "approve", "理由", 600, ACCESS_KEY),
      errorIs("INVALID_RESPONSE"),
    );
  }
  fixture = accessDecisionFixture();
  await assert.rejects(
    client.decideEvidenceAccess(ACCESS_ID, "deny", "理由", null, ACCESS_KEY),
    errorIs("INVALID_RESPONSE"),
  );
});

test("binary response binds metadata, exact bytes and an opaque Blob", async (t) => {
  const bytes = new Uint8Array([0, 255, 60]);
  const fetch = t.mock.method(globalThis, "fetch", async (path: string, init: RequestInit) => {
    assert.equal(path, `/control/v1/artifacts/${ARTIFACT_ID}/content`);
    assert.equal(init.method, "GET");
    assert.equal(init.body, undefined);
    assert.equal(new Headers(init.headers).get("X-Xshield-Evidence-Access-Request"), ACCESS_ID);
    assert.equal(new Headers(init.headers).get("Accept"), "application/octet-stream");
    assert.equal(init.credentials, "omit");
    assert.equal(init.redirect, "error");
    assert.equal(init.cache, "no-store");
    return new Response(bytes, { headers: downloadHeaders() });
  });
  const result = await new ControlClient(TOKEN).downloadEvidence(ARTIFACT_ID, ACCESS_ID);
  assert.equal(result.bytes, 3);
  assert.equal(result.blob.type, "application/octet-stream");
  assert.deepEqual(new Uint8Array(await result.blob.arrayBuffer()), bytes);
  assert.equal(result.artifact_id, ARTIFACT_ID);
  assert.equal(result.access_request_id, ACCESS_ID);
  assert.equal(fetch.mock.callCount(), 1);
});

test("binary header failures cancel before consuming the stream", async (t) => {
  let current = downloadHeaders();
  let reads = 0;
  let cancellations = 0;
  t.mock.method(
    globalThis,
    "fetch",
    async () =>
      new Response(
        new ReadableStream(
          {
            pull() {
              reads++;
            },
            cancel() {
              cancellations++;
            },
          },
          { highWaterMark: 0 },
        ),
        { headers: current },
      ),
  );
  const client = new ControlClient(TOKEN);
  for (const key of Object.keys(downloadHeaders())) {
    current = downloadHeaders();
    delete current[key];
    await assert.rejects(
      client.downloadEvidence(ARTIFACT_ID, ACCESS_ID),
      errorIs("INVALID_RESPONSE"),
    );
  }
  for (const [key, value] of [
    ["X-Xshield-Artifact-Id", OTHER_ARTIFACT_ID],
    ["X-Xshield-Request-Id", "bad"],
    ["Content-Type", "text/html"],
    ["Content-Length", "03"],
    ["Content-Length", "3, 3"],
    ["Cache-Control", "public, private, no-store"],
    ["Content-Encoding", "gzip"],
  ]) {
    current = { ...downloadHeaders(), [key!]: value! };
    await assert.rejects(
      client.downloadEvidence(ARTIFACT_ID, ACCESS_ID),
      errorIs("INVALID_RESPONSE"),
    );
  }
  current = downloadHeaders(64 * 1024 * 1024 + 1);
  await assert.rejects(
    client.downloadEvidence(ARTIFACT_ID, ACCESS_ID),
    errorIs("RESPONSE_TOO_LARGE"),
  );
  assert.equal(reads, 0);
  assert.ok(cancellations > 10);
});

test("binary stream length and resource caps are enforced for actual chunks", async (t) => {
  let headers = downloadHeaders();
  let chunk = new Uint8Array(2);
  let cancelled = false;
  t.mock.method(
    globalThis,
    "fetch",
    async () =>
      new Response(
        new ReadableStream({
          start(controller) {
            controller.enqueue(chunk);
            controller.close();
          },
          cancel() {
            cancelled = true;
          },
        }),
        { headers },
      ),
  );
  const client = new ControlClient(TOKEN);
  await assert.rejects(
    client.downloadEvidence(ARTIFACT_ID, ACCESS_ID),
    errorIs("INVALID_RESPONSE"),
  );
  chunk = new Uint8Array(4);
  await assert.rejects(
    client.downloadEvidence(ARTIFACT_ID, ACCESS_ID),
    errorIs("INVALID_RESPONSE"),
  );
  headers = downloadHeaders(64 * 1024 * 1024);
  chunk = new Uint8Array(64 * 1024 * 1024 + 1);
  await assert.rejects(
    client.downloadEvidence(ARTIFACT_ID, ACCESS_ID),
    errorIs("RESPONSE_TOO_LARGE"),
  );
  headers = downloadHeaders(0);
  chunk = new Uint8Array();
  assert.equal((await client.downloadEvidence(ARTIFACT_ID, ACCESS_ID)).bytes, 0);
  // Closed streams are released; cancellation has no externally visible callback.
  assert.equal(cancelled, false);
});

test("many tiny binary chunks retain exact fidelity in one bounded buffer", async (t) => {
  const expected = new Uint8Array(4096).map((_, index) => index % 256);
  let next = 0;
  t.mock.method(
    globalThis,
    "fetch",
    async () =>
      new Response(
        new ReadableStream({
          pull(controller) {
            if (next === expected.length) controller.close();
            else controller.enqueue(expected.slice(next, ++next));
          },
        }),
        { headers: downloadHeaders(expected.length) },
      ),
  );
  const result = await new ControlClient(TOKEN).downloadEvidence(ARTIFACT_ID, ACCESS_ID);
  assert.equal(result.bytes, expected.length);
  assert.deepEqual(new Uint8Array(await result.blob.arrayBuffer()), expected);
});

test("binary and JSON errors share safe codes, request IDs and single-attempt semantics", async (t) => {
  let value = {
    error_code: "CONTROL_EVIDENCE_READ_NOT_AVAILABLE",
    request_id: accessRequestedFixture().request_id,
    message_safe: TOKEN,
    storage_key: TOKEN,
  };
  const network = t.mock.method(globalThis, "fetch", async () => response(value, 404));
  const client = new ControlClient(TOKEN);
  await assert.rejects(client.downloadEvidence(ARTIFACT_ID, ACCESS_ID), (error: unknown) => {
    errorIs("CONTROL_EVIDENCE_READ_NOT_AVAILABLE", 404)(error);
    assert.equal((error as ApiError).requestId, value.request_id);
    return true;
  });
  value = { ...value, error_code: TOKEN, request_id: "bad" };
  await assert.rejects(client.downloadEvidence(ARTIFACT_ID, ACCESS_ID), errorIs("HTTP_ERROR", 404));
  value = { ...value, error_code: "CONTROL_EVIDENCE_ACCESS_SELF_APPROVAL_DENIED" };
  await assert.rejects(
    client.decideEvidenceAccess(ACCESS_ID, "approve", "理由", 600, ACCESS_KEY),
    errorIs("CONTROL_EVIDENCE_ACCESS_SELF_APPROVAL_DENIED", 404),
  );
  assert.equal(network.mock.callCount(), 3);
});

test("binary cancellation and the total deadline interrupt an already returned stalled body", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  let cancellations = 0;
  const network = t.mock.method(
    globalThis,
    "fetch",
    async () =>
      new Response(
        new ReadableStream({
          start(controller) {
            controller.enqueue(new Uint8Array([1]));
          },
          cancel() {
            cancellations++;
          },
        }),
        { headers: downloadHeaders() },
      ),
  );
  const client = new ControlClient(TOKEN);
  const aborted = new AbortController();
  aborted.abort(TOKEN);
  await assert.rejects(
    client.downloadEvidence(ARTIFACT_ID, ACCESS_ID, aborted.signal),
    errorIs("REQUEST_ABORTED"),
  );
  assert.equal(network.mock.callCount(), 0);
  const controller = new AbortController();
  const cancelled = client.downloadEvidence(ARTIFACT_ID, ACCESS_ID, controller.signal);
  await Promise.resolve();
  await Promise.resolve();
  controller.abort(TOKEN);
  await assert.rejects(cancelled, errorIs("REQUEST_ABORTED", 200));
  const timeout = client.downloadEvidence(ARTIFACT_ID, ACCESS_ID);
  await Promise.resolve();
  await Promise.resolve();
  t.mock.timers.tick(15_000);
  await assert.rejects(timeout, errorIs("REQUEST_TIMEOUT", 200));
  assert.equal(cancellations, 2);
});

test("JSON access mutations retain the same body deadline for independent stalled streams", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  let cancellations = 0;
  const network = t.mock.method(
    globalThis,
    "fetch",
    async () =>
      new Response(
        new ReadableStream({
          cancel() {
            cancellations++;
          },
        }),
        { status: 201, headers: { "Content-Type": "application/json" } },
      ),
  );
  const pending = new ControlClient(TOKEN).requestEvidenceAccess(
    ARTIFACT_ID,
    ACCESS_CASE_ID,
    "理由",
    ACCESS_KEY,
  );
  await Promise.resolve();
  await Promise.resolve();
  t.mock.timers.tick(15_000);
  await assert.rejects(pending, errorIs("REQUEST_TIMEOUT", 201));
  assert.equal(cancellations, 1);
  assert.equal(network.mock.callCount(), 1);
});
