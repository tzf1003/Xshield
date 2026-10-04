import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiError, ControlClient } from "../src/api.ts";
import {
  decodeHoldCreated,
  decodeHoldReleased,
  decodeHoldCollection,
  validHoldReason,
  validHoldUntil,
} from "../src/evidence-holds.ts";
import { TOKEN, ARTIFACT_ID } from "./fixtures.ts";
import {
  HOLD_ID,
  HOLD_CASE_ID,
  HOLD_KEY,
  HOLD_UNTIL,
  holdMutationFixture,
  holdCollectionFixture,
  holdRecordFixture,
} from "./hold-fixtures.ts";
const response = (value: unknown, status = 200) =>
  new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json" },
  });
const errorIs =
  (code = "INVALID_RESPONSE") =>
  (error: unknown) =>
    error instanceof ApiError && error.code === code;
const cursor = (id = HOLD_ID) => `v1.${id}.${"a".repeat(64)}`;
const otherHold = "ev_018f2a3b-4c5d-7000-8000-000000000071";

test("hold client uses exact routes, wire parameters and original idempotency keys", async (t) => {
  const replies = [
    holdMutationFixture(),
    holdMutationFixture(true, true),
    holdMutationFixture(true),
    holdCollectionFixture(),
  ];
  const paths = [
    `cases/${HOLD_CASE_ID}/holds`,
    `cases/${HOLD_CASE_ID}/holds`,
    `evidence-holds/${HOLD_ID}/release`,
    `cases/${HOLD_CASE_ID}/holds`,
  ];
  const bodies = [
    { artifact_id: ARTIFACT_ID, reason: "保留调查证据", hold_until: HOLD_UNTIL },
    { artifact_id: ARTIFACT_ID, reason: "保留调查证据", hold_until: HOLD_UNTIL },
    { reason: "调查已完成" },
  ];
  let count = 0;
  t.mock.method(globalThis, "fetch", async (path: string, options: RequestInit) => {
    assert.equal(path, `/control/v1/${paths[count]}`);
    assert.equal(options.method, count === 3 ? "GET" : "POST");
    assert.equal(options.credentials, "omit");
    assert.equal(options.cache, "no-store");
    assert.equal(options.redirect, "error");
    assert.equal(options.referrerPolicy, "no-referrer");
    assert.ok(options.signal instanceof AbortSignal);
    const headers = new Headers(options.headers);
    assert.equal(headers.get("Authorization"), `Bearer ${TOKEN}`);
    assert.equal(headers.get("Idempotency-Key"), count === 3 ? null : HOLD_KEY);
    assert.equal(options.body, count === 3 ? undefined : JSON.stringify(bodies[count]));
    return response(replies[count], count++ === 0 ? 201 : 200);
  });
  const client = new ControlClient(TOKEN);
  assert.equal(
    (
      await client.createEvidenceHold(
        HOLD_CASE_ID,
        ARTIFACT_ID,
        "保留调查证据",
        HOLD_UNTIL,
        HOLD_KEY,
      )
    ).replayed,
    false,
  );
  assert.equal(
    (
      await client.createEvidenceHold(
        HOLD_CASE_ID,
        ARTIFACT_ID,
        "保留调查证据",
        HOLD_UNTIL,
        HOLD_KEY,
      )
    ).released_reason,
    "调查已完成",
  );
  assert.equal(
    (await client.releaseEvidenceHold(HOLD_ID, "调查已完成", HOLD_KEY)).hold_id,
    HOLD_ID,
  );
  assert.equal((await client.evidenceHolds(HOLD_CASE_ID)).items.length, 1);
  assert.equal(count, 4);
});

test("hold input validates UTF-8 and nanosecond bounds without changing replay values", async (t) => {
  for (const value of [
    "1970-01-01T00:00:00.000Z",
    "2000-02-29T12:34:56.001Z",
    "2262-04-11T23:47:16.854Z",
  ])
    assert.equal(validHoldUntil(value), true);
  for (const value of [
    "1969-12-31T23:59:59.999Z",
    "2262-04-11T23:47:16.855Z",
    "2026-02-29T00:00:00.000Z",
    "2026-09-20T24:00:00.000Z",
    "2026-09-20T08:00:60.000Z",
    "2026-09-20T08:00:00Z",
    "2026-09-20T08:00:00.000000Z",
    "2026-09-20T08:00:00.000+00:00",
    `${HOLD_UNTIL}\n`,
  ])
    assert.equal(validHoldUntil(value), false, value);
  assert.equal(validHoldReason("中".repeat(170)), true);
  for (const value of ["中".repeat(171), " x", "x\u0085", "x\u007f", "\ud800", ""])
    assert.equal(validHoldReason(value), false);
  const fetch = t.mock.method(globalThis, "fetch", async () => response({}));
  const client = new ControlClient(TOKEN);
  await assert.rejects(
    client.createEvidenceHold(`${HOLD_CASE_ID}\n`, ARTIFACT_ID, "保留", HOLD_UNTIL, HOLD_KEY),
    errorIs("CONTROL_CASE_ID_INVALID"),
  );
  await assert.rejects(
    client.createEvidenceHold(HOLD_CASE_ID, `${ARTIFACT_ID}\n`, "保留", HOLD_UNTIL, HOLD_KEY),
    errorIs("CONTROL_ARTIFACT_ID_INVALID"),
  );
  await assert.rejects(
    client.createEvidenceHold(HOLD_CASE_ID, ARTIFACT_ID, " 保留", HOLD_UNTIL, HOLD_KEY),
    errorIs("CONTROL_EVIDENCE_HOLD_REQUEST_INVALID"),
  );
  await assert.rejects(
    client.createEvidenceHold(HOLD_CASE_ID, ARTIFACT_ID, "保留", `${HOLD_UNTIL}\n`, HOLD_KEY),
    errorIs("CONTROL_EVIDENCE_HOLD_REQUEST_INVALID"),
  );
  await assert.rejects(
    client.releaseEvidenceHold(`${HOLD_ID}\n`, "释放", HOLD_KEY),
    errorIs("CONTROL_EVIDENCE_HOLD_ID_INVALID"),
  );
  await assert.rejects(
    client.releaseEvidenceHold(HOLD_ID, "释放", "short"),
    errorIs("CONTROL_IDEMPOTENCY_KEY_INVALID"),
  );
  await assert.rejects(
    client.evidenceHolds(HOLD_CASE_ID, `${cursor()}\n`),
    errorIs("CONTROL_CURSOR_INVALID"),
  );
  assert.equal(fetch.mock.callCount(), 0);
});

test("hold continuation sends its exact cursor and historical creation retries keep old deadlines", async (t) => {
  const historical = {
    ...holdMutationFixture(false, true),
    created_at: "2000-01-01T00:00:00.000Z",
    hold_until: "2000-01-02T00:00:00.000Z",
  };
  let calls = 0;
  t.mock.method(globalThis, "fetch", async (path: string, options: RequestInit) => {
    if (calls++ === 0) {
      assert.equal(path, `/control/v1/cases/${HOLD_CASE_ID}/holds?cursor=${cursor()}`);
      return response({
        ...holdCollectionFixture(),
        items: [{ ...holdRecordFixture(), hold_id: otherHold }],
      });
    }
    assert.equal(JSON.parse(String(options.body)).hold_until, historical.hold_until);
    return response(historical);
  });
  const client = new ControlClient(TOKEN);
  assert.equal((await client.evidenceHolds(HOLD_CASE_ID, cursor())).items[0]?.hold_id, otherHold);
  assert.equal(
    (
      await client.createEvidenceHold(
        HOLD_CASE_ID,
        ARTIFACT_ID,
        historical.reason,
        historical.hold_until,
        HOLD_KEY,
      )
    ).replayed,
    true,
  );
  assert.equal(calls, 2);
});

test("hold decoder correlates immutable create/release input and HTTP replay status", () => {
  const decode = (value: unknown, status = 201) =>
    decodeHoldCreated(value, HOLD_CASE_ID, ARTIFACT_ID, "保留调查证据", HOLD_UNTIL, status);
  for (const change of [
    { schema_version: 2 },
    { case_id: "case_018f2a3b-4c5d-7000-8000-000000000032" },
    { artifact_id: "artifact_018f2a3b-4c5d-7000-8000-000000000001" },
    { reason: "修改理由" },
    { hold_until: "2026-09-24T08:00:00.000Z" },
    { replayed: true },
    { tenant_id: " bad" },
  ])
    assert.throws(() => decode({ ...holdMutationFixture(), ...change }), errorIs());
  assert.throws(() => decode(holdMutationFixture(), 200), errorIs());
  assert.throws(() => decode(holdMutationFixture(true), 201), errorIs());
  assert.equal(decode(holdMutationFixture(true, true), 200).replayed, true);
  for (const [value, status] of [
    [holdMutationFixture(), 200],
    [holdMutationFixture(true), 201],
    [{ ...holdMutationFixture(true), hold_id: otherHold }, 200],
    [{ ...holdMutationFixture(true), released_reason: "changed" }, 200],
  ] as const)
    assert.throws(() => decodeHoldReleased(value, HOLD_ID, "调查已完成", status), errorIs());
});

test("hold records reject inconsistent release tuples, malformed facts and invalid lifetimes", () => {
  const corruptions = [
    { released_by: "actor" },
    { released_at: "2026-09-20T08:01:00.000Z" },
    {
      released_event_id: HOLD_ID,
      released_by: "actor",
      released_reason: "释放",
      released_at: "2026-09-20T08:01:00.000Z",
    },
    { released_reason: "bad\u0001" },
    { created_by: "中".repeat(86) },
    { created_by: " actor" },
    { hold_until: "2026-09-20T08:00:00.000Z" },
    { hold_until: "2026-10-20T08:00:00.001Z" },
    { created_at: "2026-09-20T08:00:00.000000Z" },
    { released_at: undefined },
  ];
  for (const change of corruptions)
    assert.throws(
      () =>
        decodeHoldCollection(
          {
            ...holdCollectionFixture(),
            items: [{ ...holdRecordFixture(), ...change }],
          },
          HOLD_CASE_ID,
        ),
      errorIs(),
    );
  const historical = {
    ...holdCollectionFixture(),
    case_status: "closed",
    as_of: "2026-09-19T00:00:00.000001Z",
    items: [{ ...holdRecordFixture(true), released_at: "2026-09-19T08:00:00.000Z" }],
  };
  assert.equal(decodeHoldCollection(historical, HOLD_CASE_ID).items.length, 1);
});

test("hold history enforces page bounds, ascending identity and exact cursor binding", () => {
  const next = { ...holdRecordFixture(), hold_id: otherHold };
  const page = {
    ...holdCollectionFixture(),
    items: [holdRecordFixture(), next],
    truncated: true,
    next_cursor: cursor(otherHold),
  };
  assert.equal(decodeHoldCollection(page, HOLD_CASE_ID).next_cursor, cursor(otherHold));
  assert.equal(
    decodeHoldCollection({ ...page, items: [next] }, HOLD_CASE_ID, cursor()).items.length,
    1,
  );
  for (const change of [
    { items: [next, holdRecordFixture()] },
    { items: [next, next] },
    { items: [] },
    { next_cursor: cursor() },
    { truncated: false },
    { next_cursor: cursor(otherHold).toUpperCase() },
    { items: Array(129).fill(holdRecordFixture()) },
    { as_of: "2026-09-20T08:02:00.000Z" },
    { items: [{ ...next, case_id: "case_018f2a3b-4c5d-7000-8000-000000000032" }] },
  ])
    assert.throws(() => decodeHoldCollection({ ...page, ...change }, HOLD_CASE_ID), errorIs());
  assert.throws(() => decodeHoldCollection(page, HOLD_CASE_ID, cursor()), errorIs());
  const projected = decodeHoldCollection(
    {
      ...holdCollectionFixture(),
      key_ref: "sensitive",
      items: [{ ...holdRecordFixture(), storage_locator: "secret" }],
    },
    HOLD_CASE_ID,
  );
  assert.equal(JSON.stringify(projected).includes("sensitive"), false);
  assert.equal(JSON.stringify(projected).includes("secret"), false);
});

test("hold errors preserve safe reasons and abort without automatic mutation retry", async (t) => {
  const client = new ControlClient(TOKEN);
  const fetch = t.mock.method(globalThis, "fetch", async () =>
    response(
      {
        error_code: "CONTROL_EVIDENCE_HOLD_CONFLICT",
        message: `unsafe ${TOKEN}`,
        request_id: holdMutationFixture().request_id,
      },
      409,
    ),
  );
  await assert.rejects(
    client.releaseEvidenceHold(HOLD_ID, "调查已完成", HOLD_KEY),
    (error: unknown) => {
      assert.ok(error instanceof ApiError);
      assert.equal(error.code, "CONTROL_EVIDENCE_HOLD_CONFLICT");
      assert.equal(error.requestId, holdMutationFixture().request_id);
      assert.equal(error.message.includes(TOKEN), false);
      return true;
    },
  );
  await assert.rejects(
    client.releaseEvidenceHold(HOLD_ID, "调查已完成", HOLD_KEY, AbortSignal.abort()),
    errorIs("REQUEST_ABORTED"),
  );
  assert.equal(fetch.mock.callCount(), 1);
});
