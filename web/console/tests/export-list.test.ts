import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiError, ControlClient } from "../src/api.ts";
import type { ExportListView } from "../src/exports.ts";
import { EXPORT_ID, exportListFixture, exportListItemFixture } from "./export-fixtures.ts";
import { errorFixture, TOKEN } from "./fixtures.ts";

const cursor = `v1.${EXPORT_ID}.${"a".repeat(64)}`;
const earlier = `${EXPORT_ID.slice(0, -2)}70`;
const response = (value: unknown, status = 200) =>
  new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json" },
  });
const errorIs = (code: string) => (error: unknown) => {
  assert.ok(error instanceof ApiError);
  assert.equal(error.code, code);
  assert.ok(!error.message.includes(TOKEN));
  return true;
};

test("export lists use fixed GET routes and drop everything that is not projected", async (t) => {
  const fixtures = [exportListFixture(), exportListFixture("review")];
  fixtures[0]?.items.splice(0, 1, exportListItemFixture("ready"));
  const reviewItem = fixtures[1]?.items[0];
  assert.ok(reviewItem);
  reviewItem.export_id = earlier;
  let calls = 0;
  t.mock.method(globalThis, "fetch", async (path: string, init: RequestInit) => {
    const index = calls++;
    assert.equal(
      path,
      `/control/v1/exports?view=${index === 0 ? "mine" : `review&cursor=${cursor}`}`,
    );
    assert.equal(init.method, "GET");
    assert.equal(init.body, undefined);
    const headers = new Headers(init.headers);
    assert.equal(headers.get("Authorization"), `Bearer ${TOKEN}`);
    assert.equal(headers.get("Idempotency-Key"), null);
    assert.equal(init.credentials, "omit");
    assert.equal(init.cache, "no-store");
    assert.equal(init.redirect, "error");
    assert.equal(init.referrerPolicy, "no-referrer");
    const page = fixtures[index];
    assert.ok(page);
    return response({
      ...page,
      private_key: "synthetic-private",
      items: page.items.map((item) => ({
        ...item,
        purpose: "not-listed",
        package_artifact_id: "artifact_must_not_appear",
      })),
    });
  });
  const client = new ControlClient(TOKEN);
  assert.deepEqual(await client.exportList("mine"), fixtures[0]);
  assert.deepEqual(await client.exportList("review", cursor), fixtures[1]);
  assert.equal(calls, 2);
});

test("invalid views and cursor shapes reject before the network; aborted reads stay aborted", async (t) => {
  const calls = t.mock.method(globalThis, "fetch", async () => {
    throw new Error("unexpected");
  });
  const client = new ControlClient(TOKEN);
  for (const view of ["all", "mine\n", "review&view=mine", "", null])
    await assert.rejects(
      client.exportList(view as ExportListView),
      errorIs("CONTROL_EXPORT_LIST_REQUEST_INVALID"),
    );
  for (const value of [
    "",
    `${cursor}\n`,
    cursor.toUpperCase(),
    `${cursor}&view=review`,
    cursor.replace("v1", "v2"),
    `v1.${EXPORT_ID}.${"a".repeat(63)}`,
    // An access-request or case cursor must never be accepted for an export list.
    `v1.access_018f2a3b-4c5d-7000-8000-000000000041.${"a".repeat(64)}`,
    `v1.case_018f2a3b-4c5d-7000-8000-000000000031.${"a".repeat(64)}`,
  ])
    await assert.rejects(client.exportList("mine", value), errorIs("CONTROL_CURSOR_INVALID"));
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(
    client.exportList("mine", undefined, controller.signal),
    errorIs("REQUEST_ABORTED"),
  );
  assert.equal(calls.mock.callCount(), 0);
});

type Page = ReturnType<typeof exportListFixture>;
const first = (row: Page) => {
  const item = row.items[0];
  assert.ok(item);
  return item;
};

test("export list scope, precision, ordering, view and cursor edges are validated", async (t) => {
  let value: unknown;
  t.mock.method(globalThis, "fetch", async () => response(value));
  const client = new ControlClient(TOKEN);
  value = exportListFixture();
  await client.exportList("mine");
  const mutations: Array<(row: Page) => void> = [
    (row) => {
      row.schema_version = 4 as 3;
    },
    (row) => {
      row.view = "review";
    },
    (row) => {
      row.tenant_id = "../tenant";
    },
    (row) => {
      row.site_id = "../site";
    },
    (row) => {
      row.as_of = "2026-02-30T08:00:00.000000Z";
    },
    (row) => {
      // Only the observation keeps microseconds; milliseconds are not enough there ...
      row.as_of = "2026-09-20T08:00:00.000Z";
    },
    (row) => {
      // ... and item times are milliseconds, never microseconds.
      first(row).requested_at = "2026-09-20T08:00:00.000000Z";
    },
    (row) => {
      first(row).export_id += "\n";
    },
    (row) => {
      first(row).case_id = "bad";
    },
    (row) => {
      first(row).requested_by = " leading";
    },
    (row) => {
      first(row).requested_by = "x".repeat(257);
    },
    (row) => {
      first(row).status = "other" as "ready";
    },
    (row) => {
      // A decided row must name its decider and time; a pending row must not.
      first(row).decided_by = "synthetic-approver";
    },
    (row) => {
      row.items[0] = exportListItemFixture("ready");
      first(row).decided_by = null;
    },
    (row) => {
      // Separation of duties holds in the projection itself.
      row.items[0] = exportListItemFixture("ready");
      first(row).decided_by = first(row).requested_by;
    },
    (row) => {
      row.items[0] = exportListItemFixture("ready");
      first(row).expires_at = null;
    },
    (row) => {
      row.items[0] = exportListItemFixture("rejected");
      first(row).expires_at = "2026-09-20T08:25:00.000Z";
    },
    (row) => {
      row.items[0] = exportListItemFixture("ready");
      first(row).decided_at = "2026-09-19T08:10:00.000Z";
    },
    (row) => {
      row.items.push({ ...first(row) });
    },
    (row) => {
      row.items.unshift({ ...first(row), export_id: earlier });
    },
    (row) => {
      row.items = Array.from({ length: 129 }, () => ({ ...first(row) }));
    },
    (row) => {
      row.truncated = true;
    },
    (row) => {
      row.next_cursor = cursor;
    },
    (row) => {
      row.truncated = true;
      row.next_cursor = `${cursor}\n`;
    },
    (row) => {
      row.truncated = true;
      row.next_cursor = cursor.replace(EXPORT_ID, earlier);
    },
    (row) => {
      row.truncated = true;
      row.next_cursor = cursor;
      row.items = [];
    },
  ];
  for (const mutate of mutations) {
    const row = exportListFixture();
    mutate(row);
    value = row;
    await assert.rejects(
      client.exportList("mine"),
      (error) => error instanceof ApiError,
      `mutation ${mutations.indexOf(mutate)}`,
    );
  }
  const valid = exportListFixture();
  valid.truncated = true;
  valid.next_cursor = cursor;
  value = valid;
  assert.deepEqual(await client.exportList("mine"), valid);
  // The same page is not acceptable as a continuation of itself: the order must keep falling.
  await assert.rejects(client.exportList("mine", cursor), errorIs("INVALID_RESPONSE"));
  first(valid).export_id = earlier;
  valid.next_cursor = cursor.replace(EXPORT_ID, earlier);
  assert.deepEqual(await client.exportList("mine", cursor), valid);
});

test("mine keeps every persistent state; review holds pending rows only; empty is explicit", async (t) => {
  let fixture = exportListFixture();
  t.mock.method(globalThis, "fetch", async () => response(fixture));
  const client = new ControlClient(TOKEN);
  for (const status of [
    "pending_approval",
    "approved",
    "ready",
    "rejected",
    "expired",
    "failed",
  ] as const) {
    fixture.items = [exportListItemFixture(status)];
    assert.equal((await client.exportList("mine")).items[0]?.status, status);
  }
  fixture = exportListFixture("review");
  assert.equal((await client.exportList("review")).items.length, 1);
  fixture.items = [exportListItemFixture("approved")];
  await assert.rejects(client.exportList("review"), errorIs("INVALID_RESPONSE"));
  fixture.items = [];
  assert.deepEqual((await client.exportList("review")).items, []);
});

test("role denials and list failure reasons retain safe structured errors", async (t) => {
  let code = "CONTROL_SCOPE_DENIED";
  t.mock.method(globalThis, "fetch", async () => response(errorFixture(code), 403));
  for (const next of [
    "CONTROL_SCOPE_DENIED",
    "CONTROL_CURSOR_INVALID",
    "CONTROL_EXPORT_LIST_REQUEST_INVALID",
    "CONTROL_EXPORT_BUSY",
    "CONTROL_EXPORT_STORE_UNAVAILABLE",
  ]) {
    code = next;
    await assert.rejects(new ControlClient(TOKEN).exportList("review"), errorIs(code));
  }
});
