import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiError } from "../src/api-contract.ts";
import {
  decodeSavedViewCreated,
  decodeSavedViewDeleted,
  decodeSavedViewList,
  savedViewCreateBody,
  validateSavedViewCursor,
  validateSavedViewId,
  validateSavedViewName,
} from "../src/saved-views.ts";
import type { SearchPlan } from "../src/search.ts";

const VIEW_NEW = "view_018f2a3b-4c5d-7000-8000-000000000052";
const VIEW_OLD = "view_018f2a3b-4c5d-7000-8000-000000000041";
const CURSOR = `v1.${VIEW_OLD}.${"a".repeat(64)}`;
const envelope = {
  request_id: "req_018f2a3b-4c5d-7000-8000-000000000042",
  tenant_id: "tenant_demo",
  site_id: "site_demo",
};
const WINDOW = { start: "2026-09-20T08:00:00Z", end: "2026-09-21T08:00:00Z" };
const plan: SearchPlan = {
  schema_version: 3,
  ...WINDOW,
  filters: [{ kind: "text", field: "event_type", value: "request.completed" }],
  sort: "occurred_at_desc",
  limit: 25,
} as SearchPlan;
const item = (view_id: string, overrides: Record<string, unknown> = {}) => ({
  view_id,
  name: "Weekly review",
  search: plan,
  created_at: "2026-10-09T01:00:00.000Z",
  ...overrides,
});
const page = (items: unknown[], extra: Record<string, unknown> = {}) => ({
  ...envelope,
  schema_version: 1,
  as_of: "2026-10-09T01:02:03.123456Z",
  items,
  truncated: false,
  next_cursor: null,
  ...extra,
});

test("names are 1 to 160 bytes without control characters", () => {
  assert.equal(validateSavedViewName("Weekly review"), "Weekly review");
  for (const bad of ["", "a\nb", "\u0007", "x".repeat(161), "界".repeat(54)]) {
    assert.throws(() => validateSavedViewName(bad), ApiError);
  }
});

test("the create body carries a checked plan and never a cursor", () => {
  const body = JSON.parse(savedViewCreateBody("Weekly review", plan));
  assert.deepEqual(Object.keys(body).sort(), ["name", "schema_version", "search"]);
  assert.equal(body.schema_version, 1);
  assert.equal("cursor" in body.search, false);
  assert.throws(() => savedViewCreateBody("", plan), ApiError);
});

test("a complete page decodes in descending order and names its last row", () => {
  const decoded = decodeSavedViewList(page([item(VIEW_NEW), item(VIEW_OLD)]));
  assert.deepEqual(
    decoded.items.map((row) => row.view_id),
    [VIEW_NEW, VIEW_OLD],
  );
  assert.equal(decoded.items[0]?.search.limit, 25);
  const next = decodeSavedViewList(
    page([item(VIEW_OLD)], { truncated: true, next_cursor: CURSOR }),
    undefined,
  );
  assert.equal(next.next_cursor, CURSOR);
  assert.throws(() => decodeSavedViewList(page([item(VIEW_OLD)]), CURSOR), ApiError);
  assert.throws(
    () =>
      decodeSavedViewList(
        page([item(VIEW_OLD)], {
          truncated: true,
          next_cursor: `v1.${VIEW_NEW}.${"b".repeat(64)}`,
        }),
      ),
    ApiError,
  );
});

test("a stored search that is not a valid plan is refused as an invalid response", () => {
  assert.throws(
    () => decodeSavedViewList(page([item(VIEW_NEW, { search: { schema_version: 2 } })])),
    ApiError,
  );
});

test("create and delete responses must echo the name and identity they were asked for", () => {
  const created = decodeSavedViewCreated(
    {
      ...envelope,
      schema_version: 1,
      view_id: VIEW_NEW,
      name: "Weekly review",
      created_at: "2026-10-09T01:00:00.000Z",
    },
    "Weekly review",
  );
  assert.equal(created.view_id, VIEW_NEW);
  assert.throws(
    () =>
      decodeSavedViewCreated(
        {
          ...envelope,
          schema_version: 1,
          view_id: VIEW_NEW,
          name: "Other",
          created_at: "2026-10-09T01:00:00.000Z",
        },
        "Weekly review",
      ),
    ApiError,
  );
  assert.deepEqual(
    decodeSavedViewDeleted(
      { ...envelope, schema_version: 1, view_id: VIEW_OLD, deleted: true },
      VIEW_OLD,
    ).deleted,
    true,
  );
  assert.throws(
    () =>
      decodeSavedViewDeleted(
        { ...envelope, schema_version: 1, view_id: VIEW_NEW, deleted: true },
        VIEW_OLD,
      ),
    ApiError,
  );
});

test("identifiers and cursors accept only their canonical shapes", () => {
  assert.equal(validateSavedViewId(VIEW_NEW), VIEW_NEW);
  assert.throws(() => validateSavedViewId(`${VIEW_NEW}x`), ApiError);
  assert.throws(() => validateSavedViewId("view_not-a-uuid"), ApiError);
  assert.equal(validateSavedViewCursor(CURSOR), VIEW_OLD);
  assert.throws(() => validateSavedViewCursor("v1.job_x.aa"), ApiError);
});
