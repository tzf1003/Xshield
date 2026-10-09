import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiError } from "../src/api-contract.ts";
import { decodeJobList, validateJobListCursor } from "../src/job-list.ts";

const CASE_ID = "case_018f2a3b-4c5d-7000-8000-000000000031";
const JOB_NEW = "job_018f2a3b-4c5d-7000-8000-000000000052";
const JOB_OLD = "job_018f2a3b-4c5d-7000-8000-000000000041";
const CURSOR = `v1.${JOB_OLD}.${"a".repeat(64)}`;
const envelope = {
  request_id: "req_018f2a3b-4c5d-7000-8000-000000000042",
  tenant_id: "tenant_demo",
  site_id: "site_demo",
};
const item = (job_id: string, overrides: Record<string, unknown> = {}) => ({
  job_id,
  kind: "case_analysis",
  status: "succeeded",
  checkpoint: "inventory_committed",
  reason_code: "CONTROL_CASE_ANALYSIS_COMPLETE",
  retryable: false,
  case_id: CASE_ID,
  artifact_count: 3,
  active_artifact_count: 1,
  created_at: "2026-10-09T01:00:00.000Z",
  updated_at: "2026-10-09T01:00:01.000Z",
  completed_at: "2026-10-09T01:00:01.000Z",
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

test("a complete page decodes, keeping the server's descending order", () => {
  const decoded = decodeJobList(page([item(JOB_NEW), item(JOB_OLD)]));
  assert.deepEqual(
    decoded.items.map((row) => row.job_id),
    [JOB_NEW, JOB_OLD],
  );
  assert.equal(decoded.truncated, false);
  assert.equal(decoded.next_cursor, null);
});

test("a continuation page must start below its cursor and name its last row", () => {
  const next = decodeJobList(
    page([item(JOB_OLD)], { truncated: true, next_cursor: CURSOR }),
    undefined,
  );
  assert.equal(next.next_cursor, CURSOR);
  // The cursor names JOB_OLD, so a row at or above it cannot follow.
  assert.throws(() => decodeJobList(page([item(JOB_OLD)]), CURSOR), ApiError);
  assert.throws(
    () => decodeJobList(page([item(JOB_NEW)], { truncated: true, next_cursor: CURSOR })),
    ApiError,
  );
});

test("the next cursor must name the last returned row", () => {
  const other = `v1.${JOB_NEW}.${"b".repeat(64)}`;
  assert.throws(
    () => decodeJobList(page([item(JOB_OLD)], { truncated: true, next_cursor: other })),
    ApiError,
  );
  assert.throws(() => decodeJobList(page([], { truncated: true, next_cursor: CURSOR })), ApiError);
});

test("only queued and running jobs lack a completion time, and counts stay ordered", () => {
  const running = item(JOB_NEW, {
    status: "running",
    completed_at: null,
    checkpoint: "inventory_pending",
  });
  assert.equal(decodeJobList(page([running])).items[0]?.completed_at, null);
  assert.throws(() => decodeJobList(page([item(JOB_NEW, { completed_at: null })])), ApiError);
  assert.throws(() => decodeJobList(page([item(JOB_NEW, { status: "queued" })])), ApiError);
  assert.throws(() => decodeJobList(page([item(JOB_NEW, { active_artifact_count: 4 })])), ApiError);
});

test("items reject foreign shapes and unknown statuses", () => {
  for (const override of [
    { job_id: "job_not-a-uuid" },
    { kind: "model_run" },
    { status: "archived" },
    { checkpoint: "bad\u0007" },
    { retryable: "no" },
  ]) {
    assert.throws(() => decodeJobList(page([item(JOB_NEW, override)])), ApiError);
  }
});

test("owner references in a row are not projected into the result", () => {
  const decoded = decodeJobList(page([item(JOB_NEW, { owner_ref: "investigator-1" })]));
  assert.equal("owner_ref" in decoded.items[0]!, false);
  assert.equal(JSON.stringify(decoded).includes("investigator-1"), false);
});

test("cursor validation accepts only the job cursor shape", () => {
  assert.equal(validateJobListCursor(undefined), undefined);
  assert.equal(validateJobListCursor(CURSOR), JOB_OLD);
  for (const bad of ["", "v1.case_x.aa", `v2.${JOB_OLD}.${"a".repeat(64)}`, `v1.${JOB_OLD}.zz`]) {
    assert.throws(() => validateJobListCursor(bad), ApiError);
  }
});
