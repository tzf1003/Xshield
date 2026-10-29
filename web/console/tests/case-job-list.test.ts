import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiError } from "../src/api-contract.ts";
import { decodeCaseJobList, validateCaseJobListCursor } from "../src/case-job-list.ts";

const CASE_ID = "case_018f2a3b-4c5d-7000-8000-000000000031";
const OTHER_CASE_ID = "case_018f2a3b-4c5d-7000-8000-000000000032";
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
  case_id: CASE_ID,
  as_of: "2026-10-09T01:02:03.123456Z",
  items,
  truncated: false,
  next_cursor: null,
  ...extra,
});

test("a complete page decodes, keeping the server's descending order", () => {
  const decoded = decodeCaseJobList(page([item(JOB_NEW), item(JOB_OLD)]), CASE_ID);
  assert.deepEqual(
    decoded.items.map((row) => row.job_id),
    [JOB_NEW, JOB_OLD],
  );
  assert.equal(decoded.case_id, CASE_ID);
  assert.equal(decoded.truncated, false);
  assert.equal(decoded.next_cursor, null);
});

test("a page for a different case than requested is rejected", () => {
  assert.throws(() => decodeCaseJobList(page([item(JOB_NEW)]), OTHER_CASE_ID), ApiError);
});

test("a continuation page must start below its cursor and name its last row", () => {
  const next = decodeCaseJobList(
    page([item(JOB_OLD)], { truncated: true, next_cursor: CURSOR }),
    CASE_ID,
    undefined,
  );
  assert.equal(next.next_cursor, CURSOR);
  // The cursor names JOB_OLD, so a row at or above it cannot follow.
  assert.throws(() => decodeCaseJobList(page([item(JOB_OLD)]), CASE_ID, CURSOR), ApiError);
  assert.throws(
    () =>
      decodeCaseJobList(page([item(JOB_NEW)], { truncated: true, next_cursor: CURSOR }), CASE_ID),
    ApiError,
  );
});

test("the next cursor must name the last returned row", () => {
  const other = `v1.${JOB_NEW}.${"b".repeat(64)}`;
  assert.throws(
    () =>
      decodeCaseJobList(page([item(JOB_OLD)], { truncated: true, next_cursor: other }), CASE_ID),
    ApiError,
  );
  assert.throws(
    () => decodeCaseJobList(page([], { truncated: true, next_cursor: CURSOR }), CASE_ID),
    ApiError,
  );
});

test("only queued and running jobs lack a completion time, and counts stay ordered", () => {
  const running = item(JOB_NEW, {
    status: "running",
    completed_at: null,
    checkpoint: "inventory_pending",
  });
  assert.equal(decodeCaseJobList(page([running]), CASE_ID).items[0]?.completed_at, null);
  assert.throws(
    () => decodeCaseJobList(page([item(JOB_NEW, { completed_at: null })]), CASE_ID),
    ApiError,
  );
  assert.throws(
    () => decodeCaseJobList(page([item(JOB_NEW, { status: "queued" })]), CASE_ID),
    ApiError,
  );
  assert.throws(
    () => decodeCaseJobList(page([item(JOB_NEW, { active_artifact_count: 4 })]), CASE_ID),
    ApiError,
  );
});

test("items reject foreign shapes and unknown statuses", () => {
  for (const override of [
    { job_id: "job_not-a-uuid" },
    { kind: "model_run" },
    { status: "archived" },
    { checkpoint: "bad\u0007" },
    { retryable: "no" },
  ]) {
    assert.throws(() => decodeCaseJobList(page([item(JOB_NEW, override)]), CASE_ID), ApiError);
  }
});

test("a case reference on a row is not projected into the result", () => {
  const decoded = decodeCaseJobList(page([item(JOB_NEW, { case_id: OTHER_CASE_ID })]), CASE_ID);
  assert.equal("case_id" in decoded.items[0]!, false);
});

test("cursor validation accepts only the job cursor shape", () => {
  assert.equal(validateCaseJobListCursor(undefined), undefined);
  assert.equal(validateCaseJobListCursor(CURSOR), JOB_OLD);
  for (const bad of ["", "v1.case_x.aa", `v2.${JOB_OLD}.${"a".repeat(64)}`, `v1.${JOB_OLD}.zz`]) {
    assert.throws(() => validateCaseJobListCursor(bad), ApiError);
  }
});
