import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiError, ControlClient } from "../src/api.ts";
import { decodeJobResponse } from "../src/jobs.ts";

const CASE_ID = "case_018f2a3b-4c5d-7000-8000-000000000031";
const JOB_ID = "job_018f2a3b-4c5d-7000-8000-000000000041";
const KEY = "synthetic-case-analysis-key-0001";
const envelope = {
  request_id: "req_018f2a3b-4c5d-7000-8000-000000000042",
  tenant_id: "tenant_demo",
  site_id: "site_demo",
};
const job = {
  job_id: JOB_ID,
  kind: "case_analysis",
  status: "succeeded",
  checkpoint: "inventory_committed",
  reason_code: "CONTROL_CASE_ANALYSIS_COMPLETE",
  retryable: false,
  case_id: CASE_ID,
  artifact_count: 3,
  active_artifact_count: 2,
  created_at: "2026-09-20T08:00:00.000Z",
  updated_at: "2026-09-20T08:00:00.123Z",
  completed_at: "2026-09-20T08:00:00.123Z",
  replayed: false,
};

test("case analysis and job reads keep strict paths and idempotency", async (t) => {
  let call = 0;
  t.mock.method(globalThis, "fetch", async (path: string, options: RequestInit) => {
    call += 1;
    assert.equal(options.credentials, "omit");
    assert.equal(options.cache, "no-store");
    assert.equal(options.redirect, "error");
    if (call === 1) {
      assert.equal(path, `/control/v1/cases/${CASE_ID}/analyze`);
      assert.equal(options.method, "POST");
      assert.equal(options.body, "");
      assert.equal((options.headers as Record<string, string>)["Idempotency-Key"], KEY);
      return new Response(JSON.stringify({ ...envelope, found: true, job }), {
        status: 202,
        headers: { "Content-Type": "application/json" },
      });
    }
    assert.equal(path, `/control/v1/jobs/${JOB_ID}`);
    assert.equal(options.method, "GET");
    assert.equal(options.body, undefined);
    return new Response(
      JSON.stringify({ ...envelope, found: true, job: { ...job, replayed: true } }),
      {
        status: 200,
        headers: { "Content-Type": "application/json" },
      },
    );
  });

  const client = new ControlClient("t".repeat(32));
  const created = await client.analyzeCase(CASE_ID, KEY);
  assert.equal(created.job?.job_id, JOB_ID);
  assert.equal(created.job?.replayed, false);
  const read = await client.job(JOB_ID);
  assert.equal(read.job?.replayed, true);
  assert.equal(call, 2);
});

test("unknown jobs remain an opaque not-found response", () => {
  const result = decodeJobResponse({ ...envelope, found: false, job: null }, 200);
  assert.equal(result.found, false);
  assert.equal(result.job, null);
});

test("job decoder rejects inconsistent completion metadata", () => {
  assert.throws(
    () => decodeJobResponse({ ...envelope, found: true, job: { ...job, completed_at: null } }, 200),
    (error: unknown) => error instanceof ApiError && error.code === "INVALID_RESPONSE",
  );
});

test("client validates job IDs before making a request", async () => {
  await assert.rejects(
    new ControlClient("t".repeat(32)).job("case_not-a-job"),
    (error: unknown) => error instanceof ApiError && error.code === "CONTROL_JOB_ID_INVALID",
  );
});
