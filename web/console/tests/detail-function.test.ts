import assert from "node:assert/strict";
import { test } from "node:test";
import type { RequestRow, Trace } from "../src/api/types.ts";
import { type PipelineStep, pipelineSteps } from "../src/features/request-detail/detail-model.ts";
import { requestDetails } from "./helpers/fixtures.ts";

const sample = requestDetails.find(
  (detail) => detail.summary.request_id === "req_01a1973ed5c0732b8f29804d7fc746d3",
);
if (sample === undefined) throw new Error("the search sample is missing");
const summary: RequestRow = {
  ...sample.summary,
  decision_path: "jev_deny",
  outcome: "blocked",
  context: "session",
  session: "a913ee40771c2b05",
  status: 403,
};
const base: Trace = { v: 1, values: [] };

function stepsOf(trace: Trace): PipelineStep[] {
  return pipelineSteps(summary, trace, null);
}

function stepNamed(steps: PipelineStep[], id: string): PipelineStep | undefined {
  return steps.find((step) => step.id === id);
}

test("the function step follows the session step", () => {
  const attempt = stepsOf({
    ...base,
    function: {
      key: "POST /api/admin/export",
      entry: "POST /api/admin/export",
      tier: "admin",
      attempt: "over_privilege",
    },
  });
  const ids = attempt.map((step) => step.id);
  assert.equal(ids[ids.indexOf("session") + 1], "function");
  const attemptStep = stepNamed(attempt, "function");
  assert.equal(
    attemptStep?.reason,
    "管理档功能 POST /api/admin/export：这个会话不是管理员，算尝试越权，交 Jev 并要求拒绝",
  );
  assert.equal(attemptStep?.warn, true);
  assert.equal(attemptStep?.done, true);

  const admin = stepNamed(
    stepsOf({
      ...base,
      function: { key: "GET /api/admin/y", entry: "GET /api/admin/y", tier: "admin" },
    }),
    "function",
  );
  assert.equal(admin?.reason, "管理档功能 GET /api/admin/y：管理员会话");
  assert.equal(admin?.warn, false);

  const unknown = stepsOf({ ...base, function: { key: "GET /metrics", known: false } });
  assert.equal(
    unknown.map((step) => step.id)[unknown.map((step) => step.id).indexOf("session") + 1],
    "function",
  );
  assert.equal(
    stepNamed(unknown, "function")?.reason,
    "GET /metrics 不在功能表里，按未知功能交 Jev",
  );
  assert.equal(stepNamed(unknown, "function")?.warn, true);

  const both = stepNamed(
    stepsOf({
      ...base,
      function: {
        key: "GET /api/admin/x",
        entry: "GET /api/admin/x",
        tier: "admin",
        attempt: "over_privilege",
        known: false,
      },
    }),
    "function",
  );
  assert.equal(
    both?.reason,
    "管理档功能 GET /api/admin/x：这个会话不是管理员，算尝试越权，交 Jev 并要求拒绝；GET /api/admin/x 不在功能表里，按未知功能交 Jev",
  );
  assert.equal(both?.warn, true);
});

test("a request that reaches the entry under another spelling says which key it was", () => {
  const routed = stepNamed(
    stepsOf({
      ...base,
      function: {
        key: "GET /api/admin/export",
        entry: "POST /api/admin/export",
        tier: "admin",
        attempt: "over_privilege",
      },
    }),
    "function",
  );
  assert.equal(
    routed?.reason,
    "请求是 GET /api/admin/export，按 POST /api/admin/export 处理：这个会话不是管理员，算尝试越权，交 Jev 并要求拒绝",
  );
});

test("a record without a function has no function step, and an old record has none either", () => {
  assert.equal(stepNamed(stepsOf(base), "function"), undefined);
  assert.equal(
    stepNamed(
      stepsOf({ v: 0, values: [], function: { key: "GET /metrics", known: false } }),
      "function",
    ),
    undefined,
  );
});
