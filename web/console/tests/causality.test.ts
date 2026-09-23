import assert from "node:assert/strict";
import test from "node:test";
import { ApiError, ControlClient } from "../src/api.ts";
import {
  decodeCausalityResponse,
  validateCausalityPlan,
  type CausalityPlan,
} from "../src/search.ts";
import { causalityFixture, TOKEN } from "./fixtures.ts";

const ROOT = "ev_018f2a3b-4c5d-7000-8000-000000000001";
const PLAN: CausalityPlan = {
  schema_version: 3,
  start: "2026-09-20T00:00:00Z",
  end: "2026-09-21T00:00:00Z",
  event_id: ROOT,
  direction: "both",
  max_depth: 2,
  max_nodes: 4,
};

test("causality plan validation keeps strict UTC and graph bounds", () => {
  assert.deepEqual(validateCausalityPlan(PLAN), PLAN);
  for (const mutation of [
    { ...PLAN, start: "2026-09-20T00:00:00.001Z" },
    { ...PLAN, direction: "all" },
    { ...PLAN, max_depth: 0 },
    { ...PLAN, max_nodes: 17 },
    { ...PLAN, extra: true },
  ]) {
    assert.throws(
      () => validateCausalityPlan(mutation),
      (error: unknown) =>
        error instanceof ApiError &&
        error.code === "CONTROL_CAUSALITY_REQUEST_INVALID",
    );
  }
});

test("causality client posts the frozen plan and decodes redacted nodes", async (t) => {
  let body: unknown;
  t.mock.method(globalThis, "fetch", async (path: string, options: RequestInit) => {
    assert.equal(path, "/control/v1/causality");
    assert.equal(options.method, "POST");
    assert.deepEqual(options.headers, {
      Authorization: `Bearer ${TOKEN}`,
      Accept: "application/json",
      "Content-Type": "application/json",
    });
    body = JSON.parse(String(options.body));
    return new Response(JSON.stringify(await causalityFixture(body as CausalityPlan)), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  });
  const result = await new ControlClient(TOKEN).causality(PLAN);
  assert.deepEqual(body, PLAN);
  assert.equal(result.root_event_id, ROOT);
  assert.equal(result.nodes.length, 2);
  assert.ok(result.nodes.every((node) => !Object.hasOwn(node.event, "payload_json")));
  assert.throws(() => decodeCausalityResponse({ ...result, root_event_id: `${ROOT}x` }, PLAN));
});
