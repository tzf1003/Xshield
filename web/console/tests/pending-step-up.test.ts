import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiError } from "../src/api-contract.ts";
import { PendingOperationStore } from "../src/security/pending-operations.ts";

const KEY = "0123456789abcdef-key";
const stepUp = () => new ApiError("CONTROL_EXPORT_STEP_UP_REQUIRED", 403);

function frozen(store: PendingOperationStore) {
  return store.freeze({
    label: "导出审批",
    method: "POST",
    path: "/control/v1/exports/export_018f2a3b-4c5d-7000-8000-000000000071/approve",
    body: { reason: "独立复核通过" },
    idempotencyKey: KEY,
    execute: async () => {
      throw new Error("the store is exercised directly; nothing is sent");
    },
  });
}

test("a step-up refusal of a first attempt keeps the request and is not an unresolved write", () => {
  const store = new PendingOperationStore();
  const operation = frozen(store);
  store.start(operation.id);
  assert.equal(store.fail(operation.id, stepUp()), "step_up");
  assert.equal(store.get(operation.id)?.phase, "step_up");
  // The server did nothing, so leaving the page (to re-verify) must not warn.
  assert.equal(store.unresolvedCount, 0);
});

test("after an ambiguous attempt a step-up refusal proves nothing: the write stays unknown", () => {
  const store = new PendingOperationStore();
  const operation = frozen(store);
  store.start(operation.id);
  assert.equal(store.fail(operation.id, new ApiError("NETWORK_UNAVAILABLE", 0)), "unknown");
  // The retry is refused because the MFA window lapsed in the meantime.
  store.start(operation.id);
  assert.equal(store.fail(operation.id, stepUp()), "unknown");
  const kept = store.get(operation.id);
  assert.equal(kept?.phase, "unknown");
  assert.equal(kept?.attempts, 2);
  assert.equal(kept?.lastError?.code, "CONTROL_EXPORT_STEP_UP_REQUIRED");
  // The first attempt may have committed, so the page-leave warning stays armed ...
  assert.equal(store.unresolvedCount, 1);
  // ... and the only way forward is the identical request under the identical key.
  const again = store.start(operation.id);
  assert.equal(again.snapshot.idempotencyKey, KEY);
  assert.equal(again.snapshot.body, '{"reason":"独立复核通过"}');
});

test("a later plain refusal after such a step-up refusal still cannot resolve the write", () => {
  const store = new PendingOperationStore();
  const operation = frozen(store);
  store.start(operation.id);
  store.fail(operation.id, new ApiError("REQUEST_TIMEOUT", 0));
  store.start(operation.id);
  store.fail(operation.id, stepUp());
  store.start(operation.id);
  assert.equal(
    store.fail(operation.id, new ApiError("CONTROL_EVIDENCE_ACCESS_DECISION_CONFLICT", 409)),
    "unknown",
  );
  assert.equal(store.unresolvedCount, 1);
});
