import assert from "node:assert/strict";
import { afterEach, test } from "node:test";
import { type BrowserSession, ControlClient } from "../src/api.ts";
import { ApiError } from "../src/api-contract.ts";
import { isStepUpRequired, isUnauthorized } from "../src/security/errors.ts";
import { runFrozenWrite } from "../src/security/guarded.ts";
import { installBeforeUnloadGuard } from "../src/security/pending-operations.ts";
import { createSessionRuntime as createRuntime } from "../src/security/runtime.ts";
import { unauthorizedNotice } from "../src/security/session-store.ts";

const created: ReturnType<typeof createRuntime>[] = [];
afterEach(() => {
  for (const runtime of created.splice(0)) {
    runtime.store.disconnect(null);
    runtime.queryClient.clear();
  }
});

const scope = { tenant_id: "tenant_a", site_id: "site_a" };
const csrf = "0".repeat(64);
const KEY = "synthetic-operation-key-0001";
const session: BrowserSession = {
  subject: "operator",
  ...scope,
  csrf_token: csrf,
  roles: ["system_admin"],
  session_expires_at: "2027-01-01T08:00:00.000Z",
  idle_expires_at: "2027-01-01T00:15:00.000Z",
  last_reauthenticated_at: null,
  step_up_valid: false,
};

function connected() {
  const runtime = createRuntime({ queryGcMs: 0 });
  created.push(runtime);
  runtime.store.connect({
    client: new ControlClient(undefined, csrf),
    scope,
    roles: ["system_admin"],
    session,
  });
  return runtime;
}

const reply = () => ({ request_id: "req_018f2a3b-4c5d-7000-8000-000000000001", ...scope });
const stepUp = () => new ApiError("CONTROL_SITE_DELETE_STEP_UP_REQUIRED", 403);

function deleteSite(runtime: ReturnType<typeof connected>, outcomes: (call: number) => unknown) {
  const calls: { key: string }[] = [];
  const frozen = runtime.pending.freeze({
    label: "删除站点 · site_a",
    method: "DELETE",
    path: "/control/v1/sites/site_a",
    idempotencyKey: KEY,
    expectedSiteId: "site_a",
    execute: async (_client, _signal, key) => {
      calls.push({ key });
      const outcome = outcomes(calls.length);
      if (outcome instanceof Error) throw outcome;
      return outcome as ReturnType<typeof reply>;
    },
  });
  return { calls, frozen };
}

test("only the step-up refusals are step-up refusals", () => {
  for (const [code, status] of [
    ["CONTROL_SITE_DELETE_STEP_UP_REQUIRED", 403],
    ["CONTROL_STEP_UP_REQUIRED", 401],
    ["CONTROL_STEP_UP_REQUIRED", 403],
    ["CONTROL_EXPORT_STEP_UP_REQUIRED", 403],
  ] as const) {
    assert.equal(isStepUpRequired(new ApiError(code, status)), true, `${code} ${status}`);
  }
  assert.equal(isStepUpRequired(new ApiError("CONTROL_SCOPE_DENIED", 403)), false);
  assert.equal(isStepUpRequired(new ApiError("CONTROL_AUTH_REQUIRED", 401)), false);
  assert.equal(isStepUpRequired(new ApiError("CONTROL_SITE_DELETE_STEP_UP_REQUIRED", 500)), false);
  assert.equal(isStepUpRequired(new Error("x")), false);
  // A step-up 401 is not a dead session; every other 401 still is.
  assert.equal(isUnauthorized(new ApiError("CONTROL_STEP_UP_REQUIRED", 401)), false);
  assert.equal(isUnauthorized(new ApiError("CONTROL_AUTH_REQUIRED", 401)), true);
  assert.equal(isUnauthorized(new ApiError("CONTROL_CSRF_REQUIRED", 401)), true);
  assert.equal(isUnauthorized(new ApiError("HTTP_ERROR", 401)), true);
});

test("a step-up refusal keeps the frozen request and repeats it exactly after re-verification", async () => {
  const runtime = connected();
  const { calls, frozen } = deleteSite(runtime, (call) => (call === 1 ? stepUp() : reply()));

  const first = await runFrozenWrite(runtime.store, runtime.pending, frozen.id);
  assert.equal(first.kind, "step_up");
  const kept = runtime.pending.get(frozen.id);
  assert.equal(kept?.phase, "step_up");
  assert.equal(kept?.attempts, 1);
  assert.equal(kept?.lastError?.code, "CONTROL_SITE_DELETE_STEP_UP_REQUIRED");
  assert.equal(runtime.pending.getSnapshot().length, 1, "it is still listed");
  assert.equal(runtime.pending.unresolvedCount, 0, "but nothing is in an unknown state");
  assert.equal(runtime.store.getState().status, "connected", "the session is untouched");

  const second = await runFrozenWrite(runtime.store, runtime.pending, frozen.id);
  assert.equal(second.kind, "confirmed");
  assert.equal(runtime.pending.getSnapshot().length, 0);
  assert.deepEqual(calls, [{ key: KEY }, { key: KEY }], "same key, same request");
  assert.equal(frozen.method, "DELETE");
  assert.equal(frozen.path, "/control/v1/sites/site_a");
  assert.equal(frozen.body, null);
});

test("after a step-up refusal a later refusal resolves it and a lost connection leaves it unknown", async () => {
  const refused = connected();
  const a = deleteSite(refused, (call) =>
    call === 1 ? stepUp() : new ApiError("CONTROL_SITE_DELETE_EDGE_NOT_CONFIRMED", 409),
  );
  assert.equal((await runFrozenWrite(refused.store, refused.pending, a.frozen.id)).kind, "step_up");
  // Step-up never reached the idempotency store, so this is still a first attempt.
  assert.equal(
    (await runFrozenWrite(refused.store, refused.pending, a.frozen.id)).kind,
    "rejected",
  );
  assert.equal(refused.pending.getSnapshot().length, 0);

  const lost = connected();
  const b = deleteSite(lost, (call) =>
    call === 1 ? stepUp() : new ApiError("NETWORK_UNAVAILABLE", 0),
  );
  await runFrozenWrite(lost.store, lost.pending, b.frozen.id);
  assert.equal((await runFrozenWrite(lost.store, lost.pending, b.frozen.id)).kind, "unknown");
  assert.equal(lost.pending.get(b.frozen.id)?.phase, "unknown");
  assert.equal(lost.pending.unresolvedCount, 1);
});

test("a step-up entry does not arm the page-leave warning, because re-verifying leaves the page", async () => {
  const runtime = connected();
  const target = new EventTarget();
  const warns = () => {
    const probe = new Event("beforeunload", { cancelable: true });
    target.dispatchEvent(probe);
    return probe.defaultPrevented;
  };
  const dispose = installBeforeUnloadGuard(
    runtime.pending,
    target as unknown as Parameters<typeof installBeforeUnloadGuard>[1],
  );
  const { frozen } = deleteSite(runtime, () => stepUp());
  assert.equal(warns(), true, "a registered write that may be running blocks leaving");
  await runFrozenWrite(runtime.store, runtime.pending, frozen.id);
  assert.equal(runtime.pending.get(frozen.id)?.phase, "step_up");
  assert.equal(warns(), false, "it did not run, so there is nothing to lose by leaving");
  dispose();
});

test("an approval refused for a missing step-up keeps the session; a dead session still ends it", async () => {
  const runtime = connected();
  const approve = runtime.pending.freeze({
    label: "批准并应用 · site_a",
    method: "POST",
    path: "/control/v1/sites/site_a/approve",
    idempotencyKey: KEY,
    expectedSiteId: "site_a",
    execute: async () => {
      throw new ApiError("CONTROL_STEP_UP_REQUIRED", 401);
    },
  });
  const result = await runFrozenWrite(runtime.store, runtime.pending, approve.id);
  assert.equal(result.kind, "step_up");
  assert.equal(runtime.store.getState().status, "connected");
  assert.equal(runtime.store.getState().notice, null);

  const dead = runtime.pending.freeze({
    label: "批准并应用 · site_a",
    method: "POST",
    path: "/control/v1/sites/site_a/approve",
    idempotencyKey: KEY,
    expectedSiteId: "site_a",
    execute: async () => {
      throw new ApiError("CONTROL_AUTH_REQUIRED", 401);
    },
  });
  assert.deepEqual(await runFrozenWrite(runtime.store, runtime.pending, dead.id), {
    kind: "stale",
  });
  assert.equal(runtime.store.getState().status, "disconnected");
  assert.equal(runtime.store.getState().notice, unauthorizedNotice);
  assert.equal(runtime.pending.getSnapshot().length, 0, "the session end clears everything");
});

test("abandoning an unknown write drops its frozen request for good", async () => {
  const runtime = connected();
  const { calls, frozen } = deleteSite(runtime, () => new ApiError("NETWORK_UNAVAILABLE", 0));
  assert.equal((await runFrozenWrite(runtime.store, runtime.pending, frozen.id)).kind, "unknown");
  assert.equal(runtime.pending.abandon(frozen.id), true);
  assert.equal(runtime.pending.abandon(frozen.id), false);
  assert.equal(runtime.pending.getSnapshot().length, 0);
  assert.equal(runtime.pending.unresolvedCount, 0);
  assert.throws(() => runtime.pending.start(frozen.id), /unknown pending operation/);
  assert.equal(calls.length, 1);
});
