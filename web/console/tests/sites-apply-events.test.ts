import assert from "node:assert/strict";
import { afterEach, test } from "node:test";
import { guardedQueryKey } from "../src/security/guarded-query.ts";
import {
  createSessionRuntime as createRuntime,
  type RuntimeOptions,
} from "../src/security/runtime.ts";
import { invalidateApplyEvent } from "../src/sites/state/apply-events.ts";
import { siteKeys } from "../src/sites/state/site-keys.ts";

// GC timers of an unobserved query keep the process alive for a minute; clear every runtime.
const created: ReturnType<typeof createRuntime>[] = [];
function createSessionRuntime(options?: RuntimeOptions) {
  const runtime = createRuntime({ queryGcMs: 0, ...options });
  created.push(runtime);
  return runtime;
}
afterEach(() => {
  for (const runtime of created.splice(0)) {
    runtime.store.disconnect(null);
    runtime.queryClient.clear();
  }
});

const epoch = 3;
const siteId = "site_a";

function seeded(runtime: ReturnType<typeof createRuntime>) {
  const keys = {
    config: guardedQueryKey(epoch, siteKeys.config(siteId)),
    status: guardedQueryKey(epoch, siteKeys.status(siteId)),
    revisions: guardedQueryKey(epoch, siteKeys.revisions(siteId)),
    list: guardedQueryKey(epoch, siteKeys.list),
  };
  for (const key of Object.values(keys)) {
    runtime.queryClient.setQueryData(key, { seeded: true });
  }
  return keys;
}

function isInvalidated(runtime: ReturnType<typeof createRuntime>, key: readonly unknown[]) {
  return runtime.queryClient.getQueryState(key)?.isInvalidated === true;
}

test("a site_apply_changed frame invalidates that site's config, status and revisions", () => {
  const runtime = createSessionRuntime();
  const keys = seeded(runtime);
  invalidateApplyEvent(runtime, epoch, JSON.stringify({ site_id: siteId }));
  assert.ok(isInvalidated(runtime, keys.config));
  assert.ok(isInvalidated(runtime, keys.status));
  assert.ok(isInvalidated(runtime, keys.revisions));
  assert.ok(
    isInvalidated(runtime, keys.list),
    "the list is invalidated too, so it re-reads next open",
  );
});

test("the invalidation never writes state itself: the cached rows are untouched", () => {
  const runtime = createSessionRuntime();
  const keys = seeded(runtime);
  invalidateApplyEvent(runtime, epoch, JSON.stringify({ site_id: siteId }));
  assert.deepEqual(runtime.queryClient.getQueryData(keys.config), { seeded: true });
});

test("a frame for a different site never invalidates this one's queries", () => {
  const runtime = createSessionRuntime();
  const keys = seeded(runtime);
  invalidateApplyEvent(runtime, epoch, JSON.stringify({ site_id: "site_b" }));
  assert.equal(isInvalidated(runtime, keys.config), false);
  assert.equal(isInvalidated(runtime, keys.status), false);
  assert.equal(isInvalidated(runtime, keys.revisions), false);
  // The list has no single site scope, so any change still marks it for a next open.
  assert.ok(isInvalidated(runtime, keys.list));
});

test("a frame missing or mistyping site_id is dropped without touching any query", () => {
  const runtime = createSessionRuntime();
  const keys = seeded(runtime);
  for (const raw of [
    "not json",
    "{}",
    JSON.stringify({ site_id: 1 }),
    JSON.stringify({ site_id: "" }),
  ]) {
    invalidateApplyEvent(runtime, epoch, raw);
  }
  for (const key of Object.values(keys)) {
    assert.equal(isInvalidated(runtime, key), false, `key ${JSON.stringify(key)} was invalidated`);
  }
});
