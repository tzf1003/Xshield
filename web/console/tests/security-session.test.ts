import assert from "node:assert/strict";
import { afterEach, test } from "node:test";
import { CancelledError } from "@tanstack/react-query";
import { type BrowserSession, ControlClient } from "../src/api.ts";
import { ApiError } from "../src/api-contract.ts";
import { isStaleSessionError, StaleSessionError } from "../src/security/errors.ts";
import { runGuardedRead } from "../src/security/guarded.ts";
import { guardedQuery, guardedQueryKey } from "../src/security/guarded-query.ts";
import { createQueryClient, MANUAL_REFRESH } from "../src/security/query-client.ts";
import {
  createSessionRuntime as createRuntime,
  type RuntimeOptions,
} from "../src/security/runtime.ts";
import { checkScope } from "../src/security/scope.ts";
import {
  IDLE_MS,
  idleNotice,
  scopeNotice,
  SessionStore,
  type Timers,
  unauthorizedNotice,
} from "../src/security/session-store.ts";

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

const scope = { tenant_id: "tenant_a", site_id: "site_a" };
const csrf = "0".repeat(64);

function browserSession(overrides: Partial<BrowserSession> = {}): BrowserSession {
  return {
    subject: "operator",
    ...scope,
    csrf_token: csrf,
    roles: ["observer"],
    session_expires_at: "2027-01-01T08:00:00.000Z",
    idle_expires_at: "2027-01-01T00:15:00.000Z",
    last_reauthenticated_at: null,
    step_up_valid: false,
    ...overrides,
  };
}

function connect(store: SessionStore, overrides: { scope?: typeof scope | null } = {}) {
  return store.connect({
    client: new ControlClient(undefined, csrf),
    scope: overrides.scope === undefined ? scope : overrides.scope,
    roles: ["observer"],
    session: browserSession(),
  });
}

function manualTimers() {
  let nextId = 1;
  const pending = new Map<number, { callback: () => void; ms: number }>();
  const timers: Timers = {
    setTimeout(callback, ms) {
      const id = nextId++;
      pending.set(id, { callback, ms });
      return id;
    },
    clearTimeout(handle) {
      pending.delete(handle as number);
    },
  };
  return {
    timers,
    pending,
    fire() {
      const [first] = [...pending.entries()];
      if (!first) throw new Error("no timer armed");
      pending.delete(first[0]);
      first[1].callback();
    },
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((ok, fail) => {
    resolve = ok;
    reject = fail;
  });
  return { promise, resolve, reject };
}

/** TanStack cancels a query destroyed by `clear()`, which is how a session end surfaces. */
const isDropped = (error: unknown) => isStaleSessionError(error) || error instanceof CancelledError;

const reply = (overrides: Partial<{ tenant_id: string; site_id: string }> = {}) => ({
  request_id: "req_018f2a3b-4c5d-7000-8000-000000000001",
  ...scope,
  ...overrides,
  payload: "rows",
});

test("scope check: matching, cross-tenant, cross-site and site-specific replies", () => {
  assert.deepEqual(checkScope(scope, scope), { kind: "ok", confirm: null });
  assert.deepEqual(checkScope(scope, { ...scope, tenant_id: "tenant_b" }), { kind: "mismatch" });
  assert.deepEqual(checkScope(scope, { ...scope, site_id: "site_b" }), { kind: "mismatch" });
  // Multi-site reads answer for the expected site; the tenant must still match.
  assert.deepEqual(checkScope(scope, { ...scope, site_id: "site_b" }, "site_b"), {
    kind: "ok",
    confirm: null,
  });
  assert.deepEqual(checkScope(scope, { ...scope, site_id: "site_c" }, "site_b"), {
    kind: "wrong_site",
  });
  assert.deepEqual(checkScope(scope, { tenant_id: "tenant_b", site_id: "site_b" }, "site_b"), {
    kind: "mismatch",
  });
  // Machine login: the first unscoped reply establishes the scope, a site-specific one does not.
  assert.deepEqual(checkScope(null, scope), { kind: "ok", confirm: scope });
  assert.deepEqual(checkScope(null, scope, "site_a"), { kind: "ok", confirm: null });
});

test("epoch increments on every connect and disconnect and the signal follows the lifetime", () => {
  const store = new SessionStore();
  assert.equal(store.getState().epoch, 0);
  assert.equal(store.signal.aborted, true);
  const first = connect(store);
  assert.equal(first, 1);
  assert.equal(store.getState().status, "connected");
  assert.equal(store.signal.aborted, false);
  const liveSignal = store.signal;
  store.disconnect("bye");
  assert.equal(liveSignal.aborted, true);
  assert.equal(store.getState().epoch, 2);
  assert.equal(store.getState().notice, "bye");
  assert.equal(store.getState().client, null);
  assert.equal(store.getState().scope, null);
  assert.equal(connect(store), 3);
  assert.equal(store.getState().notice, null);
  // Connecting over a live session first ends it, so nothing carries over.
  const before = store.signal;
  assert.equal(connect(store), 5);
  assert.equal(before.aborted, true);
  assert.equal(store.signal.aborted, false);
});

test("disconnect aborts requests before hooks run and survives a failing hook", () => {
  const store = new SessionStore();
  connect(store);
  const order: string[] = [];
  const signal = store.signal;
  store.onDisconnect(() => {
    order.push(`hook-1 aborted=${signal.aborted}`);
    throw new Error("cache failure");
  });
  store.onDisconnect(() => order.push("hook-2"));
  let notified = 0;
  store.subscribe(() => notified++);
  store.disconnect(null);
  assert.deepEqual(order, ["hook-1 aborted=true", "hook-2"]);
  assert.equal(notified, 1);
  // Disconnecting again changes nothing (no extra epoch, no hook run), but may add a reason.
  store.disconnect(null);
  assert.equal(store.getState().epoch, 2);
  assert.equal(order.length, 2);
});

test("idle expiry disconnects after 15 minutes and activity restarts the countdown", () => {
  const clock = manualTimers();
  const store = new SessionStore({ timers: clock.timers });
  connect(store);
  assert.equal([...clock.pending.values()][0]?.ms, IDLE_MS);
  assert.equal(IDLE_MS, 15 * 60 * 1000);
  store.touch();
  assert.equal(clock.pending.size, 1, "touch replaces the timer instead of stacking them");
  clock.fire();
  assert.equal(store.getState().status, "disconnected");
  assert.equal(store.getState().notice, idleNotice);
  store.touch();
  assert.equal(clock.pending.size, 0, "a disconnected store arms nothing");
});

test("logout, idle, pagehide and 401 all clear the query cache and the pending registry together", () => {
  const runtime = createSessionRuntime();
  connect(runtime.store);
  runtime.queryClient.setQueryData(["xs", 1, "x"], { secret: "rows" });
  runtime.pending.freeze({
    label: "创建案件",
    method: "POST",
    path: "/control/v1/cases",
    body: { purpose: "p" },
    execute: async () => reply(),
  });
  assert.equal(runtime.pending.unresolvedCount, 1);
  runtime.store.disconnect(null);
  assert.equal(runtime.queryClient.getQueryCache().getAll().length, 0);
  assert.equal(runtime.pending.unresolvedCount, 0);
});

test("a late response from an older epoch is dropped and never repopulates the cache", async () => {
  const runtime = createSessionRuntime();
  connect(runtime.store);
  const slow = deferred<ReturnType<typeof reply>>();
  const oldOptions = guardedQuery(runtime, {
    key: ["workbench", "overview"],
    staleTime: MANUAL_REFRESH,
    fetch: () => slow.promise,
  });
  const oldKey = oldOptions.queryKey;
  const outcome = runtime.queryClient.fetchQuery(oldOptions).then(
    () => "resolved",
    (error: unknown) => error,
  );
  // The operator is disconnected and a (possibly different) operator connects again.
  runtime.store.disconnect(null);
  connect(runtime.store);
  slow.resolve(reply());
  const error = await outcome;
  assert.ok(isDropped(error), `expected the reply to be dropped, got ${String(error)}`);
  assert.equal(runtime.queryClient.getQueryData(oldKey), undefined);
  assert.equal(runtime.queryClient.getQueryCache().getAll().length, 0);
  assert.equal(runtime.store.getState().status, "connected", "the new session is untouched");
});

test("the read guard itself drops a reply that outlives its epoch, without any query client", async () => {
  const store = new SessionStore();
  connect(store);
  const slow = deferred<ReturnType<typeof reply>>();
  const call = runGuardedRead(store, { fetch: () => slow.promise }).then(
    () => "resolved",
    (error: unknown) => error,
  );
  store.disconnect(null);
  connect(store);
  slow.resolve(reply());
  const error = await call;
  assert.ok(error instanceof StaleSessionError, String(error));
  assert.equal(error.reason, "epoch");

  // A reply built for epoch N must not even start once the epoch is N+1.
  const stale = store.getState().epoch - 2;
  let started = false;
  await assert.rejects(
    runGuardedRead(store, {
      epoch: stale,
      fetch: async () => {
        started = true;
        return reply();
      },
    }),
    StaleSessionError,
  );
  assert.equal(started, false);
});

test("a query built for an earlier epoch never starts its request", async () => {
  const runtime = createSessionRuntime();
  connect(runtime.store);
  let calls = 0;
  const options = guardedQuery(runtime, {
    key: ["audit", "health"],
    staleTime: MANUAL_REFRESH,
    fetch: async () => {
      calls++;
      return reply();
    },
  });
  runtime.store.disconnect(null);
  connect(runtime.store);
  await assert.rejects(runtime.queryClient.fetchQuery(options), StaleSessionError);
  assert.equal(calls, 0);
  assert.deepEqual(guardedQueryKey(7, ["a", "b"]), ["xs", 7, "a", "b"]);
  assert.notDeepEqual(
    options.queryKey,
    guardedQuery(runtime, { ...specOf(), key: ["audit", "health"] }).queryKey,
  );
});

function specOf() {
  return { staleTime: MANUAL_REFRESH, fetch: async () => reply() };
}

test("a reply for another tenant or site ends the session and clears everything", async () => {
  for (const foreign of [{ tenant_id: "tenant_b" }, { site_id: "site_b" }]) {
    const runtime = createSessionRuntime();
    connect(runtime.store);
    runtime.queryClient.setQueryData(["xs", 1, "other"], { rows: 1 });
    const options = guardedQuery(runtime, {
      key: ["sites"],
      staleTime: MANUAL_REFRESH,
      fetch: async () => reply(foreign),
    });
    await assert.rejects(runtime.queryClient.fetchQuery(options), isDropped);
    assert.equal(runtime.store.getState().status, "disconnected");
    assert.equal(runtime.store.getState().notice, scopeNotice);
    assert.equal(runtime.queryClient.getQueryCache().getAll().length, 0);
  }
});

test("a site-specific read for another site is an invalid response, not a disconnect", async () => {
  const runtime = createSessionRuntime();
  connect(runtime.store);
  const options = guardedQuery(runtime, {
    key: ["site", "site_b"],
    staleTime: MANUAL_REFRESH,
    expectedSiteId: "site_b",
    fetch: async () => reply({ site_id: "site_c" }),
  });
  await assert.rejects(
    runtime.queryClient.fetchQuery(options),
    (error: unknown) => error instanceof ApiError && error.code === "INVALID_RESPONSE",
  );
  assert.equal(runtime.store.getState().status, "connected");
  const ok = await runtime.queryClient.fetchQuery(
    guardedQuery(runtime, {
      key: ["site", "site_b", "ok"],
      staleTime: MANUAL_REFRESH,
      expectedSiteId: "site_b",
      fetch: async () => reply({ site_id: "site_b" }),
    }),
  );
  assert.equal(ok.site_id, "site_b");
});

test("401 ends the session, clears the query cache and ignores 401s from older epochs", async () => {
  const runtime = createSessionRuntime();
  connect(runtime.store);
  runtime.queryClient.setQueryData(["xs", 1, "cached"], { rows: 1 });
  const unauthorized = new ApiError("CONTROL_AUTH_REQUIRED", 401);
  await assert.rejects(
    runtime.queryClient.fetchQuery(
      guardedQuery(runtime, {
        key: ["overview"],
        staleTime: MANUAL_REFRESH,
        fetch: async () => {
          throw unauthorized;
        },
      }),
    ),
    isDropped,
  );
  assert.equal(runtime.store.getState().status, "disconnected");
  assert.equal(runtime.store.getState().notice, unauthorizedNotice);
  assert.equal(runtime.queryClient.getQueryCache().getAll().length, 0);

  // A request of the previous session fails with 401 only after a new session started.
  connect(runtime.store);
  const lateFailure = deferred<ReturnType<typeof reply>>();
  const call = runGuardedRead(runtime.store, {
    fetch: () => lateFailure.promise,
  });
  const settled = call.then(
    () => null,
    (error: unknown) => error,
  );
  runtime.store.disconnect(null);
  connect(runtime.store);
  lateFailure.reject(unauthorized);
  assert.ok(isStaleSessionError(await settled));
  assert.equal(
    runtime.store.getState().status,
    "connected",
    "a stale 401 must not end the new session",
  );
});

test("ordinary failures surface to the caller without ending the session", async () => {
  const runtime = createSessionRuntime();
  connect(runtime.store);
  const denied = new ApiError("CONTROL_SCOPE_DENIED", 403);
  await assert.rejects(
    runtime.queryClient.fetchQuery(
      guardedQuery(runtime, {
        key: ["denied"],
        staleTime: MANUAL_REFRESH,
        fetch: async () => {
          throw denied;
        },
      }),
    ),
    (error: unknown) => error === denied,
  );
  assert.equal(runtime.store.getState().status, "connected");
});

test("the abort signal is passed through and a session end aborts the request", async () => {
  const runtime = createSessionRuntime();
  connect(runtime.store);
  let seen: AbortSignal | undefined;
  const pendingFetch = deferred<ReturnType<typeof reply>>();
  const options = guardedQuery(runtime, {
    key: ["signal"],
    staleTime: MANUAL_REFRESH,
    fetch: (_client, signal) => {
      seen = signal;
      return pendingFetch.promise;
    },
  });
  const outcome = runtime.queryClient.fetchQuery(options).catch((error: unknown) => error);
  await Promise.resolve();
  assert.ok(seen, "fetch received a signal");
  assert.equal(seen.aborted, false);
  runtime.store.disconnect(null);
  assert.equal(seen.aborted, true);
  pendingFetch.reject(new ApiError("REQUEST_ABORTED", 0));
  assert.ok(isDropped(await outcome));
});

test("machine login: the first reply establishes the scope and later strangers disconnect", async () => {
  const runtime = createSessionRuntime();
  connect(runtime.store, { scope: null });
  await runGuardedRead(runtime.store, { fetch: async () => reply() });
  assert.deepEqual(runtime.store.getState().scope, scope);
  await assert.rejects(
    runGuardedRead(runtime.store, { fetch: async () => reply({ tenant_id: "tenant_b" }) }),
    StaleSessionError,
  );
  assert.equal(runtime.store.getState().status, "disconnected");
});

test("query defaults never poll, retry or refetch on focus or reconnect", () => {
  const defaults = createQueryClient().getDefaultOptions();
  assert.equal(defaults.queries?.retry, 0);
  assert.equal(defaults.queries?.refetchOnWindowFocus, false);
  assert.equal(defaults.queries?.refetchOnReconnect, false);
  assert.equal(defaults.queries?.refetchInterval, false);
  assert.equal(defaults.queries?.retryOnMount, false);
  assert.equal(defaults.queries?.staleTime, Number.POSITIVE_INFINITY);
  assert.equal(defaults.queries?.networkMode, "always");
  assert.equal(defaults.mutations?.retry, 0);
  assert.equal(defaults.mutations?.networkMode, "always");

  const runtime = createSessionRuntime();
  const disconnected = guardedQuery(runtime, specOfKey("a"));
  assert.equal(disconnected.enabled, false, "nothing is requested without a session");
  connect(runtime.store);
  const options = guardedQuery(runtime, { ...specOfKey("a"), staleTime: 5_000 });
  assert.equal(options.enabled, true);
  assert.equal(options.staleTime, 5_000);
  assert.equal(options.retry, 0);
  assert.equal(options.refetchOnWindowFocus, false);
  assert.equal(options.refetchOnReconnect, false);
  assert.equal(options.refetchInterval, false);
  assert.equal(options.retryOnMount, false);
  assert.equal(options.networkMode, "always");
  assert.equal(guardedQuery(runtime, { ...specOfKey("a"), enabled: false }).enabled, false);
});

function specOfKey(name: string) {
  return { key: [name], staleTime: MANUAL_REFRESH, fetch: async () => reply() };
}

test("updateSession refreshes roles without ending the session", () => {
  const store = new SessionStore();
  const epoch = connect(store);
  store.updateSession(browserSession({ roles: ["observer", "investigator"] }));
  assert.deepEqual(store.getState().roles, ["observer", "investigator"]);
  assert.equal(store.getState().epoch, epoch);
  store.disconnect(null);
  store.updateSession(browserSession());
  assert.equal(store.getState().roles, null, "a disconnected store ignores session facts");
});
