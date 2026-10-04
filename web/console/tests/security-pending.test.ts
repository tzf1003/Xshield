import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { afterEach, test } from "node:test";
import { type BrowserSession, ControlClient } from "../src/api.ts";
import { ApiError } from "../src/api-contract.ts";
import { runFrozenWrite } from "../src/security/guarded.ts";
import {
  installBeforeUnloadGuard,
  PendingOperationStore,
} from "../src/security/pending-operations.ts";
import {
  createSessionRuntime as createRuntime,
  type RuntimeOptions,
} from "../src/security/runtime.ts";
import { scopeNotice, unauthorizedNotice } from "../src/security/session-store.ts";

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
const KEY = "synthetic-operation-key-0001";

function session(): BrowserSession {
  return {
    subject: "operator",
    ...scope,
    csrf_token: csrf,
    roles: ["investigator"],
    session_expires_at: "2027-01-01T08:00:00.000Z",
    idle_expires_at: "2027-01-01T00:15:00.000Z",
    last_reauthenticated_at: null,
    step_up_valid: false,
  };
}

function connected() {
  const runtime = createSessionRuntime();
  runtime.store.connect({
    client: new ControlClient(undefined, csrf),
    scope,
    roles: ["investigator"],
    session: session(),
  });
  return runtime;
}

const ack = (overrides: Partial<{ tenant_id: string; site_id: string }> = {}) => ({
  request_id: "req_018f2a3b-4c5d-7000-8000-000000000001",
  ...scope,
  ...overrides,
});

type Call = { key: string; signalAborted: boolean };
function recorder(
  outcomes: (call: number) => Promise<ReturnType<typeof ack>> | ReturnType<typeof ack>,
) {
  const calls: Call[] = [];
  const execute = async (_client: ControlClient, signal: AbortSignal, key: string) => {
    calls.push({ key, signalAborted: signal.aborted });
    return outcomes(calls.length);
  };
  return { calls, execute };
}

const networkLoss = () => new ApiError("NETWORK_UNAVAILABLE", 0);
const refusal = () => new ApiError("CONTROL_CASE_REQUEST_INVALID", 400);

test("freezing keeps method, path, key, body, label and creation time immutable", () => {
  const store = new PendingOperationStore({ now: () => 1_700_000_000_000 });
  const body = { purpose: "核对合成请求" };
  const snapshot = store.freeze({
    label: "创建案件",
    method: "POST",
    path: "/control/v1/cases",
    body,
    idempotencyKey: KEY,
    execute: async () => ack(),
  });
  body.purpose = "changed after submit";
  assert.equal(snapshot.body, '{"purpose":"核对合成请求"}');
  assert.equal(snapshot.idempotencyKey, KEY);
  assert.equal(snapshot.method, "POST");
  assert.equal(snapshot.path, "/control/v1/cases");
  assert.equal(snapshot.label, "创建案件");
  assert.equal(snapshot.createdAt, 1_700_000_000_000);
  assert.equal(snapshot.phase, "inflight");
  assert.throws(() => {
    (snapshot as { body: string | null }).body = "tampered";
  }, TypeError);
  assert.throws(() => {
    (snapshot as { idempotencyKey: string }).idempotencyKey = "other-operation-key-9999";
  }, TypeError);
  assert.equal(store.get(snapshot.id)?.body, '{"purpose":"核对合成请求"}');
});

test("only fixed control paths, short labels and valid idempotency keys are accepted", () => {
  const store = new PendingOperationStore();
  const base = { label: "x", method: "POST" as const, execute: async () => ack() };
  for (const path of [
    "https://evil.example/control/v1/cases",
    "//evil.example/control/v1/cases",
    "/other/v1/cases",
    "/control/v1/../admin",
    "/control/v1//cases",
    "/control/v1/",
    "control/v1/cases",
    "/control/v1/cases?token=secret",
  ]) {
    assert.throws(() => store.freeze({ ...base, path }), TypeError, path);
  }
  assert.throws(() => store.freeze({ ...base, label: "", path: "/control/v1/cases" }), TypeError);
  assert.throws(
    () => store.freeze({ ...base, path: "/control/v1/cases", idempotencyKey: "short" }),
    TypeError,
  );
  assert.equal(store.unresolvedCount, 0);
});

test("an unknown outcome is retried with the original key and body, and success resolves it", async () => {
  const runtime = connected();
  const { calls, execute } = recorder((call) => {
    if (call === 1) throw networkLoss();
    return ack();
  });
  const frozen = runtime.pending.freeze({
    label: "创建案件",
    method: "POST",
    path: "/control/v1/cases",
    body: { purpose: "核对合成请求" },
    idempotencyKey: KEY,
    execute,
  });
  const first = await runFrozenWrite(runtime.store, runtime.pending, frozen.id);
  assert.equal(first.kind, "unknown");
  const unknown = runtime.pending.get(frozen.id);
  assert.equal(unknown?.phase, "unknown");
  assert.equal(unknown?.attempts, 1);
  assert.equal(unknown?.lastError?.code, "NETWORK_UNAVAILABLE");
  assert.equal(runtime.pending.unresolvedCount, 1);

  const second = await runFrozenWrite(runtime.store, runtime.pending, frozen.id);
  assert.equal(second.kind, "confirmed");
  assert.deepEqual(
    calls.map((call) => call.key),
    [KEY, KEY],
    "the retry reuses the original idempotency key",
  );
  assert.equal(runtime.pending.unresolvedCount, 0);
  assert.equal(runtime.pending.get(frozen.id), null);
});

test("a refusal of the first attempt resolves; a refusal after an unknown attempt stays unknown", async () => {
  const runtime = connected();
  const refused = runtime.pending.freeze({
    label: "关闭案件",
    method: "POST",
    path: "/control/v1/cases/case_x/close",
    idempotencyKey: KEY,
    execute: async () => {
      throw refusal();
    },
  });
  const verdict = await runFrozenWrite(runtime.store, runtime.pending, refused.id);
  assert.equal(verdict.kind, "rejected");
  assert.equal(
    runtime.pending.unresolvedCount,
    0,
    "a deterministic refusal leaves nothing pending",
  );

  const calls: number[] = [];
  const ambiguous = runtime.pending.freeze({
    label: "创建保留锁",
    method: "POST",
    path: "/control/v1/evidence-holds",
    idempotencyKey: KEY,
    execute: async () => {
      calls.push(calls.length + 1);
      throw calls.length === 1 ? networkLoss() : refusal();
    },
  });
  assert.equal(
    (await runFrozenWrite(runtime.store, runtime.pending, ambiguous.id)).kind,
    "unknown",
  );
  // The server now refuses the retry, which still cannot prove the first attempt did not commit.
  assert.equal(
    (await runFrozenWrite(runtime.store, runtime.pending, ambiguous.id)).kind,
    "unknown",
  );
  assert.equal(runtime.pending.get(ambiguous.id)?.phase, "unknown");
  assert.equal(runtime.pending.get(ambiguous.id)?.attempts, 2);
});

test("an operation cannot be started twice at once, nor restarted after it resolved", async () => {
  const runtime = connected();
  let release!: () => void;
  const gate = new Promise<void>((open) => {
    release = open;
  });
  const slow = runtime.pending.freeze({
    label: "导出",
    method: "POST",
    path: "/control/v1/exports",
    idempotencyKey: KEY,
    execute: async () => {
      await gate;
      return ack();
    },
  });
  const running = runFrozenWrite(runtime.store, runtime.pending, slow.id);
  assert.throws(() => runtime.pending.start(slow.id), /already in flight/);
  release();
  assert.equal((await running).kind, "confirmed");
  assert.throws(() => runtime.pending.start(slow.id), /unknown pending operation/);
});

test("only unresolved operations are listed, ordered by creation time", () => {
  let clock = 100;
  const store = new PendingOperationStore({ now: () => clock });
  const seen: number[] = [];
  store.subscribe(() => seen.push(store.getSnapshot().length));
  const a = store.freeze({
    label: "a",
    method: "POST",
    path: "/control/v1/a",
    execute: async () => ack(),
  });
  clock = 50;
  const b = store.freeze({
    label: "b",
    method: "PUT",
    path: "/control/v1/b",
    execute: async () => ack(),
  });
  assert.deepEqual(
    store.getSnapshot().map((entry) => entry.label),
    ["b", "a"],
  );
  assert.equal(store.getSnapshot(), store.getSnapshot(), "snapshots are referentially stable");
  store.resolve(a.id);
  assert.deepEqual(
    store.getSnapshot().map((entry) => entry.id),
    [b.id],
  );
  assert.deepEqual(seen, [1, 2, 1]);
  assert.equal(store.clear(), 1);
  assert.equal(store.clear(), 0);
});

test("the beforeunload warning exists exactly while an operation is unresolved", async () => {
  const runtime = connected();
  const target = new EventTarget();
  const listeners = () => {
    const probe = new Event("beforeunload", { cancelable: true });
    target.dispatchEvent(probe);
    return probe.defaultPrevented;
  };
  const dispose = installBeforeUnloadGuard(
    runtime.pending,
    target as unknown as Parameters<typeof installBeforeUnloadGuard>[1],
  );
  assert.equal(listeners(), false, "nothing pending, nothing to warn about");
  const op = runtime.pending.freeze({
    label: "创建案件",
    method: "POST",
    path: "/control/v1/cases",
    idempotencyKey: KEY,
    execute: async () => {
      throw networkLoss();
    },
  });
  assert.equal(listeners(), true, "a registered write blocks leaving the page");
  await runFrozenWrite(runtime.store, runtime.pending, op.id);
  assert.equal(listeners(), true, "an unknown outcome keeps the warning");
  runtime.pending.clear();
  assert.equal(listeners(), false);
  runtime.pending.freeze({
    label: "再次",
    method: "POST",
    path: "/control/v1/cases",
    execute: async () => ack(),
  });
  assert.equal(listeners(), true);
  dispose();
  assert.equal(listeners(), false, "disposing removes the listener");
});

test("a write answered after the session ended is dropped and cannot leave an entry behind", async () => {
  const runtime = connected();
  let release!: () => void;
  const gate = new Promise<void>((open) => {
    release = open;
  });
  const op = runtime.pending.freeze({
    label: "创建案件",
    method: "POST",
    path: "/control/v1/cases",
    idempotencyKey: KEY,
    execute: async () => {
      await gate;
      return ack();
    },
  });
  const running = runFrozenWrite(runtime.store, runtime.pending, op.id);
  runtime.store.disconnect(null);
  assert.equal(runtime.pending.unresolvedCount, 0, "ending the session clears the registry");
  release();
  assert.deepEqual(await running, { kind: "stale" });
});

test("401 on a write ends the session; a foreign-scope write reply ends it too", async () => {
  const unauthorized = connected();
  const op = unauthorized.pending.freeze({
    label: "创建案件",
    method: "POST",
    path: "/control/v1/cases",
    idempotencyKey: KEY,
    execute: async () => {
      throw new ApiError("CONTROL_AUTH_REQUIRED", 401);
    },
  });
  assert.deepEqual(await runFrozenWrite(unauthorized.store, unauthorized.pending, op.id), {
    kind: "stale",
  });
  assert.equal(unauthorized.store.getState().notice, unauthorizedNotice);
  assert.equal(unauthorized.pending.unresolvedCount, 0);

  const foreign = connected();
  const crossTenant = foreign.pending.freeze({
    label: "创建案件",
    method: "POST",
    path: "/control/v1/cases",
    idempotencyKey: KEY,
    execute: async () => ack({ tenant_id: "tenant_b" }),
  });
  assert.deepEqual(await runFrozenWrite(foreign.store, foreign.pending, crossTenant.id), {
    kind: "stale",
  });
  assert.equal(foreign.store.getState().notice, scopeNotice);
  assert.equal(foreign.pending.unresolvedCount, 0);
});

test("a reply for the wrong site leaves the write unknown instead of disconnecting", async () => {
  const runtime = connected();
  const op = runtime.pending.freeze({
    label: "应用站点配置",
    method: "POST",
    path: "/control/v1/sites/site_b/apply",
    idempotencyKey: KEY,
    expectedSiteId: "site_b",
    execute: async () => ack({ site_id: "site_other" }),
  });
  const result = await runFrozenWrite(runtime.store, runtime.pending, op.id);
  assert.equal(result.kind, "unknown");
  assert.equal(runtime.pending.get(op.id)?.lastError?.code, "INVALID_RESPONSE");
  assert.equal(runtime.store.getState().status, "connected");
  const retry = runtime.pending.get(op.id);
  assert.equal(retry?.idempotencyKey, KEY);
});

test("a write reply for a multi-site target is checked against that site", async () => {
  const runtime = connected();
  const op = runtime.pending.freeze({
    label: "应用站点配置",
    method: "POST",
    path: "/control/v1/sites/site_b/apply",
    idempotencyKey: KEY,
    expectedSiteId: "site_b",
    execute: async () => ack({ site_id: "site_b" }),
  });
  assert.equal((await runFrozenWrite(runtime.store, runtime.pending, op.id)).kind, "confirmed");
});

test("neither the stores nor the session layer ever touch web storage or cookies", async () => {
  const touched: string[] = [];
  const trap = (name: string) =>
    new Proxy(
      {},
      {
        get(_target, property) {
          touched.push(`${name}.${String(property)}`);
          return () => {
            throw new Error(`${name} must not be used`);
          };
        },
      },
    );
  const originals = new Map<string, PropertyDescriptor | undefined>();
  for (const name of ["localStorage", "sessionStorage", "indexedDB"]) {
    originals.set(name, Object.getOwnPropertyDescriptor(globalThis, name));
    Object.defineProperty(globalThis, name, { configurable: true, value: trap(name) });
  }
  try {
    const runtime = connected();
    const op = runtime.pending.freeze({
      label: "创建案件",
      method: "POST",
      path: "/control/v1/cases",
      body: { purpose: "p" },
      idempotencyKey: KEY,
      execute: async () => {
        throw networkLoss();
      },
    });
    await runFrozenWrite(runtime.store, runtime.pending, op.id);
    runtime.queryClient.setQueryData(["xs", 1, "x"], { rows: 1 });
    JSON.stringify(runtime.pending.getSnapshot());
    runtime.store.disconnect("done");
  } finally {
    for (const [name, descriptor] of originals) {
      if (descriptor) Object.defineProperty(globalThis, name, descriptor);
      else Reflect.deleteProperty(globalThis, name);
    }
  }
  assert.deepEqual(touched, []);

  const directory = new URL("../src/security/", import.meta.url);
  for (const file of readdirSync(directory)) {
    const source = readFileSync(new URL(file, directory), "utf8").replace(
      /\/\*[\s\S]*?\*\/|\/\/.*$/gm,
      "",
    );
    assert.doesNotMatch(
      source,
      /localStorage|sessionStorage|indexedDB|document\.cookie|BroadcastChannel|navigator\.storage/,
      file,
    );
  }
});
