import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiError } from "../src/api-contract.ts";
import {
  StepUpCancelledError,
  StepUpCoordinator,
  type StepUpDeps,
  StepUpUnavailableError,
  type StepUpWindow,
  withStepUp,
} from "../src/work/step-up.ts";

type Harness = {
  coordinator: StepUpCoordinator;
  deps: StepUpDeps;
  log: string[];
  window: StepUpWindow & { closed: boolean; url: string | null };
  hint: () => void;
  valid: { value: boolean };
  blockPopups: { value: boolean };
  startFails: { value: boolean };
  ticks: Array<() => void>;
};

function harness(available = true): Harness {
  const log: string[] = [];
  const valid = { value: false };
  const blockPopups = { value: false };
  const startFails = { value: false };
  const listeners = new Set<() => void>();
  const ticks: Array<() => void> = [];
  const window = {
    closed: false,
    url: null as string | null,
    navigate(url: string) {
      this.url = url;
      log.push(`navigate ${url}`);
    },
    close() {
      this.closed = true;
      log.push("close");
    },
    isClosed() {
      return this.closed;
    },
  };
  const deps: StepUpDeps = {
    available: () => available,
    openWindow: () => {
      log.push("open");
      return blockPopups.value ? null : window;
    },
    start: async () => {
      log.push("start");
      if (startFails.value) throw new ApiError("CONTROL_OIDC_REAUTH_REQUEST_INVALID", 403);
      return "https://idp.example/authorize?state=1";
    },
    check: async () => {
      log.push("check");
      return valid.value;
    },
    listen: (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    every: (tick) => {
      ticks.push(tick);
      return () => {
        const at = ticks.indexOf(tick);
        if (at >= 0) ticks.splice(at, 1);
      };
    },
  };
  const coordinator = new StepUpCoordinator(deps);
  coordinator.attach();
  return {
    coordinator,
    deps,
    log,
    window,
    hint: () => {
      for (const listener of [...listeners]) listener();
    },
    valid,
    blockPopups,
    startFails,
    ticks,
  };
}
const flush = () => new Promise<void>((resolve) => setImmediate(resolve));
const stepUpError = () => new ApiError("CONTROL_STEP_UP_REQUIRED", 403);

test("a refused attempt waits, the operator verifies, and the same closure runs again", async () => {
  const h = harness();
  const signal = new AbortController().signal;
  const calls: string[] = [];
  let attempt = 0;
  const run = async () => {
    attempt += 1;
    calls.push(`run ${attempt}`);
    if (attempt === 1) throw stepUpError();
    return "done";
  };
  const result = withStepUp(h.coordinator, signal, run);
  await flush();
  assert.equal(h.coordinator.getState().phase, "needed");
  assert.deepEqual(calls, ["run 1"], "nothing is sent again before the step-up");
  h.coordinator.begin();
  assert.equal(h.coordinator.getState().phase, "opening");
  await flush();
  assert.equal(h.coordinator.getState().phase, "waiting");
  assert.equal(h.window.url, "https://idp.example/authorize?state=1");
  h.valid.value = true;
  h.hint();
  assert.equal(await result, "done");
  assert.deepEqual(calls, ["run 1", "run 2"]);
  assert.equal(h.coordinator.getState().phase, "idle");
  assert.equal(h.window.closed, true);
});

test("only a step-up refusal pauses; other errors and a second refusal pass straight through", async () => {
  const h = harness();
  const signal = new AbortController().signal;
  const denied = new ApiError("CONTROL_SCOPE_DENIED", 403);
  await assert.rejects(
    withStepUp(h.coordinator, signal, async () => {
      throw denied;
    }),
    (error) => error === denied,
  );
  assert.equal(h.coordinator.getState().phase, "idle");
  await assert.rejects(
    withStepUp(h.coordinator, signal, async () => {
      throw new ApiError("CONTROL_STEP_UP_REQUIRED", 500);
    }),
    (error) => error instanceof ApiError && error.status === 500,
  );
  // A refusal after a successful step-up is reported, never looped on.
  let runs = 0;
  const second = withStepUp(h.coordinator, signal, async () => {
    runs += 1;
    throw stepUpError();
  });
  await flush();
  h.coordinator.begin();
  await flush();
  h.valid.value = true;
  h.hint();
  await assert.rejects(second, (error) => isStepUp(error));
  assert.equal(runs, 2);
});
const isStepUp = (error: unknown) =>
  error instanceof ApiError && error.code === "CONTROL_STEP_UP_REQUIRED";

test("concurrent refused attempts share one verification and all resume", async () => {
  const h = harness();
  const signal = new AbortController().signal;
  const make = () => {
    let attempt = 0;
    return withStepUp(h.coordinator, signal, async () => {
      attempt += 1;
      if (attempt === 1) throw stepUpError();
      return attempt;
    });
  };
  const both = Promise.all([make(), make()]);
  await flush();
  h.coordinator.begin();
  await flush();
  h.valid.value = true;
  await h.coordinator.recheck();
  assert.deepEqual(await both, [2, 2]);
  assert.equal(h.log.filter((line) => line === "open").length, 1);
  assert.equal(h.log.filter((line) => line === "start").length, 1);
});

test("cancelling gives every paused attempt its original refusal and closes the window", async () => {
  const h = harness();
  const signal = new AbortController().signal;
  const original = stepUpError();
  const result = withStepUp(h.coordinator, signal, async () => {
    throw original;
  });
  await flush();
  h.coordinator.begin();
  await flush();
  h.coordinator.cancel();
  await assert.rejects(result, (error) => error === original);
  assert.equal(h.coordinator.getState().phase, "idle");
  assert.equal(h.window.closed, true);
});

test("the session ending aborts the wait; detaching cancels too", async () => {
  const h = harness();
  const controller = new AbortController();
  const original = stepUpError();
  const result = withStepUp(h.coordinator, controller.signal, async () => {
    throw original;
  });
  await flush();
  assert.equal(h.coordinator.getState().phase, "needed");
  controller.abort();
  await assert.rejects(result, (error) => error === original);
  assert.equal(h.coordinator.getState().phase, "idle");
  await assert.rejects(
    h.coordinator.require(controller.signal),
    (error) => error instanceof StepUpCancelledError,
  );
  const detach = h.coordinator.attach();
  const next = h.coordinator.require(new AbortController().signal);
  detach();
  await assert.rejects(next, (error) => error instanceof StepUpCancelledError);
});

test("machine credentials cannot step up: the refusal stands at once", async () => {
  const h = harness(false);
  await assert.rejects(
    h.coordinator.require(new AbortController().signal),
    (error) => error instanceof StepUpUnavailableError,
  );
  const original = stepUpError();
  await assert.rejects(
    withStepUp(h.coordinator, new AbortController().signal, async () => {
      throw original;
    }),
    (error) => error === original,
  );
  assert.equal(h.coordinator.getState().phase, "idle");
});

test("a blocked window, a failed start and an unverified return keep the operator in control", async () => {
  const h = harness();
  const signal = new AbortController().signal;
  const original = stepUpError();
  const result = withStepUp(h.coordinator, signal, async () => {
    throw original;
  });
  result.catch(() => {});
  await flush();
  h.blockPopups.value = true;
  h.coordinator.begin();
  assert.equal(h.coordinator.getState().phase, "needed");
  assert.match(h.coordinator.getState().message ?? "", /拦截了新窗口/);
  h.blockPopups.value = false;
  h.startFails.value = true;
  h.coordinator.begin();
  await flush();
  assert.equal(h.coordinator.getState().phase, "needed");
  assert.match(h.coordinator.getState().message ?? "", /再认证请求无效/);
  assert.equal(h.window.closed, true, "a window whose start failed is closed");
  h.startFails.value = false;
  h.window.closed = false;
  h.coordinator.begin();
  await flush();
  assert.equal(h.coordinator.getState().phase, "waiting");
  // The return hint is never proof: the session is re-read, and an unverified one waits on.
  h.hint();
  await flush();
  assert.equal(h.coordinator.getState().phase, "waiting");
  assert.match(h.coordinator.getState().message ?? "", /尚未生效/);
  h.coordinator.cancel();
  await assert.rejects(result, (error) => error === original);
});

test("a window the operator closed is re-checked once, not polled", async () => {
  const h = harness();
  const signal = new AbortController().signal;
  let attempt = 0;
  const result = withStepUp(h.coordinator, signal, async () => {
    attempt += 1;
    if (attempt === 1) throw stepUpError();
    return "ok";
  });
  await flush();
  h.coordinator.begin();
  await flush();
  assert.equal(h.ticks.length, 1);
  h.valid.value = true;
  h.window.closed = true;
  h.ticks[0]?.();
  assert.equal(await result, "ok");
  assert.equal(h.ticks.length, 0, "the watcher stops with the verification");
  assert.equal(h.log.filter((line) => line === "check").length, 1);
});

test("a hint with nothing paused changes nothing", async () => {
  const h = harness();
  h.hint();
  await flush();
  assert.equal(h.coordinator.getState().phase, "idle");
  assert.equal(h.log.length, 0);
  h.coordinator.begin();
  assert.equal(h.log.length, 0, "begin only acts while an attempt is waiting");
});
