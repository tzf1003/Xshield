import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const source = await readFile(new URL("../src/sensor.ts", import.meta.url), "utf8");
const loaderSource = await readFile(new URL("../src/loader.ts", import.meta.url), "utf8");

const context = (prepareUrl = "/__xshield/v1/events/prepare") => {
  const requests = [];
  const listeners = new Map();
  const sandbox = {
    URL,
    location: new URL("https://app.example/account"),
    document: {
      visibilityState: "visible",
      addEventListener: (name, listener) => listeners.set(name, listener),
    },
    fetch: (url, init) => {
      requests.push({ url: url.href, init });
      return Promise.resolve({ ok: true });
    },
    setTimeout: () => 1,
    __XSHIELD_BOOTSTRAP__: {
      sensor_version: "1.0.0",
      build_ref: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      page_handle: "pgh_018f2a3b-4c5d-7000-8000-000000000001",
      navigation_id: "nav_018f2a3b-4c5d-7000-8000-000000000002",
      heartbeat_seconds: 15,
      prepare_url: prepareUrl,
    },
  };
  vm.runInNewContext(source, sandbox);
  return { listeners, requests, sandbox };
};

test("emits bounded same-origin page observations", () => {
  const { listeners, requests, sandbox } = context();
  assert.equal(sandbox.XshieldSensor.version, "1.0.0");
  assert.equal(requests.length, 1);
  assert.equal(requests[0].url, "https://app.example/__xshield/v1/events/prepare");
  assert.equal(requests[0].init.credentials, "same-origin");
  const event = JSON.parse(requests[0].init.body).events[0];
  assert.deepEqual(
    {
      type: event.event_type,
      sequence: event.client_event_seq,
      visibility: event.visibility,
      actionHint: event.action_hint,
    },
    { type: "PAGE_READY", sequence: 1, visibility: "visible", actionHint: null },
  );
  sandbox.document.visibilityState = "hidden";
  listeners.get("visibilitychange")();
  assert.equal(JSON.parse(requests[1].init.body).events[0].client_event_seq, 2);
});

test("rejects cross-origin event destinations", () => {
  const { requests, sandbox } = context("https://collector.example/events");
  assert.equal(requests.length, 0);
  assert.equal(sandbox.XshieldSensor.start(sandbox.__XSHIELD_BOOTSTRAP__), false);
  assert.equal(context("http://[").requests.length, 0);
});

test("loader starts the sensor from the same-origin bootstrap", async () => {
  const starts = [];
  const sandbox = {
    XshieldSensor: { start: (bootstrap) => starts.push(bootstrap) },
    fetch: (url, init) => {
      assert.equal(url, "/__xshield/v1/bootstrap");
      assert.equal(init.credentials, "same-origin");
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ sensor_version: "1.0.0" }),
      });
    },
  };
  vm.runInNewContext(loaderSource, sandbox);
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(starts, [{ sensor_version: "1.0.0" }]);
});
