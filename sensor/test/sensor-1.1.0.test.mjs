import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const source = await readFile(new URL("../src/sensor-1.1.0.js", import.meta.url), "utf8");
const loaderSource = await readFile(new URL("../src/loader-1.1.0.js", import.meta.url), "utf8");

const HANDLE = "pgh_018f2a3b-4c5d-7000-8000-000000000001";
const PAGE_REF = `action.${"a".repeat(64)}`;
const ORDER_REF = `action.${"b".repeat(64)}`;
const OTHER_REF = `action.${"c".repeat(64)}`;

const bootstrap = (overrides = {}) => ({
  sensor_version: "1.1.0",
  build_ref: "f".repeat(64),
  page_handle: HANDLE,
  navigation_id: "nav_018f2a3b-4c5d-7000-8000-000000000002",
  prepare_url: "/__xshield/v1/events/prepare",
  heartbeat_seconds: 15,
  request_id: "req_018f2a3b-4c5d-7000-8000-000000000003",
  actions: [{ action_ref: PAGE_REF, method: "GET", path_template: "/orders", expires_in_seconds: 600 }],
  harvest: [
    {
      source: { method: "GET", path: "/orders" },
      items_pointer: "/orders",
      resource_pointer: "/id",
      ref_field: "_xshield_action_ref",
      target: { method: "GET", prefix: "/orders/" },
      ttl_seconds: 600,
      max_items: 10,
    },
  ],
  invalidate: [{ method: "POST", path: "/api/logout" }],
  ...overrides,
});

const json = (body, init = {}) =>
  new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
    ...init,
  });

function fakeXhrClass(log) {
  return class FakeXHR {
    constructor() {
      this.requestHeaders = [];
      this.listeners = new Map();
      this.status = 0;
      this.responseType = "";
      this.responseText = "";
    }
    open(method, url) {
      this.method = method;
      this.url = String(url);
    }
    setRequestHeader(name, value) {
      this.requestHeaders.push([name, value]);
    }
    send() {
      log.push(this);
    }
    addEventListener(type, listener) {
      this.listeners.set(type, listener);
    }
    removeEventListener(type) {
      this.listeners.delete(type);
    }
    getResponseHeader(name) {
      return this.responseHeaders?.[name.toLowerCase()] ?? null;
    }
    respond(status, contentType, text) {
      this.status = status;
      this.responseHeaders = { "content-type": contentType };
      this.responseText = text;
      this.listeners.get("loadend")?.();
    }
  };
}

// One sensor instance in a fresh realm. `route` answers every native fetch;
// the bootstrap is answered from `document` unless the route handles it.
function harness({ document = bootstrap(), route = () => json({}), delayBootstrap = false } = {}) {
  const calls = [];
  const xhrs = [];
  const timers = [];
  const clock = { now: 1_800_000_000_000 };
  let releaseBootstrap = () => undefined;
  const sandbox = {
    URL,
    URLSearchParams,
    Headers,
    Request,
    Response,
    TextDecoder,
    location: new URL("https://app.example/app"),
    document: {
      visibilityState: "visible",
      addEventListener: () => undefined,
    },
    Date: { now: () => clock.now },
    setTimeout: (callback, delay) => {
      timers.push({ callback, delay });
      return timers.length;
    },
    fetch(input, init) {
      calls.push({ input, init, self: this });
      let url;
      try {
        url = new URL(input instanceof Request ? input.url : String(input), "https://app.example/app");
      } catch (error) {
        return Promise.reject(error);
      }
      if (url.pathname === "/__xshield/v1/bootstrap") {
        const response = Promise.resolve(json(document));
        if (!delayBootstrap) return response;
        return new Promise((resolve) => {
          releaseBootstrap = () => resolve(response);
        });
      }
      if (url.pathname === "/__xshield/v1/events/prepare") return Promise.resolve(new Response(null, { status: 202 }));
      // Like the real fetch, failures surface as rejected promises.
      return new Promise((resolve) => resolve(route(url, input, init)));
    },
  };
  sandbox.XMLHttpRequest = fakeXhrClass(xhrs);
  vm.runInNewContext(source, sandbox);
  const app = (path, init) => sandbox.fetch(path, init);
  const reference = (call) => {
    const headers = call.init?.headers;
    return headers instanceof Headers ? headers.get("x-xshield-action-ref") : null;
  };
  const target = (input) => {
    try {
      return String(input instanceof Request ? input.url : input);
    } catch {
      return "";
    }
  };
  const businessCalls = () => calls.filter((call) => !target(call.input).includes("/__xshield/"));
  return { sandbox, calls, xhrs, timers, clock, app, reference, businessCalls, release: () => releaseBootstrap() };
}

const settle = () => new Promise((resolve) => setImmediate(resolve));

test("declares exactly which request paths it observes", () => {
  const { sandbox } = harness();
  assert.equal(sandbox.XshieldSensor.version, "1.1.0");
  assert.deepEqual({ ...sandbox.XshieldSensor.coverage }, {
    fetch: true,
    xhr: true,
    workers: false,
    iframes: false,
    serviceWorkers: false,
    savedFetchReferences: false,
  });
  assert.equal(sandbox.fetch.name, "fetch");
  assert.equal(sandbox.fetch.length, 2);
});

test("boots once, for a valid page handle only, through the native fetch", async () => {
  const valid = harness();
  assert.equal(await valid.sandbox.XshieldSensor.boot(HANDLE), true);
  assert.equal(await valid.sandbox.XshieldSensor.boot(HANDLE), false);
  const [first] = valid.calls;
  assert.equal(first.input, `/__xshield/v1/bootstrap?page=${HANDLE}`);
  assert.equal(first.init.credentials, "same-origin");
  assert.equal(first.init.cache, "no-store");
  for (const handle of [null, "", "pgh_018F2A3B-4C5D-7000-8000-000000000001", `${HANDLE}&page=x`]) {
    const invalid = harness();
    assert.equal(await invalid.sandbox.XshieldSensor.boot(handle), false);
    assert.equal(invalid.calls.length, 0, String(handle));
  }
});

test("attaches a page reference only to the exact same-origin method and path", async () => {
  const sensor = harness();
  await sensor.sandbox.XshieldSensor.boot(HANDLE);
  await sensor.app("/orders", { headers: { Authorization: "Bearer page-token" } });
  await sensor.app("/orders?page=2");
  await sensor.app("/orders", { method: "POST" });
  await sensor.app("https://other.example/orders");
  const [listed, query, post, foreign] = sensor.businessCalls();
  assert.equal(sensor.reference(listed), PAGE_REF);
  assert.equal(listed.init.headers.get("authorization"), "Bearer page-token");
  assert.equal(sensor.reference(query), null);
  assert.equal(sensor.reference(post), null);
  assert.equal(foreign.init, undefined, "cross-origin calls pass through untouched");
});

test("never replaces a reference the page set itself and never invents one", async () => {
  const sensor = harness();
  await sensor.sandbox.XshieldSensor.boot(HANDLE);
  await sensor.app("/orders", { headers: { "X-Xshield-Action-Ref": OTHER_REF } });
  await sensor.app("/orders/ord-unknown");
  const [own, unknown] = sensor.businessCalls();
  assert.equal(own.init.headers["X-Xshield-Action-Ref"], OTHER_REF);
  assert.equal(sensor.reference(unknown), null);
});

test("keeps Request inputs, Headers instances, init members and referrer data", async () => {
  const sensor = harness();
  await sensor.sandbox.XshieldSensor.boot(HANDLE);
  const controller = new AbortController();
  const request = new Request("https://app.example/orders", {
    headers: new Headers({ "X-App": "1" }),
    referrerPolicy: "no-referrer",
  });
  await sensor.app(request);
  await sensor.app("/orders", { headers: new Headers({ "X-App": "2" }), signal: controller.signal, credentials: "include" });
  const [fromRequest, fromInit] = sensor.businessCalls();
  assert.equal(fromRequest.input, request, "the Request object itself is forwarded");
  assert.equal(fromRequest.init.headers.get("x-app"), "1");
  assert.equal(sensor.reference(fromRequest), PAGE_REF);
  assert.equal(fromRequest.init.referrerPolicy, "no-referrer");
  assert.equal(fromInit.init.signal, controller.signal);
  assert.equal(fromInit.init.credentials, "include");
  assert.equal(fromInit.init.headers.get("x-app"), "2");
  assert.equal(sensor.reference(fromInit), PAGE_REF);
});

test("returns the native result and propagates native failures", async () => {
  const failure = new TypeError("network down");
  const sensor = harness({
    route: (url) => {
      if (url.pathname === "/fail") throw failure;
      return json({ ok: true });
    },
  });
  await sensor.sandbox.XshieldSensor.boot(HANDLE);
  const response = await sensor.app("/orders");
  assert.ok(response instanceof Response);
  assert.deepEqual(await response.json(), { ok: true });
  await assert.rejects(() => sensor.app("/fail"), (error) => error === failure);
});

test("waits for the bootstrap before deciding, and still lets a late one apply", async () => {
  const sensor = harness({ delayBootstrap: true });
  const booting = sensor.sandbox.XshieldSensor.boot(HANDLE);
  const pending = sensor.app("/orders");
  await settle();
  assert.equal(sensor.businessCalls().length, 0, "the page request waits for the bootstrap");
  sensor.release();
  await booting;
  await pending;
  assert.equal(sensor.reference(sensor.businessCalls()[0]), PAGE_REF);

  const late = harness({ delayBootstrap: true });
  const lateBoot = late.sandbox.XshieldSensor.boot(HANDLE);
  const early = late.app("/orders");
  // The wait is bounded: the timer releases the request without a reference.
  late.timers.find((timer) => timer.delay === 5000).callback();
  await early;
  assert.equal(late.reference(late.businessCalls()[0]), null);
  late.release();
  await lateBoot;
  await late.app("/orders");
  assert.equal(late.reference(late.businessCalls()[1]), PAGE_REF);
});

test("harvests list references without consuming the page's body", async () => {
  const list = {
    orders: [
      { id: "ord-1", _xshield_action_ref: ORDER_REF },
      { id: "ord-2", _xshield_action_ref: "not a reference" },
      { id: 3, _xshield_action_ref: OTHER_REF },
      { id: "ord a/b", _xshield_action_ref: OTHER_REF },
    ],
  };
  const sensor = harness({ route: (url) => (url.pathname === "/orders" ? json(list) : json({})) });
  await sensor.sandbox.XshieldSensor.boot(HANDLE);
  const response = await sensor.app("/orders");
  assert.deepEqual(await response.json(), list, "the page still reads its own body");
  await sensor.app("/orders/ord-1");
  await sensor.app("/orders/ord-2");
  await sensor.app("/orders/3");
  await sensor.app(`/orders/${encodeURIComponent("ord a/b")}`);
  await sensor.app("/orders/ord-1/extra");
  const [, ord1, ord2, numeric, encoded, nested] = sensor.businessCalls();
  assert.equal(sensor.reference(ord1), ORDER_REF);
  assert.equal(sensor.reference(ord2), null, "malformed references are ignored");
  assert.equal(sensor.reference(numeric), null, "only string resources are matched");
  assert.equal(sensor.reference(encoded), OTHER_REF, "the path segment is decoded once");
  assert.equal(sensor.reference(nested), null);
});

test("ignores lists that are not same-origin JSON, oversized or over their bound", async () => {
  const body = { orders: [{ id: "ord-1", _xshield_action_ref: ORDER_REF }] };
  const cases = [
    () => new Response(JSON.stringify(body), { headers: { "content-type": "text/plain" } }),
    () => json(body, { status: 500 }),
    () => json(body, { headers: { "content-type": "application/json", "content-length": String(2 * 1024 * 1024) } }),
    () => json({ orders: Array.from({ length: 11 }, (_, index) => ({ id: `o${index}`, _xshield_action_ref: ORDER_REF })) }),
    () => new Response("{not json", { headers: { "content-type": "application/json" } }),
  ];
  for (const respond of cases) {
    const sensor = harness({ route: (url) => (url.pathname === "/orders" ? respond() : json({})) });
    await sensor.sandbox.XshieldSensor.boot(HANDLE);
    await sensor.app("/orders").catch(() => undefined);
    await settle();
    await sensor.app("/orders/ord-1");
    assert.equal(sensor.reference(sensor.businessCalls().at(-1)), null);
  }
});

test("waits briefly for an in-flight list before a matching target request", async () => {
  let deliver = () => undefined;
  const sensor = harness({
    route: (url) =>
      url.pathname === "/orders"
        ? new Promise((resolve) => {
            deliver = () => resolve(json({ orders: [{ id: "ord-1", _xshield_action_ref: ORDER_REF }] }));
          })
        : json({}),
  });
  await sensor.sandbox.XshieldSensor.boot(HANDLE);
  const listing = sensor.app("/orders");
  await settle();
  const detail = sensor.app("/orders/ord-1");
  await settle();
  deliver();
  await listing;
  await detail;
  assert.equal(sensor.reference(sensor.businessCalls().at(-1)), ORDER_REF);
});

test("drops held references after an identity-changing response or their lease", async () => {
  const sensor = harness({
    route: (url) => (url.pathname === "/orders" ? json({ orders: [{ id: "ord-1", _xshield_action_ref: ORDER_REF }] }) : json({})),
  });
  await sensor.sandbox.XshieldSensor.boot(HANDLE);
  await sensor.app("/orders");
  await settle();
  sensor.clock.now += 601_000;
  await sensor.app("/orders/ord-1");
  await sensor.app("/orders");
  const expired = sensor.businessCalls().slice(-2);
  assert.deepEqual(expired.map(sensor.reference), [null, null], "client-side expiry");

  const logout = harness({
    route: (url) => (url.pathname === "/orders" ? json({ orders: [{ id: "ord-1", _xshield_action_ref: ORDER_REF }] }) : json({})),
  });
  await logout.sandbox.XshieldSensor.boot(HANDLE);
  await logout.app("/orders");
  await settle();
  await logout.app("/api/logout", { method: "POST" });
  await settle();
  await logout.app("/orders/ord-1");
  await logout.app("/orders");
  assert.deepEqual(logout.businessCalls().slice(-2).map(logout.reference), [null, null]);
});

test("rejects any invalid bootstrap document as a whole (default deny)", async () => {
  const invalid = [
    { sensor_version: "1.0.0" },
    { page_handle: "pgh_018f2a3b-4c5d-7000-8000-000000000009" },
    { prepare_url: "https://collector.example/prepare" },
    { actions: Array.from({ length: 17 }, () => bootstrap().actions[0]) },
    { actions: [{ ...bootstrap().actions[0], action_ref: "has space" }] },
    { actions: [{ ...bootstrap().actions[0], method: "TRACE" }] },
    { actions: [{ ...bootstrap().actions[0], path_template: "/orders/{id}" }] },
    { actions: [{ ...bootstrap().actions[0], expires_in_seconds: 0 }] },
    { harvest: [{ ...bootstrap().harvest[0], target: { method: "GET", prefix: "/orders" } }] },
    { harvest: [{ ...bootstrap().harvest[0], items_pointer: "orders" }] },
    { invalidate: [{ method: "POST", prefix: "/api/" }] },
    { heartbeat_seconds: 1 },
    { actions: undefined },
  ];
  for (const override of invalid) {
    const sensor = harness({ document: bootstrap(override) });
    assert.equal(await sensor.sandbox.XshieldSensor.boot(HANDLE), false, JSON.stringify(override));
    await sensor.app("/orders");
    assert.equal(sensor.reference(sensor.businessCalls()[0]), null);
  }
});

test("emits 1.1.0 observations for the bootstrapped page instance", async () => {
  const sensor = harness();
  await sensor.sandbox.XshieldSensor.boot(HANDLE);
  const prepare = sensor.calls.find((call) => String(call.input).endsWith("/events/prepare"));
  const event = JSON.parse(prepare.init.body).events[0];
  assert.equal(event.sensor_version, "1.1.0");
  assert.equal(event.page_handle, HANDLE);
  assert.equal(event.action_hint, null, "client hints never carry authority");
  assert.equal(event.event_type, "PAGE_READY");
});

test("XHR: attaches references, respects page headers, defers until bootstrap, harvests", async () => {
  const sensor = harness({ delayBootstrap: true });
  const booting = sensor.sandbox.XshieldSensor.boot(HANDLE);
  const early = new sensor.sandbox.XMLHttpRequest();
  early.open("GET", "/orders");
  early.setRequestHeader("Authorization", "Bearer page-token");
  assert.equal(early.send(), undefined);
  assert.equal(sensor.xhrs.length, 0, "an async XHR waits for the bootstrap");
  sensor.release();
  await booting;
  await settle();
  assert.deepEqual(early.requestHeaders, [
    ["Authorization", "Bearer page-token"],
    ["X-Xshield-Action-Ref", PAGE_REF],
  ]);
  early.respond(200, "application/json", JSON.stringify({ orders: [{ id: "ord-1", _xshield_action_ref: ORDER_REF }] }));

  const detail = new sensor.sandbox.XMLHttpRequest();
  detail.open("GET", "/orders/ord-1");
  detail.send();
  assert.deepEqual(detail.requestHeaders, [["X-Xshield-Action-Ref", ORDER_REF]]);

  const own = new sensor.sandbox.XMLHttpRequest();
  own.open("GET", "/orders");
  own.setRequestHeader("x-xshield-action-ref", OTHER_REF);
  own.send();
  assert.deepEqual(own.requestHeaders, [["x-xshield-action-ref", OTHER_REF]]);

  const reopened = new sensor.sandbox.XMLHttpRequest();
  reopened.open("GET", "https://other.example/orders");
  reopened.send();
  assert.deepEqual(reopened.requestHeaders, [], "cross-origin XHR is untouched");
});

test("a hook failure falls back to the unmodified native call", async () => {
  const sensor = harness();
  await sensor.sandbox.XshieldSensor.boot(HANDLE);
  const hostile = {
    toString() {
      throw new Error("hostile input");
    },
  };
  await sensor.app(hostile, { headers: { A: "1" } }).catch(() => undefined);
  const [call] = sensor.businessCalls();
  assert.equal(call.input, hostile);
  assert.deepEqual(call.init, { headers: { A: "1" } });
});

test("loader boots the sensor with its own tag's page handle", () => {
  const boots = [];
  const sandbox = {
    document: { currentScript: { getAttribute: (name) => (name === "data-xshield-page" ? HANDLE : null) } },
    XshieldSensor: { boot: (page) => (boots.push(page), Promise.resolve(true)) },
  };
  vm.runInNewContext(loaderSource, sandbox);
  assert.deepEqual(boots, [HANDLE]);
  const absent = [];
  vm.runInNewContext(loaderSource, {
    document: { currentScript: null },
    XshieldSensor: { boot: (page) => (absent.push(page), Promise.resolve(false)) },
  });
  assert.deepEqual(absent, [null]);
  assert.doesNotThrow(() => vm.runInNewContext(loaderSource, { document: {} }));
});
