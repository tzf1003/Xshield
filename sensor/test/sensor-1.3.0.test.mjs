import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const source = await readFile(new URL("../src/sensor-1.3.0.js", import.meta.url), "utf8");
const loaderSource = await readFile(new URL("../src/loader-1.3.0.js", import.meta.url), "utf8");

const HANDLE = "pgh_018f2a3b-4c5d-7000-8000-000000000001";
const PAGE_REF = `action.${"a".repeat(64)}`;
const ORDER_REF = `action.${"b".repeat(64)}`;
const OTHER_REF = `action.${"c".repeat(64)}`;

const bootstrap = (overrides = {}) => ({
  sensor_version: "1.3.0",
  build_ref: "f".repeat(64),
  page_handle: HANDLE,
  navigation_id: "nav_018f2a3b-4c5d-7000-8000-000000000002",
  prepare_url: "/__xshield/v1/events/prepare",
  ws_url: "/__xshield/v1/sensor/ws",
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

const ENVELOPE_KEY_HEX = "11".repeat(32);
const ENVELOPE_KEY_ID = "ehk.7";

// `bootstrap()` plus one ENVELOPE_HOOK operation on POST /checkout, the
// session key, and the tenant/site identifiers the AAD binds.
const envelopeBootstrap = (overrides = {}) =>
  bootstrap({
    tenant_id: "tenant_demo",
    site_id: "site_demo",
    envelope_key: ENVELOPE_KEY_HEX,
    envelope_key_id: ENVELOPE_KEY_ID,
    envelope_operations: [
      {
        method: "POST",
        path: "/checkout",
        operation_id: "checkout.submit",
        adapter_revision: "checkout-json-r1",
      },
    ],
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
    send(body) {
      this.body = body;
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

// A minimal, test-controlled WebSocket: the harness drives `open()` and
// `closeFromServer()` itself instead of a real socket ever connecting.
function fakeWebSocketClass(sockets) {
  return class FakeWebSocket {
    static CONNECTING = 0;
    static OPEN = 1;
    static CLOSING = 2;
    static CLOSED = 3;
    constructor(url) {
      this.url = url;
      this.readyState = FakeWebSocket.CONNECTING;
      this.listeners = new Map();
      this.sent = [];
      sockets.push(this);
    }
    addEventListener(type, listener) {
      this.listeners.set(type, listener);
    }
    removeEventListener(type) {
      this.listeners.delete(type);
    }
    send(data) {
      if (this.readyState !== FakeWebSocket.OPEN) throw new Error("not open");
      this.sent.push(data);
    }
    open() {
      this.readyState = FakeWebSocket.OPEN;
      this.listeners.get("open")?.();
    }
    closeFromServer() {
      this.readyState = FakeWebSocket.CLOSED;
      this.listeners.get("close")?.();
    }
  };
}

// One sensor instance in a fresh realm. `route` answers every native fetch;
// the bootstrap is answered from `document` unless the route handles it.
// `webSocket` is the sandbox's WebSocket constructor, or `null` to simulate
// a browser without WebSocket support.
function harness({
  document = bootstrap(),
  route = () => json({}),
  delayBootstrap = false,
  telemetryDown = false,
  webSocket = "default",
} = {}) {
  const calls = [];
  const listeners = new Map();
  const xhrs = [];
  const sockets = [];
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
    TextEncoder,
    DataView,
    Uint8Array,
    crypto: globalThis.crypto,
    location: new URL("https://app.example/app"),
    document: {
      visibilityState: "visible",
      addEventListener: (name, listener) => listeners.set(name, listener),
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
      if (url.pathname === "/__xshield/v1/events/prepare") {
        // A dropped telemetry channel surfaces like a failed native fetch.
        if (telemetryDown) return Promise.reject(new TypeError("network error"));
        return Promise.resolve(new Response(null, { status: 202 }));
      }
      // Like the real fetch, failures surface as rejected promises.
      return new Promise((resolve) => resolve(route(url, input, init)));
    },
  };
  if (webSocket !== null) {
    sandbox.WebSocket = webSocket === "default" ? fakeWebSocketClass(sockets) : webSocket;
  }
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
  const httpsObservations = () =>
    calls
      .filter((call) => target(call.input).endsWith("/events/prepare"))
      .flatMap((call) => JSON.parse(call.init.body).events);
  const wsObservations = () =>
    sockets.flatMap((socket) => socket.sent.flatMap((body) => JSON.parse(body).events));
  // Transport-agnostic view: most tests only care what the page reported,
  // not which of the two channels carried it.
  const observations = () => [...httpsObservations(), ...wsObservations()];
  return {
    sandbox,
    calls,
    xhrs,
    sockets,
    timers,
    clock,
    listeners,
    app,
    reference,
    businessCalls,
    observations,
    httpsObservations,
    wsObservations,
    release: () => releaseBootstrap(),
  };
}

// A few event-loop turns: enough for chained microtasks and, unlike 1.2.0,
// for the real (if tiny) WebCrypto operations ENVELOPE_HOOK now awaits.
const settle = async () => {
  for (let turn = 0; turn < 20; turn += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
};

test("declares exactly which request paths it observes", () => {
  const { sandbox } = harness();
  assert.equal(sandbox.XshieldSensor.version, "1.3.0");
  assert.deepEqual({ ...sandbox.XshieldSensor.coverage }, {
    fetch: true,
    xhr: true,
    workers: false,
    iframes: false,
    serviceWorkers: false,
    savedFetchReferences: false,
    envelopeHook: true,
  });
  assert.equal(sandbox.fetch.name, "fetch");
  assert.equal(sandbox.fetch.length, 2);
});

test("boots once, for a valid page handle only, through the native fetch", async () => {
  const valid = harness();
  assert.equal(await valid.sandbox.XshieldSensor.boot(HANDLE), true);
  assert.equal(await valid.sandbox.XshieldSensor.boot(HANDLE), false);
  const [first] = valid.calls;
  assert.equal(first.input, `/__xshield/v1/bootstrap?page=${HANDLE}&sensor_version=1.3.0`);
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

test("a hidden, frozen or disconnected page keeps its edge checks and never fakes liveness", async () => {
  const sensor = harness({ telemetryDown: true });
  assert.equal(await sensor.sandbox.XshieldSensor.boot(HANDLE), true);
  // The page goes to the background and its timers freeze: no heartbeat fires,
  // and every observation fails like a dropped connection.
  sensor.sandbox.document.visibilityState = "hidden";
  sensor.listeners.get("visibilitychange")();
  await settle();
  assert.deepEqual(
    sensor.observations().map((event) => [event.event_type, event.client_event_seq, event.visibility]),
    [
      ["PAGE_READY", 1, "visible"],
      ["VISIBILITY", 2, "hidden"],
    ],
    "the sensor reports the state change and never backfills missed heartbeats",
  );
  // Business calls are neither blocked nor stripped: the edge still receives
  // the same reference and applies its identity and grant checks to it.
  await sensor.app("/orders");
  await sensor.app("/orders/ord-unknown");
  const [listed, unknown] = sensor.businessCalls();
  assert.equal(sensor.reference(listed), PAGE_REF);
  assert.equal(sensor.reference(unknown), null, "a missing heartbeat never widens what is presented");

  // When the timers thaw, the next heartbeat continues the same page sequence.
  sensor.sandbox.document.visibilityState = "visible";
  sensor.timers.find((timer) => timer.delay === 15_000).callback();
  await settle();
  const last = sensor.observations().at(-1);
  assert.deepEqual([last.event_type, last.client_event_seq, last.visibility], ["HEARTBEAT", 3, "visible"]);
  assert.equal(last.page_handle, HANDLE);
});

test("a business request that beats the telemetry is never paired with a later heartbeat", async () => {
  const sensor = harness({ delayBootstrap: true });
  const booting = sensor.sandbox.XshieldSensor.boot(HANDLE);
  const early = sensor.app("/orders");
  sensor.timers.find((timer) => timer.delay === 5000).callback();
  await early;
  assert.equal(sensor.observations().length, 0, "the request reached the edge before any telemetry");
  const [first] = sensor.businessCalls();
  assert.equal(sensor.reference(first), null, "it falls under the missing-reference rule");
  const headers = first.init?.headers;
  assert.deepEqual(
    headers instanceof Headers ? [...headers.keys()].filter((name) => name.startsWith("x-xshield")) : [],
    [],
    "no telemetry handle rides on the business call",
  );

  sensor.release();
  await booting;
  sensor.timers.find((timer) => timer.delay === 15_000).callback();
  await settle();
  const events = sensor.observations();
  assert.deepEqual(events.map((event) => event.event_type), ["PAGE_READY", "HEARTBEAT"]);
  for (const event of events) {
    assert.equal(event.client_request_id, null, "telemetry never claims a business request");
    assert.equal(event.action_hint, null);
  }
  // The late bootstrap applies only to calls made after it, never retroactively.
  await sensor.app("/orders");
  assert.deepEqual(sensor.businessCalls().map(sensor.reference), [null, PAGE_REF]);
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

  // A list fetched with a query still carries edge-injected references; a
  // target or page action with a query never matches.
  const paged = harness({ route: (url) => (url.pathname === "/orders" ? json(list) : json({})) });
  await paged.sandbox.XshieldSensor.boot(HANDLE);
  await paged.app("/orders?page=2");
  await settle();
  await paged.app("/orders/ord-1");
  await paged.app("/orders/ord-1?view=full");
  const [pagedList, pagedDetail, pagedQuery] = paged.businessCalls();
  assert.equal(paged.reference(pagedList), null);
  assert.equal(paged.reference(pagedDetail), ORDER_REF);
  assert.equal(paged.reference(pagedQuery), null);
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
    { ws_url: "https://collector.example/ws" },
    { ws_url: undefined },
    { ws_url: "" },
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

test("emits 1.3.0 observations for the bootstrapped page instance", async () => {
  const sensor = harness();
  await sensor.sandbox.XshieldSensor.boot(HANDLE);
  const prepare = sensor.calls.find((call) => String(call.input).endsWith("/events/prepare"));
  const event = JSON.parse(prepare.init.body).events[0];
  assert.equal(event.sensor_version, "1.3.0");
  assert.equal(event.page_handle, HANDLE);
  assert.equal(event.action_hint, null, "client hints never carry authority");
  assert.equal(event.event_type, "PAGE_READY");
});

test("opens a same-origin wss: channel derived from ws_url and uses it once open", async () => {
  const sensor = harness();
  await sensor.sandbox.XshieldSensor.boot(HANDLE);
  assert.equal(sensor.sockets.length, 1);
  const [socket] = sensor.sockets;
  assert.equal(socket.url, "wss://app.example/__xshield/v1/sensor/ws");
  // Before the socket opens, PAGE_READY already went out over HTTPS.
  assert.equal(sensor.httpsObservations().length, 1);
  assert.equal(sensor.wsObservations().length, 0);
  socket.open();
  sensor.timers.find((timer) => timer.delay === 15_000).callback();
  assert.equal(sensor.wsObservations().length, 1);
  assert.equal(sensor.wsObservations()[0].event_type, "HEARTBEAT");
  assert.equal(sensor.httpsObservations().length, 1, "no duplicate once the socket is open");
});

test("derives ws: (not wss:) from a plain-http page", async () => {
  const sensor = harness({
    document: bootstrap(),
  });
  sensor.sandbox.location.href = "http://app.example/app";
  sensor.sandbox.location = new URL("http://app.example/app");
  await sensor.sandbox.XshieldSensor.boot(HANDLE);
  assert.equal(sensor.sockets[0].url, "ws://app.example/__xshield/v1/sensor/ws");
});

test("falls back to HTTPS when the socket is not open, and when WebSocket is unavailable", async () => {
  const neverOpens = harness();
  await neverOpens.sandbox.XshieldSensor.boot(HANDLE);
  neverOpens.timers.find((timer) => timer.delay === 15_000).callback();
  assert.equal(neverOpens.wsObservations().length, 0);
  assert.equal(neverOpens.httpsObservations().length, 2, "PAGE_READY and HEARTBEAT both over HTTPS");

  const noSocketSupport = harness({ webSocket: null });
  await noSocketSupport.sandbox.XshieldSensor.boot(HANDLE);
  assert.equal(noSocketSupport.sockets.length, 0);
  noSocketSupport.timers.find((timer) => timer.delay === 15_000).callback();
  assert.equal(noSocketSupport.httpsObservations().length, 2);
});

test("falls back to HTTPS for the one send whose socket throws", async () => {
  class ThrowingWebSocket {
    static OPEN = 1;
    constructor() {
      this.readyState = ThrowingWebSocket.OPEN;
    }
    addEventListener() {}
    removeEventListener() {}
    send() {
      throw new Error("send failed");
    }
  }
  const sensor = harness({ webSocket: ThrowingWebSocket });
  await sensor.sandbox.XshieldSensor.boot(HANDLE);
  assert.equal(sensor.httpsObservations().length, 1);
});

test("reconnects the WSS channel with backoff after the server closes it", async () => {
  const sensor = harness();
  await sensor.sandbox.XshieldSensor.boot(HANDLE);
  const [first] = sensor.sockets;
  first.open();
  first.closeFromServer();
  assert.equal(sensor.sockets.length, 1, "no reconnect before the backoff timer fires");
  const reconnect = sensor.timers.find((timer) => timer.delay >= 500 && timer.delay <= 1000);
  assert.ok(reconnect, "a bounded, jittered reconnect delay was scheduled");
  reconnect.callback();
  assert.equal(sensor.sockets.length, 2);
  assert.notEqual(sensor.sockets[1], first);
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

const hexToBytes = (hex) => Uint8Array.from(hex.match(/../g) ?? [], (byte) => Number.parseInt(byte, 16));

const envelopeAad = (fields) => {
  const encoder = new TextEncoder();
  const parts = fields.map((field) => encoder.encode(field));
  const total = parts.reduce((sum, part) => sum + 4 + part.byteLength, 0);
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  let offset = 0;
  for (const part of parts) {
    view.setUint32(offset, part.byteLength, false);
    offset += 4;
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
};

// Decrypts one ENVELOPE_HOOK envelope exactly as the edge would (its own
// AAD layout, independently reconstructed here), so these tests catch a
// drift in the sensor's own framing rather than only that it produced *some*
// ciphertext under *some* key.
const decryptEnvelope = async (envelopeJson, scope) => {
  const envelope = JSON.parse(envelopeJson);
  const key = await globalThis.crypto.subtle.importKey(
    "raw",
    hexToBytes(ENVELOPE_KEY_HEX),
    "AES-GCM",
    false,
    ["decrypt"],
  );
  const aad = envelopeAad([
    "xshield.request.envelope-hook.v1",
    scope.tenantId,
    scope.siteId,
    scope.operationId,
    scope.method,
    scope.path,
    scope.adapterRevision,
    envelope.key_id,
    envelope.message_id,
    String(envelope.issued_at),
    String(envelope.expires_at),
    "application/json",
  ]);
  const sealed = new Uint8Array([...hexToBytes(envelope.ciphertext), ...hexToBytes(envelope.tag)]);
  const plaintext = await globalThis.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: hexToBytes(envelope.nonce), additionalData: aad, tagLength: 128 },
    key,
    sealed,
  );
  return { envelope, plaintext: new TextDecoder().decode(plaintext) };
};

const CHECKOUT_SCOPE = {
  tenantId: "tenant_demo",
  siteId: "site_demo",
  operationId: "checkout.submit",
  method: "POST",
  path: "/checkout",
  adapterRevision: "checkout-json-r1",
};

test("fetch: encrypts a configured operation's JSON string body into an envelope the edge can decode", async () => {
  const sensor = harness({ document: envelopeBootstrap() });
  await sensor.sandbox.XshieldSensor.boot(HANDLE);
  const plaintext = JSON.stringify({ sku: "A-1", quantity: 2 });
  await sensor.app("/checkout", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: plaintext,
  });
  const [call] = sensor.businessCalls();
  assert.equal(call.init.headers.get("content-type"), "application/vnd.xshield.encrypted+json");
  assert.notEqual(call.init.body, plaintext, "the plaintext never reaches the wire");
  const { envelope, plaintext: decoded } = await decryptEnvelope(call.init.body, CHECKOUT_SCOPE);
  assert.equal(decoded, plaintext);
  assert.equal(envelope.schema_version, 1);
  assert.equal(envelope.adapter_revision, "checkout-json-r1");
  assert.equal(envelope.key_id, ENVELOPE_KEY_ID);
  assert.match(envelope.message_id, /^msg_[0-9a-f-]{36}$/);
  assert.equal(envelope.expires_at - envelope.issued_at, 30);
});

test("fetch: two calls to the same operation never reuse a message_id or nonce", async () => {
  const sensor = harness({ document: envelopeBootstrap() });
  await sensor.sandbox.XshieldSensor.boot(HANDLE);
  await sensor.app("/checkout", { method: "POST", body: JSON.stringify({ a: 1 }) });
  await sensor.app("/checkout", { method: "POST", body: JSON.stringify({ a: 1 }) });
  const [first, second] = sensor.businessCalls();
  const a = JSON.parse(first.init.body);
  const b = JSON.parse(second.init.body);
  assert.notEqual(a.message_id, b.message_id);
  assert.notEqual(a.nonce, b.nonce);
  assert.notEqual(a.ciphertext, b.ciphertext);
});

test("fetch: never encrypts a different method, an unconfigured path, or a call with a query string", async () => {
  const sensor = harness({ document: envelopeBootstrap() });
  await sensor.sandbox.XshieldSensor.boot(HANDLE);
  const plaintext = JSON.stringify({ a: 1 });
  await sensor.app("/checkout", { method: "PUT", body: plaintext });
  await sensor.app("/checkout?x=1", { method: "POST", body: plaintext });
  await sensor.app("/other", { method: "POST", body: plaintext });
  for (const call of sensor.businessCalls()) {
    assert.equal(call.init.body, plaintext);
  }
});

test("fetch: a Request-carried or missing body passes through unmodified rather than being guessed at", async () => {
  const sensor = harness({ document: envelopeBootstrap() });
  await sensor.sandbox.XshieldSensor.boot(HANDLE);
  const request = new Request("https://app.example/checkout", {
    method: "POST",
    body: JSON.stringify({ a: 1 }),
  });
  await sensor.app(request);
  await sensor.app("/checkout", { method: "POST" });
  const [fromRequest, noBody] = sensor.businessCalls();
  assert.equal(fromRequest.input, request, "a Request's own body stream is left untouched");
  assert.equal(noBody.init.body, undefined);
});

test("fetch: a site with no ENVELOPE_HOOK operations never holds up or touches the call", async () => {
  const sensor = harness();
  await sensor.sandbox.XshieldSensor.boot(HANDLE);
  const plaintext = JSON.stringify({ a: 1 });
  await sensor.app("/checkout", { method: "POST", body: plaintext });
  assert.equal(sensor.businessCalls()[0].init.body, plaintext);
});

test("XHR: encrypts a configured operation's string body before the native send", async () => {
  const sensor = harness({ document: envelopeBootstrap() });
  await sensor.sandbox.XshieldSensor.boot(HANDLE);
  const xhr = new sensor.sandbox.XMLHttpRequest();
  xhr.open("POST", "/checkout");
  const plaintext = JSON.stringify({ sku: "A-1" });
  xhr.send(plaintext);
  await settle();
  const [sent] = sensor.xhrs;
  assert.notEqual(sent.body, plaintext);
  assert.deepEqual(
    sent.requestHeaders.filter(([name]) => name.toLowerCase() === "content-type"),
    [["Content-Type", "application/vnd.xshield.encrypted+json"]],
  );
  const { plaintext: decoded } = await decryptEnvelope(sent.body, CHECKOUT_SCOPE);
  assert.equal(decoded, plaintext);
});

test("XHR: a page-set Content-Type is left alone rather than risking a combined header", async () => {
  const sensor = harness({ document: envelopeBootstrap() });
  await sensor.sandbox.XshieldSensor.boot(HANDLE);
  const xhr = new sensor.sandbox.XMLHttpRequest();
  xhr.open("POST", "/checkout");
  xhr.setRequestHeader("Content-Type", "application/json");
  const plaintext = JSON.stringify({ sku: "A-1" });
  xhr.send(plaintext);
  await settle();
  const [sent] = sensor.xhrs;
  assert.equal(sent.body, plaintext, "left for the edge to deny rather than risk a combined header");
  assert.deepEqual(sent.requestHeaders, [["Content-Type", "application/json"]]);
});

test("rejects a bootstrap with malformed or incomplete ENVELOPE_HOOK fields as a whole", async () => {
  const base = envelopeBootstrap();
  const invalid = [
    { envelope_operations: Array.from({ length: 65 }, () => base.envelope_operations[0]) },
    { envelope_operations: [{ ...base.envelope_operations[0], method: "TRACE" }] },
    { envelope_operations: [{ ...base.envelope_operations[0], operation_id: "" }] },
    { envelope_operations: [{ ...base.envelope_operations[0], path: "/checkout?x=1" }] },
    { envelope_key: "zz".repeat(32) },
    { envelope_key: ENVELOPE_KEY_HEX.slice(0, 62) },
    { envelope_key_id: "not-an-id" },
    { envelope_key: undefined },
    { tenant_id: undefined },
    { site_id: undefined },
  ];
  for (const override of invalid) {
    const sensor = harness({ document: envelopeBootstrap(override) });
    assert.equal(await sensor.sandbox.XshieldSensor.boot(HANDLE), false, JSON.stringify(override));
  }
});

test("a site with no ENVELOPE_HOOK operations needs none of the key, tenant, or site fields", async () => {
  const sensor = harness({ document: bootstrap() });
  assert.equal(await sensor.sandbox.XshieldSensor.boot(HANDLE), true);
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
