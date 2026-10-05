/**
 * Real-browser provenance loop, driven by scripts/test_browser_loop.sh.
 *
 * The happy path uses only page interactions (goto, fill, click): the app's
 * own script sends its Authorization header and the 1.1.0 sensor attaches
 * the server-issued references. Attack cases then replay what a user, a
 * script or another browser could send; each must be denied with its stable
 * reason code before the origin sees it. Writes the request IDs it observed
 * to LOOP_EXPECTATIONS so the shell can check the encrypted journal.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";

const packageJson = process.env.XSHIELD_PLAYWRIGHT_PACKAGE
  ? pathToFileURL(process.env.XSHIELD_PLAYWRIGHT_PACKAGE)
  : new URL("../web/console/package.json", import.meta.url);
const { chromium } = createRequire(packageJson)("@playwright/test");

const edge = process.env.EDGE_URL;
const origin = process.env.ORIGIN_URL;
const database = process.env.LOOP_DATABASE;
const expectationsPath = process.env.LOOP_EXPECTATIONS;
assert.ok(edge && origin && database && expectationsPath, "run through scripts/test_browser_loop.sh");

const transcript = { flow: [], denials: [], coverage: [], isolation: [] };
const expectations = { decisions: [], stages: [] };
const pathOf = (response) => new URL(response.url()).pathname;
const requestId = (response) => response.headers()["x-xshield-request-id"];
const metrics = async () => (await fetch(`${origin}/__lab/metrics`)).json();
const ORDER_PATHS = ["/orders", "/orders/ord-alice-1", "/orders/ord-alice-2", "/orders/ord-bob-1"];

// Runs one request from inside the page. "fetch" and "xhr" go through the
// page's (hooked) globals; "saved-fetch", "iframe" and "worker" are the
// documented unhooked paths. The test only adds a reference header when a
// case explicitly replays one; the app-style bearer is the app's own token.
function call(page, path, { reference = null, via = "fetch" } = {}) {
  return page.evaluate(
    async ([target, ref, transport]) => {
      const headers = { Authorization: `Bearer ${sessionStorage.getItem("orders.token")}` };
      if (ref !== null) headers["X-Xshield-Action-Ref"] = ref;
      const url = new URL(target, location.href).href;
      const read = async (response) => ({
        status: response.status,
        requestId: response.headers.get("x-xshield-request-id"),
        body: await response.text(),
      });
      if (transport === "fetch") return read(await fetch(url, { headers }));
      if (transport === "saved-fetch") return read(await window.appRawFetch(url, { headers }));
      if (transport === "iframe") {
        const frame = document.createElement("iframe");
        document.body.append(frame);
        return read(await frame.contentWindow.fetch(url, { headers }));
      }
      if (transport === "worker") {
        const source = `onmessage = async (event) => {
          const response = await fetch(event.data.url, { headers: event.data.headers });
          postMessage({ status: response.status,
                        requestId: response.headers.get("x-xshield-request-id"),
                        body: await response.text() });
        };`;
        const worker = new Worker(URL.createObjectURL(new Blob([source], { type: "text/javascript" })));
        return new Promise((resolve) => {
          worker.onmessage = (event) => {
            worker.terminate();
            resolve(event.data);
          };
          worker.postMessage({ url, headers });
        });
      }
      return new Promise((resolve) => {
        const xhr = new XMLHttpRequest();
        xhr.open("GET", url);
        for (const [name, value] of Object.entries(headers)) xhr.setRequestHeader(name, value);
        xhr.onloadend = () =>
          resolve({
            status: xhr.status,
            requestId: xhr.getResponseHeader("x-xshield-request-id"),
            body: xhr.responseText,
          });
        xhr.send();
      });
    },
    [path, reference, via],
  );
}

function reasonOf(result) {
  try {
    return JSON.parse(result.body).reason_code ?? null;
  } catch {
    return null;
  }
}

function expectDenied(label, result, reason, list = transcript.denials) {
  const observed = reasonOf(result);
  list.push({ case: label, status: result.status, reason_code: observed, request_id: result.requestId });
  assert.equal(result.status, reason === "AUTH_REQUIRED" ? 401 : 403, `${label}: ${result.body}`);
  assert.equal(observed, reason, label);
  assert.match(result.requestId ?? "", /^req_/, `${label}: request id`);
  expectations.decisions.push({ request_id: result.requestId, decision: "DENY", reason_code: reason });
}

async function signIn(browser, user) {
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();
  const sent = [];
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.origin === edge) {
      sent.push({ method: request.method(), path: url.pathname, headers: request.headers() });
    }
  });
  const appResponse = page.waitForResponse((r) => pathOf(r) === "/app");
  const bootstrapResponse = page.waitForResponse((r) => pathOf(r) === "/__xshield/v1/bootstrap");
  const listResponse = page.waitForResponse(
    (r) => pathOf(r) === "/orders" && r.request().method() === "GET",
  );
  await page.goto(`${edge}/`);
  await page.fill("#user", user);
  await page.click("button[type=submit]");
  const app = await appResponse;
  const bootstrap = await bootstrapResponse;
  const list = await listResponse;
  await page.waitForSelector('#status[data-status="200"]');
  return {
    context,
    page,
    sent,
    app,
    html: await app.text(),
    bootstrap: await bootstrap.json(),
    bootstrapRequestId: requestId(bootstrap),
    list: await list.json(),
    listRequestId: requestId(list),
    pageHandle: await page.getAttribute("script[data-xshield-page]", "data-xshield-page"),
  };
}

// The reference header the page (i.e. the sensor) put on the latest request
// to `path`, so a denial can be attributed to the edge rather than to a
// reference the sensor never sent.
function lastReference(session, path) {
  const request = session.sent.findLast((entry) => entry.path === path);
  assert.ok(request, `no request to ${path} was observed`);
  return request.headers["x-xshield-action-ref"] ?? null;
}

async function openByClick(session, orderId) {
  const response = session.page.waitForResponse((r) => pathOf(r) === `/orders/${orderId}`);
  await session.page.click(`button[data-order-id="${orderId}"]`);
  const detail = await response;
  await session.page.waitForSelector(`#detail[data-status="${detail.status()}"]`);
  return detail;
}

const browser = await chromium.launch();
try {
  // 1. Alice: login page -> approved page -> list (page action) -> detail
  //    (response-derived action), all through the page's own script.
  const alice = await signIn(browser, "alice");
  assert.equal(alice.app.status(), 200);
  assert.equal(alice.bootstrap.sensor_version, "1.1.0");
  assert.equal(alice.bootstrap.page_handle, alice.pageHandle);
  assert.deepEqual(
    alice.bootstrap.actions.map(({ method, path_template }) => `${method} ${path_template}`),
    ["GET /orders"],
  );
  const pageRef = alice.bootstrap.actions[0].action_ref;
  const refs = Object.fromEntries(alice.list.orders.map((order) => [order.id, order._xshield_action_ref]));
  assert.deepEqual(Object.keys(refs).sort(), ["ord-alice-1", "ord-alice-2"]);
  const detail = await openByClick(alice, "ord-alice-1");
  assert.equal(detail.status(), 200);
  assert.equal((await detail.json()).owner, "alice");
  const listRequest = alice.sent.find((request) => request.path === "/orders");
  const detailRequest = alice.sent.find((request) => request.path === "/orders/ord-alice-1");
  assert.equal(listRequest.headers["x-xshield-action-ref"], pageRef, "sensor attached the page action");
  assert.equal(detailRequest.headers["x-xshield-action-ref"], refs["ord-alice-1"], "sensor attached the harvested ref");
  for (const reference of [pageRef, ...Object.values(refs)]) {
    assert.ok(!alice.html.includes(reference), "references never appear in HTML");
  }
  transcript.flow.push(
    { step: "GET /app", status: alice.app.status(), request_id: requestId(alice.app) },
    { step: "bootstrap", actions: alice.bootstrap.actions.length, request_id: alice.bootstrapRequestId },
    { step: "GET /orders (page action)", status: 200, request_id: alice.listRequestId },
    { step: "click -> GET /orders/ord-alice-1 (harvested ref)", status: detail.status(), request_id: requestId(detail) },
  );
  expectations.stages.push(
    { request_id: requestId(alice.app), stage: "ui_action_issue", outcome: "PASS", reason_code: "UI_ACTION_ISSUED" },
    { request_id: alice.bootstrapRequestId, stage: "sensor_bootstrap", outcome: "PASS", reason_code: "SENSOR_ACTIONS_DELIVERED" },
  );
  expectations.decisions.push(
    { request_id: requestId(alice.app), decision: "ALLOW", reason_code: "PAGE_ROOT_SESSION_ALLOWED" },
    { request_id: alice.listRequestId, decision: "ALLOW", reason_code: "UI_ACTION_ALLOWED" },
    { request_id: requestId(detail), decision: "ALLOW", reason_code: "UI_ACTION_ALLOWED" },
  );

  // XMLHttpRequest is hooked too: the second order opens over XHR.
  const xhr = await call(alice.page, "/orders/ord-alice-2", { via: "xhr" });
  assert.equal(xhr.status, 200, xhr.body);
  transcript.coverage.push({ case: "XHR, hooked", status: xhr.status, request_id: xhr.requestId });
  expectations.decisions.push({ request_id: xhr.requestId, decision: "ALLOW", reason_code: "UI_ACTION_ALLOWED" });

  // 2. Bob in another browser context runs his own flow.
  const bob = await signIn(browser, "bob");
  const bobDetail = await openByClick(bob, "ord-bob-1");
  assert.equal(bobDetail.status(), 200);
  transcript.flow.push({ step: "bob: click -> GET /orders/ord-bob-1", status: 200, request_id: requestId(bobDetail) });

  // 3. Requests that did not follow the flow. Nothing below may reach the origin.
  const before = await metrics();
  expectDenied("alice: another user's order (no reference exists)", await call(alice.page, "/orders/ord-bob-1"), "UI_ACTION_NOT_AVAILABLE");
  assert.equal(lastReference(alice, "/orders/ord-bob-1"), null, "the sensor never invents a reference");
  expectDenied(
    "alice: reference of another object",
    await call(alice.page, "/orders/ord-alice-1", { reference: refs["ord-alice-2"] }),
    "CAPABILITY_MISSING",
  );
  for (const via of ["worker", "iframe", "saved-fetch"]) {
    expectDenied(`alice: unhooked ${via} (stays denied)`, await call(alice.page, "/orders/ord-alice-1", { via }), "UI_ACTION_NOT_AVAILABLE", transcript.coverage);
  }
  expectDenied(
    "bob: reference harvested in alice's browser context",
    await call(bob.page, "/orders/ord-alice-1", { reference: refs["ord-alice-1"] }),
    "UI_ACTION_NOT_AVAILABLE",
  );
  expectDenied(
    "bob: alice's page-issued list reference",
    await call(bob.page, "/orders", { reference: pageRef }),
    "UI_ACTION_NOT_AVAILABLE",
  );
  // A page handle copied into another session yields no reference.
  const copied = await bob.page.evaluate(async (handle) => {
    const response = await fetch(`/__xshield/v1/bootstrap?page=${handle}`);
    return { status: response.status, requestId: response.headers.get("x-xshield-request-id"), body: await response.json() };
  }, alice.pageHandle);
  assert.equal(copied.status, 200);
  assert.deepEqual(copied.body.actions, []);
  transcript.isolation.push({ case: "bob bootstraps alice's page handle", actions: 0, request_id: copied.requestId });
  expectations.stages.push({ request_id: copied.requestId, stage: "sensor_bootstrap", outcome: "SKIPPED", reason_code: "SENSOR_ACTIONS_UNAVAILABLE" });

  // An expired lease: the sensor still holds the reference, the edge does not.
  execFileSync("psql", ["-X", "-q", "-d", database, "-c",
    `UPDATE xshield.ui_actions SET expires_at = issued_at + interval '1 second' WHERE action_ref = '${refs["ord-alice-2"]}'`]);
  expectDenied("alice: expired reference (app-style call)", await call(alice.page, "/orders/ord-alice-2"), "UI_ACTION_NOT_AVAILABLE");
  assert.equal(lastReference(alice, "/orders/ord-alice-2"), refs["ord-alice-2"], "the expired reference was presented");

  // Logout revokes the binding; the sensor drops what it held.
  await alice.page.click("#logout");
  await alice.page.waitForSelector('#status[data-logout="200"]');
  expectDenied("alice after logout: app-style call", await call(alice.page, "/orders/ord-alice-1"), "AUTH_BINDING_MISMATCH");
  assert.equal(lastReference(alice, "/orders/ord-alice-1"), null, "logout cleared the sensor's references");
  expectDenied(
    "alice after logout: replayed reference",
    await call(alice.page, "/orders/ord-alice-1", { reference: refs["ord-alice-1"] }),
    "AUTH_BINDING_MISMATCH",
  );
  const after = await metrics();
  for (const path of ORDER_PATHS) {
    assert.equal(after[`GET ${path}`] ?? 0, before[`GET ${path}`] ?? 0, `origin reached ${path}`);
  }
  transcript.origin_unchanged = ORDER_PATHS;
  writeFileSync(expectationsPath, JSON.stringify(expectations));
  console.log(JSON.stringify(transcript, null, 2));
} finally {
  await browser.close();
}
