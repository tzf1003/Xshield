/**
 * Real-browser OIDC login regression. Driven by scripts/test_oidc_browser.sh, which starts a
 * native Keycloak (the dev realm), the real `xshield-control` binary, a throwaway PostgreSQL
 * database and the console's Vite dev server (VITE_XSHIELD_E2E_MACHINE_LOGIN=0, proxy to the
 * control process). A real Chromium then signs in through the console's own button, the real
 * Keycloak form and the console's same-origin proxy, and the run asserts what only a browser
 * can show: the `__Host-` Secure HttpOnly cookies are accepted, kept and sent by Chromium
 * exactly as the code intends, the proxy passes `Set-Cookie` through on the four paths that
 * need it and strips it elsewhere, and the console's session UI (sign-in, session view,
 * step-up, a CSRF-protected write, sign-out) works end to end.
 *
 * Not proven here (kept honest in docs/20 section 20.20): the dev realm's `acr` is a
 * hardcoded claim, so no multi-factor authentication happens; the origin is plain HTTP on a
 * loopback address (Chromium treats it as a secure context, so this is not HTTPS/TLS
 * behaviour); only Chromium; only the Vite dev proxy, not a production reverse proxy.
 *
 * Needs @playwright/test from web/console (npm ci there). Exit status 0 only if every check
 * passed. Session tokens, CSRF tokens and Keycloak credentials are never printed.
 */
import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";

const require = createRequire(new URL("../web/console/package.json", import.meta.url));
const { chromium, request: playwrightRequest } = require("@playwright/test");

const env = (name) => {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required (run scripts/test_oidc_browser.sh)`);
  return value;
};
const consoleOrigin = env("XSHIELD_BROWSER_CONSOLE_ORIGIN");
const keycloakOrigin = env("XSHIELD_BROWSER_KEYCLOAK_ORIGIN");
const databaseUrl = env("XSHIELD_BROWSER_DATABASE_URL");
const consoleHost = new URL(consoleOrigin).hostname;
const password = "xshield-dev-password"; // dev realm, local only
const SESSION = "__Host-xshield-session";
const STATE = "__Host-xshield-oidc-state";
const developerId = "00000000-0000-7000-8000-000000000001";

const results = [];
function expect(condition, name, detail = "") {
  results.push([Boolean(condition), name]);
  console.log(`${condition ? "ok  " : "FAIL"} ${name}${!condition && detail ? `  [${detail}]` : ""}`);
  return Boolean(condition);
}
const section = (title) => console.log(`\n== ${title}`);

function psql(sql) {
  return execFileSync("psql", ["-X", "-At", "-v", "ON_ERROR_STOP=1", "-d", databaseUrl, "-c", sql], {
    encoding: "utf8",
  }).trim();
}
const digestOf = (token) => createHash("sha256").update(token).digest("hex");
const sessionRow = (token, column) =>
  psql(`SELECT ${column} FROM xshield.management_browser_sessions WHERE session_digest = decode('${digestOf(token)}', 'hex')`);

/** Cookies of the console host only, by name. */
async function jar(context) {
  const cookies = await context.cookies();
  return new Map(cookies.filter((cookie) => cookie.domain.replace(/^\./, "") === consoleHost).map((c) => [c.name, c]));
}

/** A page with a console/pageerror/failed-request recorder. */
async function observedPage(context) {
  const page = await context.newPage();
  const seen = { pageErrors: [], consoleProblems: [], refused: [], controlResponses: [], setCookies: [] };
  page.on("pageerror", (error) => seen.pageErrors.push(error.message));
  page.on("console", (message) => {
    // The unauthenticated session probe answers 401 on purpose; the dev server may also log its own client noise.
    if (["error", "warning"].includes(message.type()) && !message.text().includes("401 (Unauthorized)"))
      seen.consoleProblems.push(message.text());
  });
  page.on("response", async (response) => {
    const url = new URL(response.url());
    if (url.origin !== consoleOrigin || !url.pathname.startsWith("/control/v1/")) return;
    let headers = {};
    try {
      headers = await response.allHeaders();
    } catch {
      // The response may be gone with its page; the status is still recorded.
    }
    seen.controlResponses.push({ path: url.pathname, status: response.status(), setCookie: headers["set-cookie"] ?? null });
    if (response.status() >= 400) {
      const body = await response.json().catch(() => null);
      seen.refused.push(`${response.request().method()} ${url.pathname} -> ${response.status()} ${body?.error_code ?? ""}`.trim());
    }
  });
  return { page, seen };
}

async function signInAtKeycloak(page, { username = "developer", reauth = false } = {}) {
  await page.waitForURL((url) => url.origin === keycloakOrigin, { timeout: 30_000 });
  const field = page.locator("#username");
  // At step-up Keycloak may show the known user read-only or prefilled; fill only when editable.
  if ((await field.count()) > 0 && (await field.isEditable())) await field.fill(username);
  await page.locator("#password").fill(password);
  await page.getByRole("button", { name: "Sign In", exact: true }).click();
  if (reauth) expect(true, "step-up: Keycloak asked for credentials again");
}

function attributes(cookie) {
  return {
    secure: cookie.secure,
    httpOnly: cookie.httpOnly,
    sameSite: cookie.sameSite,
    path: cookie.path,
    hostOnly: !cookie.domain.startsWith("."),
  };
}

const browser = await chromium.launch();
try {
  // ------------------------------------------------------------------ browser rules
  section("what Chromium itself enforces on this origin");
  {
    const context = await browser.newContext();
    const page = await context.newPage();
    await page.goto(`${consoleOrigin}/`);
    const secureContext = await page.evaluate(() => window.isSecureContext);
    expect(secureContext, `${consoleOrigin} is a secure context (loopback HTTP)`);
    await page.evaluate(() => {
      document.cookie = "__Host-probe-plain=1; Path=/";
      document.cookie = "__Host-probe-path=1; Path=/x; Secure";
      document.cookie = "__Host-probe-ok=1; Path=/; Secure";
    });
    const names = (await jar(context)).keys();
    const kept = new Set(names);
    expect(!kept.has("__Host-probe-plain"), "Chromium rejects a __Host- cookie without Secure");
    expect(!kept.has("__Host-probe-path"), "Chromium rejects a __Host- cookie with Path other than /");
    expect(kept.has("__Host-probe-ok"), "Chromium accepts a __Host- Secure Path=/ cookie over loopback HTTP");
    await context.close();
  }

  // ------------------------------------------------------------------ happy path
  section("sign-in through the console, Keycloak and the Vite proxy");
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
  const { page, seen } = await observedPage(context);
  await page.goto(`${consoleOrigin}/cases`);
  const signInButton = page.getByRole("button", { name: "使用企业身份登录" });
  await signInButton.waitFor();
  expect((await jar(context)).size === 0, "no console cookie before sign-in");
  expect(
    seen.controlResponses.some((r) => r.path === "/control/v1/session" && r.status === 401 && r.setCookie === null),
    "the unauthenticated session probe answers 401 without a Set-Cookie",
  );

  await signInButton.click();
  await page.waitForURL((url) => url.origin === keycloakOrigin, { timeout: 30_000 });
  const startResponse = seen.controlResponses.find((r) => r.path === "/control/v1/auth/oidc/start");
  expect(startResponse?.status === 303, "oidc/start answered 303 through the proxy", String(startResponse?.status));
  expect(
    (startResponse?.setCookie ?? "").includes(`${STATE}=`),
    "the proxy passed the state Set-Cookie of oidc/start through",
  );
  let cookies = await jar(context);
  const state = cookies.get(STATE);
  expect(state !== undefined, "Chromium holds the state cookie while at Keycloak");
  if (state) {
    expect(
      JSON.stringify(attributes(state)) ===
        JSON.stringify({ secure: true, httpOnly: true, sameSite: "Lax", path: "/", hostOnly: true }),
      "state cookie is Secure, HttpOnly, SameSite=Lax, Path=/, host-only",
      JSON.stringify(attributes(state)),
    );
    const ttl = state.expires - Date.now() / 1000;
    expect(ttl > 0 && ttl <= 900, "state cookie is short-lived", String(Math.round(ttl)));
  }
  expect(!cookies.has(SESSION), "no session cookie before the callback");

  await signInAtKeycloak(page);
  await page.waitForURL((url) => url.origin === consoleOrigin && url.pathname === "/", { timeout: 30_000 });
  const callback = seen.controlResponses.find((r) => r.path === "/control/v1/auth/oidc/callback");
  expect(callback?.status === 303, "oidc/callback answered 303 through the proxy", String(callback?.status));
  expect(
    (callback?.setCookie ?? "").includes(`${SESSION}=`) && (callback?.setCookie ?? "").includes(`${STATE}=;`),
    "the proxy passed the callback's session Set-Cookie and state-clearing Set-Cookie through",
  );

  section("the console shows the session");
  const userButton = page.getByRole("button", { name: "用户菜单" });
  await userButton.waitFor();
  expect(
    ((await userButton.innerText()) || "").includes(developerId),
    "the user menu shows the Keycloak subject",
  );
  await page.getByRole("link", { name: "权限中心", exact: true }).click().catch(async () => {
    await userButton.click();
    await page.getByText("权限中心", { exact: true }).click();
  });
  await page.getByRole("heading", { name: "当前管理会话", exact: true }).waitFor();
  const main = await page.locator("main").innerText();
  expect(main.includes(developerId), "the session page shows the subject");
  for (const role of ["observer", "investigator", "audit_administrator", "policy_approver", "system_admin"])
    expect(main.includes(role), `the session page lists the mapped role ${role}`);
  expect(main.includes("tenant_oidc") || (await page.content()).includes("tenant_oidc"), "the session page shows the tenant");

  section("cookie jar after the callback");
  cookies = await jar(context);
  expect(!cookies.has(STATE), "the state cookie is gone after the callback");
  const session = cookies.get(SESSION);
  expect(session !== undefined, `Chromium holds ${SESSION}`);
  let sessionToken = "";
  if (session) {
    sessionToken = session.value;
    expect(
      JSON.stringify(attributes(session)) ===
        JSON.stringify({ secure: true, httpOnly: true, sameSite: "Lax", path: "/", hostOnly: true }),
      "session cookie is Secure, HttpOnly, SameSite=Lax, Path=/, host-only (no Domain)",
      JSON.stringify(attributes(session)),
    );
    const lifetime = session.expires - Date.now() / 1000;
    expect(lifetime > 28_800 - 300 && lifetime <= 28_800, "session cookie lifetime is about 8 hours", String(Math.round(lifetime)));
    expect(/^[A-Za-z0-9_-]{32,}$/.test(sessionToken), "session cookie value is an opaque token");
  }
  const visible = await page.evaluate(() => document.cookie);
  expect(!visible.includes("xshield") && !visible.includes(sessionToken || "\u0000"), "document.cookie does not expose the session cookie", visible.length ? "non-empty" : "");
  const storages = await page.evaluate(() => JSON.stringify([{ ...localStorage }, { ...sessionStorage }]));
  expect(!storages.includes(sessionToken || "\u0000"), "the session token is not in localStorage or sessionStorage");
  expect(
    sessionToken !== "" && sessionRow(sessionToken, "subject") === developerId,
    "PostgreSQL holds the session for the Keycloak subject, found by the token's digest",
  );
  expect(
    seen.controlResponses
      .filter((r) => !["/control/v1/auth/oidc/start", "/control/v1/auth/oidc/callback"].includes(r.path))
      .every((r) => r.setCookie === null),
    "no proxied response other than oidc/start and oidc/callback carried a Set-Cookie",
    JSON.stringify(seen.controlResponses.filter((r) => r.setCookie !== null).map((r) => r.path)),
  );

  section("a reload keeps the session (the browser sends the cookie through the proxy)");
  await page.reload();
  await page.getByRole("button", { name: "用户菜单" }).waitFor();
  expect(
    seen.controlResponses.filter((r) => r.path === "/control/v1/session").at(-1)?.status === 200,
    "the session probe answers 200 after a reload",
  );

  section("step-up re-authentication through the UI");
  expect(sessionRow(sessionToken, "last_reauthenticated_at") === "", "before: no step-up recorded for the session");
  await page.getByText("高危操作需要 MFA 再认证").first().waitFor();
  expect(true, "before: the console shows that step-up is needed");
  await page.getByRole("button", { name: "重新验证高危操作" }).click();
  await page.waitForURL((url) => url.origin === keycloakOrigin, { timeout: 30_000 });
  const reauthStart = seen.controlResponses.find((r) => r.path === "/control/v1/auth/oidc/reauth/start");
  expect(
    reauthStart?.status === 200 && (reauthStart.setCookie ?? "").includes(`${STATE}=`),
    "reauth/start answered 200 and the proxy passed its state Set-Cookie through",
    JSON.stringify(reauthStart && { status: reauthStart.status }),
  );
  expect((await jar(context)).has(STATE), "Chromium holds the step-up state cookie while at Keycloak");
  expect((await jar(context)).get(SESSION)?.value === sessionToken, "the session cookie is untouched while at Keycloak");
  await signInAtKeycloak(page, { reauth: true });
  await page.waitForURL((url) => url.origin === consoleOrigin && url.pathname === "/", { timeout: 30_000 });
  await page.getByText("MFA 再认证有效").first().waitFor({ timeout: 15_000 });
  expect(true, "after: the console shows MFA re-authentication as valid");
  expect(sessionRow(sessionToken, "last_reauthenticated_at") !== "", "after: PostgreSQL recorded the step-up on the same session");
  cookies = await jar(context);
  expect(!cookies.has(STATE), "the step-up state cookie is gone after its callback");
  expect(cookies.get(SESSION)?.value === sessionToken, "the session token is unchanged by the step-up");

  section("a write that needs CSRF, through the UI");
  await page.goto(`${consoleOrigin}/cases`);
  await page.getByRole("button", { name: "新建案件", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "新建案件" });
  const purpose = `browser-oidc-regression-${Date.now()}`;
  await dialog.getByLabel("调查目的").fill(purpose);
  const created = page.waitForResponse((r) => new URL(r.url()).pathname === "/control/v1/cases" && r.request().method() === "POST");
  await dialog.getByRole("button", { name: "创建案件", exact: true }).click();
  const createResponse = await created;
  const sentCsrf = createResponse.request().headers()["x-xshield-csrf"] ?? "";
  expect(/^[0-9a-f]{64}$/.test(sentCsrf), "the console sent a 64-hex X-Xshield-CSRF header");
  expect(createResponse.status() >= 200 && createResponse.status() < 300, "the write succeeded with the browser's cookie and the CSRF header", String(createResponse.status()));
  await page.getByText("案件已创建").first().waitFor({ timeout: 15_000 });
  expect(true, "the console confirmed the case");
  // The control plane serves case reads one at a time (429 CONTROL_CASE_EVIDENCE_BUSY for an
  // overlapping one) and the dev server's StrictMode sends one aborted duplicate of each read
  // that the server still finishes, so the first read of the case page may be refused BUSY.
  // The page offers a retry; the case must show once the operator uses it.
  const heading = page.getByRole("heading", { name: purpose });
  const deadline = Date.now() + 30_000;
  while (!(await heading.isVisible()) && Date.now() < deadline) {
    const retry = page.getByRole("alert").getByRole("button", { name: "重试" }).first();
    // The alert re-renders while a read settles; a click that misses is simply tried again.
    if (await retry.isVisible()) await retry.click({ timeout: 2_000 }).catch(() => {});
    await page.waitForTimeout(400);
  }
  await heading.waitFor({ timeout: 5_000 });
  expect(true, "the new case opens in the console (after a retry if the first read was BUSY)");
  // The same cookie without the CSRF header is refused (the browser does send the cookie).
  const noCsrf = await page.evaluate(async () => {
    const response = await fetch("/control/v1/cases", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "Idempotency-Key": crypto.randomUUID() },
      body: JSON.stringify({ purpose: "csrf probe, must be refused" }),
    });
    return { status: response.status, body: await response.json().catch(() => null) };
  });
  expect(
    noCsrf.status === 403 && noCsrf.body?.error_code === "CONTROL_CSRF_REQUIRED",
    "the same write without the CSRF header is refused 403 CONTROL_CSRF_REQUIRED",
    JSON.stringify({ status: noCsrf.status, code: noCsrf.body?.error_code }),
  );
  expect(sessionRow(sessionToken, "revoked_at") === "", "the refused write did not end the session");

  section("sign-out through the UI");
  await page.getByRole("button", { name: "用户菜单" }).click();
  await page.getByText("安全退出", { exact: true }).click();
  await page.getByRole("button", { name: "使用企业身份登录" }).waitFor({ timeout: 15_000 });
  await page.getByText("已安全退出管理会话。").waitFor();
  expect(true, "the console is back at the sign-in screen with the sign-out notice");
  const logout = seen.controlResponses.find((r) => r.path === "/control/v1/session/logout");
  expect(logout?.status >= 200 && logout.status < 300, "session/logout answered 2xx through the proxy", String(logout?.status));
  expect(
    (logout?.setCookie ?? "").includes(`${SESSION}=`) && /max-age=0/i.test(logout?.setCookie ?? ""),
    "the proxy passed the logout's cookie-clearing Set-Cookie through",
  );
  expect(!(await jar(context)).has(SESSION), "Chromium dropped the session cookie");
  expect(sessionRow(sessionToken, "revoked_at") !== "", "PostgreSQL shows the session revoked");
  const probe = await page.evaluate(async () => (await fetch("/control/v1/session", { credentials: "same-origin" })).status);
  expect(probe === 401, "the browser's own session probe answers 401 after sign-out", String(probe));
  const replay = await playwrightRequest.newContext();
  const replayed = await replay.get(`${consoleOrigin}/control/v1/session`, { headers: { cookie: `${SESSION}=${sessionToken}` } });
  expect(replayed.status() === 401, "the signed-out session token is refused when replayed", String(replayed.status()));
  await replay.dispose();
  expect(seen.pageErrors.length === 0, "no uncaught page error during the whole flow", seen.pageErrors.join(" | "));
  // Browser console noise is only the refused responses the run provokes or tolerates on purpose:
  // the unauthenticated session probe (401), the CSRF probe (403) and *_BUSY 429 (see above).
  const tolerated = (line) =>
    /^GET \/control\/v1\/session -> 401 /.test(line) ||
    /^POST \/control\/v1\/cases -> 403 CONTROL_CSRF_REQUIRED$/.test(line) ||
    // The body of a read the page aborted meanwhile (the StrictMode duplicate) is gone: no code.
    /^GET \/control\/v1\/.* -> 429( CONTROL_[A-Z_]*BUSY)?$/.test(line);
  const surprising = seen.refused.filter((line) => !tolerated(line));
  expect(surprising.length === 0, "every refused control response was provoked or tolerated on purpose", surprising.join(" | "));
  const busy = seen.refused.filter((line) => / -> 429 /.test(line));
  if (busy.length > 0) console.log(`note: ${busy.length} read(s) were refused BUSY by the single-permit control reads: ${busy.join("; ")}`);
  const unexplained = seen.consoleProblems.filter((text) => !/status of (401|403|429) /.test(text));
  expect(unexplained.length === 0, "no console error or warning other than those refused responses", unexplained.join(" | "));
  await context.close();

  // ------------------------------------------------------------------ negative cases
  for (const variant of ["deleted", "tampered"]) {
    section(`negative: the state cookie is ${variant} before the callback`);
    const hostile = await browser.newContext();
    const { page: victim, seen: hostileSeen } = await observedPage(hostile);
    const sessionsBefore = Number(psql("SELECT count(*) FROM xshield.management_browser_sessions"));
    await victim.goto(`${consoleOrigin}/`);
    await victim.getByRole("button", { name: "使用企业身份登录" }).click();
    await victim.waitForURL((url) => url.origin === keycloakOrigin, { timeout: 30_000 });
    expect((await jar(hostile)).has(STATE), `${variant}: the state cookie was set at the start`);
    if (variant === "deleted") {
      await hostile.clearCookies({ name: STATE });
    } else {
      const original = (await jar(hostile)).get(STATE);
      await hostile.clearCookies({ name: STATE });
      await hostile.addCookies([
        {
          name: STATE,
          value: `${original.value.slice(0, -1)}${original.value.endsWith("A") ? "B" : "A"}`,
          domain: consoleHost,
          path: "/",
          secure: true,
          httpOnly: true,
          sameSite: "Lax",
        },
      ]);
    }
    expect(
      variant === "deleted" ? !(await jar(hostile)).has(STATE) : (await jar(hostile)).has(STATE),
      `${variant}: the cookie jar was changed as intended`,
    );
    await signInAtKeycloak(victim);
    await victim.waitForURL((url) => url.origin === consoleOrigin, { timeout: 30_000 });
    // The control plane's refusal is a JSON document at the callback URL; the proxy passes it through.
    const text = await victim.locator("body").innerText();
    const refusal = hostileSeen.controlResponses.find((r) => r.path === "/control/v1/auth/oidc/callback");
    expect(refusal?.status === 401, `${variant}: the callback is refused 401`, String(refusal?.status));
    expect(text.includes("CONTROL_OIDC_STATE_INVALID"), `${variant}: the page shows the documented refusal CONTROL_OIDC_STATE_INVALID`, text.slice(0, 120));
    expect(!(await jar(hostile)).has(SESSION), `${variant}: no session cookie was set`);
    expect(
      Number(psql("SELECT count(*) FROM xshield.management_browser_sessions")) === sessionsBefore,
      `${variant}: no session row was created`,
    );
    await victim.goto(`${consoleOrigin}/`);
    await victim.getByRole("button", { name: "使用企业身份登录" }).waitFor();
    expect(true, `${variant}: opening the console afterwards still shows the sign-in screen, no session`);
    await hostile.close();
  }
} finally {
  await browser.close();
}

const failed = results.filter(([ok]) => !ok);
console.log(`\n${results.length - failed.length} passed, ${failed.length} failed`);
if (failed.length) {
  for (const [, name] of failed) console.log(`FAILED: ${name}`);
  process.exit(1);
}
