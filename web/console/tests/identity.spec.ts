import { expect, type Page, test } from "@playwright/test";
import { type Call, mockControl, paint, requestSettled } from "./control-mock";
import { errorFixture, REQUEST_ID, SEARCH_PLAN, TOKEN } from "./fixtures";
import {
  expectPrefilled,
  pasteId,
  pickRange,
  signInQuietly,
  submitSearch,
} from "./investigation-helpers";
import {
  BINDING_ID,
  bindingFixture,
  GRANT_ID,
  grantFixture,
  OTHER_BINDING_ID,
  OTHER_GRANT_ID,
} from "./ledger-fixtures";
import { openView } from "./navigation";
import { signIn } from "./shell-helpers";

const LEDGER = { grant: "资格", binding: "身份绑定" } as const;
const grantRecord = (page: Page) => page.getByRole("region", { name: "资格记录", exact: true });
const bindingRecord = (page: Page) =>
  page.getByRole("region", { name: "身份绑定记录", exact: true });
const row = (region: ReturnType<typeof grantRecord>, label: string) =>
  region.locator("tr").filter({ hasText: label });
const history = (page: Page) => page.getByRole("button", { name: "准备历史检索", exact: true });
const lookup = (page: Page, kind: "grant" | "binding") =>
  page.getByLabel(kind === "grant" ? "资格 ID" : "身份绑定 ID", { exact: true });
const paths = (calls: Call[]) => calls.map((call) => call.path);

/** Opens a ledger page from the sidebar and looks one ID up in its box. */
async function look(
  page: Page,
  kind: "grant" | "binding",
  id = kind === "grant" ? GRANT_ID : BINDING_ID,
) {
  await openView(page, "grant");
  await page.getByRole("tab", { name: LEDGER[kind] }).click();
  await expect(page.getByRole("tab", { name: LEDGER[kind], selected: true })).toBeVisible();
  await lookup(page, kind).fill(id);
  await page.getByRole("button", { name: "查询", exact: true }).click();
}

test("one page, two tabs: both addresses keep resolving and the tab follows the address", async ({
  page,
}) => {
  const calls = await mockControl(page);
  await signIn(page, `/investigation/grants/${GRANT_ID}`);
  await expect(grantRecord(page)).toContainText("orders.read");
  await expect(page.getByRole("tab", { name: "资格", selected: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "身份与资格", exact: true })).toBeVisible();
  expect(paths(calls)).toEqual([`/control/v1/grants/${GRANT_ID}`]);
  // The binding tab is another address; moving there keeps the session and reads nothing yet.
  await page.getByRole("tab", { name: "身份绑定" }).click();
  await expect(page).toHaveURL(/\/investigation\/bindings$/);
  await expect(page.getByRole("tab", { name: "身份绑定", selected: true })).toBeVisible();
  await expect(grantRecord(page)).toHaveCount(0);
  await paint(page);
  expect(calls).toHaveLength(1);
  await lookup(page, "binding").fill(BINDING_ID);
  await page.getByRole("button", { name: "查询", exact: true }).click();
  await expect(page).toHaveURL(new RegExp(`/investigation/bindings/${BINDING_ID}$`));
  await expect(bindingRecord(page)).toContainText(BINDING_ID);
});

test("⌘K opens a grant or a binding on its own tab", async ({ page }) => {
  const calls = await mockControl(page);
  await signInQuietly(page);
  await pasteId(page, GRANT_ID);
  await expect(page).toHaveURL(new RegExp(`/investigation/grants/${GRANT_ID}$`));
  await expect(page.getByRole("tab", { name: "资格", selected: true })).toBeVisible();
  await expect(grantRecord(page)).toContainText("orders.read");
  await pasteId(page, BINDING_ID);
  await expect(page).toHaveURL(new RegExp(`/investigation/bindings/${BINDING_ID}$`));
  await expect(page.getByRole("tab", { name: "身份绑定", selected: true })).toBeVisible();
  await expect(bindingRecord(page)).toContainText(BINDING_ID);
  expect(paths(calls)).toEqual([
    `/control/v1/grants/${GRANT_ID}`,
    `/control/v1/auth-bindings/${BINDING_ID}`,
  ]);
});

test("a pasted ID of the other kind opens the other tab; bad input sends nothing", async ({
  page,
}) => {
  const calls = await mockControl(page);
  await signInQuietly(page);
  await openView(page, "grant");
  for (const bad of ["invalid-grant", GRANT_ID.toUpperCase(), `${GRANT_ID}x`, "req_x"]) {
    await lookup(page, "grant").fill(bad);
    await page.getByRole("button", { name: "查询", exact: true }).click();
    await expect(page.getByText(/请输入规范的资格 ID/)).toBeVisible();
  }
  expect(calls).toHaveLength(0);
  // Quotes and spaces around a pasted ID are not part of it, and the kind is recognised.
  await lookup(page, "grant").fill(`  "${BINDING_ID}" `);
  await page.getByRole("button", { name: "查询", exact: true }).click();
  await expect(page).toHaveURL(new RegExp(`/investigation/bindings/${BINDING_ID}$`));
  await expect(page.getByRole("tab", { name: "身份绑定", selected: true })).toBeVisible();
  await expect(bindingRecord(page)).toContainText(BINDING_ID);
  expect(paths(calls)).toEqual([`/control/v1/auth-bindings/${BINDING_ID}`]);
});

test("ledger grant and binding snapshots show independent facts and navigate known references", async ({
  page,
}) => {
  const calls = await mockControl(page);
  await signInQuietly(page);
  await look(page, "grant");
  await expect(grantRecord(page)).toContainText("orders.read");
  await expect(row(grantRecord(page), "持久状态")).toContainText("有效");
  await expect(row(grantRecord(page), "持久状态")).toContainText("active");
  await expect(row(grantRecord(page), "时间到期")).toContainText("未到期");
  await expect(row(grantRecord(page), "发行身份代际")).toContainText("4");
  await expect(page.getByText("2026-09-20T08:10:30.123456Z", { exact: true })).toBeVisible();
  await expect(bindingRecord(page)).toContainText("一致");
  await expect(page.getByText(/实际请求仍须校验完整身份/)).toBeVisible();
  // A ledger snapshot is not an admission decision: no index status, no verdict words.
  await expect(page.getByText(/查看水位|待发布段|已允许/)).toHaveCount(0);
  // The binding of the same snapshot opens its own tab; the source request opens the request.
  await page.getByRole("link", { name: BINDING_ID, exact: true }).click();
  await expect(page.getByRole("heading", { name: "身份绑定账本快照", exact: true })).toBeVisible();
  await expect(lookup(page, "binding")).toHaveValue(BINDING_ID);
  await expect(row(bindingRecord(page), "凭证代际")).toContainText("2");
  await expect(page.getByText("2026-09-20T08:01:00.000000Z", { exact: true })).toBeVisible();
  await look(page, "grant");
  await page.getByRole("link", { name: REQUEST_ID, exact: true }).click();
  await expect(page.getByRole("heading", { name: "请求调查", exact: true })).toBeVisible();
  await expect(page.getByText("AUTH_BINDING_VALID", { exact: true })).toBeVisible();
  expect(paths(calls)).toEqual([
    `/control/v1/grants/${GRANT_ID}`,
    `/control/v1/auth-bindings/${BINDING_ID}`,
    `/control/v1/grants/${GRANT_ID}`,
    `/control/v1/requests/${REQUEST_ID}`,
    `/control/v1/requests/${REQUEST_ID}/events`,
  ]);
  expect(
    calls.every((call) => call.method === "GET" && call.authorized && call.cookie === null),
  ).toBe(true);
});

test.describe("history", () => {
  // The picker works in local time; a UTC browser clock makes the typed text the plan's text.
  test.use({ timezoneId: "UTC" });

  test("history presets only the reference and needs an explicit UTC window and Investigator", async ({
    page,
  }) => {
    const calls = await mockControl(page, (url) =>
      url.pathname === "/control/v1/search"
        ? { status: 403, body: errorFixture("CONTROL_SCOPE_DENIED") }
        : undefined,
    );
    await signInQuietly(page);
    for (const kind of ["grant", "binding"] as const) {
      await look(page, kind);
      await history(page).click();
      await expectPrefilled(
        page,
        kind === "grant" ? "资格 ID" : "身份绑定 ID",
        kind === "grant" ? GRANT_ID : BINDING_ID,
      );
      const count = calls.length;
      // No range yet: the search page asks for one and sends nothing.
      await submitSearch(page);
      await expect(page.getByRole("alert")).toContainText("请先选择时间范围");
      expect(calls).toHaveLength(count);
      await pickRange(page, "2026-09-20T00:00", "2026-09-21T00:00");
      await submitSearch(page);
      await expect(page.getByRole("alert")).toContainText("CONTROL_SCOPE_DENIED");
      expect(calls.at(-1)?.body).toEqual({
        ...SEARCH_PLAN,
        limit: 25,
        filters: [
          {
            kind: kind === "grant" ? "grant_id" : "auth_binding_id",
            value: kind === "grant" ? GRANT_ID : BINDING_ID,
          },
        ],
      });
    }
  });
});

test("stored lifecycle, database expiry and epoch mismatch are separate facts", async ({
  page,
}) => {
  let bindingState = "anonymous";
  await mockControl(page, (url) => {
    if (url.pathname.includes("/grants/")) {
      const value = grantFixture(url.pathname.split("/").at(-1));
      const grant = value.grant as NonNullable<typeof value.grant>;
      grant.stored_status = value.source_grant_id === OTHER_GRANT_ID ? "revoked" : "active";
      grant.time_expired = value.source_grant_id === GRANT_ID;
      if (grant.time_expired) grant.expires_at = value.as_of as string;
      grant.binding.current_auth_epoch = 5;
      grant.binding.epoch_matches_grant = false;
      grant.binding.stored_status = "revoked";
      return { body: value };
    }
    if (url.pathname.includes("/auth-bindings/")) {
      const value = bindingFixture(url.pathname.split("/").at(-1));
      const binding = value.binding as NonNullable<typeof value.binding>;
      Object.assign(binding, {
        stored_status: bindingState,
        current_auth_epoch: bindingState === "anonymous" ? 0 : 4,
        credential_generation: bindingState === "anonymous" ? 0 : 2,
      });
      if (bindingState === "expired")
        Object.assign(binding, { expires_at: value.as_of, time_expired: true });
      return { body: value };
    }
    return undefined;
  });
  await signInQuietly(page);
  await look(page, "grant");
  await expect(row(grantRecord(page), "持久状态")).toContainText("active");
  await expect(row(grantRecord(page), "时间到期")).toContainText("已到期");
  await expect(row(bindingRecord(page), "当前身份代际")).toContainText("5");
  await expect(row(bindingRecord(page), "发行代际对比")).toContainText("不一致");
  await expect(row(bindingRecord(page), "持久状态")).toContainText("已撤销");
  await expect(row(bindingRecord(page), "时间到期")).toContainText("未到期");
  await look(page, "grant", OTHER_GRANT_ID);
  await expect(row(grantRecord(page), "持久状态")).toContainText("revoked");
  await expect(row(grantRecord(page), "时间到期")).toContainText("未到期");
  for (const state of ["anonymous", "expired", "revoked"]) {
    bindingState = state;
    await look(page, "binding", OTHER_BINDING_ID);
    await expect(row(bindingRecord(page), "持久状态")).toContainText(state);
    await expect(row(bindingRecord(page), "时间到期")).toContainText(
      state === "expired" ? "已到期" : "未到期",
    );
    await expect(row(bindingRecord(page), "当前身份代际")).toContainText(
      state === "anonymous" ? "0" : "4",
    );
  }
});

test("missing records keep an explicit observation state and a history entry", async ({ page }) => {
  await mockControl(page, (url) =>
    url.pathname.includes("/grants/")
      ? { body: { ...grantFixture(), found: false, grant: null, as_of: null } }
      : { body: { ...bindingFixture(), found: false, binding: null, as_of: null } },
  );
  await signInQuietly(page);
  for (const kind of ["grant", "binding"] as const) {
    await look(page, kind);
    await expect(page.getByRole("heading", { name: "当前账本未找到", exact: true })).toBeVisible();
    await expect(page.getByText("未返回观察时间", { exact: true })).toBeVisible();
    await expect(page.getByText(/历史事件可通过独立检索继续核对/)).toBeVisible();
    await expect(history(page)).toBeVisible();
    await expect(page.getByText(/待发布段|查看水位/)).toHaveCount(0);
  }
});

test("403 and database 503 stay safe and wait for an explicit retry", async ({ page }) => {
  await page.clock.install();
  let status = 403;
  const calls = await mockControl(page, (url) => ({
    status,
    body: errorFixture(
      status === 403
        ? "CONTROL_SCOPE_DENIED"
        : url.pathname.includes("/grants/")
          ? "CONTROL_GRANT_STORE_UNAVAILABLE"
          : "CONTROL_BINDING_STORE_UNAVAILABLE",
    ),
  }));
  await signInQuietly(page);
  for (const kind of ["grant", "binding"] as const) {
    for (const code of [403, 503]) {
      status = code;
      await look(page, kind);
      await expect(page.getByRole("alert")).toContainText(
        code === 403
          ? "CONTROL_SCOPE_DENIED"
          : kind === "grant"
            ? "CONTROL_GRANT_STORE_UNAVAILABLE"
            : "CONTROL_BINDING_STORE_UNAVAILABLE",
      );
      await expect(page.getByText("Synthetic server detail must not be rendered")).toHaveCount(0);
    }
  }
  await page.clock.fastForward(60_000);
  expect(calls).toHaveLength(4);
  // The retry is a button, and it reads again.
  status = 403;
  await page.getByRole("button", { name: "重新读取", exact: true }).click();
  await expect.poll(() => calls.length).toBe(5);
});

test("invalidated sessions clear the snapshot and every query", async ({ page }) => {
  // Ten complete sign-in cycles (two kinds, five ways to end the session) in one test: the
  // default 30 s is more than a two-core CI runner needs for the page loads alone.
  test.setTimeout(120_000);
  await page.clock.install();
  let expired = false;
  await mockControl(page, () =>
    expired ? { status: 401, body: errorFixture("CONTROL_AUTH_REQUIRED") } : undefined,
  );
  for (const kind of ["grant", "binding"] as const) {
    for (const action of ["401", "idle", "reload", "pagehide", "disconnect"] as const) {
      expired = false;
      await signInQuietly(page);
      await look(page, kind);
      await expect(history(page)).toBeVisible();
      if (action === "401") {
        expired = true;
        await page.getByRole("button", { name: "重新读取", exact: true }).click();
      } else if (action === "idle") await page.clock.fastForward(15 * 60_000 + 1);
      else if (action === "reload") await page.reload();
      else if (action === "pagehide")
        await page.evaluate(() => window.dispatchEvent(new Event("pagehide")));
      else await page.getByRole("button", { name: "断开连接", exact: true }).click();
      await expect(page.getByLabel("管理凭证", { exact: true })).toHaveValue("");
      await expect(history(page)).toHaveCount(0);
      await expect(page.getByText("2026-09-20T08:10:30.123456Z", { exact: true })).toHaveCount(0);
      expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([
        0, 0,
      ]);
    }
  }
});

test("switching the ID discards a late reply, and a snapshot from another scope disconnects", async ({
  page,
}) => {
  let arrive = () => {};
  let release = () => {};
  let delay = Promise.resolve();
  let drift = false;
  await mockControl(page, async (url) => {
    if (url.pathname.endsWith(GRANT_ID) || url.pathname.endsWith(BINDING_ID)) {
      arrive();
      await delay;
    }
    if (url.pathname.includes("/grants/"))
      return {
        body: {
          ...grantFixture(url.pathname.split("/").at(-1)),
          tenant_id: drift ? "tenant_other" : "tenant_demo",
        },
      };
    if (url.pathname.includes("/auth-bindings/"))
      return {
        body: {
          ...bindingFixture(url.pathname.split("/").at(-1)),
          site_id: drift ? "site_other" : "site_demo",
        },
      };
    return undefined;
  });
  await signInQuietly(page);
  for (const kind of ["grant", "binding"] as const) {
    delay = new Promise<void>((resolve) => {
      release = resolve;
    });
    const arrived = new Promise<void>((resolve) => {
      arrive = resolve;
    });
    const settled = requestSettled(
      page,
      kind === "grant"
        ? `/control/v1/grants/${GRANT_ID}`
        : `/control/v1/auth-bindings/${BINDING_ID}`,
    );
    await look(page, kind);
    await arrived;
    // Asking for another ID while the first is in flight: the first reply must never show.
    await lookup(page, kind).fill(kind === "grant" ? OTHER_GRANT_ID : OTHER_BINDING_ID);
    await page.getByRole("button", { name: "查询", exact: true }).click();
    release();
    await settled;
    await paint(page);
    await expect(history(page)).toBeVisible();
    const other = kind === "grant" ? OTHER_GRANT_ID : OTHER_BINDING_ID;
    await expect(page.getByText(other, { exact: true }).first()).toBeVisible();
    await expect(
      page.getByText(kind === "grant" ? GRANT_ID : BINDING_ID, { exact: true }),
    ).toHaveCount(0);
    drift = true;
    await page.getByRole("button", { name: "重新读取", exact: true }).click();
    await expect(page.getByRole("status").filter({ hasText: "响应范围校验失败" })).toBeVisible();
    await expect(page.getByLabel("管理凭证", { exact: true })).toHaveValue("");
    drift = false;
    await page.getByLabel("管理凭证", { exact: true }).fill(TOKEN);
    await page.getByRole("button", { name: "连接", exact: true }).click();
  }
});

test("malicious or undisclosed fields are rejected or dropped, and the layout fits", async ({
  page,
}) => {
  let malicious = true;
  const injected = '<img src=x onerror="window.xshieldInjected=true">';
  const runtimeErrors: string[] = [];
  const consoleErrors: string[] = [];
  page.on("pageerror", (error) => runtimeErrors.push(error.message));
  page.on("console", (message) => {
    if (["warning", "error"].includes(message.type())) consoleErrors.push(message.text());
  });
  await mockControl(page, (url) => {
    if (url.pathname.includes("/grants/")) {
      const value = grantFixture();
      if (malicious) (value.grant as NonNullable<typeof value.grant>).operation_id = injected;
      return {
        body: {
          ...value,
          subject: "PRIVATE_SUBJECT_SENTINEL",
          resource_fingerprint: "PRIVATE_FINGERPRINT_SENTINEL",
        },
      };
    }
    const value = bindingFixture();
    return {
      body: {
        ...value,
        binding: {
          ...value.binding,
          ...(malicious ? { stored_status: injected } : {}),
          waf_sid: "PRIVATE_SID_SENTINEL",
          credential_fingerprint: "PRIVATE_FINGERPRINT_SENTINEL",
        },
      },
    };
  });
  await signInQuietly(page);
  for (const kind of ["grant", "binding"] as const) {
    malicious = true;
    await look(page, kind);
    await expect(page.getByRole("alert")).toContainText("INVALID_RESPONSE");
    await expect(page.getByText(injected, { exact: true })).toHaveCount(0);
    malicious = false;
    await page.getByRole("button", { name: "重新读取", exact: true }).click();
    await expect(history(page)).toBeVisible();
    await expect(page).toHaveURL(
      new RegExp(`/investigation/${kind === "grant" ? "grants" : "bindings"}/`),
    );
    await expect(page).toHaveTitle(/Xshield/);
    await expect(page.locator("vite-error-overlay")).toHaveCount(0);
    await expect(page.locator("main img")).toHaveCount(0);
    await expect(page.getByText(/PRIVATE_.*_SENTINEL/)).toHaveCount(0);
    expect(await page.evaluate(() => Reflect.get(window, "xshieldInjected"))).toBeUndefined();
    for (const width of [1536, 390]) {
      await page.setViewportSize({ width, height: 1024 });
      await expect
        .poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth))
        .toBe(true);
    }
    await page.setViewportSize({ width: 1280, height: 800 });
  }
  expect(runtimeErrors).toEqual([]);
  expect(consoleErrors).toEqual([]);
});

test.describe("mobile", () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test("both tabs stay inside the phone width", async ({ page }) => {
    await mockControl(page);
    await signInQuietly(page);
    await look(page, "grant");
    await expect(grantRecord(page)).toBeVisible();
    expect(
      await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
    ).toBe(true);
    await page.getByRole("link", { name: BINDING_ID, exact: true }).click();
    await expect(bindingRecord(page)).toBeVisible();
    expect(
      await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
    ).toBe(true);
  });
});
