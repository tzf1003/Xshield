import { openView } from "./navigation";
import { expectPrefilled } from "./investigation-helpers";
import { expect, test, type Page, type Route } from "@playwright/test";
import { resolve } from "node:path";
import { ARTIFACT_ID, TOKEN, errorFixture } from "./fixtures";
import {
  HOLD_ID,
  HOLD_CASE_ID,
  HOLD_KEY,
  HOLD_UNTIL,
  holdRecordFixture,
  holdMutationFixture,
  holdCollectionFixture,
} from "./hold-fixtures";

type Call = { path: string; method: string; key: string | null; body: unknown };
async function intercept(page: Page, handler: (route: Route, call: Call) => Promise<void>) {
  const calls: Call[] = [];
  await page.route("**/control/v1/**", async (route) => {
    const request = route.request();
    expect(await request.headerValue("authorization")).toBe(`Bearer ${TOKEN}`);
    expect(await request.headerValue("cookie")).toBeNull();
    const url = new URL(request.url());
    const call = {
      path: url.pathname + url.search,
      method: request.method(),
      key: await request.headerValue("idempotency-key"),
      body: request.postDataJSON(),
    };
    calls.push(call);
    await handler(route, call);
  });
  return calls;
}
async function connect(page: Page) {
  await page.goto("/access/session");
  await page.getByLabel("管理凭证", { exact: true }).fill(TOKEN);
  await page.getByRole("button", { name: "连接", exact: true }).click();
  await openView(page, "hold");
}
async function fillCreate(page: Page, until = HOLD_UNTIL) {
  await page.getByLabel("保留案件 ID", { exact: true }).fill(HOLD_CASE_ID);
  await page.getByLabel("保留证据 ID", { exact: true }).fill(ARTIFACT_ID);
  await page.getByLabel("保留至（UTC）", { exact: true }).fill(until);
  await page.getByLabel("保留理由", { exact: true }).fill(holdRecordFixture().reason);
  await page.getByLabel("保留幂等键", { exact: true }).fill(HOLD_KEY);
}
async function create(page: Page) {
  await fillCreate(page);
  await page.getByRole("button", { name: "创建保留锁", exact: true }).click();
}
async function history(page: Page) {
  await page.getByLabel("保留历史案件 ID", { exact: true }).fill(HOLD_CASE_ID);
  await page.getByRole("button", { name: "读取保留历史 / 刷新", exact: true }).click();
}

test("prepares scoped evidence hold history without submitting a search", async ({ page }) => {
  const calls = await intercept(page, (route) => route.fulfill({ json: holdCollectionFixture() }));
  await connect(page);
  await history(page);
  await page.getByRole("button", { name: `准备历史检索 ${HOLD_ID}`, exact: true }).click();
  await expectPrefilled(page, "保留锁 ID", HOLD_ID);
  expect(calls.map((call) => call.path)).toEqual([`/control/v1/cases/${HOLD_CASE_ID}/holds`]);
});

test("explicit hold creation, history selection, release and refresh", async ({ page }) => {
  let released = false;
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });
  const calls = await intercept(page, async (route, call) => {
    if (call.path.endsWith("/release")) {
      released = true;
      return route.fulfill({ json: holdMutationFixture(true) });
    }
    if (call.method === "POST") return route.fulfill({ status: 201, json: holdMutationFixture() });
    return route.fulfill({
      json: { ...holdCollectionFixture(), items: [holdRecordFixture(released)] },
    });
  });
  await connect(page);
  await expect(page).toHaveTitle(/Xshield/);
  await expect(page.getByRole("heading", { name: "证据保留", exact: true })).toBeVisible();
  expect(calls).toHaveLength(0);
  await create(page);
  await expect(page.getByRole("heading", { name: "创建保留锁已确认" })).toBeVisible();
  expect(calls[0]).toEqual({
    path: `/control/v1/cases/${HOLD_CASE_ID}/holds`,
    method: "POST",
    key: HOLD_KEY,
    body: { artifact_id: ARTIFACT_ID, reason: holdRecordFixture().reason, hold_until: HOLD_UNTIL },
  });
  expect(calls).toHaveLength(1);
  await page.getByRole("button", { name: "准备新的保留操作" }).click();
  await history(page);
  await expect(page.getByText("保留生效中", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: `选择释放 ${HOLD_ID}`, exact: true }).click();
  await expect(page.getByLabel("释放保留锁 ID", { exact: true })).toHaveValue(HOLD_ID);
  await page.getByLabel("释放理由", { exact: true }).fill(holdRecordFixture(true).released_reason!);
  await page.getByLabel("保留幂等键", { exact: true }).fill(`${HOLD_KEY}-release`);
  await page.getByRole("button", { name: "释放保留锁", exact: true }).click();
  await expect(page.getByRole("heading", { name: "释放保留锁已确认" })).toBeVisible();
  expect(calls).toHaveLength(3);
  expect(calls[2]).toEqual({
    path: `/control/v1/evidence-holds/${HOLD_ID}/release`,
    method: "POST",
    key: `${HOLD_KEY}-release`,
    body: { reason: holdRecordFixture(true).released_reason },
  });
  await page.getByRole("button", { name: "读取保留历史 / 刷新", exact: true }).click();
  await expect(page.getByText("released · 已释放", { exact: true })).toBeVisible();
  await expect(
    page.getByRole("button", { name: `选择释放 ${HOLD_ID}`, exact: true }),
  ).toBeDisabled();
  await expect(page.locator("vite-error-overlay")).toHaveCount(0);
  expect(errors).toEqual([]);
  const output = process.env.XSHIELD_CONSOLE_SCREENSHOT_DIR;
  if (output) await page.screenshot({ path: resolve(output, "holds-desktop.png"), fullPage: true });
});

test("unknown write preserves its original key through navigation and later rejection", async ({
  page,
}) => {
  let attempts = 0;
  const calls = await intercept(page, (route) => {
    attempts += 1;
    if (attempts === 1) return route.abort("failed");
    if (attempts === 2)
      return route.fulfill({ status: 403, json: errorFixture("CONTROL_SCOPE_DENIED") });
    return route.fulfill({ json: holdMutationFixture(false, true) });
  });
  await connect(page);
  await create(page);
  await expect(page.getByRole("heading", { name: "保留操作结果未知" })).toBeVisible();
  expect(
    await page.evaluate(
      () => !window.dispatchEvent(new Event("beforeunload", { cancelable: true })),
    ),
  ).toBe(true);
  await expect(page.getByRole("button", { name: "准备新的保留操作" })).toBeDisabled();
  await openView(page, "audit-health");
  await openView(page, "hold");
  await page.getByRole("button", { name: "原样重试保留操作" }).click();
  await expect(page.getByRole("heading", { name: "保留操作结果未知" })).toBeVisible();
  await expect(page.getByText("CONTROL_SCOPE_DENIED", { exact: false }).first()).toBeVisible();
  await page.getByRole("button", { name: "原样重试保留操作" }).click();
  await expect(page.getByRole("heading", { name: "创建保留锁已确认" })).toBeVisible();
  expect(calls).toEqual([calls[0], calls[0], calls[0]]);
  expect(
    await page.evaluate(() =>
      window.dispatchEvent(new Event("beforeunload", { cancelable: true })),
    ),
  ).toBe(true);
});

for (const action of ["create", "release"] as const) {
  test(`manual recovery of ${action} retains uncertainty after conflict`, async ({ page }) => {
    await intercept(page, (route) =>
      route.fulfill({ status: 409, json: errorFixture("CONTROL_EVIDENCE_HOLD_CONFLICT") }),
    );
    await connect(page);
    await page.getByLabel("保留操作类型", { exact: true }).selectOption(action);
    await page.getByLabel("恢复原保留操作", { exact: true }).check();
    if (action === "create") await create(page);
    else {
      await page.getByLabel("释放保留锁 ID", { exact: true }).fill(HOLD_ID);
      await page.getByLabel("释放理由", { exact: true }).fill("恢复先前释放请求");
      await page.getByLabel("保留幂等键", { exact: true }).fill(HOLD_KEY);
      await page.getByRole("button", { name: "释放保留锁", exact: true }).click();
    }
    await expect(page.getByRole("heading", { name: "保留操作结果未知" })).toBeVisible();
    await expect(page.getByRole("button", { name: "准备新的保留操作" })).toBeDisabled();
    await expect(page.getByLabel("保留幂等键", { exact: true })).toHaveValue(HOLD_KEY);
  });
}

test("invalid inputs remain local while restored past deadlines are sent unchanged", async ({
  page,
}) => {
  const calls = await intercept(page, (route) =>
    route.fulfill({ status: 409, json: errorFixture("CONTROL_EVIDENCE_HOLD_CONFLICT") }),
  );
  await connect(page);
  await fillCreate(page, "2026-02-30T00:00:00.000Z");
  await expect(page.getByRole("button", { name: "创建保留锁", exact: true })).toBeDisabled();
  await page.getByLabel("保留至（UTC）", { exact: true }).fill(HOLD_UNTIL);
  await page.getByLabel("保留理由", { exact: true }).fill("汉".repeat(171));
  await expect(page.getByRole("button", { name: "创建保留锁", exact: true })).toBeDisabled();
  expect(calls).toHaveLength(0);
  await fillCreate(page, "2020-01-01T00:00:00.000Z");
  await page.getByLabel("恢复原保留操作", { exact: true }).check();
  await page.getByRole("button", { name: "创建保留锁", exact: true }).click();
  await expect(page.getByRole("heading", { name: "保留操作结果未知" })).toBeVisible();
  expect(calls[0]?.body).toMatchObject({ hold_until: "2020-01-01T00:00:00.000Z" });
});

test("history paging is explicit and scoped to its case", async ({ page }) => {
  const cursor = `v1.${HOLD_ID}.${"a".repeat(64)}`;
  const calls = await intercept(page, (route, call) => {
    const body = holdCollectionFixture();
    if (call.path.includes("cursor="))
      body.items = [{ ...holdRecordFixture(), hold_id: HOLD_ID.replace(/.$/, "9") }];
    else {
      body.truncated = true;
      body.next_cursor = cursor;
    }
    return route.fulfill({ json: body });
  });
  await connect(page);
  await history(page);
  await page.getByRole("button", { name: "下一页保留历史" }).click();
  await expect(page.getByRole("button", { name: "下一页保留历史" })).toBeDisabled();
  expect(calls[1]?.path).toBe(`/control/v1/cases/${HOLD_CASE_ID}/holds?cursor=${cursor}`);
  await page.getByLabel("保留历史案件 ID", { exact: true }).fill(HOLD_CASE_ID.replace(/.$/, "9"));
  await expect(page.getByText("保留生效中", { exact: true })).toHaveCount(0);
});

test("mobile history separates durable release from expiry and renders reasons inertly", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const injected = '<img src=x onerror="window.injected=1">';
  await intercept(page, (route) => {
    const body = holdCollectionFixture();
    body.case_status = "closed";
    body.as_of = holdRecordFixture().hold_until.replace(/(\d{3})Z$/, "$1000Z");
    body.items[0]!.reason = injected;
    return route.fulfill({ json: body });
  });
  await connect(page);
  await history(page);
  await expect(page.getByText("保留期限已过", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("unreleased · 未释放", { exact: true })).toBeVisible();
  await expect(page.getByText(injected, { exact: true })).toBeVisible();
  await expect(
    page.getByRole("button", { name: `选择释放 ${HOLD_ID}`, exact: true }),
  ).toBeEnabled();
  expect(await page.evaluate(() => Reflect.get(window, "injected"))).toBeUndefined();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  const output = process.env.XSHIELD_CONSOLE_SCREENSHOT_DIR;
  if (output) await page.screenshot({ path: resolve(output, "holds-mobile.png"), fullPage: true });
});

test("navigation ignores a late write response while preserving recovery", async ({ page }) => {
  let release!: () => void;
  let delivered!: () => void;
  const gate = new Promise<void>((done) => {
    release = done;
  });
  const responseDelivered = new Promise<void>((done) => {
    delivered = done;
  });
  const calls = await intercept(page, async (route) => {
    await gate;
    await route.fulfill({ status: 201, json: holdMutationFixture() });
    delivered();
  });
  await connect(page);
  await create(page);
  await expect.poll(() => calls.length).toBe(1);
  await openView(page, "audit-health");
  release();
  await responseDelivered;
  await openView(page, "hold");
  await expect(page.getByRole("heading", { name: "保留操作结果未知" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "创建保留锁已确认" })).toHaveCount(0);
  await expect(page.getByLabel("保留幂等键", { exact: true })).toHaveValue(HOLD_KEY);
});

test("changing history case discards a late page and its cursor", async ({ page }) => {
  let release!: () => void;
  let delivered!: () => void;
  const gate = new Promise<void>((done) => {
    release = done;
  });
  const responseDelivered = new Promise<void>((done) => {
    delivered = done;
  });
  const calls = await intercept(page, async (route) => {
    await gate;
    await route.fulfill({
      json: {
        ...holdCollectionFixture(),
        truncated: true,
        next_cursor: `v1.${HOLD_ID}.${"a".repeat(64)}`,
      },
    });
    delivered();
  });
  await connect(page);
  await history(page);
  await expect.poll(() => calls.length).toBe(1);
  await page.getByLabel("保留历史案件 ID", { exact: true }).fill(HOLD_CASE_ID.replace(/.$/, "9"));
  release();
  await responseDelivered;
  await page.evaluate(
    () =>
      new Promise<void>((done) => requestAnimationFrame(() => requestAnimationFrame(() => done()))),
  );
  await expect(page.getByText("保留生效中", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "下一页保留历史" })).toHaveCount(0);
  await expect(page.getByLabel("保留历史案件 ID", { exact: true })).toHaveValue(
    HOLD_CASE_ID.replace(/.$/, "9"),
  );
});

test("mismatched write response preserves the frozen request as unknown", async ({ page }) => {
  await intercept(page, (route) =>
    route.fulfill({
      status: 201,
      json: { ...holdMutationFixture(), artifact_id: ARTIFACT_ID.replace(/.$/, "9") },
    }),
  );
  await connect(page);
  await create(page);
  await expect(page.getByRole("heading", { name: "保留操作结果未知" })).toBeVisible();
  await expect(page.getByText("INVALID_RESPONSE", { exact: false }).first()).toBeVisible();
  await expect(page.getByRole("button", { name: "准备新的保留操作" })).toBeDisabled();
  await expect(page.getByLabel("冻结保留请求参数")).toContainText(ARTIFACT_ID);
});

for (const end of ["disconnect", "pagehide", "idle", "refresh", "unauthorized", "scope"] as const) {
  test(`hold session clears on ${end}`, async ({ page }) => {
    await page.clock.install();
    let count = 0;
    await intercept(page, (route) => {
      count += 1;
      if (count > 1 && end === "unauthorized")
        return route.fulfill({ status: 401, json: errorFixture("CONTROL_AUTH_REQUIRED") });
      const body = holdCollectionFixture();
      if (count > 1 && end === "scope") body.tenant_id = "tenant_other";
      return route.fulfill({ json: body });
    });
    await connect(page);
    await history(page);
    await expect(page.getByText("保留生效中", { exact: true })).toBeVisible();
    await page.getByLabel("保留理由", { exact: true }).fill("私有保留理由");
    if (end === "disconnect")
      await page.getByRole("button", { name: "断开连接", exact: true }).click();
    else if (end === "pagehide")
      await page.evaluate(() => window.dispatchEvent(new Event("pagehide")));
    else if (end === "idle") await page.clock.runFor(15 * 60 * 1000 + 1);
    else if (end === "refresh") await page.reload();
    else await page.getByRole("button", { name: "读取保留历史 / 刷新", exact: true }).click();
    await expect(page.getByRole("heading", { name: "连接管理服务" })).toBeVisible();
    expect(
      await page.evaluate(() => ({ local: { ...localStorage }, session: { ...sessionStorage } })),
    ).toEqual({ local: {}, session: {} });
    await page.getByLabel("管理凭证", { exact: true }).fill(TOKEN);
    await page.getByRole("button", { name: "连接", exact: true }).click();
    await openView(page, "hold");
    await expect(page.getByLabel("保留理由", { exact: true })).toHaveValue("");
    await expect(page.getByLabel("保留历史案件 ID", { exact: true })).toHaveValue("");
  });
}
