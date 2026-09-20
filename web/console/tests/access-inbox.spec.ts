import { expect, test, type Page, type Route } from "@playwright/test";
import { resolve } from "node:path";
import { ARTIFACT_ID, TOKEN, errorFixture } from "./fixtures";
import { ACCESS_ID, ACCESS_CASE_ID, ACCESS_KEY, accessListFixture,
  accessInspectionFixture, accessRequestedFixture } from "./access-fixtures";

const cursor = `v1.${ACCESS_ID}.${"a".repeat(64)}`;
const earlier = ACCESS_ID.slice(0, -2) + "40";
const inbox = (page: Page) => page.getByRole("region", { name: "访问申请列表", exact: true });
const detail = (page: Page) => page.getByRole("region", { name: "访问申请详情", exact: true });
async function connect(page: Page) {
  await page.goto("/");
  await page.getByLabel("管理凭证", { exact: true }).fill(TOKEN);
  await page.getByRole("button", { name: "连接", exact: true }).click();
  await page.getByLabel("查询类型", { exact: true }).selectOption("access");
}
async function routes(page: Page, handler: (route: Route, url: URL) => Promise<void>) {
  const calls: string[] = [];
  await page.route("**/control/v1/**", async (route) => {
    expect(await route.request().headerValue("authorization")).toBe(`Bearer ${TOKEN}`);
    expect(await route.request().headerValue("cookie")).toBeNull();
    const url = new URL(route.request().url());
    calls.push(url.pathname + url.search);
    await handler(route, url);
  });
  return calls;
}
async function read(page: Page) {
  await page.getByRole("button", { name: "读取申请列表 / 刷新", exact: true }).click();
}

test("explicit history pages and refreshed detail keep review authority separate", async ({ page }) => {
  const calls = await routes(page, async (route, url) => {
    if (url.pathname.endsWith(earlier)) {
      const fixture = accessInspectionFixture("revoked");
      fixture.access_request.access_request_id = earlier;
      return route.fulfill({ json: fixture });
    }
    const view = url.searchParams.get("view") === "review" ? "review" : "mine";
    const fixture = accessListFixture(view);
    if (view === "review") fixture.items = [];
    else if (url.searchParams.has("cursor")) {
      expect(url.searchParams.get("cursor")).toBe(cursor);
      fixture.items[0]!.access_request_id = earlier;
      fixture.items[0]!.stored_status = "revoked";
    } else {
      fixture.truncated = true; fixture.next_cursor = cursor;
    }
    return route.fulfill({ json: fixture });
  });
  await connect(page);
  expect(calls).toHaveLength(0);
  await expect(inbox(page)).toBeVisible();
  await read(page);
  await expect(inbox(page).getByRole("button", { name: `打开申请 ${ACCESS_ID}`, exact: true })).toBeVisible();
  await page.getByRole("button", { name: "下一页申请", exact: true }).click();
  await expect(inbox(page).getByText("revoked", { exact: true })).toBeVisible();
  await expect(inbox(page).getByText(ACCESS_ID, { exact: true })).toHaveCount(0);
  await page.getByLabel("访问操作", { exact: true }).selectOption("approve");
  await page.getByRole("button", { name: `打开申请 ${earlier}`, exact: true }).click();
  await expect(detail(page).getByText("核查证据内容", { exact: true })).toBeVisible();
  expect(calls).toEqual([
    "/control/v1/evidence-access-requests?view=mine",
    `/control/v1/evidence-access-requests?view=mine&cursor=${cursor}`,
    `/control/v1/evidence-access-requests/${earlier}`,
  ]);
  await expect(page.getByRole("button", { name: "批准访问", exact: true })).toBeDisabled();
  const output = process.env.XSHIELD_CONSOLE_SCREENSHOT_DIR;
  if (output) {
    await page.screenshot({ path: resolve(output, "access-inbox-desktop.png"), fullPage: true });
    await page.setViewportSize({ width: 390, height: 844 });
    await expect(inbox(page)).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
    await page.screenshot({ path: resolve(output, "access-inbox-mobile.png"), fullPage: true });
  }
  await page.getByLabel("申请列表范围", { exact: true }).selectOption("review");
  await expect(detail(page).getByText("核查证据内容", { exact: true })).toHaveCount(0);
  await expect(inbox(page).getByText("revoked", { exact: true })).toHaveCount(0);
  expect(calls).toHaveLength(3);
  await read(page);
  await expect(inbox(page).getByText("当前范围内暂无审批待办。", { exact: true })).toBeVisible();
  await page.getByLabel("查询类型", { exact: true }).selectOption("request");
  await page.getByLabel("查询类型", { exact: true }).selectOption("access");
  await expect(inbox(page).getByText("当前范围内暂无审批待办。", { exact: true })).toHaveCount(0);
});

test("review role refusal displays audited error and no record", async ({ page }) => {
  await routes(page, async (route) => route.fulfill({ status: 403, json: errorFixture("CONTROL_SCOPE_DENIED") }));
  await connect(page);
  await page.getByLabel("申请列表范围", { exact: true }).selectOption("review");
  await read(page);
  await expect(inbox(page).getByRole("alert")).toContainText("CONTROL_SCOPE_DENIED");
  await expect(inbox(page).getByRole("button", { name: /^打开申请/ })).toHaveCount(0);
});

test("scope mismatch disconnects before revealing another tenant list", async ({ page }) => {
  let count = 0;
  await routes(page, async (route) => {
    const fixture = accessListFixture();
    if (++count > 1) {
      fixture.tenant_id = "tenant_other";
      fixture.items[0]!.requested_by = "cross-scope-list-owner";
    }
    return route.fulfill({ json: fixture });
  });
  await connect(page);
  await read(page);
  await expect(inbox(page).getByRole("button", { name: /^打开申请/ })).toBeVisible();
  await read(page);
  await expect(page.getByText("响应范围校验失败，连接已断开。", { exact: true })).toBeVisible();
  await expect(page.getByText("cross-scope-list-owner", { exact: true })).toHaveCount(0);
});

for (const transition of ["view", "query", "disconnect"] as const) {
  test(`stale list response is discarded after ${transition}`, async ({ page }) => {
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let started = false;
    await routes(page, async (route) => {
      started = true;
      await gate;
      const fixture = accessListFixture();
      fixture.items[0]!.requested_by = "stale-list-owner";
      await route.fulfill({ json: fixture });
    });
    await connect(page);
    await read(page);
    await expect.poll(() => started).toBe(true);
    if (transition === "view") await page.getByLabel("申请列表范围", { exact: true }).selectOption("review");
    else if (transition === "query") await page.getByLabel("查询类型", { exact: true }).selectOption("request");
    else await page.getByRole("button", { name: "断开连接", exact: true }).click();
    release?.();
    if (transition === "query") await page.getByLabel("查询类型", { exact: true }).selectOption("access");
    await expect(page.getByText("stale-list-owner", { exact: true })).toHaveCount(0);
    if (transition !== "disconnect") await expect(page.getByRole("button", { name: "读取申请列表 / 刷新", exact: true })).toBeEnabled();
  });
}

test("opening another list record preserves frozen unknown mutation and exact replay", async ({ page }) => {
  const mutations: Array<{ body: unknown; key: string | null }> = [];
  await routes(page, async (route, url) => {
    if (route.request().method() === "POST") {
      mutations.push({ body: route.request().postDataJSON(), key: await route.request().headerValue("idempotency-key") });
      if (mutations.length === 1) return route.abort("failed");
      return route.fulfill({ json: { ...accessRequestedFixture(), replayed: true } });
    }
    if (url.searchParams.has("view")) {
      const fixture = accessListFixture(); fixture.items[0]!.access_request_id = earlier;
      return route.fulfill({ json: fixture });
    }
    const fixture = accessInspectionFixture(); fixture.access_request.access_request_id = earlier;
    return route.fulfill({ json: fixture });
  });
  await connect(page);
  await page.getByLabel("申请案件 ID", { exact: true }).fill(ACCESS_CASE_ID);
  await page.getByLabel("申请证据 ID", { exact: true }).fill(ARTIFACT_ID);
  await page.getByLabel("申请理由", { exact: true }).fill("核查证据内容");
  await page.getByLabel("访问幂等键", { exact: true }).fill(ACCESS_KEY);
  await page.getByRole("button", { name: "提交访问申请", exact: true }).click();
  await expect(page.getByRole("heading", { name: "访问操作结果未知", exact: true })).toBeVisible();
  const frozen = await page.getByLabel("冻结访问请求参数", { exact: true }).textContent();
  await read(page);
  await page.getByRole("button", { name: `打开申请 ${earlier}`, exact: true }).click();
  await expect(detail(page).getByText("核查证据内容", { exact: true })).toBeVisible();
  await expect(page.getByLabel("冻结访问请求参数", { exact: true })).toHaveText(frozen ?? "");
  await expect(page.getByRole("button", { name: "准备新的访问操作", exact: true })).toBeDisabled();
  await page.getByRole("button", { name: "原样重试访问操作", exact: true }).click();
  await expect(page.getByRole("heading", { name: "提交访问申请已确认", exact: true })).toBeVisible();
  expect(mutations).toHaveLength(2);
  expect(mutations[1]).toEqual(mutations[0]);
});
