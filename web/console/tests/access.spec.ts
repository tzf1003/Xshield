import { openView } from "./navigation";
import { expect, test, type Page, type Route } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { ARTIFACT_ID, TOKEN, errorFixture } from "./fixtures";
import {
  ACCESS_ID, ACCESS_CASE_ID, ACCESS_KEY, accessRequestedFixture,
  accessInspectionFixture, accessDecisionFixture, downloadHeaders,
} from "./access-fixtures";

type Call = { path: string; method: string; key: string | null; body: unknown };
async function intercept(page: Page, handler: (route: Route, call: Call) => Promise<void>) {
  const calls: Call[] = [];
  await page.route("**/control/v1/**", async (route) => {
    const request = route.request();
    expect(await request.headerValue("authorization")).toBe(`Bearer ${TOKEN}`);
    expect(await request.headerValue("cookie")).toBeNull();
    const url = new URL(request.url());
    const call = { path: url.pathname + url.search, method: request.method(),
      key: await request.headerValue("idempotency-key"), body: request.postDataJSON() };
    calls.push(call);
    await handler(route, call);
  });
  return calls;
}
async function connect(page: Page) {
  await page.goto("/investigation/requests");
  await page.getByLabel("管理凭证", { exact: true }).fill(TOKEN);
  await page.getByRole("button", { name: "连接", exact: true }).click();
  await openView(page, "access");
}
async function inspect(page: Page) {
  await page.getByLabel("访问申请 ID", { exact: true }).fill(ACCESS_ID);
  await page.getByRole("button", { name: "读取申请 / 刷新", exact: true }).click();
  await expect(page.getByText("synthetic-investigator", { exact: true })).toBeVisible();
}
async function requestAccess(page: Page) {
  await page.getByLabel("申请案件 ID", { exact: true }).fill(ACCESS_CASE_ID);
  await page.getByLabel("申请证据 ID", { exact: true }).fill(ARTIFACT_ID);
  await page.getByLabel("申请理由", { exact: true }).fill("核查证据内容");
  await page.getByLabel("访问幂等键", { exact: true }).fill(ACCESS_KEY);
  await page.getByRole("button", { name: "提交访问申请", exact: true }).click();
}
test("prepares scoped access-request history without submitting a search", async ({ page }) => {
  const calls = await intercept(page, async (route) => route.fulfill({ json: accessInspectionFixture() }));
  await connect(page);
  await inspect(page);
  await page.getByRole("button", { name: "准备历史检索", exact: true }).click();
  await expect(page.getByRole("heading", { name: "结构化事件检索", exact: true })).toBeVisible();
  await expect(page.getByLabel("条件 1 字段", { exact: true })).toHaveValue(
    "evidence_access_request_id",
  );
  await expect(page.getByLabel("条件 1 值", { exact: true })).toHaveValue(ACCESS_ID);
  await expect(page.getByLabel("开始时间（UTC，含）", { exact: true })).toHaveValue("");
  await expect(page.getByLabel("结束时间（UTC，不含）", { exact: true })).toHaveValue("");
  expect(calls.map((call) => call.path)).toEqual([
    `/control/v1/evidence-access-requests/${ACCESS_ID}`,
  ]);
});
test("explicit request, independent review, approval and exact binary download", async ({ page }) => {
  let approved = false;
  const payload = Buffer.from([0, 255, 60, 115, 99, 114, 105, 112, 116, 62]);
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  const calls = await intercept(page, async (route, call) => {
    if (call.path.endsWith("/access")) return route.fulfill({ status: 201, json: accessRequestedFixture() });
    if (call.path.endsWith("/approve")) {
      approved = true;
      return route.fulfill({ json: accessDecisionFixture() });
    }
    if (call.path.endsWith("/content")) {
      expect(await route.request().headerValue("x-xshield-evidence-access-request")).toBe(ACCESS_ID);
      return route.fulfill({ body: payload, headers: downloadHeaders(payload.length) });
    }
    return route.fulfill({ json: accessInspectionFixture(approved ? "approved" : "pending") });
  });
  await connect(page);
  await expect(page).toHaveTitle(/Xshield/);
  await expect(page.getByRole("heading", { name: "证据访问", exact: true })).toBeVisible();
  expect(calls).toHaveLength(0);
  await requestAccess(page);
  await expect(page.getByRole("heading", { name: "提交访问申请已确认" })).toBeVisible();
  expect(calls[0]).toEqual({ path: `/control/v1/artifacts/${ARTIFACT_ID}/access`, method: "POST", key: ACCESS_KEY,
    body: { case_id: ACCESS_CASE_ID, access_kind: "sensitive_raw", justification: "核查证据内容" } });
  await expect(page.getByText(`POST /control/v1/artifacts/${ARTIFACT_ID}/access`, { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "准备新的访问操作" }).click();
  await page.getByLabel("访问操作", { exact: true }).selectOption("approve");
  await expect(page.getByRole("button", { name: "批准访问", exact: true })).toBeDisabled();
  await inspect(page);
  await page.getByLabel("审批理由", { exact: true }).fill("已核对案件用途");
  await page.getByLabel("批准期限（秒）", { exact: true }).fill("600");
  await page.getByLabel("访问幂等键", { exact: true }).fill(`${ACCESS_KEY}-decision`);
  await page.getByRole("button", { name: "批准访问", exact: true }).click();
  await expect(page.getByRole("heading", { name: "批准访问已确认" })).toBeVisible();
  expect(calls[2]?.body).toEqual({ reason: "已核对案件用途", ttl_seconds: 600 });
  await page.getByRole("button", { name: "读取申请 / 刷新", exact: true }).click();
  const downloadButton = page.getByRole("button", { name: "下载原文（.bin）", exact: true });
  await expect(downloadButton).toBeEnabled();
  const downloadEvent = page.waitForEvent("download");
  await downloadButton.click();
  const download = await downloadEvent;
  expect(download.suggestedFilename()).toBe(`${ARTIFACT_ID}.bin`);
  expect(await readFile((await download.path())!)).toEqual(payload);
  await download.delete();
  await expect(page.getByText(/已发起附件保存/)).toBeVisible();
  expect(errors).toEqual([]);
  await expect(page.locator("vite-error-overlay")).toHaveCount(0);
  const output = process.env.XSHIELD_CONSOLE_SCREENSHOT_DIR;
  if (output) await page.screenshot({ path: resolve(output, "access-desktop.png"), fullPage: true });
});

test("uncertain request preserves exact retry after a later rejection and navigation", async ({ page }) => {
  let attempt = 0;
  const calls = await intercept(page, async (route) => {
    attempt += 1;
    if (attempt === 1) return route.abort("failed");
    if (attempt === 2) return route.fulfill({ status: 409, json: errorFixture("CONTROL_IDEMPOTENCY_CONFLICT") });
    return route.fulfill({ json: { ...accessRequestedFixture(), replayed: true } });
  });
  await connect(page);
  await requestAccess(page);
  await expect(page.getByRole("heading", { name: "访问操作结果未知" })).toBeVisible();
  await expect(page.getByRole("button", { name: "准备新的访问操作" })).toBeDisabled();
  await openView(page, "request");
  await openView(page, "access");
  await page.getByRole("button", { name: "原样重试访问操作" }).click();
  await expect(page.getByRole("heading", { name: "访问操作结果未知" })).toBeVisible();
  await expect(page.getByText("CONTROL_IDEMPOTENCY_CONFLICT", { exact: false }).first()).toBeVisible();
  await page.getByRole("button", { name: "原样重试访问操作" }).click();
  await expect(page.getByRole("heading", { name: "提交访问申请已确认" })).toBeVisible();
  expect(calls).toEqual([calls[0], calls[0], calls[0]]);
});

for (const status of ["pending", "denied", "expired", "revoked"] as const) {
  test(`historical ${status} detail does not enable content download`, async ({ page }) => {
    await intercept(page, (route) => route.fulfill({ json: accessInspectionFixture(status) }));
    await connect(page);
    await inspect(page);
    await expect(page.getByRole("button", { name: "下载原文（.bin）" })).toBeDisabled();
  });
}

test("closed evidence can be denied after review and text stays inert on mobile", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const text = '<img src=x onerror="window.injected=1">';
  const calls = await intercept(page, async (route, call) => {
    if (call.method === "POST") return route.fulfill({ json: accessDecisionFixture("denied") });
    const body = accessInspectionFixture();
    body.access_request.case_status = "closed";
    body.access_request.artifact_status = "deleted";
    body.access_request.justification = text;
    return route.fulfill({ json: body });
  });
  await connect(page);
  await inspect(page);
  await expect(page.getByText(text, { exact: true })).toBeVisible();
  expect(await page.evaluate(() => Reflect.get(window, "injected"))).toBeUndefined();
  await page.getByLabel("访问操作", { exact: true }).selectOption("deny");
  await page.getByLabel("审批理由", { exact: true }).fill("已核对案件用途");
  await page.getByRole("button", { name: "拒绝访问", exact: true }).click();
  await expect(page.getByRole("heading", { name: "拒绝访问已确认" })).toBeVisible();
  expect(calls[1]?.body).toEqual({ reason: "已核对案件用途" });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  const output = process.env.XSHIELD_CONSOLE_SCREENSHOT_DIR;
  if (output) await page.screenshot({ path: resolve(output, "access-mobile.png"), fullPage: true });
});

for (const failure of ["scope", "unauthorized", "audit"] as const) {
  test(`download ${failure} failure never releases a browser attachment`, async ({ page }) => {
    const downloads: string[] = [];
    page.on("download", (download) => downloads.push(download.suggestedFilename()));
    await intercept(page, async (route, call) => {
      if (!call.path.endsWith("/content")) return route.fulfill({ json: accessInspectionFixture("approved") });
      if (failure === "scope") return route.fulfill({ body: Buffer.from([1, 2, 3]), headers: { ...downloadHeaders(), "X-Xshield-Tenant-Id": "tenant_other" } });
      return route.fulfill({ status: failure === "unauthorized" ? 401 : 503,
        json: errorFixture(failure === "unauthorized" ? "CONTROL_AUTH_REQUIRED" : "AUDIT_DURABILITY_FAILED") });
    });
    await connect(page);
    await inspect(page);
    await page.getByRole("button", { name: "下载原文（.bin）" }).click();
    if (failure === "audit") await expect(page.getByText("AUDIT_DURABILITY_FAILED", { exact: false }).first()).toBeVisible();
    else await expect(page.getByRole("heading", { name: "连接管理服务" })).toBeVisible();
    expect(downloads).toEqual([]);
  });
}

test("changing target invalidates delayed binary response", async ({ page }) => {
  let release!: () => void;
  const gate = new Promise<void>((done) => { release = done; });
  const downloads: string[] = [];
  page.on("download", (download) => downloads.push(download.suggestedFilename()));
  const calls = await intercept(page, async (route, call) => {
    if (!call.path.endsWith("/content")) return route.fulfill({ json: accessInspectionFixture("approved") });
    await gate;
    await route.fulfill({ body: Buffer.from([1, 2, 3]), headers: downloadHeaders() });
  });
  await connect(page);
  await inspect(page);
  await page.getByRole("button", { name: "下载原文（.bin）" }).click();
  await expect.poll(() => calls.length).toBe(2);
  await page.getByLabel("访问申请 ID", { exact: true }).fill(ACCESS_ID.replace(/41$/, "42"));
  release();
  await expect(page.getByText("synthetic-investigator", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "下载原文（.bin）" })).toBeDisabled();
  expect(downloads).toEqual([]);
});

test("restored approval keeps uncertainty after rejection until exact replay succeeds", async ({ page }) => {
  let attempts = 0;
  const calls = await intercept(page, async (route, call) => {
    if (call.method === "GET") return route.fulfill({ json: accessInspectionFixture("approved") });
    attempts += 1;
    if (attempts === 1) return route.fulfill({ status: 409, json: errorFixture("CONTROL_IDEMPOTENCY_CONFLICT") });
    return route.fulfill({ json: accessDecisionFixture("approved", true) });
  });
  await connect(page);
  await inspect(page);
  await page.getByLabel("访问操作", { exact: true }).selectOption("approve");
  await page.getByLabel("审批理由", { exact: true }).fill("已核对案件用途");
  await page.getByLabel("批准期限（秒）", { exact: true }).fill("600");
  await page.getByLabel("访问幂等键", { exact: true }).fill(ACCESS_KEY);
  await expect(page.getByRole("button", { name: "批准访问", exact: true })).toBeDisabled();
  await page.getByLabel("恢复原审批请求", { exact: true }).check();
  await page.getByRole("button", { name: "批准访问", exact: true }).click();
  await expect(page.getByRole("heading", { name: "访问操作结果未知" })).toBeVisible();
  await expect(page.getByRole("button", { name: "准备新的访问操作" })).toBeDisabled();
  await page.getByRole("button", { name: "原样重试访问操作" }).click();
  await expect(page.getByRole("heading", { name: "批准访问已确认" })).toBeVisible();
  expect(calls[1]).toEqual(calls[2]);
});

for (const end of ["disconnect", "pagehide", "idle", "refresh"] as const) {
  test(`access state and drafts clear on ${end}`, async ({ page }) => {
    await page.clock.install();
    await intercept(page, (route) => route.fulfill({ json: accessInspectionFixture("approved") }));
    await connect(page);
    await inspect(page);
    await page.getByLabel("申请理由", { exact: true }).fill("私有的恢复理由");
    if (end === "disconnect") await page.getByRole("button", { name: "断开连接", exact: true }).click();
    else if (end === "pagehide") await page.evaluate(() => window.dispatchEvent(new Event("pagehide")));
    else if (end === "idle") await page.clock.runFor(15 * 60 * 1000 + 1);
    else await page.reload();
    await expect(page.getByRole("heading", { name: "连接管理服务" })).toBeVisible();
    await expect(page.getByText("synthetic-investigator", { exact: true })).toHaveCount(0);
    expect(await page.evaluate(() => ({ local: { ...localStorage }, session: { ...sessionStorage } }))).toEqual({ local: {}, session: {} });
    await page.getByLabel("管理凭证", { exact: true }).fill(TOKEN);
    await page.getByRole("button", { name: "连接", exact: true }).click();
    await openView(page, "access");
    await expect(page.getByLabel("申请理由", { exact: true })).toHaveValue("");
    await expect(page.getByLabel("访问申请 ID", { exact: true })).toHaveValue("");
  });
}

test("approval target mismatch remains unknown and cannot replace its frozen request", async ({ page }) => {
  await intercept(page, (route, call) => route.fulfill({ json: call.method === "GET"
    ? accessInspectionFixture()
    : { ...accessDecisionFixture(), artifact_id: ARTIFACT_ID.replace(/11$/, "12") } }));
  await connect(page);
  await inspect(page);
  await page.getByLabel("访问操作", { exact: true }).selectOption("approve");
  await page.getByLabel("审批理由", { exact: true }).fill("已核对案件用途");
  await page.getByLabel("批准期限（秒）", { exact: true }).fill("600");
  await page.getByRole("button", { name: "批准访问", exact: true }).click();
  await expect(page.getByRole("heading", { name: "访问操作结果未知" })).toBeVisible();
  await expect(page.getByText("INVALID_RESPONSE", { exact: false }).first()).toBeVisible();
  await expect(page.getByRole("button", { name: "准备新的访问操作" })).toBeDisabled();
});

test("restored access application remains unknown on a subsequent rejection", async ({ page }) => {
  await intercept(page, (route) => route.fulfill({ status: 404, json: errorFixture("CONTROL_EVIDENCE_ACCESS_TARGET_UNAVAILABLE") }));
  await connect(page);
  await page.getByLabel("恢复原访问申请", { exact: true }).check();
  await requestAccess(page);
  await expect(page.getByRole("heading", { name: "访问操作结果未知" })).toBeVisible();
  await expect(page.getByRole("button", { name: "准备新的访问操作" })).toBeDisabled();
  await expect(page.getByLabel("访问幂等键", { exact: true })).toHaveValue(ACCESS_KEY);
});
