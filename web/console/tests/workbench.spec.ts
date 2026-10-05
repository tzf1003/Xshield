import { expect, type Page, test } from "@playwright/test";
import { errorFixture } from "./fixtures";
import { workbenchOverviewFixture } from "./overview-fixtures";
import { seamState, signIn, storageSnapshot } from "./shell-helpers";
import {
  DENIED_REQUEST,
  mockWorkbench,
  OTHER_DENIED_REQUEST,
  settledReads,
} from "./workbench-helpers";

// The workbench (`/`) in the machine-login build, where roles are unknown and every source is
// read. Role-specific behaviour is in operations-session.spec.ts (cookie sessions).

const OPENING = [
  "/control/v1/workbench/overview",
  "/control/v1/sites?limit=100",
  "/control/v1/evidence-access-requests?view=review",
  "/control/v1/exports?view=review",
];

const kpi = (page: Page, label: string) =>
  page.getByRole("list", { name: "关键指标" }).getByRole("listitem").filter({ hasText: label });
const todo = (page: Page) => page.getByRole("region", { name: /待我处理/ });
const sitesCard = (page: Page) => page.getByRole("region", { name: "站点健康" });
const siteRow = (page: Page, name: string) =>
  sitesCard(page).getByRole("row").filter({ hasText: name });

async function open(page: Page, mock: Parameters<typeof mockWorkbench>[1] = {}) {
  const calls = await mockWorkbench(page, mock);
  await signIn(page, "/");
  await expect(page.getByRole("heading", { name: "运行概览", level: 1 })).toBeVisible();
  return calls;
}

test("opens with one snapshot read plus the todo sources, and nothing reads again by itself", async ({
  page,
}) => {
  await page.clock.install();
  const calls = await open(page);
  await expect(siteRow(page, "Gamma 支付")).toBeVisible();
  await settledReads(page, calls, OPENING);
  const opened = calls.length;
  // No timer, focus, visibility or reconnect brings a read: every read is audited server-side.
  await page.clock.fastForward(10 * 60_000);
  await page.evaluate(() => {
    window.dispatchEvent(new Event("focus"));
    document.dispatchEvent(new Event("visibilitychange"));
    window.dispatchEvent(new Event("online"));
  });
  await page.waitForTimeout(500);
  expect(calls).toHaveLength(opened);
  expect(calls.some((call) => call.path === "/control/v1/search")).toBe(false);
  expect(calls.some((call) => call.path.endsWith("/health"))).toBe(false);
  expect(await storageSnapshot(page)).toEqual({ local: {}, session: {} });
});

test("the KPI strip names each source and its time", async ({ page }) => {
  await open(page);
  await expect(kpi(page, "正在服务的站点")).toContainText("3");
  await expect(kpi(page, "正在服务的站点")).toContainText("来源：工作台快照 · 观察于");
  // Awaiting approval comes from the site list (only it carries requires_approval).
  await expect(kpi(page, "待审批修订")).toContainText("1");
  await expect(kpi(page, "待审批修订")).toContainText("来源：站点清单首页 · 读取于");
  await expect(kpi(page, "待审批修订")).toContainText("（浏览器时间）");
  await expect(kpi(page, "应用失败")).toContainText("1");
  await expect(kpi(page, "审计发布")).toContainText("连续");
  await expect(page.locator(".xs-page-actions").getByText(/快照观察于/)).toBeVisible();
});

test("sources that cannot answer show — with the reason, never 0", async ({ page }) => {
  await open(page, {
    overview: { noSites: true, noAudit: true },
    override: (url) =>
      url.pathname === "/control/v1/sites"
        ? { status: 403, body: errorFixture("CONTROL_SCOPE_DENIED") }
        : undefined,
  });
  for (const label of ["正在服务的站点", "待审批修订", "应用失败", "审计发布"]) {
    await expect(kpi(page, label).locator(".xs-wb-kpi-value")).toHaveText("—无数据");
    await expect(kpi(page, label).locator(".xs-wb-kpi-value")).not.toContainText("0");
  }
  await expect(kpi(page, "正在服务的站点")).toContainText("可能没有投影站点列表或读取失败");
  await expect(kpi(page, "待审批修订")).toContainText("需要 SystemAdmin");
  // The snapshot says it is partial, and the page says why.
  const notice = page.getByRole("alert").filter({ hasText: "这份快照是部分结果" });
  await expect(notice).toBeVisible();
  await expect(notice).toContainText("审计发布观察");
  await expect(sitesCard(page)).toContainText("快照没有站点列表");
  await expect(sitesCard(page).getByRole("table")).toHaveCount(0);
});

test("each todo source fails on its own and retries on its own", async ({ page }) => {
  let failing = true;
  const calls = await open(page, {
    override: (url) =>
      url.pathname === "/control/v1/exports" && failing
        ? { status: 503, body: errorFixture("CONTROL_EXPORT_STORE_UNAVAILABLE") }
        : undefined,
  });
  const card = todo(page);
  const banner = card.getByRole("alert").filter({ hasText: "导出待办读取失败" });
  await expect(banner).toContainText("CONTROL_EXPORT_STORE_UNAVAILABLE");
  await expect(banner).toContainText("HTTP 503");
  // What the other sources answered is still there.
  await expect(card.getByText("原文访问申请待审批")).toBeVisible();
  await expect(card.getByText("应用失败：Gamma 支付")).toBeVisible();
  await expect(card.getByText("待审批修订：Beta 商城")).toBeVisible();
  await expect(siteRow(page, "Alpha 官网")).toBeVisible();
  failing = false;
  const before = calls.length;
  await banner.getByRole("button", { name: "重试" }).click();
  await expect(card.getByText("导出申请待审批")).toBeVisible();
  await expect(banner).toHaveCount(0);
  expect(calls.slice(before).map((call) => call.path)).toEqual(["/control/v1/exports?view=review"]);
});

test("a refused source is a role hint, not an error, and a failed snapshot hides nothing else", async ({
  page,
}) => {
  await open(page, {
    override: (url) =>
      url.pathname === "/control/v1/sites"
        ? { status: 403, body: errorFixture("CONTROL_SCOPE_DENIED") }
        : url.pathname === "/control/v1/workbench/overview"
          ? { status: 503, body: errorFixture("CONTROL_INDEX_UNAVAILABLE") }
          : undefined,
  });
  const card = todo(page);
  await expect(card.getByText("站点清单：服务端拒绝了当前身份")).toBeVisible();
  await expect(card.getByRole("alert").filter({ hasText: "站点清单读取失败" })).toHaveCount(0);
  await expect(card.getByText("原文访问申请待审批")).toBeVisible();
  const snapshot = page.getByRole("alert").filter({ hasText: "工作台快照读取失败" });
  await expect(snapshot).toContainText("CONTROL_INDEX_UNAVAILABLE");
  await expect(snapshot.getByRole("button", { name: "重试" })).toBeVisible();
  await expect(kpi(page, "应用失败").locator(".xs-wb-kpi-value")).toHaveText("—无数据");
});

test("todo rows lead to the page that handles them, urgent rows first", async ({ page }) => {
  await open(page);
  const rows = todo(page).getByRole("list", { name: "待处理事项" }).getByRole("listitem");
  await expect(rows).toHaveCount(4);
  await expect(rows.first()).toContainText("应用失败：Gamma 支付");
  await expect(rows.first().getByRole("link", { name: "去处理" })).toHaveAttribute(
    "href",
    "/sites/site_gamma/releases",
  );
  await expect(
    rows.filter({ hasText: "待审批修订：Beta 商城" }).getByRole("link", { name: "去处理" }),
  ).toHaveAttribute("href", "/sites/site_beta/releases");
  const access = rows.filter({ hasText: "原文访问申请待审批" }).getByRole("link");
  await expect(access).toHaveAttribute("href", /^\/approvals\?item=access_/);
  await access.click();
  await expect(page).toHaveURL(/\/approvals\?item=access_/);
});

test("the upstream value reads as the last stored observation; refreshing health is one audited read", async ({
  page,
}) => {
  const calls = await open(page);
  const alpha = siteRow(page, "Alpha 官网");
  await expect(alpha).toContainText("健康");
  await expect(alpha).toContainText("上次观察");
  const beta = siteRow(page, "Beta 商城");
  await expect(beta).toContainText("从未观察");
  await expect(beta).not.toContainText("上次观察");
  const gamma = siteRow(page, "Gamma 支付");
  await expect(gamma).toContainText("不可用");
  await expect(gamma).toContainText("上次观察");
  // Mode and status come from the site list; the never-applied revision would say so.
  await expect(alpha).toContainText("必须有界面操作来源");
  const before = calls.length;
  await alpha.getByRole("button", { name: /刷新 Alpha 官网 的健康/ }).click();
  await expect(alpha).toContainText("本次读取");
  expect(calls.slice(before).map((call) => call.path)).toEqual([
    "/control/v1/sites/site_alpha/health",
  ]);
  // A row click opens the site; the buttons and links inside it do not.
  await siteRow(page, "Beta 商城").getByRole("cell").nth(4).click();
  await expect(page).toHaveURL(/\/sites\/site_beta\/overview$/);
});

test("the denied-requests card reads only on an explicit click, once", async ({ page }) => {
  const calls = await open(page);
  await settledReads(page, calls, OPENING);
  expect(calls.some((call) => call.path === "/control/v1/search")).toBe(false);
  const card = page.getByRole("region", { name: "最近被拒绝的请求" });
  await card.getByRole("button", { name: "读取最近被拒绝的请求" }).click();
  const list = card.getByRole("list", { name: "被拒绝的请求" });
  await expect(list.getByRole("listitem")).toHaveCount(2);
  const searches = calls.filter((call) => call.path === "/control/v1/search");
  expect(searches).toHaveLength(1);
  const plan = searches[0]?.body as {
    start: string;
    end: string;
    filters: unknown[];
    sort: string;
    limit: number;
  };
  expect(plan.filters).toEqual([
    { kind: "text", field: "event_type", value: "request.completed" },
    { kind: "outcome", value: "DENY" },
  ]);
  expect(plan.sort).toBe("occurred_at_desc");
  expect(plan.limit).toBe(10);
  expect(Date.parse(plan.end) - Date.parse(plan.start)).toBe(24 * 3_600_000);
  await expect(list.getByRole("link", { name: `打开请求 ${DENIED_REQUEST}` })).toHaveAttribute(
    "href",
    `/investigation/requests/${DENIED_REQUEST}`,
  );
  await expect(list.getByRole("link", { name: `打开请求 ${OTHER_DENIED_REQUEST}` })).toBeVisible();
  // Unknown scan statistics stay unknown; known ones are numbers.
  await expect(card).toContainText("扫描行数 1,280 行");
  await expect(card).toContainText("扫描字节 未知");
  await expect(card.getByRole("link", { name: "在结构化检索中查看更多" })).toHaveAttribute(
    "href",
    "/investigation/search",
  );
  await page.waitForTimeout(300);
  expect(calls.filter((call) => call.path === "/control/v1/search")).toHaveLength(1);
});

test("an unknown write waits under 待我处理 and is retried exactly from there", async ({
  page,
}) => {
  await open(page);
  await expect(siteRow(page, "Alpha 官网")).toBeVisible();
  await page.evaluate(async () => {
    const { runtime, runFrozenWrite } = window.__xshieldE2E;
    const keys: string[] = [];
    Reflect.set(window, "__e2eKeys", keys);
    let attempts = 0;
    const operation = runtime.pending.freeze({
      label: "创建案件",
      method: "POST",
      path: "/control/v1/cases",
      body: { purpose: "核对合成请求" },
      idempotencyKey: "e2e-operation-key-0001",
      execute: async (_client, _signal, key) => {
        keys.push(key);
        attempts += 1;
        if (attempts === 1) throw new TypeError("offline");
        return {
          request_id: "req_018f2a3b-4c5d-7000-8000-000000000001",
          tenant_id: "tenant_demo",
          site_id: "site_demo",
        };
      },
    });
    await runFrozenWrite(runtime.store, runtime.pending, operation.id);
  });
  const row = todo(page)
    .getByRole("list", { name: "待处理事项" })
    .getByRole("listitem")
    .filter({ hasText: "结果未知：创建案件" });
  await expect(row).toContainText("POST /control/v1/cases · 幂等键 e2e-operation-key-0001");
  await expect(row.getByRole("link", { name: "前往原页面" })).toHaveAttribute("href", "/cases");
  // It is listed first: it is lost on reload, so it is the most urgent thing on the page.
  await expect(
    todo(page).getByRole("list", { name: "待处理事项" }).getByRole("listitem").first(),
  ).toContainText("结果未知");
  await row.getByRole("button", { name: "原样重试" }).click();
  await expect(row).toHaveCount(0);
  await expect(page.getByText(/已由服务端确认/)).toBeVisible();
  expect(await page.evaluate(() => Reflect.get(window, "__e2eKeys"))).toEqual([
    "e2e-operation-key-0001",
    "e2e-operation-key-0001",
  ]);
  expect((await seamState(page)).pending).toBe(0);
});

test("a snapshot for another tenant ends the session; a malformed one is a contract failure", async ({
  page,
}) => {
  let mode: "drift" | "extra" = "extra";
  await open(page, {
    override: (url) =>
      url.pathname !== "/control/v1/workbench/overview"
        ? undefined
        : mode === "extra"
          ? { body: { ...workbenchOverviewFixture(), unexpected: true } }
          : { body: workbenchOverviewFixture({ tenant_id: "tenant_other" }) },
  });
  const failure = page.getByRole("alert").filter({ hasText: "工作台快照读取失败" });
  await expect(failure).toContainText("INVALID_RESPONSE");
  // The other sources still answer: a strict decoder fails one source, not the page.
  await expect(todo(page).getByText("原文访问申请待审批")).toBeVisible();
  mode = "drift";
  await failure.getByRole("button", { name: "重试" }).click();
  await expect(page.getByRole("status")).toContainText("响应范围校验失败");
  await expect(page.getByRole("heading", { name: "连接管理服务" })).toBeVisible();
  expect(await seamState(page)).toMatchObject({ status: "disconnected", queries: 0, pending: 0 });
});
