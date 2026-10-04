import { expect, type Page, test } from "@playwright/test";
import { mockSite, revisionsBody, type SiteMock, siteConfig } from "./site-fixtures";
import { sessionBody } from "./shell-helpers";

// Cookie-session mode: roles come from the server session, so what is offered, and above all
// what is read, follows the roles. Hiding is only a convenience; the server authorizes each call.

async function asRoles(page: Page, roles: string[], init: Partial<SiteMock> = {}) {
  const mock = await mockSite(page, {
    revisions: [
      { revision: 4, config: siteConfig({ display_name: "Alpha 新" }) },
      { revision: 3, config: siteConfig() },
    ],
    state: {
      desired_revision: 4,
      active_revision: 3,
      apply_state: "pending",
      requires_approval: true,
      reason_code: "CONTROL_SITE_APPROVAL_REQUIRED",
    },
    ...init,
  });
  const inner = mock.intercept;
  mock.intercept = async (route, url) => {
    if (url.pathname === "/control/v1/session" && route.request().method() === "GET") {
      await route.fulfill({ json: sessionBody(roles) });
      return true;
    }
    return (await inner?.(route, url)) ?? false;
  };
  return mock;
}

const tabs = (page: Page) =>
  page.getByRole("navigation", { name: "站点运营导航" }).getByRole("link").allTextContents();
const reads = (mock: SiteMock) =>
  mock.calls
    .filter((call) => call.startsWith("GET /control/v1/sites/"))
    .map((call) => call.split("/").at(-1));

test("an observer reads status, revisions and health, and is offered no editor", async ({
  page,
}) => {
  const mock = await asRoles(page, ["observer"]);
  await page.goto("/sites/site_alpha/overview");
  await expect(page.getByRole("region", { name: "站点概况" })).toContainText("待审批");
  expect(await tabs(page)).toEqual(["概览", "策略与健康", "发布", "审计"]);
  await expect(page.getByRole("region", { name: "未保存的修改" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "刷新站点状态" })).toBeVisible();
  expect(new Set(reads(mock))).toEqual(new Set(["status", "revisions"]));

  await page
    .getByRole("navigation", { name: "站点运营导航" })
    .getByRole("link", { name: "发布", exact: true })
    .click();
  await expect(page.getByRole("region", { name: "修订历史" })).toBeVisible();
  for (const name of ["验证配置", "批准并应用", "应用期望版本", "回滚上一版本"]) {
    await expect(page.getByRole("button", { name })).toHaveCount(0);
  }
  // The health read is the observer's, explicit and audited.
  await page
    .getByRole("navigation", { name: "站点运营导航" })
    .getByRole("link", { name: "策略与健康", exact: true })
    .click();
  await expect(page.getByLabel("健康检查路径", { exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "读取健康状态" }).click();
  await expect(page.getByText("观察于")).toBeVisible();
  expect(mock.calls.some((call) => call.endsWith("/config"))).toBe(false);
});

test("a deep link to an editor section explains the missing role and reads nothing", async ({
  page,
}) => {
  const mock = await asRoles(page, ["observer"]);
  await page.goto("/sites/site_alpha/network");
  await expect(page.getByText("当前角色没有权限查看“网络”。")).toBeVisible();
  await expect(page.getByRole("button", { name: "转到“概览”" })).toBeVisible();
  await expect(page.getByLabel("站点名称", { exact: true })).toHaveCount(0);
  expect(mock.calls.some((call) => call.endsWith("/config"))).toBe(false);
});

test("a system administrator edits configuration; state and revisions need the observer role", async ({
  page,
}) => {
  const mock = await asRoles(page, ["system_admin"]);
  await page.goto("/sites/site_alpha/network");
  await expect(page.getByLabel("站点名称", { exact: true })).toHaveValue("Alpha 官网");
  expect(await tabs(page)).toEqual([
    "概览",
    "网络",
    "安全入口",
    "路由与操作",
    "身份",
    "加密",
    "WAF 与限流",
    "策略与健康",
    "发布",
    "审计",
  ]);
  expect(new Set(reads(mock))).toEqual(new Set(["config"]));
  await page
    .getByRole("navigation", { name: "站点运营导航" })
    .getByRole("link", { name: "发布", exact: true })
    .click();
  for (const name of ["验证配置", "批准并应用", "应用期望版本", "回滚上一版本"]) {
    await expect(page.getByRole("button", { name })).toHaveCount(0);
  }
  await expect(page.getByRole("region", { name: "修订历史" })).toHaveCount(0);
  expect(mock.calls.some((call) => call.endsWith("/revisions") || call.endsWith("/status"))).toBe(
    false,
  );
});

test("an approver sees only the release page and reads nothing before acting", async ({ page }) => {
  const mock = await asRoles(page, ["policy_approver"]);
  await page.goto("/sites/site_alpha/releases");
  await expect(page.getByRole("region", { name: "站点运行与发布" })).toBeVisible();
  expect(await tabs(page)).toEqual(["发布"]);
  await expect(page.getByText("状态及修订读取需要 observer 角色")).toBeVisible();
  await expect(page.getByRole("button", { name: "批准并应用" })).toBeEnabled();
  await expect(page.getByRole("button", { name: "验证配置" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "应用期望版本" })).toHaveCount(0);
  expect(reads(mock)).toEqual([]);
  await page.getByRole("button", { name: "批准并应用" }).click();
  await expect
    .poll(() => mock.writes.map((write) => write.path.split("/").at(-1)))
    .toEqual(["approve"]);
  expect(mock.writes[0]?.key).toBeTruthy();
});

test("a role without any site role gets the explanation and no request", async ({ page }) => {
  const mock = await asRoles(page, ["investigator"]);
  await page.goto("/sites/site_alpha/overview");
  await expect(page.getByText("当前角色没有权限查看“概览”。")).toBeVisible();
  expect(await tabs(page)).toEqual([]);
  expect(reads(mock)).toEqual([]);
});

test("revisions are read with the reviewer's role and shown newest first", async ({ page }) => {
  const mock = await asRoles(page, ["observer"], {
    revisions: [
      { revision: 3, config: siteConfig() },
      { revision: 4, config: siteConfig({ display_name: "Alpha 新" }) },
    ],
  });
  await page.goto("/sites/site_alpha/releases");
  const rows = page.getByRole("region", { name: "修订历史" }).locator("tbody tr.ant-table-row");
  await expect(rows).toHaveCount(2);
  await expect(rows.first()).toContainText("r4");
  await expect(rows.first()).toContainText("暂存");
  await expect(rows.last()).toContainText("edge 在用");
  await rows
    .first()
    .getByRole("button", { name: /展开|Expand/ })
    .click();
  await expect(page.getByText("站点名称")).toBeVisible();
  void revisionsBody;
  expect(mock.writes).toEqual([]);
});
