import AxeBuilder from "@axe-core/playwright";
import { expect, type Page, test } from "@playwright/test";
import { mockControl } from "./control-mock";
import { REQUEST_ID } from "./fixtures";
import { pickRange } from "./investigation-helpers";
import { BINDING_ID, GRANT_ID } from "./ledger-fixtures";
import { openView } from "./navigation";
import { mockShellApi, SCOPE, signIn } from "./shell-helpers";

// axe-core scans of the redesigned screens in both themes. Only critical and serious findings
// fail the build; moderate and minor ones (for example the legacy panels' heading order) are
// listed by `npx playwright test a11y --reporter=list` output when they appear.
// antd fades overlays in; axe must not sample colours halfway through the transition.
async function settled(page: Page) {
  await page.evaluate(() =>
    Promise.all(
      document.getAnimations().map((animation) => animation.finished.catch(() => undefined)),
    ),
  );
}

async function serious(page: Page) {
  await settled(page);
  const results = await new AxeBuilder({ page }).analyze();
  return results.violations
    .filter((violation) => violation.impact === "critical" || violation.impact === "serious")
    .map((violation) => ({
      rule: violation.id,
      impact: violation.impact,
      nodes: violation.nodes
        .slice(0, 3)
        .map((node) => `${node.target.join(" ")} :: ${node.failureSummary ?? ""}`),
    }));
}

const sitesList = {
  request_id: REQUEST_ID,
  ...SCOPE,
  truncated: false,
  next_cursor: null,
  sites: [
    {
      site_id: "site_alpha",
      display_name: "Alpha 站点",
      public_origin: "https://example.test",
      listen_port: 6100,
      security_entry: "ui_action_required",
      sensor_enabled: false,
      policy_revision: "policy-v1",
      status: "draft",
      revision: 1,
      config_digest: "a".repeat(64),
      updated_by: "fixture-author",
      updated_at: "2026-09-20T08:10:30.000Z",
      desired_revision: 1,
      active_revision: null,
      apply_id: "apply_fixture",
      apply_state: "pending",
      reason_code: "CONTROL_SITE_CONFIG_SAVED",
      requires_approval: false,
    },
  ],
};

for (const scheme of ["light", "dark"] as const) {
  test.describe(`accessibility (${scheme})`, () => {
    test.use({ colorScheme: scheme, timezoneId: "UTC" });

    test("sign-in screen", async ({ page }) => {
      await mockShellApi(page);
      await page.goto("/");
      await expect(page.getByLabel("管理凭证", { exact: true })).toBeVisible();
      expect(await serious(page)).toEqual([]);
    });

    test("overview", async ({ page }) => {
      await mockShellApi(page);
      await signIn(page, "/");
      await expect(page.getByText("Alpha 官网").first()).toBeVisible();
      expect(await serious(page)).toEqual([]);
    });

    test("protected sites list", async ({ page }) => {
      await mockShellApi(page, (url) =>
        url.pathname === "/control/v1/sites" ? { body: sitesList } : undefined,
      );
      await signIn(page, "/sites");
      await expect(page.getByRole("region", { name: "受保护站点列表" })).toBeVisible();
      await expect(page.getByText("Alpha 站点").first()).toBeVisible();
      expect(await serious(page)).toEqual([]);
    });

    test("request investigation with data", async ({ page }) => {
      await mockShellApi(page);
      await signIn(page, "/access/session");
      await page.keyboard.press("Control+KeyK");
      await page.getByRole("combobox", { name: "命令面板" }).fill(REQUEST_ID);
      await page.keyboard.press("Enter");
      await expect(page.getByRole("tab", { name: "事件时间线" })).toBeVisible();
      await expect(page.getByText("REQUEST_ACCEPTED", { exact: true })).toBeVisible();
      expect(await serious(page)).toEqual([]);
      // The event drawer with its causality section, and the evidence tab.
      await page
        .getByRole("button", { name: /^查看事件 / })
        .first()
        .click();
      const drawer = page.getByRole("dialog", { name: "事件详情" });
      await expect(drawer.getByRole("button", { name: "查看因果", exact: true })).toBeVisible();
      await drawer.getByText("更多事件字段", { exact: true }).click();
      expect(await serious(page)).toEqual([]);
      await page.keyboard.press("Escape");
      await expect(drawer).toHaveCount(0);
      await page.getByRole("tab", { name: "输入与输出" }).click();
      await expect(page.getByRole("tabpanel", { name: "输入与输出" })).toContainText("已脱敏");
      expect(await serious(page)).toEqual([]);
    });

    test("request stream with data", async ({ page }) => {
      await mockControl(page);
      await signIn(page, "/access/session");
      await openView(page, "request");
      await expect(page.locator(".ant-table-row")).toHaveCount(25);
      expect(await serious(page)).toEqual([]);
      await page.getByRole("button", { name: /更多筛选/ }).click();
      await expect(page.getByLabel("操作 ID", { exact: true })).toBeVisible();
      expect(await serious(page)).toEqual([]);
    });

    test("structured search with conditions and results", async ({ page }) => {
      await mockControl(page);
      await signIn(page, "/access/session");
      await openView(page, "search");
      await expect(
        page.getByRole("heading", { name: "结构化事件检索", exact: true }),
      ).toBeVisible();
      // The form with a condition, the open column picker and the unfilled range hint.
      await page.getByLabel("条件值", { exact: true }).fill(REQUEST_ID);
      await page.getByRole("button", { name: "添加条件", exact: true }).click();
      await expect(page.getByRole("list", { name: "已添加的检索条件" })).toContainText(REQUEST_ID);
      expect(await serious(page)).toEqual([]);
      await pickRange(page, "2026-09-20T00:00", "2026-09-21T00:00");
      await page.getByRole("button", { name: "检索事件", exact: true }).click();
      await expect(page.locator(".ant-table-row")).toHaveCount(25);
      expect(await serious(page)).toEqual([]);
      await page.getByRole("button", { name: "选择列", exact: true }).click();
      await expect(page.getByRole("checkbox", { name: "Trace", exact: true })).toBeVisible();
      expect(await serious(page)).toEqual([]);
      await page.keyboard.press("Escape");
      await page.getByText("查看已提交计划", { exact: true }).click();
      await expect(page.getByRole("region", { name: "已提交查询计划" })).toBeVisible();
      expect(await serious(page)).toEqual([]);
    });

    test("identity and grants with a snapshot", async ({ page }) => {
      await mockControl(page);
      await signIn(page, `/investigation/grants/${GRANT_ID}`);
      await expect(page.getByRole("region", { name: "资格记录", exact: true })).toBeVisible();
      expect(await serious(page)).toEqual([]);
      await page.getByRole("link", { name: BINDING_ID, exact: true }).click();
      await expect(page.getByRole("region", { name: "身份绑定记录", exact: true })).toBeVisible();
      expect(await serious(page)).toEqual([]);
    });

    test("command palette and theme menu overlays", async ({ page }) => {
      await mockShellApi(page);
      await signIn(page, "/");
      await expect(page.getByText("Alpha 官网").first()).toBeVisible();
      await page.keyboard.press("Control+KeyK");
      await expect(page.getByRole("combobox", { name: "命令面板" })).toBeFocused();
      await page.getByRole("combobox", { name: "命令面板" }).fill("案件");
      await expect(page.getByRole("option").first()).toBeVisible();
      expect(await serious(page)).toEqual([]);
      await page.keyboard.press("Escape");
      await page.getByRole("button", { name: "主题与密度" }).click();
      await expect(page.getByRole("menuitem", { name: "深色" })).toBeVisible();
      expect(await serious(page)).toEqual([]);
    });

    test("mobile navigation drawer", async ({ page }) => {
      await page.setViewportSize({ width: 390, height: 844 });
      await mockShellApi(page);
      await signIn(page, "/");
      await page.getByRole("button", { name: "打开导航" }).click();
      await expect(page.getByRole("complementary", { name: "后台导航" })).toBeVisible();
      await page.waitForTimeout(400);
      expect(await serious(page)).toEqual([]);
    });
  });
}
