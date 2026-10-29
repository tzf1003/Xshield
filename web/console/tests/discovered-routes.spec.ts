import AxeBuilder from "@axe-core/playwright";
import { expect, type Page, test } from "@playwright/test";
import { mockSite, signInAt } from "./site-fixtures";

const bar = (page: Page) => page.getByRole("region", { name: "未保存的修改" });
const header = (page: Page) => page.getByRole("button", { name: "从观察流量导入路由" });
const panel = (page: Page) => page.getByRole("region", { name: "从观察流量导入路由" });

async function discover(page: Page) {
  await header(page).click();
  await panel(page).getByRole("button", { name: "发现", exact: true }).click();
}

test("discovers unmatched traffic and imports only the literal, route-capable rows", async ({
  page,
}) => {
  const mock = await mockSite(page);
  await signInAt(page, "/sites/site_alpha/routes");
  await expect(page.getByText("共 2 条路由（最多 256）")).toBeVisible();
  await discover(page);

  const templated = panel(page).locator(".ant-table-row", { hasText: "/orders/{id}" });
  const literal = panel(page).locator(".ant-table-row", { hasText: "/webhooks/stripe" });
  await expect(templated).toBeVisible();
  await expect(literal).toBeVisible();
  await expect(templated).toContainText("含参数，仅供参考，不自动导入");

  // A template is a read-only hint: its row cannot be selected for import.
  await expect(templated.getByRole("checkbox")).toBeDisabled();
  await expect(panel(page).getByRole("button", { name: /导入所选/ })).toBeDisabled();

  await literal.getByRole("checkbox").check();
  await expect(
    panel(page).getByRole("button", { name: "导入所选（1）", exact: true }),
  ).toBeEnabled();
  await panel(page).getByRole("button", { name: "导入所选（1）", exact: true }).click();

  // Importing only edits the draft; nothing is sent until the workspace is saved.
  expect(mock.calls.filter((call) => call.startsWith("PUT"))).toHaveLength(0);
  await expect(bar(page)).toBeVisible();
  await expect(page.getByText("共 3 条路由（最多 256）")).toBeVisible();
  // The imported draft route now has its own editor row in the main table, distinct from the
  // still-visible discovery result it came from.
  const importedRow = page.getByRole("row", { name: /编辑路由 webhooks\.stripe/ });
  await expect(importedRow).toBeVisible();
  await expect(importedRow).toContainText("POST");
});

test("an unsupported method stays visible but cannot be selected for import", async ({ page }) => {
  await mockSite(page, {
    discoveredRoutes: [{ method: "HEAD", path_template: "/healthz", hits: 3 }],
  });
  await signInAt(page, "/sites/site_alpha/routes");
  await discover(page);
  const row = panel(page).locator(".ant-table-row", { hasText: "/healthz" });
  await expect(row).toContainText("该方法不受路由支持，不可导入");
  await expect(row.getByRole("checkbox")).toBeDisabled();
});

test("an empty window reports no unmatched traffic instead of an error", async ({ page }) => {
  await mockSite(page, { discoveredRoutes: [] });
  await signInAt(page, "/sites/site_alpha/routes");
  await discover(page);
  await expect(panel(page).getByText("当前窗口内没有未覆盖的端点")).toBeVisible();
});

for (const scheme of ["light", "dark"] as const) {
  test.describe(`discovered routes accessibility (${scheme})`, () => {
    test.use({ colorScheme: scheme });
    test("the expanded panel and its results have no serious violations", async ({ page }) => {
      await mockSite(page);
      await signInAt(page, "/sites/site_alpha/routes");
      await discover(page);
      await expect(panel(page).getByText("/webhooks/stripe")).toBeVisible();
      await page.waitForTimeout(300);
      const results = await new AxeBuilder({ page }).include(".xs-discovered-routes").analyze();
      const serious = results.violations
        .filter((violation) => violation.impact === "critical" || violation.impact === "serious")
        .map((violation) => violation.id);
      expect(serious).toEqual([]);
    });
  });
}
