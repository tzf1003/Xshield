// The site list at /sites (docs/06 6.4.8): one row per site with its gateway state and its 24-hour figures,
// a row that opens the site, and the first-site prompt when there is none.

import { expect, test } from "@playwright/test";
import { expectNoAxeViolations, setTheme, type Theme } from "./helpers/axe.ts";
import { mockApi, reply } from "./helpers/mock-api.ts";
import { freezeClock } from "./helpers/sites-flow.ts";

test("each site row shows its gateway state, mode and 24-hour figures", async ({ page }) => {
  await freezeClock(page);
  await mockApi(page);
  await page.goto("/sites");

  const table = page.getByRole("table", { name: "站点列表" });
  const rowOf = (name: string) =>
    table.getByRole("row").filter({ has: page.getByRole("link", { name, exact: true }) });

  // emr: enforce, one of its three gateways is behind the current version 13.
  await expect(rowOf("emr")).toContainText("emr.example.com");
  await expect(rowOf("emr")).toContainText("◌ v13 · 1/2 个网关已生效");
  await expect(rowOf("emr")).toContainText("21 拦截");
  await expect(rowOf("emr")).toContainText("9,812");

  // juice: observing since six days and four hours before the frozen clock, every gateway loaded.
  await expect(rowOf("juice")).toContainText("观察 6 天 4 小时");
  await expect(rowOf("juice")).toContainText("● v7 · 2/2 个网关已生效");
  await expect(rowOf("juice")).toContainText("14 本应拦截");
  await expect(page.getByText("2 个站点")).toBeVisible();
});

test("a row opens the site page", async ({ page }) => {
  await freezeClock(page);
  await mockApi(page);
  await page.goto("/sites");

  await page.getByRole("link", { name: "juice", exact: true }).click();

  await expect(page).toHaveURL(/\/sites\/juice$/);
  await expect(page.getByRole("heading", { level: 1, name: "juice" })).toBeVisible();
  await expect(page.getByRole("tab", { name: "概览" })).toHaveAttribute("aria-selected", "true");
});

test("the new-site button opens the new-site page", async ({ page }) => {
  await mockApi(page);
  await page.goto("/sites");

  await page.getByRole("link", { name: "新建站点" }).click();

  await expect(page).toHaveURL(/\/sites\/new$/);
  await expect(page.getByRole("heading", { level: 1, name: "新建站点" })).toBeVisible();
});

test("an empty list asks for the first site", async ({ page }) => {
  await mockApi(page, { overrides: { "/api/sites": { sites: [] } } });
  await page.goto("/sites");

  await expect(page.getByText("还没有站点")).toBeVisible();
  await expect(page.getByRole("table", { name: "站点列表" })).toHaveCount(0);
  // One in the page head, one in the empty state.
  await expect(page.getByRole("link", { name: "新建站点" })).toHaveCount(2);
});

test("a failed load shows the error with its code", async ({ page }) => {
  await mockApi(page, { overrides: { "/api/sites": reply(500, { error: "INTERNAL" }) } });
  await page.goto("/sites");

  await expect(page.getByRole("alert")).toContainText("控制面出错，请稍后重试");
  await expect(page.getByRole("alert")).toContainText("INTERNAL");
});

for (const theme of ["light", "dark"] satisfies Theme[]) {
  test(`the site list passes axe in the ${theme} theme`, async ({ page }) => {
    await freezeClock(page);
    await mockApi(page);
    await setTheme(page, theme);
    await page.goto("/sites");
    await expect(page.getByRole("table", { name: "站点列表" })).toBeVisible();
    await expectNoAxeViolations(page);
  });
}
