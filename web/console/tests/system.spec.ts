// The system page (docs/06 6.4.11): each gateway's counters and its loss windows with their dropped,
// bypass-dropped and write-error counts, the storage tab with the daily partitions and the log gaps,
// the tabs, and axe in both themes.

import { expect, type Locator, type Page, test } from "@playwright/test";
import { expectNoAxeViolations, setTheme, type Theme } from "./helpers/axe.ts";
import { useFixtures } from "./helpers/trace.ts";

function edgeBody(page: Page, edge: string): Locator {
  return page
    .getByRole("table", { name: "网关实例" })
    .locator("tbody")
    .filter({ has: page.getByText(edge, { exact: true }) });
}

/** The two-column row of a loss window, found by its start and end. */
function gapRow(table: Locator, start: string): Locator {
  return table.locator("tbody tr").filter({ hasText: start });
}

test("the gateway tab lists each instance, and a gateway's detail shows its loss windows", async ({
  page,
}) => {
  await useFixtures(page);
  await page.goto("/system");
  await expect(page.getByRole("table", { name: "网关实例" }).locator("tbody")).toHaveCount(3);
  await expect(edgeBody(page, "edge-3").getByText("离线")).toBeVisible();
  await expect(edgeBody(page, "edge-1").getByText("在线")).toBeVisible();

  await edgeBody(page, "edge-1").getByRole("button", { name: "详情" }).click();
  const siteLoad = page.getByRole("table", { name: "这个实例的站点加载结果" });
  await expect(siteLoad.getByText("已加载 v13")).toBeVisible();
  await expect(siteLoad.getByText("已加载 v7")).toBeVisible();
  await expect(siteLoad.getByText(/已加载 v13（\d{2}-\d{2} \d{2}:\d{2}:\d{2}）/)).toBeVisible();

  const gaps = page.getByRole("table", { name: "这个实例的日志缺口" });
  const window = gapRow(gaps, "11-01 21:10:00 – 21:12");
  await expect(window).toBeVisible();
  await expect(window.getByRole("cell", { name: "31", exact: true })).toBeVisible();
  await expect(window.getByRole("cell", { name: "6", exact: true })).toBeVisible();
  await expect(window.getByRole("cell", { name: "0", exact: true })).toBeVisible();
});

test("a gateway's write errors show in its loss window, even when the window is older than a day", async ({
  page,
}) => {
  await useFixtures(page);
  await page.goto("/system");
  await edgeBody(page, "edge-2").getByRole("button", { name: "详情" }).click();

  const gaps = page.getByRole("table", { name: "这个实例的日志缺口" });
  const window = gapRow(gaps, "10-31 19:20:00 – 19:26");
  await expect(window).toBeVisible();
  await expect(window.getByRole("cell", { name: "5", exact: true })).toBeVisible();
});

test("the storage tab lists the daily partitions, the log gaps and the storage totals", async ({
  page,
}) => {
  await useFixtures(page);
  await page.goto("/system?tab=storage");

  await expect(page.getByText("5 个，共 5,294,464 行，4150.5 MiB")).toBeVisible();
  await expect(page.getByText("2026-10-26 09:20:00.000")).toBeVisible();
  await expect(page.getByText("7 天（代码默认值）")).toBeVisible();

  const partitions = page.getByRole("table", { name: "日志分区" });
  await expect(partitions.locator("tbody tr")).toHaveCount(5);
  await expect(
    partitions.locator("tbody tr").filter({ hasText: "decision_log_p20261101" }),
  ).toContainText("今天");
  await expect(
    partitions.locator("tbody tr").filter({ hasText: "decision_log_p20261102" }),
  ).toContainText("明天");
  await expect(
    partitions.locator("tbody tr").filter({ hasText: "decision_log_p20261103" }),
  ).toContainText("2 天后");

  const gaps = page.getByRole("table", { name: "日志缺口" });
  await expect(gaps.locator("tbody tr")).toHaveCount(2);
  await expect(gapRow(gaps, "11-01 21:10:00 – 21:12")).toContainText("edge-1");
  await expect(gapRow(gaps, "10-31 19:20:00 – 19:26")).toContainText("edge-2");
  await expect(page.getByText("缺口来自网关的心跳，网关重启后清空。")).toBeVisible();
});

test("the tabs switch between the gateways, the storage, the parameters and the import", async ({
  page,
}) => {
  await useFixtures(page);
  await page.goto("/system");
  await expect(page.getByRole("tab", { name: "网关" })).toHaveAttribute("aria-selected", "true");

  await page.getByRole("tab", { name: "日志存储" }).click();
  await expect(page).toHaveURL(/tab=storage/);
  await expect(page.getByRole("table", { name: "日志分区" })).toBeVisible();

  await page.getByRole("tab", { name: "运行参数" }).click();
  await expect(page).toHaveURL(/tab=params/);
  await expect(page.getByText("站点可覆盖的默认值")).toBeVisible();
  await expect(page.getByRole("table", { name: "固定参数" })).toBeVisible();

  await page.getByRole("tab", { name: "导入" }).click();
  await expect(page).toHaveURL(/tab=import/);
});

for (const theme of ["light", "dark"] satisfies Theme[]) {
  test(`the gateway tab passes axe in the ${theme} theme, with a detail open`, async ({ page }) => {
    await useFixtures(page);
    await setTheme(page, theme);
    await page.goto("/system");
    await expect(page.getByRole("table", { name: "网关实例" })).toBeVisible();
    await expectNoAxeViolations(page);

    await edgeBody(page, "edge-1").getByRole("button", { name: "详情" }).click();
    await expect(page.getByRole("table", { name: "这个实例的日志缺口" })).toBeVisible();
    await expectNoAxeViolations(page);
  });

  test(`the storage tab passes axe in the ${theme} theme`, async ({ page }) => {
    await useFixtures(page);
    await setTheme(page, theme);
    await page.goto("/system?tab=storage");
    await expect(page.getByRole("table", { name: "日志分区" })).toBeVisible();
    await expectNoAxeViolations(page);
  });
}
