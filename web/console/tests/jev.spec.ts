// The Jev page (docs/06 6.4.6): the health card, the latency and confidence histograms, the answers by
// hour, the quick chips with their counts, the condition line and the list of Jev calls, from the
// fixtures, with axe in both themes.

import { expect, type Locator, type Page, test } from "@playwright/test";
import { expectNoAxeViolations, setTheme, type Theme } from "./helpers/axe.ts";
import { IDS, useFixtures } from "./helpers/trace.ts";

function jevList(page: Page): Locator {
  return page.getByRole("table", { name: "Jev 调用列表" }).locator("tbody tr");
}

/** The chip of the quick filters, by its name (the count is part of the name). */
function chip(page: Page, name: string): Locator {
  return page.getByRole("button", { name: new RegExp(`^${name}`) });
}

/** Sums the numeric cells of each column of a table, column 0 excluded. */
async function columnSums(table: Locator): Promise<number[]> {
  return table.locator("tbody tr").evaluateAll((rows) => {
    const totals: number[] = [];
    for (const row of rows) {
      row.querySelectorAll("td").forEach((cell, index) => {
        if (index === 0) return;
        totals[index - 1] =
          (totals[index - 1] ?? 0) + Number((cell.textContent ?? "0").replace(/,/g, ""));
      });
    }
    return totals;
  });
}

test("the health card reads the status: healthy, all calls succeeded, the last failure and the line", async ({
  page,
}) => {
  await useFixtures(page);
  await page.goto("/jev");

  await expect(page.getByText("健康", { exact: true })).toBeVisible();
  await expect(page.locator(".jev-health-head").getByText("正常")).toBeVisible();
  await expect(page.getByText("42 次，全部成功")).toBeVisible();
  await expect(page.getByText("p50 540 ms · p95 910 ms")).toBeVisible();
  await expect(page.getByText("没有失败")).toBeVisible();
  await expect(page.getByText("21:02:00 超时（emr）")).toBeVisible();
  await expect(page.getByText("经 AI Gateway · ai-gateway.vercel.sh")).toBeVisible();
  await expect(page.getByText("typesafe-ai/jev")).toBeVisible();
});

test("the latency and confidence histograms and the hourly bars render from the statistics", async ({
  page,
}) => {
  await useFixtures(page);
  await page.goto("/jev");

  await expect(
    page.getByRole("img", { name: "耗时直方图，共 478 次调用，超时 3,000 毫秒" }),
  ).toBeVisible();
  await expect(page.getByText("p50 569 ms · p95 1,703 ms")).toBeVisible();
  await expect(
    page.getByRole("img", { name: "置信度直方图，共 478 次调用，低于 70% 的 60 次" }),
  ).toBeVisible();
  await expect(page.getByText("低于 70%：60 次")).toBeVisible();
  await expect(
    page.getByRole("img", { name: "按小时的 Jev 结论：24 个时段，共 478 次调用" }),
  ).toBeVisible();
  await expect(page.getByText("不可用", { exact: true }).first()).toBeVisible();
});

test("the hourly table adds up to the answers, and its unavailable column counts the UNKNOWN answers too", async ({
  page,
}) => {
  await useFixtures(page);
  await page.goto("/jev");

  const hourly = page.locator(".jev-hourly-card");
  await hourly.getByRole("button", { name: "以表格查看" }).click();
  const table = page.getByRole("table", { name: "按小时的 Jev 结论（表格）" });
  await expect(table.locator("tbody tr")).toHaveCount(24);

  // Columns after the hour: 通过, 拒绝, 不可用. The fixture's unavailable calls are its 3 UNKNOWN answers.
  const [allow, deny, unavailable] = await columnSums(table);
  expect(allow).toBe(392);
  expect(deny).toBe(83);
  expect(unavailable).toBe(3);
});

test("the latency histogram can be read as a table with its 100 ms buckets", async ({ page }) => {
  await useFixtures(page);
  await page.goto("/jev");

  const latency = page.locator(".jev-hist-card").first();
  await latency.getByRole("button", { name: "以表格查看" }).click();
  const table = page.getByRole("table", { name: "耗时分布（100 ms 一档）（表格）" });
  await expect(table.locator("tbody tr")).toHaveCount(31);
  await expect(table.getByRole("row", { name: /^0–100 ms/ })).toBeVisible();
});

test("the chips show the counts of the statistics, and a chip narrows the list", async ({
  page,
}) => {
  await useFixtures(page);
  await page.goto("/jev");

  await expect(chip(page, "全部")).toContainText("478");
  await expect(chip(page, "拒绝")).toContainText("83");
  await expect(chip(page, "通过")).toContainText("392");
  await expect(chip(page, "失败")).toContainText("14");
  await expect(chip(page, "置信度低")).toContainText("60");

  await expect(jevList(page)).toHaveCount(8);
  await expect(page.getByRole("status").filter({ hasText: "已显示 8 条" })).toBeVisible();

  await chip(page, "拒绝").click();
  await expect(page).toHaveURL(/chip=blocked/);
  await expect(chip(page, "拒绝")).toHaveAttribute("aria-pressed", "true");
  await expect(jevList(page)).toHaveCount(4);
  await expect(jevList(page).filter({ hasText: "拒绝" })).toHaveCount(4);
});

test("the condition line narrows the Jev list with the request filter syntax", async ({ page }) => {
  await useFixtures(page);
  await page.goto("/jev");

  const condition = page.getByRole("textbox", { name: "筛选条件" });
  await condition.fill("decision:jev_allow");
  await condition.press("Enter");

  await expect(page).toHaveURL(/q=decision(%3A|:)jev_allow/);
  await expect(jevList(page)).toHaveCount(2);
});

test("a row opens its request on the Jev tab", async ({ page }) => {
  await useFixtures(page);
  await page.goto("/jev");

  const row = jevList(page).filter({ hasText: "/rest/basket/6" });
  await row.getByRole("link", { name: "GET /rest/basket/6" }).click();

  await expect(page).toHaveURL(new RegExp(`/requests/${IDS.basket}\\?tab=jev`));
  await expect(page.getByRole("tab", { name: "Jev 上下文" })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  await expect(page.getByRole("radio", { name: "结构化" })).toBeChecked();
});

for (const theme of ["light", "dark"] satisfies Theme[]) {
  test(`the Jev page passes axe in the ${theme} theme, with its tables open`, async ({ page }) => {
    await useFixtures(page);
    await setTheme(page, theme);
    await page.goto("/jev");
    await expect(page.getByRole("img", { name: /耗时直方图/ })).toBeVisible();
    await expect(jevList(page)).toHaveCount(8);
    await expectNoAxeViolations(page);

    await page.locator(".jev-hourly-card").getByRole("button", { name: "以表格查看" }).click();
    await page
      .locator(".jev-hist-card")
      .first()
      .getByRole("button", { name: "以表格查看" })
      .click();
    await expect(page.getByRole("table", { name: "按小时的 Jev 结论（表格）" })).toBeVisible();
    await expectNoAxeViolations(page);
  });
}
