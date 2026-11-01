// The request trace (docs/06 6.4.3): the 本应拦截 quick filter and its count, j/k and Enter in the list,
// the filter in the address after a reload, bypass and unknown-site rows, the log-gap notice, and axe.

import { expect, type Locator, type Page, test } from "@playwright/test";
import { expectNoAxeViolations, setTheme, type Theme } from "./helpers/axe.ts";
import { servedRequests } from "./helpers/mock-api.ts";
import { requestList } from "./helpers/fixtures.ts";
import { IDS, useFixtures } from "./helpers/trace.ts";

function listRows(page: Page): Locator {
  return page.getByRole("table", { name: "请求列表" }).locator("tbody tr");
}

function chip(page: Page, name: RegExp): Locator {
  return page.getByRole("group", { name: "快捷筛选" }).getByRole("button", { name });
}

test("本应拦截 shows only would-block rows, and its count matches them", async ({ page }) => {
  await useFixtures(page);
  await page.goto("/requests");
  await expect(listRows(page)).toHaveCount(41);

  const wouldBlock = chip(page, /^本应拦截/);
  await expect(wouldBlock).toContainText("5");
  await wouldBlock.click();

  await expect(page).toHaveURL(/chip=would_block/);
  await expect(wouldBlock).toHaveAttribute("aria-pressed", "true");
  await expect(listRows(page)).toHaveCount(5);
  await expect(listRows(page).filter({ hasText: "本应拦截" })).toHaveCount(5);

  const query = servedRequests(page)
    .filter((call) => call.path === "/api/requests")
    .map((call) => call.query);
  expect(query.some((text) => text.includes("outcome=would_block"))).toBe(true);
  expect(query.some((text) => text.includes("scope=all"))).toBe(false);
});

test("j and k move the selection, and Enter opens the selected record", async ({ page }) => {
  await useFixtures(page);
  await page.goto("/requests");
  await expect(listRows(page)).toHaveCount(41);

  // Clicking the heading leaves the focus on the page, so the keys reach the list.
  await page.getByRole("heading", { level: 1, name: "请求追溯" }).click();
  await page.keyboard.press("j");
  await expect(page.locator(`#row-${IDS.newest}`)).toHaveAttribute("aria-selected", "true");
  await expect(page.getByRole("complementary", { name: "预览" })).toBeVisible();

  await page.keyboard.press("j");
  await expect(page.locator(`#row-${IDS.newest}`)).toHaveAttribute("aria-selected", "false");
  await expect(page.locator(`#row-req_01a1974369a07b01a988708e93340c1c`)).toHaveAttribute(
    "aria-selected",
    "true",
  );

  await page.keyboard.press("k");
  await expect(page.locator(`#row-${IDS.newest}`)).toHaveAttribute("aria-selected", "true");

  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(new RegExp(`/requests/${IDS.newest}$`));
  await expect(page.getByRole("heading", { level: 1, name: "/api/patients/7" })).toBeVisible();
});

test("Escape closes the preview panel", async ({ page }) => {
  await useFixtures(page);
  await page.goto("/requests");
  await page.getByRole("heading", { level: 1, name: "请求追溯" }).click();
  await page.keyboard.press("j");
  const preview = page.getByRole("complementary", { name: "预览" });
  await expect(preview).toBeVisible();

  await page.keyboard.press("Escape");
  await expect(preview).toBeHidden();
  await expect(page).not.toHaveURL(/peek=/);
});

test("the quick filter and the condition text stay in the address and after a reload", async ({
  page,
}) => {
  await useFixtures(page);
  await page.goto("/requests");

  await chip(page, /^本应拦截/).click();
  await expect(page).toHaveURL(/chip=would_block/);

  const condition = page.getByRole("textbox", { name: "筛选条件" });
  await condition.fill("method:GET");
  await condition.press("Enter");
  await expect(page).toHaveURL(/q=method(%3A|:)GET/);
  await expect(listRows(page)).toHaveCount(4);

  await page.reload();
  await expect(chip(page, /^本应拦截/)).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByRole("textbox", { name: "筛选条件" })).toHaveValue("method:GET");
  await expect(listRows(page)).toHaveCount(4);
});

test("the bypass switch shows bypass rows, and the 绕过 chip shows only them", async ({ page }) => {
  await useFixtures(page);
  await page.goto("/requests");

  await page.getByRole("switch", { name: "含绕过和未知站点的请求" }).click();
  await expect(page).toHaveURL(/scope=all/);
  await expect(listRows(page)).toHaveCount(49);

  await chip(page, /^绕过/).click();
  await expect(listRows(page)).toHaveCount(5);
  await expect(listRows(page).filter({ hasText: "绕过" })).toHaveCount(5);
});

test("the unknown-site note filters the list to unknown-site requests", async ({ page }) => {
  await useFixtures(page);
  await page.goto("/requests");

  const note = page.getByText("另有 3 条未知站点请求");
  await expect(note).toBeVisible();
  await note.getByRole("button", { name: "查看" }).click();

  await expect(page).toHaveURL(/decision(%3A|:)unknown_site/);
  await expect(listRows(page)).toHaveCount(3);
  await expect(listRows(page).filter({ hasText: "未知站点" })).toHaveCount(3);
});

test("a loss window in the time range is named above the list, with a way to the system page", async ({
  page,
}) => {
  await useFixtures(page);
  await page.goto("/requests");

  await expect(page.getByText("21:10–21:12 edge-1 有 31 条记录未写入")).toBeVisible();
  await expect(page.getByText("缺口历史来自网关心跳，网关重启后清空")).toBeVisible();
  await page.getByRole("link", { name: "查看系统" }).click();
  await expect(page).toHaveURL(/\/system$/);
});

test("the Jev column names each answer by its direction and confidence, and a failure by its short name", async ({
  page,
}) => {
  await useFixtures(page);
  await page.goto("/requests");
  await expect(listRows(page)).toHaveCount(41);

  const jevCell = (id: string) => page.locator(`#row-${id} td.rq-c-jev`);
  await expect(jevCell(IDS.basket)).toHaveText("越权 86%");
  await expect(jevCell(IDS.timeout)).toHaveText("超时");
  await expect(jevCell(IDS.callLimit)).toHaveText("达到上限");
});

test("a Jev confidence under 70% carries a 低 mark beside it", async ({ page }) => {
  const list = structuredClone(requestList);
  const basket = list.rows.find((row) => row.request_id === IDS.basket);
  if (!basket?.jev) throw new Error("the basket row has no Jev answer in the fixture");
  basket.jev.confidence = 0.62;
  await useFixtures(page, { overrides: { "/api/requests": list } });
  await page.goto("/requests");

  const cell = page.locator(`#row-${IDS.basket} td.rq-c-jev`);
  await expect(cell).toContainText("越权 62%");
  await expect(cell.getByTitle("置信度低于 70%")).toHaveText("低");
});

test("the preview sits beside the list from 1200 px, and over the list below it", async ({
  page,
}) => {
  await useFixtures(page);
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto(`/requests?peek=${IDS.basket}`);
  const preview = page.getByRole("complementary", { name: "预览" });
  await expect(preview).toBeVisible();
  await expect(preview).toHaveCSS("position", "sticky");

  await page.setViewportSize({ width: 1100, height: 800 });
  await expect(preview).toHaveCSS("position", "fixed");
});

test("a narrow list keeps its values on a second line under the path", async ({ page }) => {
  await useFixtures(page);
  await page.setViewportSize({ width: 900, height: 800 });
  await page.goto("/requests");
  const table = page.getByRole("table", { name: "请求列表" });
  await expect(listRows(page).first()).toBeVisible();
  await expect(table.getByRole("columnheader", { name: "站点" })).toBeHidden();
  await expect(table.getByRole("columnheader", { name: "状态" })).toBeHidden();
  await expect(listRows(page).first().locator(".rq-sub")).toBeVisible();
});

for (const theme of ["light", "dark"] satisfies Theme[]) {
  test(`the request list passes axe in the ${theme} theme, with a filter and the preview open`, async ({
    page,
  }) => {
    await useFixtures(page);
    await setTheme(page, theme);
    await page.goto(`/requests?chip=would_block&peek=${IDS.basket}`);
    await expect(listRows(page)).toHaveCount(5);
    await expect(page.getByRole("complementary", { name: "预览" })).toBeVisible();
    await expectNoAxeViolations(page);
  });
}
