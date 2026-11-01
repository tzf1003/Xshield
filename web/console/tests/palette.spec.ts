// The command palette (docs/06 6.3.3): Ctrl+K or Cmd+K opens it, a pasted request ID opens that
// request, two IDs open the batch lookup, a session label opens its timeline, and the empty palette
// lists what was opened last. Axe runs with the palette open in both themes.

import { expect, type Page, test } from "@playwright/test";
import { expectNoAxeViolations, setTheme, type Theme } from "./helpers/axe.ts";
import { IDS, SESSION, untilDialogOpen, useFixtures } from "./helpers/trace.ts";

const PALETTE = "命令面板";

/**
 * Opens the palette once the page has rendered, so the shortcut listener of the shell is in place, and
 * once the dialog has faded in, so that the axe checks read its final colours.
 */
async function openPalette(page: Page, shortcut = "Control+k") {
  await expect(page.getByRole("heading", { level: 1 }).first()).toBeVisible();
  await page.keyboard.press(shortcut);
  const input = page.getByRole("combobox", { name: PALETTE });
  await expect(input).toBeFocused();
  await untilDialogOpen(page, PALETTE);
  return input;
}

for (const shortcut of ["Control+k", "Meta+k"]) {
  test(`${shortcut} opens the palette, and a typed request ID opens that request`, async ({
    page,
  }) => {
    await useFixtures(page);
    await page.goto("/requests");
    await expect(page.getByRole("table", { name: "请求列表" })).toBeVisible();

    const input = await openPalette(page, shortcut);
    await input.fill(IDS.basket);

    const option = page.getByRole("option", { name: `打开请求 ${IDS.basket}` });
    await expect(option).toBeVisible();
    await expect(option).toContainText("2026-11-01 21:07:54");

    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(new RegExp(`/requests/${IDS.basket}$`));
    await expect(page.getByRole("heading", { level: 1, name: "/rest/basket/6" })).toBeVisible();
    await expect(page.getByRole("combobox", { name: PALETTE })).toBeHidden();
  });
}

test("a request ID inside pasted text is found, and Escape closes the palette", async ({
  page,
}) => {
  await useFixtures(page);
  await page.goto("/requests");
  const input = await openPalette(page);

  await input.fill(`测试套件 ${IDS.search} 返回 403`);
  await expect(page.getByRole("option", { name: `打开请求 ${IDS.search}` })).toBeVisible();

  await page.keyboard.press("Escape");
  await expect(input).toBeHidden();
  await expect(page).toHaveURL(/\/requests$/);
});

test("two request IDs offer the batch lookup, which opens with the text pasted", async ({
  page,
}) => {
  await useFixtures(page);
  await page.goto("/requests");
  const input = await openPalette(page);
  const text = `${IDS.basket} ${IDS.login}`;
  await input.fill(text);

  await expect(page.getByRole("option", { name: "批量对照 2 个请求 ID" })).toBeVisible();
  await page.keyboard.press("Enter");

  await expect(page).toHaveURL(/\/requests\?batch=1$/);
  await expect(page.getByRole("dialog", { name: "批量对照" })).toBeVisible();
  await expect(page.getByRole("textbox", { name: "粘贴的内容" })).toHaveValue(text);
});

test("a session label opens its timeline", async ({ page }) => {
  await useFixtures(page);
  await page.goto("/requests");
  const input = await openPalette(page);
  await input.fill(SESSION);

  await expect(page.getByRole("option", { name: `打开会话 ${SESSION.slice(0, 8)}` })).toBeVisible();
  await page.keyboard.press("Enter");

  await expect(page).toHaveURL(new RegExp(`/sessions/${SESSION}$`));
  await expect(page.getByRole("heading", { name: "会话时间线" })).toBeVisible();
});

test("a site name offers the site and its configuration", async ({ page }) => {
  await useFixtures(page);
  await page.goto("/requests");
  const input = await openPalette(page);
  await input.fill("juice");

  await expect(page.getByRole("option", { name: "打开站点 juice" })).toBeVisible();
  await expect(page.getByRole("option", { name: "打开 juice 的站点配置" })).toBeVisible();
  await page.getByRole("option", { name: "打开 juice 的站点配置" }).click();
  await expect(page).toHaveURL(/\/sites\/juice\?tab=config$/);
});

test("a path filters the list to that path", async ({ page }) => {
  await useFixtures(page);
  await page.goto("/requests");
  const input = await openPalette(page);
  await input.fill("/rest/basket/6");

  await expect(page.getByRole("option", { name: "筛选路径 /rest/basket/6" })).toBeVisible();
  await page.keyboard.press("Enter");

  await expect(page).toHaveURL(/q=path(%3A|:)/);
  const rows = page.getByRole("table", { name: "请求列表" }).locator("tbody tr");
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText("/rest/basket/6");
});

test("an invalid condition is named and cannot be opened", async ({ page }) => {
  await useFixtures(page);
  await page.goto("/requests");
  const input = await openPalette(page);
  await input.fill("outcome:nope");

  const error = page.getByRole("option", { name: "条件语法有误" });
  await expect(error).toBeVisible();
  await expect(error).toBeDisabled();
});

test("the help command opens the shortcut list", async ({ page }) => {
  await useFixtures(page);
  await page.goto("/requests");
  const input = await openPalette(page);
  await input.fill("快捷键");

  await page.getByRole("option", { name: "查看快捷键" }).click();
  await expect(page.getByRole("dialog", { name: "快捷键" })).toBeVisible();
});

test("the empty palette lists the request opened last", async ({ page }) => {
  await useFixtures(page);
  await page.goto(`/requests/${IDS.basket}`);
  await expect(page.getByRole("heading", { level: 1, name: "/rest/basket/6" })).toBeVisible();

  await page.goto("/requests");
  const input = await openPalette(page);
  await expect(input).toHaveValue("");
  await expect(page.getByRole("option", { name: /GET \/rest\/basket\/6/ })).toBeVisible();
});

for (const theme of ["light", "dark"] satisfies Theme[]) {
  test(`the palette passes axe in the ${theme} theme`, async ({ page }) => {
    await useFixtures(page);
    await setTheme(page, theme);
    await page.goto("/requests");
    const input = await openPalette(page);
    await expectNoAxeViolations(page);

    await input.fill(IDS.basket);
    await expect(page.getByRole("option", { name: `打开请求 ${IDS.basket}` })).toBeVisible();
    await expectNoAxeViolations(page);
  });
}
