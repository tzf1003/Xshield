// Batch lookup (docs/06 6.4.3), opened from the request list: the pasted IDs are counted, the lookup
// sends them to the server, and the results table compares the expected column with what was recorded
// (一致, 不一致, 查不到). Covers the two filters, the expected-column choice, the 1000-ID limit, a
// paste with no ID, a row that opens its record, and axe in both themes.

import { expect, type Locator, type Page, test } from "@playwright/test";
import { expectNoAxeViolations, setTheme, type Theme } from "./helpers/axe.ts";
import { servedRequests } from "./helpers/mock-api.ts";
import { IDS, requestIdAt, untilDialogOpen, useFixtures } from "./helpers/trace.ts";

/** Not in the 24-hour fixtures, so the gateway answers it as not found. */
const PROBE = "req_01a19741107477ff9224781077354552";

/** A test-suite table: the request ID column, then the verdict the suite expected for each request. */
const SUITE_TSV = [
  "x_xshield_request_id\toutcome",
  `${IDS.login}\tallowed`,
  `${IDS.basket}\tallowed`,
  `${PROBE}\tblocked`,
].join("\n");

function dialog(page: Page): Locator {
  return page.getByRole("dialog", { name: "批量对照" });
}

function pasteBox(page: Page): Locator {
  return dialog(page).getByRole("textbox", { name: "粘贴的内容" });
}

function lookupButton(page: Page): Locator {
  return dialog(page).getByRole("button", { name: "对照 ⏎" });
}

function resultRows(page: Page): Locator {
  return dialog(page).getByRole("table", { name: "对照结果" }).locator("tbody tr");
}

function lookupCalls(page: Page) {
  return servedRequests(page).filter((call) => call.path === "/api/requests/lookup");
}

/** Opens the dialog from the request list, the way an analyst does. */
async function openFromList(page: Page): Promise<void> {
  await page.goto("/requests");
  await page.getByRole("button", { name: "批量对照", exact: true }).click();
  await expect(dialog(page)).toBeVisible();
  await expect(page).toHaveURL(/batch=1/);
}

/** Pastes the suite table and runs the lookup, then waits for the results. */
async function lookUpSuite(page: Page): Promise<void> {
  await pasteBox(page).fill(SUITE_TSV);
  await expect(dialog(page).getByText("识别到 3 个请求 ID", { exact: false })).toBeVisible();
  await lookupButton(page).click();
  await expect(resultRows(page)).toHaveCount(3);
}

test("the batch button opens the dialog, and the pasted table is read with its expected column", async ({
  page,
}) => {
  await useFixtures(page);
  await openFromList(page);

  await pasteBox(page).fill(SUITE_TSV);
  await expect(dialog(page).getByText("识别到 3 个请求 ID", { exact: false })).toBeVisible();
  await expect(dialog(page).getByText("表头 2 列", { exact: false })).toBeVisible();
  await expect(dialog(page).getByRole("combobox", { name: "预期结论列" })).toBeVisible();

  await lookupButton(page).click();
  await expect(resultRows(page)).toHaveCount(3);
  await expect(
    dialog(page).getByText("② 结果：3 个 · 找到 2 · 查不到 1 · 预期不一致 1"),
  ).toBeVisible();

  const calls = lookupCalls(page);
  expect(calls).toHaveLength(1);
  expect(calls[0]?.body).toEqual({ ids: [IDS.login, IDS.basket, PROBE] });
});

test("each result is marked 一致, 不一致 or 查不到 against the expected verdict", async ({
  page,
}) => {
  await useFixtures(page);
  await openFromList(page);
  await lookUpSuite(page);

  const rows = resultRows(page);
  await expect(rows.filter({ hasText: "✓ 一致" })).toHaveCount(1);
  await expect(rows.filter({ hasText: "✗ 不一致" })).toHaveCount(1);
  await expect(rows.filter({ hasText: "? 查不到" })).toHaveCount(1);

  // The login was expected allowed and was allowed; the basket was expected allowed but would block.
  await expect(
    rows.filter({ has: page.getByTitle(IDS.login) }).filter({ hasText: "✓ 一致" }),
  ).toHaveCount(1);
  await expect(
    rows.filter({ has: page.getByTitle(IDS.basket) }).filter({ hasText: "✗ 不一致" }),
  ).toHaveCount(1);
  await expect(
    rows.filter({ has: page.getByTitle(PROBE) }).filter({ hasText: "? 查不到" }),
  ).toHaveCount(1);
});

test("the mismatch and not-found filters narrow the results, one at a time", async ({ page }) => {
  await useFixtures(page);
  await openFromList(page);
  await lookUpSuite(page);

  const mismatch = dialog(page).getByRole("checkbox", { name: "只看不一致" });
  const missing = dialog(page).getByRole("checkbox", { name: "只看查不到" });

  await mismatch.check();
  await expect(resultRows(page)).toHaveCount(1);
  await expect(resultRows(page).first()).toContainText("✗ 不一致");

  await mismatch.uncheck();
  await expect(resultRows(page)).toHaveCount(3);

  await missing.check();
  await expect(resultRows(page)).toHaveCount(1);
  await expect(resultRows(page).first()).toContainText("? 查不到");
});

test("choosing 不对照 for the expected column stops the comparison, without a new lookup", async ({
  page,
}) => {
  await useFixtures(page);
  await openFromList(page);
  await lookUpSuite(page);

  await dialog(page)
    .getByRole("combobox", { name: "预期结论列" })
    .selectOption({ label: "不对照" });

  await expect(dialog(page).getByText("预期不一致 0")).toBeVisible();
  await expect(resultRows(page).filter({ hasText: "✗ 不一致" })).toHaveCount(0);
  await expect(resultRows(page).filter({ hasText: "一致" })).toHaveCount(0);
  expect(lookupCalls(page)).toHaveLength(1);
});

test("a result opens its request record", async ({ page }) => {
  await useFixtures(page);
  await openFromList(page);
  await lookUpSuite(page);

  await dialog(page).getByTitle(IDS.login).click();
  await expect(page).toHaveURL(new RegExp(`/requests/${IDS.login}`));
  await expect(page.getByRole("heading", { level: 1, name: "/rest/user/login" })).toBeVisible();
});

test("a paste with no request ID cannot be looked up", async ({ page }) => {
  await useFixtures(page);
  await openFromList(page);

  await pasteBox(page).fill("这段文字里没有请求 ID");
  await expect(dialog(page).getByText("识别到 0 个请求 ID", { exact: false })).toBeVisible();
  await expect(lookupButton(page)).toBeDisabled();
});

test("more than 1000 IDs names the limit, and nothing is sent to the server", async ({ page }) => {
  await useFixtures(page);
  await openFromList(page);

  const start = Date.UTC(2026, 10, 1, 13, 0, 0);
  const ids = Array.from({ length: 1001 }, (_, index) => requestIdAt(start + index));
  await pasteBox(page).fill(ids.join("\n"));

  await expect(dialog(page).getByText("一次最多对照 1000 个请求 ID")).toBeVisible();
  await expect(lookupButton(page)).toBeDisabled();
  expect(lookupCalls(page)).toHaveLength(0);
});

for (const theme of ["light", "dark"] satisfies Theme[]) {
  test(`the batch dialog passes axe in the ${theme} theme, with results shown`, async ({
    page,
  }) => {
    await useFixtures(page);
    await setTheme(page, theme);
    await openFromList(page);
    await lookUpSuite(page);
    await untilDialogOpen(page, "批量对照");
    await expectNoAxeViolations(page);
  });
}
