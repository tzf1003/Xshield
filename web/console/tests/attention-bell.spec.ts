// The bell of the top bar (docs/06 6.3.2): the "需要处理" rows reach every page through it. Its badges count the
// alerts, serious and warning, apart from the hints; its panel keeps each row's links, and following one closes
// the panel; Escape closes the panel and gives the focus back to the bell. The rows themselves are checked in
// overview.spec.ts; this spec checks the bell where the overview is not the page.

import { expect, type Page, test } from "@playwright/test";
import { expectNoAxeViolations, setTheme, type Theme } from "./helpers/axe.ts";
import { FIXTURE_NOW_MS, mockApi } from "./helpers/mock-api.ts";
import {
  bell,
  bellPanel,
  changeSite,
  healthyStatus,
  openBell,
  quietSites,
  statusWith,
} from "./helpers/overview.ts";

/** Opens the request list, a page that is not the overview, on the frozen clock. */
async function openRequests(page: Page): Promise<void> {
  await page.clock.setFixedTime(FIXTURE_NOW_MS);
  await page.goto("/requests");
  await expect(page.getByRole("table", { name: "请求列表" })).toBeVisible();
}

test("the bell sits in the top bar and counts the alerts apart from the hints", async ({
  page,
}) => {
  await mockApi(page);
  await openRequests(page);

  // Two serious rows and a warning are alerts, so the badge is red and marked with ■; the two hints are apart.
  const button = page.getByRole("button", { name: "需要处理（3 项，2 条提示）" });
  await expect(button).toBeVisible();
  await expect(button.locator(".ov-bell-serious")).toHaveText("■3");
  await expect(button.locator(".ov-bell-hint")).toHaveText("i2");
  await expect(button.locator(".ov-bell-warn")).toHaveCount(0);
});

test("a warning alone is an amber alert", async ({ page }) => {
  await mockApi(page, {
    overrides: {
      "/api/status": statusWith({ jev: { health: "degraded", failures: { JEV_TIMEOUT: 7 } } }),
      "/api/sites": { sites: quietSites() },
    },
  });
  await openRequests(page);

  const button = page.getByRole("button", { name: "需要处理（1 项）" });
  await expect(button).toBeVisible();
  await expect(button.locator(".ov-bell-warn")).toHaveText("▲1");
  await expect(button.locator(".ov-bell-serious")).toHaveCount(0);
  await expect(button.locator(".ov-bell-hint")).toHaveCount(0);
});

test("a hint alone has no alert badge", async ({ page }) => {
  await mockApi(page, {
    overrides: {
      "/api/status": healthyStatus(),
      "/api/sites": { sites: changeSite(quietSites(), "juice", { suggestions: 2 }) },
    },
  });
  await openRequests(page);

  const button = page.getByRole("button", { name: "需要处理（1 条提示）" });
  await expect(button).toBeVisible();
  await expect(button.locator(".ov-bell-hint")).toHaveText("i1");
  await expect(button.locator(".ov-bell-serious, .ov-bell-warn")).toHaveCount(0);
});

test("with nothing to handle the bell has no badge, and its panel says all is well", async ({
  page,
}) => {
  await mockApi(page, {
    overrides: { "/api/status": healthyStatus(), "/api/sites": { sites: quietSites() } },
  });
  await openRequests(page);

  const button = page.getByRole("button", { name: "需要处理（没有事项）" });
  await expect(button).toBeVisible();
  await expect(button.locator(".ov-bell-count")).toHaveCount(0);
  await openBell(page);
  await expect(bellPanel(page)).toContainText("一切正常");
});

test("the panel keeps each row's links, and following one opens its page and closes the panel", async ({
  page,
}) => {
  await mockApi(page);
  await openRequests(page);
  await openBell(page);

  const panel = bellPanel(page);
  await expect(panel.getByRole("listitem")).toHaveCount(5);
  const row = panel.getByRole("listitem").filter({ hasText: "emr v13 保存后未生效" });
  await row.getByRole("link", { name: "查看系统", exact: true }).click();

  await expect(page).toHaveURL(
    (url) => url.pathname === "/system" && url.searchParams.get("tab") === "edges",
  );
  await expect(panel).toBeHidden();
  await expect(bell(page)).toHaveAttribute("aria-expanded", "false");
});

test("Escape closes the panel and gives the focus back to the bell", async ({ page }) => {
  await mockApi(page);
  await openRequests(page);
  await openBell(page);
  await expect(bellPanel(page)).toBeFocused();

  await page.keyboard.press("Escape");
  await expect(bellPanel(page)).toBeHidden();
  await expect(bell(page)).toBeFocused();
});

for (const theme of ["light", "dark"] satisfies Theme[]) {
  test(`the bell's panel with its rows passes axe in the ${theme} theme`, async ({ page }) => {
    await mockApi(page);
    await setTheme(page, theme);
    await page.clock.setFixedTime(FIXTURE_NOW_MS);
    await page.goto("/requests");
    await expect(page.getByRole("table", { name: "请求列表" })).toBeVisible();
    await openBell(page);
    await expect(bellPanel(page).getByRole("listitem")).toHaveCount(5);
    await expectNoAxeViolations(page);
  });
}
