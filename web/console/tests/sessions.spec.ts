// Sessions (docs/06 6.4.7): the list with its chips and label prefix, the timeline of one session with
// its gap rows, the 只看 choices that narrow the rows, the request named by `at`, and axe in both themes.

import { expect, type Locator, type Page, test } from "@playwright/test";
import { expectNoAxeViolations, setTheme, type Theme } from "./helpers/axe.ts";
import { sessionTimeline } from "./helpers/fixtures.ts";
import {
  IDS,
  SESSION,
  serveTimelineOnly,
  serveTimelineWithLogin,
  useFixtures,
} from "./helpers/trace.ts";

function sessionRows(page: Page): Locator {
  return page.getByRole("table", { name: "会话列表" }).locator("tbody tr");
}

function timelineRows(page: Page): Locator {
  return page.getByRole("list", { name: "会话里的请求" }).locator("[data-tl-row]");
}

test("the list shows the sessions of the last 24 hours, and the chips narrow them on the server", async ({
  page,
}) => {
  await useFixtures(page);
  await page.goto("/sessions");
  await expect(sessionRows(page)).toHaveCount(6);
  await expect(page.getByRole("status").filter({ hasText: "显示 6 个会话" })).toBeVisible();

  await page.getByRole("button", { name: "有拦截" }).click();
  await expect(page).toHaveURL(/flag=blocked/);
  await expect(sessionRows(page)).toHaveCount(3);

  await page.getByRole("button", { name: "有 Jev 调用" }).click();
  await expect(page).toHaveURL(/flag=jev/);
  await expect(sessionRows(page)).toHaveCount(5);

  await page.getByRole("button", { name: "全部", exact: true }).click();
  await expect(page).not.toHaveURL(/flag=/);
  await expect(sessionRows(page)).toHaveCount(6);
});

test("a label prefix narrows the list, and a prefix that cannot be a label is named", async ({
  page,
}) => {
  await useFixtures(page);
  await page.goto("/sessions");

  const prefix = page.getByRole("textbox", { name: "按会话标签前缀搜索" });
  await prefix.fill("7c1e");
  await expect(page).toHaveURL(/q=7c1e/);
  await expect(sessionRows(page)).toHaveCount(1);
  await expect(sessionRows(page).first()).toContainText("7c1e9a40");

  await prefix.fill("zz");
  await expect(page.getByText("会话标签只含 0–9 和 a–f")).toBeVisible();
  await expect(page.getByText("没有标签以 “zz” 开头的会话")).toBeVisible();
});

test("a session opens its timeline, with the gap between requests named", async ({ page }) => {
  await useFixtures(page);
  await page.goto("/sessions");
  await page.getByRole("link", { name: `会话 ${SESSION} 的时间线` }).click();

  await expect(page).toHaveURL(new RegExp(`/sessions/${SESSION}$`));
  await expect(page.getByRole("heading", { name: "会话时间线" })).toBeVisible();
  await expect(timelineRows(page)).toHaveCount(17);
  await expect(page.getByText("请求 17 · Jev 调用 1 · 本应拦截 2")).toBeVisible();
  await expect(page.getByText("⋯ 15 分钟无请求")).toBeVisible();
  // The refused response taught nothing (new format); the record written before the change did.
  await expect(page.getByText("▲ 本应拦截，未学习")).toHaveCount(1);
  await expect(page.getByText("▲ 本应拦截学习")).toHaveCount(1);

  await page.keyboard.press("j");
  await expect(timelineRows(page).first()).toBeFocused();
});

/** The time of the request at 13:11:00 UTC, which lies inside edge-1's loss window (system.json). */
const LOST_WINDOW_ROW_MS = 1793538660000;

test("a quiet time that a window of lost records covers names the window, and the others do not", async ({
  page,
}) => {
  await useFixtures(page);
  // Without the request at 13:11, the quiet time from about 13:08 to 13:15 covers edge-1's loss window
  // (13:10–13:12, 31 records dropped under queue pressure). The other two quiet times do not reach it.
  await page.route(
    (url) => url.pathname === `/api/sessions/${SESSION}`,
    async (route) => {
      const body = {
        ...sessionTimeline,
        rows: sessionTimeline.rows.filter((row) => row.at_millis !== LOST_WINDOW_ROW_MS),
      };
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(body),
      });
    },
  );
  await page.goto(`/sessions/${SESSION}`);
  await expect(timelineRows(page)).toHaveCount(16);

  const gaps = page.locator(".sx-timeline .tl-gap");
  await expect(gaps).toHaveCount(3);
  await expect(gaps.nth(0)).not.toContainText("其中");
  await expect(gaps.nth(1)).not.toContainText("其中");
  await expect(gaps.nth(2)).toContainText(
    "其中 21:10–21:12 edge-1 有 31 条记录未写入（队列满），这段时间可能有请求查不到",
  );
});

test("只看 narrows the timeline to the chosen requests, asking the server each time", async ({
  page,
}) => {
  await useFixtures(page);
  await serveTimelineOnly(page);
  await page.goto(`/sessions/${SESSION}`);
  await expect(timelineRows(page)).toHaveCount(17);

  const only = page.getByRole("combobox", { name: "只看" });
  await only.selectOption("jev");
  await expect(page).toHaveURL(/only=jev/);
  await expect(timelineRows(page)).toHaveCount(1);
  await expect(timelineRows(page).first()).toContainText("/rest/basket/6");

  await only.selectOption("blocks");
  await expect(page).toHaveURL(/only=blocks/);
  await expect(timelineRows(page)).toHaveCount(3);

  await only.selectOption("judged");
  await expect(page).not.toHaveURL(/only=/);
  await expect(timelineRows(page)).toHaveCount(17);
});

test("at scrolls to and highlights the named request, and says when it is not in the session", async ({
  page,
}) => {
  await useFixtures(page);
  await page.goto(`/sessions/${SESSION}?at=${IDS.basket}`);
  await expect(page.locator(`#tl-${IDS.basket}`)).toHaveClass(/\bhl\b/);
  await expect(page.getByText("找不到请求")).toHaveCount(0);

  await page.goto(`/sessions/${SESSION}?at=${IDS.newest}`);
  await expect(page.getByText("找不到请求 …")).toBeVisible();
});

test("a session the gateway does not hold reads as having no record in the range", async ({
  page,
}) => {
  await useFixtures(page);
  await page.goto("/sessions/0123456789abcdef");
  await expect(page.getByText("这个会话在当前时间范围内没有记录")).toBeVisible();

  await page.goto("/sessions/not-a-session");
  await expect(page.getByText("这个会话在当前时间范围内没有记录")).toBeVisible();
});

test("the first row of the timeline is the login that issued the session, marked with its context", async ({
  page,
}) => {
  await useFixtures(page);
  await serveTimelineWithLogin(page);
  await page.goto(`/sessions/${SESSION}`);

  const rows = timelineRows(page);
  // The login comes first, then the session's seventeen requests.
  await expect(rows).toHaveCount(18);
  await expect(rows.first()).toContainText("/rest/user/login");
  await expect(rows.first()).toContainText("◆ 签发本会话 · 上下文：地址");
});

for (const theme of ["light", "dark"] satisfies Theme[]) {
  test(`the session list passes axe in the ${theme} theme`, async ({ page }) => {
    await useFixtures(page);
    await setTheme(page, theme);
    await page.goto("/sessions?flag=blocked");
    await expect(sessionRows(page)).toHaveCount(3);
    await expectNoAxeViolations(page);
  });

  test(`the session timeline passes axe in the ${theme} theme`, async ({ page }) => {
    await useFixtures(page);
    await setTheme(page, theme);
    await page.goto(`/sessions/${SESSION}?at=${IDS.basket}`);
    await expect(timelineRows(page)).toHaveCount(17);
    await expectNoAxeViolations(page);
  });
}
