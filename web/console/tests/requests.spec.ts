// The request trace (docs/06 6.4.3): the 本应拦截 quick filter and its count, j/k and Enter in the list,
// the filter in the address after a reload, bypass and unknown-site rows, the log-gap notice, and axe.

import { expect, type Locator, type Page, test } from "@playwright/test";
import { expectNoAxeViolations, setTheme, type Theme } from "./helpers/axe.ts";
import { FIXTURE_NOW_MS, mockApi, servedRequests } from "./helpers/mock-api.ts";
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

  await expect(page.getByText("21:10–21:12 edge-1 有 31 条判定记录未写入（队列满）")).toBeVisible();
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

test("a custom window names its bounds, and 清除 returns the range to 24 hours and drops them", async ({
  page,
}) => {
  await useFixtures(page);
  const since = Date.UTC(2026, 10, 1, 13, 0, 0);
  const until = Date.UTC(2026, 10, 1, 14, 0, 0);
  await page.goto(`/requests?range=custom&since=${since}&until=${until}`);

  await expect(page.getByText(/^时间窗 \d{2}:\d{2}–\d{2}:\d{2} ·/)).toBeVisible();
  await page.getByRole("button", { name: "清除" }).click();
  await expect(page).toHaveURL(/range=24h/);
  await expect(page).not.toHaveURL(/since=|until=/);
  await expect(page.getByText(/^时间窗/)).toHaveCount(0);
});

// Two rule rows of the requests fixture (design 4.1): a name that a rule read, and a name that could not
// be read. Both are judged and in the default list.
const NAMED = "req_01a1973d7630773798b4592bb8ca5fde";
const UNKNOWN = "req_01a1973204807054a82075e6b298fb37";

function conditionBox(page: Page): Locator {
  return page.getByRole("textbox", { name: "筛选条件" });
}

test("the path column adds the interface name after ›, and the hover says where it came from", async ({
  page,
}) => {
  await useFixtures(page);
  await page.goto("/requests");
  const via = page.locator(`#row-${NAMED} .rq-via`);
  await expect(via).toHaveText("› dashboard.HomeService/getStats");
  await expect(via).toHaveAttribute("title", "接口名来自请求头 X-Service-Id、X-Service-Method");
});

test("a name that could not be read reads 未知接口 after the path, and the hover gives the reason", async ({
  page,
}) => {
  await useFixtures(page);
  await page.goto("/requests");
  const via = page.locator(`#row-${UNKNOWN} .rq-via`);
  await expect(via).toHaveText("› 未知接口");
  await expect(via).toHaveAttribute(
    "title",
    "未知接口：X-Service-Method 出现了多次，按未知接口处理（不算入口、不走绕过）",
  );
});

test("api:unknown and api: name the rows, and object: names the class of a value", async ({
  page,
}) => {
  await useFixtures(page);
  await page.goto("/requests");
  const condition = conditionBox(page);

  await condition.fill("api:unknown");
  await condition.press("Enter");
  await expect(page).toHaveURL(/q=api(%3A|:)unknown/);
  await expect(listRows(page)).toHaveCount(2);
  await expect(page.locator(`#row-${UNKNOWN}`)).toBeVisible();

  await condition.fill("api:dashboard.HomeService/getStats");
  await condition.press("Enter");
  await expect(page).toHaveURL(/api(%3A|:)dashboard/);
  await expect(listRows(page)).toHaveCount(1);
  await expect(page.locator(`#row-${NAMED}`)).toBeVisible();

  await condition.fill("object:basket");
  await condition.press("Enter");
  await expect(page).toHaveURL(/object(%3A|:)basket/);
  await expect(listRows(page)).toHaveCount(1);
  await expect(page.locator(`#row-${IDS.basket}`)).toBeVisible();
});

test("a link's interface name moves into the condition text, and the address keeps the condition only", async ({
  page,
}) => {
  await useFixtures(page);
  await page.goto("/requests?api=dashboard.HomeService/getStats");
  await expect(conditionBox(page)).toHaveValue("api:dashboard.HomeService/getStats");
  await expect(page).toHaveURL(/q=api(%3A|:)dashboard/);
  await expect(page).not.toHaveURL(/[?&]api=/);
  await expect(listRows(page)).toHaveCount(1);
});

test("只看这个路径 names the logical path, which the path condition then matches", async ({
  page,
}) => {
  await useFixtures(page);
  await page.goto("/requests");
  await page.getByRole("button", { name: `操作：${NAMED}` }).click();
  await page.getByRole("menuitem", { name: "只看这个路径" }).click();
  await expect(conditionBox(page)).toHaveValue("path:/api/home/dashboard.HomeService/getStats");
  await expect(listRows(page)).toHaveCount(1);
});

test("the rows stay on screen while a preset window that has moved with the clock is read again", async ({
  page,
}) => {
  await page.clock.install({ time: FIXTURE_NOW_MS });
  await mockApi(page);
  await page.goto("/requests");
  await expect(listRows(page)).toHaveCount(41);
  const first = servedRequests(page).filter((call) => call.path === "/api/requests").length;

  // Hold every later list answer, so the page is seen between asking for the moved window and getting it.
  let release: () => void = () => {};
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  let asked = 0;
  await page.route("**/api/requests?*", async (route) => {
    asked += 1;
    await held;
    await route.fallback();
  });

  await page.clock.runFor(31_000);
  await expect.poll(() => asked).toBeGreaterThan(0);
  await expect(listRows(page)).toHaveCount(41);

  release();
  await expect
    .poll(() => servedRequests(page).filter((call) => call.path === "/api/requests").length)
    .toBeGreaterThan(first);
  await expect(listRows(page)).toHaveCount(41);
});
