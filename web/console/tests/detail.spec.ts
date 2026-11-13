// The request detail (docs/06 6.4.4, 6.4.5, 6.7.2): the five tabs, the four Jev views, the source chip
// that opens the source request, the neighbour keys, the not-found state with its reason, and axe on
// every tab in both themes.

import { expect, type Page, test } from "@playwright/test";
import type { RequestDetail } from "../src/api/types.ts";
import { expectNoAxeViolations, setTheme, type Theme } from "./helpers/axe.ts";
import { requestDetails } from "./helpers/fixtures.ts";
import { IDS, requestIdAt, useFixtures } from "./helpers/trace.ts";

const DAY_MS = 24 * 60 * 60 * 1000;
const FIXTURE_NOW = 1793539200000;

function heading(page: Page, path: string) {
  return page.getByRole("heading", { level: 1, name: path });
}

async function openBasket(page: Page, search = ""): Promise<void> {
  await page.goto(`/requests/${IDS.basket}${search}`);
  await expect(heading(page, "/rest/basket/6")).toBeVisible();
}

/**
 * Answers the basket's detail with a copy of its fixture, changed by `change`. Each test states the one
 * record shape it covers; the fixture itself stays as it is for the other specs.
 */
async function serveBasketDetail(
  page: Page,
  change: (detail: RequestDetail) => void,
): Promise<void> {
  const fixture = requestDetails.find((detail) => detail.summary.request_id === IDS.basket);
  if (fixture === undefined) throw new Error("the basket fixture is missing");
  await page.route(
    (url) => url.pathname === `/api/requests/${IDS.basket}`,
    async (route) => {
      const detail = structuredClone(fixture);
      change(detail);
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(detail),
      });
    },
  );
}

/** A choice of the Jev view control. antd hides its radio, so the visible label is what gets clicked. */
function viewChoice(page: Page, name: string) {
  return page.getByRole("tabpanel").getByText(name, { exact: true });
}

test("the five tabs switch, and their number keys do too", async ({ page }) => {
  await useFixtures(page);
  await openBasket(page);
  await expect(page.getByRole("tab", { name: "判定过程" })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  await expect(page.getByRole("list", { name: "判定步骤" })).toBeVisible();

  await page.getByRole("tab", { name: "请求值" }).click();
  await expect(page).toHaveURL(/tab=values/);
  await expect(page.getByRole("table").getByText("quantity")).toBeVisible();

  await page.getByRole("tab", { name: "Jev 上下文" }).click();
  await expect(page).toHaveURL(/tab=jev/);
  await expect(page.getByRole("radio", { name: "结构化" })).toBeChecked();

  await page.getByRole("tab", { name: "会话上下文" }).click();
  await expect(page).toHaveURL(/tab=session/);
  await expect(page.getByRole("tabpanel").getByText("会话上下文", { exact: true })).toBeVisible();

  await page.getByRole("tab", { name: "原始记录" }).click();
  await expect(page).toHaveURL(/tab=raw/);
  await expect(page.getByRole("button", { name: "复制 JSON" })).toBeVisible();

  await page.keyboard.press("1");
  await expect(page).toHaveURL(/tab=pipeline/);
  await page.keyboard.press("2");
  await expect(page).toHaveURL(/tab=values/);
  await page.keyboard.press("3");
  await expect(page).toHaveURL(/tab=jev/);
});

test("the Jev views switch between structured, JSON, raw and the instruction", async ({ page }) => {
  await useFixtures(page);
  await openBasket(page, "?tab=jev");

  await viewChoice(page, "JSON").click();
  await expect(page).toHaveURL(/jev_view=json/);
  await expect(page.locator(".json-tree").getByText("request:").first()).toBeVisible();

  await viewChoice(page, "原文").click();
  await expect(page).toHaveURL(/jev_view=raw/);
  await expect(page.locator(".codeblock").first()).toContainText("/rest/basket/6");

  await viewChoice(page, "指令").click();
  await expect(page).toHaveURL(/jev_view=prompt/);
  await expect(page.getByRole("heading", { name: "访问有依据吗" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "内容是攻击吗" })).toBeVisible();

  await viewChoice(page, "结构化").click();
  await expect(page).toHaveURL(/jev_view=structured/);
  await expect(page.getByRole("radio", { name: "结构化" })).toBeChecked();

  // `v` walks the same cycle, so the four views come round again.
  await page.getByRole("heading", { level: 1, name: "/rest/basket/6" }).click();
  await page.keyboard.press("v");
  await expect(page).toHaveURL(/jev_view=json/);
  await page.keyboard.press("v");
  await expect(page).toHaveURL(/jev_view=raw/);
});

test("a source chip opens the request that showed the value", async ({ page }) => {
  await useFixtures(page);
  await openBasket(page, "?tab=jev");

  await page
    .getByRole("link", { name: /quantity/ })
    .first()
    .click();

  await expect(page).toHaveURL(new RegExp(`/requests/${IDS.basketSource}$`));
  await expect(heading(page, "/rest/basket/1")).toBeVisible();
});

test("[ and ] move to the neighbours in the same session", async ({ page }) => {
  await useFixtures(page);
  await openBasket(page);

  await page.keyboard.press("[");
  await expect(page).toHaveURL(new RegExp(`/requests/${IDS.basketSource}$`));
  await expect(heading(page, "/rest/basket/1")).toBeVisible();

  await page.keyboard.press("]");
  await expect(page).toHaveURL(new RegExp(`/requests/${IDS.basket}$`));
  await expect(heading(page, "/rest/basket/6")).toBeVisible();
});

test("a request ID the gateway does not hold shows the not-found state, with the log gap that covers its time", async ({
  page,
}) => {
  await useFixtures(page);
  // 13:11:00 UTC is inside the loss window of edge-1 in status.json (13:10 to 13:12, 31 records).
  const lost = requestIdAt(Date.UTC(2026, 10, 1, 13, 11, 0));
  await page.goto(`/requests/${lost}`);

  await expect(page.getByText("找不到这个请求")).toBeVisible();
  await expect(page.getByText(lost)).toBeVisible();
  await expect(
    page.getByText("当时 edge-1 丢失了 31 条记录（队列满），这段时间的请求可能查不到。"),
  ).toBeVisible();
  await expect(page).toHaveURL(new RegExp(`/requests/${lost}$`));
  await expect(page.getByRole("link", { name: "返回请求追溯" })).toBeVisible();
});

test("a request ID that is in retention and outside any loss window says it may come from another gateway", async ({
  page,
}) => {
  await useFixtures(page);
  await page.goto("/requests/req_01a19741107477ff9224781077354552");
  await expect(page.getByText("找不到这个请求")).toBeVisible();
  await expect(page.getByText("可能来自其他环境的网关。")).toBeVisible();
});

test("an ID older than retention, a future ID and a malformed ID each give their own reason", async ({
  page,
}) => {
  await useFixtures(page);

  await page.goto(`/requests/${requestIdAt(FIXTURE_NOW - 8 * DAY_MS)}`);
  await expect(page.getByText(/已超过 7 天保留期/)).toBeVisible();

  await page.goto(`/requests/${requestIdAt(FIXTURE_NOW + 10 * 60 * 1000)}`);
  await expect(page.getByText("ID 时间异常，可能不是本系统生成的。")).toBeVisible();

  await page.goto("/requests/req_not-a-real-id");
  await expect(
    page.getByText("这不是本系统生成的请求 ID 格式（req_ 加 32 位十六进制）。"),
  ).toBeVisible();
  await expect(page).toHaveURL(/\/requests\/req_not-a-real-id$/);
});

const TABS = [
  { name: "判定过程", search: "" },
  { name: "请求值", search: "?tab=values" },
  { name: "Jev 上下文", search: "?tab=jev" },
  { name: "Jev 上下文", search: "?tab=jev&jev_view=json" },
  { name: "Jev 上下文", search: "?tab=jev&jev_view=raw" },
  { name: "Jev 上下文", search: "?tab=jev&jev_view=prompt" },
  { name: "会话上下文", search: "?tab=session" },
  { name: "原始记录", search: "?tab=raw" },
];

test("the raw text can be numbered, wrapped or not, and says how many bytes it holds", async ({
  page,
}) => {
  await useFixtures(page);
  await openBasket(page, "?tab=jev&jev_view=raw");
  const formatted = page.getByRole("checkbox", { name: "格式化显示" });
  const wrap = page.getByRole("checkbox", { name: "自动换行" });
  await expect(formatted).not.toBeChecked();
  await expect(wrap).toBeChecked();
  await expect(page.locator(".rd-viewtools .tnum")).toHaveText(/^\d+(\.\d)? (B|KiB)$/);

  await formatted.check();
  await expect(page.locator(".code-no").first()).toHaveText("1");
  await expect(page.locator("pre.codeblock")).not.toHaveClass(/nowrap/);

  await wrap.uncheck();
  await expect(page.locator("pre.codeblock")).toHaveClass(/nowrap/);
});

test("a redacted value says so with its length, on a hatched ground", async ({ page }) => {
  await useFixtures(page);
  await page.goto(`/requests/${IDS.login}?tab=values`);
  const redacted = page.locator(".rd-redacted").first();
  await expect(redacted).toHaveText(/^已脱敏 · \d+ 字符$/);
  await expect(redacted).toHaveCSS("background-image", /repeating-linear-gradient/);
});

test("a request that made no Jev call shows its session without the lists only Jev keeps", async ({
  page,
}) => {
  await useFixtures(page);
  await serveBasketDetail(page, (detail) => {
    // A fast allow: the session was already known, so the judge never called Jev and kept no lists.
    detail.summary.decision_path = "fast_allow";
    detail.summary.outcome = "allowed";
    detail.summary.jev = null;
    detail.jev = null;
    detail.trace.session = { age_seconds: 48, known_values: 3 };
  });
  await page.goto(`/requests/${IDS.basket}?tab=session`);
  await expect(heading(page, "/rest/basket/6")).toBeVisible();
  const panel = page.getByRole("tabpanel");
  await expect(panel.getByText("已存在")).toBeVisible();
  await expect(panel.getByText("经过的入口只在调用 Jev 的记录里保存")).toBeVisible();
  await expect(panel.getByText("最近访问只在调用 Jev 的记录里保存")).toBeVisible();
  await expect(page.getByText("Something went wrong!")).toHaveCount(0);
});

test("a request with no session context says so on its session tab", async ({ page }) => {
  await useFixtures(page);
  await serveBasketDetail(page, (detail) => {
    detail.summary.context = null;
    detail.summary.session = "";
    delete detail.trace.session;
  });
  await page.goto(`/requests/${IDS.basket}?tab=session`);
  await expect(page.getByText("这条记录没有会话上下文")).toBeVisible();
  await expect(page.getByText("Something went wrong!")).toHaveCount(0);
});

test("a page that cannot render shows its own error page, with a retry and a way back", async ({
  page,
}) => {
  await useFixtures(page);
  await serveBasketDetail(page, (detail) => {
    // The head reads the neighbours on every tab, so a record without them fails the whole page.
    detail.neighbors = null as unknown as RequestDetail["neighbors"];
  });
  await page.goto(`/requests/${IDS.basket}`);
  await expect(page.getByRole("heading", { name: "这个页面出错了" })).toBeVisible();
  await expect(page.getByRole("button", { name: "重试" })).toBeVisible();
  await expect(page.getByRole("link", { name: "返回请求追溯" })).toBeVisible();
  await expect(page.getByText("Something went wrong!")).toHaveCount(0);
});

for (const theme of ["light", "dark"] satisfies Theme[]) {
  // One test per tab: each loads the page afresh, so a slow scan of one tab cannot use up a shared time budget.
  for (const tab of TABS) {
    const label = tab.search === "" ? tab.name : `${tab.name} ${tab.search}`;
    test(`the ${label} tab passes axe in the ${theme} theme`, async ({ page }) => {
      await useFixtures(page);
      await setTheme(page, theme);
      await page.goto(`/requests/${IDS.basket}${tab.search}`);
      await expect(heading(page, "/rest/basket/6")).toBeVisible();
      await expect(page.getByRole("tab", { name: tab.name, selected: true })).toBeVisible();
      await expectNoAxeViolations(page);
    });
  }

  test(`the not-found state passes axe in the ${theme} theme`, async ({ page }) => {
    await useFixtures(page);
    await setTheme(page, theme);
    await page.goto(`/requests/${requestIdAt(Date.UTC(2026, 10, 1, 13, 11, 0))}`);
    await expect(page.getByText("找不到这个请求")).toBeVisible();
    await expectNoAxeViolations(page);
  });
}

// Two rule rows of the requests fixture (design 4.2): a name that a rule read, and one that could not be
// read. They have no sample record, so the detail is built from the row.
const NAMED_ROW = "req_01a1973d7630773798b4592bb8ca5fde";
const UNKNOWN_ROW = "req_01a1973204807054a82075e6b298fb37";

/** The judgement step of the interface name (the step after the site). */
function nameStep(page: Page) {
  return page.getByRole("list", { name: "判定步骤" }).locator("li").filter({ hasText: "接口名" });
}

test("the head names the interface and where it came from, and the step says the rule", async ({
  page,
}) => {
  await useFixtures(page);
  await page.goto(`/requests/${NAMED_ROW}`);
  await expect(heading(page, "/api/home")).toBeVisible();
  await expect(page.locator(".rd-api")).toContainText("接口 dashboard.HomeService/getStats");
  await expect(page.locator(".rd-api")).toContainText("来自请求头");
  await expect(nameStep(page)).toContainText(
    "规则 /api/home → dashboard.HomeService/getStats（请求头）",
  );
  await expect(nameStep(page).locator(".step-mark")).toHaveText("✓");
});

test("a name that could not be read is a warning in the head, and a ! in the step, with the reason", async ({
  page,
}) => {
  await useFixtures(page);
  await page.goto(`/requests/${UNKNOWN_ROW}`);
  await expect(page.locator(".rd-api-unknown")).toContainText(
    "未知接口：X-Service-Method 出现了多次",
  );
  await expect(nameStep(page)).toContainText("按未知接口处理（不算入口、不走绕过）");
  await expect(nameStep(page).locator(".step-mark")).toHaveText("!");
});

test("a path without a rule says so in grey, and its name is the URL path", async ({ page }) => {
  await useFixtures(page);
  await openBasket(page);
  await expect(nameStep(page)).toContainText("没有规则，用 URL 路径");
  await expect(nameStep(page).locator(".step-mark")).toHaveText("–");
  await expect(nameStep(page)).toHaveClass(/skipped/);
});

test("the values name each value's class and where it came from, and a changed class says so", async ({
  page,
}) => {
  await useFixtures(page);
  await openBasket(page, "?tab=values");
  const table = page.locator(".rd-table");
  await expect(table.getByRole("columnheader", { name: "类别" })).toBeVisible();
  // The class tag is inline-flex, so the cell's accessible name gets a space; the text is what counts.
  const basketClass = table.locator(".rd-cls").filter({ hasText: "basket" });
  await expect(basketClass).toHaveCount(1);
  await expect(basketClass).toContainText("（对象表）");
  await expect(table.getByText("类别不同：count ≠ basket")).toBeVisible();
  await expect(table.getByText("· count", { exact: true })).toBeVisible();
});

test("the Jev view and the explanation say the value was seen only as another class", async ({
  page,
}) => {
  await useFixtures(page);
  await openBasket(page, "?tab=jev");
  await expect(page.getByText("值只以 count 出现过，现在用作 basket")).toBeVisible();
  await expect(page.locator(".explain")).toContainText("只以 count 出现过，现在用作 basket");
});

test("the related rail offers to declare the field's class and to name this path's rule", async ({
  page,
}) => {
  await useFixtures(page);
  await openBasket(page);
  await expect(page.getByRole("link", { name: "把这个字段归类…" })).toHaveAttribute(
    "href",
    /tab=objects&declare=quantity&in=%2Frest%2Fbasket%2F1$/,
  );
  await expect(page.getByRole("link", { name: "为这条路径写接口名规则…" })).toHaveAttribute(
    "href",
    /\/sites\/juice\?tab=config&route=%2Frest%2Fbasket%2F6$/,
  );
});

/** A synthetic record: an ordinary session asks for an administrator's function on emr (docs/06 6.4.4). */
const FUNCTION_ID = "req_c0ffee00c0ffee00c0ffee00c0ffee00";

test("a request that asks for an administrator's function says why, in the explanation and in a functions step", async ({
  page,
}) => {
  await useFixtures(page);
  await page.goto(`/requests/${FUNCTION_ID}`);
  await expect(heading(page, "/api/admin/export")).toBeVisible();

  await expect(page.locator(".explain")).toContainText(
    "请求的是管理档功能 POST /api/admin/export，这个会话不是管理员。",
  );
  const step = page
    .getByRole("list", { name: "判定步骤" })
    .locator("li")
    .filter({ hasText: "管理档功能 POST /api/admin/export" });
  await expect(step).toHaveCount(1);
  await expect(step.getByText("功能", { exact: true })).toBeVisible();
  await expect(step).toContainText("这个会话不是管理员，算尝试越权，交 Jev 并要求拒绝");
});
