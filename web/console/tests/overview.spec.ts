// The overview at "/" (docs/06 6.4.2): the "需要处理" rows with their levels and links, the metric
// cards and the hourly trend. Each warning is set up with mockApi overrides for the status and the
// site list, and for the one site detail or insights that its row reads, so every test states its
// condition and nothing else. Each link is followed to the page it names.

import { expect, type Locator, type Page, test } from "@playwright/test";
import { expectNoAxeViolations, setTheme, type Theme } from "./helpers/axe.ts";
import { siteEmr, statusDown } from "./helpers/fixtures.ts";
import { FIXTURE_NOW_MS, mockApi, reply, servedRequests } from "./helpers/mock-api.ts";
import { changeSite, healthyStatus, quietSites, statusWith } from "./helpers/overview.ts";

/** Opens the overview on the frozen clock (the fixtures are written around FIXTURE_NOW_MS). */
async function openOverview(page: Page, theme?: Theme): Promise<void> {
  if (theme !== undefined) await setTheme(page, theme);
  await page.clock.setFixedTime(FIXTURE_NOW_MS);
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "总览", level: 1 })).toBeVisible();
}

/** The "需要处理" list. */
function attention(page: Page): Locator {
  return page.getByRole("list", { name: "需要处理" });
}

/** The row of the list whose text contains `text`. */
function rowWith(page: Page, text: string): Locator {
  return attention(page).getByRole("listitem").filter({ hasText: text });
}

/** Follows the action named `label` in a row. */
async function follow(row: Locator, label: string): Promise<void> {
  await row.getByRole("link", { name: label, exact: true }).click();
}

/** The browser is on `path`, with each of `search` as a query value. */
async function expectAt(
  page: Page,
  path: string,
  search: Record<string, string> = {},
): Promise<void> {
  await expect(page).toHaveURL(
    (url) =>
      url.pathname === path &&
      Object.entries(search).every(([key, value]) => url.searchParams.get(key) === value),
  );
}

test("the metric cards and the hourly trend render from the summary and the series", async ({
  page,
}) => {
  await mockApi(page);
  await openOverview(page);

  // A card's name is its label and then its figure; the sidebar's "Jev 调用" link has no figure.
  const card = (label: string) => page.getByRole("link", { name: new RegExp(`^${label} \\d`) });
  await expect(card("已判定请求")).toContainText("6,204");
  await expect(card("拦截")).toContainText("23");
  await expect(card("本应拦截")).toContainText("14");
  await expect(card("未经判定")).toContainText("2");
  await expect(card("Jev 调用")).toContainText("478");
  await expect(card("Jev 耗时 p95")).toContainText("910 ms");

  const plot = page.getByRole("region", { name: "每小时请求，按判定路径分组" });
  await expect(plot.locator(".ov-trend-col")).toHaveCount(24);

  await page.getByRole("button", { name: "以表格查看" }).click();
  const table = page.getByRole("table", { name: "每小时请求数，按判定路径分组" });
  await expect(table.getByRole("row")).toHaveCount(25);
});

test("a metric card opens the request list filtered to its figure", async ({ page }) => {
  await mockApi(page);
  await openOverview(page);
  await page.getByRole("link", { name: /^本应拦截/ }).click();
  await expectAt(page, "/requests", { chip: "would_block" });
  await expect(page.getByRole("button", { name: /本应拦截/, pressed: true })).toBeVisible();
});

test("with nothing to handle the card says all is well, with the last check time", async ({
  page,
}) => {
  await mockApi(page, {
    overrides: { "/api/status": healthyStatus(), "/api/sites": { sites: quietSites() } },
  });
  await openOverview(page);
  await expect(page.getByText("一切正常")).toBeVisible();
  await expect(page.getByText("最后检查 21:20:00")).toBeVisible();
  await expect(attention(page)).toHaveCount(0);
});

test("the default fixtures list five rows, most serious first", async ({ page }) => {
  await mockApi(page);
  await openOverview(page);

  const rows = attention(page).getByRole("listitem");
  await expect(rows).toHaveCount(5);
  await expect(rows.nth(0)).toContainText("emr v13 保存后未生效，edge-2 仍是 v12");
  await expect(rows.nth(0)).toContainText("严重");
  await expect(rows.nth(1)).toContainText("有 31 条判定记录未写入");
  await expect(rows.nth(1)).toContainText("严重");
  await expect(rows.nth(2)).toContainText(
    "juice 观察中 6 天：本应拦截 14 条（Jev 拒绝 11、无会话 3）",
  );
  await expect(rows.nth(2)).toContainText("警告");
  await expect(rows.nth(3)).toContainText("在队列压力下丢弃了 6 条绕过记录");
  await expect(rows.nth(3)).toContainText("提示");
  // A hint is marked with a ringed i, as the prototype draws it (docs/06 6.5.3 keeps ● for 正常).
  await expect(rows.nth(3).getByText("i", { exact: true })).toHaveCount(1);
  await expect(rows.nth(4)).toContainText("juice 有 2 条调优建议：登记入口 1、加入绕过 1");
  await expect(rows.nth(4)).toContainText("提示");
});

test("no online gateway is serious and opens the gateway tab; a partition that runs short warns", async ({
  page,
}) => {
  await mockApi(page, {
    overrides: { "/api/status": statusDown, "/api/sites": { sites: quietSites() } },
  });
  await openOverview(page);

  const offline = rowWith(page, "没有在线的网关：3 个实例在 24 小时内上报过心跳，现在都已离线");
  await expect(offline).toContainText("严重");
  await follow(offline, "查看系统");
  await expectAt(page, "/system", { tab: "edges" });
  await expect(page.getByRole("tab", { name: "网关", selected: true })).toBeVisible();

  await openOverview(page);
  const partition = rowWith(page, "判定日志分区不足，未来只有 1 天");
  await expect(partition).toContainText("警告");
  await follow(partition, "查看存储");
  await expectAt(page, "/system", { tab: "storage" });
});

test("a site the gateway refused to load is serious and opens its configuration", async ({
  page,
}) => {
  await mockApi(page, {
    overrides: {
      "/api/status": statusWith({
        problems: [
          {
            kind: "site_load_failed",
            edge: "edge-2",
            site: "emr",
            error: "SITE_CONFIG_ORIGIN_INVALID",
          },
        ],
      }),
      "/api/sites": { sites: quietSites() },
    },
  });
  await openOverview(page);

  const refused = rowWith(page, "edge-2 加载 emr 失败");
  await expect(refused).toContainText("严重");
  await follow(refused, "打开配置");
  await expectAt(page, "/sites/emr", { tab: "config" });
  await expect(page.getByRole("tab", { name: "配置", selected: true })).toBeVisible();
});

test("a version that stays unloaded on a gateway is serious and opens the gateway tab", async ({
  page,
}) => {
  await mockApi(page);
  await openOverview(page);

  const behind = rowWith(page, "emr v13 保存后未生效，edge-2 仍是 v12");
  await expect(behind).toContainText("严重");
  await follow(behind, "查看系统");
  await expectAt(page, "/system", { tab: "edges" });
});

test("a log gap that lost decision records is serious and opens the gap list", async ({ page }) => {
  await mockApi(page);
  await openOverview(page);

  const gap = rowWith(page, "edge-1 21:10–21:12 有 31 条判定记录未写入（队列满）");
  await expect(gap).toContainText("严重");
  await expect(gap).toContainText("这段时间的请求可能查不到");
  await follow(gap, "查看缺口");
  await expectAt(page, "/system", { tab: "storage" });
  await expect(page.getByRole("tab", { name: "日志存储", selected: true })).toBeVisible();
});

test("the requests of a log gap open over the gap's own window", async ({ page }) => {
  await mockApi(page);
  await openOverview(page);

  await follow(rowWith(page, "21:10–21:12"), "查看这段请求");
  await expectAt(page, "/requests", {
    range: "custom",
    since: "1793538600000",
    until: "1793538720000",
  });
  await expect(page.getByRole("heading", { name: "请求追溯", level: 1 })).toBeVisible();
});

test("bypass records dropped under queue pressure are a note, not a gap", async ({ page }) => {
  await mockApi(page, {
    overrides: {
      "/api/status": statusWith({
        problems: [
          {
            kind: "log_gap",
            edge: "edge-1",
            from_ms: 1793538600000,
            to_ms: 1793538720000,
            dropped: 0,
            dropped_bypass: 1204,
            write_errors: 0,
          },
        ],
      }),
      "/api/sites": { sites: quietSites() },
    },
  });
  await openOverview(page);

  const note = rowWith(page, "在队列压力下丢弃了 1,204 条绕过记录（静态资源），判定记录不受影响");
  await expect(note).toContainText("提示");
  await expect(attention(page).getByRole("listitem")).toHaveCount(1);
  await follow(note, "查看系统");
  await expectAt(page, "/system", { tab: "edges" });
});

test("a degraded Jev is a warning that opens the Jev page", async ({ page }) => {
  await mockApi(page, {
    overrides: {
      "/api/status": statusWith({
        jev: { health: "degraded", failures: { JEV_TIMEOUT: 7, JEV_RATE_LIMITED: 2 } },
      }),
      "/api/sites": { sites: quietSites() },
    },
  });
  await openOverview(page);

  const jev = rowWith(page, "Jev 降级：最近 5 分钟失败 9 次（超时 7、服务限流 2）");
  await expect(jev).toContainText("警告");
  await follow(jev, "查看 Jev");
  await expectAt(page, "/jev");
  await expect(page.getByRole("heading", { name: "Jev 调用", level: 1 })).toBeVisible();
});

test("a Jev that is down is serious", async ({ page }) => {
  await mockApi(page, {
    overrides: {
      "/api/status": statusWith({ jev: { health: "down", failures: { JEV_TIMEOUT: 9 } } }),
      "/api/sites": { sites: quietSites() },
    },
  });
  await openOverview(page);

  const jev = rowWith(page, "Jev 不可用：最近 5 分钟失败 9 次（超时 9）");
  await expect(jev).toContainText("严重");
  await follow(jev, "查看 Jev");
  await expectAt(page, "/jev");
});

test("an observed site with would-block requests is a warning, with its breakdown and two links", async ({
  page,
}) => {
  await mockApi(page);
  await openOverview(page);

  const observe = rowWith(page, "juice 观察中 6 天");
  await expect(observe).toContainText("juice 观察中 6 天：本应拦截 14 条（Jev 拒绝 11、无会话 3）");
  await expect(observe).toContainText("警告");

  await follow(observe, "查看");
  await expectAt(page, "/requests", { site: "juice", range: "24h", chip: "would_block" });
  await expect(page.getByRole("button", { name: /本应拦截/, pressed: true })).toBeVisible();

  await openOverview(page);
  await follow(rowWith(page, "juice 观察中 6 天"), "就绪检查");
  await expectAt(page, "/sites/juice", { tab: "insights" });
  await expect(page.getByRole("tab", { name: /调优建议/, selected: true })).toBeVisible();
});

test("an observation row keeps its count, without the breakdown, when the insights cannot be read", async ({
  page,
}) => {
  await mockApi(page, {
    overrides: { "/api/sites/juice/insights": reply(500, { error: "INTERNAL" }) },
  });
  await openOverview(page);

  const observe = rowWith(page, "juice 观察中 6 天");
  await expect(
    observe.getByText("juice 观察中 6 天：本应拦截 14 条", { exact: true }),
  ).toBeVisible();
  const suggest = rowWith(page, "juice 有 2 条调优建议");
  await expect(suggest.getByText("juice 有 2 条调优建议", { exact: true })).toBeVisible();
});

test("a site that is not observing, or has no misses, has no observation row", async ({ page }) => {
  await mockApi(page, {
    overrides: {
      "/api/status": healthyStatus(),
      "/api/sites": { sites: changeSite(quietSites(), "juice", { suggestions: 2 }) },
    },
  });
  await openOverview(page);

  await expect(rowWith(page, "调优建议")).toBeVisible();
  await expect(rowWith(page, "观察中")).toHaveCount(0);
});

test("open suggestions are a note that names each kind and opens the insights tab", async ({
  page,
}) => {
  await mockApi(page);
  await openOverview(page);

  const suggest = rowWith(page, "juice 有 2 条调优建议");
  await expect(suggest).toContainText("登记入口 1、加入绕过 1");
  await expect(suggest).toContainText("提示");
  await follow(suggest, "查看建议");
  await expectAt(page, "/sites/juice", { tab: "insights" });
  await expect(page.getByRole("tab", { name: /调优建议/, selected: true })).toBeVisible();
});

test("unjudged requests on a site that allows them are a warning that lists them", async ({
  page,
}) => {
  await mockApi(page, {
    overrides: {
      "/api/status": healthyStatus(),
      "/api/sites": { sites: changeSite(quietSites(), "emr", { unjudged_24h: 5 }) },
      "/api/sites/emr": { ...siteEmr, spec: { ...siteEmr.spec, on_jev_unavailable: "allow" } },
    },
  });
  await openOverview(page);

  const unjudged = rowWith(page, "emr 有 5 个请求未经判定就放行了");
  await expect(unjudged).toContainText("警告");
  await follow(unjudged, "查看");
  await expectAt(page, "/requests", { site: "emr", range: "24h", chip: "unjudged" });
  await expect(page.getByRole("button", { name: /未经判定/, pressed: true })).toBeVisible();
});

test("unjudged requests on a site that denies them have no row", async ({ page }) => {
  await mockApi(page, {
    overrides: {
      "/api/status": healthyStatus(),
      "/api/sites": { sites: changeSite(quietSites(), "emr", { unjudged_24h: 5 }) },
    },
  });
  await openOverview(page);

  // The card says all is well only after the detail has answered, so this also waits for it.
  await expect(page.getByText("一切正常")).toBeVisible();
  await expect(rowWith(page, "未经判定")).toHaveCount(0);
});

test("Jev timeouts at one percent of the calls are a note that opens the site's evidence", async ({
  page,
}) => {
  await mockApi(page, {
    overrides: {
      "/api/status": healthyStatus(),
      "/api/sites": { sites: changeSite(quietSites(), "emr", { jev_timeouts_24h: 9 }) },
    },
  });
  await openOverview(page);

  const evidence = rowWith(page, "emr Jev 超时 9 次 / 412 次调用");
  await expect(evidence).toContainText("提示");
  await follow(evidence, "查看证据");
  await expectAt(page, "/sites/emr", { tab: "config", group: "advanced" });
  await expect(page.getByText("Jev 证据", { exact: true })).toBeVisible();
});

test("call-limit hits at one percent of the calls are a note too", async ({ page }) => {
  await mockApi(page, {
    overrides: {
      "/api/status": healthyStatus(),
      "/api/sites": { sites: changeSite(quietSites(), "emr", { call_limits_24h: 6 }) },
    },
  });
  await openOverview(page);

  const evidence = rowWith(page, "emr 触发调用上限 6 次 / 412 次调用");
  await expect(evidence).toContainText("提示");
  await expect(evidence.getByRole("link", { name: "查看证据", exact: true })).toBeVisible();
});

test("three Jev timeouts in 412 calls are under the line, so the card says all is well", async ({
  page,
}) => {
  // The site list of the fixtures: emr has 3 timeouts in 412 calls, 0.7 percent.
  await mockApi(page, {
    overrides: {
      "/api/status": healthyStatus(),
      "/api/sites": { sites: changeSite(quietSites(), "emr", { jev_timeouts_24h: 3 }) },
    },
  });
  await openOverview(page);
  await expect(page.getByText("一切正常")).toBeVisible();
  await expect(rowWith(page, "Jev 超时")).toHaveCount(0);
});

test("a failed site list says so, and the gateway rows still show", async ({ page }) => {
  await mockApi(page, { overrides: { "/api/sites": reply(500, { error: "INTERNAL" }) } });
  await openOverview(page);

  await expect(page.getByText("站点数据读取失败")).toBeVisible();
  await expect(rowWith(page, "emr v13 保存后未生效")).toBeVisible();
  await expect(page.getByText("一切正常")).toHaveCount(0);
});

test("a site detail that cannot be read says so, and the card does not claim all is well", async ({
  page,
}) => {
  await mockApi(page, {
    overrides: {
      "/api/status": healthyStatus(),
      "/api/sites": { sites: changeSite(quietSites(), "emr", { unjudged_24h: 5 }) },
      "/api/sites/emr": reply(500, { error: "INTERNAL" }),
    },
  });
  await openOverview(page);

  await expect(page.getByText("部分站点的详情读取失败")).toBeVisible();
  await expect(page.getByText("一切正常")).toHaveCount(0);
});

test("a site's detail and insights are read only where its row needs them", async ({ page }) => {
  await mockApi(page);
  await openOverview(page);
  await expect(rowWith(page, "juice 有 2 条调优建议")).toContainText("登记入口 1、加入绕过 1");

  const reads = servedRequests(page)
    .filter((call) => call.method === "GET" && call.path.startsWith("/api/sites/"))
    .map((call) => call.path);
  expect(reads).toEqual(["/api/sites/juice/insights"]);
});

for (const theme of ["light", "dark"] satisfies Theme[]) {
  test(`the overview with its rows passes axe in the ${theme} theme`, async ({ page }) => {
    await mockApi(page);
    await openOverview(page, theme);
    await expect(rowWith(page, "登记入口 1、加入绕过 1")).toBeVisible();
    await expectNoAxeViolations(page);
  });

  test(`the overview with nothing to handle passes axe in the ${theme} theme`, async ({ page }) => {
    await mockApi(page, {
      overrides: { "/api/status": healthyStatus(), "/api/sites": { sites: quietSites() } },
    });
    await openOverview(page, theme);
    await expect(page.getByText("一切正常")).toBeVisible();
    await expectNoAxeViolations(page);
  });
}
