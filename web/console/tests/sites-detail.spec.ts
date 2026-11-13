// The site page at /sites/$name (docs/06 6.4.9): five tabs over one draft. Each tab renders from the fixtures,
// the tuning suggestions can be added to the draft, and every tab passes axe in both themes.

import { expect, type Page, test } from "@playwright/test";
import { expectNoAxeViolations, setTheme, type Theme } from "./helpers/axe.ts";
import { mockApi, reply } from "./helpers/mock-api.ts";
import { callsTo, freezeClock } from "./helpers/sites-flow.ts";

async function openSite(page: Page, path: string): Promise<void> {
  await freezeClock(page);
  await mockApi(page);
  await page.goto(path);
  await expect(page.getByRole("tablist")).toBeVisible();
}

test("the overview of an enforcing site shows its 24-hour figures", async ({ page }) => {
  await openSite(page, "/sites/emr");

  await expect(page.getByRole("heading", { level: 1, name: "emr" })).toBeVisible();
  await expect(page.getByRole("link", { name: /^24 小时请求/ })).toContainText("9,812");
  await expect(page.getByRole("link", { name: /^拦截/ })).toContainText("21");
  await expect(page.getByRole("link", { name: /^Jev 调用 \d/ })).toContainText("412");
  // Only an observing site shows the readiness checklist on its overview.
  await expect(page.getByRole("list", { name: "就绪检查" })).toHaveCount(0);
  // The overview reads no Jev evidence: the advanced group reads it when it opens (docs/07 7.10.4).
  await expect(page.getByText("没有集中的本应拦截路径。")).toBeVisible();
  expect(callsTo(page, "GET", "/api/sites/emr/evidence")).toHaveLength(0);
});

test("the overview of an observing site shows its readiness checklist", async ({ page }) => {
  await openSite(page, "/sites/juice");

  await expect(page.getByRole("link", { name: /^本应拦截/ })).toContainText("14");
  const readiness = page.getByRole("list", { name: "就绪检查" });
  await expect(readiness).toContainText("已观察 6 天 4 小时");
  await expect(readiness).toContainText("本应拦截 14 条：Jev 拒绝 11 · 无会话 3");
  await expect(readiness).toContainText("Jev 不可用时：拒绝");

  // Only the row of blocked-to-be requests opens them one by one (docs/06 line 627).
  await expect(readiness.getByRole("link", { name: "逐条查看" })).toHaveCount(1);
  await readiness
    .getByRole("listitem")
    .filter({ hasText: "本应拦截 14 条" })
    .getByRole("link", { name: "逐条查看" })
    .click();
  await expect(page).toHaveURL(
    (url) =>
      url.pathname === "/requests" &&
      url.searchParams.get("site") === "juice" &&
      url.searchParams.get("chip") === "would_block",
  );
});

test("the five tabs are overview, configuration, object map, tuning suggestions and history", async ({
  page,
}) => {
  // juice has no object map yet, so its tab has no count; emr's shows its seven proposals.
  await openSite(page, "/sites/juice");

  const tabs = page.getByRole("tab");
  await expect(tabs).toHaveText(["概览", "配置", "对象表", "调优建议 2", "变更历史"]);
  await expect(page.getByRole("tab", { name: "概览" })).toHaveAttribute("aria-selected", "true");

  await page.getByRole("tab", { name: "变更历史" }).click();
  await expect(page).toHaveURL(/tab=history/);
  await expect(page.getByRole("table", { name: "版本历史" })).toBeVisible();
});

test("the configuration tab shows the saved fields of the site", async ({ page }) => {
  await openSite(page, "/sites/emr?tab=config");

  await expect(page.getByLabel("源站地址")).toHaveValue("http://10.0.0.5:8080");
  await expect(page.getByRole("group", { name: "Host" })).toContainText("emr.example.com");
  const groups = page.getByRole("navigation", { name: "配置分组" });
  await expect(groups.getByRole("button", { name: /^入口/ })).toContainText("3");
  await expect(groups.getByRole("button", { name: /^绕过/ })).toContainText("2");

  await groups.getByRole("button", { name: /^会话凭证/ }).click();
  await expect(page.getByLabel("名称")).toHaveValue("Authorization");

  await groups.getByRole("button", { name: /^入口/ }).click();
  const entries = page.getByRole("list", { name: "入口" });
  await expect(entries).toContainText("/login");
  await expect(entries).toContainText("/api/patients");

  await groups.getByRole("button", { name: /^高级判定参数/ }).click();
  await expect(page.getByText("已自定义 2 项：Jev 超时 3000 ms、追加脱敏词 2 个")).toBeVisible();
});

test("the Jev evidence is read only when the advanced group opens", async ({ page }) => {
  await openSite(page, "/sites/emr?tab=config");
  await expect(page.getByLabel("源站地址")).toHaveValue("http://10.0.0.5:8080");
  expect(callsTo(page, "GET", "/api/sites/emr/evidence")).toHaveLength(0);

  await page
    .getByRole("navigation", { name: "配置分组" })
    .getByRole("button", { name: /^高级判定参数/ })
    .click();
  await expect
    .poll(() => callsTo(page, "GET", "/api/sites/emr/evidence").length)
    .toBeGreaterThan(0);
  await expect(
    page.getByRole("heading", { level: 2, name: "Jev 证据", exact: true }),
  ).toBeVisible();
});

test("built-in redaction words and synonyms are dashed chips with no remove control", async ({
  page,
}) => {
  await openSite(page, "/sites/emr?tab=config&group=advanced");

  const builtin = page.getByTitle("内置词，不能删除");
  await expect(builtin).toHaveText([
    "authorization",
    "credential",
    "cvv",
    "otp",
    "passwd",
    "password",
    "pwd",
    "secret",
    "token",
    "card ↔ payment",
  ]);
  const count = await builtin.count();
  for (let index = 0; index < count; index += 1) {
    await expect(builtin.nth(index)).toHaveCSS("border-top-style", "dashed");
  }
  await expect(page.getByRole("button", { name: "删除 password" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "删除 idcard" })).toBeVisible();
  await expect(page.getByText("🔒")).toHaveCount(0);
});

test("under 768 px the configuration stays editable and says to edit on a desktop", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await openSite(page, "/sites/emr?tab=config");

  await expect(page.getByText("建议在桌面端修改配置")).toBeVisible();
  await expect(page.getByLabel("源站地址")).toBeEditable();
});

test("at desktop width the configuration tab carries no mobile hint", async ({ page }) => {
  await openSite(page, "/sites/emr?tab=config");

  await expect(page.getByText("建议在桌面端修改配置")).toBeHidden();
});

test("the tuning suggestions show each change and can be added to the draft", async ({ page }) => {
  await openSite(page, "/sites/juice?tab=insights");

  const entry = page.getByRole("region", { name: "登记入口" });
  await expect(entry).toContainText("/rest/admin/application-configuration");
  await expect(entry).toContainText("312 次");
  await expect(entry.getByRole("list", { name: "改动" })).toContainText(
    "入口 ＋ /rest/admin/application-configuration",
  );

  // The static-resource suggestion offers the directory or the exact path; the directory is the default.
  const bypass = page.getByRole("region", { name: "加入绕过" });
  await expect(bypass.getByRole("list", { name: "改动" })).toContainText("绕过 ＋ /assets/*");
  await bypass.getByRole("radio", { name: /精确路径/ }).check();
  await expect(bypass.getByRole("list", { name: "改动" })).toContainText(
    "绕过 ＋ /assets/i18n/en.json",
  );

  await entry.getByRole("button", { name: "加入草稿" }).click();
  await expect(page.getByText("未保存的改动 1 处")).toBeVisible();

  await page.getByRole("button", { name: "去配置查看" }).click();
  await expect(page.getByRole("region", { name: "未保存的改动" })).toBeVisible();
  await page
    .getByRole("navigation", { name: "配置分组" })
    .getByRole("button", { name: /^入口/ })
    .click();
  await expect(page.getByRole("list", { name: "入口" })).toContainText(
    "/rest/admin/application-configuration",
  );
});

test("the history lists every version with its note and kind", async ({ page }) => {
  await openSite(page, "/sites/emr?tab=history");

  const history = page.getByRole("table", { name: "版本历史" });
  await expect(history.getByRole("row")).toHaveCount(14); // the header row and v13 to v1
  const current = history.getByRole("row").filter({ hasText: "追加脱敏字段 ssn" });
  await expect(current).toContainText("v13");
  await expect(current).toContainText("当前");
  await expect(current).not.toContainText("以此版本回滚");
  const created = history.getByRole("row").filter({ hasText: "创建站点（观察模式）" });
  await expect(created).toContainText("创建");
  await expect(created).toContainText("新建站点");
});

test("an unknown site says it is not there", async ({ page }) => {
  await freezeClock(page);
  await mockApi(page);
  await page.goto("/sites/nope");

  await expect(page.getByRole("alert")).toContainText("站点不存在，可能已被删除");
  await expect(page.getByRole("alert")).toContainText("SITE_NOT_FOUND");
});

test("a failed delete says so and stays on the page", async ({ page }) => {
  await freezeClock(page);
  await mockApi(page, {
    overrides: { "DELETE /api/sites/emr": reply(500, { error: "INTERNAL" }) },
  });
  await page.goto("/sites/emr");
  await expect(page.getByRole("tablist")).toBeVisible();

  await page.getByRole("button", { name: "更多操作" }).click();
  await page.getByRole("menuitem", { name: "删除站点" }).click();
  const confirm = page.getByRole("dialog", { name: "删除站点 emr？" });
  await confirm.getByRole("button", { name: "删除站点" }).click();

  await expect.poll(() => callsTo(page, "DELETE", "/api/sites/emr").length).toBe(1);
  await expect(page.getByRole("alert")).toBeVisible();
  await expect(page).toHaveURL((url) => url.pathname === "/sites/emr");
  await expect(page.getByRole("heading", { level: 1, name: "emr" })).toBeVisible();
});

const PAGES = [
  { name: "the overview", path: "/sites/emr" },
  { name: "the observing overview with its readiness checklist", path: "/sites/juice" },
  { name: "the configuration form", path: "/sites/emr?tab=config" },
  { name: "the configuration YAML", path: "/sites/emr?tab=config&edit=yaml" },
  { name: "the object map", path: "/sites/emr?tab=objects" },
  { name: "the tuning suggestions", path: "/sites/juice?tab=insights" },
  { name: "the change history", path: "/sites/emr?tab=history" },
  { name: "the advanced parameters", path: "/sites/emr?tab=config&group=advanced" },
] as const;

for (const theme of ["light", "dark"] satisfies Theme[]) {
  for (const target of PAGES) {
    test(`${target.name} passes axe in the ${theme} theme`, async ({ page }) => {
      await freezeClock(page);
      await mockApi(page);
      await setTheme(page, theme);
      await page.goto(target.path);
      await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
      if (target.path.includes("edit=yaml")) {
        await expect(page.getByRole("textbox", { name: "站点配置，YAML 或 JSON" })).toBeVisible();
      }
      await expectNoAxeViolations(page);
    });
  }
}
