import AxeBuilder from "@axe-core/playwright";
import { expect, type Page, test } from "@playwright/test";
import { errorFixture, REQUEST_ID } from "./fixtures";
import { sessionBody, TRACE_ID } from "./shell-helpers";

// Cookie-session (OIDC) mode: roles come from the server, so these checks cover what the
// machine-login build cannot - role-dependent navigation, palette filtering and the step-up UI.

type SessionMock = {
  roles: string[];
  overrides?: Record<string, unknown>;
  /** Roles the server reports once `control.switched` is set. */
  later?: { roles: string[]; control: { switched: boolean } };
};

async function mockSession(page: Page, options: SessionMock, origin = "http://127.0.0.1") {
  const calls: { path: string; method: string; csrf: string | null }[] = [];
  await page.route("**/control/v1/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    calls.push({
      path: url.pathname,
      method: request.method(),
      csrf: await request.headerValue("x-xshield-csrf"),
    });
    if (url.pathname === "/control/v1/session" && request.method() === "GET") {
      const roles = options.later?.control.switched ? options.later.roles : options.roles;
      await route.fulfill({ json: sessionBody(roles, options.overrides) });
    } else if (url.pathname === "/control/v1/session/logout") {
      await route.fulfill({ status: 204 });
    } else if (url.pathname === "/control/v1/auth/oidc/reauth/start") {
      await route.fulfill({
        json: {
          schema_version: 3,
          request_id: REQUEST_ID,
          tenant_id: "tenant_demo",
          site_id: "site_demo",
          authorization_url: `${origin}/__reauth?state=synthetic`,
        },
      });
    } else {
      await route.fulfill({ status: 403, json: errorFixture("CONTROL_SCOPE_DENIED") });
    }
  });
  return calls;
}

const palette = (page: Page) => page.getByRole("combobox", { name: "命令面板" });
const optionLabels = (page: Page) => page.getByRole("option").allTextContents();

test.describe("command palette respects role visibility", () => {
  test("an observer opens detail routes but is offered no search or case page", async ({
    page,
  }) => {
    await mockSession(page, { roles: ["observer"] });
    await page.goto("/access/session");
    await expect(page.getByRole("heading", { name: "当前管理会话" })).toBeVisible();
    await page.keyboard.press("Control+KeyK");
    await palette(page).fill(REQUEST_ID);
    expect(await optionLabels(page)).toEqual([expect.stringContaining("打开请求调查")]);

    await palette(page).fill(TRACE_ID);
    expect(await optionLabels(page)).toEqual([]);
    await expect(page.getByText("已识别为Trace ID，但当前角色看不到对应页面。")).toBeVisible();

    await palette(page).fill("案件");
    expect(await optionLabels(page)).toEqual([]);
    await palette(page).fill("");
    const pages = await optionLabels(page);
    expect(pages.some((text) => text.includes("案件工作台"))).toBe(false);
    expect(pages.some((text) => text.includes("站点状态"))).toBe(true);
    expect(pages.some((text) => text.includes("模型调用详情"))).toBe(true);
  });

  test("an investigator searches events; hold-ID search additionally needs the audit role", async ({
    page,
  }) => {
    await mockSession(page, { roles: ["investigator"] });
    await page.goto("/access/session");
    await expect(page.getByRole("heading", { name: "当前管理会话" })).toBeVisible();
    await page.keyboard.press("Control+KeyK");
    await palette(page).fill(TRACE_ID);
    expect(await optionLabels(page)).toEqual([
      expect.stringContaining("在事件检索中查找 Trace ID"),
    ]);
    const eventOrHold = `ev_018f2a3b-4c5d-7000-8000-000000000012`;
    await palette(page).fill(eventOrHold);
    const labels = await optionLabels(page);
    expect(labels).toEqual([expect.stringContaining("在事件检索中查找 事件 ID")]);
    await palette(page).fill("请求");
    expect(await optionLabels(page)).toEqual([expect.stringContaining("请求调查")]);
    // A system administrator sees neither investigation pages nor event search.
  });

  test("a system administrator is offered configuration pages only", async ({ page }) => {
    await mockSession(page, { roles: ["system_admin"] });
    await page.goto("/access/session");
    await expect(page.getByRole("heading", { name: "当前管理会话" })).toBeVisible();
    await page.keyboard.press("Control+KeyK");
    await palette(page).fill("");
    const pages = await optionLabels(page);
    expect(pages.map((text) => text.replace(/\s+/g, ""))).toEqual([
      "概览工作台",
      "受保护站点站点",
      "APIKey运维与治理",
      "权限中心运维与治理",
    ]);
  });
});

test.describe("step-up status and the session menu", () => {
  test("the chip counts down the two-minute window, then offers re-verification", async ({
    page,
  }) => {
    await page.clock.install({ time: new Date("2026-09-20T08:00:30.000Z") });
    await mockSession(page, {
      roles: ["investigator"],
      overrides: { step_up_valid: true, last_reauthenticated_at: "2026-09-20T08:00:00.000Z" },
    });
    await page.goto("/access/session");
    // The fake clock keeps running in real time after install, so allow one second of drift.
    await expect(page.getByText(/^MFA 再认证有效 · 剩余 1:(30|29)$/)).toBeVisible();
    await page.clock.runFor(31_000);
    await expect(page.getByText(/^MFA 再认证有效 · 剩余 0:(59|58|57)$/)).toBeVisible();
    await page.clock.runFor(61_000);
    await expect(page.getByText("高危操作需要 MFA 再认证", { exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "重新验证高危操作", exact: true })).toBeVisible();
  });

  test("re-verification starts the OIDC step-up with the CSRF header and then leaves", async ({
    page,
    baseURL,
  }) => {
    const calls = await mockSession(page, { roles: ["investigator"] }, baseURL);
    await page.route("**/__reauth**", (route) =>
      route.fulfill({ contentType: "text/html", body: "<title>idp</title>idp" }),
    );
    await page.goto("/access/session");
    await expect(page.getByText("高危操作需要 MFA 再认证", { exact: true })).toBeVisible();
    await page.getByRole("button", { name: "重新验证高危操作", exact: true }).click();
    await page.waitForURL("**/__reauth?state=synthetic");
    const start = calls.find((call) => call.path === "/control/v1/auth/oidc/reauth/start");
    expect(start).toMatchObject({ method: "POST", csrf: "a".repeat(64) });
  });

  test("the user menu offers the session page, theme, density, step-up and secure sign-out", async ({
    page,
  }) => {
    const calls = await mockSession(page, { roles: ["observer"] });
    await page.goto("/investigation/requests");
    await expect(page.getByRole("button", { name: "断开连接" })).toHaveCount(0);
    const menu = page.locator(".ant-dropdown-menu");
    await page.getByRole("button", { name: "用户菜单" }).click();
    for (const name of ["权限中心", "主题", "密度", "重新验证高危操作", "安全退出"]) {
      await expect(menu.getByRole("menuitem", { name })).toBeVisible();
    }
    await menu.getByRole("menuitem", { name: "权限中心" }).click();
    await expect(page).toHaveURL(/\/access\/session$/);

    await page.getByRole("button", { name: "用户菜单" }).click();
    await menu.getByRole("menuitem", { name: "安全退出" }).click();
    await expect(page.getByRole("heading", { name: "企业身份登录" })).toBeVisible();
    await expect(page.getByRole("status")).toContainText("已安全退出管理会话。");
    await expect(page.getByRole("button", { name: "使用企业身份登录" })).toBeVisible();
    expect(
      calls.some(
        (call) => call.path === "/control/v1/session/logout" && call.csrf === "a".repeat(64),
      ),
    ).toBe(true);
  });

  test("refreshing the session re-reads the server roles through the guarded layer", async ({
    page,
  }) => {
    const control = { switched: false };
    const calls = await mockSession(page, {
      roles: ["observer"],
      later: { roles: ["observer", "investigator"], control },
    });
    await page.goto("/access/session");
    const nav = page.getByRole("complementary", { name: "后台导航" });
    await expect(nav.getByRole("link", { name: "请求调查", exact: true })).toBeVisible();
    await expect(nav.getByRole("link", { name: "案件工作台", exact: true })).toHaveCount(0);
    const reads = () => calls.filter((call) => call.path === "/control/v1/session").length;
    const before = reads();
    control.switched = true;
    await page.getByRole("button", { name: "刷新会话信息" }).click();
    await expect(nav.getByRole("link", { name: "案件工作台", exact: true })).toBeVisible();
    await expect(page.locator("main")).toContainText("observer、investigator");
    expect(reads()).toBe(before + 1);
  });
});

for (const scheme of ["light", "dark"] as const) {
  test.describe(`sign-in screen (${scheme})`, () => {
    test.use({ colorScheme: scheme });

    test("the OIDC sign-in has no serious accessibility violations", async ({ page }) => {
      await page.route("**/control/v1/session", (route) =>
        route.fulfill({ status: 401, json: errorFixture("CONTROL_AUTH_REQUIRED") }),
      );
      await page.goto("/");
      await expect(page.getByRole("button", { name: "使用企业身份登录" })).toBeVisible();
      await expect(page.getByLabel("管理凭证", { exact: true })).toHaveCount(0);
      const results = await new AxeBuilder({ page }).analyze();
      expect(
        results.violations
          .filter((violation) => violation.impact === "critical" || violation.impact === "serious")
          .map((violation) => violation.id),
      ).toEqual([]);
    });
  });
}
