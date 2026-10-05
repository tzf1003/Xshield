import { expect, type Page, test } from "@playwright/test";
import { serious } from "./axe";
import { errorFixture } from "./fixtures";
import { JOB_ID, mockWorkbench, reads, SECRET, settledReads } from "./workbench-helpers";

// Cookie-session (OIDC) mode: roles come from the server, so these checks cover what the
// machine-login build cannot: which sources each role reads, and the hints for the rest.

const kpi = (page: Page, label: string) =>
  page.getByRole("list", { name: "关键指标" }).getByRole("listitem").filter({ hasText: label });
const todo = (page: Page) => page.getByRole("region", { name: /待我处理/ });

test.describe("the workbench follows the roles the server reports", () => {
  test("a system administrator reads the site list: failed applies and approvals lead to the release page", async ({
    page,
  }) => {
    const calls = await mockWorkbench(page, {
      roles: ["system_admin"],
      overview: { noAudit: true },
    });
    await page.goto("/");
    await expect(todo(page).getByText("应用失败：Gamma 支付")).toBeVisible();
    await expect(todo(page).getByText("待审批修订：Beta 商城")).toBeVisible();
    await settledReads(page, calls, [
      "/control/v1/session",
      "/control/v1/workbench/overview",
      "/control/v1/sites?limit=100",
    ]);
    await expect(kpi(page, "待审批修订")).toContainText("1");
    await expect(kpi(page, "审计发布")).toContainText("只对 AuditAdministrator 读取");
    await expect(
      page.getByRole("region", { name: "审计发布" }).getByText("需要 AuditAdministrator 角色"),
    ).toBeVisible();
    await expect(page.getByRole("region", { name: "最近被拒绝的请求" })).toHaveCount(0);
    await expect(page.getByRole("button", { name: /刷新 Alpha 官网 的健康/ })).toHaveCount(0);
    await expect(page.getByText("刷新健康需要 Observer 角色").first()).toBeVisible();
  });

  test("an evidence approver reads the review queues only, and links into the approval center", async ({
    page,
  }) => {
    const calls = await mockWorkbench(page, {
      roles: ["sensitive_evidence_approver"],
      overview: { noSites: true, noAudit: true },
    });
    await page.goto("/");
    const rows = todo(page).getByRole("list", { name: "待处理事项" }).getByRole("listitem");
    await expect(rows).toHaveCount(2);
    await expect(rows.filter({ hasText: "导出申请待审批" }).getByRole("link")).toHaveAttribute(
      "href",
      /^\/approvals\?item=export_/,
    );
    await settledReads(page, calls, [
      "/control/v1/session",
      "/control/v1/workbench/overview",
      "/control/v1/evidence-access-requests?view=review",
      "/control/v1/exports?view=review",
    ]);
    await expect(kpi(page, "正在服务的站点")).toContainText("快照只为 SystemAdmin 投影站点列表");
    await expect(kpi(page, "待审批修订")).toContainText("当前角色不读取站点清单");
    await expect(page.getByRole("region", { name: "站点健康" })).toContainText("快照没有站点列表");
  });

  test("an observer's refused site list is a role hint; the snapshot still says what it can", async ({
    page,
  }) => {
    await mockWorkbench(page, {
      roles: ["observer"],
      overview: { noSites: true, noAudit: true },
      override: (url) =>
        url.pathname === "/control/v1/sites"
          ? { status: 403, body: errorFixture("CONTROL_SCOPE_DENIED") }
          : undefined,
    });
    await page.goto("/");
    const card = todo(page);
    await expect(card.getByText("站点清单：服务端拒绝了当前身份")).toBeVisible();
    await expect(card.getByRole("alert").filter({ hasText: "读取失败" })).toHaveCount(0);
    await expect(card).toContainText("已读取的来源中没有待处理事项");
    await expect(kpi(page, "待审批修订")).toContainText("需要 SystemAdmin");
    // The session's own site stays reachable for an observer.
    await expect(
      page.getByRole("region", { name: "站点健康" }).getByRole("link", { name: "站点状态" }),
    ).toHaveAttribute("href", "/sites/site_demo/overview");
  });

  test("an investigator gets the denied-requests card and no todo sources", async ({ page }) => {
    const calls = await mockWorkbench(page, {
      roles: ["investigator"],
      overview: { noSites: true, noAudit: true },
    });
    await page.goto("/");
    await expect(page.getByRole("region", { name: "最近被拒绝的请求" })).toBeVisible();
    await expect(todo(page)).toContainText("当前角色没有需要在这里处理的待办来源");
    await settledReads(page, calls, ["/control/v1/session", "/control/v1/workbench/overview"]);
    expect(calls.some((call) => call.path === "/control/v1/search")).toBe(false);
    // Quick links follow the role.
    const links = page.getByRole("navigation", { name: "快捷入口" }).getByRole("link");
    await expect(links.first()).toHaveText("审批中心");
    await expect(links).toContainText(["审批中心", "案件工作台", "结构化检索", "请求调查"]);
  });

  test("an audit administrator sees the publication card from the snapshot", async ({ page }) => {
    await mockWorkbench(page, {
      roles: ["audit_administrator"],
      overview: { noSites: true },
    });
    await page.goto("/");
    const card = page.getByRole("region", { name: "审计发布" });
    await expect(card).toContainText("连续发布");
    await expect(card).toContainText("连续水位");
    await expect(card).toContainText("#42");
    await expect(card.getByRole("link", { name: "查看审计发布状态" })).toHaveAttribute(
      "href",
      "/operations/audit",
    );
    await expect(kpi(page, "审计发布")).toContainText("连续");
  });
});

test.describe("权限中心 explains the session and what each role unlocks", () => {
  test("subject, scope, expiries and every role with its pages; no secret", async ({ page }) => {
    await page.clock.install({ time: new Date("2026-12-31T23:00:00.000Z") });
    const calls = await mockWorkbench(page, { roles: ["observer", "key_administrator"] });
    await page.goto("/access/session");
    const session = page.getByRole("region", { name: "当前管理会话" });
    await expect(session).toContainText("test-subject");
    await expect(session).toContainText("tenant_demo");
    await expect(session).toContainText("site_demo");
    await expect(session).toContainText("浏览器 OIDC 会话");
    await expect(session).toContainText("observer、key_administrator");
    await expect(session).toContainText("尚未再认证");
    await expect(session).toContainText("未生效");
    const roles = page.getByRole("list", { name: "角色" }).getByRole("listitem");
    await expect(roles).toHaveCount(2);
    const observer = roles.filter({ hasText: "Observer" });
    await expect(observer).toContainText("只读查看脱敏摘要");
    await expect(observer.getByRole("link", { name: "站点状态" })).toHaveAttribute(
      "href",
      "/sites/site_demo/overview",
    );
    const keys = roles.filter({ hasText: "KeyAdministrator" });
    await expect(keys).toContainText("签发带权限的 Key 还需要对应的站点角色");
    await expect(keys.getByRole("link", { name: "API Key" })).toHaveAttribute(
      "href",
      "/admin/api-keys",
    );
    // The CSRF companion of the session is never rendered.
    expect(await page.evaluate(() => document.body.innerHTML.includes("a".repeat(64)))).toBe(false);
    await page.waitForTimeout(300);
    expect(reads(calls)).toEqual(["/control/v1/session"]);
  });

  test("a valid step-up counts down locally and lapses", async ({ page }) => {
    await page.clock.install({ time: new Date("2026-09-20T08:00:30.000Z") });
    await mockWorkbench(page, { roles: ["investigator"] });
    await page.route("**/control/v1/session", (route) =>
      route.fulfill({
        json: {
          subject: "test-subject",
          tenant_id: "tenant_demo",
          site_id: "site_demo",
          roles: ["investigator"],
          csrf_token: "a".repeat(64),
          session_expires_at: "2026-09-20T16:00:00.000Z",
          idle_expires_at: "2026-09-20T08:15:00.000Z",
          last_reauthenticated_at: "2026-09-20T08:00:00.000Z",
          step_up_valid: true,
        },
      }),
    );
    await page.goto("/access/session");
    const session = page.getByRole("region", { name: "当前管理会话" });
    await expect(session.getByText(/^有效 · 剩余 1:(30|29)$/)).toBeVisible();
    await page.clock.runFor(95_000);
    await expect(session.getByText("未生效", { exact: true })).toBeVisible();
  });
});

const ALL = [
  "system_admin",
  "key_administrator",
  "observer",
  "investigator",
  "audit_administrator",
  "sensitive_evidence_approver",
  "policy_approver",
  "release_operator",
];

for (const scheme of ["light", "dark"] as const) {
  test.describe(`operations accessibility (${scheme})`, () => {
    test.use({ colorScheme: scheme });

    test("workbench with data and the denied requests", async ({ page }) => {
      await mockWorkbench(page, { roles: ALL });
      await page.goto("/");
      await expect(page.getByText("Gamma 支付").first()).toBeVisible();
      await page.getByRole("button", { name: "读取最近被拒绝的请求" }).click();
      await expect(page.getByRole("list", { name: "被拒绝的请求" })).toBeVisible();
      expect(await serious(page)).toEqual([]);
    });

    test("workbench with failing and refused sources", async ({ page }) => {
      await mockWorkbench(page, {
        roles: ALL,
        overview: { noAudit: true },
        override: (url) =>
          url.pathname === "/control/v1/exports"
            ? { status: 503, body: errorFixture("CONTROL_EXPORT_STORE_UNAVAILABLE") }
            : url.pathname === "/control/v1/sites"
              ? { status: 403, body: errorFixture("CONTROL_SCOPE_DENIED") }
              : undefined,
      });
      await page.goto("/");
      await expect(page.getByText("导出待办读取失败")).toBeVisible();
      expect(await serious(page)).toEqual([]);
    });

    test("audit publication with a result", async ({ page }) => {
      await mockWorkbench(page, { roles: ALL });
      await page.goto("/operations/audit");
      await page.getByRole("button", { name: "读取发布状态" }).click();
      await expect(page.getByRole("region", { name: "审计发布状态结果" })).toBeVisible();
      expect(await serious(page)).toEqual([]);
    });

    test("job lookup with a result and a misread ID", async ({ page }) => {
      await mockWorkbench(page, { roles: ALL });
      await page.goto(`/operations/jobs?job=${JOB_ID}`);
      await expect(page.getByText("清单分析完成").first()).toBeVisible();
      expect(await serious(page)).toEqual([]);
      await page.getByLabel("任务 ID", { exact: true }).fill("case_123");
      await page.getByRole("button", { name: "查询", exact: true }).click();
      await expect(page.getByText(/不是任务 ID|格式/).first()).toBeVisible();
      expect(await serious(page)).toEqual([]);
    });

    test("API keys: list, create form and the one-time plaintext", async ({ page }) => {
      await mockWorkbench(page, { roles: ALL });
      await page.goto("/admin/api-keys");
      await expect(page.getByText("部署机器人").first()).toBeVisible();
      expect(await serious(page)).toEqual([]);
      await page.getByRole("button", { name: "创建 API Key" }).click();
      const dialog = page.getByRole("dialog", { name: "创建 API Key" });
      await dialog.getByLabel("名称").fill("发布机器人");
      await dialog.getByLabel("Agent 主体").fill("agent-release");
      await dialog.getByRole("combobox", { name: "站点" }).fill("site_alpha");
      await dialog.getByRole("checkbox", { name: /读取站点/ }).check();
      expect(await serious(page)).toEqual([]);
      await dialog.getByRole("button", { name: "创建并显示明文" }).click();
      await expect(page.getByRole("dialog", { name: /只显示这一次/ })).toContainText(SECRET);
      // One dialog closes while the next opens; sample colours once both motions are over.
      await expect(dialog).toHaveCount(0);
      await page.waitForTimeout(400);
      expect(await serious(page)).toEqual([]);
    });

    test("权限中心", async ({ page }) => {
      await mockWorkbench(page, { roles: ALL });
      await page.goto("/access/session");
      await expect(page.getByRole("heading", { name: "当前管理会话" })).toBeVisible();
      expect(await serious(page)).toEqual([]);
    });
  });
}
