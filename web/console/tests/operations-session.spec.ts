import { expect, type Page, test } from "@playwright/test";
import { errorFixture } from "./fixtures";
import { mockWorkbench, settledReads } from "./workbench-helpers";

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
