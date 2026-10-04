import { test, expect } from "@playwright/test";
import { REQUEST_ID } from "./fixtures";
// Phase 0 information architecture: 工作台 > 站点 > 流量与调查 > 案件与证据 > 运维与治理.
// Labels and role rules are unchanged; only the grouping order differs from the previous shell,
// which listed 防护/调查/案件与证据/治理 and appended the per-site entries after 权限中心.
const roleLinks: Record<string, string[]> = {
  observer: [
    "概览",
    "站点状态",
    "请求调查",
    "资格与身份账本",
    "身份绑定",
    "模型调用列表",
    "模型调用详情",
    "Agent 运行",
    "权限中心",
  ],
  investigator: [
    "概览",
    "请求调查",
    "结构化检索",
    "资格与身份账本",
    "身份绑定",
    "案件工作台",
    "证据访问",
    "调查导出",
    "运行状态",
    "权限中心",
  ],
  system_admin: ["概览", "受保护站点", "API Key", "权限中心"],
  policy_author: ["概览", "站点发布", "权限中心"],
  policy_approver: ["概览", "站点发布", "权限中心"],
  release_operator: ["概览", "站点发布", "权限中心"],
  sensitive_evidence_approver: ["概览", "证据访问", "调查导出", "权限中心"],
  sensitive_evidence_reader: ["概览", "证据访问", "调查导出", "权限中心"],
  audit_administrator: ["概览", "证据保留", "审计发布状态", "校准报告", "权限中心"],
};
for (const [role, links] of Object.entries(roleLinks)) {
  test("server role navigation: " + role, async ({ page }) => {
    const calls: string[] = [];
    await page.route("**/control/v1/**", async (route) => {
      const path = new URL(route.request().url()).pathname;
      calls.push(path);
      if (path === "/control/v1/session")
        await route.fulfill({
          json: {
            subject: "test-subject",
            tenant_id: "tenant_demo",
            site_id: "site_demo",
            roles: [role],
            csrf_token: "a".repeat(64),
            session_expires_at: "2027-01-01T08:00:00.000Z",
            idle_expires_at: "2027-01-01T00:15:00.000Z",
            last_reauthenticated_at: null,
            step_up_valid: false,
          },
        });
      else
        await route.fulfill({
          status: 403,
          json: {
            error_code: "CONTROL_SCOPE_DENIED",
            message_safe: "Synthetic denied",
            request_id: REQUEST_ID,
            retryable: false,
            next_action: "contact_admin",
          },
        });
    });
    await page.goto("/access/session");
    const nav = page
      .getByRole("complementary", { name: "后台导航" })
      .getByRole("navigation")
      .first();
    await expect(nav).toBeVisible();
    await expect(nav.getByRole("link")).toHaveText(links);
    await expect(page.getByRole("heading", { name: "当前管理会话" })).toBeVisible();
    await expect(page.locator("main")).toContainText(role);
    await expect(page.getByLabel("管理凭证", { exact: true })).toHaveCount(0);
    expect(calls.every((path) => path === "/control/v1/session")).toBeTruthy();
    if (["policy_author", "policy_approver", "release_operator"].includes(role)) {
      await nav.getByRole("link", { name: "站点发布", exact: true }).click();
      await expect(page.getByRole("region", { name: "站点运行与发布" })).toBeVisible();
      const expected =
        role === "policy_author"
          ? "验证配置"
          : role === "policy_approver"
            ? "批准并应用"
            : "应用期望版本";
      await page.getByRole("button", { name: expected, exact: true }).click();
      await expect(
        page.getByRole("alert").filter({ hasText: "CONTROL_SCOPE_DENIED" }),
      ).toBeVisible();
      expect(calls.some((path) => path.endsWith("/config"))).toBeFalsy();
      expect(
        calls.some((path) =>
          path.endsWith(
            role === "policy_author"
              ? "/validate"
              : role === "policy_approver"
                ? "/approve"
                : "/apply",
          ),
        ),
      ).toBeTruthy();
    }
    if (role === "observer") {
      await nav.getByRole("link", { name: "站点状态", exact: true }).click();
      await expect(page.getByRole("button", { name: "刷新站点状态" })).toBeVisible();
      await expect(page.getByRole("alert").first()).toContainText("CONTROL_SCOPE_DENIED");
      expect(calls.some((path) => path.endsWith("/status"))).toBeTruthy();
      expect(calls.some((path) => path.endsWith("/config"))).toBeFalsy();
      await page.goto("/sites");
      await expect(page.getByRole("alert")).toContainText("CONTROL_SCOPE_DENIED");
      await expect(page.getByRole("alert")).toContainText("403");
      await expect(page.getByRole("button", { name: "新建站点" })).toHaveCount(0);
      await expect(page.getByText("CONTROL_SITE_CONFIG_UNAVAILABLE", { exact: false })).toHaveCount(
        0,
      );
    }
  });
}
