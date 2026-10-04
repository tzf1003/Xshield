import { test, expect } from "@playwright/test";
import { REQUEST_ID } from "./fixtures";
const roleViews: Record<string, string[]> = {
  observer: [
    "请求调查",
    "模型调用列表",
    "模型调用详情",
    "Agent 运行",
    "资格与身份账本",
    "身份绑定",
  ],
  investigator: [
    "运行状态",
    "请求调查",
    "结构化检索",
    "资格与身份账本",
    "身份绑定",
    "案件工作台",
    "证据访问",
    "调查导出",
  ],
  system_admin: ["受保护站点"],
  policy_author: [],
  policy_approver: [],
  release_operator: [],
  sensitive_evidence_approver: ["证据访问", "调查导出"],
  sensitive_evidence_reader: ["证据访问", "调查导出"],
  audit_administrator: ["证据保留", "校准报告", "审计发布状态"],
};
for (const [role, views] of Object.entries(roleViews)) {
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
    await expect(nav.getByRole("link")).toHaveText([
      "概览",
      ...views,
      "权限中心",
      ...(role === "observer" ? ["站点状态"] : []),
      ...(["policy_author", "policy_approver", "release_operator"].includes(role)
        ? ["站点发布"]
        : []),
    ]);
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
