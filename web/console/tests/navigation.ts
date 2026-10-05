import type { Page } from "@playwright/test";
const links: Record<string, string> = {
  request: "请求调查",
  model: "模型调用详情",
  agent: "Agent 运行",
  "model-list": "模型调用列表",
  "audit-health": "审计发布状态",
  "calibration-report": "校准报告",
  grant: "资格与身份账本",
  binding: "身份绑定",
  search: "结构化检索",
  case: "案件工作台",
  approvals: "审批中心",
};
export async function openView(page: Page, kind: string) {
  const label = links[kind];
  if (!label) throw new Error("Unknown test view: " + kind);
  // Below the mobile breakpoint the sidebar is an off-canvas drawer.
  const trigger = page.getByRole("button", { name: "打开导航" });
  if (await trigger.isVisible()) await trigger.click();
  await page
    .getByRole("complementary", { name: "后台导航" })
    .getByRole("link", { name: label, exact: true })
    .click();
}
