import { expect, test, type Page } from "@playwright/test";
import { mockControl, paint, requestSettled } from "./control-mock";
import { REQUEST_ID, TOKEN, auditHealthFixture, errorFixture } from "./fixtures";
import { openView } from "./navigation";

async function connect(page: Page) {
  // The audit-status page reads nothing until asked, so call counts start at zero, and it keeps
  // the legacy host mounted the way the previous request page did.
  await page.goto("/operations/audit");
  await page.getByLabel("管理凭证", { exact: true }).fill(TOKEN);
  await page.getByRole("button", { name: "连接", exact: true }).click();
}

/** Opens a request the way an operator pastes an ID: through the ⌘K palette. */
async function query(page: Page, requestId = REQUEST_ID) {
  await page.keyboard.press("Control+KeyK");
  const palette = page.getByRole("combobox", { name: "命令面板" });
  await palette.fill(requestId);
  await page.keyboard.press("Enter");
  // An ID the palette does not recognise leaves it open; close it so the next call starts clean.
  if (await palette.isVisible()) await page.keyboard.press("Escape");
}

async function queryAuditHealth(page: Page) {
  await openView(page, "audit-health");
  await page.getByRole("button", { name: "读取发布状态", exact: true }).click();
}

test("reads audit publication state only after an explicit manual action", async ({ page }) => {
  const calls = await mockControl(page);
  await connect(page);
  await openView(page, "audit-health");
  await expect(page.getByRole("heading", { name: "审计发布状态", exact: true })).toBeVisible();
  expect(calls).toHaveLength(0);
  await page.getByRole("button", { name: "读取发布状态", exact: true }).click();
  const result = page.getByRole("region", { name: "审计发布状态结果", exact: true });
  await expect(result).toContainText("clickhouse_primary");
  await expect(result).toContainText("audit_events");
  await expect(result).toContainText("未封存段");
  await expect(result).toContainText("1");
  await expect(page.getByText(/不代表业务准入、全部 Outbox 状态或系统整体健康/)).toBeVisible();
  await page.getByRole("button", { name: "手动刷新发布状态", exact: true }).click();
  const healthCalls = calls.filter((call) => call.path === "/control/v1/audit/health");
  expect(healthCalls).toHaveLength(2);
  expect(healthCalls.every((call) => call.authorized && call.cookie === null)).toBe(true);
});

test("audit publication reads discard expired, scope-drifting, and late state", async ({
  page,
}) => {
  let mode: "expired" | "drift" | "delayed" = "expired";
  let release = () => {};
  const delayed = new Promise<void>((resolve) => {
    release = resolve;
  });
  let arrived = () => {};
  const arrivedHealth = new Promise<void>((resolve) => {
    arrived = resolve;
  });
  await mockControl(page, async (url) => {
    if (url.pathname !== "/control/v1/audit/health") return undefined;
    if (mode === "expired") return { status: 401, body: errorFixture("CONTROL_AUTH_REQUIRED") };
    if (mode === "drift") return { body: { ...auditHealthFixture(), site_id: "site_other" } };
    arrived();
    await delayed;
    return { body: auditHealthFixture() };
  });
  await connect(page);
  await queryAuditHealth(page);
  await expect(page.getByRole("status")).toContainText("管理会话已失效");
  await expect(page.getByLabel("管理凭证", { exact: true })).toHaveValue("");

  mode = "drift";
  await page.getByLabel("管理凭证", { exact: true }).fill(TOKEN);
  await page.getByRole("button", { name: "连接", exact: true }).click();
  await query(page);
  await expect(page.getByText("AUTH_BINDING_VALID", { exact: true })).toBeVisible();
  await queryAuditHealth(page);
  await expect(page.getByRole("status")).toContainText("响应范围校验失败");
  await expect(page.getByRole("region", { name: "审计发布状态结果" })).toHaveCount(0);

  mode = "delayed";
  await page.getByLabel("管理凭证", { exact: true }).fill(TOKEN);
  await page.getByRole("button", { name: "连接", exact: true }).click();
  const settled = requestSettled(page, "/control/v1/audit/health");
  await queryAuditHealth(page);
  await arrivedHealth;
  await openView(page, "request");
  await query(page);
  await expect(page.getByText("AUTH_BINDING_VALID", { exact: true })).toBeVisible();
  release();
  await settled;
  await paint(page);
  await expect(page.getByRole("region", { name: "审计发布状态结果" })).toHaveCount(0);
});
