import { expect, type Page, test } from "@playwright/test";
import { errorFixture } from "./fixtures";
import {
  type Call,
  KEY_ID,
  keyList,
  keyRecord,
  mockWorkbench,
  type Override,
  SECRET,
  settledReads,
} from "./workbench-helpers";

// Agent API key administration in cookie-session mode: only a browser session with
// KeyAdministrator or SystemAdmin may administer keys, so these run with server roles.

const ADMIN = ["system_admin", "observer", "release_operator", "policy_approver"];
const keyWrites = (calls: readonly Call[]) =>
  calls.filter(
    (call) => call.method === "POST" && call.path.startsWith("/control/v1/agent-api-keys"),
  );
const createDialog = (page: Page) => page.getByRole("dialog", { name: "创建 API Key" });
const secretDialog = (page: Page) => page.getByRole("dialog", { name: /只显示这一次/ });
const keyRow = (page: Page, name = "部署机器人") =>
  page
    .getByRole("region", { name: "Agent API Key 列表" })
    .getByRole("row")
    .filter({ hasText: name });

async function open(page: Page, roles = ADMIN, override?: Override) {
  const calls = await mockWorkbench(page, { roles, override });
  await page.goto("/admin/api-keys");
  return calls;
}

async function fillCreate(page: Page) {
  const dialog = createDialog(page);
  await dialog.getByLabel("名称").fill("发布机器人");
  await dialog.getByLabel("Agent 主体").fill("agent-release");
  await dialog.getByRole("combobox", { name: "站点" }).fill("site_alpha");
  await dialog.getByRole("checkbox", { name: /读取站点/ }).check();
  await dialog.getByRole("checkbox", { name: /直接应用/ }).check();
}

test("the list is read once on opening, without scopes or secrets, and never by itself", async ({
  page,
}) => {
  await page.clock.install();
  const calls = await open(page);
  const row = keyRow(page);
  await expect(row).toContainText("agent-deploy");
  await expect(row).toContainText("xsk_a1b2c3d4");
  await expect(row).toContainText("有效");
  await expect(row).toContainText("列表不含范围");
  await settledReads(page, calls, ["/control/v1/agent-api-keys", "/control/v1/session"]);
  const opened = calls.length;
  await page.clock.fastForward(10 * 60_000);
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await page.waitForTimeout(300);
  expect(calls).toHaveLength(opened);
});

test("create: the exact body is frozen, the plaintext is shown once and cleared on close", async ({
  page,
  context,
}) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  const calls = await open(page);
  await expect(keyRow(page)).toBeVisible();
  await page.getByRole("button", { name: "创建 API Key" }).click();
  // The direct-apply consequence is spelled out next to its checkbox before anything is ticked.
  await expect(createDialog(page)).toContainText("跳过“另一位审批人批准”");
  await fillCreate(page);
  await createDialog(page).getByText("7 天", { exact: true }).click();
  const before = Date.now();
  await createDialog(page).getByRole("button", { name: "创建并显示明文" }).click();
  const secret = secretDialog(page);
  await expect(secret).toContainText(SECRET);
  const [write] = keyWrites(calls);
  expect(write?.path).toBe("/control/v1/agent-api-keys");
  expect(write?.csrf).toBe("a".repeat(64));
  expect(write?.key).toMatch(/^[A-Za-z0-9_.:-]{16,128}$/);
  const body = write?.body as { expires_at: string } & Record<string, unknown>;
  expect(body).toEqual({
    subject: "agent-release",
    display_name: "发布机器人",
    expires_at: body.expires_at,
    scopes: [
      {
        tenant_id: "tenant_demo",
        site_id: "site_alpha",
        capabilities: ["site.read", "site.config.apply_direct"],
      },
    ],
  });
  const days = (Date.parse(body.expires_at) - before) / 86_400_000;
  expect(days).toBeGreaterThan(6.99);
  expect(days).toBeLessThan(7.01);
  // It cannot be dismissed without the confirmation.
  await page.keyboard.press("Escape");
  await expect(secret).toBeVisible();
  await expect(secret.getByRole("button", { name: "关闭并清除明文" })).toBeDisabled();
  await secret.getByRole("button", { name: "复制明文" }).click();
  await expect(secret.getByRole("button", { name: "已复制" })).toBeVisible();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(SECRET);
  // The plaintext is never an attribute, the address or the title.
  expect(
    await page.evaluate(
      (value) =>
        [...document.querySelectorAll("*")].some((element) =>
          [...element.attributes].some((attribute) => attribute.value.includes(value)),
        ),
      SECRET,
    ),
  ).toBe(false);
  expect(page.url()).not.toContain(SECRET);
  expect(await page.title()).not.toContain(SECRET);
  await secret.getByRole("checkbox", { name: "我已把明文保存到安全位置" }).check();
  await secret.getByRole("button", { name: "关闭并清除明文" }).click();
  await expect(secret).toHaveCount(0);
  await expect(page.getByText(SECRET)).toHaveCount(0);
  expect(await page.evaluate((value) => document.body.innerHTML.includes(value), SECRET)).toBe(
    false,
  );
  expect(
    await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length })),
  ).toEqual({ local: 0, session: 0 });
  // Leaving the page and coming back never shows it again.
  await page.goto("/admin/api-keys");
  await expect(keyRow(page)).toBeVisible();
  await expect(secretDialog(page)).toHaveCount(0);
});

test("the form refuses malformed requests locally and sends nothing", async ({ page }) => {
  const calls = await open(page);
  await page.getByRole("button", { name: "创建 API Key" }).click();
  const dialog = createDialog(page);
  await dialog.getByRole("button", { name: "创建并显示明文" }).click();
  await expect(dialog).toContainText("请填写名称");
  await expect(dialog).toContainText("请填写 Agent 主体");
  await expect(dialog).toContainText("请选择或输入站点");
  await expect(dialog).toContainText("至少勾选一项能力");
  await dialog.getByLabel("Agent 主体").fill("-agent with spaces");
  await expect(dialog).toContainText("以字母或数字开头");
  // The tenant-wide row offers site.create and nothing else.
  await dialog.getByText("整个租户（仅创建站点）", { exact: true }).click();
  await expect(dialog.getByRole("checkbox", { name: /创建站点/ })).toBeChecked();
  await expect(dialog.getByRole("checkbox", { name: /读取站点/ })).toHaveCount(0);
  expect(keyWrites(calls)).toEqual([]);
});

test("a refusal is explained from the dictionary and leaves the form editable", async ({
  page,
}) => {
  const calls = await open(page, ADMIN, (url, request) =>
    url.pathname === "/control/v1/agent-api-keys" && request.method() === "POST"
      ? { status: 403, body: errorFixture("CONTROL_API_KEY_SCOPE_FORBIDDEN") }
      : undefined,
  );
  await page.getByRole("button", { name: "创建 API Key" }).click();
  await fillCreate(page);
  await createDialog(page).getByRole("button", { name: "创建并显示明文" }).click();
  const alert = createDialog(page)
    .getByRole("alert")
    .filter({ hasText: "CONTROL_API_KEY_SCOPE_FORBIDDEN" });
  await expect(alert).toContainText("超过了当前会话自身可以行使的权限");
  await expect(alert).toContainText("CONTROL_API_KEY_SCOPE_FORBIDDEN · HTTP 403");
  await expect(createDialog(page).getByLabel("名称")).toBeEditable();
  await expect(createDialog(page).getByText("冻结的请求")).toHaveCount(0);
  await expect(secretDialog(page)).toHaveCount(0);
  expect(keyWrites(calls)).toHaveLength(1);
});

test("an unknown create says the server does not deduplicate it and can be given up", async ({
  page,
}) => {
  const calls = await open(page, ADMIN, (url, request) =>
    url.pathname === "/control/v1/agent-api-keys" && request.method() === "POST"
      ? { status: 503, body: errorFixture("CONTROL_API_KEY_UNAVAILABLE") }
      : undefined,
  );
  await page.getByRole("button", { name: "创建 API Key" }).click();
  await fillCreate(page);
  await createDialog(page).getByRole("button", { name: "创建并显示明文" }).click();
  const dialog = createDialog(page);
  await expect(dialog).toContainText("结果未知");
  await expect(dialog).toContainText("服务端不按幂等键对“创建 API Key”去重");
  await dialog.getByRole("button", { name: "稍后处理" }).click();
  await expect(page.getByText("创建 API Key：结果未知")).toBeVisible();
  await page.getByRole("button", { name: "查看并处理" }).click();
  await dialog.getByRole("button", { name: "放弃这次请求（不再重试）" }).click();
  await page.getByRole("button", { name: "放弃", exact: true }).click();
  await expect(page.getByText("创建 API Key：结果未知")).toHaveCount(0);
  expect(keyWrites(calls)).toHaveLength(1);
});

test("rotate: an unknown outcome is retried with the same key and body, then shows the new plaintext", async ({
  page,
}) => {
  let attempts = 0;
  const calls = await open(page, ADMIN, (url) => {
    if (!url.pathname.endsWith("/rotate")) return undefined;
    attempts += 1;
    return attempts === 1
      ? { status: 503, body: errorFixture("CONTROL_API_KEY_UNAVAILABLE") }
      : undefined;
  });
  await keyRow(page).getByRole("button", { name: "轮换 部署机器人" }).click();
  const dialog = page.getByRole("dialog", { name: "轮换 API Key：部署机器人" });
  await expect(dialog).toContainText("列表不返回这把 Key 的范围");
  await expect(dialog.getByLabel("名称")).toHaveValue("部署机器人");
  await dialog.getByRole("combobox", { name: "站点" }).fill("site_alpha");
  await dialog.getByRole("checkbox", { name: /读取站点/ }).check();
  await dialog.getByRole("button", { name: "轮换并显示新明文" }).click();
  await expect(dialog).toContainText("结果未知");
  await expect(dialog).toContainText("轮换只会成功一次");
  await dialog.getByRole("button", { name: "原样重试" }).click();
  const secret = secretDialog(page);
  await expect(secret).toContainText(SECRET);
  await expect(secret).toContainText("旧 Key 已在同一事务中撤销");
  const writes = keyWrites(calls);
  expect(writes).toHaveLength(2);
  expect(writes[0]?.path).toBe(`/control/v1/agent-api-keys/${KEY_ID}/rotate`);
  expect(writes[1]).toEqual({ ...writes[0] });
  await secret.getByRole("checkbox", { name: "我已把明文保存到安全位置" }).check();
  await secret.getByRole("button", { name: "关闭并清除明文" }).click();
  await expect(page.getByText(SECRET)).toHaveCount(0);
});

test("revoke: confirm, then an unknown outcome allows only the exact retry", async ({ page }) => {
  let attempts = 0;
  let revoked = false;
  const calls = await open(page, ADMIN, (url, request) => {
    if (url.pathname === "/control/v1/agent-api-keys" && request.method() === "GET") {
      return { body: keyList([keyRecord(revoked ? { status: "revoked" } : {})]) };
    }
    if (!url.pathname.endsWith("/revoke")) return undefined;
    attempts += 1;
    if (attempts === 1) return { status: 503, body: errorFixture("CONTROL_API_KEY_UNAVAILABLE") };
    revoked = true;
    return undefined;
  });
  await keyRow(page).getByRole("button", { name: "撤销 部署机器人" }).click();
  const dialog = page.getByRole("dialog", { name: "撤销 API Key：部署机器人" });
  await expect(dialog).toContainText("401 CONTROL_API_KEY_INVALID");
  await dialog.getByRole("button", { name: "确认撤销" }).click();
  await expect(dialog).toContainText("结果未知");
  await dialog.getByRole("button", { name: "稍后处理" }).click();
  // The row now leads to the frozen request instead of offering new actions.
  await keyRow(page).getByRole("button", { name: "查看待确认操作" }).click();
  await dialog.getByRole("button", { name: "原样重试" }).click();
  await expect(dialog).toHaveCount(0);
  await expect(keyRow(page)).toContainText("已撤销");
  const writes = keyWrites(calls);
  expect(writes.map((call) => call.path)).toEqual([
    `/control/v1/agent-api-keys/${KEY_ID}/revoke`,
    `/control/v1/agent-api-keys/${KEY_ID}/revoke`,
  ]);
  expect(writes[1]?.key).toBe(writes[0]?.key);
});

test("non-administrators get a role hint, no navigation entry and no key read", async ({
  page,
}) => {
  const calls = await open(page, ["observer", "investigator"]);
  await expect(page.getByText("需要 KeyAdministrator 或 SystemAdmin 角色")).toBeVisible();
  await expect(
    page.getByRole("complementary", { name: "后台导航" }).getByRole("link", { name: "API Key" }),
  ).toHaveCount(0);
  await page.waitForTimeout(300);
  expect(calls.some((call) => call.path.startsWith("/control/v1/agent-api-keys"))).toBe(false);
});

test("a key administrator alone may revoke but is told it cannot issue", async ({ page }) => {
  await open(page, ["key_administrator"]);
  await expect(keyRow(page)).toBeVisible();
  await expect(page.getByRole("button", { name: "创建 API Key" })).toBeDisabled();
  await expect(page.getByText("只能撤销，不能签发")).toBeVisible();
  await expect(keyRow(page).getByRole("button", { name: "撤销 部署机器人" })).toBeEnabled();
});

test("a refused list is a role hint; an unavailable one an error with a retry", async ({
  page,
}) => {
  let status = 403;
  const calls = await open(page, ADMIN, (url, request) =>
    url.pathname === "/control/v1/agent-api-keys" && request.method() === "GET"
      ? {
          status,
          body: errorFixture(
            status === 403 ? "CONTROL_SCOPE_DENIED" : "CONTROL_API_KEY_UNAVAILABLE",
          ),
        }
      : undefined,
  );
  await expect(page.getByText("服务端拒绝了当前身份")).toBeVisible();
  status = 503;
  await page.getByRole("button", { name: "刷新", exact: true }).click();
  const failure = page.getByRole("alert").filter({ hasText: "Key 列表读取失败" });
  await expect(failure).toContainText("CONTROL_API_KEY_UNAVAILABLE");
  await expect(page.getByText("Synthetic server detail must not be rendered")).toHaveCount(0);
  const reads = calls.filter((call) => call.path === "/control/v1/agent-api-keys").length;
  await failure.getByRole("button", { name: "重试" }).click();
  await expect
    .poll(() => calls.filter((call) => call.path === "/control/v1/agent-api-keys").length)
    .toBe(reads + 1);
});

test("a key of another tenant in the list ends the session", async ({ page }) => {
  await open(page, ADMIN, (url, request) =>
    url.pathname === "/control/v1/agent-api-keys" && request.method() === "GET"
      ? { body: keyList([keyRecord({ tenant_id: "tenant_other" })]) }
      : undefined,
  );
  await expect(page.getByRole("status")).toContainText("响应范围校验失败");
  await expect(page.getByRole("button", { name: "使用企业身份登录" })).toBeVisible();
});

test("a plaintext waiting for its dialog is gone once the session ends", async ({ page }) => {
  await open(page);
  await page.getByRole("button", { name: "创建 API Key" }).click();
  await fillCreate(page);
  await createDialog(page).getByRole("button", { name: "创建并显示明文" }).click();
  await expect(secretDialog(page)).toContainText(SECRET);
  await page.evaluate(() => window.dispatchEvent(new Event("pagehide")));
  await expect(page.getByRole("button", { name: "使用企业身份登录" })).toBeVisible();
  await expect(page.getByText(SECRET)).toHaveCount(0);
  expect(await page.evaluate((value) => document.body.innerHTML.includes(value), SECRET)).toBe(
    false,
  );
});
