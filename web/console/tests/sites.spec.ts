import { test, expect, type Page, type Route } from "@playwright/test";
import { REQUEST_ID, TOKEN, AS_OF, errorFixture } from "./fixtures";

// Synthetic contracts exercise the actual browser client, separately from local OIDC smoke.
const envelope = (id = "site_demo") => ({
  request_id: REQUEST_ID,
  tenant_id: "tenant_demo",
  site_id: id,
});
function config(id = "site_alpha", display = "Alpha 站点") {
  return {
    ...envelope(id),
    found: true,
    desired_revision: 1,
    active_revision: null,
    apply_state: "pending",
    apply_id: "apply_fixture",
    requires_approval: false,
    reason_code: "CONTROL_SITE_CONFIG_SAVED",
    config_digest: "a".repeat(64),
    config: {
      display_name: display,
      public_origin: "https://example.test",
      upstream_address: "127.0.0.1:8080",
      upstream_server_name: "example.test",
      upstream_tls: false,
      listen_port: 6100,
      entry_path: "/",
      security_entry: "ui_action_required",
      sensor_enabled: false,
      policy_revision: "policy-v1",
      status: "draft",
      revision: 1,
      config_digest: "a".repeat(64),
      updated_by: "fixture-author",
      created_at: AS_OF,
      updated_at: AS_OF,
      gateway_config: {},
    },
  };
}
const item = (id: string, title: string) => {
  const c = config(id, title);
  return { ...c.config, ...c, config: undefined, found: undefined };
};
async function setup(page: Page, override?: (route: Route) => Promise<boolean>) {
  await page.route("**/control/v1/**", async (route) => {
    if (await override?.(route)) return;
    const path = new URL(route.request().url()).pathname;
    if (path === "/control/v1/sites") {
      await route.fulfill({
        json: {
          ...envelope(),
          sites: [item("site_alpha", "Alpha 站点"), item("site_beta", "Beta 站点")],
          truncated: false,
          next_cursor: null,
        },
      });
    } else if (path.endsWith("/revisions")) {
      await route.fulfill({ json: { ...envelope(path.split("/")[4]), revisions: [] } });
    } else if (path.endsWith("/config")) {
      const id = path.split("/")[4];
      await route.fulfill({ json: config(id, id === "site_beta" ? "Beta 站点" : "Alpha 站点") });
    } else await route.fulfill({ status: 404, json: errorFixture("CONTROL_SITE_NOT_FOUND") });
  });
}
async function login(page: Page, path = "/sites") {
  await page.goto(path);
  await page.getByLabel("管理凭证", { exact: true }).fill(TOKEN);
  await page.getByRole("button", { name: "连接", exact: true }).click();
}
const category = (page: Page, name: string) =>
  page.getByRole("navigation", { name: "站点运营导航" }).getByRole("link", { name, exact: true });

test("site list opens exact site; categories and history retain draft; deep link reloads", async ({
  page,
}) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await setup(page);
  await login(page);
  await expect(page.getByRole("region", { name: "受保护站点列表" })).toBeVisible();
  await expect(page.getByLabel("源站地址", { exact: true })).toHaveCount(0);
  // The site cards became table rows; the site name is the link that opens the site.
  await page.getByRole("link", { name: "Beta 站点", exact: true }).click();
  await expect(page).toHaveURL(/sites.site_beta.overview$/);
  await category(page, "网络").click();
  await expect(page.getByLabel("站点名称", { exact: true })).toHaveValue("Beta 站点");
  await page.getByLabel("站点名称", { exact: true }).fill("Beta 草稿");
  await category(page, "安全入口").click();
  await expect(page.getByLabel("站点名称", { exact: true })).toHaveCount(0);
  await page.goBack();
  await expect(page.getByLabel("站点名称", { exact: true })).toHaveValue("Beta 草稿");
  await page.goForward();
  await expect(page.getByRole("combobox", { name: "安全入口", exact: true })).toBeVisible();
  page.once("dialog", (d) => d.dismiss());
  await page.getByRole("button", { name: "返回站点列表" }).click();
  await expect(page).toHaveURL(/sites.site_beta.security-entry$/);
  page.once("dialog", (d) => d.accept());
  await page.reload();
  await page.getByLabel("管理凭证", { exact: true }).fill(TOKEN);
  await page.getByRole("button", { name: "连接", exact: true }).click();
  await expect(page.getByRole("combobox", { name: "安全入口", exact: true })).toBeVisible();
  expect(errors).toEqual([]);
});

test("new site works with populated list and refresh resets draft", async ({ page }) => {
  await setup(page);
  await login(page);
  await page.getByRole("button", { name: "新建站点" }).click();
  await expect(page).toHaveURL(/sites.new.network$/);
  await page.getByLabel("站点 ID", { exact: true }).fill("fresh");
  await page.getByLabel("站点名称", { exact: true }).fill("新站点");
  await category(page, "路由与操作").click();
  await expect(page.getByLabel("站点名称", { exact: true })).toHaveCount(0);
  await category(page, "网络").click();
  await expect(page.getByLabel("站点名称", { exact: true })).toHaveValue("新站点");
  page.once("dialog", (d) => d.accept());
  await page.getByRole("button", { name: "刷新站点" }).click();
  await expect(page.getByLabel("站点名称", { exact: true })).toHaveValue("");
});

test("empty list differs from unavailable database and preserves diagnostics", async ({ page }) => {
  let failed = true;
  await setup(page, async (route) => {
    if (new URL(route.request().url()).pathname !== "/control/v1/sites") return false;
    await route.fulfill(
      failed
        ? { status: 503, json: errorFixture("CONTROL_SITE_CONFIG_UNAVAILABLE") }
        : { json: { ...envelope(), sites: [], truncated: false, next_cursor: null } },
    );
    return true;
  });
  await login(page);
  await expect(page.getByText("CONTROL_SITE_CONFIG_UNAVAILABLE", { exact: false })).toBeVisible();
  await expect(page.getByText("暂无受保护站点", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("alert")).toContainText("503");
  failed = false;
  await page.getByRole("button", { name: "刷新", exact: true }).click();
  await expect(page.getByText("暂无受保护站点", { exact: true })).toBeVisible();
});

test("unknown save outcome requires explicit identical retry", async ({ page }) => {
  const writes: { body: string | null; key: string | null }[] = [];
  await setup(page, async (route) => {
    if (route.request().method() === "GET") return false;
    writes.push({
      body: route.request().postData(),
      key: await route.request().headerValue("idempotency-key"),
    });
    await route.fulfill(
      writes.length === 1
        ? { status: 503, json: errorFixture("CONTROL_SITE_CONFIG_UNAVAILABLE") }
        : { json: config("site_alpha", "保存后") },
    );
    return true;
  });
  await login(page, "/sites/site_alpha/network");
  await page.getByLabel("站点名称", { exact: true }).fill("保存后");
  await page.getByRole("button", { name: "保存配置", exact: true }).click();
  await expect(page.getByRole("button", { name: "确认后原样重试" })).toBeVisible();
  expect(writes).toHaveLength(1);
  await expect(page.getByLabel("站点名称", { exact: true })).toBeDisabled();
  await page.getByRole("button", { name: "确认后原样重试" }).click();
  await expect(page.getByRole("button", { name: "确认后原样重试" })).toHaveCount(0);
  expect(writes).toHaveLength(2);
  expect(writes[0]?.key).toBeTruthy();
  expect(writes[1]).toEqual(writes[0]);
});

test("config and mutation responses cannot switch the selected site", async ({ page }) => {
  let mutation = false;
  await setup(page, async (route) => {
    if (!new URL(route.request().url()).pathname.endsWith("/config")) return false;
    await route.fulfill({
      json: config(!mutation || route.request().method() !== "GET" ? "site_other" : "site_alpha"),
    });
    return true;
  });
  await login(page, "/sites/site_alpha/network");
  await expect(page.getByText("INVALID_RESPONSE", { exact: false })).toBeVisible();
  await expect(page.getByLabel("站点名称", { exact: true })).toHaveCount(0);
  mutation = true;
  await page.getByRole("button", { name: "刷新站点" }).click();
  await expect(page.getByLabel("站点名称", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "保存配置", exact: true }).click();
  await expect(page.getByRole("button", { name: "确认后原样重试" })).toBeVisible();
  await expect(page).toHaveURL(/sites.site_alpha.network$/);
});

test("missing site with null approval shows not found", async ({ page }) => {
  await setup(page, async (route) => {
    if (!new URL(route.request().url()).pathname.endsWith("/config")) return false;
    await route.fulfill({
      json: {
        ...envelope("site_missing"),
        found: false,
        desired_revision: null,
        active_revision: null,
        apply_state: null,
        apply_id: null,
        requires_approval: null,
        reason_code: null,
        config_digest: null,
        config: null,
      },
    });
    return true;
  });
  await login(page, "/sites/site_missing/overview");
  await expect(page.getByText("站点不存在或当前范围内不可见。")).toBeVisible();
  await expect(page.getByText("INVALID_RESPONSE", { exact: false })).toHaveCount(0);
});

test("WAF category saves explicit query fragments", async ({ page }) => {
  let saved: Record<string, unknown> = {};
  await setup(page, async (route) => {
    if (
      route.request().method() !== "PUT" ||
      !new URL(route.request().url()).pathname.endsWith("/config")
    )
      return false;
    saved = route.request().postDataJSON() as Record<string, unknown>;
    await route.fulfill({ json: config("site_alpha") });
    return true;
  });
  await login(page, "/sites/site_alpha/waf-limits");
  await page.getByRole("textbox", { name: /查询阻断片段/ }).fill("' or 1=1--\n<script");
  await page.getByRole("button", { name: "保存配置", exact: true }).click();
  await expect.poll(() => saved.policy).toBeDefined();
  const policy = saved.policy as { waf: { blocked_query_fragments: string[] } };
  expect(policy.waf.blocked_query_fragments).toEqual(["' or 1=1--", "<script"]);
});

test("release page sequences validation approval apply and rollback with explicit actions", async ({
  page,
}) => {
  let approval = true;
  let active = false;
  const actions: string[] = [];
  const state = () => ({
    ...config(),
    active_revision: active ? 1 : null,
    requires_approval: approval,
    apply_state: active ? "active" : "pending",
  });
  await setup(page, async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith("/config")) {
      await route.fulfill({ json: state() });
      return true;
    }
    if (!["validate", "approve", "apply", "rollback"].includes(path.split("/").at(-1) ?? ""))
      return false;
    const action = path.split("/").at(-1) ?? "";
    actions.push(action);
    if (action === "validate")
      await route.fulfill({
        json: {
          ...envelope("site_alpha"),
          revision: 1,
          config_digest: "a".repeat(64),
          valid: true,
          reason_code: "CONTROL_SITE_CONFIG_VALID",
        },
      });
    else {
      expect(await route.request().headerValue("idempotency-key")).toBeTruthy();
      if (action === "approve") approval = false;
      if (action === "apply") active = true;
      await route.fulfill({ json: { ...state(), listen_port: 6100 } });
    }
    return true;
  });
  await login(page, "/sites/site_alpha/releases");
  await expect(page.getByRole("button", { name: "应用期望版本" })).toBeDisabled();
  await page.getByRole("button", { name: "验证配置" }).click();
  await expect(page.getByRole("status")).toContainText("配置验证通过");
  await page.getByRole("button", { name: "批准并应用" }).click();
  await expect(page.getByRole("button", { name: "应用期望版本" })).toBeEnabled();
  await page.getByRole("button", { name: "应用期望版本" }).click();
  await expect(page.getByRole("button", { name: "回滚上一版本" })).toBeEnabled();
  await page.getByRole("button", { name: "回滚上一版本" }).click();
  await expect(page.getByRole("button", { name: "回滚上一版本" })).toBeEnabled();
  expect(actions).toEqual(["validate", "approve", "apply", "rollback"]);
});

test("manual health reads show bounded states and reject wrong site", async ({ page }) => {
  let count = 0;
  await setup(page, async (route) => {
    if (!new URL(route.request().url()).pathname.endsWith("/health")) return false;
    count++;
    await route.fulfill({
      json: {
        ...config(count === 1 ? "site_alpha" : "site_other"),
        listen_port: 6100,
        edge_health: {
          edge_state: "healthy",
          upstream_state: "unavailable",
          audit_state: "healthy",
        },
      },
    });
    return true;
  });
  await login(page, "/sites/site_alpha/policies");
  const region = page.getByRole("region", { name: "站点运行健康" });
  await region.getByRole("button", { name: "读取健康状态" }).click();
  await expect(region).toContainText("unavailable");
  await region.getByRole("button", { name: "读取健康状态" }).click();
  await expect(page.getByRole("alert")).toContainText("INVALID_RESPONSE");
  await expect(region.getByText("unavailable", { exact: true })).toHaveCount(0);
});
