import AxeBuilder from "@axe-core/playwright";
import { expect, type Page, test } from "@playwright/test";
import { errorFixture } from "./fixtures";
import { mockSite, signInAt } from "./site-fixtures";

const next = (page: Page) => page.getByRole("button", { name: "下一步", exact: true });
const previous = (page: Page) => page.getByRole("button", { name: "上一步", exact: true });
const step = (page: Page, name: string) =>
  page.locator(".xs-wizard-steps").getByText(name, { exact: true });

async function settled(page: Page) {
  await page.evaluate(() =>
    Promise.all(
      document.getAnimations().map((animation) => animation.finished.catch(() => undefined)),
    ),
  );
}
async function serious(page: Page) {
  await settled(page);
  const results = await new AxeBuilder({ page }).analyze();
  return results.violations
    .filter((violation) => violation.impact === "critical" || violation.impact === "serious")
    .map((violation) => ({
      rule: violation.id,
      nodes: violation.nodes
        .slice(0, 3)
        .map((node) => `${node.target.join(" ")} :: ${node.failureSummary ?? ""}`),
    }));
}

async function fillBasics(page: Page) {
  await page.getByLabel("站点 ID", { exact: true }).fill("shop_cn");
  await page.getByLabel("站点名称", { exact: true }).fill("商城站点");
  await page.getByLabel("公网入口", { exact: true }).fill("https://shop.example.com");
}
async function fillUpstream(page: Page) {
  await page.getByLabel("源站地址", { exact: true }).fill("8.8.8.8:443");
  await page.getByLabel("源站 Server Name", { exact: true }).fill("origin.example.com");
}

test("addresses from before the wizard still resolve, to the step they became", async ({
  page,
}) => {
  await mockSite(page);
  for (const [old, now] of [
    ["network", "basics"],
    ["security-entry", "entry"],
    ["routes", "routes"],
    ["waf-limits", "review"],
    ["policies", "review"],
    ["overview", "basics"],
  ] as const) {
    await signInAt(page, `/sites/new/${old}`);
    await expect(page).toHaveURL(new RegExp(`/sites/new/${now}$`));
    await expect(page.getByRole("region", { name: "新建站点向导" })).toBeVisible();
  }
  await signInAt(page, "/sites/new/not-a-step");
  await expect(page.getByText("该地址没有对应页面，请从侧栏选择功能。")).toBeVisible();
});

test("each step explains itself and stops at what the server would refuse", async ({ page }) => {
  await mockSite(page);
  await signInAt(page, "/sites/new/basics");
  await expect(next(page)).toBeDisabled();
  await expect(page.getByText("本步还有 3 项需要修正")).toBeVisible();
  await expect(previous(page)).toBeDisabled();

  await page.getByLabel("站点 ID", { exact: true }).fill("new");
  await expect(page.getByText("“new” 是保留字")).toBeVisible();
  await page.getByLabel("站点 ID", { exact: true }).fill("shop cn");
  await expect(page.getByText("站点 ID 只能包含字母、数字和 _ . -。")).toBeVisible();
  await page.getByLabel("公网入口", { exact: true }).fill("http://shop.example.com");
  await expect(page.getByText("明文 http 只允许 localhost 或 127.x 本地靶场")).toBeVisible();
  await fillBasics(page);
  await expect(next(page)).toBeEnabled();
  await next(page).click();

  // upstream: format, SSRF classes, loopback warning, server name, port
  await expect(page).toHaveURL(/sites\/new\/upstream$/);
  await expect(next(page)).toBeDisabled();
  await page.getByLabel("源站地址", { exact: true }).fill("shop.internal:443");
  await expect(page.getByText("不能填域名")).toBeVisible();
  await page.getByLabel("源站地址", { exact: true }).fill("192.168.1.10:443");
  await expect(page.getByText("内网地址（RFC 1918）不能作为上游")).toBeVisible();
  await page.getByLabel("源站地址", { exact: true }).fill("[::ffff:8.8.8.8]:443");
  await expect(page.getByText("IPv4 映射的 IPv6 写法")).toBeVisible();
  await page.getByLabel("源站地址", { exact: true }).fill("127.0.0.1:8080");
  await expect(page.getByText("回环地址只在部署方显式开启本地靶场放行时才被接受")).toBeVisible();
  await page.getByLabel("源站 Server Name", { exact: true }).fill("127.0.0.1");
  await expect(page.getByText("服务名不能是 IP 地址")).toBeVisible();
  await expect(next(page)).toBeDisabled();
  await fillUpstream(page);
  await page.getByLabel("监听端口", { exact: true }).fill("80");
  await expect(
    page.getByText("监听端口填 0（自动分配），或 6100–65535 之间的端口。"),
  ).toBeVisible();
  await expect(next(page)).toBeDisabled();
  await page.getByLabel("监听端口", { exact: true }).fill("0");
  await expect(next(page)).toBeEnabled();
  await next(page).click();

  // entry and mode
  await expect(page).toHaveURL(/sites\/new\/entry$/);
  await page.getByLabel("入口路径", { exact: true }).fill("app");
  await expect(page.getByText("入口路径必须以 / 开头。")).toBeVisible();
  await expect(next(page)).toBeDisabled();
  await page.getByLabel("入口路径", { exact: true }).fill("/");
  await expect(page.getByRole("radio", { name: /^草稿/ })).toBeChecked();
  await page.getByRole("radio", { name: /^启用/ }).check();
  await expect(page.getByText("创建为“启用”后仍需要独立审批")).toBeVisible();
  await page.getByRole("radio", { name: /^草稿/ }).check();
  await next(page).click();

  // first routes: the default entry route, and an example that says it is one
  await expect(page).toHaveURL(/sites\/new\/routes$/);
  await expect(page.getByText("共 1 条路由（最多 256）")).toBeVisible();
  await expect(page.getByText("示例，不是推荐")).toBeVisible();
  await page.getByRole("button", { name: /套用示例/ }).click();
  await expect(page.getByText("共 4 条路由（最多 256）")).toBeVisible();
  await page.getByRole("button", { name: /套用示例/ }).click();
  await expect(page.getByText("套用示例会替换当前的路由列表。")).toBeVisible();
  await page.getByRole("button", { name: "取消" }).click();
  await next(page).click();

  // review
  await expect(page).toHaveURL(/sites\/new\/review$/);
  const checks = page.getByRole("list", { name: "校验结果" });
  for (const name of ["基本信息", "上游与监听", "入口与模式", "路由"]) {
    await expect(checks.getByText(name, { exact: true })).toBeVisible();
  }
  await expect(checks).not.toContainText("有错误");
  await expect(page.getByText("保存为草稿后，站点不会发布，也不需要审批。")).toBeVisible();
  await expect(page.getByRole("button", { name: "保存为草稿", exact: true })).toBeEnabled();
});

test("the draft survives step changes and the browser's back and forward", async ({ page }) => {
  await mockSite(page);
  await signInAt(page, "/sites/new/basics");
  await fillBasics(page);
  await next(page).click();
  await fillUpstream(page);
  await expect(page.getByLabel("站点名称", { exact: true })).toHaveCount(0);
  await page.goBack();
  await expect(page).toHaveURL(/sites\/new\/basics$/);
  await expect(page.getByLabel("站点名称", { exact: true })).toHaveValue("商城站点");
  await page.goForward();
  await expect(page.getByLabel("源站地址", { exact: true })).toHaveValue("8.8.8.8:443");
  // the step headers go back freely and forward only over valid steps
  await step(page, "基本信息").click();
  await expect(page).toHaveURL(/sites\/new\/basics$/);
  await step(page, "校验与保存").click();
  await expect(page).toHaveURL(/sites\/new\/review$/);
  await expect(page.getByRole("button", { name: "保存为草稿", exact: true })).toBeEnabled();
  await page.getByLabel("站点名称", { exact: true }).count();
  await step(page, "基本信息").click();
  await page.getByLabel("公网入口", { exact: true }).fill("not an origin");
  await step(page, "校验与保存").click();
  await expect(page).toHaveURL(/sites\/new\/basics$/);
});

test("leaving with entries asks first, and a reload starts over", async ({ page }) => {
  await mockSite(page);
  await signInAt(page, "/sites/new/basics");
  await fillBasics(page);
  page.once("dialog", (dialog) => dialog.dismiss());
  await page.getByRole("button", { name: "返回站点列表" }).click();
  await expect(page).toHaveURL(/sites\/new\/basics$/);
  await expect(page.getByLabel("站点名称", { exact: true })).toHaveValue("商城站点");
  page.once("dialog", (dialog) => dialog.accept());
  await page.reload();
  await page
    .getByLabel("管理凭证", { exact: true })
    .fill("synthetic-observer-token-for-browser-tests-000000000000000000000000");
  await page.getByRole("button", { name: "连接", exact: true }).click();
  await expect(page.getByLabel("站点名称", { exact: true })).toHaveValue("");
  const stored = await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }));
  expect(stored).not.toContain("shop_cn");
});

async function throughToReview(page: Page) {
  await fillBasics(page);
  await next(page).click();
  await fillUpstream(page);
  await next(page).click();
  await next(page).click();
  await page.getByRole("button", { name: /套用示例/ }).click();
  await next(page).click();
}

test("saving creates the draft once, with a framework key, and lands on the new site", async ({
  page,
}) => {
  const mock = await mockSite(page);
  await signInAt(page, "/sites/new/basics");
  await throughToReview(page);
  await page.getByRole("button", { name: "保存为草稿", exact: true }).click();
  await expect(page).toHaveURL(/sites\/shop_cn\/overview$/);
  await expect(page.getByRole("status")).toContainText("站点已创建，已保存为 r1");
  await expect(page.getByRole("status")).toContainText("草稿不会发布到 edge");
  await expect(page.getByRole("region", { name: "站点概况" })).toContainText("草稿");
  const creates = mock.writes.filter((write) => write.method === "POST");
  expect(creates).toHaveLength(1);
  expect(creates[0]?.key).toMatch(/^[A-Za-z0-9._:-]{16,128}$/);
  const body = JSON.parse(creates[0]?.body ?? "{}") as {
    site_id: string;
    status: string;
    listen_port: number;
    display_name: string;
    policy: { routes: { operation_id: string }[]; static_asset_max_path_depth: number };
  };
  expect(body).toMatchObject({
    site_id: "shop_cn",
    status: "draft",
    listen_port: 0,
    display_name: "商城站点",
  });
  expect(body.policy.routes.map((route) => route.operation_id)).toEqual([
    "protected.entry",
    "api.items.list",
    "api.items.get",
    "api.items.create",
  ]);
  // The identity-less static fallback is never on by default.
  expect(body.policy.static_asset_max_path_depth).toBe(0);
});

test("the static fallback is an explicit opt-in that says what it admits", async ({ page }) => {
  const mock = await mockSite(page);
  await signInAt(page, "/sites/new/basics");
  await fillBasics(page);
  await next(page).click();
  await fillUpstream(page);
  await next(page).click();
  await expect(page).toHaveURL(/sites\/new\/entry$/);
  const toggle = page.getByLabel("放行公开静态资源", { exact: true });
  await expect(toggle).not.toBeChecked();
  await expect(page.getByText("默认关闭，未登记的路径一律拒绝。")).toBeVisible();
  await toggle.click();
  await expect(toggle).toBeChecked();
  await expect(page.getByText("不需要身份即可访问").first()).toBeVisible();
  await next(page).click();
  await page.getByRole("button", { name: /套用示例/ }).click();
  await next(page).click();
  await page.getByRole("button", { name: "保存为草稿", exact: true }).click();
  await expect(page).toHaveURL(/sites\/shop_cn\/overview$/);
  const created = mock.writes.find((write) => write.method === "POST");
  const body = JSON.parse(created?.body ?? "{}") as {
    policy: { static_asset_max_path_depth: number };
  };
  expect(body.policy.static_asset_max_path_depth).toBe(5);
});

test("an unknown create outcome keeps the exact request and allows only an exact retry", async ({
  page,
}) => {
  const sent: { body: string | null; key: string | null }[] = [];
  const mock = await mockSite(page);
  const inner = mock.intercept;
  mock.intercept = async (route, url) => {
    if (
      url.pathname === "/control/v1/sites" &&
      route.request().method() === "POST" &&
      sent.length === 0
    ) {
      sent.push({
        body: route.request().postData(),
        key: await route.request().headerValue("idempotency-key"),
      });
      await route.fulfill({ status: 503, json: errorFixture("CONTROL_SITE_CONFIG_UNAVAILABLE") });
      return true;
    }
    if (url.pathname === "/control/v1/sites" && route.request().method() === "POST") {
      sent.push({
        body: route.request().postData(),
        key: await route.request().headerValue("idempotency-key"),
      });
    }
    return (await inner?.(route, url)) ?? false;
  };
  await signInAt(page, "/sites/new/basics");
  await throughToReview(page);
  await page.getByRole("button", { name: "保存为草稿", exact: true }).click();
  await expect(page.getByRole("button", { name: "确认后原样重试" })).toBeVisible();
  await expect(page.getByRole("button", { name: "保存为草稿", exact: true })).toBeDisabled();
  expect(sent).toHaveLength(1);
  await page.getByRole("button", { name: "确认后原样重试" }).click();
  await expect(page).toHaveURL(/sites\/shop_cn\/overview$/);
  expect(sent).toHaveLength(2);
  expect(sent[1]).toEqual(sent[0]);
  expect(sent[0]?.key).toBeTruthy();
});

test("a refusal shows its reason and keeps the draft", async ({ page }) => {
  const mock = await mockSite(page);
  const inner = mock.intercept;
  mock.intercept = async (route, url) => {
    if (url.pathname === "/control/v1/sites" && route.request().method() === "POST") {
      await route.fulfill({ status: 400, json: errorFixture("CONTROL_SITE_SSRF_BLOCKED") });
      return true;
    }
    return (await inner?.(route, url)) ?? false;
  };
  await signInAt(page, "/sites/new/basics");
  await throughToReview(page);
  await page.getByRole("button", { name: "保存为草稿", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("上游地址被安全策略拒绝");
  await expect(page.getByRole("alert")).toContainText("CONTROL_SITE_SSRF_BLOCKED");
  await expect(page.getByRole("button", { name: "确认后原样重试" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "保存为草稿", exact: true })).toBeEnabled();
  await step(page, "上游与监听").click();
  await expect(page.getByLabel("源站地址", { exact: true })).toHaveValue("8.8.8.8:443");
});

test("every wizard step fits a 390 px screen", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await mockSite(page);
  await signInAt(page, "/sites/new/basics");
  const overflow = () =>
    page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
    );
  expect(await overflow()).toBeLessThanOrEqual(0);
  await fillBasics(page);
  await next(page).click();
  expect(await overflow()).toBeLessThanOrEqual(0);
  await fillUpstream(page);
  await next(page).click();
  expect(await overflow()).toBeLessThanOrEqual(0);
  await next(page).click();
  expect(await overflow()).toBeLessThanOrEqual(0);
  await next(page).click();
  expect(await overflow()).toBeLessThanOrEqual(0);
});

for (const scheme of ["light", "dark"] as const) {
  test.describe(`wizard accessibility (${scheme})`, () => {
    test.use({ colorScheme: scheme });
    test("every step has no serious violations", async ({ page }) => {
      await mockSite(page);
      await signInAt(page, "/sites/new/basics");
      await page.getByLabel("站点 ID", { exact: true }).fill("new");
      expect(await serious(page)).toEqual([]);
      await fillBasics(page);
      await next(page).click();
      await page.getByLabel("源站地址", { exact: true }).fill("10.0.0.5:443");
      expect(await serious(page)).toEqual([]);
      await fillUpstream(page);
      await next(page).click();
      expect(await serious(page)).toEqual([]);
      await next(page).click();
      await page.getByRole("button", { name: /套用示例/ }).click();
      expect(await serious(page)).toEqual([]);
      await next(page).click();
      await expect(page.getByRole("list", { name: "校验结果" })).toBeVisible();
      expect(await serious(page)).toEqual([]);
    });
  });
}
