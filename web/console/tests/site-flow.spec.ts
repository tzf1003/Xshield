import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { expect, type Locator, type Page, test } from "@playwright/test";
import { serious, settled } from "./axe";
import { configBody, mockSite, type SiteMock, sectionLink, signInAt } from "./site-fixtures";

/**
 * The browser provenance-flow editor: building the loop of scripts/test_browser_loop.sh in the
 * route drawer and through the wizard template, each cross-route rule's message, the page-digest
 * helper, keyboard operation, the release page's wording and axe scans of every new group.
 * Responses are the synthetic site mock (tests/site-fixtures.ts).
 */
type Json = Record<string, unknown>;
type Routes = Json[];

const repo = (path: string) => new URL(`../../../${path}`, import.meta.url);
const LOOP = JSON.parse(readFileSync(repo("tests/site-config/browser-loop.json"), "utf8")) as Json;
const APP_HTML = fileURLToPath(repo("tests/browser-loop/app.html"));
const APP_SHA256 = "f5eb29b7c7fbac05248d0d1d9b4e693b913bc1fbe2aaf3fd878e8384209b43ea";

const loop = (): Json => structuredClone(LOOP);
const routesOf = (config: Json) => (config.policy as { routes: Routes }).routes;
const withRoutes = (config: Json, routes: Routes, over: Json = {}): Json => ({
  ...config,
  ...over,
  policy: { ...(config.policy as Json), routes },
});
const byId = (routes: Routes) =>
  Object.fromEntries(routes.map((item) => [item.operation_id, item]));
const routeNamed = (id: string) => {
  const found = routesOf(LOOP).find((item) => item.operation_id === id);
  if (!found) throw new Error(id);
  return structuredClone(found);
};

const bar = (page: Page) => page.getByRole("region", { name: "未保存的修改" });
const drawerNamed = (page: Page, name: string) => page.getByRole("dialog", { name });
const group = (scope: Locator, name: string) => scope.getByRole("region", { name, exact: true });
const field = (scope: Locator, label: string) => scope.getByLabel(label, { exact: true });
const apply = (drawer: Locator) => drawer.getByRole("button", { name: "应用到草稿" });
const sent = (mock: SiteMock, method: string) =>
  JSON.parse(mock.writes.find((write) => write.method === method)?.body ?? "{}") as Json;

/** Picks a route in one of the drawer's route selects. */
async function choose(page: Page, select: Locator, text: string) {
  await select.click();
  await page
    .locator(".ant-select-dropdown:visible .ant-select-item-option", { hasText: text })
    .click();
}

async function computeFromFile(drawer: Locator) {
  await drawer.getByRole("button", { name: "从页面源码计算", exact: true }).click();
  await field(drawer, "页面文件").setInputFiles(APP_HTML);
  await drawer.getByRole("button", { name: "计算并填入摘要与偏移" }).click();
  await expect(drawer.getByRole("status")).toContainText("已填入");
  const build = group(drawer, "SENSOR_HTML 页面构建");
  await expect(field(build, "页面摘要（SHA-256）")).toHaveValue(APP_SHA256);
  await expect(field(build, "注入偏移（字节）")).toHaveValue("293");
}

test("an operator builds the whole loop in the route drawer and saves exactly the golden routes", async ({
  page,
}) => {
  const login = routeNamed("login.page");
  const mock = await mockSite(page, {
    config: withRoutes(loop(), [login], { sensor_enabled: false }),
  });
  await signInAt(page, "/sites/site_alpha/routes");

  // 1. The login API: an authentication entry that establishes identity.
  await page.getByRole("button", { name: "新增路由" }).click();
  let drawer = drawerNamed(page, "新增路由");
  await field(drawer, "操作 ID").fill("auth.login");
  await field(drawer, "路径").fill("/api/login");
  await drawer.getByText("POST", { exact: true }).click();
  await drawer.getByRole("radio", { name: /^认证入口/ }).check();
  await expect(field(drawer, "操作来源")).toBeDisabled();
  const identity = group(drawer, "身份建立");
  await identity.getByRole("switch", { name: "建立身份" }).click();
  await expect(identity.getByText("JSON 指针须以 / 开头").first()).toBeVisible();
  await expect(apply(drawer)).toBeDisabled();
  await field(identity, "主体指针").fill("/identity/id");
  await field(identity, "授权上下文指针").fill("/identity/authorization_context");
  await field(identity, "业务凭证指针").fill("/identity/id");
  await expect(identity.getByText("三个 JSON 指针必须互不相同。")).toBeVisible();
  await field(identity, "业务凭证指针").fill("/access_token");
  await field(identity, "凭证期限").fill("7200");
  await expect(identity.getByText("凭证期限不能长于会话期限。")).toBeVisible();
  await field(identity, "凭证期限").fill("1800");
  await drawer.getByText("BUFFERED_JSON", { exact: true }).click();
  await field(drawer, "响应上限").fill("1024");
  await apply(drawer).click();
  await expect(drawer).toHaveCount(0);

  // 2. The application page: SENSOR_HTML, its build computed from the page the origin serves.
  await page.getByRole("button", { name: "新增路由" }).click();
  drawer = drawerNamed(page, "新增路由");
  await field(drawer, "操作 ID").fill("app.page");
  await field(drawer, "路径").fill("/app");
  await drawer.getByRole("radio", { name: /^已认证根/ }).check();
  await drawer.getByText("SENSOR_HTML", { exact: true }).click();
  const build = group(drawer, "SENSOR_HTML 页面构建");
  await expect(build.getByText("请填写页面摘要")).toBeVisible();
  await expect(build.getByText("请填写注入偏移")).toBeVisible();
  await expect(apply(drawer)).toBeDisabled();
  await field(build, "构建版本").fill("app-r1");
  await computeFromFile(drawer);
  await field(drawer, "响应上限").fill("16384");
  await apply(drawer).click();
  await expect(bar(page)).toContainText("1 项需要修正");

  // 3. The detail route, bound to the order in its path.
  await page.getByRole("button", { name: "新增路由" }).click();
  drawer = drawerNamed(page, "新增路由");
  await field(drawer, "操作 ID").fill("orders.read");
  await field(drawer, "路径").fill("/orders/{order_id}");
  await field(drawer, "操作来源").fill("orders.open");
  await field(drawer, "资源类型").fill("order");
  await field(drawer, "视图 profile").fill("customer_detail");
  await field(drawer, "资源路径字段").fill("order_id");
  // A detail route addresses a resource, so it cannot be issued by a page.
  await expect(group(drawer, "由页面签发")).toHaveCount(0);
  await apply(drawer).click();

  // 4. The list: issued by the page, qualifying each order for the detail route.
  await page.getByRole("button", { name: "新增路由" }).click();
  drawer = drawerNamed(page, "新增路由");
  await field(drawer, "操作 ID").fill("orders.list");
  await field(drawer, "路径").fill("/orders");
  await field(drawer, "操作来源").fill("app.orders.list");
  const issued = group(drawer, "由页面签发");
  await issued.getByRole("switch", { name: "由页面签发" }).click();
  await expect(issued.getByText("请选择签发这个动作的页面。")).toBeVisible();
  await choose(page, field(issued, "签发页面"), "app.page");
  // The page does not issue actions yet: said next to the choice, and it does not block.
  await expect(issued.getByText("不是声明了“页面签发动作”的 SENSOR_HTML 页面根")).toBeVisible();
  await drawer.getByText("BUFFERED_JSON", { exact: true }).click();
  await field(drawer, "响应上限").fill("4096");
  const grant = group(drawer, "响应资源资格");
  await grant.getByRole("switch", { name: "签发资源资格" }).click();
  await field(grant, "列表指针").fill("/orders");
  await field(grant, "资源指针").fill("/id");
  await choose(page, field(grant, "目标详情路由"), "orders.read");
  await field(grant, "目标映射修订").fill("orders-map-r1");
  await field(grant, "单次最多项数").fill("10");
  await field(grant, "活动资格上限").fill("200");
  await expect(drawer).toContainText("还有 1 项跨路由问题，可以先应用，保存前须解决");
  await expect(apply(drawer)).toBeEnabled();
  await apply(drawer).click();
  await expect(bar(page)).toContainText("2 项需要修正");
  await expect(page.getByText("有 1 项问题，打开编辑查看")).toBeVisible();

  // 5. The page starts issuing: the list's open reference is resolved.
  await page.getByRole("button", { name: "编辑路由 app.page" }).click();
  drawer = drawerNamed(page, "编辑路由");
  const actions = group(drawer, "页面签发动作");
  await actions.getByRole("switch", { name: "签发页面动作" }).click();
  await field(actions, "映射修订").fill("app-map-r1");
  await expect(actions).toContainText("由它签发：orders.list（1/16）");
  await apply(drawer).click();
  await expect(page.getByText("有 1 项问题，打开编辑查看")).toHaveCount(0);

  // 6. The logout revokes identity.
  await page.getByRole("button", { name: "新增路由" }).click();
  drawer = drawerNamed(page, "新增路由");
  await field(drawer, "操作 ID").fill("auth.logout");
  await field(drawer, "路径").fill("/api/logout");
  await drawer.getByText("POST", { exact: true }).click();
  await drawer.getByRole("radio", { name: /^已认证根/ }).check();
  await drawer.getByText("BUFFERED_JSON", { exact: true }).click();
  await field(drawer, "响应上限").fill("256");
  await group(drawer, "身份撤销").getByRole("switch", { name: "撤销身份" }).click();
  await apply(drawer).click();

  // 7. The site-level rule: SENSOR_HTML pages need the browser sensor.
  await bar(page)
    .getByRole("button", { name: /项需要修正/ })
    .click();
  await expect(page.locator(".ant-popover").last()).toContainText(
    "有 SENSOR_HTML 页面路由时必须启用浏览器探针",
  );
  await sectionLink(page, "安全入口").click();
  // The finding sits next to the switch and describes it.
  const sensor = page.getByRole("switch", { name: "启用浏览器探针运行时" });
  await expect(sensor).toHaveAccessibleDescription(/有 SENSOR_HTML 页面路由时必须启用浏览器探针/);
  await sensor.click();
  await expect(bar(page).getByRole("button", { name: /项需要修正/ })).toHaveCount(0);

  await bar(page).getByRole("button", { name: "保存草稿", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("已保存为");
  const body = sent(mock, "PUT");
  expect(body.sensor_enabled).toBe(true);
  expect(byId(routesOf(body))).toEqual(byId(routesOf(LOOP)));
});

test("the wizard builds the loop from its template once the page build is computed", async ({
  page,
}) => {
  const mock = await mockSite(page);
  await signInAt(page, "/sites/new/basics");
  await field(page.locator("body"), "站点 ID").fill("orders_loop");
  await field(page.locator("body"), "站点名称").fill("订单站点");
  await field(page.locator("body"), "公网入口").fill("https://orders.example.test");
  await page.getByRole("button", { name: "下一步", exact: true }).click();
  await field(page.locator("body"), "源站地址").fill("8.8.8.8:9000");
  await field(page.locator("body"), "源站 Server Name").fill("orders.example.test");
  await page.getByRole("button", { name: "下一步", exact: true }).click();
  await page.getByRole("button", { name: "下一步", exact: true }).click();

  await expect(page).toHaveURL(/sites\/new\/routes$/);
  const title = "浏览器来源闭环（登录 → 页面 → 列表 → 详情）";
  await page.getByRole("radio", { name: title }).check();
  await expect(page.getByText("套用后同时启用浏览器探针")).toBeVisible();
  await page.getByRole("button", { name: `套用示例：${title}` }).click();
  await expect(page.getByText("共 6 条路由（最多 256）")).toBeVisible();
  await expect(page.getByText("有 2 项问题，打开编辑查看")).toBeVisible();
  await expect(page.getByText("本步还有 2 项需要修正")).toBeVisible();
  await expect(page.getByRole("button", { name: "下一步", exact: true })).toBeDisabled();

  await page.getByRole("button", { name: "编辑路由 app.page" }).click();
  const drawer = drawerNamed(page, "编辑路由");
  await computeFromFile(drawer);
  await apply(drawer).click();
  await expect(page.getByText("有 2 项问题，打开编辑查看")).toHaveCount(0);
  await page.getByRole("button", { name: "下一步", exact: true }).click();

  const checks = page.getByRole("list", { name: "校验结果" });
  await expect(checks).not.toContainText("有错误");
  await page.getByRole("button", { name: "保存为草稿", exact: true }).click();
  await expect(page).toHaveURL(/sites\/orders_loop\/overview$/);
  const body = sent(mock, "POST");
  expect(body.sensor_enabled).toBe(true);
  // The template is the loop route for route, in the loop's own order.
  expect(routesOf(body)).toEqual(routesOf(LOOP));
});

test("each cross-route rule explains itself where it is broken", async ({ page }) => {
  await mockSite(page, { config: loop() });
  await signInAt(page, "/sites/site_alpha/routes");
  const elsewhere = (drawer: Locator) => drawer.getByRole("list", { name: "对其他路由的影响" });

  // A page root that issues nothing.
  await page.getByRole("button", { name: "编辑路由 orders.list" }).click();
  let drawer = drawerNamed(page, "编辑路由");
  await group(drawer, "由页面签发").getByRole("switch", { name: "由页面签发" }).click();
  await expect(elsewhere(drawer)).toContainText(
    "路由 app.page：页面根须签发 1–16 个动作，当前没有",
  );
  await drawer.getByRole("button", { name: "取消" }).click();

  // An action issued by a page that does not declare page actions.
  await page.getByRole("button", { name: "编辑路由 app.page" }).click();
  drawer = drawerNamed(page, "编辑路由");
  await group(drawer, "页面签发动作").getByRole("switch", { name: "签发页面动作" }).click();
  await expect(elsewhere(drawer)).toContainText(
    "路由 orders.list：签发页面“app.page”不是声明了“页面签发动作”的 SENSOR_HTML 页面根。",
  );
  await drawer.getByRole("button", { name: "取消" }).click();

  // A grant whose target no longer addresses a resource.
  await page.getByRole("button", { name: "编辑路由 orders.read" }).click();
  drawer = drawerNamed(page, "编辑路由");
  for (const label of ["资源类型", "视图 profile", "资源路径字段"])
    await field(drawer, label).fill("");
  await field(drawer, "路径").fill("/orders-all");
  await expect(elsewhere(drawer)).toContainText(
    "路由 orders.list：资源资格目标“orders.read”必须是已存在、绑定资源的“必须有界面操作来源”路由。",
  );
  await drawer.getByRole("button", { name: "取消" }).click();

  // One action with two meanings: a copy of the list under another path.
  await page.getByRole("button", { name: "复制路由 orders.list" }).click();
  drawer = drawerNamed(page, "复制路由");
  await expect(drawer.getByText("已被另一条路由占用")).toBeVisible();
  await expect(apply(drawer)).toBeDisabled();
  await field(drawer, "路径").fill("/orders-copy");
  await expect(
    drawer.getByText(
      "操作来源“app.orders.list”在映射修订“app-map-r1”下与路由 orders.list 含义不同",
    ),
  ).toBeVisible();
  await expect(apply(drawer)).toBeEnabled();
  await drawer.getByRole("button", { name: "取消" }).click();

  // One identity or qualification effect per response.
  await page.getByRole("button", { name: "编辑路由 auth.logout" }).click();
  drawer = drawerNamed(page, "编辑路由");
  await group(drawer, "响应资源资格").getByRole("switch", { name: "签发资源资格" }).click();
  await expect(drawer.getByText("同一路由的响应最多只能有一种身份或资格效果")).toBeVisible();
  await expect(apply(drawer)).toBeDisabled();
  await drawer.getByRole("button", { name: "取消" }).click();

  // A mode switch parks what no longer fits and restores it on the way back.
  await page.getByRole("button", { name: "编辑路由 auth.login" }).click();
  drawer = drawerNamed(page, "编辑路由");
  await drawer.getByRole("radio", { name: /^公开/ }).check();
  await expect(group(drawer, "身份建立")).toHaveCount(0);
  // Said plainly: applying now would not keep it.
  await expect(drawer.getByRole("note")).toContainText(
    "已收起不适用于当前准入或响应模式的设置：身份建立",
  );
  await drawer.getByRole("radio", { name: /^认证入口/ }).check();
  await expect(field(group(drawer, "身份建立"), "主体指针")).toHaveValue("/identity/id");
  await expect(drawer.getByText("已收起不适用于当前准入或响应模式的设置")).toHaveCount(0);
  await drawer.getByRole("button", { name: "取消" }).click();
  await expect(bar(page)).toHaveCount(0);
});

test("an existing site can take the loop example from its route table", async ({ page }) => {
  await mockSite(page);
  await signInAt(page, "/sites/site_alpha/routes");
  await expect(page.getByText("共 2 条路由（最多 256）")).toBeVisible();
  await page.getByRole("button", { name: "套用示例", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "套用示例" });
  await dialog.getByRole("radio", { name: "浏览器来源闭环（登录 → 页面 → 列表 → 详情）" }).check();
  await expect(dialog).toContainText("套用会用示例替换当前的 2 条路由");
  await expect(dialog).toContainText("套用后同时启用浏览器探针");
  expect(await serious(page)).toEqual([]);
  await dialog.getByRole("button", { name: "替换路由列表" }).click();
  await expect(dialog).toHaveCount(0);
  await expect(page.getByText("共 6 条路由（最多 256）")).toBeVisible();
  await expect(page.getByText("有 2 项问题，打开编辑查看")).toBeVisible();
  // Only the draft changed: the bar shows the sensor and the routes, and can discard both.
  await expect(bar(page).getByRole("button", { name: /^安全入口 1$/ })).toBeVisible();
  await expect(bar(page)).toContainText("2 项需要修正");
  await bar(page).getByRole("button", { name: "放弃" }).click();
  await page.getByRole("button", { name: "放弃", exact: true }).last().click();
  await expect(page.getByText("共 2 条路由（最多 256）")).toBeVisible();
});

test("the sensor learns at most 64 grant lists and 64 identity-change routes", async ({ page }) => {
  const list = routeNamed("orders.list");
  const logout = routeNamed("auth.logout");
  const many: Routes = [];
  for (let index = 1; index <= 65; index += 1) {
    many.push({
      ...list,
      operation_id: `orders.list${index}`,
      path: `/orders${index}`,
      security_entry: "authenticated_root",
      source_action: null,
      issued_by: undefined,
    });
    many.push({ ...logout, operation_id: `auth.logout${index}`, path: `/api/logout${index}` });
  }
  const routes = [
    ...routesOf(loop()).filter(
      (item) => !["orders.list", "auth.logout"].includes(String(item.operation_id)),
    ),
    ...many.map((item) => JSON.parse(JSON.stringify(item)) as Json),
  ];
  // Without the list the page issues nothing; drop its page actions to keep the case focused.
  const appPage = routes.find((item) => item.operation_id === "app.page");
  if (appPage) delete appPage.page_actions;
  await mockSite(page, { config: withRoutes(loop(), routes) });
  await signInAt(page, "/sites/site_alpha/routes");
  const search = page.getByRole("textbox", { name: "搜索路由" });
  await search.fill("orders.list65");
  await page.getByRole("button", { name: "编辑路由 orders.list65" }).click();
  let drawer = drawerNamed(page, "编辑路由");
  await expect(group(drawer, "响应资源资格")).toContainText("每个站点最多 64 条响应资源资格。");
  await drawer.getByRole("button", { name: "取消" }).click();
  await search.fill("auth.logout65");
  await page.getByRole("button", { name: "编辑路由 auth.logout65" }).click();
  drawer = drawerNamed(page, "编辑路由");
  await expect(group(drawer, "身份撤销")).toContainText("每个站点最多 64 条建立或撤销身份的路由。");
});

test("the page helper counts bytes, refuses what the edge refuses and keeps nothing", async ({
  page,
}) => {
  const mock = await mockSite(page, { config: loop() });
  await signInAt(page, "/sites/site_alpha/routes");
  await page.getByRole("button", { name: "编辑路由 app.page" }).click();
  const drawer = drawerNamed(page, "编辑路由");
  const build = group(drawer, "SENSOR_HTML 页面构建");
  await drawer.getByRole("button", { name: "从页面源码计算", exact: true }).click();
  await expect(
    drawer.getByText("必须是源站返回的原始字节，空白或换行不同就是另一份页面。"),
  ).toBeVisible();
  await drawer.getByText("粘贴源码", { exact: true }).click();
  const source = field(drawer, "页面源码");
  const compute = drawer.getByRole("button", { name: "计算并填入摘要与偏移" });
  const calls = mock.calls.length;

  // Multi-byte text before </head>: the offset is a byte offset.
  const text = "<html><head><title>订单 😀</title></head><body></body></html>";
  await source.fill(text);
  await compute.click();
  const bytes = Buffer.from(text, "utf8");
  const offset = bytes.indexOf("</head>");
  expect(offset).toBeGreaterThan(text.indexOf("</head>"));
  await expect(field(build, "注入偏移（字节）")).toHaveValue(String(offset));
  const digest = createHash("sha256").update(bytes).digest("hex");
  await expect(field(build, "页面摘要（SHA-256）")).toHaveValue(digest);
  await expect(source).toHaveValue("");

  // What the edge cannot inject into is refused, and the fields keep their values.
  await source.fill("<HTML><HEAD></HEAD><BODY></BODY></HTML>");
  await compute.click();
  await expect(drawer.getByRole("status")).toContainText("大写或大小写混合的 </HEAD>");
  await source.fill("<p>no head</p>");
  await compute.click();
  await expect(drawer.getByRole("status")).toContainText("页面里没有 </head>");
  await expect(field(build, "注入偏移（字节）")).toHaveValue(String(offset));

  // A page larger than the route's response limit is computed, with the consequence said.
  await source.fill(`<html><head></head><body>${"x".repeat(20_000)}</body></html>`);
  await compute.click();
  await expect(drawer.getByRole("status")).toContainText("超过这条路由的响应上限");

  // Nothing left the page or was stored.
  expect(mock.calls.length).toBe(calls);
  const stored = await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }));
  expect(stored).not.toContain("订单");
  expect(stored).not.toContain("<head>");
});

test("keyboard only: a list issued by the page that qualifies the detail route", async ({
  page,
}) => {
  const routes = routesOf(loop()).filter((item) => item.operation_id !== "orders.list");
  const mock = await mockSite(page, { config: withRoutes(loop(), routes) });
  await signInAt(page, "/sites/site_alpha/routes");
  await expect(page.getByText("有 1 项问题，打开编辑查看")).toBeVisible();
  const key = (locator: Locator, keys: string) => locator.focus().then(() => locator.press(keys));
  const type = async (locator: Locator, value: string) => {
    await locator.focus();
    await page.keyboard.press("ControlOrMeta+A");
    await page.keyboard.type(value);
  };

  await key(page.getByRole("button", { name: "新增路由" }), "Enter");
  const drawer = drawerNamed(page, "新增路由");
  await expect(drawer).toBeVisible();
  await type(field(drawer, "操作 ID"), "orders.list");
  await type(field(drawer, "路径"), "/orders");
  await type(field(drawer, "操作来源"), "app.orders.list");
  const issued = group(drawer, "由页面签发");
  await key(issued.getByRole("switch", { name: "由页面签发" }), "Space");
  await key(field(issued, "签发页面"), "ArrowDown");
  await page.keyboard.press("Enter");
  await expect(issued).toContainText("app.page · GET /app");
  await key(drawer.getByRole("radio", { name: "BUFFERED_JSON" }), "Space");
  await type(field(drawer, "响应上限"), "4096");
  const grant = group(drawer, "响应资源资格");
  await key(grant.getByRole("switch", { name: "签发资源资格" }), "Space");
  await type(field(grant, "列表指针"), "/orders");
  await type(field(grant, "资源指针"), "/id");
  await key(field(grant, "目标详情路由"), "ArrowDown");
  await page.keyboard.press("Enter");
  await expect(grant).toContainText("orders.read · GET /orders/{order_id}");
  await type(field(grant, "目标映射修订"), "orders-map-r1");
  await type(field(grant, "单次最多项数"), "10");
  await type(field(grant, "活动资格上限"), "200");
  await key(apply(drawer), "Enter");
  await expect(drawer).toHaveCount(0);
  await expect(page.getByText("有 1 项问题，打开编辑查看")).toHaveCount(0);

  await key(bar(page).getByRole("button", { name: "保存草稿", exact: true }), "Enter");
  await expect(page.getByRole("status")).toContainText("已保存为");
  const saved = routesOf(sent(mock, "PUT")).find((item) => item.operation_id === "orders.list");
  expect(saved).toEqual(routeNamed("orders.list"));
});

test("flow edits show in the diff and the approval banner, and nothing offers a direct apply", async ({
  page,
}) => {
  const served = loop();
  const mock = await mockSite(page, { config: loop() });
  // The save stages r4 over the served r3, which then needs approval, as on the server.
  mock.intercept = async (route, url) => {
    if (!url.pathname.endsWith("/config") || route.request().method() !== "PUT") return false;
    const posted = route.request().postDataJSON() as Json;
    mock.writes.push({
      method: "PUT",
      path: url.pathname,
      body: JSON.stringify(posted),
      key: null,
      digest: null,
    });
    mock.config = posted;
    mock.state = {
      desired_revision: 4,
      active_revision: 3,
      apply_state: "pending",
      requires_approval: true,
      reason_code: "CONTROL_SITE_APPROVAL_REQUIRED",
    };
    mock.revisions = [
      { revision: 4, config: posted },
      { revision: 3, config: served },
    ];
    await route.fulfill({ json: configBody(mock.id, mock.config, mock.state) });
    return true;
  };
  await signInAt(page, "/sites/site_alpha/routes");

  await page.getByRole("button", { name: "编辑路由 auth.login" }).click();
  let drawer = drawerNamed(page, "编辑路由");
  await field(group(drawer, "身份建立"), "凭证期限").fill("900");
  await apply(drawer).click();
  await page.getByRole("button", { name: "编辑路由 app.page" }).click();
  drawer = drawerNamed(page, "编辑路由");
  await field(group(drawer, "页面签发动作"), "活动页面上限").fill("64");
  await apply(drawer).click();

  await bar(page).getByRole("button", { name: "查看差异" }).click();
  const diff = page.getByRole("dialog", { name: "未保存修改的差异" });
  await expect(diff.getByRole("row", { name: /路由 auth\.login · 身份建立/ })).toContainText(
    "凭证 30 分钟",
  );
  await expect(diff.getByRole("row", { name: /路由 auth\.login · 身份建立/ })).toContainText(
    "凭证 15 分钟",
  );
  await expect(diff.getByRole("row", { name: /路由 app\.page · 页面签发动作/ })).toContainText(
    "活动页面 ≤ 64",
  );
  await diff.getByRole("button", { name: "关闭" }).last().click();
  await bar(page).getByRole("button", { name: "保存草稿", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("已保存为 r4");

  await sectionLink(page, "发布").click();
  const approval = page.getByRole("region", { name: "审批说明" });
  await expect(approval).toContainText("为什么需要审批");
  for (const label of ["认证入口或身份建立/撤销变更", "页面签发动作变更", "路由变更"]) {
    await expect(approval).toContainText(label);
  }
  await expect(approval).toContainText("持有“直接应用”能力的");
  await expect(approval).toContainText("CONTROL_SITE_INDEPENDENT_APPROVAL_REQUIRED");
  // There is no direct apply for these: applying waits for the approval.
  await expect(page.getByRole("button", { name: /直接应用/ })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "应用期望版本" })).toBeDisabled();

  await page.getByRole("button", { name: /查看待发布差异/ }).click();
  const pending = page.getByRole("dialog", { name: "待发布差异" });
  await expect(pending.getByRole("row", { name: /路由 auth\.login · 身份建立/ })).toContainText(
    "认证入口或身份建立/撤销变更",
  );
  // The page root takes part in both page facets: both are named for its change.
  const pageRow = pending.getByRole("row", { name: /路由 app\.page · 页面签发动作/ });
  await expect(pageRow).toContainText("页面签发动作变更");
  await expect(pageRow).toContainText("SENSOR_HTML 页面变更");
  await pending.getByRole("button", { name: "关闭" }).last().click();

  await page.getByRole("button", { name: "批准并应用" }).click();
  const confirm = page.getByRole("dialog", { name: "批准并应用 r4" });
  await expect(confirm).toContainText("只有独立审批人的批准能让它发布");
  await expect(confirm).toContainText("CONTROL_SITE_POLICY_REVISION_REUSED");
});

test("an operator declares pagination on the list, with the server's messages next to each field", async ({
  page,
}) => {
  const mock = await mockSite(page, { config: loop() });
  await signInAt(page, "/sites/site_alpha/routes");

  // Offered where the edge enforces it, and nowhere else.
  await page.getByRole("button", { name: "编辑路由 orders.read" }).click();
  let drawer = drawerNamed(page, "编辑路由");
  await expect(group(drawer, "分页参数")).toHaveCount(0);
  await drawer.getByRole("button", { name: "取消" }).click();

  await page.getByRole("button", { name: "编辑路由 orders.list" }).click();
  drawer = drawerNamed(page, "编辑路由");
  const paging = group(drawer, "分页参数");
  await paging.getByRole("switch", { name: "接受分页参数" }).click();
  await expect(field(paging, "参数名 1")).toHaveValue("page");

  // Each rule names itself next to the control that fixes it.
  await field(paging, "参数名 1").fill("order_id");
  await expect(paging.getByText("与某条路由的资源参数同名")).toBeVisible();
  await expect(apply(drawer)).toBeEnabled();
  await field(paging, "参数名 1").fill("Page");
  await expect(paging.getByText("参数名只能含小写字母 a–z 和下划线")).toBeVisible();
  await expect(apply(drawer)).toBeDisabled();
  await field(paging, "参数名 1").fill("page");
  await paging.getByRole("button", { name: "添加参数" }).click();
  await field(paging, "参数名 2").fill("page");
  await expect(paging.getByText("参数名与另一个参数重复")).toBeVisible();
  await field(paging, "参数名 2").fill("page_size");
  await choose(page, field(paging, "类型 2"), "页长 page_size");
  await field(paging, "页长上限 2").fill("50");
  await apply(drawer).click();

  await bar(page).getByRole("button", { name: "查看差异" }).click();
  const diff = page.getByRole("dialog", { name: "未保存修改的差异" });
  await expect(diff.getByRole("row", { name: /路由 orders\.list · 分页参数/ })).toContainText(
    "page_size（page_size ≤ 50）",
  );
  await diff.getByRole("button", { name: "关闭" }).last().click();

  await bar(page).getByRole("button", { name: "保存草稿", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("已保存为");
  const saved = byId(routesOf(sent(mock, "PUT")));
  expect(saved["orders.list"]?.query_pagination).toEqual({
    parameters: [
      { name: "page", kind: "page" },
      { name: "page_size", kind: "page_size", max_value: 50 },
    ],
  });
});

const openGroups: [string, string, (drawer: Locator, page: Page) => Promise<void>][] = [
  ["auth.login", "身份建立", async () => {}],
  [
    "app.page",
    "SENSOR_HTML 页面构建",
    async (drawer) => {
      await drawer.getByRole("button", { name: "从页面源码计算", exact: true }).click();
      await drawer.getByText("粘贴源码", { exact: true }).click();
      await field(drawer, "页面源码").fill("<html><HEAD></HEAD></html>");
      await drawer.getByRole("button", { name: "计算并填入摘要与偏移" }).click();
      await expect(drawer.getByRole("status")).toContainText("</HEAD>");
    },
  ],
  ["orders.list", "响应资源资格", async () => {}],
  [
    "orders.list",
    "分页参数",
    async (drawer) => {
      const paging = group(drawer, "分页参数");
      await paging.getByRole("switch", { name: "接受分页参数" }).click();
      await paging.getByRole("button", { name: "添加参数" }).click();
      await field(paging, "参数名 2").fill("Bad");
      await expect(paging.getByText("参数名只能含小写字母 a–z 和下划线")).toBeVisible();
    },
  ],
  [
    "auth.logout",
    "身份撤销",
    async (drawer) => {
      // A finding and a second effect open at once.
      await group(drawer, "响应资源资格").getByRole("switch", { name: "签发资源资格" }).click();
    },
  ],
];

for (const scheme of ["light", "dark"] as const) {
  test.describe(`flow drawer accessibility (${scheme})`, () => {
    test.use({ colorScheme: scheme });
    test("every flow group has no serious violations", async ({ page }) => {
      await mockSite(page, { config: loop() });
      await signInAt(page, "/sites/site_alpha/routes");
      for (const [id, name, prepare] of openGroups) {
        await page.getByRole("button", { name: `编辑路由 ${id}` }).click();
        const drawer = drawerNamed(page, "编辑路由");
        await expect(group(drawer, name)).toBeVisible();
        await prepare(drawer, page);
        expect(await serious(page), `${id}: ${name}`).toEqual([]);
        await drawer.getByRole("button", { name: "取消" }).click();
        await expect(drawer).toHaveCount(0);
      }
    });
  });
}

test("on a 390 px screen the drawer and every flow group fit without sideways scrolling", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await mockSite(page, { config: loop() });
  await signInAt(page, "/sites/site_alpha/routes");
  for (const [id, name, prepare] of openGroups) {
    await page.getByRole("button", { name: `编辑路由 ${id}` }).click();
    const drawer = drawerNamed(page, "编辑路由");
    await expect(group(drawer, name)).toBeVisible();
    await prepare(drawer, page);
    // Measure the drawer where it rests, not halfway through its slide-in.
    await settled(page);
    const box = await page.locator(".ant-drawer-content-wrapper").last().boundingBox();
    expect(box?.x ?? -1, id).toBeGreaterThanOrEqual(0);
    expect((box?.x ?? 0) + (box?.width ?? 999), id).toBeLessThanOrEqual(390);
    const sideways = await page.evaluate(() => {
      const body = document.querySelector(".ant-drawer-body");
      return body ? body.scrollWidth - body.clientWidth : 1;
    });
    expect(sideways, id).toBeLessThanOrEqual(0);
    expect(await serious(page), `${id}: ${name}`).toEqual([]);
    await drawer.getByRole("button", { name: "取消" }).click();
    await expect(drawer).toHaveCount(0);
  }
});
