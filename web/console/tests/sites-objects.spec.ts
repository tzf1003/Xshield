// The object map of a site (console design 3.1 to 3.6): the classes and their positions, the counters and the search,
// the position drawer and its actions, the declaration dialog, the synonym migration, the learning settings, the cold
// start of an empty map, and the wizard's option to open the new site on its map. The learning actions are served by
// the mock as learning state; every change to the configuration goes through the save dialog.

import { expect, type Page, test } from "@playwright/test";
import { type MockOptions, mockApi } from "./helpers/mock-api.ts";
import { siteEmr } from "./helpers/fixtures.ts";
import { callsTo, freezeClock } from "./helpers/sites-flow.ts";

const EDITOR = "站点配置，YAML 或 JSON";

const YAML_SITE = `name: yaml-shop
hosts:
  - yaml.example.com
origin: http://10.0.0.9:8080
session:
  cookie: JSESSIONID
entries:
  - /api/home
bypass: []
mode: observe
on_jev_unavailable: deny
`;

async function openMap(page: Page, path: string, options: MockOptions = {}): Promise<void> {
  await freezeClock(page);
  await mockApi(page, options);
  await page.goto(path);
  await expect(page.getByRole("tablist")).toBeVisible();
}

test("the object map lists the classes, and the positions of the chosen class", async ({
  page,
}) => {
  await openMap(page, "/sites/emr?tab=objects");

  await expect(page.getByRole("tab", { name: "对象表 7" })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  const classes = page.getByRole("navigation", { name: "类别" });
  await expect(classes.getByRole("button", { name: /医生/ })).toHaveAttribute(
    "aria-current",
    "true",
  );
  await expect(classes).toContainText("预约");

  const table = page.getByRole("table", { name: "位置列表" });
  await expect(table).toContainText("GET /api/doctors [].id");
  await expect(table).not.toContainText("GET /api/patients [].id");

  await classes.getByRole("button", { name: /患者/ }).click();
  await expect(page).toHaveURL(/class=patient/);
  await expect(table).toContainText("GET /api/patients [].id");
  await expect(table).not.toContainText("GET /doctor/{id} path[1]");
});

test("a counter narrows the positions to its state, and the URL keeps it", async ({ page }) => {
  await openMap(page, "/sites/emr?tab=objects&view=slot");
  const table = page.getByRole("table", { name: "位置列表" });
  await expect(table.locator("tbody tr")).toHaveCount(10);

  await page.getByRole("button", { name: /^已暂停/ }).click();
  await expect(page).toHaveURL(/state=suspended/);
  await expect(page.getByRole("button", { name: /^已暂停/ })).toHaveAttribute(
    "aria-pressed",
    "true",
  );
  await expect(table.locator("tbody tr")).toHaveCount(1);
  await expect(table).toContainText("GET /doctor/{id} path[1]");

  await page.getByRole("button", { name: /^类别/ }).click();
  await expect(page).not.toHaveURL(/state=/);
  await expect(table.locator("tbody tr")).toHaveCount(10);
});

test("the search text narrows the positions, and the URL keeps it", async ({ page }) => {
  await openMap(page, "/sites/emr?tab=objects&view=slot");
  await page.getByRole("searchbox", { name: "搜索类别、字段、路径" }).fill("doc_id");
  await expect(page).toHaveURL(/q=doc_id/);
  await expect(page.getByRole("table", { name: "位置列表" }).locator("tbody tr")).toHaveCount(3);
});

test("a position opens its drawer, j and k step through the positions, and Escape closes it", async ({
  page,
}) => {
  await openMap(page, "/sites/emr?tab=objects&view=slot");
  await page.locator("#slot-s2").click();
  await expect(page).toHaveURL(/slot=s2/);
  const drawer = page.getByRole("dialog");
  await expect(drawer).toContainText("GET /api/appointments [].doc_id");
  await expect(drawer).toContainText("这个位置的值之后用在");
  await expect(
    drawer.getByRole("link", { name: /GET \/doctor\/\{id\} path\[1\]/ }),
  ).toHaveAttribute("href", /object%3Adoctor/);

  await page.keyboard.press("j");
  await expect(page).toHaveURL(/slot=s3/);
  await expect(drawer).toContainText("GET /doctor/{id} path[1]");
  await page.keyboard.press("k");
  await expect(page).toHaveURL(/slot=s2/);

  await page.keyboard.press("Escape");
  await expect(page).not.toHaveURL(/slot=/);
  await expect(page.getByRole("dialog")).toHaveCount(0);
});

test("ignoring a proposal records it on the server and leaves the draft alone", async ({
  page,
}) => {
  await openMap(page, "/sites/emr?tab=objects&view=slot");
  await page.locator("#slot-s2").click();
  const drawer = page.getByRole("dialog");
  await drawer.getByRole("button", { name: "忽略" }).click();

  await expect(drawer).toContainText("已忽略这个位置的提议");
  expect(callsTo(page, "POST", "/api/sites/emr/objects/slots/s2/dismiss")).toHaveLength(1);
  await expect(page.getByText("未保存的改动")).toHaveCount(0);
  await expect(page.getByRole("dialog", { name: "保存 emr 的配置" })).toHaveCount(0);
});

test("confirming a proposal puts its declaration in the save dialog", async ({ page }) => {
  await openMap(page, "/sites/emr?tab=objects&view=slot");
  await page.locator("#slot-s2").click();
  const drawer = page.getByRole("dialog");
  await expect(drawer).toContainText(
    "对象表 ＋ 响应 GET /api/appointments [].doc_id 归为医生（仅 /api/appointments*）",
  );

  await drawer.getByRole("button", { name: "确认…", exact: true }).click();
  const save = page.getByRole("dialog", { name: "保存 emr 的配置" });
  await expect(save.getByRole("list", { name: "改动摘要" })).toContainText(
    "对象表 ＋ 字段 doc_id 归为医生（仅 /api/appointments*）",
  );
});

test("the declaration dialog takes the field and the interface from the URL, and lists where the name appears", async ({
  page,
}) => {
  await openMap(page, "/sites/emr?tab=objects&declare=doc_id&in=/api/appointments*");
  const dialog = page.getByRole("dialog", { name: "声明字段归类" });
  await expect(dialog.getByLabel("字段", { exact: true })).toHaveValue("doc_id");
  await expect(dialog.getByRole("radio", { name: "仅这些接口" })).toBeChecked();
  await expect(dialog).toContainText("/api/appointments*");

  const matches = dialog.getByRole("region", { name: "会匹配" });
  await expect(matches).toContainText("GET /api/appointments [].doc_id");
  await expect(dialog).toContainText("另有 2 个同名位置不在范围内");

  await dialog.getByRole("radio", { name: "全站" }).check();
  await expect(dialog).toContainText("站点里同名字段指两种东西");

  await dialog.getByRole("button", { name: "预估影响并加入草稿" }).click();
  await expect(page.getByRole("dialog", { name: "声明字段归类" })).toHaveCount(0);
  await expect(page.getByText("未保存的改动 1 处")).toBeVisible();
});

test("a site with no object map lists its candidate positions, picks the clear ones, and skipping keeps learning going", async ({
  page,
}) => {
  await openMap(page, "/sites/juice?tab=objects");
  await expect(page.getByText("还没有对象表")).toBeVisible();

  await expect(page.getByRole("checkbox", { name: "响应 GET /api/doctors [].id" })).toBeChecked();
  await expect(page.getByRole("checkbox", { name: "请求 GET /doctor/{id} path[1]" })).toBeChecked();
  await expect(page.getByRole("checkbox", { name: "响应 GET /api/docs [].id" })).not.toBeChecked();
  await expect(page.getByRole("button", { name: "确认 5 个位置…" })).toBeEnabled();

  await page.getByRole("button", { name: "稍后再说" }).click();
  await expect(page.getByText("还没有对象表")).toHaveCount(0);
  await expect(page.getByText("对象表还是空的，学习照常进行。")).toBeVisible();
});

test("confirming the candidates puts their declarations and slots in the save dialog", async ({
  page,
}) => {
  await openMap(page, "/sites/juice?tab=objects");
  await page.getByRole("button", { name: "确认 5 个位置…" }).click();

  const save = page.getByRole("dialog", { name: "保存 juice 的配置" });
  const changes = save.getByRole("list", { name: "改动摘要" });
  await expect(changes).toContainText("对象表 ＋ 字段 id 归为医生（仅 /api/doctors*）");
  await expect(changes).toContainText("对象表 ＋ 字段 id 归为患者（仅 /api/patients*）");
  await expect(changes).toContainText("对象表 ＋ 请求 GET /doctor/{id} 第 1 个路径参数 = 医生");
});

test("the learning settings save through the save dialog, and the agent stays off without a model", async ({
  page,
}) => {
  await openMap(page, "/sites/emr?tab=objects");
  await page.getByRole("button", { name: "学习设置 ⚙" }).click();

  const drawer = page.getByRole("dialog", { name: "学习设置" });
  await expect(drawer.getByRole("switch", { name: "学习代理" })).toBeDisabled();
  await expect(drawer).toContainText("系统里还没有配置学习代理模型");
  await expect(drawer).not.toContainText("网关接受对象表的学习设置之后");
  const save = drawer.getByRole("button", { name: "保存…" });
  await expect(save).toBeDisabled();

  await drawer.getByRole("switch", { name: "自动收紧" }).click();
  await expect(save).toBeEnabled();

  const uses = drawer.getByRole("spinbutton", { name: "至少使用次数" });
  await uses.fill("10001");
  await expect(save).toBeDisabled();
  await uses.fill("20");
  await expect(save).toBeEnabled();

  await save.click();
  await page.keyboard.press("Control+s");
  const dialog = page.getByRole("dialog", { name: "保存 emr 的配置" });
  await expect(dialog.getByRole("list", { name: "改动摘要" })).toContainText(
    "学习设置 自动收紧 开 → 关",
  );
});

test("the learning line shows the last run, its proposals open the positions to decide, and the source menu keeps its choice", async ({
  page,
}) => {
  await openMap(page, "/sites/emr?tab=objects");
  await expect(page.getByText("学习任务", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "新提议 3" }).click();
  await expect(page).toHaveURL(/state=proposed/);
  await page.getByRole("combobox", { name: /来源/ }).selectOption("agent");
  await expect(page).toHaveURL(/source=agent/);
});

test("the run record lists the runs, and a run opens the calls the agent got", async ({ page }) => {
  await openMap(page, "/sites/emr?tab=objects");
  await page.getByRole("button", { name: "运行记录" }).click();
  const drawer = page.getByRole("dialog", { name: "学习任务运行记录" });
  await expect(drawer.getByText("✕ 失败：读取判定日志超时")).toBeVisible();
  await drawer.getByText("手动", { exact: true }).click();
  await expect(drawer.getByRole("table", { name: "学习代理的调用" })).toBeVisible();
  await expect(drawer.getByText("失败：超时")).toBeVisible();
});

test("an agent answer that disagrees with the rules leaves the position to a decision, and the agent is not asked again while it is off", async ({
  page,
}) => {
  await openMap(page, "/sites/emr?tab=objects&slot=s8");
  const drawer = page.getByRole("dialog").filter({ hasText: "学习代理结论" });
  await expect(drawer.getByText("▲ 与规则不一致")).toBeVisible();
  await expect(drawer.getByRole("button", { name: "按规则确认…" })).toBeEnabled();
  await expect(drawer.getByRole("button", { name: "按学习代理确认…" })).toBeEnabled();
  await expect(drawer.getByRole("button", { name: "重新询问" })).toBeDisabled();
  await expect(drawer.getByText("学习代理没有开启，不能重新询问")).toBeVisible();
  await drawer.getByRole("button", { name: "保持有歧义" }).click();
  await expect(drawer.getByText("这个位置保持有歧义，等人处理。")).toBeVisible();
});

test("the synonym migration turns a group into declarations, and the save removes the group", async ({
  page,
}) => {
  const emr = structuredClone(siteEmr);
  emr.spec.advanced = { ...emr.spec.advanced, synonyms: [["doc", "doctor"]] };
  await openMap(page, "/sites/emr?tab=objects", { overrides: { "GET /api/sites/emr": emr } });

  await page.getByRole("button", { name: "从同义词改写…" }).click();
  const dialog = page.getByRole("dialog", { name: "从同义词改写" });
  const group = dialog.getByRole("region", { name: "doc ↔ doctor" });
  await expect(group).toContainText("GET /api/appointments [].doc_id");
  await expect(group.getByLabel("归为 GET /api/appointments [].doc_id")).toHaveValue("doctor");

  await dialog.getByRole("button", { name: "改写并加入草稿" }).click();
  await expect(page.getByRole("dialog", { name: "从同义词改写" })).toHaveCount(0);

  await page.keyboard.press("Control+s");
  const save = page.getByRole("dialog", { name: "保存 emr 的配置" });
  const changes = save.getByRole("list", { name: "改动摘要" });
  await expect(changes).toContainText("同义词 －doc ↔ doctor");
  await expect(changes).toContainText("对象表 ＋ 字段 doc_id 归为医生（仅 /api/appointments*）");
});

test("the wizard's last step opens the new site on its object map, and confirming there saves the candidates", async ({
  page,
}) => {
  await freezeClock(page);
  await mockApi(page);
  await page.goto("/sites/new?from=yaml");

  await page.getByRole("textbox", { name: EDITOR }).fill(YAML_SITE);
  await expect(page).toHaveURL(/\/sites\/new\?step=4$/);
  await expect(page.getByText("✓ 服务端校验通过")).toBeVisible();
  await expect(
    page.getByRole("checkbox", { name: "创建后确认对象表起点（可跳过）" }),
  ).toBeChecked();
  await page.getByRole("button", { name: "创建站点" }).click();

  await expect(page).toHaveURL(/\/sites\/new\?step=5&site=yaml-shop$/);
  await page.getByRole("button", { name: "确认 5 个位置…" }).click();

  await expect(page).toHaveURL(/\/sites\/yaml-shop\?tab=objects$/);
  await expect(page.getByRole("dialog", { name: "保存 yaml-shop 的配置" })).toBeVisible();
});

test("the events drawer asks the server for the open changes of the kind it names", async ({
  page,
}) => {
  const asked: string[] = [];
  page.on("request", (request) => {
    if (request.url().includes("/objects/events")) asked.push(request.url());
  });
  await openMap(page, "/sites/emr?tab=objects&objevents=open&objkind=auto_pause");
  await expect(page.getByRole("dialog")).toContainText("GET /doctor/{id} path[1]");
  expect(asked.some((url) => url.includes("status=open") && url.includes("kind=auto_pause"))).toBe(
    true,
  );
});

test("a declared position offers no mark-ambiguous button", async ({ page }) => {
  await openMap(page, "/sites/emr?tab=objects&view=slot");
  await page.locator("#slot-s1").click();
  const drawer = page.getByRole("dialog");
  await expect(drawer.locator(".obj-foot")).toBeVisible();
  await expect(drawer.getByRole("button", { name: "标为有歧义" })).toHaveCount(0);
});

test("a paused path position offers neither reject nor mark-ambiguous", async ({ page }) => {
  // Its entry is still in the configuration, so the backend refuses both until a save removes it.
  await openMap(page, "/sites/emr?tab=objects&view=slot&slot=s3");
  const drawer = page.getByRole("dialog");
  await expect(drawer).toContainText("判定退回名字推断");
  await expect(drawer.getByRole("button", { name: "重新确认为医生…" })).toBeVisible();
  await expect(drawer.getByRole("button", { name: "驳回" })).toHaveCount(0);
  await expect(drawer.getByRole("button", { name: "标为有歧义" })).toHaveCount(0);
});

test("a paused position is named in the banner, and its drawer re-confirms it through the save dialog", async ({
  page,
}) => {
  await openMap(page, "/sites/emr?tab=objects&view=slot");
  const banner = page.getByRole("status").filter({ hasText: "个位置已自动暂停" });
  await expect(banner).toContainText("GET /doctor/{id} path[1]");

  await banner.getByRole("button", { name: "查看" }).click();
  await expect(page).toHaveURL(/slot=s3/);
  const drawer = page.getByRole("dialog");
  await expect(drawer).toContainText("判定退回名字推断");
  await drawer.getByRole("button", { name: "重新确认为医生…" }).click();

  const save = page.getByRole("dialog", { name: "保存 emr 的配置" });
  await expect(save.getByRole("list", { name: "改动摘要" })).toContainText(
    "对象表 ＋ 请求 GET /doctor/{id} 第 1 个路径参数 = 医生",
  );
});
