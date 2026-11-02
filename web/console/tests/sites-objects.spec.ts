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
    "对象表 ＋ 字段 doc_id 归为 doctor（仅 /api/appointments*）",
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

test("a site with no object map offers its candidate classes, and skipping them keeps learning going", async ({
  page,
}) => {
  await openMap(page, "/sites/juice?tab=objects");
  await expect(page.getByText("还没有对象表")).toBeVisible();

  await expect(page.getByRole("checkbox", { name: /医生/ })).toBeChecked();
  await expect(page.getByRole("checkbox", { name: /患者/ })).toBeChecked();
  await expect(page.getByRole("checkbox", { name: /文档/ })).not.toBeChecked();
  await expect(page.getByRole("checkbox", { name: /记录/ })).toBeDisabled();
  await expect(page.getByRole("button", { name: "确认 2 个类别…" })).toBeEnabled();

  await page.getByRole("button", { name: "稍后再说" }).click();
  await expect(page.getByText("还没有对象表")).toHaveCount(0);
  await expect(page.getByText("对象表还是空的，学习照常进行。")).toBeVisible();
});

test("confirming the candidates puts their declarations in the save dialog", async ({ page }) => {
  await openMap(page, "/sites/juice?tab=objects");
  await page.getByRole("button", { name: "确认 2 个类别…" }).click();

  const save = page.getByRole("dialog", { name: "保存 juice 的配置" });
  const changes = save.getByRole("list", { name: "改动摘要" });
  await expect(changes).toContainText("对象表 ＋ 字段 id 归为 doctor（仅 /api/doctors*）");
  await expect(changes).toContainText("对象表 ＋ 字段 id 归为 patient（仅 /api/patients*）");
});

test("the learning settings change the configuration, and the change goes through the save dialog", async ({
  page,
}) => {
  await openMap(page, "/sites/emr?tab=objects");
  await page.getByRole("button", { name: "学习设置 ⚙" }).click();

  const drawer = page.getByRole("dialog", { name: "学习设置" });
  await expect(drawer.getByRole("switch", { name: "agent" })).toBeDisabled();
  await expect(drawer).toContainText("没有配置模型，agent 暂不可用。");
  await drawer.getByRole("switch", { name: "自动收紧" }).click();
  await drawer.getByRole("button", { name: "保存…" }).click();

  const save = page.getByRole("dialog", { name: "保存 emr 的配置" });
  await expect(save.getByRole("list", { name: "改动摘要" })).toContainText(
    "学习设置 自动收紧 开 → 关",
  );
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
  await expect(changes).toContainText("对象表 ＋ 字段 doc_id 归为 doctor（仅 /api/appointments*）");
});

test("the wizard can open the new site on its object map", async ({ page }) => {
  await freezeClock(page);
  await mockApi(page);
  await page.goto("/sites/new?from=yaml");

  await page.getByRole("textbox", { name: EDITOR }).fill(YAML_SITE);
  await expect(page).toHaveURL(/\/sites\/new\?step=4$/);
  await expect(page.getByText("✓ 服务端校验通过")).toBeVisible();
  await page.getByRole("checkbox", { name: "创建后打开对象表" }).check();
  await page.getByRole("button", { name: "创建站点" }).click();

  await expect(page).toHaveURL(/\/sites\/yaml-shop\?tab=objects$/);
  await expect(page.getByRole("tab", { name: "对象表" })).toHaveAttribute("aria-selected", "true");
});
