// The impact in the save dialog, in the wording of design 6 (docs/06 6.4.9, docs/07 7.9.10): the new kinds of change
// read as sentences with their numbers, the notes say where the history can only estimate, and an enforce site that
// gets new fast allows is saved only after its example requests were looked at (design 3.2).

import { expect, type Locator, type Page, test } from "@playwright/test";
import type { ImpactChange, ImpactWarning } from "../src/api/types.ts";
import { setTheme, type Theme } from "./helpers/axe.ts";
import { mockApi } from "./helpers/mock-api.ts";
import {
  callsTo,
  expectDialogNoAxeViolations,
  freezeClock,
  impactWith,
} from "./helpers/sites-flow.ts";

const SAMPLE = "req_01a1973ed5c0732b8f29804d7fc746d3";
const GATEWAY = "/weixin/wx/mp/wx361163d21a65f679/gateway";

/** Adds /api/admin as an entry of the site, then waits for the draft bar. */
async function draftEntry(page: Page, site: string): Promise<void> {
  await page.goto(`/sites/${site}?tab=config&group=entries`);
  await page.getByRole("textbox", { name: "添加入口规则" }).fill("/api/admin");
  await page.getByRole("button", { name: "添加", exact: true }).click();
  await expect(page.getByRole("region", { name: "未保存的改动" })).toContainText(
    "未保存的改动 1 处",
  );
}

/** Opens the save dialog of the draft, and waits until its impact has loaded. */
async function openSave(page: Page, site: string): Promise<Locator> {
  await page
    .getByRole("region", { name: "未保存的改动" })
    .getByRole("button", { name: "预估影响并保存 ⌘S" })
    .click();
  const dialog = page.getByRole("dialog", { name: `保存 ${site} 的配置` });
  await expect(dialog).toContainText("影响（最近 24 小时");
  return dialog;
}

/** Juice (observe) with the given impact for the draft; the draft adds an entry. */
async function juiceWith(
  page: Page,
  changes: ImpactChange[],
  complete = true,
  warnings: ImpactWarning[] = [],
): Promise<Locator> {
  await freezeClock(page);
  const preview = { ...impactWith(changes, { warnings }), complete };
  await mockApi(page, { overrides: { "POST /api/sites/juice/preview": preview } });
  await draftEntry(page, "juice");
  return openSave(page, "juice");
}

test("接口拆分写成一句话，请求数和接口数都写在句子里", async ({ page }) => {
  const dialog = await juiceWith(page, [
    {
      kind: "api_split",
      count: 9812,
      detail: { apis: 37 },
      top: [["POST", GATEWAY, 9812]],
      sample: SAMPLE,
    },
  ]);

  await expect(
    dialog.getByText("按接口拆分：这条路径下 9,812 个请求将按 37 个接口分别判定"),
  ).toBeVisible();
  await expect(dialog).not.toContainText("保存后开始统计");
});

test("接口名来自请求头的拆分只能保存后统计，并且写明这一点", async ({ page }) => {
  const dialog = await juiceWith(page, [
    { kind: "api_split", count: 9812, detail: { source: "header", apis: 37 } },
  ]);

  await expect(dialog.getByText("按接口拆分：这条路径下的请求将按接口分别判定")).toBeVisible();
  await expect(dialog.getByText("保存后开始统计", { exact: true })).toBeVisible();
});

test("入口不再命中时写出入口和受影响的无会话请求数", async ({ page }) => {
  const dialog = await juiceWith(page, [
    {
      kind: "entry_unreachable",
      count: 41,
      top: [["POST", "/rest/user/login", 41]],
    },
  ]);

  await expect(
    dialog.getByText(
      "入口不再命中：入口 /rest/user/login 将不再命中任何请求（41 个原本放行的无会话请求将需要会话）",
    ),
  ).toBeVisible();
});

test("新增快速放行写出次数，近似时附上来源的说明", async ({ page }) => {
  const dialog = await juiceWith(page, [
    {
      kind: "new_fast_allow",
      count: 158,
      detail: { approximate: true },
      top: [["GET", "/rest/products/search", 158]],
      sample: SAMPLE,
    },
  ]);

  await expect(dialog.getByText("新增快速放行：158 次 Jev 调用会变成快速放行")).toBeVisible();
  await expect(
    dialog.getByText("来源只记录了前 3 个，结果是近似值", { exact: true }),
  ).toBeVisible();
});

test("估算的按接口拆分、入口不再命中和缓存按接口区分，都附上近似的说明", async ({ page }) => {
  const dialog = await juiceWith(page, [
    {
      kind: "api_split",
      count: 9812,
      detail: { apis: 37, approximate: true },
      top: [["POST", GATEWAY, 9812]],
      sample: SAMPLE,
    },
    {
      kind: "entry_unreachable",
      count: 41,
      detail: { approximate: true },
      top: [["POST", "/rest/user/login", 41]],
    },
    { kind: "cache_by_api", count: 0, detail: { approximate: true } },
  ]);

  await expect(dialog.getByText("来源只记录了前 3 个，结果是近似值", { exact: true })).toHaveCount(
    3,
  );
  await expect(dialog.getByText("只提示，不计数", { exact: true })).toHaveCount(1);
});

test("接口名没有核对过时，影响的提示写明按接口和前缀入口的数字可能不完整", async ({ page }) => {
  const dialog = await juiceWith(
    page,
    [
      {
        kind: "api_split",
        count: 9812,
        detail: { apis: 37, approximate: true },
        top: [["POST", GATEWAY, 9812]],
        sample: SAMPLE,
      },
    ],
    true,
    ["INTERFACE_UNVERIFIED"],
  );

  await expect(
    dialog.getByText("接口名没有在历史里核对过，按接口和前缀入口的数字可能不完整"),
  ).toBeVisible();
});

test("改回 Jev 写出靠名字认错的类别，说清楚原来认成了什么", async ({ page }) => {
  const dialog = await juiceWith(page, [
    {
      kind: "back_to_jev",
      count: 14,
      detail: { name_kind: "document", object_kind: "doctor" },
      top: [["GET", "/docs/{id}", 14]],
      sample: SAMPLE,
    },
  ]);

  await expect(dialog.getByText("改回 Jev：14 次快速放行会改回调用 Jev")).toBeVisible();
  await expect(
    dialog.getByText("这些请求原本靠名字把医生编号当成了文档编号", { exact: true }),
  ).toBeVisible();
});

test("缓存按接口区分只是提示，说明里写明不计数", async ({ page }) => {
  const dialog = await juiceWith(page, [{ kind: "cache_by_api", count: 0 }]);

  await expect(
    dialog.getByText("缓存按接口区分：同一会话里参数相同的不同接口不再共用放行结论"),
  ).toBeVisible();
  await expect(dialog.getByText("只提示，不计数", { exact: true })).toBeVisible();
});

test("统计不完整时，影响的标题写明按前几条记录计算", async ({ page }) => {
  const dialog = await juiceWith(page, [{ kind: "cache_by_api", count: 0 }], false);

  await expect(dialog).toContainText("影响（最近 24 小时，548 条记录；按前 548 条记录计算）");
});

test("观察模式的站点出现新增快速放行时，保存不需要勾选", async ({ page }) => {
  const dialog = await juiceWith(page, [
    {
      kind: "new_fast_allow",
      count: 158,
      top: [["GET", "/rest/products/search", 158]],
      sample: SAMPLE,
    },
  ]);

  await expect(dialog.getByRole("button", { name: "保存为 v8" })).toBeEnabled();
  await expect(dialog.getByRole("checkbox", { name: "我已查看示例请求" })).toHaveCount(0);
});

test("拦截模式的站点出现新增快速放行时，勾选查看示例请求之前不能保存", async ({ page }) => {
  await freezeClock(page);
  await mockApi(page, {
    overrides: {
      "POST /api/sites/emr/preview": impactWith([
        {
          kind: "new_fast_allow",
          count: 158,
          top: [["GET", "/rest/products/search", 158]],
          sample: SAMPLE,
        },
      ]),
    },
  });
  await draftEntry(page, "emr");
  const dialog = await openSave(page, "emr");

  const checkbox = dialog.getByRole("checkbox", { name: "我已查看示例请求" });
  await expect(checkbox).toBeVisible();
  await expect(checkbox).not.toBeChecked();
  const save = dialog.getByRole("button", { name: "保存为 v14" });
  await expect(save).toBeDisabled();

  await checkbox.check();
  await expect(save).toBeEnabled();
  await save.click();

  await expect(dialog).toBeHidden();
  expect(callsTo(page, "PUT", "/api/sites/emr")).toHaveLength(1);
});

test("拦截模式的站点没有新增快速放行时，不出现示例请求的复选框", async ({ page }) => {
  await freezeClock(page);
  await mockApi(page, {
    overrides: {
      "POST /api/sites/emr/preview": impactWith([
        {
          kind: "no_session_to_entry",
          count: 4,
          top: [["GET", "/api/admin/users", 4]],
          sample: SAMPLE,
        },
      ]),
    },
  });
  await draftEntry(page, "emr");
  const dialog = await openSave(page, "emr");

  await expect(dialog.getByRole("button", { name: "保存为 v14" })).toBeEnabled();
  await expect(dialog.getByRole("checkbox", { name: "我已查看示例请求" })).toHaveCount(0);
});

for (const theme of ["light", "dark"] satisfies Theme[]) {
  test(`保存对话框里的新影响写法在 ${theme} 主题下通过 axe 检查`, async ({ page }) => {
    await setTheme(page, theme);
    const dialog = await juiceWith(page, [
      {
        kind: "api_split",
        count: 9812,
        detail: { apis: 37 },
        top: [["POST", GATEWAY, 9812]],
        sample: SAMPLE,
      },
      {
        kind: "new_fast_allow",
        count: 158,
        detail: { approximate: true },
        top: [["GET", "/rest/products/search", 158]],
        sample: SAMPLE,
      },
      {
        kind: "back_to_jev",
        count: 14,
        detail: { name_kind: "document", object_kind: "doctor" },
        top: [["GET", "/docs/{id}", 14]],
        sample: SAMPLE,
      },
      { kind: "cache_by_api", count: 0 },
    ]);
    await expect(dialog.getByText("改回 Jev：14 次快速放行会改回调用 Jev")).toBeVisible();

    await expectDialogNoAxeViolations(page);
  });
}
