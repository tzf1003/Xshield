// Saving a configuration (docs/06 6.4.9, docs/07 7.9.10 and 7.9.13): the draft bar, the save dialog with its
// changes and impact, the new version, and the rollout that follows it. A partial rollout is said in words.

import { expect, type Page, test } from "@playwright/test";
import { setTheme, type Theme } from "./helpers/axe.ts";
import { mockApi, reply } from "./helpers/mock-api.ts";
import {
  callsTo,
  expectDialogNoAxeViolations,
  freezeClock,
  impactWith,
} from "./helpers/sites-flow.ts";

const SAMPLE = "req_01a1974194e0758bb0b9c9408bfc31eb";

/** The preview of adding /api/admin as an entry: four requests that were not judged are now judged. */
const ADD_ENTRY_PREVIEW = impactWith([
  { kind: "no_session_to_entry", count: 4, top: [["GET", "/api/admin/users", 4]], sample: SAMPLE },
]);

/** Adds one entry to emr in the entries group, then opens the save dialog from the draft bar. */
async function draftAnEntry(page: Page): Promise<void> {
  await page.goto("/sites/emr?tab=config&group=entries");
  await page.getByRole("textbox", { name: "添加入口规则" }).fill("/api/admin");
  await page.getByRole("button", { name: "添加", exact: true }).click();
  await expect(page.getByRole("region", { name: "未保存的改动" })).toContainText(
    "未保存的改动 1 处",
  );
}

test("saving a draft shows its changes and impact, then the new version reaches the gateways", async ({
  page,
}) => {
  await freezeClock(page);
  await mockApi(page, { overrides: { "POST /api/sites/emr/preview": ADD_ENTRY_PREVIEW } });
  await draftAnEntry(page);

  await page
    .getByRole("region", { name: "未保存的改动" })
    .getByRole("button", { name: "预估影响并保存 ⌘S" })
    .click();

  const dialog = page.getByRole("dialog", { name: "保存 emr 的配置" });
  await expect(dialog.getByRole("list", { name: "改动摘要" })).toContainText(
    "入口 ＋1：/api/admin",
  );
  await expect(dialog).toContainText("影响（最近 24 小时，548 条记录）");
  const change = dialog.getByText("无会话请求改为按入口判定");
  await expect(change).toBeVisible();
  await change.click(); // the example paths sit behind the row
  await expect(dialog).toContainText("GET /api/admin/users");

  await dialog.getByRole("button", { name: "保存为 v14" }).click();

  await expect(dialog).toBeHidden();
  await expect(page.getByRole("region", { name: "未保存的改动" })).toHaveCount(0);
  await expect(page.getByText("● v14 已生效（2/2 个网关")).toBeVisible();

  const [saved] = callsTo(page, "PUT", "/api/sites/emr");
  expect(saved?.body).toMatchObject({
    expected_version: 13,
    spec: { entries: ["/login", "/api/home", "/api/patients", "/api/admin"] },
  });
});

test("with the gateways still on the old version, the page says the rollout is partial", async ({
  page,
}) => {
  await freezeClock(page);
  await mockApi(page, {
    gatewaysLoadSaved: false,
    overrides: { "POST /api/sites/emr/preview": ADD_ENTRY_PREVIEW },
  });
  await draftAnEntry(page);
  await page
    .getByRole("region", { name: "未保存的改动" })
    .getByRole("button", { name: "预估影响并保存 ⌘S" })
    .click();
  await page
    .getByRole("dialog", { name: "保存 emr 的配置" })
    .getByRole("button", { name: "保存为 v14" })
    .click();

  await expect(page.getByText("已保存 v14 · 0/2 个网关已生效")).toBeVisible();
  await expect(page.getByText("edge-1 还没有加载 v14（停在 v13）")).toBeVisible();
  await expect(page.getByText("edge-2 还没有加载 v14（停在 v12）")).toBeVisible();
  await expect(page.getByText("edge-3 离线")).toBeVisible();
  await expect(page.getByText("● v14 已生效")).toHaveCount(0);
});

test("ctrl+s on a draft opens the same save dialog", async ({ page }) => {
  await freezeClock(page);
  await mockApi(page, { overrides: { "POST /api/sites/emr/preview": ADD_ENTRY_PREVIEW } });
  await draftAnEntry(page);

  await page.keyboard.press("Control+s");

  await expect(page.getByRole("dialog", { name: "保存 emr 的配置" })).toBeVisible();
  expect(callsTo(page, "PUT", "/api/sites/emr")).toHaveLength(0);
});

test("a draft with an invalid origin is not saved, and the page names the field", async ({
  page,
}) => {
  await freezeClock(page);
  await mockApi(page);
  await page.goto("/sites/emr?tab=config");

  await page.getByLabel("源站地址").fill("ftp://10.0.0.5:8080");
  const draft = page.getByRole("region", { name: "未保存的改动" });
  await expect(draft).toContainText("有 1 项需要修正，修好后才能保存");

  await draft.getByRole("button", { name: "预估影响并保存 ⌘S" }).click();

  await expect(page.getByRole("alert").filter({ hasText: "有 1 项需要修正" })).toContainText(
    "有 1 项需要修正：源站地址必须是 http://主机[:端口] 或 https://主机[:端口]，不带路径",
  );
  await expect(page.getByLabel("源站地址")).toBeFocused();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  expect(callsTo(page, "PUT", "/api/sites/emr")).toHaveLength(0);
});

test("a save against a newer version says which version is current", async ({ page }) => {
  await freezeClock(page);
  await mockApi(page, {
    overrides: {
      "POST /api/sites/emr/preview": ADD_ENTRY_PREVIEW,
      "PUT /api/sites/emr": reply(409, { error: "VERSION_CONFLICT", current_version: 14 }),
    },
  });
  await draftAnEntry(page);
  await page
    .getByRole("region", { name: "未保存的改动" })
    .getByRole("button", { name: "预估影响并保存 ⌘S" })
    .click();
  const dialog = page.getByRole("dialog", { name: "保存 emr 的配置" });
  await dialog.getByRole("button", { name: "保存为 v14" }).click();

  await expect(dialog.getByRole("alert")).toContainText(
    "配置已被修改（当前 v14）。你的改动基于 v13，保存前需要先处理。",
  );
  await expect(dialog.getByRole("button", { name: "在 v14 基础上重新应用我的改动" })).toBeVisible();
});

for (const theme of ["light", "dark"] satisfies Theme[]) {
  test(`the save dialog passes axe in the ${theme} theme`, async ({ page }) => {
    await freezeClock(page);
    await mockApi(page, { overrides: { "POST /api/sites/emr/preview": ADD_ENTRY_PREVIEW } });
    await setTheme(page, theme);
    await draftAnEntry(page);
    await page
      .getByRole("region", { name: "未保存的改动" })
      .getByRole("button", { name: "预估影响并保存 ⌘S" })
      .click();
    const dialog = page.getByRole("dialog", { name: "保存 emr 的配置" });
    await expect(dialog.getByRole("button", { name: "保存为 v14" })).toBeEnabled();
    await expectDialogNoAxeViolations(page);
  });
}
