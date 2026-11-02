// The change history of a site (docs/06 6.4.9): every version, the difference between two of them, and a rollback.
// A rollback saves a new version whose content is the target's, so the history keeps every step.

import { expect, type Page, test } from "@playwright/test";
import { expectNoAxeViolations, setTheme, type Theme } from "./helpers/axe.ts";
import { mockApi } from "./helpers/mock-api.ts";
import {
  callsTo,
  expectDialogNoAxeViolations,
  freezeClock,
  impactWith,
} from "./helpers/sites-flow.ts";

/** Rolling back to v10 takes ssn out of the redaction words, so the redacted range changes for 17 requests. */
const ROLLBACK_PREVIEW = impactWith([
  { kind: "secret_fields", count: 17, top: [["POST", "/api/patients", 12]] },
]);

const ROLLBACK_ROW = "Jev 超时调到 3000 ms";

async function openHistory(
  page: Page,
  path: string,
  overrides: Record<string, unknown> = {},
): Promise<void> {
  await freezeClock(page);
  await mockApi(page, { overrides });
  await page.goto(path);
  await expect(page.getByRole("table", { name: "版本历史" })).toBeVisible();
}

test("the history compares the newest version with the one before it by default", async ({
  page,
}) => {
  await openHistory(page, "/sites/emr?tab=history");

  await expect(page.getByRole("combobox", { name: /^从/ })).toHaveValue("12");
  await expect(page.getByRole("combobox", { name: /^到/ })).toHaveValue("13");
  await expect(page.getByRole("region", { name: "差异" })).toContainText("ssn");
});

test("two chosen versions show their difference, and the address keeps the pair", async ({
  page,
}) => {
  await openHistory(page, "/sites/emr?tab=history&diff=6..7");

  const diff = page.getByRole("region", { name: "差异" });
  await expect(diff).toContainText("mode: observe");
  await expect(diff).toContainText("mode: enforce");

  await page.getByRole("combobox", { name: /^到/ }).selectOption({ label: "v8" });
  await expect(page).toHaveURL(/diff=6\.\.8/);
  await expect(page.getByRole("combobox", { name: /^到/ })).toHaveValue("8");
});

test("the same version on both sides asks for two different versions", async ({ page }) => {
  await openHistory(page, "/sites/emr?tab=history&diff=7..7");

  await expect(page.getByText("选择两个不同的版本。")).toBeVisible();
});

test("a version can be read in full, in a row across the table", async ({ page }) => {
  await openHistory(page, "/sites/emr?tab=history");

  const row = page.getByRole("row").filter({ hasText: "追加脱敏字段 ssn" });
  await row.getByRole("button", { name: "查看全文" }).click();
  await expect(row.getByRole("button", { name: "收起全文" })).toBeVisible();

  // The full text opens under the summary and keeps its lines: it fills the table's width and scrolls sideways.
  const full = page.getByRole("region", { name: /全文$/ });
  await expect(full).toContainText("mode: enforce");
  const code = full.locator("pre");
  await expect(code).toHaveCSS("white-space", "pre");
  const [table, text] = await Promise.all([
    page.getByRole("table", { name: "版本历史" }).boundingBox(),
    code.boundingBox(),
  ]);
  expect(text?.width ?? 0).toBeGreaterThan((table?.width ?? 0) - 40);

  await row.getByRole("button", { name: "收起全文" }).click();
  await expect(full).toBeHidden();
});

test("rolling back to v10 shows the change and the impact, then saves v14 with the note", async ({
  page,
}) => {
  await openHistory(page, "/sites/emr?tab=history", {
    "POST /api/sites/emr/preview": ROLLBACK_PREVIEW,
  });

  const history = page.getByRole("table", { name: "版本历史" });
  await history
    .getByRole("row")
    .filter({ hasText: ROLLBACK_ROW })
    .getByRole("button", { name: "以此版本回滚…" })
    .click();

  const dialog = page.getByRole("dialog", { name: "回滚 emr 到 v10" });
  await expect(dialog.getByRole("list", { name: "改动摘要" })).toContainText("追加脱敏词 －ssn");
  await expect(dialog.getByRole("region", { name: "差异" })).toContainText("ssn");
  await expect(dialog).toContainText("影响（最近 24 小时）");
  await expect(dialog).toContainText("脱敏范围变化");
  await dialog.getByLabel("备注（可选，最多 500 字）").fill("回到 v10，去掉 ssn");
  await dialog.getByRole("button", { name: "回滚，生成 v14（内容同 v10）" }).click();

  await expect(dialog).toBeHidden();
  await expect(page.getByText("● v14 已生效（2/2 个网关")).toBeVisible();
  const [rolled] = callsTo(page, "POST", "/api/sites/emr/rollback");
  expect(rolled?.body).toMatchObject({
    to_version: 10,
    expected_version: 13,
    note: "回到 v10，去掉 ssn",
  });

  // v12 is an older rollback to v10 as well, so the new row is the one with this note.
  const made = history.getByRole("row").filter({ hasText: "回到 v10，去掉 ssn" });
  await expect(made).toHaveCount(1);
  await expect(made).toContainText("回滚（回到 v10）");
  await expect(made).toContainText("v14");
  await expect(made).toContainText("当前");
});

test("a draft with unsaved changes holds the rollback until it is saved or dropped", async ({
  page,
}) => {
  await freezeClock(page);
  await mockApi(page);
  await page.goto("/sites/emr?tab=config&group=entries");
  await page.getByRole("textbox", { name: "添加入口规则" }).fill("/api/admin");
  await page.getByRole("button", { name: "添加", exact: true }).click();
  await expect(page.getByRole("region", { name: "未保存的改动" })).toContainText(
    "未保存的改动 1 处",
  );

  await page.getByRole("tab", { name: "变更历史" }).click();
  await page
    .getByRole("row")
    .filter({ hasText: ROLLBACK_ROW })
    .getByRole("button", { name: "以此版本回滚…" })
    .click();

  const dialog = page.getByRole("dialog", { name: "回滚 emr 到 v10" });
  await expect(dialog.getByRole("alert")).toContainText(
    "有未保存的改动。请先在配置页保存或放弃，再回滚。",
  );
  await expect(dialog.getByRole("button", { name: /^回滚，生成 v14/ })).toBeDisabled();
  expect(callsTo(page, "POST", "/api/sites/emr/rollback")).toHaveLength(0);
});

for (const theme of ["light", "dark"] satisfies Theme[]) {
  test(`the rollback dialog passes axe in the ${theme} theme`, async ({ page }) => {
    await setTheme(page, theme);
    await openHistory(page, "/sites/emr?tab=history", {
      "POST /api/sites/emr/preview": ROLLBACK_PREVIEW,
    });
    await page
      .getByRole("row")
      .filter({ hasText: ROLLBACK_ROW })
      .getByRole("button", { name: "以此版本回滚…" })
      .click();

    await expect(page.getByRole("dialog", { name: "回滚 emr 到 v10" })).toContainText(
      "脱敏范围变化",
    );
    await expectDialogNoAxeViolations(page);
  });
}

for (const theme of ["light", "dark"] satisfies Theme[]) {
  test(`a full text in the history passes axe in the ${theme} theme`, async ({ page }) => {
    await setTheme(page, theme);
    await openHistory(page, "/sites/emr?tab=history");
    await page
      .getByRole("row")
      .filter({ hasText: "追加脱敏字段 ssn" })
      .getByRole("button", { name: "查看全文" })
      .click();

    await expect(page.getByRole("region", { name: /全文$/ })).toContainText("mode: enforce");
    await expectNoAxeViolations(page);
  });
}
