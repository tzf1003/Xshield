// Switching a site between observe and enforce (docs/06 6.4.10, flow D): the readiness checklist and the impact of the
// switch. Switching to enforce waits until the blocked requests are confirmed. Either way the switch saves a new
// version of the saved configuration, so it waits while the draft has unsaved changes.

import { expect, test } from "@playwright/test";
import { setTheme, type Theme } from "./helpers/axe.ts";
import { mockApi } from "./helpers/mock-api.ts";
import {
  callsTo,
  expectDialogNoAxeViolations,
  freezeClock,
  impactWith,
  untilModalSettled,
} from "./helpers/sites-flow.ts";

/** juice goes to enforce: the 14 requests that observation would have blocked are blocked from now on. */
const ENFORCE_PREVIEW = impactWith([{ kind: "would_block_to_blocked", count: 14 }]);

const ENFORCE_TITLE = "把 juice 切换到拦截模式";
const ENFORCE_ACTION = "切换到拦截模式（生成 v8）";
const CONFIRM = "我已查看这些请求，确认它们应当被拦截";

test("switching an observing site to enforce shows its readiness and waits for the blocked requests to be confirmed", async ({
  page,
}) => {
  await freezeClock(page);
  await mockApi(page, { overrides: { "POST /api/sites/juice/preview": ENFORCE_PREVIEW } });
  await page.goto("/sites/juice");
  await page.getByRole("button", { name: "切换到拦截模式…" }).click();

  await untilModalSettled(page, ENFORCE_TITLE);
  const dialog = page.getByRole("dialog", { name: ENFORCE_TITLE });
  const readiness = dialog.getByRole("list", { name: "就绪检查" });
  await expect(readiness).toContainText("已观察 6 天 4 小时");
  await expect(readiness).toContainText("本应拦截 14 条：Jev 拒绝 11 · 无会话 3");
  await expect(readiness.getByRole("link", { name: "逐条查看" })).toHaveCount(1);
  await expect(dialog).toContainText("观察模式切为拦截");
  const submit = dialog.getByRole("button", { name: ENFORCE_ACTION });
  await expect(submit).toBeDisabled();
  expect(callsTo(page, "PUT", "/api/sites/juice")).toHaveLength(0);

  await dialog.getByRole("checkbox", { name: CONFIRM }).check();
  await expect(submit).toBeEnabled();
  await submit.click();

  await expect(dialog).toBeHidden();
  await expect(page.getByRole("button", { name: "切回观察模式…" })).toBeVisible();
  await expect(page.getByText("● v8 已生效")).toBeVisible();
  const [saved] = callsTo(page, "PUT", "/api/sites/juice");
  expect(saved?.body).toMatchObject({
    expected_version: 7,
    note: "切换到拦截模式",
    spec: { mode: "enforce" },
  });
});

test("switching an enforcing site back to observe needs no confirmation", async ({ page }) => {
  await freezeClock(page);
  await mockApi(page);
  await page.goto("/sites/emr");
  await page.getByRole("button", { name: "切回观察模式…" }).click();

  await untilModalSettled(page, "把 emr 切回观察模式");
  const dialog = page.getByRole("dialog", { name: "把 emr 切回观察模式" });
  await expect(dialog).toContainText("切回观察后不再拦截任何请求，只记录本应拦截。");
  await expect(dialog.getByRole("checkbox")).toHaveCount(0);
  await dialog.getByRole("button", { name: "切回观察模式（生成 v14）" }).click();

  await expect(dialog).toBeHidden();
  await expect(page.getByText(/^观察模式（自 .+ 起）$/)).toBeVisible();
  const [saved] = callsTo(page, "PUT", "/api/sites/emr");
  expect(saved?.body).toMatchObject({
    expected_version: 13,
    note: "切回观察模式",
    spec: { mode: "observe" },
  });
});

test("a draft with unsaved changes holds the mode switch", async ({ page }) => {
  await freezeClock(page);
  await mockApi(page);
  await page.goto("/sites/juice?tab=config&group=entries");
  await page.getByRole("textbox", { name: "添加入口规则" }).fill("/api/admin");
  await page.getByRole("button", { name: "添加", exact: true }).click();
  await expect(page.getByRole("region", { name: "未保存的改动" })).toContainText(
    "未保存的改动 1 处",
  );

  await page.getByRole("button", { name: "切换到拦截模式…" }).click();

  const dialog = page.getByRole("dialog", { name: ENFORCE_TITLE });
  await expect(dialog.getByRole("alert")).toContainText(
    "有未保存的改动。请先在配置页保存或放弃，再切换模式。",
  );
  await expect(dialog.getByRole("button", { name: ENFORCE_ACTION })).toBeDisabled();
  expect(callsTo(page, "PUT", "/api/sites/juice")).toHaveLength(0);
});

for (const theme of ["light", "dark"] satisfies Theme[]) {
  test(`the switch to enforce passes axe in the ${theme} theme`, async ({ page }) => {
    await setTheme(page, theme);
    await freezeClock(page);
    await mockApi(page, { overrides: { "POST /api/sites/juice/preview": ENFORCE_PREVIEW } });
    await page.goto("/sites/juice");
    await page.getByRole("button", { name: "切换到拦截模式…" }).click();

    await expect(page.getByRole("dialog", { name: ENFORCE_TITLE })).toContainText(
      "观察模式切为拦截",
    );
    await expectDialogNoAxeViolations(page);
  });

  test(`the switch back to observe passes axe in the ${theme} theme`, async ({ page }) => {
    await setTheme(page, theme);
    await freezeClock(page);
    await mockApi(page);
    await page.goto("/sites/emr");
    await page.getByRole("button", { name: "切回观察模式…" }).click();

    await expect(page.getByRole("dialog", { name: "把 emr 切回观察模式" })).toContainText(
      "切回观察后不再拦截任何请求",
    );
    await expectDialogNoAxeViolations(page);
  });
}
