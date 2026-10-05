/**
 * axe-core scans of the case center and the approval center, with data, in both themes. Only
 * critical and serious findings fail the build (the same bar as the other screens).
 */
import { expect, type Page, test } from "@playwright/test";
import { ACCESS_ID, accessInspectionFixture, accessListFixture } from "./access-fixtures";
import { serious } from "./axe";
import { exportFixture, exportListFixture, exportListItemFixture } from "./export-fixtures";
import { signIn } from "./shell-helpers";
import { CASE_ID, EXPORT_ID, mockWork, type Override } from "./work-helpers";

/** The personal lists carry one decided request of each kind, so the download panels render. */
const mine: Override = (url) => {
  if (url.pathname === "/control/v1/evidence-access-requests") {
    const list = accessListFixture("mine");
    const [first] = list.items;
    if (first) first.stored_status = "approved";
    return { body: list };
  }
  if (url.pathname === "/control/v1/exports") {
    const list = exportListFixture("mine");
    list.items = [exportListItemFixture("ready")];
    return { body: list };
  }
  if (url.pathname === `/control/v1/evidence-access-requests/${ACCESS_ID}`)
    return { body: accessInspectionFixture("approved") };
  if (url.pathname === `/control/v1/exports/${EXPORT_ID}`) return { body: exportFixture("ready") };
  return undefined;
};

async function open(page: Page, path: string, override?: Override) {
  await mockWork(page, override);
  await signIn(page, path);
}

for (const scheme of ["light", "dark"] as const) {
  test.describe(`work accessibility (${scheme})`, () => {
    test.use({ colorScheme: scheme });

    test("case list with data and the create dialog", async ({ page }) => {
      await open(page, "/cases");
      await expect(page.getByRole("link", { name: "核对合成请求的证据引用" })).toBeVisible();
      expect(await serious(page)).toEqual([]);
      await page.getByRole("button", { name: "新建案件", exact: true }).click();
      await expect(page.getByRole("dialog", { name: "新建案件" })).toBeVisible();
      expect(await serious(page)).toEqual([]);
    });

    for (const [tab, wait] of [
      ["evidence", "证据集合"],
      ["access", "访问申请"],
      ["holds", "保留锁"],
      ["exports", "导出"],
      ["analysis", "分析任务"],
    ] as const) {
      test(`case detail, ${tab} tab`, async ({ page }) => {
        await open(page, `/cases/${CASE_ID}/${tab}`);
        await expect(page.getByRole("tab", { name: wait, selected: true })).toBeVisible();
        // Every tab reads on opening; wait until its first reply is on screen.
        await expect(page.getByRole("progressbar")).toHaveCount(0);
        await page.waitForTimeout(300);
        expect(await serious(page)).toEqual([]);
      });
    }

    test("approval center with a selected access request", async ({ page }) => {
      await open(page, "/approvals");
      await page.getByRole("button", { name: `处理 ${ACCESS_ID}` }).click();
      const pane = page.getByRole("region", { name: "审批详情" });
      await expect(pane.getByLabel("审批理由")).toBeVisible();
      expect(await serious(page)).toEqual([]);
    });

    test("approval center with a selected export and a policy revision", async ({ page }) => {
      await open(page, "/approvals");
      await page.getByRole("button", { name: `处理 ${EXPORT_ID}` }).click();
      await expect(
        page.getByRole("region", { name: "审批详情" }).getByLabel("审批理由"),
      ).toBeVisible();
      expect(await serious(page)).toEqual([]);
      await page.getByRole("button", { name: "查看 site_alpha" }).click();
      await expect(page.getByRole("link", { name: "前往站点发布页审阅并决定" })).toBeVisible();
      expect(await serious(page)).toEqual([]);
    });

    test("approval center, my requests with a download panel", async ({ page }) => {
      await open(page, "/approvals/mine", mine);
      await page
        .getByRole("row")
        .filter({ hasText: "已批准" })
        .getByRole("button", { name: /^查看并下载/ })
        .click();
      await expect(page.getByRole("button", { name: "下载原文（.bin）" })).toBeVisible();
      expect(await serious(page)).toEqual([]);
    });

    test("approval center on a phone, with the detail drawer open", async ({ page }) => {
      await page.setViewportSize({ width: 390, height: 844 });
      await open(page, "/approvals");
      await page.getByRole("button", { name: `处理 ${ACCESS_ID}` }).click();
      const drawer = page.getByRole("dialog", { name: "原文访问申请" });
      await expect(drawer.getByLabel("审批理由")).toBeVisible();
      await page.waitForTimeout(400);
      expect(await serious(page)).toEqual([]);
    });
  });
}
