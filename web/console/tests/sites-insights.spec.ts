// The two tuning suggestions of design 5 (docs/06 6.4.9, docs/07 7.9.11): the proposals waiting in the object table,
// and a gateway path whose interface name sits in the body. Each card says what it found and links to the page that
// makes the change. Its figures come with the suggestion when the backend sends them; without them the card shows
// the count alone.

import { expect, type Page, test } from "@playwright/test";
import type { Insights } from "../src/api/types.ts";
import { expectNoAxeViolations, setTheme, type Theme } from "./helpers/axe.ts";
import { insights } from "./helpers/fixtures.ts";
import { mockApi } from "./helpers/mock-api.ts";
import { freezeClock } from "./helpers/sites-flow.ts";

const GATEWAY = "/weixin/wx/mp/wx361163d21a65f679/gateway";

/** The fixture with the figures a backend that counts them sends for the two cards. */
function insightsWithFigures(): Insights {
  const next = structuredClone(insights);
  for (const item of next.suggestions) {
    if (item.kind === "object_proposals") {
      item.detail = {
        jev_calls_saved_per_day: 42,
        top: [
          "attachments[].doc_id 在 /api/records/{id} 归为文档，14 次",
          "patient_no 归为患者，9 次",
          "doctor_id 归为医生，6 次",
          "owner 归为医生，2 次",
        ],
      };
    }
    if (item.kind === "route_rule_candidate") {
      item.detail = { share: 0.94, field: "method", values: 3 };
    }
  }
  return next;
}

async function openInsights(page: Page, overrides: Record<string, unknown> = {}): Promise<void> {
  await freezeClock(page);
  await mockApi(page, { overrides });
  await page.goto("/sites/juice?tab=insights");
  await expect(page.getByRole("region", { name: "登记入口" })).toBeVisible();
}

test("对象表待确认和可能是统一网关各自成组，写出它们找到的内容", async ({ page }) => {
  await openInsights(page);

  await expect(page.getByRole("region", { name: "对象表待确认" })).toContainText(
    "对象表有 7 条待确认",
  );
  await expect(page.getByRole("region", { name: "可能是统一网关" })).toContainText(
    `${GATEWAY} 有 9,812 次请求`,
  );
});

test("没有附带数字时，两张卡只写条数和次数，不写 Jev 的估计", async ({ page }) => {
  await openInsights(page);

  const objects = page.getByRole("region", { name: "对象表待确认" });
  await expect(objects).not.toContainText("每天少调用");
  await expect(objects.getByRole("list", { name: "待确认的前 3 条" })).toHaveCount(0);
  await expect(page.getByRole("region", { name: "可能是统一网关" })).not.toContainText("占本站点");
});

test("对象表待确认写出待确认数和每天少调用的次数，并列出前三条", async ({ page }) => {
  await openInsights(page, { "/api/sites/juice/insights": insightsWithFigures() });

  const objects = page.getByRole("region", { name: "对象表待确认" });
  await expect(objects).toContainText("对象表有 7 条待确认，确认后预计每天少调用 Jev 42 次");
  const top = objects.getByRole("list", { name: "待确认的前 3 条" });
  await expect(top.getByRole("listitem")).toHaveCount(3);
  await expect(top).toContainText("attachments[].doc_id 在 /api/records/{id} 归为文档，14 次");
  await expect(top).not.toContainText("owner");
});

test("可能是统一网关写出路径占本站点的比例，以及正文字段的取值数", async ({ page }) => {
  await openInsights(page, { "/api/sites/juice/insights": insightsWithFigures() });

  await expect(page.getByRole("region", { name: "可能是统一网关" })).toContainText(
    `${GATEWAY} 占本站点 94% 的请求，正文字段 method 有 3 种取值`,
  );
});

test("两张卡的按钮分别链到对象表的待确认页签，和这条路径的接口名规则", async ({ page }) => {
  await openInsights(page);

  await expect(page.getByRole("link", { name: "前往对象表" })).toHaveAttribute(
    "href",
    "/sites/juice?tab=objects&state=proposed",
  );
  await expect(page.getByRole("link", { name: "写接口名规则…" })).toHaveAttribute(
    "href",
    `/sites/juice?tab=config&route=${encodeURIComponent(GATEWAY)}`,
  );
});

test("点击前往对象表在应用内打开，不重新载入页面", async ({ page }) => {
  await openInsights(page);

  await page.evaluate(() => {
    document.documentElement.dataset.mark = "kept";
  });
  await page.getByRole("link", { name: "前往对象表" }).click();
  // The address keeps the state of the proposals. The tab itself is named by the link's address, checked above: the
  // object table's tab is added with the object table, and a site page without it drops the tab from the address.
  await expect(page).toHaveURL(/\/sites\/juice\?(?:.*&)?state=proposed$/);
  await expect(page.locator("html")).toHaveAttribute("data-mark", "kept");
});

test("忽略一张卡后它收起，在已忽略里显示后可以恢复", async ({ page }) => {
  await openInsights(page);

  const objects = page.getByRole("region", { name: "对象表待确认" });
  await objects.getByRole("button", { name: "忽略", exact: true }).click();
  await expect(objects).toHaveCount(0);
  await expect(page.getByText("已忽略 1 条")).toBeVisible();

  await page.getByRole("button", { name: "显示", exact: true }).click();
  await page.getByRole("button", { name: "恢复", exact: true }).click();
  await expect(objects).toBeVisible();
});

for (const theme of ["light", "dark"] satisfies Theme[]) {
  test(`两张新卡在 ${theme} 主题下通过 axe 检查`, async ({ page }) => {
    await setTheme(page, theme);
    await openInsights(page, { "/api/sites/juice/insights": insightsWithFigures() });

    await expect(page.getByRole("region", { name: "可能是统一网关" })).toBeVisible();
    await expectNoAxeViolations(page);
  });
}
