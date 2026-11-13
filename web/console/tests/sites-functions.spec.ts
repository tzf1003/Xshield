// The function view of the object map (docs/06 6.4.10, docs/07 7.9.18 to 7.9.20): the three blocks of the table, the
// candidates picked by default, the confirmation that sends one batch, the dismissal, the holds on a draft, the switch
// with its estimate, and the states of the list. The mock records every call the page makes, so each write is checked as
// the gateway receives it, and loading the view is checked to write nothing.

import { expect, type Page, test } from "@playwright/test";
import { type MockOptions, mockApi, reply, servedRequests } from "./helpers/mock-api.ts";
import { siteEmr, siteFunctions } from "./helpers/fixtures.ts";
import { callsTo, freezeClock } from "./helpers/sites-flow.ts";
import { expectNoAxeViolations } from "./helpers/axe.ts";
import type { SiteDetail, SiteFunctions } from "../src/api/types.ts";

const FUNCTIONS = "/api/sites/emr/objects/functions";
const CHANGES = "/api/sites/emr/objects/functions/changes";
const DISMISS = "/api/sites/emr/objects/functions/proposals/dismiss";
const VIEW = "/sites/emr?tab=objects&view=functions";

async function openView(page: Page, options: MockOptions = {}, path = VIEW): Promise<void> {
  await freezeClock(page);
  await mockApi(page, {
    ...options,
    overrides: {
      [`GET ${FUNCTIONS}`]: siteFunctions,
      "GET /api/sites/emr": emrWithTable(),
      [`POST ${CHANGES}`]: reply(204),
      [`POST ${DISMISS}`]: reply(204),
      ...options.overrides,
    },
  });
  await page.goto(path);
  // The tab's label counts the proposals, so it reads just "功能" when there are none.
  await expect(page.getByRole("radio", { name: /^功能( \d+)?$/ })).toBeChecked();
}

/**
 * emr's saved configuration holds the table's functions (docs/07 7.9.20). The fixture's configuration has no function
 * list, so the two entries of the table are written into it here; the fixture itself stays as the other specs read it.
 */
function emrWithTable(): SiteDetail {
  const emr = structuredClone(siteEmr);
  emr.spec.objects = {
    ...emr.spec.objects,
    functions: [
      { key: "POST /api/admin/export", source: "rule", tier: "admin", reliability: "high" },
      { key: "GET /api/products/{id}", source: "admin" },
    ],
  };
  return emr;
}

/** The function table of emr with the given changes to the sample. */
function withSample(changes: Partial<SiteFunctions>): SiteFunctions {
  return { ...structuredClone(siteFunctions), ...changes };
}

/** Drops the default pick, so the table has no pending change and the switch can move (plan 2.5). */
async function dropDefaultPick(page: Page): Promise<void> {
  await page.getByRole("checkbox", { name: "加入功能表 GET /api/reports/{id}" }).uncheck();
}

test("the functions view lists the table, the candidates and the proposals", async ({ page }) => {
  await openView(page);

  await expect(page.getByRole("table", { name: "功能表 2" }).locator("tbody tr")).toHaveCount(2);
  await expect(page.getByRole("table", { name: "候选 3" }).locator("tbody tr")).toHaveCount(3);
  await expect(page.locator(".obj-fn-proposals .obj-judge-row")).toHaveCount(2);
  // The position view's counters and search are not on this view.
  await expect(page.locator("fieldset.chips")).toHaveCount(0);
  await expect(page.getByRole("searchbox")).toHaveCount(0);
});

test("the suggested candidates are picked, the sensitive ones are not", async ({ page }) => {
  await openView(page);

  await expect(
    page.getByRole("checkbox", { name: "加入功能表 GET /api/reports/{id}" }),
  ).toBeChecked();
  await expect(
    page.getByRole("checkbox", { name: "加入功能表 GET /api/admin/reports" }),
  ).not.toBeChecked();
  await expect(
    page.getByRole("checkbox", { name: "加入功能表 GET /api/system/metrics" }),
  ).not.toBeChecked();
  await expect(page.getByRole("row").filter({ hasText: "GET /api/admin/reports" })).toContainText(
    "名字敏感",
  );
});

test("loading and refreshing the view sends no write", async ({ page }) => {
  await openView(page);
  await expect(
    page.getByRole("checkbox", { name: "加入功能表 GET /api/reports/{id}" }),
  ).toBeChecked();

  expect(callsTo(page, "POST", CHANGES)).toHaveLength(0);
  expect(callsTo(page, "POST", DISMISS)).toHaveLength(0);
  expect(servedRequests(page).filter((call) => call.method !== "GET")).toHaveLength(0);
});

test("confirming posts one change with what was picked", async ({ page }) => {
  await openView(page);

  await page.getByRole("checkbox", { name: "确认为管理档 POST /api/orders/{id}/refund" }).check();
  await page.getByRole("button", { name: "确认变更…" }).click();
  const dialog = page.getByRole("dialog", { name: "确认功能表的变更？" });
  await expect(dialog).toContainText("加入 1 个已知功能");
  await expect(dialog).toContainText("确认 1 个管理档");
  await dialog.getByRole("button", { name: "确认并保存版本" }).click();

  await expect(page.getByText("已确认。站点保存了一个新版本。")).toBeVisible();
  const sent = callsTo(page, "POST", CHANGES);
  expect(sent).toHaveLength(1);
  expect(sent[0]?.body).toEqual({
    add: ["GET /api/reports/{id}"],
    admin: [{ key: "POST /api/orders/{id}/refund", reliability: "high" }],
  });
  await expect(page.getByText("待确认：加入 0 · 管理档 0 · 取消管理档 0 · 删除 0")).toBeVisible();
});

test("a proposal is dismissed at once", async ({ page }) => {
  await openView(page);

  await page.getByRole("button", { name: "驳回 DELETE /api/users/{id}" }).click();

  await expect(page.getByText("已驳回，同一提议不再出现，除非证据得出另一个结论。")).toBeVisible();
  const sent = callsTo(page, "POST", DISMISS);
  expect(sent).toHaveLength(1);
  expect(sent[0]?.body).toEqual({ key: "DELETE /api/users/{id}" });
});

test("a draft with changes of its own holds the confirmation back, and dismissing stays open", async ({
  page,
}) => {
  await openView(page);

  // The switch waits for the default pick to go, then changes the draft; closing the save dialog keeps the draft.
  await dropDefaultPick(page);
  await page.getByRole("switch", { name: "未知功能交 Jev" }).click();
  const save = page.getByRole("dialog", { name: "保存 emr 的配置" });
  await expect(save).toBeVisible();
  await save.getByRole("button", { name: "取消" }).click();

  await page.getByRole("checkbox", { name: "确认为管理档 POST /api/orders/{id}/refund" }).check();
  await expect(page.getByRole("button", { name: "确认变更…" })).toBeDisabled();
  await expect(page.getByText("草稿里有未保存的改动。先保存或放弃，再确认")).toBeVisible();
  await expect(page.getByRole("button", { name: "驳回" }).first()).toBeEnabled();
});

test("a refused change says why and keeps the rest picked", async ({ page }) => {
  await openView(page, {
    overrides: {
      [`POST ${CHANGES}`]: reply(409, { error: "FUNCTION_CHANGED", field: "remove[0]" }),
    },
  });

  await page.getByRole("button", { name: "删除 POST /api/admin/export" }).click();
  await page.getByRole("button", { name: "确认变更…" }).click();
  await page
    .getByRole("dialog", { name: "确认功能表的变更？" })
    .getByRole("button", { name: "确认并保存版本" })
    .click();

  await expect(
    page.getByText("功能表已经变了，列表已刷新，请再确认一次：POST /api/admin/export"),
  ).toBeVisible();
  // The list was read again, and the other pick is still there.
  expect(callsTo(page, "GET", FUNCTIONS).length).toBeGreaterThanOrEqual(2);
  await expect(
    page.getByRole("checkbox", { name: "加入功能表 GET /api/reports/{id}" }),
  ).toBeChecked();
  await expect(page.getByRole("button", { name: "删除 POST /api/admin/export" })).toHaveAttribute(
    "aria-pressed",
    "true",
  );
});

test("the switch states its impact and goes through the save dialog", async ({ page }) => {
  await openView(page);

  // 407 requests of the candidates, 55 of the unlearned paths and 2 unkeyed ones: 464 in all.
  await expect(page.getByText("功能不在功能表里的有 464 个")).toBeVisible();
  await expect(page.getByText("3 个候选功能上 407 个，没学到的路径上 55 个")).toBeVisible();
  await expect(page.getByRole("switch", { name: "未知功能交 Jev" })).not.toBeChecked();
  // The default pick is a pending change, and the switch waits for it (plan 2.5).
  await expect(page.getByRole("switch", { name: "未知功能交 Jev" })).toBeDisabled();
  await expect(page.getByText("先确认或放弃上面的变更。")).toBeVisible();

  await dropDefaultPick(page);
  await page.getByRole("switch", { name: "未知功能交 Jev" }).click();
  const save = page.getByRole("dialog", { name: "保存 emr 的配置" });
  await expect(save).toContainText("功能表 未知功能送 Jev 判定 关 → 开");
});

test("a site with an empty table cannot switch the unknown functions on", async ({ page }) => {
  await openView(page, {}, "/sites/juice?tab=objects&view=functions");

  await expect(page.getByRole("switch", { name: "未知功能交 Jev" })).toBeDisabled();
  await expect(page.getByText("功能表为空时不能打开。先确认候选。")).toBeVisible();
});

test("the over-limit state shows its warning and no candidates", async ({ page }) => {
  await openView(page, {
    overrides: {
      [`GET ${FUNCTIONS}`]: withSample({
        status: "over_limit",
        candidates: [],
        proposals: [],
        functions: [],
      }),
    },
  });

  await expect(page.getByText("功能键超过上限，学习这一轮没有判断")).toBeVisible();
  await expect(page.getByRole("table", { name: /^候选/ })).toHaveCount(0);
});

test("the functions view has no accessibility violations", async ({ page }) => {
  await openView(page);
  await expectNoAxeViolations(page);
});
