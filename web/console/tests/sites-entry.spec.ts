// Registering an entry from one request (docs/06 6.4.10, flow A): the quick rule dialog opens from a request with no
// session record, shows the candidate rules and their impact, saves a new version, and the site lists the entry.

import { expect, type Page, test } from "@playwright/test";
import { setTheme, type Theme } from "./helpers/axe.ts";
import { FIXTURE_NOW_MS, mockApi } from "./helpers/mock-api.ts";
import { callsTo, expectDialogNoAxeViolations, freezeClock } from "./helpers/sites-flow.ts";

/** juice, GET /rest/admin/application-configuration, no session: the page the SPA asks for before login. */
const NO_SESSION = "req_01a1971fb50073a59298767186c1a22f";
/** emr, GET /api/patients/7, with a session: it must not offer the entry action. */
const WITH_SESSION = "req_01a19743ded079f89fa9c4b66aa44e9b";
const DIALOG = "登记为入口 · juice";
const PATH = "/rest/admin/application-configuration";

/** The row menu of a request in the list (the ⋯ button names the request). */
async function openRowMenu(page: Page, requestId: string): Promise<void> {
  await page.getByRole("button", { name: `操作：${requestId}` }).click();
}

test("registering an entry from the request list saves the rule and the site lists it", async ({
  page,
}) => {
  await freezeClock(page);
  await mockApi(page);
  await page.goto("/requests");

  await openRowMenu(page, NO_SESSION);
  await page.getByRole("menuitem", { name: "登记为入口…" }).click();

  const dialog = page.getByRole("dialog", { name: DIALOG });
  await expect(dialog.getByRole("radio", { name: /精确路径/ })).toBeChecked();
  await expect(dialog.getByRole("radio", { name: /父路径前缀/ })).not.toBeChecked();
  await expect(dialog).toContainText(`改动：entries ＋ ${PATH}`);
  await expect(dialog).toContainText("影响（最近 24 小时，548 条记录）");
  await expect(dialog.getByText("无会话请求改为按入口判定")).toBeVisible();
  await expect(dialog.getByText("312", { exact: true })).toBeVisible();
  await expect(dialog.getByRole("textbox", { name: "备注" })).toHaveValue(
    `从请求 …${NO_SESSION.slice(-8)} 登记为入口`,
  );

  await dialog.getByRole("button", { name: "保存为 v8" }).click();

  await expect(dialog.getByRole("status")).toHaveText("● v8 已生效");
  const [saved] = callsTo(page, "PUT", "/api/sites/juice");
  expect(saved?.body).toMatchObject({
    expected_version: 7,
    note: `从请求 …${NO_SESSION.slice(-8)} 登记为入口`,
    spec: {
      entries: ["/rest/user/login", "/api/Products", "/rest/products/search", PATH],
    },
  });

  await dialog.getByRole("link", { name: "查看变更历史" }).click();
  await expect(page).toHaveURL(/\/sites\/juice\?tab=history/);
  await expect(page.getByRole("table", { name: "版本历史" })).toContainText(`入口 ＋1：${PATH}`);

  await page.goto("/sites/juice?tab=config&group=entries");
  await expect(page.getByRole("list", { name: "入口" })).toContainText(PATH);
});

test("registering an entry from the request detail can take the prefix candidate", async ({
  page,
}) => {
  await freezeClock(page);
  await mockApi(page);
  await page.goto(`/requests/${NO_SESSION}`);

  await page
    .getByRole("complementary", { name: "相关" })
    .getByRole("button", { name: "登记为入口…" })
    .click();

  const dialog = page.getByRole("dialog", { name: DIALOG });
  await dialog.getByRole("radio", { name: /父路径前缀/ }).check();
  await expect(dialog).toContainText("改动：entries ＋ /rest/admin/*");
  await expect(dialog).toContainText("前缀入口会放大无会话可达的范围");

  await dialog.getByRole("button", { name: "保存为 v8" }).click();

  await expect(dialog.getByRole("status")).toHaveText("● v8 已生效");
  const [saved] = callsTo(page, "PUT", "/api/sites/juice");
  expect(saved?.body).toMatchObject({
    spec: { entries: expect.arrayContaining(["/rest/admin/*"]) },
  });
});

test("cancelling the entry dialog saves nothing", async ({ page }) => {
  await freezeClock(page);
  await mockApi(page);
  await page.goto("/requests");

  await openRowMenu(page, NO_SESSION);
  await page.getByRole("menuitem", { name: "登记为入口…" }).click();
  const dialog = page.getByRole("dialog", { name: DIALOG });
  await dialog.getByRole("button", { name: "取消" }).click();

  await expect(dialog).toBeHidden();
  expect(callsTo(page, "PUT", "/api/sites/juice")).toHaveLength(0);
});

test("a request that carries a session offers no entry action", async ({ page }) => {
  await freezeClock(page);
  await mockApi(page);
  await page.goto("/requests");

  await openRowMenu(page, WITH_SESSION);

  await expect(page.getByRole("menuitem", { name: "复制请求 ID" })).toBeVisible();
  await expect(page.getByRole("menuitem", { name: "登记为入口…" })).toHaveCount(0);
});

test("while the gateways have not loaded the new version, the dialog says it is waiting", async ({
  page,
}) => {
  await freezeClock(page);
  await mockApi(page, { gatewaysLoadSaved: false });
  await page.goto("/requests");

  await openRowMenu(page, NO_SESSION);
  await page.getByRole("menuitem", { name: "登记为入口…" }).click();
  const dialog = page.getByRole("dialog", { name: DIALOG });
  await dialog.getByRole("button", { name: "保存为 v8" }).click();

  await expect(dialog.getByRole("status")).toHaveText("已保存 v8 · 等待网关加载…");
  await expect(dialog.getByRole("status")).not.toContainText("已生效");
});

test("once the gateways load the rule, the dialog offers the requests on this path after the change", async ({
  page,
}) => {
  await freezeClock(page);
  await mockApi(page);
  await page.goto("/requests");

  await openRowMenu(page, NO_SESSION);
  await page.getByRole("menuitem", { name: "登记为入口…" }).click();
  const dialog = page.getByRole("dialog", { name: DIALOG });
  await dialog.getByRole("button", { name: "保存为 v8" }).click();
  await expect(dialog.getByRole("status")).toHaveText("● v8 已生效");

  await dialog.getByRole("link", { name: "查看这个路径之后的请求" }).click();

  // The requests of this path from the save on: the site, the rule's path, and a window that starts at the save.
  await expect(page).toHaveURL(
    (url) =>
      url.pathname === "/requests" &&
      url.searchParams.get("site") === "juice" &&
      url.searchParams.get("q") === `path:${PATH}` &&
      url.searchParams.get("range") === "custom" &&
      url.searchParams.get("since") === String(FIXTURE_NOW_MS),
  );
});

for (const theme of ["light", "dark"] satisfies Theme[]) {
  test(`the entry dialog passes axe in the ${theme} theme`, async ({ page }) => {
    await freezeClock(page);
    await mockApi(page);
    await setTheme(page, theme);
    await page.goto("/requests");

    await openRowMenu(page, NO_SESSION);
    await page.getByRole("menuitem", { name: "登记为入口…" }).click();
    const dialog = page.getByRole("dialog", { name: DIALOG });
    await expect(dialog).toContainText("影响（最近 24 小时");
    await expectDialogNoAxeViolations(page);

    // The saved state adds the link to the path's requests once the gateways have loaded the rule.
    await dialog.getByRole("button", { name: "保存为 v8" }).click();
    await expect(dialog.getByRole("link", { name: "查看这个路径之后的请求" })).toBeVisible();
    await expectDialogNoAxeViolations(page);
  });
}
