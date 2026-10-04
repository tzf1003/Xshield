import { expect, type Page, test } from "@playwright/test";
import { errorFixture, REQUEST_ID } from "./fixtures";
import { mockShellApi, SCOPE, signIn } from "./shell-helpers";

const AT = "2026-09-20T08:10:30.000Z";

function item(id: string, name: string, over: Record<string, unknown> = {}) {
  return {
    site_id: id,
    display_name: name,
    public_origin: `https://${id}.example.test`,
    listen_port: 6100,
    security_entry: "ui_action_required",
    sensor_enabled: false,
    policy_revision: "policy-v1",
    status: "active",
    revision: 3,
    config_digest: "a".repeat(64),
    updated_by: "author@example.test",
    updated_at: AT,
    desired_revision: 3,
    active_revision: 3,
    apply_id: "apply_fixture",
    apply_state: "active",
    reason_code: "EDGE_APPLY_CONFIRMED",
    requires_approval: false,
    ...over,
  };
}

const firstPage = {
  request_id: REQUEST_ID,
  ...SCOPE,
  truncated: true,
  next_cursor: "v1.site_cursor.page-two",
  sites: [
    item("site_alpha", "Alpha 官网"),
    item("site_beta", "Beta 商城", {
      apply_state: "pending",
      requires_approval: true,
      desired_revision: 5,
      active_revision: 4,
    }),
    item("site_gamma", "Gamma 支付", { apply_state: "failed", reason_code: "EDGE_UNAVAILABLE" }),
    item("site_delta", "Delta 草稿", {
      status: "draft",
      apply_state: "pending",
      active_revision: null,
      desired_revision: 1,
    }),
  ],
};
const secondPage = {
  request_id: REQUEST_ID,
  ...SCOPE,
  truncated: false,
  next_cursor: null,
  // site_beta repeats on purpose: pages that overlap must not list a site twice.
  sites: [item("site_beta", "Beta 商城"), item("site_omega", "Omega 终点站")],
};

async function openList(page: Page, requests: string[] = []) {
  await mockShellApi(page, (url, method) => {
    if (url.pathname !== "/control/v1/sites" || method !== "GET") return undefined;
    requests.push(url.search);
    return { body: url.searchParams.get("cursor") ? secondPage : firstPage };
  });
  await signIn(page, "/sites");
  await expect(page.getByRole("link", { name: "Alpha 官网", exact: true })).toBeVisible();
}

const rows = (page: Page) => page.getByRole("row").filter({ has: page.getByRole("link") });

test("the summary and the status chips describe only the rows that are loaded", async ({
  page,
}) => {
  await openList(page);
  const summary = page.getByRole("region", { name: "已加载站点统计" });
  await expect(summary).toContainText("统计基于已加载的 4 个站点，还有更多未加载");
  await expect(summary.getByText("已生效", { exact: true })).toBeVisible();
  await expect(rows(page)).toHaveCount(4);
  await page.getByRole("button", { name: /^待审批 1$/ }).click();
  await expect(rows(page)).toHaveCount(1);
  await expect(rows(page).first()).toContainText("Beta 商城");
  await expect(rows(page).first()).toContainText("desired r5 · active r4");
  await page.getByRole("button", { name: /^全部 4$/ }).click();
  await expect(rows(page)).toHaveCount(4);
});

test("search looks at loaded rows, says so, and offers to clear when nothing matches", async ({
  page,
}) => {
  await openList(page);
  const search = page.getByRole("textbox", { name: "搜索已加载的站点" });
  await search.fill("gamma");
  await expect(rows(page)).toHaveCount(1);
  await search.fill("omega");
  await expect(page.getByText("没有符合条件的已加载站点")).toBeVisible();
  await expect(page.getByText("还有未加载的站点：先点击“加载更多”再继续搜索。")).toBeVisible();
  await page.getByRole("button", { name: "清除搜索与筛选" }).click();
  await expect(rows(page)).toHaveCount(4);
});

test("加载更多 sends the signed cursor untouched and never lists a site twice", async ({
  page,
}) => {
  const requests: string[] = [];
  await openList(page, requests);
  // The dev server runs React StrictMode, which may read the first page twice; production does not.
  expect(requests.every((search) => search === "?limit=100")).toBe(true);
  await page.getByRole("button", { name: "加载更多" }).click();
  await expect(page.getByRole("link", { name: "Omega 终点站" })).toBeVisible();
  expect(requests.filter((search) => search.includes("cursor="))).toEqual([
    "?limit=100&cursor=v1.site_cursor.page-two",
  ]);
  await expect(rows(page)).toHaveCount(5);
  await expect(page.getByRole("button", { name: "加载更多" })).toHaveCount(0);
  await expect(page.getByRole("region", { name: "已加载站点统计" })).toContainText(
    "统计基于已加载的 5 个站点（已加载全部）",
  );
  // The search now reaches the page that was loaded last.
  await page.getByRole("textbox", { name: "搜索已加载的站点" }).fill("omega");
  await expect(rows(page)).toHaveCount(1);
});

test("刷新 starts over from the first page instead of replaying cursors", async ({ page }) => {
  const requests: string[] = [];
  await openList(page, requests);
  await page.getByRole("button", { name: "加载更多" }).click();
  await expect(rows(page)).toHaveCount(5);
  const before = requests.length;
  await page.getByRole("button", { name: "刷新", exact: true }).click();
  await expect(rows(page)).toHaveCount(4);
  // One read of the first page; the cursor of the loaded second page is not replayed.
  expect(requests.slice(before)).toEqual(["?limit=100"]);
});

test("a row opens its site, from the name link and from anywhere in the row", async ({ page }) => {
  await openList(page);
  // The row, not only its link, is the target.
  await page
    .getByRole("row", { name: /Gamma 支付/ })
    .getByText("6100")
    .click();
  await expect(page).toHaveURL(/sites\/site_gamma\/overview$/);
});

test("a failure keeps its stable code and request ID and never looks like an empty list", async ({
  page,
}) => {
  await mockShellApi(page, (url) =>
    url.pathname === "/control/v1/sites"
      ? { status: 503, body: errorFixture("CONTROL_SITE_CONFIG_UNAVAILABLE") }
      : undefined,
  );
  await signIn(page, "/sites");
  const alert = page.getByRole("alert");
  await expect(alert).toContainText("站点配置存储暂时不可用");
  await expect(alert).toContainText("建议：");
  await expect(alert).toContainText("CONTROL_SITE_CONFIG_UNAVAILABLE");
  await expect(alert).toContainText("HTTP 503");
  await expect(alert).toContainText(errorFixture("X").request_id);
  await expect(page.getByText("暂无受保护站点")).toHaveCount(0);
  await expect(page.getByRole("table")).toHaveCount(0);
});

test("a permission denial is its own state", async ({ page }) => {
  await mockShellApi(page, (url) =>
    url.pathname === "/control/v1/sites"
      ? { status: 403, body: errorFixture("CONTROL_SCOPE_DENIED") }
      : undefined,
  );
  await signIn(page, "/sites");
  await expect(page.getByRole("alert")).toContainText("没有这个站点操作的权限");
  await expect(page.getByRole("alert")).toContainText("CONTROL_SCOPE_DENIED");
  await expect(page.getByText("暂无受保护站点")).toHaveCount(0);
});

test("the list fits a 390 px screen without scrolling the page sideways", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await openList(page);
  await expect(page.getByText("desired r5 · active r4")).toBeVisible();
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  expect(overflow).toBeLessThanOrEqual(0);
});
