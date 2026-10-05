/**
 * The approval center in the machine-login build: one inbox over evidence access requests,
 * exports and site revisions that await a policy decision, each source loaded and failing on its
 * own, a detail pane with the decision form, and the requester's own history.
 */
import { expect, type Page, test } from "@playwright/test";
import {
  ACCESS_ID,
  accessDecisionFixture,
  accessInspectionFixture,
  accessListFixture,
} from "./access-fixtures";
import { exportFixture, exportListFixture, exportListItemFixture } from "./export-fixtures";
import { signIn } from "./shell-helpers";
import {
  apiCalls,
  type Call,
  CASE_ID,
  EXPORT_ID,
  expectQuiet,
  JOB_ID,
  jobBody,
  mockWork,
  type Override,
  refuse,
  sitesPage,
  writes,
} from "./work-helpers";

const sidebar = (page: Page) => page.getByRole("complementary", { name: "后台导航" });
const keyPattern = /^[A-Za-z0-9_.:-]{16,128}$/;
const frozen = (call: Call) => ({
  path: call.path,
  method: call.method,
  key: call.key,
  body: call.body,
});
const row = (page: Page, text: string | RegExp) => page.getByRole("row").filter({ hasText: text });
/** The access-request row: the requester text alone also matches the export row. */
const accessRow = (page: Page) =>
  page.getByRole("row").filter({ has: page.getByRole("button", { name: `处理 ${ACCESS_ID}` }) });

function watch(page: Page): string[] {
  const seen: string[] = [];
  page.on("pageerror", (error) => seen.push(error.message));
  page.on("console", (message) => {
    if (["error", "warning"].includes(message.type())) seen.push(message.text());
  });
  return seen;
}

/** The list pages the approval center reads: both review/mine queues and the site list. */
const listReads = (calls: Call[]) =>
  new Set(
    apiCalls(calls)
      .filter((call) => call.method === "GET")
      .map((call) => call.path)
      .filter((path) =>
        /^\/control\/v1\/(evidence-access-requests|exports)\?view=|^\/control\/v1\/sites\?/.test(
          path,
        ),
      ),
  );

test.describe("待我审批", () => {
  test("loads three sources when the page opens, merges them newest first and types every row", async ({
    page,
  }) => {
    const seen = watch(page);
    const calls = await mockWork(page);
    await signIn(page, "/approvals");
    await expect(page.getByRole("heading", { name: "审批中心", exact: true })).toBeVisible();
    // Nothing was pressed: the three first pages were read because the page opened.
    await expect(row(page, "synthetic-author")).toBeVisible();
    await expect.poll(() => listReads(calls).size).toBe(3);
    expect(listReads(calls)).toEqual(
      new Set([
        "/control/v1/evidence-access-requests?view=review",
        "/control/v1/exports?view=review",
        "/control/v1/sites?limit=100",
      ]),
    );
    const rows = page
      .getByRole("row")
      .filter({ has: page.getByRole("button", { name: /^(处理|查看) / }) });
    await expect(rows).toHaveCount(3);
    // Newest first: the policy revision (09:00), then the access request and the export (08:00).
    await expect(rows.nth(0)).toContainText("策略");
    await expect(rows.nth(0)).toContainText("synthetic-author");
    await expect(rows.nth(0)).toContainText("Alpha 站点");
    await expect(rows.nth(1)).toContainText("原文");
    await expect(rows.nth(1)).toContainText("synthetic-investigator");
    await expect(rows.nth(2)).toContainText("导出");
    // Age is the wait up to the server's observation: 08:00 to 08:01.
    await expect(rows.nth(1)).toContainText("1 分钟");
    await expect(rows.nth(2)).toContainText("1 分钟");
    // Only revisions that require approval are tasks.
    await expect(page.getByText("Beta 站点")).toHaveCount(0);
    expect(writes(calls)).toEqual([]);
    await expectQuiet(page, calls);
    expect(seen).toEqual([]);
  });

  test("an empty inbox says so and explains that nothing refreshes by itself", async ({ page }) => {
    await mockWork(page, (url) => {
      if (url.pathname === "/control/v1/evidence-access-requests")
        return { body: { ...accessListFixture("review"), items: [] } };
      if (url.pathname === "/control/v1/exports")
        return { body: { ...exportListFixture("review"), items: [] } };
      if (url.pathname === "/control/v1/sites") return { body: { ...sitesPage(), sites: [] } };
      return undefined;
    });
    await signIn(page, "/approvals");
    await expect(page.getByText("没有待审批事项")).toBeVisible();
    await expect(page.getByText("点击“刷新待办”重新读取")).toBeVisible();
    await expect(page.getByRole("alert")).toHaveCount(0);
  });

  test("one source failing never hides the others; each failure has its own banner and retry", async ({
    page,
  }) => {
    let exportsFailing = true;
    const calls = await mockWork(page, (url) => {
      if (url.pathname === "/control/v1/exports" && exportsFailing)
        return refuse(503, "CONTROL_EXPORT_STORE_UNAVAILABLE");
      if (url.pathname === "/control/v1/sites") return refuse(403, "CONTROL_SCOPE_DENIED");
      return undefined;
    });
    await signIn(page, "/approvals");
    // The access request is still there.
    await expect(accessRow(page)).toBeVisible();
    const exportBanner = page.getByRole("alert").filter({ hasText: "导出待办读取失败" });
    await expect(exportBanner).toContainText("CONTROL_EXPORT_STORE_UNAVAILABLE");
    await expect(exportBanner).toContainText("HTTP 503");
    const siteBanner = page.getByRole("alert").filter({ hasText: "策略修订读取失败" });
    await expect(siteBanner).toContainText("CONTROL_SCOPE_DENIED");
    // The site list is the only place revisions are discovered, and it needs SystemAdmin.
    await expect(page.getByText("读取站点清单需要 SystemAdmin")).toBeVisible();
    await expect(page.getByRole("alert").filter({ hasText: "原文访问待办读取失败" })).toHaveCount(
      0,
    );
    await expectQuiet(page, calls);
    exportsFailing = false;
    await exportBanner.getByRole("button", { name: "重试" }).click();
    await expect(page.getByRole("button", { name: `处理 ${EXPORT_ID}` })).toBeVisible();
    await expect(page.getByRole("alert").filter({ hasText: "导出待办读取失败" })).toHaveCount(0);
    // The other failure is untouched by that retry.
    await expect(siteBanner).toBeVisible();
  });

  test("when every source fails the banners are all there is, and the table says so", async ({
    page,
  }) => {
    await mockWork(page, (url) =>
      url.pathname === "/control/v1/evidence-access-requests" ||
      url.pathname === "/control/v1/exports" ||
      url.pathname === "/control/v1/sites"
        ? refuse(503, "CONTROL_EVIDENCE_ACCESS_READ_STORE_UNAVAILABLE")
        : undefined,
    );
    await signIn(page, "/approvals");
    await expect(page.getByRole("alert")).toHaveCount(4);
    await expect(page.getByText("没有读取到待办；上方列出了读取失败的来源。")).toBeVisible();
  });

  test("a type filter shows one kind; paging a source is bound to its cursor and filter", async ({
    page,
  }) => {
    const cursor = `v1.${ACCESS_ID}.${"a".repeat(64)}`;
    const earlier = `${ACCESS_ID.slice(0, -2)}40`;
    const calls = await mockWork(page, (url) => {
      if (url.pathname !== "/control/v1/evidence-access-requests") return undefined;
      const list = accessListFixture("review");
      if (url.searchParams.get("cursor") === cursor) {
        const [first] = list.items;
        if (first) first.access_request_id = earlier;
        list.as_of = "2026-09-20T08:02:00.000000Z";
        return { body: list };
      }
      list.truncated = true;
      list.next_cursor = cursor;
      return { body: list };
    });
    await signIn(page, "/approvals");
    await expect(accessRow(page)).toBeVisible();
    // "全部" shows first pages only and says that more exist.
    await expect(page.getByText("还有更多待办未显示")).toBeVisible();
    const filter = page.getByRole("radiogroup", { name: "待办类型筛选" });
    await filter.getByText("原文", { exact: true }).click();
    await expect(page.getByRole("row").filter({ hasText: "策略" })).toHaveCount(0);
    await page.getByRole("button", { name: "下一页" }).click();
    await expect(page.getByRole("button", { name: `处理 ${earlier}` })).toBeVisible();
    expect(apiCalls(calls).at(-1)?.path).toBe(
      `/control/v1/evidence-access-requests?view=review&cursor=${encodeURIComponent(cursor)}`,
    );
    // Editing the filter drops the cursor: the next read is the first page again.
    await filter.getByText("全部", { exact: true }).click();
    await filter.getByText("原文", { exact: true }).click();
    await expect(page.getByText("第 1 页")).toBeVisible();
    await expect(page.getByRole("button", { name: `处理 ${ACCESS_ID}` })).toBeVisible();
  });

  test("a read that finishes after the operator left is never applied", async ({ page }) => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let delayNext = false;
    let delayed = false;
    await mockWork(page, async (url) => {
      if (url.pathname !== "/control/v1/evidence-access-requests" || !delayNext) return undefined;
      delayNext = false;
      delayed = true;
      await gate;
      const list = accessListFixture("review");
      const [first] = list.items;
      if (first) first.requested_by = "STALE-LATE-REQUESTER";
      return { body: list };
    });
    await signIn(page, "/approvals");
    await expect(accessRow(page)).toBeVisible();
    delayNext = true;
    await page.getByRole("button", { name: "刷新待办" }).click();
    await expect.poll(() => delayed).toBe(true);
    await sidebar(page).getByRole("link", { name: "权限中心", exact: true }).click();
    // Release the reply only once the page it was meant for is gone: the address changes first,
    // while the next page's chunk loads, and a reply that lands before then is simply on time.
    await expect(page).toHaveURL(/\/access\/session$/);
    await expect(accessRow(page)).toHaveCount(0);
    release();
    await page.waitForTimeout(300);
    await sidebar(page).getByRole("link", { name: "审批中心", exact: true }).click();
    await expect(accessRow(page)).toBeVisible();
    await expect(page.getByText("STALE-LATE-REQUESTER")).toHaveCount(0);
  });

  test("a reply for another tenant disconnects and shows none of it", async ({ page }) => {
    let armed = false;
    await mockWork(page, (url) => {
      if (url.pathname !== "/control/v1/evidence-access-requests" || !armed) return undefined;
      const list = accessListFixture("review");
      list.tenant_id = "tenant_other";
      const [first] = list.items;
      if (first) first.requested_by = "cross-scope-requester";
      return { body: list };
    });
    await signIn(page, "/approvals");
    await expect(accessRow(page)).toBeVisible();
    armed = true;
    await page.getByRole("button", { name: "刷新待办" }).click();
    await expect(page.getByRole("heading", { name: "连接管理服务" })).toBeVisible();
    await expect(page.getByText("响应范围校验失败，连接已断开。")).toBeVisible();
    await expect(page.getByText("cross-scope-requester")).toHaveCount(0);
  });
});

test.describe("the detail pane and the decision", () => {
  test("selecting a request reads its detail and offers the decision form", async ({ page }) => {
    const calls = await mockWork(page);
    await signIn(page, "/approvals");
    await page.getByRole("button", { name: `处理 ${ACCESS_ID}` }).click();
    await expect(page).toHaveURL(new RegExp(`/approvals\\?item=${ACCESS_ID}$`));
    const pane = page.getByRole("region", { name: "审批详情" });
    await expect(pane).toContainText("synthetic-investigator");
    await expect(pane).toContainText("核查证据内容");
    await expect(pane).toContainText("开放");
    await expect(pane).toContainText("有效");
    await expect(pane.getByRole("button", { name: "批准", exact: true })).toBeDisabled();
    expect(apiCalls(calls).at(-1)?.path).toBe(`/control/v1/evidence-access-requests/${ACCESS_ID}`);
    await pane.getByRole("button", { name: "关闭详情" }).click();
    await expect(page).toHaveURL(/\/approvals$/);
    await expect(pane).toContainText("选择左侧一项");
  });

  test("approves with a lifetime preset capped by the server maximum, a reason and a framework key", async ({
    page,
  }) => {
    const detail = accessInspectionFixture();
    detail.max_approval_ttl_seconds = 3600;
    const calls = await mockWork(page, (url, request) => {
      if (
        url.pathname === `/control/v1/evidence-access-requests/${ACCESS_ID}` &&
        request.method() === "GET"
      )
        return { body: detail };
      if (url.pathname.endsWith("/approve")) return { body: accessDecisionFixture("approved") };
      return undefined;
    });
    await signIn(page, "/approvals");
    await page.getByRole("button", { name: `处理 ${ACCESS_ID}` }).click();
    const pane = page.getByRole("region", { name: "审批详情" });
    const approve = pane.getByRole("button", { name: "批准", exact: true });
    await expect(approve).toBeDisabled();
    // The presets that exceed the server maximum are not offered; the maximum itself is shown.
    await expect(pane.getByText("15 分钟", { exact: true })).toBeVisible();
    await expect(pane.getByText("1 小时", { exact: true })).toBeVisible();
    await expect(pane.getByText("4 小时", { exact: true })).toHaveCount(0);
    await expect(pane).toContainText("服务端上限 1 小时");
    await expect(pane.getByLabel(/幂等键/)).toHaveCount(0);
    await pane.getByLabel("审批理由").fill("已核对案件用途");
    await expect(approve).toBeEnabled();
    await pane.getByText("1 小时", { exact: true }).click();
    await approve.click();
    await expect(page.getByText("已批准访问申请")).toBeVisible();
    const [post] = writes(calls);
    expect(post).toMatchObject({
      path: `/control/v1/evidence-access-requests/${ACCESS_ID}/approve`,
      body: { reason: "已核对案件用途", ttl_seconds: 3600 },
    });
    expect(post?.key).toMatch(keyPattern);
  });

  test("a custom lifetime above the maximum is refused where the operator is typing", async ({
    page,
  }) => {
    const calls = await mockWork(page, (url, request) => {
      if (url.pathname.endsWith(ACCESS_ID) && request.method() === "GET") {
        const detail = accessInspectionFixture();
        detail.max_approval_ttl_seconds = 3600;
        return { body: detail };
      }
      return undefined;
    });
    await signIn(page, "/approvals");
    await page.getByRole("button", { name: `处理 ${ACCESS_ID}` }).click();
    const pane = page.getByRole("region", { name: "审批详情" });
    await pane.getByLabel("审批理由").fill("已核对案件用途");
    await pane.getByText("自定义", { exact: true }).click();
    const seconds = pane.getByRole("spinbutton", { name: "自定义批准期限（秒）" });
    await seconds.fill("7200");
    await expect(pane).toContainText("批准期限最多 3600 秒（服务端上限）");
    await expect(pane.getByRole("button", { name: "批准", exact: true })).toBeDisabled();
    await seconds.fill("1800");
    await expect(pane.getByRole("button", { name: "批准", exact: true })).toBeEnabled();
    expect(writes(calls)).toEqual([]);
  });

  test("denying needs only a reason and sends no lifetime", async ({ page }) => {
    const calls = await mockWork(page);
    await signIn(page, "/approvals");
    await page.getByRole("button", { name: `处理 ${ACCESS_ID}` }).click();
    const pane = page.getByRole("region", { name: "审批详情" });
    const deny = pane.getByRole("button", { name: "拒绝", exact: true });
    await expect(deny).toBeDisabled();
    await pane.getByLabel("审批理由").fill("证据与案件不符");
    await deny.click();
    await expect(page.getByText("已拒绝访问申请")).toBeVisible();
    expect(writes(calls)[0]).toMatchObject({
      path: `/control/v1/evidence-access-requests/${ACCESS_ID}/deny`,
      body: { reason: "证据与案件不符" },
    });
  });

  test("a target that is no longer live can only be denied", async ({ page }) => {
    await mockWork(page, (url, request) => {
      if (url.pathname.endsWith(ACCESS_ID) && request.method() === "GET") {
        const detail = accessInspectionFixture();
        detail.access_request.case_status = "closed";
        detail.access_request.artifact_status = "deleted";
        return { body: detail };
      }
      return undefined;
    });
    await signIn(page, "/approvals");
    await page.getByRole("button", { name: `处理 ${ACCESS_ID}` }).click();
    const pane = page.getByRole("region", { name: "审批详情" });
    await expect(pane).toContainText("目标已失效：案件已关闭、证据已删除");
    await pane.getByLabel("审批理由").fill("案件已关闭，终结申请");
    await expect(pane.getByRole("button", { name: "批准", exact: true })).toBeDisabled();
    await expect(pane.getByRole("button", { name: "拒绝", exact: true })).toBeEnabled();
  });

  test("the server's self-approval refusal is explained and the form stays editable", async ({
    page,
  }) => {
    await mockWork(page, (url, request) =>
      url.pathname.endsWith("/approve") && request.method() === "POST"
        ? refuse(403, "CONTROL_EVIDENCE_ACCESS_SELF_APPROVAL_DENIED")
        : undefined,
    );
    await signIn(page, "/approvals");
    await page.getByRole("button", { name: `处理 ${ACCESS_ID}` }).click();
    const pane = page.getByRole("region", { name: "审批详情" });
    await pane.getByLabel("审批理由").fill("已核对案件用途");
    await pane.getByRole("button", { name: "批准", exact: true }).click();
    const alert = pane
      .getByRole("alert")
      .filter({ hasText: "CONTROL_EVIDENCE_ACCESS_SELF_APPROVAL_DENIED" });
    await expect(alert).toContainText("申请须由另一位具备审批权限的主体处理");
    await expect(alert).toContainText("职责分离");
    await expect(pane.getByLabel("审批理由")).toHaveValue("已核对案件用途");
    expect(await page.evaluate(() => window.__xshieldE2E.runtime.pending.unresolvedCount)).toBe(0);
  });

  test("an unknown decision freezes in the pane: exact retry only, also after selecting another item", async ({
    page,
  }) => {
    let attempts = 0;
    const calls = await mockWork(page, (url, request) => {
      if (!url.pathname.endsWith("/approve") || request.method() !== "POST") return undefined;
      attempts += 1;
      if (attempts === 1) return { abort: "connectionreset" };
      if (attempts === 2) return refuse(409, "CONTROL_EVIDENCE_ACCESS_DECISION_CONFLICT");
      return { body: accessDecisionFixture("approved", true) };
    });
    await signIn(page, "/approvals");
    await page.getByRole("button", { name: `处理 ${ACCESS_ID}` }).click();
    const pane = page.getByRole("region", { name: "审批详情" });
    await pane.getByLabel("审批理由").fill("已核对案件用途");
    await pane.getByRole("button", { name: "批准", exact: true }).click();
    await expect(pane.getByText("结果未知")).toBeVisible();
    await expect(pane.getByLabel("审批理由")).toHaveCount(0);
    await expect(pane.getByRole("button", { name: "拒绝", exact: true })).toHaveCount(0);
    expect(
      await page.evaluate(
        () => !window.dispatchEvent(new Event("beforeunload", { cancelable: true })),
      ),
    ).toBe(true);
    // Look at another item and come back: the frozen decision is still the only way forward.
    await page.getByRole("button", { name: `处理 ${EXPORT_ID}` }).click();
    await expect(pane.getByText("用途", { exact: true })).toBeVisible();
    await page.getByRole("button", { name: `处理 ${ACCESS_ID}` }).click();
    await expect(pane.getByText("结果未知")).toBeVisible();
    await pane.getByRole("button", { name: "原样重试" }).click();
    await expect(pane.getByText("CONTROL_EVIDENCE_ACCESS_DECISION_CONFLICT")).toBeVisible();
    await expect(pane.getByText("结果未知")).toBeVisible();
    await pane.getByRole("button", { name: "原样重试" }).click();
    await expect(page.getByText("已批准访问申请")).toBeVisible();
    const posts = writes(calls);
    expect(posts).toHaveLength(3);
    expect(frozen(posts[1] as Call)).toEqual(frozen(posts[0] as Call));
    expect(frozen(posts[2] as Call)).toEqual(frozen(posts[0] as Call));
  });

  test("an export is decided with a reason alone; both outcomes are explicit", async ({ page }) => {
    const calls = await mockWork(page);
    await signIn(page, "/approvals");
    await page.getByRole("button", { name: `处理 ${EXPORT_ID}` }).click();
    const pane = page.getByRole("region", { name: "审批详情" });
    await expect(pane).toContainText("核对案件元数据");
    await expect(pane).toContainText("最近 2 分钟内的 MFA 再认证");
    await pane.getByLabel("审批理由").fill("独立复核通过");
    await pane.getByRole("button", { name: "批准", exact: true }).click();
    await expect(page.getByText("已批准导出申请")).toBeVisible();
    expect(writes(calls)[0]).toMatchObject({
      path: `/control/v1/exports/${EXPORT_ID}/approve`,
      body: { reason: "独立复核通过" },
    });
  });

  test("a policy revision is only located here; the decision belongs to the site page", async ({
    page,
  }) => {
    const calls = await mockWork(page);
    await signIn(page, "/approvals");
    await page.getByRole("button", { name: "查看 site_alpha" }).click();
    const pane = page.getByRole("region", { name: "审批详情" });
    await expect(pane).toContainText("等待独立审批");
    await expect(pane).toContainText("Alpha 站点");
    await expect(pane).toContainText("审批中心只定位待办，不提交策略决定");
    await expect(pane.getByRole("button", { name: "批准", exact: true })).toHaveCount(0);
    const link = pane.getByRole("link", { name: "前往站点发布页审阅并决定" });
    await expect(link).toHaveAttribute("href", "/sites/site_alpha/releases");
    expect(apiCalls(calls).some((call) => call.path.includes("/approve"))).toBe(false);
    expect(writes(calls)).toEqual([]);
  });

  test("a deep link selects an item that is not on the inbox page", async ({ page }) => {
    const other = `${ACCESS_ID.slice(0, -2)}77`;
    const calls = await mockWork(page, (url) => {
      if (url.pathname === `/control/v1/evidence-access-requests/${other}`) {
        const detail = accessInspectionFixture();
        detail.access_request.access_request_id = other;
        detail.access_request.justification = "来自深链接的申请";
        return { body: detail };
      }
      return undefined;
    });
    await signIn(page, `/approvals?item=${other}`);
    const pane = page.getByRole("region", { name: "审批详情" });
    await expect(pane).toContainText("来自深链接的申请");
    expect(apiCalls(calls).some((call) => call.path.endsWith(other))).toBe(true);
  });

  test("a malformed item in the address selects nothing", async ({ page }) => {
    const calls = await mockWork(page);
    await signIn(page, "/approvals?item=access_not-an-id");
    await expect(accessRow(page)).toBeVisible();
    await expect(page.getByRole("region", { name: "审批详情" })).toContainText("选择左侧一项");
    expect(apiCalls(calls).some((call) => call.path.includes("access_not-an-id"))).toBe(false);
  });
});

test.describe("我的申请", () => {
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
    if (url.pathname === `/control/v1/exports/${EXPORT_ID}`)
      return { body: exportFixture("ready") };
    return undefined;
  };

  test("lists both kinds with their status pills and offers the download where one is possible", async ({
    page,
  }) => {
    const calls = await mockWork(page, mine);
    await signIn(page, "/approvals");
    await page.getByRole("tab", { name: "我的申请" }).click();
    await expect(page).toHaveURL(/\/approvals\/mine$/);
    await expect(row(page, "已批准")).toContainText("原文");
    await expect(row(page, "可下载")).toContainText("导出");
    await expect(row(page, "可下载").getByRole("button", { name: /^查看并下载/ })).toBeVisible();
    await expect(row(page, "已批准").getByRole("button", { name: /^查看并下载/ })).toBeVisible();
    expect(listReads(calls).has("/control/v1/evidence-access-requests?view=mine")).toBe(true);
    expect(listReads(calls).has("/control/v1/exports?view=mine")).toBe(true);
    // The row only selects; the record is read, and nothing is downloaded, until it is asked for.
    expect(apiCalls(calls).some((call) => call.path.endsWith("/download"))).toBe(false);
    await row(page, "已批准")
      .getByRole("button", { name: /^查看并下载/ })
      .click();
    const pane = page.getByRole("region", { name: "申请详情" });
    await expect(pane.getByRole("button", { name: "下载原文（.bin）" })).toBeVisible();
    // My own request never offers a decision.
    await expect(pane.getByRole("button", { name: "批准", exact: true })).toHaveCount(0);
  });

  test("the type filter reads one source and an expired export is shown as expired", async ({
    page,
  }) => {
    await mockWork(page, (url, request, call, count) => {
      if (url.pathname === "/control/v1/exports") {
        const list = exportListFixture("mine");
        const ready = exportListItemFixture("ready");
        ready.expires_at = "2026-09-20T08:10:00.000Z";
        list.items = [ready];
        list.as_of = "2026-09-20T08:30:00.000000Z";
        return { body: list };
      }
      return mine(url, request, call, count);
    });
    await signIn(page, "/approvals/mine");
    await expect(row(page, "已过期")).toContainText("导出");
    await expect(row(page, "已过期").getByRole("button", { name: /^详情/ })).toBeVisible();
    await page
      .getByRole("radiogroup", { name: "申请类型筛选" })
      .getByText("原文", { exact: true })
      .click();
    await expect(row(page, "已过期")).toHaveCount(0);
    await expect(row(page, "已批准")).toBeVisible();
  });
});

test.describe("the navigation badge", () => {
  test("shows what the last read found, refreshes on its own button and never polls", async ({
    page,
  }) => {
    const calls = await mockWork(page);
    // The workbench at "/" reads the review queues itself when it opens, so the badge's
    // "nothing read yet" state is checked from a page that reads nothing.
    await signIn(page, "/access/session");
    const badge = sidebar(page).getByRole("button", { name: /审批待办数量/ });
    await expect(badge).toBeVisible();
    // Before anything was read there is no number, only the offer to read it.
    await expect(badge).toHaveAccessibleName("读取审批待办数量");
    expect(listReads(calls).size).toBe(0);
    await badge.click();
    const counted = sidebar(page).getByRole("button", { name: /^审批待办 3 项/ });
    await expect(counted).toHaveText("3");
    await expect.poll(() => listReads(calls).size).toBe(3);
    await expectQuiet(page, calls, 600);
    // The approval center reuses the pages the badge read (they are cached) and keeps the count.
    await sidebar(page).getByRole("link", { name: "审批中心", exact: true }).click();
    await expect(accessRow(page)).toBeVisible();
    await expect(counted).toHaveText("3");
    // Pressing the badge navigates nowhere.
    await counted.click();
    await expect(page).toHaveURL(/\/approvals$/);
  });

  test("the approval center updates it when it loads, and a partial read is marked as a lower bound", async ({
    page,
  }) => {
    await mockWork(page, (url) =>
      url.pathname === "/control/v1/sites" ? refuse(403, "CONTROL_SCOPE_DENIED") : undefined,
    );
    await signIn(page, "/approvals");
    const badge = sidebar(page).getByRole("button", { name: /^审批待办 2\+ 项（有来源读取失败）/ });
    await expect(badge).toHaveText("2+");
  });

  test("is forgotten when the session ends", async ({ page }) => {
    await mockWork(page);
    await signIn(page, "/approvals");
    await expect(sidebar(page).getByRole("button", { name: /^审批待办 3 项/ })).toBeVisible();
    await page.getByRole("button", { name: "断开连接" }).click();
    await signIn(page, "/");
    await expect(sidebar(page).getByRole("button", { name: "读取审批待办数量" })).toBeVisible();
  });
});

test("the retired access address leaves for the approval center with its hint", async ({
  page,
}) => {
  await mockWork(page);
  await signIn(page, "/evidence/access");
  await expect(page).toHaveURL(/\/approvals\?moved=access$/);
  await expect(page.getByText("“证据访问”已并入审批中心")).toBeVisible();
  await page
    .getByRole("button", { name: /close|关闭/i })
    .first()
    .click();
  await expect(page).toHaveURL(/\/approvals$/);
  await expect(page.getByText("“证据访问”已并入审批中心")).toHaveCount(0);
});

test.describe("layouts", () => {
  test("the detail opens as a drawer on a narrow window, with no horizontal page scroll", async ({
    page,
  }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await mockWork(page);
    await signIn(page, "/approvals");
    const fits = () => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth);
    await expect(accessRow(page)).toBeVisible();
    expect(await fits()).toBe(true);
    await page.getByRole("button", { name: `处理 ${ACCESS_ID}` }).click();
    const drawer = page.getByRole("dialog", { name: "原文访问申请" });
    await expect(drawer.getByLabel("审批理由")).toBeVisible();
    expect(await fits()).toBe(true);
    await drawer.getByRole("button", { name: /^(关闭|Close)$/ }).click();
    await expect(drawer).toHaveCount(0);
    await page.getByRole("tab", { name: "我的申请" }).click();
    expect(await fits()).toBe(true);
  });

  test("a request text is inert", async ({ page }) => {
    const injected = '<img src=x onerror="window.approvalInjected=1">';
    await mockWork(page, (url, request) => {
      if (url.pathname.endsWith(ACCESS_ID) && request.method() === "GET") {
        const detail = accessInspectionFixture();
        detail.access_request.justification = injected;
        detail.access_request.requested_by = injected;
        return { body: detail };
      }
      return undefined;
    });
    await signIn(page, "/approvals");
    await page.getByRole("button", { name: `处理 ${ACCESS_ID}` }).click();
    const pane = page.getByRole("region", { name: "审批详情" });
    await expect(pane.getByText(injected, { exact: true }).first()).toBeVisible();
    await expect(pane.locator("img")).toHaveCount(0);
    expect(await page.evaluate(() => "approvalInjected" in window)).toBe(false);
  });
});

test.describe("command palette targets", () => {
  const palette = (page: Page) => page.getByRole("combobox", { name: "命令面板" });

  test("an access request ID opens the approval center with that request selected", async ({
    page,
  }) => {
    const calls = await mockWork(page);
    await signIn(page, "/");
    await page.keyboard.press("Control+KeyK");
    await palette(page).fill(ACCESS_ID);
    // The event search stays available next to the page, as before.
    await expect(page.getByRole("option")).toHaveText([
      /在事件检索中查找 访问申请 ID/,
      /打开审批中心的该申请/,
    ]);
    await page.getByRole("option", { name: /打开审批中心的该申请/ }).click();
    await expect(page).toHaveURL(new RegExp(`/approvals\\?item=${ACCESS_ID}$`));
    const pane = page.getByRole("region", { name: "审批详情" });
    await expect(pane).toContainText("核查证据内容");
    expect(
      apiCalls(calls).some(
        (call) => call.path === `/control/v1/evidence-access-requests/${ACCESS_ID}`,
      ),
    ).toBe(true);
    expect(writes(calls)).toEqual([]);
  });

  test("an export ID opens the approval center with that export selected", async ({ page }) => {
    await mockWork(page);
    await signIn(page, "/");
    await page.keyboard.press("Control+KeyK");
    await palette(page).fill(EXPORT_ID);
    await expect(page.getByRole("option")).toHaveText([/打开审批中心的该导出/]);
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(new RegExp(`/approvals\\?item=${EXPORT_ID}$`));
    await expect(page.getByRole("region", { name: "审批详情" })).toContainText("核对案件元数据");
  });

  test("a job ID opens a small status dialog over the case list and links to the analysis tab", async ({
    page,
  }) => {
    const calls = await mockWork(page);
    await signIn(page, "/");
    await page.keyboard.press("Control+KeyK");
    await palette(page).fill(JOB_ID);
    await expect(page.getByRole("option")).toHaveText([
      /在事件检索中查找 任务 ID/,
      /打开案件分析任务/,
    ]);
    await page.getByRole("option", { name: /打开案件分析任务/ }).click();
    await expect(page).toHaveURL(new RegExp(`/cases/jobs/${JOB_ID}$`));
    const dialog = page.getByRole("dialog", { name: "案件分析任务" });
    await expect(dialog).toContainText(JOB_ID);
    await expect(dialog).toContainText("引用总数");
    expect(apiCalls(calls).some((call) => call.path === `/control/v1/jobs/${JOB_ID}`)).toBe(true);
    await dialog.getByRole("link", { name: "打开该案件的分析页签" }).click();
    await expect(page).toHaveURL(new RegExp(`/cases/${CASE_ID}/analysis$`));
    await expect(dialog).toHaveCount(0);
  });

  test("a job that is not found says so without hinting whether it exists", async ({ page }) => {
    await mockWork(page, (url) =>
      url.pathname === `/control/v1/jobs/${JOB_ID}`
        ? { body: { ...jobBody(), found: false, job: null } }
        : undefined,
    );
    await signIn(page, `/cases/jobs/${JOB_ID}`);
    const dialog = page.getByRole("dialog", { name: "案件分析任务" });
    await expect(dialog).toContainText("当前主体范围内未找到该任务");
    await dialog.getByRole("button", { name: "关闭", exact: true }).last().click();
    await expect(page).toHaveURL(/\/cases$/);
  });
});
