import { expect, type Page, test } from "@playwright/test";
import { abandoned, type Call, mockControl, paint, requestSettled } from "./control-mock";
import { errorFixture, REQUEST_ID } from "./fixtures";
import { streamFixture, streamRequestId } from "./investigation-fixtures";
import { openView } from "./navigation";
import { signIn } from "./shell-helpers";
import type { SearchPlan } from "../src/search";

const searches = (calls: Call[]) => calls.filter((call) => call.path === "/control/v1/search");
const body = (call: Call | undefined) => call?.body as SearchPlan & { cursor?: string };
const rows = (page: Page) => page.locator(".ant-table-row");
/** An outcome chip (the visible Segmented label; its radio input is visually hidden). */
const chip = (page: Page, label: string) =>
  page.locator("label.ant-segmented-item").filter({ hasText: new RegExp(`^${label}$`) });

/** Signs in on a page that reads nothing, then opens the request list through the navigation. */
async function openStream(page: Page) {
  await signIn(page, "/access/session");
  await openView(page, "request");
}

test("opens with the last hour already loaded as one audited search", async ({ page }) => {
  const calls = await mockControl(page);
  await openStream(page);
  await expect(rows(page)).toHaveCount(25);
  expect(searches(calls)).toHaveLength(1);
  const plan = body(searches(calls)[0]);
  expect(plan).toMatchObject({
    schema_version: 3,
    sort: "occurred_at_desc",
    limit: 25,
    filters: [{ kind: "text", field: "event_type", value: "request.completed" }],
  });
  // Whole-second UTC, exactly one hour, half-open.
  expect(plan.start).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
  expect(plan.end).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
  expect(Date.parse(plan.end) - Date.parse(plan.start)).toBe(3_600_000);
  expect(calls.every((call) => call.method === "POST" || call.path === "/control/v1/search")).toBe(
    true,
  );
  expect(calls[0]?.authorized).toBe(true);
  expect(calls[0]?.cookie).toBeNull();
  await expect(page.getByText("已加载 25 条")).toBeVisible();
  await expect(page.getByRole("heading", { name: "请求调查", exact: true })).toBeVisible();
});

test("reasons read as words, with the raw code kept beside them", async ({ page }) => {
  await mockControl(page);
  await openStream(page);
  await expect(rows(page)).toHaveCount(25);
  const first = rows(page).first();
  await expect(first).toContainText("放行");
  await expect(first).toContainText("公开入口已准入");
  await expect(first.getByText("PUBLIC_ENTRY_ALLOWED", { exact: true })).toBeVisible();
  const denied = rows(page).nth(1);
  await expect(denied).toContainText("拒绝");
  await expect(denied).toContainText("WAF 拦截查询参数");
  await expect(denied.getByText("WAF_QUERY_BLOCKED", { exact: true })).toBeVisible();
  // Local time with the exact UTC instant on the element.
  await expect(first.locator("time")).toHaveAttribute("datetime", /^\d{4}-.*\.\d{3}456Z$/);
  await expect(first).toContainText("84 µs");
});

test("outcome chips and the aborted toggle narrow the search", async ({ page }) => {
  const calls = await mockControl(page);
  await openStream(page);
  await expect(rows(page)).toHaveCount(25);

  await chip(page, "拒绝").click();
  await expect.poll(() => searches(calls).length).toBe(2);
  expect(body(searches(calls)[1]).filters).toEqual([
    { kind: "text", field: "event_type", value: "request.completed" },
    { kind: "outcome", value: "DENY" },
  ]);
  await expect(rows(page).first()).toContainText("拒绝");
  await expect(rows(page).getByText("放行", { exact: true })).toHaveCount(0);

  await chip(page, "放行").click();
  await expect.poll(() => searches(calls).length).toBe(3);
  expect(body(searches(calls)[2]).filters).toEqual([
    { kind: "text", field: "event_type", value: "request.completed" },
    { kind: "outcome", value: "ALLOW" },
  ]);
  await expect(rows(page).getByText("拒绝", { exact: true })).toHaveCount(0);

  // Search has no OR, so aborted requests are their own view. Only they can carry UNKNOWN.
  await expect(chip(page, "未知")).toHaveCount(0);
  await page.getByRole("switch", { name: /中止 \/ 未完成/ }).click();
  await expect.poll(() => searches(calls).length).toBe(4);
  expect(body(searches(calls)[3]).filters).toEqual([
    { kind: "text", field: "event_type", value: "request.aborted" },
    { kind: "outcome", value: "ALLOW" },
  ]);
  await chip(page, "未知").click();
  await expect.poll(() => searches(calls).length).toBe(5);
  expect(body(searches(calls)[4]).filters).toEqual([
    { kind: "text", field: "event_type", value: "request.aborted" },
    { kind: "outcome", value: "UNKNOWN" },
  ]);
  await expect(rows(page).first()).toContainText("请求记录不完整");
  await expect(rows(page).first()).toContainText("未知");
});

test("load more continues the submitted plan and appends the next page", async ({ page }) => {
  const calls = await mockControl(page);
  await openStream(page);
  await expect(rows(page)).toHaveCount(25);
  await page.getByRole("button", { name: "加载更多", exact: true }).click();
  await expect(rows(page)).toHaveCount(40);
  const [first, second] = searches(calls);
  expect(body(first).cursor).toBeUndefined();
  expect(body(second).cursor).toMatch(/^v1\.\d+\.ev_[0-9a-f-]+\.0{64}$/);
  const { cursor: _cursor, ...continued } = body(second);
  expect(continued).toEqual(body(first));
  await expect(page.getByText("已加载 40 条")).toBeVisible();
  await expect(page.getByRole("button", { name: "加载更多", exact: true })).toBeDisabled();
  await expect(page.getByText("当前可见结果已读完")).toBeVisible();
  // The first page is still there: the list grows instead of replacing pages.
  await expect(rows(page).first()).toContainText("PUBLIC_ENTRY_ALLOWED");
  expect(searches(calls)).toHaveLength(2);
});

test("an explicit refresh drops the loaded pages and reads the first one again", async ({
  page,
}) => {
  const calls = await mockControl(page);
  await openStream(page);
  await expect(rows(page)).toHaveCount(25);
  await page.getByRole("button", { name: "加载更多", exact: true }).click();
  await expect(rows(page)).toHaveCount(40);
  await page.getByRole("button", { name: "刷新", exact: true }).click();
  await expect(rows(page)).toHaveCount(25);
  expect(searches(calls)).toHaveLength(3);
  expect(body(searches(calls)[2]).cursor).toBeUndefined();
  await expect(page.getByRole("button", { name: "加载更多", exact: true })).toBeEnabled();
});

test("nothing polls and focus or reconnect never read again", async ({ page }) => {
  await page.clock.install();
  const calls = await mockControl(page);
  await openStream(page);
  await expect(rows(page)).toHaveCount(25);
  await page.clock.fastForward(5 * 60_000);
  await page.evaluate(() => {
    window.dispatchEvent(new Event("focus"));
    document.dispatchEvent(new Event("visibilitychange"));
    window.dispatchEvent(new Event("online"));
  });
  await paint(page);
  expect(searches(calls)).toHaveLength(1);
});

test("more filters add exact conditions; subject references are never echoed", async ({ page }) => {
  const calls = await mockControl(page);
  await openStream(page);
  await expect(rows(page)).toHaveCount(25);
  await page.getByRole("button", { name: /更多筛选/ }).click();
  await page.getByLabel("操作 ID", { exact: true }).fill("orders.read");
  await page.getByLabel("原因码", { exact: true }).fill("WAF_QUERY_BLOCKED");
  await page.getByLabel("主体引用", { exact: true }).fill("operator-1");
  await page.getByRole("button", { name: "应用筛选", exact: true }).click();
  await expect.poll(() => searches(calls).length).toBe(2);
  expect(body(searches(calls)[1]).filters).toEqual([
    { kind: "text", field: "event_type", value: "request.completed" },
    { kind: "text", field: "operation_id", value: "orders.read" },
    { kind: "text", field: "reason_code", value: "WAF_QUERY_BLOCKED" },
    { kind: "subject_ref", value: "operator-1" },
  ]);
  await expect(page.getByText("操作 ID：orders.read")).toBeVisible();
  await expect(page.getByText("主体引用：已设置（不回显）")).toBeVisible();
  await expect(rows(page).first()).toContainText("WAF_QUERY_BLOCKED");
  // The submitted plan on screen masks the value; the page never shows it anywhere.
  await page.getByText("查询详情", { exact: true }).click();
  const plan = page.getByRole("region", { name: "已提交查询计划" });
  await expect(plan).toContainText("[已隐藏]");
  await expect(page.getByText("operator-1")).toHaveCount(0);

  // Removing a tag is a new plan too.
  await page.getByLabel("移除筛选：操作 ID：orders.read", { exact: true }).click();
  await expect.poll(() => searches(calls).length).toBe(3);
  expect(body(searches(calls)[2]).filters).toEqual([
    { kind: "text", field: "event_type", value: "request.completed" },
    { kind: "text", field: "reason_code", value: "WAF_QUERY_BLOCKED" },
    { kind: "subject_ref", value: "operator-1" },
  ]);
});

test("filter values are checked before anything is sent", async ({ page }) => {
  const calls = await mockControl(page);
  await openStream(page);
  await expect(rows(page)).toHaveCount(25);
  await page.getByRole("button", { name: /更多筛选/ }).click();
  await page.getByLabel("Trace ID", { exact: true }).fill("not-a-trace");
  await page.getByLabel("操作 ID", { exact: true }).fill("select * from events");
  await page.getByRole("button", { name: "应用筛选", exact: true }).click();
  await expect(page.getByText(/Trace ID格式无效/)).toBeVisible();
  await expect(page.getByText(/只允许字母、数字/)).toBeVisible();
  expect(searches(calls)).toHaveLength(1);
});

test.describe("local time zone", () => {
  test.use({ timezoneId: "Asia/Shanghai" });

  test("a custom local range is sent as a whole-second UTC window", async ({ page }) => {
    const calls = await mockControl(page);
    await openStream(page);
    await expect(rows(page)).toHaveCount(25);
    await page.getByRole("button", { name: "自定义", exact: true }).click();
    await page.getByLabel("开始时间（本地，含）", { exact: true }).fill("2026-09-20T08:00");
    await page.getByLabel("结束时间（本地，不含）", { exact: true }).fill("2026-09-20T09:30:15");
    await expect(page.getByText(/2026-09-20T00:00:00Z/)).toBeVisible();
    expect(searches(calls)).toHaveLength(1);
    await page.getByRole("button", { name: "应用时间范围", exact: true }).click();
    await expect.poll(() => searches(calls).length).toBe(2);
    expect(body(searches(calls)[1])).toMatchObject({
      start: "2026-09-20T00:00:00Z",
      end: "2026-09-20T01:30:15Z",
    });
    // Table times are local; the exact UTC instant stays on the element.
    await expect(rows(page).first().locator("time")).toHaveAttribute("datetime", /Z$/);
  });

  test("a range over 31 days is explained and the validator still refuses it", async ({ page }) => {
    const calls = await mockControl(page);
    await openStream(page);
    await expect(rows(page)).toHaveCount(25);
    await page.getByRole("button", { name: "自定义", exact: true }).click();
    await page.getByLabel("开始时间（本地，含）", { exact: true }).fill("2026-09-01T00:00");
    await page.getByLabel("结束时间（本地，不含）", { exact: true }).fill("2026-10-05T00:00");
    await expect(page.getByText("时间范围不能超过 31 天。")).toBeVisible();
    await page.getByRole("button", { name: "应用时间范围", exact: true }).click();
    await expect(page.getByRole("alert")).toContainText("CONTROL_QUERY_INVALID");
    expect(searches(calls)).toHaveLength(1);
  });
});

test("a row, its request chip and the ID box all open the request detail", async ({ page }) => {
  const calls = await mockControl(page);
  await openStream(page);
  await expect(rows(page)).toHaveCount(25);
  // An unrecognised ID explains itself without a call.
  const box = page.getByLabel("按请求 ID 打开", { exact: true });
  await box.fill("req_123");
  await page.getByRole("button", { name: "打开", exact: true }).click();
  await expect(page.getByText("请输入规范的请求 ID（req_ 加小写 UUIDv7）。")).toBeVisible();
  expect(calls).toHaveLength(1);

  await box.fill(`  "${REQUEST_ID}" `);
  await page.getByRole("button", { name: "打开", exact: true }).click();
  await expect(page).toHaveURL(new RegExp(`/investigation/requests/${REQUEST_ID}$`));
  await expect
    .poll(() => calls.some((call) => call.path === `/control/v1/requests/${REQUEST_ID}`))
    .toBe(true);

  await openView(page, "request");
  await expect(rows(page)).toHaveCount(25);
  await page.getByRole("link", { name: streamRequestId(1), exact: true }).click();
  await expect(page).toHaveURL(new RegExp(`/investigation/requests/${streamRequestId(1)}$`));
  await openView(page, "request");
  await expect(rows(page)).toHaveCount(25);
  await rows(page).nth(2).locator("td").first().click();
  await expect(page).toHaveURL(new RegExp(`/investigation/requests/${streamRequestId(2)}$`));
});

test("the filters you set come back when you return from a request", async ({ page }) => {
  const calls = await mockControl(page);
  await openStream(page);
  await expect(rows(page)).toHaveCount(25);
  await chip(page, "拒绝").click();
  await expect.poll(() => searches(calls).length).toBe(2);
  await rows(page).first().locator("td").first().click();
  await expect(page).toHaveURL(/\/investigation\/requests\/req_/);
  await openView(page, "request");
  await expect(page.locator("label.ant-segmented-item-selected")).toHaveText("拒绝");
  await expect(rows(page).first()).toContainText("拒绝");
  // Within the same second the cached read is reused; later it is read again on open.
  const last = searches(calls).at(-1);
  expect(body(last).filters).toEqual([
    { kind: "text", field: "event_type", value: "request.completed" },
    { kind: "outcome", value: "DENY" },
  ]);
});

test("a superseded plan's late reply never reaches the table", async ({ page }) => {
  let release = () => {};
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  let arrived = () => {};
  const firstArrived = new Promise<void>((resolve) => {
    arrived = resolve;
  });
  const calls = await mockControl(page, async (_url, request) => {
    const plan = request.postDataJSON() as SearchPlan;
    if (plan.filters.some((item) => item.kind === "outcome")) return undefined;
    arrived();
    await held;
    return { body: await streamFixture(plan, undefined) };
  });
  await signIn(page, "/access/session");
  const settled = requestSettled(page, "/control/v1/search");
  await openView(page, "request");
  await firstArrived;
  await chip(page, "拒绝").click();
  await expect(rows(page).first()).toContainText("拒绝");
  release();
  await settled;
  await paint(page);
  // The "all" reply carried 放行 rows; none of them may appear under the 拒绝 plan.
  await expect(rows(page).getByText("放行", { exact: true })).toHaveCount(0);
  // Both plans were sent: the superseded one was abandoned in flight, only the 拒绝 plan answered.
  await expect.poll(() => searches(abandoned(calls)).length).toBe(1);
  expect(body(searches(abandoned(calls))[0]).filters).toEqual([
    { kind: "text", field: "event_type", value: "request.completed" },
  ]);
  expect(searches(calls)).toHaveLength(1);
  expect(body(searches(calls)[0]).filters).toContainEqual({ kind: "outcome", value: "DENY" });
});

test("failures use the safe message, show the code and request id, and wait for an explicit retry", async ({
  page,
}) => {
  await page.clock.install();
  let status = 403;
  const calls = await mockControl(page, (url) =>
    url.pathname === "/control/v1/search"
      ? {
          status,
          body: errorFixture(
            status === 403 ? "CONTROL_SCOPE_DENIED" : "CONTROL_QUERY_BUDGET_EXCEEDED",
          ),
        }
      : undefined,
  );
  await openStream(page);
  const alert = page.getByRole("alert");
  await expect(alert).toContainText("CONTROL_SCOPE_DENIED");
  await expect(alert).toContainText("req_018f2a3b-4c5d-7000-8000-000000000099");
  await expect(page.getByText("Synthetic server detail must not be rendered")).toHaveCount(0);
  await page.clock.fastForward(60_000);
  expect(searches(calls)).toHaveLength(1);
  status = 429;
  await page.getByRole("button", { name: "重新读取", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("CONTROL_QUERY_BUDGET_EXCEEDED");
  expect(searches(calls)).toHaveLength(2);
});

test("a 401 clears the session and a foreign scope disconnects", async ({ page }) => {
  let mode: "ok" | "expired" | "drift" = "expired";
  await mockControl(page, async (url, request) => {
    if (url.pathname !== "/control/v1/search") return undefined;
    if (mode === "expired") return { status: 401, body: errorFixture("CONTROL_AUTH_REQUIRED") };
    const value = await streamFixture(request.postDataJSON(), undefined);
    return { body: { ...value, site_id: mode === "drift" ? "site_other" : "site_demo" } };
  });
  await openStream(page);
  await expect(page.getByRole("status")).toContainText("管理会话已失效");
  await expect(page.getByLabel("管理凭证", { exact: true })).toHaveValue("");

  // The first valid reply of a machine-login session confirms the scope; a later reply for
  // another site then ends the session instead of being shown.
  mode = "ok";
  await signIn(page, "/access/session");
  await openView(page, "request");
  await expect(rows(page)).toHaveCount(25);
  mode = "drift";
  await page.getByRole("button", { name: "刷新", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("响应范围校验失败");
  await expect(page.getByLabel("管理凭证", { exact: true })).toHaveValue("");
  await expect(rows(page)).toHaveCount(0);
  await expect(page.getByText("site_other")).toHaveCount(0);
});

test("an empty window is not an error and does not prove there was no traffic", async ({
  page,
}) => {
  await mockControl(page, async (url, request) => {
    if (url.pathname !== "/control/v1/search") return undefined;
    const value = await streamFixture(request.postDataJSON(), undefined, { total: 0 });
    return {
      body: {
        ...value,
        index_watermark: null,
        scanned_rows: null,
        has_gaps: true,
        pending_segments: 2,
      },
    };
  });
  await openStream(page);
  await expect(page.getByText("该时间范围内没有已索引的请求终态")).toBeVisible();
  await expect(page.getByText(/空结果不证明没有流量/)).toBeVisible();
  await expect(page.getByRole("status", { name: "请求流索引状态" })).toContainText(
    "索引存在缺口 · 2 个待发布段",
  );
  await page.getByText("查看水位", { exact: true }).click();
  await expect(page.getByRole("status", { name: "请求流索引状态" })).toContainText("尚不可用");
  await page.getByText("查询详情", { exact: true }).click();
  await expect(page.getByRole("region", { name: "已提交查询计划" })).toContainText(
    "未知（索引未报告）",
  );
  await expect(page.getByRole("button", { name: "加载更多", exact: true })).toBeDisabled();
});

test("scan statistics distinguish unknown from zero and the index lag is disclosed", async ({
  page,
}) => {
  await mockControl(page, async (url, request) => {
    if (url.pathname !== "/control/v1/search") return undefined;
    return {
      body: await streamFixture(request.postDataJSON(), undefined, {
        scanned: { rows: null, bytes: 0 },
        pendingSegments: 1,
      }),
    };
  });
  await openStream(page);
  await page.getByText("查询详情", { exact: true }).click();
  const region = page.getByRole("region", { name: "已提交查询计划" });
  await expect(region.locator("tr").filter({ hasText: "实际扫描行" })).toContainText(
    "未知（索引未报告）",
  );
  await expect(region.locator("tr").filter({ hasText: "实际扫描字节" })).toContainText("0");
  const banner = page.getByRole("status", { name: "请求流索引状态" });
  await expect(banner).toContainText("索引仍在同步 · 1 个待发布段");
  await expect(banner).toContainText("当前结果可能不完整");
  await expect(banner).toContainText("水位仅代表配置的日志源");
  await expect(banner).toContainText("最新终态事件发生于");
});

test("untrusted metadata is data and undisclosed fields are dropped", async ({ page }) => {
  const injected = '<img src=x onerror="window.xshieldInjected=true">';
  await mockControl(page, async (url, request) => {
    if (url.pathname !== "/control/v1/search") return undefined;
    const value = await streamFixture(request.postDataJSON(), undefined);
    return {
      body: {
        ...value,
        payload_json: "RAW_PAYLOAD_SENTINEL",
        events: value.events.map((event) => ({
          ...event,
          payload_json: "RAW_PAYLOAD_SENTINEL",
          reason_code: "SOME_NEW_CODE_FROM_A_NEWER_SERVER",
          storage: { locator: "PRIVATE_STORAGE_SENTINEL" },
        })),
      },
    };
  });
  await openStream(page);
  await expect(rows(page)).toHaveCount(25);
  // A code this build does not describe is shown exactly as received and marked as such.
  await expect(rows(page).first()).toContainText("SOME_NEW_CODE_FROM_A_NEWER_SERVER");
  await expect(rows(page).first()).toContainText("未收录的原因码");
  await expect(page.getByText(/RAW_PAYLOAD_SENTINEL|PRIVATE_STORAGE_SENTINEL/)).toHaveCount(0);
  expect(await page.evaluate(() => Reflect.get(window, "xshieldInjected"))).toBeUndefined();
  expect(injected.length).toBeGreaterThan(0);
  expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0]);
});

test.describe("mobile", () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test("no horizontal page scroll; the table scrolls inside its own container", async ({
    page,
  }) => {
    await mockControl(page);
    await openStream(page);
    await expect(rows(page)).toHaveCount(25);
    expect(
      await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
    ).toBe(true);
    const inner = await page.evaluate(() => {
      const content = document.querySelector(".ant-table-content");
      return content ? content.scrollWidth > content.clientWidth : false;
    });
    expect(inner).toBe(true);
    for (const name of ["打开", "更多筛选"]) {
      const box = await page
        .getByRole("button", { name: new RegExp(name) })
        .first()
        .boundingBox();
      expect(box && box.x >= 0 && box.x + box.width <= 390).toBeTruthy();
    }
  });
});
