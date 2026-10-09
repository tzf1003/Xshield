import { expect, type Page, test } from "@playwright/test";
import type { SearchPlan } from "../src/search.ts";
import { type Call, mockControl, paint, requestSettled, sent } from "./control-mock";
import {
  ARTIFACT_ID,
  errorFixture,
  OTHER_REQUEST_ID,
  REQUEST_ID,
  SEARCH_PLAN,
  TOKEN,
} from "./fixtures";
import { pagedSearchFixture } from "./investigation-fixtures";
import { pickRange, signInQuietly, submitSearch } from "./investigation-helpers";
import { openView } from "./navigation";
import { signIn } from "./shell-helpers";

// The picker works in local time; a UTC browser clock makes the typed text the plan's text.
test.use({ timezoneId: "UTC" });

/** The default page size: a full first page holds this many events in the paged fixture. */
const LIMIT = 25;
const RANGE = ["2026-09-20T00:00", "2026-09-21T00:00"] as const;
const TRACE = "018f2a3b4c5d70008000000000000003";
const EVENT_1 = "ev_018f2a3b-4c5d-7000-8000-000000000001";
const EVENT_2 = "ev_018f2a3b-4c5d-7000-8000-000000000002";

const results = (page: Page) => page.getByRole("region", { name: "搜索事件结果", exact: true });
const plans = (page: Page) => page.getByRole("region", { name: "已提交查询计划" });
const conditions = (page: Page) => page.getByRole("list", { name: "已添加的检索条件" });
const index = (page: Page) => page.getByRole("status", { name: "搜索索引状态" });
const searches = (calls: Call[]) => calls.filter((call) => call.path === "/control/v1/search");
const body = (call: Call | undefined) => call?.body as SearchPlan & { cursor?: string };
const rows = (page: Page) => results(page).locator(".ant-table-row");
const loadMore = (page: Page) => page.getByRole("button", { name: "加载更多", exact: true });

async function openSearch(page: Page) {
  await signInQuietly(page);
  await openView(page, "search");
  await expect(page.getByRole("heading", { name: "结构化事件检索", exact: true })).toBeVisible();
}

/** Adds one condition. Without a field the form recognises the pasted ID by itself. */
async function addCondition(page: Page, field: string | null, value: string) {
  if (field) {
    await choose(page, "条件字段", field);
  }
  await page.getByLabel("条件值", { exact: true }).fill(value);
  await page.getByRole("button", { name: "添加条件", exact: true }).click();
}

/** Picks an option of one of the page's selects from its open list. */
async function choose(page: Page, label: string, option: string) {
  await page.getByLabel(label, { exact: true }).click();
  await page
    .locator(".ant-select-dropdown:not(.ant-select-dropdown-hidden)")
    .getByTitle(option, { exact: true })
    .click();
}

async function search(page: Page, range: readonly [string, string] = RANGE) {
  await pickRange(page, range[0], range[1]);
  await submitSearch(page);
}

test.describe("the form", () => {
  test("nothing is read on arrival, and the rules are on the page", async ({ page }) => {
    const calls = await mockControl(page);
    await openSearch(page);
    await paint(page);
    expect(calls).toHaveLength(0);
    await expect(page.getByText("已添加 0 / 8 个条件")).toBeVisible();
    await expect(page.getByText("条件之间为「且」")).toBeVisible();
    // The ordinary default is the last 24 hours; the window is whole UTC seconds, half open.
    await expect(page.getByRole("button", { name: "24 小时", exact: true })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    await expect(page.getByText(/最长 31\s*天/).first()).toBeVisible();
    await expect(results(page)).toHaveCount(0);
  });

  test("a pasted ID is recognised and becomes a condition", async ({ page }) => {
    const calls = await mockControl(page);
    await openSearch(page);
    const value = page.getByLabel("条件值", { exact: true });
    await value.fill(REQUEST_ID);
    await expect(page.getByText("识别为：请求 ID")).toBeVisible();
    await page.getByRole("button", { name: "添加条件", exact: true }).click();
    await expect(conditions(page)).toContainText(`请求 ID：${REQUEST_ID}`);
    // Quotes and spaces around a pasted ID are not part of it.
    await value.fill(`  "${TRACE}" `);
    await expect(page.getByText("识别为：Trace ID")).toBeVisible();
    await value.press("Enter");
    await expect(conditions(page)).toContainText(`Trace ID：${TRACE}`);
    // An ev_ ID is an event or a retention lock; the first reading is used and says so.
    await value.fill(EVENT_1);
    await page.getByRole("button", { name: "添加条件", exact: true }).click();
    await expect(conditions(page)).toContainText(`事件 ID：${EVENT_1}`);
    await expect(page.getByText(/同时用于事件 ID与保留锁 ID/)).toBeVisible();
    await expect(page.getByText("已添加 3 / 8 个条件")).toBeVisible();
    expect(calls).toHaveLength(0);
  });

  test("unrecognised, malformed and repeated values are explained, not added", async ({ page }) => {
    await mockControl(page);
    await openSearch(page);
    const value = page.getByLabel("条件值", { exact: true });
    const add = page.getByRole("button", { name: "添加条件", exact: true });
    await add.click();
    await expect(page.getByText("请填写条件的值，或粘贴一个规范的 ID。")).toBeVisible();
    await value.fill("select * from events");
    await add.click();
    await expect(page.getByText(/无法自动识别该值/)).toBeVisible();
    await value.fill(REQUEST_ID.toUpperCase());
    await add.click();
    await expect(page.getByText(/无法自动识别该值/)).toBeVisible();
    await expect(conditions(page)).toHaveCount(0);
    await value.fill(REQUEST_ID);
    await add.click();
    await value.fill(REQUEST_ID);
    await add.click();
    await expect(page.getByText("该条件已经添加。")).toBeVisible();
    await expect(conditions(page).getByRole("listitem")).toHaveCount(1);
  });

  test("a chosen field validates its own value before anything is added", async ({ page }) => {
    await mockControl(page);
    await openSearch(page);
    await addCondition(page, "原因码", "select * from events");
    await expect(
      page.getByText("只允许字母、数字与 _ . : - ，且不超过 128 个字符。"),
    ).toBeVisible();
    await expect(conditions(page)).toHaveCount(0);
    await choose(page, "条件字段", "置信度上限（基点）");
    for (const bad of ["10001", "-1", "1.5", "abc"]) {
      await page.getByLabel("条件值", { exact: true }).fill(bad);
      await page.getByRole("button", { name: "添加条件", exact: true }).click();
      await expect(page.getByText("请输入 0–10000 的整数。")).toBeVisible();
    }
    await expect(conditions(page)).toHaveCount(0);
    await page.getByLabel("条件值", { exact: true }).fill("10000");
    await page.getByRole("button", { name: "添加条件", exact: true }).click();
    await expect(conditions(page)).toContainText("置信度上限（基点）：10000");
  });

  test("at most eight conditions, combined with AND", async ({ page }) => {
    await mockControl(page);
    await openSearch(page);
    const ids = [
      "ev_018f2a3b-4c5d-7000-8000-000000000001",
      "grant_018f2a3b-4c5d-7000-8000-000000000001",
      "auth_018f2a3b-4c5d-7000-8000-000000000001",
      "case_018f2a3b-4c5d-7000-8000-000000000001",
      ARTIFACT_ID,
      "calr_018f2a3b-4c5d-7000-8000-000000000001",
      "mdl_018f2a3b-4c5d-7000-8000-000000000001",
      "share_018f2a3b-4c5d-7000-8000-000000000007",
    ];
    for (const id of ids) await addCondition(page, null, id);
    await expect(conditions(page).getByRole("listitem")).toHaveCount(8);
    await expect(page.getByRole("button", { name: "添加条件", exact: true })).toBeDisabled();
    await expect(page.getByText(/最多 8 个条件，已达上限/)).toBeVisible();
    // Removing one frees a slot.
    await page.getByRole("button", { name: `移除条件：事件 ID：${ids[0]}` }).click();
    await expect(page.getByRole("button", { name: "添加条件", exact: true })).toBeEnabled();
    await expect(page.getByText("已添加 7 / 8 个条件")).toBeVisible();
  });
});

test.describe("submitting", () => {
  test("submits an allowlisted plan, freezes pagination and clears edited results", async ({
    page,
  }) => {
    const calls = await mockControl(page);
    await openSearch(page);
    const filters: SearchPlan["filters"] = [
      { kind: "event_id", value: EVENT_1 },
      { kind: "grant_id", value: "grant_018f2a3b-4c5d-7000-8000-000000000001" },
      { kind: "auth_binding_id", value: "auth_018f2a3b-4c5d-7000-8000-000000000001" },
      { kind: "case_id", value: "case_018f2a3b-4c5d-7000-8000-000000000001" },
      { kind: "artifact_id", value: ARTIFACT_ID },
      { kind: "calibration_report_id", value: "calr_018f2a3b-4c5d-7000-8000-000000000001" },
      { kind: "model_call_id", value: "mdl_018f2a3b-4c5d-7000-8000-000000000001" },
      { kind: "share_grant_id", value: "share_018f2a3b-4c5d-7000-8000-000000000007" },
    ];
    for (const filter of filters) {
      if (filter.kind === "text" || filter.kind === "confidence_at_most") continue;
      await addCondition(page, null, filter.value);
    }
    await search(page);
    await expect(rows(page)).toHaveCount(LIMIT);
    await expect(results(page)).toContainText(`已加载 ${LIMIT} 条`);
    const plan = { ...SEARCH_PLAN, limit: 25, filters };
    expect(searches(sent(calls))).toHaveLength(1);
    expect(searches(sent(calls))[0]).toMatchObject({
      path: "/control/v1/search",
      method: "POST",
      authorized: true,
      cookie: null,
      body: plan,
    });
    // The submitted plan is shown exactly as sent, and unknown scan numbers stay unknown.
    await page.getByText("查看已提交计划", { exact: true }).click();
    await expect(plans(page).locator("pre")).toHaveText(JSON.stringify(plan, null, 2));
    await expect(plans(page)).toContainText("未知（索引未报告）");
    await expect(plans(page).locator("tr").filter({ hasText: "实际扫描字节" })).toContainText("0");
    // Freeze: the next page repeats the plan and adds the cursor; rows are appended.
    await loadMore(page).click();
    await expect(results(page)).toContainText(`已加载 ${LIMIT + 1} 条`);
    expect(body(searches(sent(calls))[1])).toEqual({
      ...plan,
      cursor: (await pagedSearchFixture(plan)).next_cursor,
    });
    await expect(loadMore(page)).toBeDisabled();
    // Editing a condition retires the rows, the plan and the cursor; submitting again is new.
    await page.getByRole("button", { name: `移除条件：事件 ID：${EVENT_1}` }).click();
    await expect(results(page)).toHaveCount(0);
    await expect(plans(page)).toHaveCount(0);
    await expect(loadMore(page)).toHaveCount(0);
    await addCondition(page, "请求 ID", OTHER_REQUEST_ID);
    await submitSearch(page);
    await expect(rows(page).first()).toBeVisible();
    expect(body(searches(sent(calls))[2])).toEqual({
      ...plan,
      filters: [...filters.slice(1), { kind: "request_id", value: OTHER_REQUEST_ID }],
    });
    expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0]);
  });

  test("sort, page size and the five text conditions reach the plan", async ({ page }) => {
    const calls = await mockControl(page);
    await openSearch(page);
    for (const field of ["事件类型", "阶段", "原因码", "操作 ID", "模型版本"]) {
      await addCondition(page, field, "audit.value");
    }
    await addCondition(page, "置信度上限（基点）", "0");
    await choose(page, "事件时间排序", "最早优先");
    await choose(page, "每页条数", "100");
    await search(page);
    await expect(rows(page).first()).toBeVisible();
    expect(body(searches(calls)[0])).toEqual({
      ...SEARCH_PLAN,
      sort: "occurred_at_asc",
      limit: 100,
      filters: [
        ...["event_type", "stage", "reason_code", "operation_id", "model_revision"].map(
          (field) => ({
            kind: "text",
            field,
            value: "audit.value",
          }),
        ),
        { kind: "confidence_at_most", basis_points: 0 },
      ],
    });
  });

  test("the outcome condition is a choice, not free text", async ({ page }) => {
    const calls = await mockControl(page);
    await openSearch(page);
    await choose(page, "条件字段", "结果");
    await choose(page, "条件值", "DENY");
    await page.getByRole("button", { name: "添加条件", exact: true }).click();
    await expect(conditions(page)).toContainText("结果：DENY");
    await search(page);
    await expect(rows(page).first()).toBeVisible();
    expect(body(searches(calls)[0]).filters).toEqual([{ kind: "outcome", value: "DENY" }]);
  });

  test("a range that is missing, empty or too long is refused before transport", async ({
    page,
  }) => {
    const calls = await mockControl(page);
    await openSearch(page);
    // Arriving by a preset leaves the range unchosen: clear it by editing to custom without text.
    await page.getByRole("button", { name: "自定义", exact: true }).click();
    await page.getByLabel("开始时间（本地，含）", { exact: true }).fill("");
    await submitSearch(page);
    await expect(page.getByRole("alert")).toContainText("请完整填写时间范围");
    await page.getByLabel("开始时间（本地，含）", { exact: true }).fill("2026-09-20T00:00");
    await page.getByLabel("结束时间（本地，不含）", { exact: true }).fill("2026-10-22T00:00");
    await expect(page.getByText("时间范围不能超过 31 天。")).toBeVisible();
    await submitSearch(page);
    await expect(page.getByRole("alert")).toContainText("CONTROL_QUERY_INVALID");
    await page.getByLabel("结束时间（本地，不含）", { exact: true }).fill("2026-09-20T00:00");
    await submitSearch(page);
    await expect(page.getByRole("alert")).toContainText("CONTROL_QUERY_INVALID");
    expect(calls).toHaveLength(0);
    await page.getByLabel("结束时间（本地，不含）", { exact: true }).fill("2026-09-21T00:00");
    await submitSearch(page);
    await expect(rows(page).first()).toBeVisible();
    expect(searches(calls)).toHaveLength(1);
  });

  test("a subject reference is matched exactly and never echoed", async ({ page }) => {
    const calls = await mockControl(page);
    await openSearch(page);
    await choose(page, "条件字段", "主体引用");
    await expect(page.getByText("仅用于精确筛选；结果与已提交计划都不会回显该值。")).toBeVisible();
    await page.getByLabel("条件值", { exact: true }).fill("operator-1");
    await page.getByRole("button", { name: "添加条件", exact: true }).click();
    await expect(conditions(page)).toContainText("主体引用：已设置（不回显）");
    await expect(page.getByText("operator-1")).toHaveCount(0);
    expect(searches(calls)).toHaveLength(0);
    await search(page);
    await expect(results(page)).toContainText(`已加载 ${LIMIT} 条`);
    expect(body(searches(calls)[0]).filters).toEqual([
      { kind: "subject_ref", value: "operator-1" },
    ]);
    await page.getByText("查看已提交计划", { exact: true }).click();
    await expect(plans(page).locator("pre")).toContainText("[已隐藏]");
    await expect(page.getByText("operator-1")).toHaveCount(0);
    // Leaving the page forgets it: a low-entropy identifier is not kept around.
    await openView(page, "audit-health");
    // The shell heading follows the address before the lazily loaded page replaces this one, so
    // returning earlier reuses this page with its state: wait until it has left the screen.
    await expect(results(page)).toHaveCount(0);
    await openView(page, "search");
    await expect(conditions(page)).toHaveCount(0);
    await expect(page.getByText("operator-1")).toHaveCount(0);
  });

  test("the rest of the form is remembered while the session lasts, results are not", async ({
    page,
  }) => {
    await mockControl(page);
    await openSearch(page);
    await addCondition(page, null, REQUEST_ID);
    await search(page);
    await expect(rows(page).first()).toBeVisible();
    await openView(page, "audit-health");
    // The shell heading follows the address before the lazily loaded page replaces this one, so
    // returning earlier reuses this page with its state: wait until it has left the screen.
    await expect(results(page)).toHaveCount(0);
    await openView(page, "search");
    await expect(conditions(page)).toContainText(`请求 ID：${REQUEST_ID}`);
    await expect(page.getByLabel("开始时间（本地，含）", { exact: true })).toHaveValue(RANGE[0]);
    await expect(results(page)).toHaveCount(0);
  });
});

test.describe("the results", () => {
  test("the empty answer keeps the gaps, the pending segments and the unknown scan facts", async ({
    page,
  }) => {
    await mockControl(page, async (url, request) =>
      url.pathname === "/control/v1/search"
        ? {
            body: {
              ...(await pagedSearchFixture(request.postDataJSON())),
              events: [],
              truncated: false,
              next_cursor: null,
              index_watermark: null,
            },
          }
        : undefined,
    );
    await openSearch(page);
    await search(page);
    await expect(results(page)).toContainText("当前条件下没有匹配的已索引事件");
    await expect(results(page)).toContainText("空结果不证明事件不存在");
    await expect(index(page)).toContainText("索引存在缺口 · 2 个待发布段");
    await page.getByText("查看已提交计划", { exact: true }).click();
    await expect(plans(page)).toContainText("未知（索引未报告）");
    await page.getByText("查看水位", { exact: true }).click();
    await expect(index(page)).toContainText("尚不可用");
    await expect(loadMore(page)).toBeDisabled();
  });

  test("columns can be chosen, and a row opens the event drawer", async ({ page }) => {
    await mockControl(page);
    await openSearch(page);
    await search(page);
    const headers = results(page).locator("th");
    await expect(headers.filter({ hasText: "Trace" })).toHaveCount(0);
    await page.getByRole("button", { name: "选择列", exact: true }).click();
    await page.getByRole("checkbox", { name: "Trace", exact: true }).check();
    await page.getByRole("checkbox", { name: "证据", exact: true }).check();
    await page.getByRole("checkbox", { name: "原因", exact: true }).uncheck();
    await page.keyboard.press("Escape");
    await expect(headers.filter({ hasText: "Trace" })).toHaveCount(1);
    await expect(headers.filter({ hasText: "证据" })).toHaveCount(1);
    await expect(headers.filter({ hasText: "原因" })).toHaveCount(0);
    // The drawer shows the exact UTC text with microseconds and what the DTO does not carry.
    await page.getByRole("button", { name: `查看事件 ${EVENT_1}` }).click();
    const drawer = page.getByRole("dialog", { name: "事件详情" });
    await expect(drawer.getByText(EVENT_1, { exact: true })).toBeVisible();
    await expect(drawer).toContainText("2026-09-20T08:10:30.123457Z");
    await expect(
      drawer.locator("dl > div, .ant-descriptions-row").filter({ hasText: "来源请求" }),
    ).toContainText("未记录");
    await page.keyboard.press("Escape");
    await expect(drawer).toHaveCount(0);
    // Clicking the row itself does the same; the center may be a request link, so click a corner.
    await rows(page)
      .nth(1)
      .click({ position: { x: 2, y: 2 } });
    await expect(drawer.getByText(EVENT_2, { exact: true })).toBeVisible();
  });

  test("an event can start a same-trace search that is prepared and not run", async ({ page }) => {
    const calls = await mockControl(page);
    await openSearch(page);
    await search(page);
    await expect(rows(page)).toHaveCount(LIMIT);
    await page.getByRole("button", { name: `查看事件 ${EVENT_2}` }).click();
    await page
      .getByRole("dialog", { name: "事件详情" })
      .getByRole("button", { name: "同 Trace 检索", exact: true })
      .click();
    await expect(page).toHaveURL(
      new RegExp(`/investigation/search\\?prefill=trace_id%3A${TRACE}$`),
    );
    // The page now holds exactly that condition, no range and no results.
    await expect(conditions(page).getByRole("listitem")).toHaveCount(1);
    await expect(conditions(page)).toContainText(`Trace ID：${TRACE}`);
    await expect(results(page)).toHaveCount(0);
    await expect(page.getByText("已预填目标引用，请确认 UTC 时间窗后提交历史检索。")).toBeVisible();
    expect(searches(sent(calls))).toHaveLength(1);
    await submitSearch(page);
    await expect(page.getByRole("alert")).toContainText("请先选择时间范围");
    expect(searches(sent(calls))).toHaveLength(1);
    await pickRange(page, ...RANGE);
    await submitSearch(page);
    await expect(results(page)).toContainText(`已加载 ${LIMIT} 条`);
    expect(body(searches(sent(calls))[1]).filters).toEqual([{ kind: "trace_id", value: TRACE }]);
    expect(sent(calls).every((call) => call.authorized && call.cookie === null)).toBe(true);
  });

  test("Observer detail permissions stay independent of search", async ({ page }) => {
    let denyObserver = true;
    await mockControl(page, (url) =>
      url.pathname === "/control/v1/search" || !denyObserver
        ? undefined
        : { status: 403, body: errorFixture("CONTROL_SCOPE_DENIED") },
    );
    await openSearch(page);
    await search(page);
    await expect(rows(page).first()).toBeVisible();
    // Evidence metadata is its own read, with its own authorization.
    await page.getByRole("button", { name: `查看事件 ${EVENT_2}` }).click();
    const drawer = page.getByRole("dialog", { name: "事件详情" });
    await drawer.getByRole("button", { name: ARTIFACT_ID, exact: true }).click();
    const metadata = page.getByRole("dialog", { name: "证据元数据" });
    await expect(metadata.getByRole("alert")).toContainText("CONTROL_SCOPE_DENIED");
    await expect(rows(page).first()).toBeVisible();
    await page.keyboard.press("Escape");
    await page.keyboard.press("Escape");
    // The request page is another read: denied the same way, then retried by hand.
    await page.getByRole("link", { name: REQUEST_ID, exact: true }).first().click();
    await expect(page.getByRole("alert")).toContainText("CONTROL_SCOPE_DENIED");
    denyObserver = false;
    await page.getByRole("button", { name: "重新读取", exact: true }).click();
    await expect(page.getByText("AUTH_BINDING_VALID", { exact: true })).toBeVisible();
  });
});

test.describe("failures and session end", () => {
  test("errors use safe messages, wait for a manual retry and 401 clears the session", async ({
    page,
  }) => {
    await page.clock.install();
    let reply: { status: number; body: unknown } | undefined = {
      status: 403,
      body: errorFixture("CONTROL_SCOPE_DENIED"),
    };
    const calls = await mockControl(page, (url) =>
      url.pathname === "/control/v1/search" ? reply : undefined,
    );
    await openSearch(page);
    await pickRange(page, ...RANGE);
    for (const [status, code] of [
      [403, "CONTROL_SCOPE_DENIED"],
      [429, "CONTROL_QUERY_BUDGET_EXCEEDED"],
      [503, "CONTROL_QUERY_TIMEOUT"],
      [400, "CONTROL_CURSOR_INVALID"],
    ] as const) {
      reply = { status, body: errorFixture(code) };
      await submitSearch(page);
      await expect(page.getByRole("alert")).toContainText(code);
      await expect(page.getByRole("alert")).toContainText(
        "req_018f2a3b-4c5d-7000-8000-000000000099",
      );
      await expect(results(page).locator(".ant-table")).toHaveCount(0);
    }
    await page.clock.fastForward(60_000);
    expect(searches(sent(calls))).toHaveLength(4);
    await expect(page.getByText("Synthetic server detail must not be rendered")).toHaveCount(0);
    reply = { status: 401, body: errorFixture("CONTROL_AUTH_REQUIRED") };
    await submitSearch(page);
    await expect(page.getByRole("status").filter({ hasText: "管理会话已失效" })).toBeVisible();
    await expect(page.getByLabel("管理凭证", { exact: true })).toHaveValue("");
    await expect(plans(page)).toHaveCount(0);
    expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0]);
  });

  test("a reply from another scope ends the session", async ({ page }) => {
    let drift = false;
    await mockControl(page, async (url, request) =>
      url.pathname === "/control/v1/search" && drift
        ? { body: { ...(await pagedSearchFixture(request.postDataJSON())), site_id: "site_other" } }
        : undefined,
    );
    await openSearch(page);
    // The first valid reply establishes the scope; a later one for another site ends the session.
    await search(page);
    await expect(rows(page).first()).toBeVisible();
    drift = true;
    await choose(page, "每页条数", "10");
    await submitSearch(page);
    await expect(page.getByRole("status").filter({ hasText: "响应范围校验失败" })).toBeVisible();
    await expect(page.getByLabel("管理凭证", { exact: true })).toHaveValue("");
    await expect(results(page)).toHaveCount(0);
  });

  test("editing, switching and disconnecting discard late search responses", async ({ page }) => {
    let release = () => {};
    let arrive = () => {};
    let delay = Promise.resolve();
    await mockControl(page, async (url, request) => {
      if (url.pathname !== "/control/v1/search") return undefined;
      const plan = request.postDataJSON();
      arrive();
      await delay;
      return { body: await pagedSearchFixture(plan) };
    });
    await openSearch(page);
    for (const action of ["edit", "switch", "disconnect"] as const) {
      if (action !== "edit") await openView(page, "search");
      await pickRange(page, ...RANGE).catch(() => undefined);
      delay = new Promise<void>((resolve) => {
        release = resolve;
      });
      const arrived = new Promise<void>((resolve) => {
        arrive = resolve;
      });
      const settled = requestSettled(page, "/control/v1/search");
      await submitSearch(page);
      await arrived;
      if (action === "edit") await choose(page, "每页条数", "50");
      else if (action === "switch") await openView(page, "audit-health");
      else await page.getByRole("button", { name: "断开连接", exact: true }).click();
      release();
      await settled;
      await paint(page);
      await expect(results(page)).toHaveCount(0);
      await expect(plans(page)).toHaveCount(0);
    }
  });

  test("idle, pagehide and reload clear all in-memory search state", async ({ page }) => {
    await page.clock.install();
    await mockControl(page);
    for (const action of ["idle", "pagehide", "reload"] as const) {
      await openSearch(page);
      await addCondition(page, null, REQUEST_ID);
      await search(page);
      await expect(rows(page).first()).toBeVisible();
      if (action === "idle") await page.clock.fastForward(15 * 60_000 + 1);
      else if (action === "pagehide")
        await page.evaluate(() => window.dispatchEvent(new Event("pagehide")));
      else await page.reload();
      await expect(page.getByLabel("管理凭证", { exact: true })).toHaveValue("");
      await expect(plans(page)).toHaveCount(0);
      await expect(results(page)).toHaveCount(0);
      // Signing in again starts from an empty form: nothing of the old session survived.
      await page.getByLabel("管理凭证", { exact: true }).fill(TOKEN);
      await page.getByRole("button", { name: "连接", exact: true }).click();
      await openView(page, "search");
      await expect(conditions(page)).toHaveCount(0);
    }
  });
});

test.describe("deep links and presets", () => {
  test("a valid prefill fills one condition; nothing else changes and nothing is sent", async ({
    page,
  }) => {
    const calls = await mockControl(page);
    // The address survives signing in, so a shared link lands on the prepared form.
    await signIn(page, `/investigation/search?prefill=trace_id%3A${TRACE}`);
    await expect(conditions(page)).toContainText(`Trace ID：${TRACE}`);
    await expect(conditions(page).getByRole("listitem")).toHaveCount(1);
    await expect(
      page.getByRole("group", { name: "时间范围" }).getByRole("button", { pressed: true }),
    ).toHaveCount(0);
    await paint(page);
    expect(calls).toHaveLength(0);
  });

  test("a crafted or unknown prefill is ignored", async ({ page }) => {
    const calls = await mockControl(page);
    for (const value of [
      "text%3Aselect%20*",
      "trace_id%3Anot-a-trace",
      "case_id%3Agarbage",
      "outcome%3ADENY",
      "request_id",
    ]) {
      await signIn(page, `/investigation/search?prefill=${value}`);
      await expect(
        page.getByRole("heading", { name: "结构化事件检索", exact: true }),
      ).toBeVisible();
      await expect(conditions(page)).toHaveCount(0);
      await expect(page.getByRole("button", { name: "24 小时", exact: true })).toHaveAttribute(
        "aria-pressed",
        "true",
      );
    }
    expect(calls).toHaveLength(0);
  });

  test("an event search handed over twice fills the form twice", async ({ page }) => {
    await mockControl(page);
    await signInQuietly(page);
    for (const attempt of [1, 2]) {
      await page.keyboard.press("Control+KeyK");
      await page.getByRole("combobox", { name: "命令面板" }).fill(TRACE);
      await page.getByRole("option", { name: /在事件检索中查找 Trace ID/ }).click();
      await expect(conditions(page)).toContainText(`Trace ID：${TRACE}`);
      if (attempt === 1) {
        await page.getByRole("button", { name: `移除条件：Trace ID：${TRACE}` }).click();
        await expect(conditions(page)).toHaveCount(0);
      }
    }
  });
});

test("untrusted metadata is text, raw fields are dropped and the layout fits", async ({ page }) => {
  const injected = '<img src=x onerror="window.xshieldInjected=true">';
  let malicious = true;
  const runtimeErrors: string[] = [];
  const consoleErrors: string[] = [];
  page.on("pageerror", (error) => runtimeErrors.push(error.message));
  page.on("console", (message) => {
    if (["warning", "error"].includes(message.type())) consoleErrors.push(message.text());
  });
  await mockControl(page, async (url, request) => {
    if (url.pathname !== "/control/v1/search") return undefined;
    const value = await pagedSearchFixture(request.postDataJSON());
    if (malicious) value.events[0]!.policy_revision = injected;
    return {
      body: {
        ...value,
        payload_json: "RAW_PAYLOAD_SENTINEL",
        storage: { locator: "PRIVATE_STORAGE_SENTINEL" },
        events: value.events.map((event) => ({ ...event, payload_json: "RAW_PAYLOAD_SENTINEL" })),
      },
    };
  });
  await openSearch(page);
  await addCondition(page, null, "grant_018f2a3b-4c5d-7000-8000-000000000001");
  await search(page);
  await expect(page.getByRole("alert")).toContainText("INVALID_RESPONSE");
  await expect(page.getByText(injected, { exact: true })).toHaveCount(0);
  malicious = false;
  await submitSearch(page);
  await expect(page).toHaveURL(/\/investigation\/search$/);
  await expect(page).toHaveTitle(/Xshield/);
  await expect(page.locator("vite-error-overlay")).toHaveCount(0);
  await expect(results(page)).toContainText(`已加载 ${LIMIT} 条`);
  expect(await page.evaluate(() => Reflect.get(window, "xshieldInjected"))).toBeUndefined();
  await expect(page.locator("main img")).toHaveCount(0);
  await expect(page.getByText("RAW_PAYLOAD_SENTINEL", { exact: false })).toHaveCount(0);
  await expect(page.getByText("PRIVATE_STORAGE_SENTINEL", { exact: false })).toHaveCount(0);
  for (const width of [1536, 390]) {
    await page.setViewportSize({ width, height: 1024 });
    await expect(page.getByRole("heading", { name: "结构化事件检索", exact: true })).toBeVisible();
    await expect
      .poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth))
      .toBe(true);
    for (const label of ["条件值", "条件字段", "开始时间（本地，含）", "结束时间（本地，不含）"]) {
      const box = await page.getByLabel(label, { exact: true }).boundingBox();
      expect(box && box.x >= 0 && box.x + box.width <= width).toBeTruthy();
    }
  }
  expect(runtimeErrors).toEqual([]);
  expect(consoleErrors).toEqual([]);
});

test.describe("mobile", () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test("the form and the table stay inside the phone width", async ({ page }) => {
    await mockControl(page);
    await openSearch(page);
    await addCondition(page, null, REQUEST_ID);
    await addCondition(page, null, TRACE);
    await search(page);
    await expect(rows(page)).toHaveCount(LIMIT);
    expect(
      await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
    ).toBe(true);
    // The table scrolls inside its own container instead of widening the page.
    expect(
      await page.evaluate(() => {
        const content = document.querySelector(".ant-table-content");
        return content ? content.scrollWidth > content.clientWidth : false;
      }),
    ).toBe(true);
    await page.getByRole("button", { name: `查看事件 ${EVENT_1}` }).click();
    const drawer = page.getByRole("dialog", { name: "事件详情" });
    await expect
      .poll(async () => {
        const box = await drawer.boundingBox();
        return box ? Math.round(box.x + box.width) : null;
      })
      .toBe(390);
  });
});
