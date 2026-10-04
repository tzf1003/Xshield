import { openView } from "./navigation";
import { expect, test, type Page, type Route } from "@playwright/test";
import { resolve } from "node:path";
import {
  ARTIFACT_ID,
  OTHER_ARTIFACT_ID,
  TOKEN,
  errorFixture,
} from "./fixtures";
import {
  CASE_ID,
  OTHER_CASE_ID,
  CASE_KEY,
  CASE_PURPOSE,
  CASE_CURSOR,
  CASE_LIST_CURSOR,
  caseListFixture,
  caseCreatedFixture,
  caseCollectionFixture,
  caseItemAddedFixture,
  caseClosedFixture,
  caseItemFixture,
} from "./case-fixtures";

type Call = { path: string; method: string; key: string | null; body: unknown };
type Handler = (route: Route, url: URL, count: number) => Promise<void>;
async function mockCases(page: Page, handler: Handler) {
  const calls: Call[] = [];
  await page.route("**/control/v1/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    expect(await request.headerValue("authorization")).toBe(`Bearer ${TOKEN}`);
    expect(await request.headerValue("cookie")).toBeNull();
    calls.push({
      path: url.pathname + url.search,
      method: request.method(),
      key: await request.headerValue("idempotency-key"),
      body: request.postDataJSON(),
    });
    await handler(route, url, calls.length);
  });
  return calls;
}
async function connectCases(page: Page) {
  await page.goto("/investigation/requests");
  await page.getByLabel("管理凭证", { exact: true }).fill(TOKEN);
  await page.getByRole("button", { name: "连接", exact: true }).click();
  await openView(page, "case");
}
async function createCase(page: Page, purpose = CASE_PURPOSE) {
  await page.getByLabel("调查目的", { exact: true }).fill(purpose);
  await page.getByLabel("幂等键", { exact: true }).fill(CASE_KEY);
  await page.getByRole("button", { name: "创建案件", exact: true }).click();
}
async function browseCase(page: Page, caseId = CASE_ID) {
  await page.getByLabel("案件 ID", { exact: true }).fill(caseId);
  await page
    .getByRole("button", { name: "读取案件 / 刷新首页", exact: true })
    .click();
}

test("case analysis waits for explicit submit and reads the durable job", async ({
  page,
}) => {
  const jobId = "job_018f2a3b-4c5d-7000-8000-000000000041";
  const analysisKey = "synthetic-case-analysis-key-0001";
  let analysisCalls = 0;
  let jobReads = 0;
  const calls = await mockCases(page, async (route, url) => {
    if (url.pathname.endsWith("/items")) {
      await route.fulfill({ json: caseCollectionFixture() });
    } else if (url.pathname.endsWith("/analyze")) {
      analysisCalls += 1;
      await route.fulfill({
        status: 202,
        json: {
          request_id: "req_018f2a3b-4c5d-7000-8000-000000000042",
          tenant_id: "tenant_demo",
          site_id: "site_demo",
          found: true,
          job: {
            job_id: jobId,
            kind: "case_analysis",
            status: "succeeded",
            checkpoint: "inventory_committed",
            reason_code: "CONTROL_CASE_ANALYSIS_COMPLETE",
            retryable: false,
            case_id: CASE_ID,
            artifact_count: 3,
            active_artifact_count: 2,
            created_at: "2026-09-20T08:00:00.000Z",
            updated_at: "2026-09-20T08:00:00.123Z",
            completed_at: "2026-09-20T08:00:00.123Z",
            replayed: false,
          },
        },
      });
    } else if (url.pathname.endsWith(`/jobs/${jobId}`)) {
      jobReads += 1;
      const response = {
        request_id: "req_018f2a3b-4c5d-7000-8000-000000000043",
        tenant_id: "tenant_demo",
        site_id: "site_demo",
        found: true,
        job: {
          job_id: jobId,
          kind: "case_analysis",
          status: "succeeded",
          checkpoint: "inventory_committed",
          reason_code: "CONTROL_CASE_ANALYSIS_COMPLETE",
          retryable: false,
          case_id: CASE_ID,
          artifact_count: 3,
          active_artifact_count: 2,
          created_at: "2026-09-20T08:00:00.000Z",
          updated_at: "2026-09-20T08:00:00.123Z",
          completed_at: "2026-09-20T08:00:00.123Z",
          replayed: false,
        },
      };
      await route.fulfill({ json: response });
    } else {
      await route.fulfill({ json: caseListFixture() });
    }
  });
  await connectCases(page);
  await browseCase(page);
  await expect(page.getByRole("heading", { name: "案件清单分析" })).toBeVisible();
  expect(analysisCalls).toBe(0);
  await page.getByLabel("分析幂等键", { exact: true }).fill(analysisKey);
  await page.getByRole("button", { name: "提交清单分析", exact: true }).click();
  await expect(page.getByText("分析任务已确认", { exact: true })).toBeVisible();
  expect(analysisCalls).toBe(1);
  await page.getByRole("button", { name: "重新读取任务状态", exact: true }).click();
  await expect(page.getByText("任务状态", { exact: true })).toBeVisible();
  expect(jobReads).toBe(1);
  await page
    .getByRole("button", { name: "准备任务历史检索", exact: true })
    .click();
  await expect(page.getByLabel("条件 1 字段", { exact: true })).toHaveValue(
    "job_id",
  );
  await expect(page.getByLabel("条件 1 值", { exact: true })).toHaveValue(jobId);
  expect(calls.filter((call) => call.path.endsWith("/search"))).toHaveLength(0);
  expect(calls.filter((call) => call.path.endsWith("/analyze"))).toEqual([
    {
      path: `/control/v1/cases/${CASE_ID}/analyze`,
      method: "POST",
      key: analysisKey,
      body: null,
    },
  ]);
});

test("case list explicitly reads live pages and opens a freshly authorized collection", async ({
  page,
}) => {
  const calls = await mockCases(page, async (route, url) => {
    if (url.pathname.endsWith("/items")) {
      const body = caseCollectionFixture();
      body.case.status = "closed";
      body.as_of = "2026-09-20T08:12:00.000001Z";
      await route.fulfill({ json: body });
    } else {
      const body = caseListFixture();
      if (url.search) {
        expect(url.searchParams.get("cursor")).toBe(CASE_LIST_CURSOR);
        body.items = [caseCollectionFixture().case];
        body.as_of = "2026-09-20T08:11:00.000001Z";
        body.truncated = false;
        body.next_cursor = null;
      }
      await route.fulfill({ json: body });
    }
  });
  await connectCases(page);
  const list = page.getByRole("region", { name: "我的案件", exact: true });
  await expect(
    list.getByText("读取本人案件后，选择一项打开证据集合。"),
  ).toBeVisible();
  expect(calls).toHaveLength(0);
  await list.getByRole("button", { name: "读取我的案件 / 刷新列表" }).click();
  await expect(
    list.getByRole("button", { name: `打开案件 ${OTHER_CASE_ID}` }),
  ).toBeVisible();
  await expect(
    list.getByText("2026-09-20T08:10:30.123456Z", { exact: true }),
  ).toBeVisible();
  expect(calls).toEqual([
    { path: "/control/v1/cases", method: "GET", key: null, body: null },
  ]);
  await list.getByRole("button", { name: "下一页案件" }).click();
  await expect(
    list.getByRole("button", { name: `打开案件 ${CASE_ID}` }),
  ).toBeVisible();
  await expect(
    list.getByRole("button", { name: `打开案件 ${OTHER_CASE_ID}` }),
  ).toHaveCount(0);
  await expect(
    list.getByText("2026-09-20T08:11:00.000001Z", { exact: true }),
  ).toBeVisible();
  await expect(list.getByRole("button", { name: "下一页案件" })).toBeDisabled();
  expect(calls.at(-1)).toEqual({
    path: `/control/v1/cases?cursor=${encodeURIComponent(CASE_LIST_CURSOR)}`,
    method: "GET",
    key: null,
    body: null,
  });
  await list.getByRole("button", { name: `打开案件 ${CASE_ID}` }).click();
  const collection = page.getByRole("region", {
    name: "案件证据集合",
    exact: true,
  });
  await expect(
    collection.getByText("案件已关闭，历史证据引用仍可浏览。"),
  ).toBeVisible();
  await expect(
    collection.getByText("2026-09-20T08:12:00.000001Z", { exact: true }),
  ).toBeVisible();
  await expect(page.getByLabel("案件 ID", { exact: true })).toHaveValue(
    CASE_ID,
  );
  expect(calls.at(-1)?.path).toBe(`/control/v1/cases/${CASE_ID}/items`);
  expect(calls).toHaveLength(3);
  await list.getByRole("button", { name: "读取我的案件 / 刷新列表" }).click();
  await expect(
    list.getByRole("button", { name: `打开案件 ${OTHER_CASE_ID}` }),
  ).toBeVisible();
  expect(calls.at(-1)?.path).toBe("/control/v1/cases");
  expect(calls).toHaveLength(4);
});

test("case list renders purpose as text with healthy desktop and mobile layouts", async ({
  page,
}) => {
  const problems: string[] = [];
  page.on("pageerror", (error) => problems.push(error.message));
  page.on("console", (message) => {
    if (["error", "warning"].includes(message.type()))
      problems.push(message.text());
  });
  const injection = '<img src=x onerror="window.caseListInjected=true">';
  await mockCases(page, async (route) => {
    const body = caseListFixture();
    body.items[0]!.purpose = injection;
    body.items.push({ ...caseCollectionFixture().case, status: "closed" });
    body.truncated = false;
    body.next_cursor = null;
    await route.fulfill({ json: body });
  });
  await connectCases(page);
  await expect(page).toHaveURL(new URL("/cases", page.url()).toString());
  await expect(page).toHaveTitle("管理后台 · Xshield");
  await page.getByRole("button", { name: "读取我的案件 / 刷新列表" }).click();
  const list = page.getByRole("region", { name: "我的案件", exact: true });
  await expect(list.getByText(injection, { exact: true })).toBeVisible();
  await expect(list.getByText("open · 开放", { exact: true })).toBeVisible();
  await expect(
    list.getByText("closed · 已关闭", { exact: true }),
  ).toBeVisible();
  await expect(list.locator("img")).toHaveCount(0);
  expect(await page.evaluate(() => "caseListInjected" in window)).toBe(false);
  await expect(page.locator("vite-error-overlay")).toHaveCount(0);
  for (const width of [1536, 390]) {
    await page.setViewportSize({ width, height: 1024 });
    await page.evaluate(() => window.scrollTo(0, 0));
    await expect(
      page.getByRole("heading", { name: "案件工作台", exact: true }),
    ).toBeVisible();
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
    if (process.env.XSHIELD_CONSOLE_SCREENSHOT_DIR)
      await page.screenshot({
        path: resolve(
          process.env.XSHIELD_CONSOLE_SCREENSHOT_DIR,
          `case-list-${width}.png`,
        ),
        fullPage: true,
      });
  }
  expect(problems).toEqual([]);
});

for (const field of ["tenant_id", "site_id"] as const) {
  test(`case list ${field} mismatch disconnects and clears existing rows`, async ({
    page,
  }) => {
    await mockCases(page, async (route, _url, count) => {
      const body = caseListFixture();
      if (count > 1) {
        body[field] = "other_scope";
        body.items[0]!.purpose = "cross-scope-purpose";
      }
      await route.fulfill({ json: body });
    });
    await connectCases(page);
    const refresh = page.getByRole("button", {
      name: "读取我的案件 / 刷新列表",
    });
    await refresh.click();
    await expect(
      page.getByRole("button", { name: `打开案件 ${OTHER_CASE_ID}` }),
    ).toBeVisible();
    await refresh.click();
    await expect(
      page.getByRole("heading", { name: "连接管理服务" }),
    ).toBeVisible();
    await expect(
      page.getByText("响应范围校验失败，连接已断开。"),
    ).toBeVisible();
    await expect(
      page.getByText("cross-scope-purpose", { exact: true }),
    ).toHaveCount(0);
    await expect(
      page.getByRole("region", { name: "我的案件", exact: true }),
    ).toHaveCount(0);
  });
}

test("case list late refresh cannot restore rows or cursor after leaving the view", async ({
  page,
}) => {
  let release!: () => void;
  const ready = new Promise<void>((resolveReady) => {
    release = resolveReady;
  });
  const calls = await mockCases(page, async (route, _url, count) => {
    if (count === 2) await ready;
    await route.fulfill({ json: caseListFixture() });
  });
  await connectCases(page);
  const refresh = page.getByRole("button", { name: "读取我的案件 / 刷新列表" });
  await refresh.click();
  await expect(
    page.getByRole("button", { name: `打开案件 ${OTHER_CASE_ID}` }),
  ).toBeVisible();
  await refresh.click();
  await expect.poll(() => calls.length).toBe(2);
  await openView(page, "request");
  release();
  await openView(page, "case");
  await expect(
    page.getByText("读取本人案件后，选择一项打开证据集合。"),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: `打开案件 ${OTHER_CASE_ID}` }),
  ).toHaveCount(0);
  await expect(page.getByRole("button", { name: "下一页案件" })).toHaveCount(0);
  expect(calls).toHaveLength(2);
  await refresh.click();
  await expect(
    page.getByRole("button", { name: `打开案件 ${OTHER_CASE_ID}` }),
  ).toBeVisible();
  expect(calls).toHaveLength(3);
  expect(calls.at(-1)?.path).toBe("/control/v1/cases");
});

for (const [status, code] of [
  [403, "CONTROL_SCOPE_DENIED"],
  [429, "CONTROL_CASE_BUSY"],
  [503, "CONTROL_CASE_STORE_UNAVAILABLE"],
] as const) {
  test(`case list ${status} failure keeps diagnostics until an explicit refresh`, async ({
    page,
  }) => {
    const calls = await mockCases(page, async (route, _url, count) => {
      if (count === 1)
        await route.fulfill({ status, json: errorFixture(code) });
      else
        await route.fulfill({
          json: {
            ...caseListFixture(),
            items: [],
            truncated: false,
            next_cursor: null,
          },
        });
    });
    await connectCases(page);
    const list = page.getByRole("region", { name: "我的案件", exact: true });
    const refresh = list.getByRole("button", {
      name: "读取我的案件 / 刷新列表",
    });
    await refresh.click();
    await expect(list.getByRole("alert")).toContainText(code);
    await expect(refresh).toBeEnabled();
    expect(calls).toHaveLength(1);
    await refresh.click();
    await expect(list.getByText("当前页没有本人案件。")).toBeVisible();
    await expect(list.getByRole("alert")).toHaveCount(0);
    await expect(
      list.getByRole("button", { name: "下一页案件" }),
    ).toBeDisabled();
    expect(calls).toHaveLength(2);
  });
}

test("case create → browse → add → refresh → close → browse uses explicit requests", async ({
  page,
}) => {
  const runtimeProblems: string[] = [];
  page.on("pageerror", (error) => runtimeProblems.push(error.message));
  page.on("console", (message) => {
    if (["error", "warning"].includes(message.type()))
      runtimeProblems.push(message.text());
  });
  let added = false;
  let closed = false;
  const calls = await mockCases(page, async (route, url) => {
    if (url.pathname === "/control/v1/cases") {
      await route.fulfill({ status: 201, json: caseCreatedFixture() });
    } else if (url.pathname.endsWith("/close")) {
      closed = true;
      await route.fulfill({ json: caseClosedFixture() });
    } else if (route.request().method() === "POST") {
      added = true;
      await route.fulfill({ status: 201, json: caseItemAddedFixture() });
    } else {
      const body = caseCollectionFixture();
      if (added) body.items = [caseItemFixture("active", ARTIFACT_ID)];
      if (closed) body.case.status = "closed";
      await route.fulfill({ json: body });
    }
  });
  await connectCases(page);
  await expect(page).toHaveURL(new URL("/cases", page.url()).toString());
  await expect(page).toHaveTitle("管理后台 · Xshield");
  await expect(
    page.getByRole("heading", { name: "案件工作台", exact: true }),
  ).toBeVisible();
  await expect(page.locator("vite-error-overlay")).toHaveCount(0);
  expect(calls).toHaveLength(0);
  await createCase(page);
  await expect(
    page.getByRole("heading", { name: "创建案件已确认" }),
  ).toBeVisible();
  expect(calls).toEqual([
    {
      path: "/control/v1/cases",
      method: "POST",
      key: CASE_KEY,
      body: { purpose: CASE_PURPOSE },
    },
  ]);
  await expect(
    page.getByText("false（首次提交）", { exact: true }),
  ).toBeVisible();
  await browseCase(page);
  await expect(
    page.getByText("当前案件尚无证据引用。", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText("2026-09-20T08:10:30.123456Z", { exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "准备新操作" }).click();
  await page.getByLabel("操作", { exact: true }).selectOption("add");
  await page.getByLabel("证据 ID", { exact: true }).fill(ARTIFACT_ID);
  const addKey = await page.getByLabel("幂等键", { exact: true }).inputValue();
  await page.getByRole("button", { name: "加入证据", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "加入证据已确认" }),
  ).toBeVisible();
  expect(calls.at(-1)).toEqual({
    path: `/control/v1/cases/${CASE_ID}/items`,
    method: "POST",
    key: addKey,
    body: { artifact_id: ARTIFACT_ID },
  });
  expect(calls).toHaveLength(3);
  await browseCase(page);
  await expect(
    page.getByText("active · 目录有效", { exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "准备新操作" }).click();
  await page.getByLabel("操作", { exact: true }).selectOption("close");
  await page.getByLabel("关闭理由", { exact: true }).fill("合成调查已完成");
  await page.getByRole("button", { name: "关闭案件", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "关闭案件已确认" }),
  ).toBeVisible();
  expect(calls).toHaveLength(5);
  await browseCase(page);
  await expect(
    page.getByText("案件已关闭，历史证据引用仍可浏览。", { exact: true }),
  ).toBeVisible();
  expect(calls).toHaveLength(6);
  expect(calls.some((call) => call.path.includes("/content"))).toBe(false);
  expect(
    await page.evaluate(() => [localStorage.length, sessionStorage.length]),
  ).toEqual([0, 0]);
  await expect(page.locator("vite-error-overlay")).toHaveCount(0);
  expect(runtimeProblems).toEqual([]);
});

test("case pagination renders catalog facts as text with desktop and mobile layouts", async ({
  page,
}) => {
  const injection = '<img src=x onerror="window.caseInjected=true">';
  const calls = await mockCases(page, async (route, url) => {
    const body = caseCollectionFixture();
    body.case.purpose = injection;
    if (url.search) {
      body.items = [
        caseItemFixture("expired", OTHER_ARTIFACT_ID),
        caseItemFixture("deleted", OTHER_ARTIFACT_ID.replace(/12$/, "13")),
        caseItemFixture("unavailable", OTHER_ARTIFACT_ID.replace(/12$/, "14")),
      ];
    } else {
      body.items = [
        { ...caseItemFixture("active", ARTIFACT_ID), added_by: injection },
      ];
      body.truncated = true;
      body.next_cursor = CASE_CURSOR;
    }
    await route.fulfill({ json: body });
  });
  await connectCases(page);
  await browseCase(page);
  await expect(page.getByText(injection, { exact: true })).toHaveCount(2);
  await expect(page.locator(".case-workbench img")).toHaveCount(0);
  await page.getByRole("button", { name: "下一页证据" }).click();
  await expect(
    page.getByText("expired · 已到期", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText("deleted · 已删除", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText("unavailable · 目录不可用", { exact: true }),
  ).toBeVisible();
  expect(calls.at(-1)?.path).toBe(
    `/control/v1/cases/${CASE_ID}/items?cursor=${encodeURIComponent(CASE_CURSOR)}`,
  );
  await expect(page.getByRole("button", { name: "下一页证据" })).toBeDisabled();
  for (const width of [1536, 390]) {
    await page.setViewportSize({ width, height: 1024 });
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
    if (process.env.XSHIELD_CONSOLE_SCREENSHOT_DIR) {
      await page.screenshot({
        path: resolve(
          process.env.XSHIELD_CONSOLE_SCREENSHOT_DIR,
          `cases-${width}.png`,
        ),
        fullPage: true,
      });
    }
  }
});

for (const failure of ["network", "service", "decode"] as const) {
  test(`case ${failure} failure keeps the exact frozen request across navigation`, async ({
    page,
  }) => {
    const calls = await mockCases(page, async (route, _url, count) => {
      if (count === 1) {
        if (failure === "network") await route.abort("connectionreset");
        else if (failure === "service")
          await route.fulfill({
            status: 503,
            json: errorFixture("CONTROL_CASE_STORE_UNAVAILABLE"),
          });
        else
          await route.fulfill({
            status: 201,
            json: { ...caseCreatedFixture(), purpose: "wrong purpose" },
          });
      } else
        await route.fulfill({
          status: 200,
          json: caseCreatedFixture(CASE_PURPOSE, true),
        });
    });
    await connectCases(page);
    await createCase(page);
    await expect(
      page.getByRole("heading", { name: "操作结果未知" }),
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: "准备新操作" }),
    ).toBeDisabled();
    await expect(page.getByLabel("幂等键", { exact: true })).toHaveAttribute(
      "readonly",
      "",
    );
    await expect(page.getByLabel("调查目的", { exact: true })).toBeDisabled();
    await openView(page, "search");
    await openView(page, "case");
    await expect(
      page.getByRole("heading", { name: "操作结果未知" }),
    ).toBeVisible();
    expect(calls).toHaveLength(1);
    await page.getByRole("button", { name: "原样重试" }).click();
    await expect(
      page.getByRole("heading", { name: "创建案件已确认" }),
    ).toBeVisible();
    expect(calls[1]).toEqual(calls[0]);
    await expect(
      page.getByText("true（返回原操作结果）", { exact: true }),
    ).toBeVisible();
  });
}

test("case read needs Investigator while metadata performs independent Observer authorization", async ({
  page,
}) => {
  const calls = await mockCases(page, async (route, url) => {
    if (url.pathname.includes("/artifacts/"))
      await route.fulfill({
        status: 403,
        json: errorFixture("CONTROL_SCOPE_DENIED"),
      });
    else {
      const body = caseCollectionFixture();
      body.items = [caseItemFixture()];
      await route.fulfill({ json: body });
    }
  });
  await connectCases(page);
  await browseCase(page);
  await expect(
    page.getByText("active · 目录有效", { exact: true }),
  ).toBeVisible();
  expect(calls).toHaveLength(1);
  await page.getByRole("button", { name: "查看元数据（需 Observer）" }).click();
  await expect(page.getByText(/CONTROL_SCOPE_DENIED/)).toBeVisible();
  expect(calls.at(-1)?.path).toBe(`/control/v1/artifacts/${OTHER_ARTIFACT_ID}`);
  expect(calls).toHaveLength(2);
});

test("case denial shows stable audit diagnostics and permits deliberate correction", async ({
  page,
}) => {
  await mockCases(page, async (route) =>
    route.fulfill({ status: 403, json: errorFixture("CONTROL_SCOPE_DENIED") }),
  );
  await connectCases(page);
  await createCase(page);
  await expect(
    page.getByRole("heading", { name: "本次请求被拒绝" }),
  ).toBeVisible();
  await expect(page.getByText(/CONTROL_SCOPE_DENIED/)).toBeVisible();
  await expect(page.getByRole("button", { name: "准备新操作" })).toBeEnabled();
});

test("case timeout preserves payload and a later denial keeps the original uncertainty", async ({
  page,
}) => {
  await page.clock.install();
  let release!: () => void;
  const delayed = new Promise<void>((resolveReady) => {
    release = resolveReady;
  });
  const calls = await mockCases(page, async (route, _url, count) => {
    if (count === 1) {
      await delayed;
      await route.fulfill({ status: 201, json: caseCreatedFixture() });
    } else
      await route.fulfill({
        status: 403,
        json: errorFixture("CONTROL_SCOPE_DENIED"),
      });
  });
  await connectCases(page);
  await createCase(page);
  await expect.poll(() => calls.length).toBe(1);
  await page.clock.fastForward(15_001);
  await expect(
    page.getByRole("heading", { name: "操作结果未知" }),
  ).toBeVisible();
  await expect(page.getByText(/REQUEST_TIMEOUT/)).toBeVisible();
  release();
  await page.getByRole("button", { name: "原样重试" }).click();
  await expect(page.getByText(/CONTROL_SCOPE_DENIED/)).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "操作结果未知" }),
  ).toBeVisible();
  await expect(page.getByRole("button", { name: "准备新操作" })).toBeDisabled();
  expect(calls[1]).toEqual(calls[0]);
});

test("case close can be recovered after reconnect with the original key and reason", async ({
  page,
}) => {
  const calls = await mockCases(page, async (route, url) => {
    if (url.pathname.endsWith("/close"))
      await route.fulfill({ json: caseClosedFixture(true) });
    else {
      const body = caseCollectionFixture();
      body.case.status = "closed";
      await route.fulfill({ json: body });
    }
  });
  await connectCases(page);
  await browseCase(page);
  await expect(
    page.getByText("案件已关闭，历史证据引用仍可浏览。", { exact: true }),
  ).toBeVisible();
  await page.getByLabel("操作", { exact: true }).selectOption("close");
  await page.getByLabel("关闭理由", { exact: true }).fill("保存的原关闭理由");
  await page.getByLabel("幂等键", { exact: true }).fill(CASE_KEY);
  await page.getByRole("button", { name: "关闭案件", exact: true }).click();
  await expect(
    page.getByText("true（返回原操作结果）", { exact: true }),
  ).toBeVisible();
  expect(calls[1]).toEqual({
    path: `/control/v1/cases/${CASE_ID}/close`,
    method: "POST",
    key: CASE_KEY,
    body: { reason: "保存的原关闭理由" },
  });
});

for (const [action, lookup] of [
  ["add", "new lookup"],
  ["close", "new lookup"],
  ["add", "case list selection"],
  ["close", "case list selection"],
] as const) {
  test(`case ${action} retry stays bound to the original case after a ${lookup}`, async ({
    page,
  }) => {
    const calls = await mockCases(page, async (route, url, count) => {
      if (route.request().method() === "GET")
        await route.fulfill({
          json:
            url.pathname === "/control/v1/cases"
              ? caseListFixture()
              : caseCollectionFixture(
                  url.pathname.includes(OTHER_CASE_ID)
                    ? OTHER_CASE_ID
                    : CASE_ID,
                ),
        });
      else if (count === 2) await route.abort("connectionreset");
      else
        await route.fulfill({
          json:
            action === "add"
              ? caseItemAddedFixture(ARTIFACT_ID, true)
              : caseClosedFixture(true),
        });
    });
    await connectCases(page);
    await browseCase(page);
    await expect(
      page.getByText("当前案件尚无证据引用。", { exact: true }),
    ).toBeVisible();
    await page.getByLabel("操作", { exact: true }).selectOption(action);
    await page
      .getByLabel(action === "add" ? "证据 ID" : "关闭理由", { exact: true })
      .fill(action === "add" ? ARTIFACT_ID : "原关闭理由");
    await page.getByLabel("幂等键", { exact: true }).fill(CASE_KEY);
    await page
      .getByRole("button", {
        name: action === "add" ? "加入证据" : "关闭案件",
        exact: true,
      })
      .click();
    await expect(
      page.getByRole("heading", { name: "操作结果未知" }),
    ).toBeVisible();
    if (lookup === "case list selection") {
      await page
        .getByRole("button", { name: "读取我的案件 / 刷新列表" })
        .click();
      await page
        .getByRole("button", { name: `打开案件 ${OTHER_CASE_ID}` })
        .click();
    } else await browseCase(page, OTHER_CASE_ID);
    await expect(
      page.getByText("当前案件尚无证据引用。", { exact: true }),
    ).toBeVisible();
    await expect(page.getByLabel("案件 ID", { exact: true })).toHaveValue(
      OTHER_CASE_ID,
    );
    await expect(
      page.getByRole("heading", { name: "操作结果未知" }),
    ).toBeVisible();
    expect(calls[1]).toEqual({
      path: `/control/v1/cases/${CASE_ID}/${action === "add" ? "items" : "close"}`,
      method: "POST",
      key: CASE_KEY,
      body:
        action === "add"
          ? { artifact_id: ARTIFACT_ID }
          : { reason: "原关闭理由" },
    });
    await page.getByRole("button", { name: "原样重试" }).click();
    await expect(
      page.getByText("true（返回原操作结果）", { exact: true }),
    ).toBeVisible();
    expect(calls).toHaveLength(lookup === "case list selection" ? 5 : 4);
    expect(calls.at(-1)).toEqual(calls[1]);
  });
}

test("case forms enforce UTF-8 limits and exact IDs before transport", async ({
  page,
}) => {
  const calls = await mockCases(page, async (route) =>
    route.fulfill({ json: caseCollectionFixture() }),
  );
  await connectCases(page);
  await page.getByLabel("调查目的", { exact: true }).fill("中".repeat(171));
  await expect(
    page.getByRole("button", { name: "创建案件", exact: true }),
  ).toBeDisabled();
  await page.getByLabel("调查目的", { exact: true }).fill(" leading-space");
  await expect(
    page.getByRole("button", { name: "创建案件", exact: true }),
  ).toBeDisabled();
  await page.getByLabel("调查目的", { exact: true }).fill(CASE_PURPOSE);
  await page.getByLabel("幂等键", { exact: true }).fill("short");
  await expect(
    page.getByRole("button", { name: "创建案件", exact: true }),
  ).toBeDisabled();
  await page.getByLabel("案件 ID", { exact: true }).fill("case_invalid");
  await expect(
    page.getByRole("button", { name: "读取案件 / 刷新首页", exact: true }),
  ).toBeDisabled();
  expect(calls).toHaveLength(0);
});

test("case scope mismatch disconnects before displaying mutation data", async ({
  page,
}) => {
  await mockCases(page, async (route, _url, count) => {
    await route.fulfill({
      status: count === 1 ? 200 : 201,
      json:
        count === 1
          ? caseCollectionFixture()
          : { ...caseCreatedFixture(), tenant_id: "other_tenant" },
    });
  });
  await connectCases(page);
  await browseCase(page);
  await expect(
    page.getByText("当前案件尚无证据引用。", { exact: true }),
  ).toBeVisible();
  await createCase(page);
  await expect(
    page.getByRole("heading", { name: "连接管理服务" }),
  ).toBeVisible();
  await expect(page.getByText("响应范围校验失败，连接已断开。")).toBeVisible();
  await expect(page.getByText(CASE_PURPOSE, { exact: true })).toHaveCount(0);
});

test("case late mutation response cannot repaint after navigation and retains retry identity", async ({
  page,
}) => {
  let release!: () => void;
  const ready = new Promise<void>((resolveReady) => {
    release = resolveReady;
  });
  const calls = await mockCases(page, async (route) => {
    await ready;
    await route.fulfill({ status: 201, json: caseCreatedFixture() });
  });
  await connectCases(page);
  await createCase(page);
  await expect.poll(() => calls.length).toBe(1);
  await openView(page, "request");
  release();
  await openView(page, "case");
  await expect(
    page.getByRole("heading", { name: "操作结果未知" }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "创建案件已确认" }),
  ).toHaveCount(0);
  await expect(page.getByLabel("幂等键", { exact: true })).toHaveValue(
    CASE_KEY,
  );
});

test("case edited target discards stale collection and cursor", async ({
  page,
}) => {
  let release!: () => void;
  const ready = new Promise<void>((resolveReady) => {
    release = resolveReady;
  });
  const calls = await mockCases(page, async (route) => {
    await ready;
    await route.fulfill({ json: caseCollectionFixture() });
  });
  await connectCases(page);
  await browseCase(page);
  await expect.poll(() => calls.length).toBe(1);
  await page.getByLabel("案件 ID", { exact: true }).fill(OTHER_CASE_ID);
  release();
  await expect(page.getByText(CASE_PURPOSE, { exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "下一页证据" })).toHaveCount(0);
});

for (const end of ["401", "disconnect", "pagehide", "idle"] as const) {
  test(`case ${end} clears frozen session state`, async ({ page }) => {
    if (end === "idle") await page.clock.install();
    await mockCases(page, async (route, _url, count) => {
      if (end === "401" && count > 1)
        await route.fulfill({
          status: 401,
          json: errorFixture("CONTROL_AUTH_REQUIRED"),
        });
      else await route.abort("connectionreset");
    });
    await connectCases(page);
    await createCase(page);
    await expect(
      page.getByRole("heading", { name: "操作结果未知" }),
    ).toBeVisible();
    if (end === "401")
      await page.getByRole("button", { name: "原样重试" }).click();
    else if (end === "disconnect")
      await page.getByRole("button", { name: "断开连接" }).click();
    else if (end === "pagehide")
      await page.evaluate(() =>
        window.dispatchEvent(new PageTransitionEvent("pagehide")),
      );
    else await page.clock.fastForward(15 * 60 * 1000 + 1);
    await expect(
      page.getByRole("heading", { name: "连接管理服务" }),
    ).toBeVisible();
    await expect(page.getByText(CASE_KEY, { exact: true })).toHaveCount(0);
    await page.getByLabel("管理凭证", { exact: true }).fill(TOKEN);
    await page.getByRole("button", { name: "连接", exact: true }).click();
    await openView(page, "case");
    await expect(page.getByLabel("调查目的", { exact: true })).toHaveValue("");
    await expect(page.getByLabel("幂等键", { exact: true })).not.toHaveValue(
      CASE_KEY,
    );
  });
}
