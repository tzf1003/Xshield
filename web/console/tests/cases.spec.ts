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
  await page.goto("/");
  await page.getByLabel("管理凭证", { exact: true }).fill(TOKEN);
  await page.getByRole("button", { name: "连接", exact: true }).click();
  await page.getByLabel("查询类型", { exact: true }).selectOption("case");
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
  await expect(page).toHaveURL("http://127.0.0.1:5173/");
  await expect(page).toHaveTitle("调查控制台 · Xshield");
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
    await page.getByLabel("查询类型", { exact: true }).selectOption("search");
    await page.getByLabel("查询类型", { exact: true }).selectOption("case");
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

for (const action of ["add", "close"] as const) {
  test(`case ${action} retry stays bound to the original case after a new lookup`, async ({
    page,
  }) => {
    const calls = await mockCases(page, async (route, url, count) => {
      if (route.request().method() === "GET")
        await route.fulfill({
          json: caseCollectionFixture(
            url.pathname.includes(OTHER_CASE_ID) ? OTHER_CASE_ID : CASE_ID,
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
    await browseCase(page, OTHER_CASE_ID);
    await expect(
      page.getByText("当前案件尚无证据引用。", { exact: true }),
    ).toBeVisible();
    await page.getByRole("button", { name: "原样重试" }).click();
    await expect(
      page.getByText("true（返回原操作结果）", { exact: true }),
    ).toBeVisible();
    expect(calls[3]).toEqual(calls[1]);
    expect(calls[3]?.path).toContain(CASE_ID);
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
  await page.getByLabel("查询类型", { exact: true }).selectOption("request");
  release();
  await page.getByLabel("查询类型", { exact: true }).selectOption("case");
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
    await page.getByLabel("查询类型", { exact: true }).selectOption("case");
    await expect(page.getByLabel("调查目的", { exact: true })).toHaveValue("");
    await expect(page.getByLabel("幂等键", { exact: true })).not.toHaveValue(
      CASE_KEY,
    );
  });
}
