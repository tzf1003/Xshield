import { expect, test, type Page, type Request } from "@playwright/test";
import { resolve } from "node:path";
import {
  ARTIFACT_ID,
  EVIDENCE_CURSOR,
  EVENT_CURSOR,
  OTHER_ARTIFACT_ID,
  OTHER_REQUEST_ID,
  MODEL_CALL_ID,
  OTHER_MODEL_CALL_ID,
  REQUEST_ID,
  TOKEN,
  artifactFixture,
  errorFixture,
  eventsFixture,
  evidenceFixture,
  summaryFixture,
  modelCallFixture,
} from "./fixtures";

type Reply = { status?: number; body: unknown };
type Override = (url: URL) => Reply | undefined | Promise<Reply | undefined>;

/** Browser checks exercise the real client with explicit synthetic HTTP responses. */
async function mockControl(page: Page, override?: Override) {
  const calls: {
    path: string;
    method: string;
    authorized: boolean;
    cookie: string | null;
  }[] = [];
  await page.route("**/control/v1/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    calls.push({
      path: `${url.pathname}${url.search}`,
      method: request.method(),
      authorized:
        (await request.headerValue("authorization")) === `Bearer ${TOKEN}`,
      cookie: await request.headerValue("cookie"),
    });
    const custom = await override?.(url);
    let reply: Reply;
    if (custom) reply = custom;
    else if (url.pathname.startsWith("/control/v1/model-calls/")) {
      reply = { body: modelCallFixture(url.pathname.split("/").at(-1)) };
    } else if (url.pathname.startsWith("/control/v1/artifacts/")) {
      reply = { body: artifactFixture(url.pathname.split("/").at(-1)) };
    } else {
      const id = url.pathname.split("/")[4];
      if (url.pathname.endsWith("/events")) {
        reply = { body: eventsFixture(id, url.searchParams.has("cursor")) };
      } else if (url.pathname.endsWith("/evidence")) {
        reply = { body: evidenceFixture(id, url.searchParams.has("cursor")) };
      } else reply = { body: summaryFixture(id) };
    }
    await route.fulfill({
      status: reply.status ?? 200,
      json: reply.body,
      headers: { "cache-control": "private, no-store" },
    });
  });
  return calls;
}

async function connect(page: Page) {
  await page.goto("/");
  await page.getByLabel("管理凭证", { exact: true }).fill(TOKEN);
  await page.getByRole("button", { name: "连接", exact: true }).click();
}

async function query(page: Page, requestId = REQUEST_ID) {
  await page.getByLabel("请求 ID", { exact: true }).fill(requestId);
  await page.getByRole("button", { name: "查询", exact: true }).click();
}

async function queryModel(page: Page, modelCallId = MODEL_CALL_ID) {
  await page.getByLabel("查询类型", { exact: true }).selectOption("model");
  await page.getByLabel("模型调用 ID", { exact: true }).fill(modelCallId);
  await page.getByRole("button", { name: "查询", exact: true }).click();
}

test("queries model lifecycle and opens only reference metadata", async ({
  page,
}) => {
  const runtimeErrors: string[] = [];
  page.on("pageerror", (error) => runtimeErrors.push(error.message));
  const calls = await mockControl(page);
  await connect(page);
  await queryModel(page, "invalid-model-id");
  expect(calls).toHaveLength(0);
  await queryModel(page);
  await expect(
    page.getByRole("heading", { name: "模型调用调查", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText("vercel_ai_gateway", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText("typesafe-ai/jev", { exact: true }),
  ).toBeVisible();
  await expect(page.getByText("0.8", { exact: true }).first()).toBeVisible();
  await expect(page.getByText(/评估完成不表示业务操作获准/)).toBeVisible();
  expect(calls.map((call) => call.path)).toEqual([
    `/control/v1/model-calls/${MODEL_CALL_ID}`,
  ]);
  await page
    .getByText("#3 · model.responded · success", { exact: true })
    .click();
  await expect(
    page
      .locator(".model-event[open]")
      .getByText("ev_018f2a3b-4c5d-7000-8000-000000000002", { exact: true }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: ARTIFACT_ID, exact: true })
    .first()
    .click();
  await expect(
    page.getByRole("region", { name: "模型证据详情" }),
  ).toContainText("application/json");
  await page.getByRole("button", { name: "关闭详情", exact: true }).click();
  await expect(page.getByRole("region", { name: "模型证据详情" })).toHaveCount(
    0,
  );
  expect(
    calls.every(
      (call) =>
        call.method === "GET" && call.authorized && call.cookie === null,
    ),
  ).toBe(true);
  expect(calls.some((call) => call.path.endsWith("/content"))).toBe(false);
  await expect(page.locator("vite-error-overlay")).toHaveCount(0);
  expect(
    await page.evaluate(() => [localStorage.length, sessionStorage.length]),
  ).toEqual([0, 0]);
  for (const width of [1536, 390]) {
    await page.setViewportSize({ width, height: 1024 });
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= window.innerWidth,
      ),
    ).toBe(true);
    if (width === 390) {
      const heading = await page
        .getByRole("heading", { name: "模型调用", exact: true })
        .boundingBox();
      const identity = await page
        .locator(".model-heading > .mono")
        .boundingBox();
      expect(
        heading && identity && heading.height < 30 && identity.y > heading.y,
      ).toBeTruthy();
    }
    const screenshotDirectory = process.env.XSHIELD_CONSOLE_SCREENSHOT_DIR;
    if (screenshotDirectory)
      await page.screenshot({
        path: resolve(screenshotDirectory, `model-${width}.png`),
        fullPage: true,
      });
  }
  expect(runtimeErrors).toEqual([]);
});

test("model query preserves partial Noul history and unknown absence", async ({
  page,
}) => {
  await mockControl(page, (url) => {
    if (!url.pathname.includes("/model-calls/")) return undefined;
    const value = modelCallFixture(url.pathname.split("/").at(-1));
    if (url.pathname.endsWith(OTHER_MODEL_CALL_ID))
      return {
        body: {
          ...value,
          found: false,
          completeness: "not_indexed",
          model_call: null,
        },
      };
    for (const item of [value.model_call, ...value.model_call.events])
      Object.assign(item, {
        provider: null,
        provider_model_id: null,
        question_type: "noul",
        confidence: null,
        confidence_status: "not_applicable",
      });
    value.model_call.events = value.model_call.events.slice(-1);
    value.model_call.lifecycle_complete = false;
    value.completeness = "partial";
    return { body: value };
  });
  await connect(page);
  await queryModel(page);
  await expect(
    page.getByText("生命周期部分可见", { exact: true }),
  ).toBeVisible();
  await expect(page.getByText("不适用", { exact: true }).first()).toBeVisible();
  await expect(
    page.getByText("历史记录未提供", { exact: true }).first(),
  ).toBeVisible();
  await queryModel(page, OTHER_MODEL_CALL_ID);
  await expect(
    page.getByText("当前索引未找到调用", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText(/尚未发布、不存在、已过期或不在当前作用域/),
  ).toBeVisible();
  await expect(page.getByText("MODEL_EVALUATED", { exact: true })).toHaveCount(
    0,
  );
});

test("model 401 and scope drift dispose the authenticated session", async ({
  page,
}) => {
  let drift = false;
  await mockControl(page, (url) =>
    url.pathname.includes("/model-calls/")
      ? drift
        ? { body: { ...modelCallFixture(), site_id: "site_other" } }
        : { status: 401, body: errorFixture("CONTROL_AUTH_REQUIRED") }
      : undefined,
  );
  await connect(page);
  await queryModel(page);
  await expect(page.getByRole("status")).toContainText("管理凭证已失效");
  await expect(page.getByLabel("管理凭证", { exact: true })).toHaveValue("");
  drift = true;
  await page.getByLabel("管理凭证", { exact: true }).fill(TOKEN);
  await page.getByRole("button", { name: "连接", exact: true }).click();
  await query(page);
  await expect(
    page.getByText("AUTH_BINDING_VALID", { exact: true }),
  ).toBeVisible();
  await queryModel(page);
  await expect(page.getByRole("status")).toContainText("响应范围校验失败");
  await expect(
    page.getByText("vercel_ai_gateway", { exact: true }),
  ).toHaveCount(0);
  await expect(page.getByText(REQUEST_ID, { exact: true })).toHaveCount(0);
});

test("switching to a request discards a late model response", async ({
  page,
}) => {
  let release = () => {};
  const delayed = new Promise<void>((resolve) => {
    release = resolve;
  });
  let arrive = () => {};
  const arrived = new Promise<void>((resolve) => {
    arrive = resolve;
  });
  await mockControl(page, async (url) => {
    if (!url.pathname.includes("/model-calls/")) return undefined;
    arrive();
    await delayed;
    return { body: modelCallFixture() };
  });
  await connect(page);
  const settled = requestSettled(
    page,
    `/control/v1/model-calls/${MODEL_CALL_ID}`,
  );
  await queryModel(page);
  await arrived;
  await page.getByLabel("查询类型", { exact: true }).selectOption("request");
  await query(page);
  await expect(
    page.getByText("AUTH_BINDING_VALID", { exact: true }),
  ).toBeVisible();
  release();
  await settled;
  await paint(page);
  await expect(
    page.getByText("vercel_ai_gateway", { exact: true }),
  ).toHaveCount(0);
  await expect(page.getByLabel("请求 ID", { exact: true })).toHaveValue(
    REQUEST_ID,
  );
});

test("model query budget failures remain explicit and require manual retry", async ({
  page,
}) => {
  await page.clock.install();
  const calls = await mockControl(page, () => ({
    status: 429,
    body: errorFixture("CONTROL_QUERY_BUDGET_EXCEEDED"),
  }));
  await connect(page);
  await queryModel(page);
  await expect(page.getByRole("alert")).toContainText(
    "CONTROL_QUERY_BUDGET_EXCEEDED",
  );
  await expect(page.getByRole("alert")).toContainText(
    "查询超出服务预算，请联系管理员。",
  );
  await page.clock.fastForward(60_000);
  expect(calls).toHaveLength(1);
  await expect(
    page.getByText("Synthetic server detail must not be rendered"),
  ).toHaveCount(0);
});

async function selectEvidenceEvent(page: Page) {
  const row = page
    .getByRole("row")
    .filter({ hasText: "ev_018f2a3b-4c5d-7000-8000-000000000003" });
  await row.getByRole("radio").check();
}

function requestSettled(page: Page, path: string) {
  return new Promise<void>((resolve) => {
    const finish = (request: Request) => {
      if (new URL(request.url()).pathname !== path) return;
      page.off("requestfinished", finish);
      page.off("requestfailed", finish);
      resolve();
    };
    page.on("requestfinished", finish);
    page.on("requestfailed", finish);
  });
}

async function paint(page: Page) {
  await page.evaluate(
    () =>
      new Promise<void>((resolve) =>
        requestAnimationFrame(() => requestAnimationFrame(() => resolve())),
      ),
  );
}

test("connects in memory and queries the summary before the timeline", async ({
  page,
}) => {
  const runtimeErrors: string[] = [];
  page.on("pageerror", (error) => runtimeErrors.push(error.message));
  const calls = await mockControl(page);
  await connect(page);
  expect(calls).toHaveLength(0);
  await query(page, "invalid-request-id");
  expect(calls).toHaveLength(0);
  await page
    .context()
    .addCookies([
      { name: "business_session", value: "synthetic", url: page.url() },
    ]);
  await query(page);
  await expect(
    page.getByText("AUTH_BINDING_VALID", { exact: true }),
  ).toBeVisible();
  expect(calls.map((call) => call.path)).toEqual([
    `/control/v1/requests/${REQUEST_ID}`,
    `/control/v1/requests/${REQUEST_ID}/events`,
  ]);
  expect(
    calls.every(
      (call) =>
        call.authorized && call.method === "GET" && call.cookie === null,
    ),
  ).toBe(true);
  await expect(page).toHaveTitle(/Xshield/);
  await expect(
    page.getByRole("heading", { name: "请求调查", exact: true }),
  ).toBeVisible();
  await expect(page.locator("vite-error-overlay")).toHaveCount(0);
  await expect(
    page.getByText("tenant_demo", { exact: false }).first(),
  ).toBeVisible();
  await expect(page.getByText(/2.*待发布段/)).toBeVisible();
  await expect(
    page.getByText("当前结果可能不完整；水位仅代表配置的日志源。", {
      exact: true,
    }),
  ).toBeVisible();
  await expect(page.getByText("不适用", { exact: true })).toBeVisible();
  expect(page.url()).not.toContain(TOKEN);
  expect(calls.every((call) => !call.path.includes(TOKEN))).toBe(true);
  expect(
    await page.evaluate(() => [localStorage.length, sessionStorage.length]),
  ).toEqual([0, 0]);
  const screenshotDirectory = process.env.XSHIELD_CONSOLE_SCREENSHOT_DIR;
  if (screenshotDirectory) {
    await page.setViewportSize({ width: 1536, height: 1024 });
    await page.screenshot({
      path: resolve(screenshotDirectory, "desktop.png"),
      fullPage: false,
    });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({
      path: resolve(screenshotDirectory, "mobile.png"),
      fullPage: false,
    });
  }
  expect(runtimeErrors).toEqual([]);
});

test("replaces an event page only after explicit pagination", async ({
  page,
}) => {
  const calls = await mockControl(page);
  await connect(page);
  await query(page);
  await expect(
    page.getByText("AUTH_BINDING_VALID", { exact: true }),
  ).toBeVisible();
  expect(calls).toHaveLength(2);
  await page.getByRole("button", { name: "下一页", exact: true }).click();
  await expect(
    page.getByText("REQUEST_DENIED", { exact: true }).first(),
  ).toBeVisible();
  await expect(
    page.getByText("AUTH_BINDING_VALID", { exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: "下一页", exact: true }),
  ).toBeDisabled();
  expect(calls.at(-1)?.path).toBe(
    `/control/v1/requests/${REQUEST_ID}/events?cursor=${EVENT_CURSOR}`,
  );
});

test("loads evidence lazily, pages references and opens safe metadata", async ({
  page,
}) => {
  const calls = await mockControl(page);
  await connect(page);
  await query(page);
  await selectEvidenceEvent(page);
  await page.getByRole("button", { name: ARTIFACT_ID, exact: true }).click();
  await expect(
    page.getByText("application/json", { exact: true }).first(),
  ).toBeVisible();
  await expect(page.getByText("已脱敏", { exact: true }).first()).toBeVisible();
  expect(calls.filter((call) => call.path.endsWith("/evidence"))).toHaveLength(
    0,
  );
  await page.getByRole("tab", { name: "证据引用", exact: true }).click();
  await expect(
    page.getByRole("button", { name: ARTIFACT_ID, exact: true }).first(),
  ).toBeVisible();
  await page.getByRole("button", { name: "下一页", exact: true }).click();
  await expect(
    page.getByRole("button", { name: OTHER_ARTIFACT_ID, exact: true }),
  ).toBeVisible();
  expect(calls.at(-1)?.path).toBe(
    `/control/v1/requests/${REQUEST_ID}/evidence?cursor=${EVIDENCE_CURSOR}`,
  );
  await expect(
    page.getByText("synthetic-vault-object.bin", { exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByText("synthetic-key-ref", { exact: true }),
  ).toHaveCount(0);
  await expect(page.getByText("a".repeat(64), { exact: true })).toHaveCount(0);
  expect(calls.some((call) => call.path.endsWith("/content"))).toBe(false);
});

test("renders an unavailable artifact as a catalog state", async ({ page }) => {
  await mockControl(page, (url) =>
    url.pathname.includes("/artifacts/")
      ? { body: { ...artifactFixture(), found: false, artifact: null } }
      : undefined,
  );
  await connect(page);
  await query(page);
  await selectEvidenceEvent(page);
  await page.getByRole("button", { name: ARTIFACT_ID, exact: true }).click();
  await expect(page.getByText(/当前不可用/)).toBeVisible();
  await expect(
    page.getByText("synthetic-vault-object.bin", { exact: true }),
  ).toHaveCount(0);
});

test("distinguishes an empty index from an index still publishing", async ({
  page,
}) => {
  await mockControl(page, (url) => {
    if (url.pathname.endsWith("/events"))
      return {
        body: {
          ...eventsFixture(url.pathname.split("/")[4]),
          events: [],
          truncated: false,
          next_cursor: null,
        },
      };
    const pending = url.pathname.endsWith(OTHER_REQUEST_ID);
    return {
      body: {
        ...summaryFixture(pending ? OTHER_REQUEST_ID : REQUEST_ID),
        found: false,
        summary: null,
        has_gaps: pending,
        pending_segments: pending ? 2 : 0,
        completeness: pending ? "pending_index" : "not_found",
        index_watermark: null,
      },
    };
  });
  await connect(page);
  await query(page);
  await expect(page.getByText("当前未找到请求", { exact: true })).toBeVisible();
  await expect(
    page.getByText("UI_ACTION_NOT_AVAILABLE", { exact: true }),
  ).toHaveCount(0);
  await query(page, OTHER_REQUEST_ID);
  await expect(page.getByText(/2.*待发布段/)).toBeVisible();
  await expect(page.getByText("索引待就绪", { exact: true })).toBeVisible();
});

test("preserves missing decisions and supports keyboard investigation tabs", async ({
  page,
}) => {
  await mockControl(page, (url) => {
    if (
      url.pathname !== `/control/v1/requests/${REQUEST_ID}` &&
      url.pathname !== `/control/v1/requests/${OTHER_REQUEST_ID}`
    )
      return undefined;
    const response = summaryFixture(url.pathname.split("/")[4]);
    return {
      body: {
        ...response,
        summary: {
          ...response.summary,
          decision: url.pathname.endsWith(OTHER_REQUEST_ID) ? "UNKNOWN" : null,
        },
      },
    };
  });
  await connect(page);
  await query(page);
  await expect(page.getByText("判定未记录", { exact: true })).toBeVisible();
  await expect(page.getByText("UNKNOWN · 未知", { exact: true })).toHaveCount(
    0,
  );
  const eventsTab = page.getByRole("tab", { name: "事件时间线", exact: true });
  const evidenceTab = page.getByRole("tab", { name: "证据引用", exact: true });
  await eventsTab.focus();
  for (const [key, target, other] of [
    ["ArrowRight", evidenceTab, eventsTab],
    ["Home", eventsTab, evidenceTab],
    ["End", evidenceTab, eventsTab],
    ["ArrowRight", eventsTab, evidenceTab],
    ["ArrowLeft", evidenceTab, eventsTab],
  ] as const) {
    await page.keyboard.press(key);
    await expect(target).toBeFocused();
    await expect(target).toHaveAttribute("aria-selected", "true");
    await expect(target).toHaveAttribute("tabindex", "0");
    await expect(other).toHaveAttribute("aria-selected", "false");
    await expect(other).toHaveAttribute("tabindex", "-1");
  }
  await query(page, OTHER_REQUEST_ID);
  await expect(page.getByText("UNKNOWN · 未知", { exact: true })).toBeVisible();
  await expect(page.getByText("判定未记录", { exact: true })).toHaveCount(0);
});

test("clears authenticated state after a 401 response", async ({ page }) => {
  let expired = false;
  const calls = await mockControl(page, () =>
    expired
      ? { status: 401, body: errorFixture("CONTROL_AUTH_REQUIRED") }
      : undefined,
  );
  await connect(page);
  await query(page);
  await expect(
    page.getByText("AUTH_BINDING_VALID", { exact: true }),
  ).toBeVisible();
  expired = true;
  await page.getByRole("button", { name: "下一页", exact: true }).click();
  await expect(page.getByLabel("管理凭证", { exact: true })).toHaveValue("");
  await expect(
    page.getByRole("button", { name: "连接", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText("AUTH_BINDING_VALID", { exact: true }),
  ).toHaveCount(0);
  await expect(page.getByText(REQUEST_ID, { exact: true })).toHaveCount(0);
  expect(
    await page.evaluate(() => [localStorage.length, sessionStorage.length]),
  ).toEqual([0, 0]);
  expect(calls).toHaveLength(3);
});

test("clears the session after fifteen idle minutes and after a reload", async ({
  page,
}) => {
  await page.clock.install();
  const calls = await mockControl(page);
  await connect(page);
  await query(page);
  await expect(
    page.getByText("AUTH_BINDING_VALID", { exact: true }),
  ).toBeVisible();
  await page.clock.fastForward(15 * 60_000 + 1);
  await expect(page.getByRole("status")).toContainText("会话已因闲置断开");
  await expect(page.getByLabel("管理凭证", { exact: true })).toHaveValue("");
  await expect(
    page.getByText("AUTH_BINDING_VALID", { exact: true }),
  ).toHaveCount(0);
  await expect(page.getByText(REQUEST_ID, { exact: true })).toHaveCount(0);
  await page.getByLabel("管理凭证", { exact: true }).fill(TOKEN);
  await page.getByRole("button", { name: "连接", exact: true }).click();
  await query(page);
  await expect(
    page.getByText("AUTH_BINDING_VALID", { exact: true }),
  ).toBeVisible();
  await page.reload();
  await expect(page.getByLabel("管理凭证", { exact: true })).toHaveValue("");
  await expect(
    page.getByRole("button", { name: "连接", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText("AUTH_BINDING_VALID", { exact: true }),
  ).toHaveCount(0);
  await expect(page.getByLabel("请求 ID", { exact: true })).toHaveCount(0);
  expect(
    await page.evaluate(() => [localStorage.length, sessionStorage.length]),
  ).toEqual([0, 0]);
  expect(calls).toHaveLength(4);
});

test("shows 403 and 429 with explicit retry control", async ({ page }) => {
  await page.clock.install();
  let status = 403;
  const calls = await mockControl(page, () => ({
    status,
    body: errorFixture(
      status === 403 ? "CONTROL_SCOPE_DENIED" : "CONTROL_RATE_LIMITED",
    ),
  }));
  await connect(page);
  await query(page);
  await expect(page.getByRole("alert")).toContainText("CONTROL_SCOPE_DENIED");
  await page.clock.fastForward(60_000);
  expect(calls).toHaveLength(1);
  status = 429;
  await query(page);
  await expect(page.getByRole("alert")).toContainText("CONTROL_RATE_LIMITED");
  await page.clock.fastForward(60_000);
  expect(calls).toHaveLength(2);
  await expect(
    page.getByText("Synthetic server detail must not be rendered"),
  ).toHaveCount(0);
});

test("switching requests prevents an earlier timeline from reappearing", async ({
  page,
}) => {
  let release = () => {};
  const delayed = new Promise<void>((resolve) => {
    release = resolve;
  });
  let arrive = () => {};
  const arrived = new Promise<void>((resolve) => {
    arrive = resolve;
  });
  await mockControl(page, async (url) => {
    if (url.pathname === `/control/v1/requests/${REQUEST_ID}/events`) {
      arrive();
      await delayed;
      return { body: eventsFixture() };
    }
    if (url.pathname === `/control/v1/requests/${OTHER_REQUEST_ID}/events`) {
      return { body: eventsFixture(OTHER_REQUEST_ID, true) };
    }
    return undefined;
  });
  await connect(page);
  const settled = requestSettled(
    page,
    `/control/v1/requests/${REQUEST_ID}/events`,
  );
  await query(page);
  await arrived;
  await query(page, OTHER_REQUEST_ID);
  await expect(
    page.getByText("REQUEST_DENIED", { exact: true }).first(),
  ).toBeVisible();
  release();
  await settled;
  await paint(page);
  await expect(
    page.getByText("AUTH_BINDING_VALID", { exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByText(OTHER_REQUEST_ID, { exact: true }).first(),
  ).toBeVisible();
});

test("disconnecting keeps a late response outside the new session", async ({
  page,
}) => {
  let release = () => {};
  const delayed = new Promise<void>((resolve) => {
    release = resolve;
  });
  let arrive = () => {};
  const arrived = new Promise<void>((resolve) => {
    arrive = resolve;
  });
  await mockControl(page, async () => {
    arrive();
    await delayed;
    return { body: summaryFixture() };
  });
  await connect(page);
  const settled = requestSettled(page, `/control/v1/requests/${REQUEST_ID}`);
  await query(page);
  await arrived;
  await page.getByRole("button", { name: "断开连接", exact: true }).click();
  release();
  await settled;
  await paint(page);
  await expect(page.getByLabel("管理凭证", { exact: true })).toHaveValue("");
  await expect(
    page.getByRole("button", { name: "连接", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText("UI_ACTION_NOT_AVAILABLE", { exact: true }),
  ).toHaveCount(0);
});

test("changing event selection or page discards an earlier artifact result", async ({
  page,
}) => {
  let release = () => {};
  let arrive = () => {};
  let delayed = Promise.resolve();
  await mockControl(page, async (url) => {
    if (!url.pathname.includes("/artifacts/")) return undefined;
    arrive();
    await delayed;
    return { body: artifactFixture() };
  });
  await connect(page);
  await query(page);
  for (const action of ["select", "page"]) {
    await selectEvidenceEvent(page);
    delayed = new Promise<void>((resolve) => {
      release = resolve;
    });
    const arrived = new Promise<void>((resolve) => {
      arrive = resolve;
    });
    const settled = requestSettled(
      page,
      `/control/v1/artifacts/${ARTIFACT_ID}`,
    );
    await page.getByRole("button", { name: ARTIFACT_ID, exact: true }).click();
    await arrived;
    if (action === "select") {
      await page
        .getByRole("row")
        .filter({ hasText: "ev_018f2a3b-4c5d-7000-8000-000000000001" })
        .getByRole("radio")
        .check();
    } else
      await page.getByRole("button", { name: "下一页", exact: true }).click();
    release();
    await settled;
    await paint(page);
    await expect(
      page.getByText("application/json", { exact: true }),
    ).toHaveCount(0);
    await expect(page.getByText("正在读取证据元数据…")).toHaveCount(0);
  }
});

test("rejects a timeline from a different server scope", async ({ page }) => {
  await mockControl(page, (url) =>
    url.pathname.endsWith("/events")
      ? { body: { ...eventsFixture(), tenant_id: "tenant_other" } }
      : undefined,
  );
  await connect(page);
  await query(page);
  await expect(page.getByRole("status")).toContainText("响应范围校验失败");
  await expect(
    page.getByRole("button", { name: "连接", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText("AUTH_BINDING_VALID", { exact: true }),
  ).toHaveCount(0);
  await expect(page.getByText("tenant_other", { exact: true })).toHaveCount(0);
});

test("treats metadata text as data and keeps desktop and mobile layouts bounded", async ({
  page,
}) => {
  const injected = '<img src=x onerror="window.xshieldInjected=true">';
  await mockControl(page, (url) => {
    if (!url.pathname.includes("/artifacts/")) return undefined;
    const response = artifactFixture();
    response.artifact.content_type = injected;
    return { body: response };
  });
  await page.setViewportSize({ width: 1536, height: 1024 });
  await connect(page);
  await query(page);
  await selectEvidenceEvent(page);
  await page.getByRole("button", { name: ARTIFACT_ID, exact: true }).click();
  await expect(page.getByText(injected, { exact: true })).toBeVisible();
  expect(
    await page.evaluate(() => Reflect.get(window, "xshieldInjected")),
  ).toBeUndefined();
  await expect(page.locator("main img")).toHaveCount(0);
  for (const width of [1536, 390]) {
    await page.setViewportSize({ width, height: 1024 });
    await expect(
      page.getByRole("heading", { name: "请求调查", exact: true }),
    ).toBeVisible();
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= window.innerWidth,
      ),
    ).toBe(true);
    const button = await page
      .getByRole("button", { name: "查询", exact: true })
      .boundingBox();
    expect(
      button && button.x >= 0 && button.x + button.width <= width,
    ).toBeTruthy();
  }
});
