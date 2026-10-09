import { expect, type Page, test } from "@playwright/test";
import { type Call, mockControl, paint, requestSettled, sent } from "./control-mock";
import {
  AGENT_RUN_ID,
  ARTIFACT_ID,
  CALIBRATION_REPORT_ID,
  agentRunFixture,
  calibrationReportFixture,
  errorFixture,
  MODEL_CALL_ID,
  modelCallFixture,
  OTHER_MODEL_CALL_ID,
  REQUEST_ID,
  THIRD_MODEL_CALL_ID,
} from "./fixtures";
import { expectPrefilled, pasteId, signInQuietly } from "./investigation-helpers";
import { openView } from "./navigation";
import { signIn } from "./shell-helpers";

// The picker works in local time; a UTC browser clock makes the typed text the plan's text.
test.use({ timezoneId: "UTC" });

const paths = (calls: Call[]) => calls.map((call) => call.path);
const listCalls = (calls: Call[]) =>
  calls.filter(
    (call) => new URL(`http://console.test${call.path}`).pathname === "/control/v1/model-calls",
  );
const event = (n: number) => `ev_018f2a3b-4c5d-7000-8000-${String(n).padStart(12, "0")}`;
const results = (page: Page) => page.getByRole("region", { name: "模型调用列表结果", exact: true });
const rows = (page: Page) => results(page).locator(".ant-table-row");
const modelRegion = (page: Page) => page.getByRole("region", { name: "模型调用详情", exact: true });
const index = (page: Page, label: string) => page.getByRole("status", { name: label });

async function pickModelRange(page: Page, limit = "10") {
  await page.getByRole("button", { name: "自定义", exact: true }).click();
  await page.getByLabel("开始时间（本地，含）", { exact: true }).fill("2026-09-20T00:00");
  await page.getByLabel("结束时间（本地，不含）", { exact: true }).fill("2026-09-21T00:00");
  await page.getByLabel("每页条数", { exact: true }).click();
  await page
    .locator(".ant-select-dropdown:not(.ant-select-dropdown-hidden)")
    .getByTitle(limit, { exact: true })
    .click();
}

test.describe("model call list", () => {
  test("lists calls in a window, appends pages and reauthorizes the clicked detail", async ({
    page,
  }) => {
    const calls = await mockControl(page);
    await signInQuietly(page);
    await openView(page, "model-list");
    await expect(page.getByRole("heading", { name: "模型调用", exact: true })).toBeVisible();
    await paint(page);
    expect(calls).toHaveLength(0);
    await pickModelRange(page);
    await page.getByRole("button", { name: "读取模型调用", exact: true }).click();
    await expect(rows(page)).toHaveCount(10);
    await expect(results(page).getByText("MODEL_EVALUATED", { exact: true })).toBeVisible();
    // The list carries no numeric confidence; only its availability.
    await expect(results(page).getByText("0.8", { exact: true })).toHaveCount(0);
    await expect(index(page, "模型调用列表索引状态")).toContainText("索引存在缺口 · 2 个待发布段");
    await page.getByRole("button", { name: "加载更多", exact: true }).click();
    await expect(rows(page)).toHaveCount(11);
    await expect(results(page)).toContainText("已加载 11 条");
    await page.getByRole("link", { name: THIRD_MODEL_CALL_ID, exact: true }).click();
    await expect(page.getByRole("heading", { name: "模型调用调查", exact: true })).toBeVisible();
    await expect
      .poll(() => paths(sent(calls)).at(-1))
      .toBe(`/control/v1/model-calls/${THIRD_MODEL_CALL_ID}`);
    const lists = listCalls(sent(calls));
    expect(lists).toHaveLength(2);
    for (const call of lists) {
      const url = new URL(`http://console.test${call.path}`);
      expect(url.searchParams.get("start")).toBe("2026-09-20T00:00:00Z");
      expect(url.searchParams.get("end")).toBe("2026-09-21T00:00:00Z");
      expect(url.searchParams.get("limit")).toBe("10");
      expect(call.authorized).toBe(true);
      expect(call.cookie).toBeNull();
    }
    expect(new URL(`http://console.test${lists[0]?.path}`).searchParams.has("cursor")).toBe(false);
    expect(new URL(`http://console.test${lists[1]?.path}`).searchParams.has("cursor")).toBe(true);
  });

  test("a preset window is converted when it is pressed: whole UTC seconds, 24 hours", async ({
    page,
  }) => {
    const calls = await mockControl(page);
    await signInQuietly(page);
    await openView(page, "model-list");
    await expect(page.getByRole("button", { name: "24 小时", exact: true })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    await page.getByRole("button", { name: "读取模型调用", exact: true }).click();
    await expect(rows(page)).toHaveCount(25);
    const url = new URL(`http://console.test${listCalls(calls)[0]?.path}`);
    const start = url.searchParams.get("start") as string;
    const end = url.searchParams.get("end") as string;
    expect(start).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
    expect(end).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
    expect(Date.parse(end) - Date.parse(start)).toBe(24 * 60 * 60 * 1000);
    expect(url.searchParams.get("limit")).toBe("25");
  });

  test("the plan and scan facts can be read, and editing retires the rows", async ({ page }) => {
    await mockControl(page);
    await signInQuietly(page);
    await openView(page, "model-list");
    await pickModelRange(page, "25");
    await page.getByRole("button", { name: "读取模型调用", exact: true }).click();
    await expect(rows(page)).toHaveCount(25);
    await page.getByText("已提交列表条件", { exact: true }).click();
    const plan = page.getByRole("region", { name: "已提交模型调用列表条件" });
    await expect(plan).toContainText("2026-09-20T00:00:00Z");
    await expect(plan.locator("tr").filter({ hasText: "每页条数" })).toContainText("25");
    await expect(plan.locator("tr").filter({ hasText: "实际扫描行" })).toContainText("24");
    await page.getByLabel("每页条数", { exact: true }).click();
    await page
      .locator(".ant-select-dropdown:not(.ant-select-dropdown-hidden)")
      .getByTitle("50", { exact: true })
      .click();
    await expect(results(page)).toHaveCount(0);
    await expect(plan).toHaveCount(0);
  });

  test("a range that is missing or too long is refused before transport", async ({ page }) => {
    const calls = await mockControl(page);
    await signInQuietly(page);
    await openView(page, "model-list");
    await page.getByRole("button", { name: "自定义", exact: true }).click();
    await page.getByLabel("开始时间（本地，含）", { exact: true }).fill("2026-09-01T00:00");
    await page.getByLabel("结束时间（本地，不含）", { exact: true }).fill("2026-10-22T00:00");
    await expect(page.getByText("时间范围不能超过 31 天。")).toBeVisible();
    await page.getByRole("button", { name: "读取模型调用", exact: true }).click();
    await expect(page.getByRole("alert")).toContainText("CONTROL_MODEL_CALLS_REQUEST_INVALID");
    expect(calls).toHaveLength(0);
  });

  test("the ID box opens a call, bad IDs send nothing and the old lookup address redirects", async ({
    page,
  }) => {
    const calls = await mockControl(page);
    await signIn(page, "/investigation/models/lookup");
    await expect(page).toHaveURL(/\/investigation\/models$/);
    await expect(page.getByLabel("模型调用 ID", { exact: true })).toBeVisible();
    for (const bad of ["invalid-model-id", MODEL_CALL_ID.toUpperCase(), "req_x"]) {
      await page.getByLabel("模型调用 ID", { exact: true }).fill(bad);
      await page.getByRole("button", { name: "打开", exact: true }).click();
      await expect(page.getByText(/请输入规范的模型调用 ID/)).toBeVisible();
    }
    expect(calls).toHaveLength(0);
    await page.getByLabel("模型调用 ID", { exact: true }).fill(`  ${MODEL_CALL_ID} `);
    await page.getByRole("button", { name: "打开", exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`/investigation/models/${MODEL_CALL_ID}$`));
    await expect(modelRegion(page)).toContainText(MODEL_CALL_ID);
    expect(paths(calls)).toEqual([`/control/v1/model-calls/${MODEL_CALL_ID}`]);
  });

  test("a failed list read stays explicit and waits for the operator", async ({ page }) => {
    await page.clock.install();
    const calls = await mockControl(page, (url) =>
      url.pathname === "/control/v1/model-calls"
        ? { status: 429, body: errorFixture("CONTROL_QUERY_BUDGET_EXCEEDED") }
        : undefined,
    );
    await signInQuietly(page);
    await openView(page, "model-list");
    await pickModelRange(page);
    await page.getByRole("button", { name: "读取模型调用", exact: true }).click();
    await expect(page.getByRole("alert")).toContainText("CONTROL_QUERY_BUDGET_EXCEEDED");
    await page.clock.fastForward(60_000);
    expect(listCalls(calls)).toHaveLength(1);
    await expect(page.getByText("Synthetic server detail must not be rendered")).toHaveCount(0);
  });
});

test.describe("model call detail", () => {
  test("shows the lifecycle and provider facts and opens only reference metadata", async ({
    page,
  }) => {
    const runtimeErrors: string[] = [];
    page.on("pageerror", (error) => runtimeErrors.push(error.message));
    const calls = await mockControl(page);
    await signInQuietly(page);
    await pasteId(page, "invalid-model-id");
    expect(calls).toHaveLength(0);
    await pasteId(page, MODEL_CALL_ID);
    await expect(page.getByRole("heading", { name: "模型调用调查", exact: true })).toBeVisible();
    await expect(page.getByText("vercel_ai_gateway", { exact: true })).toBeVisible();
    await expect(page.getByText("typesafe-ai/jev", { exact: true })).toBeVisible();
    await expect(page.getByText("0.8", { exact: true }).first()).toBeVisible();
    await expect(page.getByText(/评估完成不表示业务操作获准/)).toBeVisible();
    await expect(index(page, "模型查询索引状态")).toContainText("生命周期完整");
    expect(paths(calls)).toEqual([`/control/v1/model-calls/${MODEL_CALL_ID}`]);
    // The lifecycle opens event by event; the predecessor of the response is the request.
    await page.getByText("#3 · model.responded · success", { exact: true }).click();
    await expect(page.getByText(event(2), { exact: true }).first()).toBeVisible();
    await page.getByRole("button", { name: ARTIFACT_ID, exact: true }).first().click();
    await expect(page.getByRole("dialog", { name: "证据元数据" })).toContainText(
      "application/json",
    );
    await page.keyboard.press("Escape");
    await expect(page.getByRole("dialog", { name: "证据元数据" })).toHaveCount(0);
    expect(
      calls
        .filter((call) => !call.path.includes("/artifacts/"))
        .every((call) => call.method === "GET" && call.authorized && call.cookie === null),
    ).toBe(true);
    expect(calls.some((call) => call.path.endsWith("/content"))).toBe(false);
    await expect(page.locator("vite-error-overlay")).toHaveCount(0);
    expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0]);
    for (const width of [1536, 390]) {
      await page.setViewportSize({ width, height: 1024 });
      await expect
        .poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth))
        .toBe(true);
    }
    expect(runtimeErrors).toEqual([]);
  });

  test("a score question keeps its lifecycle and the provider's own confidence", async ({
    page,
  }) => {
    await mockControl(page, (url) => {
      if (!url.pathname.includes("/model-calls/")) return undefined;
      const value = modelCallFixture();
      for (const item of [value.model_call, ...value.model_call.events]) {
        Object.assign(item, { question_type: "score", score: 73 });
      }
      return { body: value };
    });
    await signInQuietly(page);
    await pasteId(page, MODEL_CALL_ID);
    await expect(page.getByText("score", { exact: true })).toBeVisible();
    await expect(page.getByText("0.8", { exact: true }).first()).toBeVisible();
    // A score is not part of the redacted projection and is never shown.
    await expect(page.getByText("73", { exact: true })).toHaveCount(0);
    await expect(page.getByText("#3 · model.responded · success", { exact: true })).toBeVisible();
    await page.getByRole("button", { name: ARTIFACT_ID, exact: true }).first().click();
    await expect(page.getByRole("dialog", { name: "证据元数据" })).toContainText(
      "application/json",
    );
  });

  test("partial Noul history keeps 无置信度 and an unknown absence stays unknown", async ({
    page,
  }) => {
    await mockControl(page, (url) => {
      if (!url.pathname.includes("/model-calls/")) return undefined;
      const value = modelCallFixture(url.pathname.split("/").at(-1));
      if (url.pathname.endsWith(OTHER_MODEL_CALL_ID)) {
        return { body: { ...value, found: false, completeness: "not_indexed", model_call: null } };
      }
      for (const item of [value.model_call, ...value.model_call.events]) {
        Object.assign(item, {
          provider: null,
          provider_model_id: null,
          question_type: "noul",
          confidence: null,
          confidence_status: "not_applicable",
        });
      }
      value.model_call.events = value.model_call.events.slice(-1);
      value.model_call.lifecycle_complete = false;
      value.completeness = "partial";
      return { body: value };
    });
    await signInQuietly(page);
    await pasteId(page, MODEL_CALL_ID);
    await expect(index(page, "模型查询索引状态")).toContainText("生命周期部分可见");
    await expect(page.getByText(/无置信度/).first()).toBeVisible();
    await expect(page.getByText("不适用", { exact: true }).first()).toBeVisible();
    await expect(page.getByText("历史记录未提供", { exact: true }).first()).toBeVisible();
    await pasteId(page, OTHER_MODEL_CALL_ID);
    await expect(index(page, "模型查询索引状态")).toContainText("当前索引未找到调用");
    await expect(page.getByText(/尚未发布、不存在、已过期或不在当前作用域/)).toBeVisible();
    await expect(page.getByText("MODEL_EVALUATED", { exact: true })).toHaveCount(0);
  });

  test("history and predecessor links prepare a search without running it", async ({ page }) => {
    const calls = await mockControl(page);
    await signInQuietly(page);
    await pasteId(page, MODEL_CALL_ID);
    await page.getByRole("button", { name: "准备历史检索", exact: true }).click();
    await expectPrefilled(page, "模型调用 ID", MODEL_CALL_ID);
    expect(paths(calls)).toEqual([`/control/v1/model-calls/${MODEL_CALL_ID}`]);
    await pasteId(page, MODEL_CALL_ID);
    await page.getByText("#2 · model.requested · requested", { exact: true }).click();
    await page.getByRole("button", { name: event(1), exact: true }).click();
    await expectPrefilled(page, "事件 ID", event(1));
    expect(listCalls(calls)).toHaveLength(0);
  });

  test("401 and a foreign scope end the session", async ({ page }) => {
    let mode: "expired" | "drift" = "expired";
    await mockControl(page, (url) =>
      url.pathname.includes("/model-calls/")
        ? mode === "expired"
          ? { status: 401, body: errorFixture("CONTROL_AUTH_REQUIRED") }
          : { body: { ...modelCallFixture(), site_id: "site_other" } }
        : undefined,
    );
    await signInQuietly(page);
    await pasteId(page, MODEL_CALL_ID);
    await expect(page.getByRole("status").filter({ hasText: "管理会话已失效" })).toBeVisible();
    await expect(page.getByLabel("管理凭证", { exact: true })).toHaveValue("");
    // The first valid reply of a machine-login session confirms the scope; a later foreign one
    // ends the session instead of being shown.
    mode = "drift";
    await signIn(page, "/access/session");
    await pasteId(page, REQUEST_ID);
    await expect(page.getByText("AUTH_BINDING_VALID", { exact: true })).toBeVisible();
    await pasteId(page, MODEL_CALL_ID);
    await expect(page.getByRole("status").filter({ hasText: "响应范围校验失败" })).toBeVisible();
    await expect(page.getByText("vercel_ai_gateway", { exact: true })).toHaveCount(0);
    await expect(page.getByText(REQUEST_ID, { exact: true })).toHaveCount(0);
  });

  test("switching to a request discards a late model response", async ({ page }) => {
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
    await signInQuietly(page);
    const settled = requestSettled(page, `/control/v1/model-calls/${MODEL_CALL_ID}`);
    await pasteId(page, MODEL_CALL_ID);
    await arrived;
    await pasteId(page, REQUEST_ID);
    await expect(page.getByText("AUTH_BINDING_VALID", { exact: true })).toBeVisible();
    release();
    await settled;
    await paint(page);
    await expect(page.getByText("vercel_ai_gateway", { exact: true })).toHaveCount(0);
    await expect(page.getByRole("region", { name: "关键事实" })).toContainText(REQUEST_ID);
  });

  test("budget failures stay explicit and wait for a manual retry", async ({ page }) => {
    await page.clock.install();
    const calls = await mockControl(page, () => ({
      status: 429,
      body: errorFixture("CONTROL_QUERY_BUDGET_EXCEEDED"),
    }));
    await signInQuietly(page);
    await pasteId(page, MODEL_CALL_ID);
    await expect(page.getByRole("alert")).toContainText("CONTROL_QUERY_BUDGET_EXCEEDED");
    await expect(page.getByRole("alert")).toContainText(
      "查询超出服务预算，请缩小时间范围或细化条件",
    );
    await page.clock.fastForward(60_000);
    expect(calls).toHaveLength(1);
    await expect(page.getByText("Synthetic server detail must not be rendered")).toHaveCount(0);
    await page.getByRole("button", { name: "重新读取", exact: true }).click();
    await expect.poll(() => calls.length).toBe(2);
  });
});

test.describe("agent run", () => {
  test("reads the redacted lifecycle and prepares scoped history", async ({ page }) => {
    const calls = await mockControl(page);
    await signInQuietly(page);
    await openView(page, "agent");
    await expect(page.getByLabel("Agent 运行 ID", { exact: true })).toBeVisible();
    expect(sent(calls)).toHaveLength(0);
    await pasteId(page, "invalid-agent-id");
    await pasteId(page, AGENT_RUN_ID);
    await expect(page.getByRole("heading", { name: "Agent 运行调查", exact: true })).toBeVisible();
    await expect(page.getByRole("region", { name: "Agent 运行详情", exact: true })).toContainText(
      AGENT_RUN_ID,
    );
    await expect(page.getByText(/agent\.tool_called/)).toBeVisible();
    await expect(page.getByText("tool_args", { exact: true })).toHaveCount(0);
    await expect(index(page, "Agent 查询索引状态")).toContainText("生命周期完整");
    await page.getByRole("button", { name: "准备历史检索", exact: true }).click();
    await expectPrefilled(page, "Agent 运行 ID", AGENT_RUN_ID);
    expect(paths(sent(calls))).toEqual([`/control/v1/agent-runs/${AGENT_RUN_ID}`]);
  });

  test("the ID box checks the shape and a missing run is stated as such", async ({ page }) => {
    const calls = await mockControl(page, (url) =>
      url.pathname.includes("/agent-runs/")
        ? { body: agentRunFixture(AGENT_RUN_ID, false) }
        : undefined,
    );
    await signInQuietly(page);
    await openView(page, "agent");
    await page.getByLabel("Agent 运行 ID", { exact: true }).fill("agt_bad");
    await page.getByRole("button", { name: "查询", exact: true }).click();
    await expect(page.getByText(/请输入规范的Agent 运行 ID/)).toBeVisible();
    expect(calls).toHaveLength(0);
    await page.getByLabel("Agent 运行 ID", { exact: true }).fill(AGENT_RUN_ID);
    await page.getByRole("button", { name: "查询", exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`/investigation/agents/${AGENT_RUN_ID}$`));
    await expect(index(page, "Agent 查询索引状态")).toContainText("当前索引未找到运行");
    await expect(page.getByText(/这不推断其他范围或保留窗口中的历史/)).toBeVisible();
  });
});

test.describe("calibration report", () => {
  test("reads restricted metadata without creating a content path", async ({ page }) => {
    const calls = await mockControl(page);
    await signInQuietly(page);
    await pasteId(page, CALIBRATION_REPORT_ID);
    const details = page.getByRole("region", { name: "校准报告详情", exact: true });
    await expect(details).toContainText(CALIBRATION_REPORT_ID);
    await expect(details).toContainText("报告正文 tombstone");
    await expect(details).toContainText("active（未记录终态删除）");
    await expect(
      page.getByText(/不显示或读取报告正文、样本、标签、概率、指标、提示词/),
    ).toBeVisible();
    expect(paths(sent(calls))).toEqual([
      `/control/v1/calibration-reports/${CALIBRATION_REPORT_ID}`,
    ]);
    expect(sent(calls).every((call) => call.authorized && call.cookie === null)).toBe(true);
    expect(sent(calls).some((call) => call.path.includes("/content"))).toBe(false);
    await page.getByRole("button", { name: "手动刷新报告", exact: true }).click();
    await expect.poll(() => sent(calls).length).toBe(2);
    await page.getByRole("button", { name: "准备历史检索", exact: true }).click();
    await expectPrefilled(page, "校准报告 ID", CALIBRATION_REPORT_ID);
    expect(sent(calls)).toHaveLength(2);
  });

  test("a missing report is stated without implying it exists elsewhere", async ({ page }) => {
    await mockControl(page, (url) =>
      url.pathname.includes("/calibration-reports/")
        ? { body: calibrationReportFixture(CALIBRATION_REPORT_ID, false) }
        : undefined,
    );
    await signInQuietly(page);
    await pasteId(page, CALIBRATION_REPORT_ID);
    await expect(page.getByText("当前范围内未找到报告", { exact: true })).toBeVisible();
    await expect(page.getByText(/不推断报告不存在于其他范围/)).toBeVisible();
  });

  test("reads discard expired, scope-drifting and late state", async ({ page }) => {
    let mode: "expired" | "drift" | "delayed" = "expired";
    let release = () => {};
    const delayed = new Promise<void>((resolve) => {
      release = resolve;
    });
    let arrive = () => {};
    const arrivedReport = new Promise<void>((resolve) => {
      arrive = resolve;
    });
    await mockControl(page, async (url) => {
      if (!url.pathname.startsWith("/control/v1/calibration-reports/")) return undefined;
      if (mode === "expired") return { status: 401, body: errorFixture("CONTROL_AUTH_REQUIRED") };
      if (mode === "drift") {
        return { body: { ...calibrationReportFixture(), site_id: "site_other" } };
      }
      arrive();
      await delayed;
      return { body: calibrationReportFixture() };
    });
    await signInQuietly(page);
    await pasteId(page, CALIBRATION_REPORT_ID);
    await expect(page.getByRole("status").filter({ hasText: "管理会话已失效" })).toBeVisible();
    await expect(page.getByLabel("管理凭证", { exact: true })).toHaveValue("");

    mode = "drift";
    await signIn(page, "/access/session");
    await pasteId(page, REQUEST_ID);
    await expect(page.getByText("AUTH_BINDING_VALID", { exact: true })).toBeVisible();
    await pasteId(page, CALIBRATION_REPORT_ID);
    await expect(page.getByRole("status").filter({ hasText: "响应范围校验失败" })).toBeVisible();
    await expect(page.getByRole("region", { name: "校准报告详情" })).toHaveCount(0);

    mode = "delayed";
    await signIn(page, "/access/session");
    const settled = requestSettled(
      page,
      `/control/v1/calibration-reports/${CALIBRATION_REPORT_ID}`,
    );
    await pasteId(page, CALIBRATION_REPORT_ID);
    await arrivedReport;
    await pasteId(page, REQUEST_ID);
    await expect(page.getByText("AUTH_BINDING_VALID", { exact: true })).toBeVisible();
    release();
    await settled;
    await paint(page);
    await expect(page.getByRole("region", { name: "校准报告详情" })).toHaveCount(0);
  });
});
