import { openView } from "./navigation";
import { expectPrefilled, pickRange, submitSearch } from "./investigation-helpers";
import { expect, test, type Page } from "@playwright/test";
import { resolve } from "node:path";
import {
  ARTIFACT_ID,
  MODEL_CALL_ID,
  AGENT_RUN_ID,
  OTHER_MODEL_CALL_ID,
  THIRD_MODEL_CALL_ID,
  CALIBRATION_REPORT_ID,
  REQUEST_ID,
  TOKEN,
  errorFixture,
  auditHealthFixture,
  calibrationReportFixture,
  modelCallFixture,
  SEARCH_PLAN,
} from "./fixtures";
import { mockControl, paint, requestSettled } from "./control-mock";
import { EXPORT_CASE_ID, EXPORT_ID, exportFixture } from "./export-fixtures";
import {
  BINDING_ID,
  GRANT_ID,
  OTHER_BINDING_ID,
  OTHER_GRANT_ID,
  bindingFixture,
  grantFixture,
} from "./ledger-fixtures";

async function connect(page: Page) {
  // The audit-status page reads nothing until asked, so call counts start at zero, and it keeps
  // the legacy host mounted the way the previous request page did.
  await page.goto("/operations/audit");
  await page.getByLabel("管理凭证", { exact: true }).fill(TOKEN);
  await page.getByRole("button", { name: "连接", exact: true }).click();
}

/** Opens a request the way an operator pastes an ID: through the ⌘K palette. */
async function query(page: Page, requestId = REQUEST_ID) {
  await page.keyboard.press("Control+KeyK");
  const palette = page.getByRole("combobox", { name: "命令面板" });
  await palette.fill(requestId);
  await page.keyboard.press("Enter");
  // An ID the palette does not recognise leaves it open; close it so the next call starts clean.
  if (await palette.isVisible()) await page.keyboard.press("Escape");
}

async function queryModel(page: Page, modelCallId = MODEL_CALL_ID) {
  await openView(page, "model");
  await page.getByLabel("模型调用 ID", { exact: true }).fill(modelCallId);
  await page.getByRole("button", { name: "查询", exact: true }).click();
}

async function queryAgent(page: Page, agentRunId = AGENT_RUN_ID) {
  await openView(page, "agent");
  await page.getByLabel("Agent 运行 ID", { exact: true }).fill(agentRunId);
  await page.getByRole("button", { name: "查询", exact: true }).click();
}

async function queryAuditHealth(page: Page) {
  await openView(page, "audit-health");
  await page.getByRole("button", { name: "读取发布状态", exact: true }).click();
}

async function queryCalibrationReport(page: Page, reportId = CALIBRATION_REPORT_ID) {
  await openView(page, "calibration-report");
  await page.getByLabel("校准报告 ID", { exact: true }).fill(reportId);
  await page.getByRole("button", { name: "查询", exact: true }).click();
}

test("reads restricted calibration report metadata without creating a content path", async ({
  page,
}) => {
  const calls = await mockControl(page);
  await connect(page);
  await queryCalibrationReport(page);
  const details = page.getByRole("region", { name: "校准报告详情", exact: true });
  await expect(details).toContainText(CALIBRATION_REPORT_ID);
  await expect(details).toContainText("报告正文 tombstone");
  await expect(details).toContainText("active（未记录终态删除）");
  await expect(
    page.getByText(/不显示或读取报告正文、样本、标签、概率、指标、提示词/),
  ).toBeVisible();
  expect(calls.map((call) => call.path)).toEqual([
    `/control/v1/calibration-reports/${CALIBRATION_REPORT_ID}`,
  ]);
  expect(calls.every((call) => call.authorized && call.cookie === null)).toBe(true);
  expect(calls.some((call) => call.path.includes("/content"))).toBe(false);
  await page.getByRole("button", { name: "手动刷新报告", exact: true }).click();
  await expect.poll(() => calls.length).toBe(2);
  await page.getByRole("button", { name: "准备历史检索", exact: true }).click();
  await expectPrefilled(page, "校准报告 ID", CALIBRATION_REPORT_ID);
  expect(calls).toHaveLength(2);
});

test("export workbench waits for explicit submission before exposing package download", async ({
  page,
}) => {
  const calls = await mockControl(page, async (url, request) => {
    if (url.pathname === "/control/v1/exports" && request.method() === "POST")
      return { status: 202, body: exportFixture() };
    if (url.pathname === `/control/v1/exports/${EXPORT_ID}` && request.method() === "GET")
      return { body: exportFixture("ready") };
    return undefined;
  });
  await connect(page);
  await openView(page, "export");
  await expect(page.getByRole("heading", { name: "调查导出", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "申请元数据导出", exact: true })).toBeDisabled();
  expect(calls).toHaveLength(0);

  await page.getByLabel("导出案件 ID", { exact: true }).fill(EXPORT_CASE_ID);
  await page.getByLabel("导出调查用途", { exact: true }).fill("核对案件元数据");
  await page.getByLabel("导出幂等键", { exact: true }).fill("browser-export-operation-key");
  await page.getByRole("button", { name: "申请元数据导出", exact: true }).click();
  await expect(page.getByText("申请元数据导出已确认", { exact: true })).toBeVisible();
  expect(calls[0]?.path).toBe("/control/v1/exports");
  expect(calls[0]?.method).toBe("POST");
  expect(calls[0]?.body).toEqual({ case_id: EXPORT_CASE_ID, purpose: "核对案件元数据" });

  await page.getByRole("button", { name: "准备新操作", exact: true }).click();
  await page.getByLabel("导出状态 ID", { exact: true }).fill(EXPORT_ID);
  await page.getByRole("button", { name: "读取状态", exact: true }).click();
  await expect(page.getByText("ready", { exact: true })).toBeVisible();
  expect(calls.some((call) => call.path.endsWith("/download"))).toBe(false);
});

test("calibration report reads discard expired, scope-drifting, and late state", async ({
  page,
}) => {
  let mode: "expired" | "drift" | "delayed" = "expired";
  let release = () => {};
  const delayed = new Promise<void>((resolve) => {
    release = resolve;
  });
  let arrived = () => {};
  const arrivedReport = new Promise<void>((resolve) => {
    arrived = resolve;
  });
  await mockControl(page, async (url) => {
    if (!url.pathname.startsWith("/control/v1/calibration-reports/")) return undefined;
    if (mode === "expired") return { status: 401, body: errorFixture("CONTROL_AUTH_REQUIRED") };
    if (mode === "drift") return { body: { ...calibrationReportFixture(), site_id: "site_other" } };
    arrived();
    await delayed;
    return { body: calibrationReportFixture() };
  });
  await connect(page);
  await queryCalibrationReport(page);
  await expect(page.getByRole("status")).toContainText("管理会话已失效");
  await expect(page.getByLabel("管理凭证", { exact: true })).toHaveValue("");

  mode = "drift";
  await page.getByLabel("管理凭证", { exact: true }).fill(TOKEN);
  await page.getByRole("button", { name: "连接", exact: true }).click();
  await query(page);
  await expect(page.getByText("AUTH_BINDING_VALID", { exact: true })).toBeVisible();
  await queryCalibrationReport(page);
  await expect(page.getByRole("status")).toContainText("响应范围校验失败");
  await expect(page.getByRole("region", { name: "校准报告详情" })).toHaveCount(0);

  mode = "delayed";
  await page.getByLabel("管理凭证", { exact: true }).fill(TOKEN);
  await page.getByRole("button", { name: "连接", exact: true }).click();
  const settled = requestSettled(page, `/control/v1/calibration-reports/${CALIBRATION_REPORT_ID}`);
  await queryCalibrationReport(page);
  await arrivedReport;
  await openView(page, "request");
  await query(page);
  release();
  await settled;
  await paint(page);
  await expect(page.getByRole("region", { name: "校准报告详情" })).toHaveCount(0);
});

test("reads audit publication state only after an explicit manual action", async ({ page }) => {
  const calls = await mockControl(page);
  await connect(page);
  await openView(page, "audit-health");
  await expect(page.getByRole("heading", { name: "审计发布状态", exact: true })).toBeVisible();
  expect(calls).toHaveLength(0);
  await page.getByRole("button", { name: "读取发布状态", exact: true }).click();
  const result = page.getByRole("region", { name: "审计发布状态结果", exact: true });
  await expect(result).toContainText("clickhouse_primary");
  await expect(result).toContainText("audit_events");
  await expect(result).toContainText("未封存段");
  await expect(result).toContainText("1");
  await expect(page.getByText(/不代表业务准入、全部 Outbox 状态或系统整体健康/)).toBeVisible();
  await page.getByRole("button", { name: "手动刷新发布状态", exact: true }).click();
  const healthCalls = calls.filter((call) => call.path === "/control/v1/audit/health");
  expect(healthCalls).toHaveLength(2);
  expect(healthCalls.every((call) => call.authorized && call.cookie === null)).toBe(true);
});

test("audit publication reads discard expired, scope-drifting, and late state", async ({
  page,
}) => {
  let mode: "expired" | "drift" | "delayed" = "expired";
  let release = () => {};
  const delayed = new Promise<void>((resolve) => {
    release = resolve;
  });
  let arrived = () => {};
  const arrivedHealth = new Promise<void>((resolve) => {
    arrived = resolve;
  });
  await mockControl(page, async (url) => {
    if (url.pathname !== "/control/v1/audit/health") return undefined;
    if (mode === "expired") return { status: 401, body: errorFixture("CONTROL_AUTH_REQUIRED") };
    if (mode === "drift") return { body: { ...auditHealthFixture(), site_id: "site_other" } };
    arrived();
    await delayed;
    return { body: auditHealthFixture() };
  });
  await connect(page);
  await queryAuditHealth(page);
  await expect(page.getByRole("status")).toContainText("管理会话已失效");
  await expect(page.getByLabel("管理凭证", { exact: true })).toHaveValue("");

  mode = "drift";
  await page.getByLabel("管理凭证", { exact: true }).fill(TOKEN);
  await page.getByRole("button", { name: "连接", exact: true }).click();
  await query(page);
  await expect(page.getByText("AUTH_BINDING_VALID", { exact: true })).toBeVisible();
  await queryAuditHealth(page);
  await expect(page.getByRole("status")).toContainText("响应范围校验失败");
  await expect(page.getByRole("region", { name: "审计发布状态结果" })).toHaveCount(0);

  mode = "delayed";
  await page.getByLabel("管理凭证", { exact: true }).fill(TOKEN);
  await page.getByRole("button", { name: "连接", exact: true }).click();
  const settled = requestSettled(page, "/control/v1/audit/health");
  await queryAuditHealth(page);
  await arrivedHealth;
  await openView(page, "request");
  await query(page);
  await expect(page.getByText("AUTH_BINDING_VALID", { exact: true })).toBeVisible();
  release();
  await settled;
  await paint(page);
  await expect(page.getByRole("region", { name: "审计发布状态结果" })).toHaveCount(0);
});

test("queries model lifecycle and opens only reference metadata", async ({ page }) => {
  const runtimeErrors: string[] = [];
  page.on("pageerror", (error) => runtimeErrors.push(error.message));
  const calls = await mockControl(page);
  await connect(page);
  await queryModel(page, "invalid-model-id");
  expect(calls).toHaveLength(0);
  await queryModel(page);
  await expect(page.getByRole("heading", { name: "模型调用调查", exact: true })).toBeVisible();
  await expect(page.getByText("vercel_ai_gateway", { exact: true })).toBeVisible();
  await expect(page.getByText("typesafe-ai/jev", { exact: true })).toBeVisible();
  await expect(page.getByText("0.8", { exact: true }).first()).toBeVisible();
  await expect(page.getByText(/评估完成不表示业务操作获准/)).toBeVisible();
  expect(calls.map((call) => call.path)).toEqual([`/control/v1/model-calls/${MODEL_CALL_ID}`]);
  await page.getByText("#3 · model.responded · success", { exact: true }).click();
  await expect(
    page
      .locator(".model-event[open]")
      .getByText("ev_018f2a3b-4c5d-7000-8000-000000000002", { exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: ARTIFACT_ID, exact: true }).first().click();
  await expect(page.getByRole("region", { name: "模型证据详情" })).toContainText(
    "application/json",
  );
  await page.getByRole("button", { name: "关闭详情", exact: true }).click();
  await expect(page.getByRole("region", { name: "模型证据详情" })).toHaveCount(0);
  expect(
    calls.every((call) => call.method === "GET" && call.authorized && call.cookie === null),
  ).toBe(true);
  expect(calls.some((call) => call.path.endsWith("/content"))).toBe(false);
  await expect(page.locator("vite-error-overlay")).toHaveCount(0);
  expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0]);
  for (const width of [1536, 390]) {
    await page.setViewportSize({ width, height: 1024 });
    expect(
      await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
    ).toBe(true);
    if (width === 390) {
      const heading = await page
        .getByRole("heading", { name: "模型调用", exact: true })
        .boundingBox();
      const identity = await page.locator(".model-heading > .mono").boundingBox();
      expect(heading && identity && heading.height < 30 && identity.y > heading.y).toBeTruthy();
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

test("prepares scoped model call history without submitting a search", async ({ page }) => {
  const calls = await mockControl(page);
  await connect(page);
  await queryModel(page);
  await page.getByRole("button", { name: "准备历史检索", exact: true }).click();
  await expectPrefilled(page, "模型调用 ID", MODEL_CALL_ID);
  expect(calls.map((call) => call.path)).toEqual([`/control/v1/model-calls/${MODEL_CALL_ID}`]);
});

test("reads the redacted Agent lifecycle and prepares scoped history", async ({ page }) => {
  const calls = await mockControl(page);
  await connect(page);
  await queryAgent(page);
  await expect(page.getByRole("heading", { name: "Agent 运行调查", exact: true })).toBeVisible();
  await expect(page.getByRole("region", { name: "Agent 运行详情", exact: true })).toContainText(
    AGENT_RUN_ID,
  );
  await expect(page.getByText(/agent\.tool_called/)).toBeVisible();
  await expect(page.getByText("tool_args", { exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "准备历史检索", exact: true }).click();
  await expectPrefilled(page, "Agent 运行 ID", AGENT_RUN_ID);
  expect(calls.map((call) => call.path)).toEqual(["/control/v1/agent-runs/" + AGENT_RUN_ID]);
});

test("lists redacted model calls and reauthorizes the clicked detail", async ({ page }) => {
  const calls = await mockControl(page);
  await connect(page);
  await openView(page, "model-list");
  const form = page.getByRole("form", { name: "模型调用列表条件" });
  await form.getByLabel("开始时间（UTC，含）", { exact: true }).fill("2026-09-20T00:00");
  await form.getByLabel("结束时间（UTC，不含）", { exact: true }).fill("2026-09-21T00:00");
  await form.getByLabel("每页条数", { exact: true }).fill("2");
  await form.getByRole("button", { name: "读取模型调用", exact: true }).click();
  await expect(page.getByRole("heading", { name: "模型调用列表", exact: true })).toBeVisible();
  await expect(page.getByText("MODEL_EVALUATED", { exact: true })).toBeVisible();
  await expect(page.getByText("0.8", { exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "下一页", exact: true }).click();
  await expect(page.getByText(THIRD_MODEL_CALL_ID, { exact: true })).toBeVisible();
  await page.getByRole("button", { name: THIRD_MODEL_CALL_ID, exact: true }).click();
  await expect(page.getByRole("heading", { name: "模型调用调查", exact: true })).toBeVisible();
  const listCalls = calls.filter(
    (call) => new URL(`http://console.test${call.path}`).pathname === "/control/v1/model-calls",
  );
  expect(listCalls).toHaveLength(2);
  for (const call of listCalls) {
    const url = new URL(`http://console.test${call.path}`);
    expect(url.searchParams.get("start")).toBe("2026-09-20T00:00:00Z");
    expect(url.searchParams.get("end")).toBe("2026-09-21T00:00:00Z");
    expect(url.searchParams.get("limit")).toBe("2");
    expect(call.authorized).toBe(true);
    expect(call.cookie).toBeNull();
  }
  expect(
    listCalls[0] && new URL(`http://console.test${listCalls[0].path}`).searchParams.has("cursor"),
  ).toBe(false);
  expect(
    listCalls[1] && new URL(`http://console.test${listCalls[1].path}`).searchParams.has("cursor"),
  ).toBe(true);
  expect(calls.at(-1)?.path).toBe(`/control/v1/model-calls/${THIRD_MODEL_CALL_ID}`);
});

test("Score query displays lifecycle and independent provider confidence", async ({ page }) => {
  await mockControl(page, (url) => {
    if (!url.pathname.includes("/model-calls/")) return undefined;
    const value = modelCallFixture();
    for (const item of [value.model_call, ...value.model_call.events])
      Object.assign(item, { question_type: "score", score: 73 });
    return { body: value };
  });
  await connect(page);
  await queryModel(page);
  await expect(page.getByText("score", { exact: true })).toBeVisible();
  await expect(page.getByText("0.8", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("73", { exact: true })).toHaveCount(0);
  await expect(page.getByText("#3 · model.responded · success", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: ARTIFACT_ID, exact: true }).first().click();
  await expect(page.getByRole("region", { name: "模型证据详情" })).toContainText(
    "application/json",
  );
});

test("model query preserves partial Noul history and unknown absence", async ({ page }) => {
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
  await expect(page.getByText("生命周期部分可见", { exact: true })).toBeVisible();
  await expect(page.getByText("不适用", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("历史记录未提供", { exact: true }).first()).toBeVisible();
  await queryModel(page, OTHER_MODEL_CALL_ID);
  await expect(page.getByText("当前索引未找到调用", { exact: true })).toBeVisible();
  await expect(page.getByText(/尚未发布、不存在、已过期或不在当前作用域/)).toBeVisible();
  await expect(page.getByText("MODEL_EVALUATED", { exact: true })).toHaveCount(0);
});

test("model lifecycle predecessor links prepare exact event history", async ({ page }) => {
  const calls = await mockControl(page);
  await connect(page);
  await queryModel(page);
  await page.locator(".model-event").nth(1).locator("summary").click();
  const predecessor = "ev_018f2a3b-4c5d-7000-8000-000000000001";
  await page.getByRole("button", { name: predecessor, exact: true }).click();
  await expectPrefilled(page, "事件 ID", predecessor);
  expect(calls.map((call) => call.path)).toEqual([`/control/v1/model-calls/${MODEL_CALL_ID}`]);
});

test("model 401 and scope drift dispose the authenticated session", async ({ page }) => {
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
  await expect(page.getByRole("status")).toContainText("管理会话已失效");
  await expect(page.getByLabel("管理凭证", { exact: true })).toHaveValue("");
  drift = true;
  await page.getByLabel("管理凭证", { exact: true }).fill(TOKEN);
  await page.getByRole("button", { name: "连接", exact: true }).click();
  await query(page);
  await expect(page.getByText("AUTH_BINDING_VALID", { exact: true })).toBeVisible();
  await queryModel(page);
  await expect(page.getByRole("status")).toContainText("响应范围校验失败");
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
  await connect(page);
  const settled = requestSettled(page, `/control/v1/model-calls/${MODEL_CALL_ID}`);
  await queryModel(page);
  await arrived;
  await openView(page, "request");
  await query(page);
  await expect(page.getByText("AUTH_BINDING_VALID", { exact: true })).toBeVisible();
  release();
  await settled;
  await paint(page);
  await expect(page.getByText("vercel_ai_gateway", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("region", { name: "关键事实" })).toContainText(REQUEST_ID);
});

test("model query budget failures remain explicit and require manual retry", async ({ page }) => {
  await page.clock.install();
  const calls = await mockControl(page, () => ({
    status: 429,
    body: errorFixture("CONTROL_QUERY_BUDGET_EXCEEDED"),
  }));
  await connect(page);
  await queryModel(page);
  await expect(page.getByRole("alert")).toContainText("CONTROL_QUERY_BUDGET_EXCEEDED");
  await expect(page.getByRole("alert")).toContainText("查询超出服务预算，请缩小时间范围或细化条件");
  await page.clock.fastForward(60_000);
  expect(calls).toHaveLength(1);
  await expect(page.getByText("Synthetic server detail must not be rendered")).toHaveCount(0);
});

async function queryLedger(
  page: Page,
  kind: "grant" | "binding",
  id = kind === "grant" ? GRANT_ID : BINDING_ID,
) {
  await openView(page, kind);
  await page.getByLabel(kind === "grant" ? "资格 ID" : "身份绑定 ID", { exact: true }).fill(id);
  await page.getByRole("button", { name: "查询", exact: true }).click();
}

test("ledger grant and binding snapshots show independent facts and navigate known references", async ({
  page,
}) => {
  const calls = await mockControl(page);
  await connect(page);
  await queryLedger(page, "grant", "invalid-grant");
  expect(calls).toHaveLength(0);
  await queryLedger(page, "grant");
  const grant = page.getByRole("region", { name: "资格记录", exact: true });
  await expect(grant).toContainText("orders.read");
  await expect(grant.locator("dl > div").filter({ hasText: "持久状态" })).toContainText("active");
  await expect(grant.locator("dl > div").filter({ hasText: "时间到期" })).toContainText("未到期");
  await expect(grant.locator("dl > div").filter({ hasText: "发行身份代际" })).toContainText("4");
  await expect(page.getByText("2026-09-20T08:10:30.123456Z", { exact: true })).toBeVisible();
  await expect(page.getByRole("region", { name: "身份绑定记录", exact: true })).toContainText(
    "一致",
  );
  await expect(page.getByText(/实际请求仍须校验完整身份/)).toBeVisible();
  await expect(page.getByText(/查看水位|待发布段|ALLOW|已允许/)).toHaveCount(0);
  await page.getByRole("button", { name: BINDING_ID, exact: true }).click();
  await expect(page.getByRole("heading", { name: "身份绑定账本快照", exact: true })).toBeVisible();
  await expect(page.getByLabel("身份绑定 ID", { exact: true })).toHaveValue(BINDING_ID);
  await expect(
    page
      .getByRole("region", { name: "身份绑定记录", exact: true })
      .locator("dl > div")
      .filter({ hasText: "凭证代际" }),
  ).toContainText("2");
  await expect(page.getByText("2026-09-20T08:01:00.000000Z", { exact: true })).toBeVisible();
  await queryLedger(page, "grant");
  await page.getByRole("button", { name: REQUEST_ID, exact: true }).click();
  await expect(page.getByRole("heading", { name: "请求调查", exact: true })).toBeVisible();
  await expect(page.getByText("AUTH_BINDING_VALID", { exact: true })).toBeVisible();
  expect(calls.map((call) => call.path)).toEqual([
    `/control/v1/grants/${GRANT_ID}`,
    `/control/v1/auth-bindings/${BINDING_ID}`,
    `/control/v1/grants/${GRANT_ID}`,
    `/control/v1/requests/${REQUEST_ID}`,
    `/control/v1/requests/${REQUEST_ID}/events`,
  ]);
  expect(
    calls.every((call) => call.method === "GET" && call.authorized && call.cookie === null),
  ).toBe(true);
});

test.describe("ledger history", () => {
  // The picker works in local time; a UTC browser clock makes the typed text the plan's text.
  test.use({ timezoneId: "UTC" });

  test("ledger history navigation presets only the reference and requires an explicit UTC window and Investigator", async ({
    page,
  }) => {
    const calls = await mockControl(page, (url) =>
      url.pathname === "/control/v1/search"
        ? { status: 403, body: errorFixture("CONTROL_SCOPE_DENIED") }
        : undefined,
    );
    await connect(page);
    for (const kind of ["grant", "binding"] as const) {
      await queryLedger(page, kind);
      await page.getByRole("button", { name: "准备历史检索", exact: true }).click();
      await expectPrefilled(
        page,
        kind === "grant" ? "资格 ID" : "身份绑定 ID",
        kind === "grant" ? GRANT_ID : BINDING_ID,
      );
      const count = calls.length;
      // Without a range nothing is sent: the page asks for one.
      await submitSearch(page);
      await expect(page.getByRole("alert")).toContainText("请先选择时间范围");
      expect(calls).toHaveLength(count);
      await pickRange(page, "2026-09-20T00:00", "2026-09-21T00:00");
      await submitSearch(page);
      await expect(page.getByRole("alert")).toContainText("CONTROL_SCOPE_DENIED");
      expect(calls.at(-1)?.body).toEqual({
        ...SEARCH_PLAN,
        limit: 25,
        filters: [
          {
            kind: kind === "grant" ? "grant_id" : "auth_binding_id",
            value: kind === "grant" ? GRANT_ID : BINDING_ID,
          },
        ],
      });
    }
  });
});

test("ledger separates stored lifecycle, database expiry and epoch mismatch", async ({ page }) => {
  let bindingState = "anonymous";
  await mockControl(page, (url) => {
    if (url.pathname.includes("/grants/")) {
      const value = grantFixture(url.pathname.split("/").at(-1));
      const grant = value.grant!;
      grant.stored_status = value.source_grant_id === OTHER_GRANT_ID ? "revoked" : "active";
      grant.time_expired = value.source_grant_id === GRANT_ID;
      if (grant.time_expired) grant.expires_at = value.as_of!;
      grant.binding.current_auth_epoch = 5;
      grant.binding.epoch_matches_grant = false;
      grant.binding.stored_status = "revoked";
      return { body: value };
    }
    if (url.pathname.includes("/auth-bindings/")) {
      const value = bindingFixture(url.pathname.split("/").at(-1));
      const binding = value.binding!;
      Object.assign(binding, {
        stored_status: bindingState,
        current_auth_epoch: bindingState === "anonymous" ? 0 : 4,
        credential_generation: bindingState === "anonymous" ? 0 : 2,
      });
      if (bindingState === "expired")
        Object.assign(binding, { expires_at: value.as_of, time_expired: true });
      return { body: value };
    }
    return undefined;
  });
  await connect(page);
  await queryLedger(page, "grant");
  const grant = page.getByRole("region", { name: "资格记录", exact: true });
  await expect(grant.locator("dl > div").filter({ hasText: "持久状态" })).toContainText("active");
  await expect(grant.locator("dl > div").filter({ hasText: "时间到期" })).toContainText("已到期");
  const binding = page.getByRole("region", {
    name: "身份绑定记录",
    exact: true,
  });
  await expect(binding.locator("dl > div").filter({ hasText: "当前身份代际" })).toContainText("5");
  await expect(binding.locator("dl > div").filter({ hasText: "发行代际对比" })).toContainText(
    "不一致",
  );
  await expect(binding.locator("dl > div").filter({ hasText: "时间到期" })).toContainText("未到期");
  await queryLedger(page, "grant", OTHER_GRANT_ID);
  await expect(grant.locator("dl > div").filter({ hasText: "持久状态" })).toContainText("revoked");
  await expect(grant.locator("dl > div").filter({ hasText: "时间到期" })).toContainText("未到期");
  for (const state of ["anonymous", "expired", "revoked"]) {
    bindingState = state;
    await queryLedger(page, "binding", OTHER_BINDING_ID);
    await expect(binding.locator("dl > div").filter({ hasText: "持久状态" })).toContainText(state);
    await expect(binding.locator("dl > div").filter({ hasText: "时间到期" })).toContainText(
      state === "expired" ? "已到期" : "未到期",
    );
    await expect(binding.locator("dl > div").filter({ hasText: "当前身份代际" })).toContainText(
      state === "anonymous" ? "0" : "4",
    );
  }
});

test("ledger missing records retain an explicit observation state and history entry", async ({
  page,
}) => {
  await mockControl(page, (url) =>
    url.pathname.includes("/grants/")
      ? { body: { ...grantFixture(), found: false, grant: null, as_of: null } }
      : {
          body: {
            ...bindingFixture(),
            found: false,
            binding: null,
            as_of: null,
          },
        },
  );
  await connect(page);
  for (const kind of ["grant", "binding"] as const) {
    await queryLedger(page, kind);
    await expect(page.getByRole("heading", { name: "当前账本未找到", exact: true })).toBeVisible();
    await expect(page.getByText("未返回观察时间", { exact: true })).toBeVisible();
    await expect(page.getByText(/历史事件可通过独立检索继续核对/)).toBeVisible();
    await expect(page.getByRole("button", { name: "准备历史检索", exact: true })).toBeVisible();
    await expect(page.getByText(/待发布段|查看水位/)).toHaveCount(0);
  }
});

test("ledger 403 and database 503 remain safe and require explicit retry", async ({ page }) => {
  await page.clock.install();
  let status = 403;
  const calls = await mockControl(page, (url) => ({
    status,
    body: errorFixture(
      status === 403
        ? "CONTROL_SCOPE_DENIED"
        : url.pathname.includes("/grants/")
          ? "CONTROL_GRANT_STORE_UNAVAILABLE"
          : "CONTROL_BINDING_STORE_UNAVAILABLE",
    ),
  }));
  await connect(page);
  for (const kind of ["grant", "binding"] as const) {
    for (const code of [403, 503]) {
      status = code;
      await queryLedger(page, kind);
      await expect(page.getByRole("alert")).toContainText(
        code === 403
          ? "CONTROL_SCOPE_DENIED"
          : kind === "grant"
            ? "CONTROL_GRANT_STORE_UNAVAILABLE"
            : "CONTROL_BINDING_STORE_UNAVAILABLE",
      );
      await expect(page.getByText("Synthetic server detail must not be rendered")).toHaveCount(0);
    }
  }
  await page.clock.fastForward(60_000);
  expect(calls).toHaveLength(4);
});

test("ledger clears invalidated sessions and all query state", async ({ page }) => {
  await page.clock.install();
  let expired = false;
  await mockControl(page, () =>
    expired ? { status: 401, body: errorFixture("CONTROL_AUTH_REQUIRED") } : undefined,
  );
  for (const kind of ["grant", "binding"] as const) {
    for (const action of ["401", "idle", "reload", "pagehide", "disconnect"] as const) {
      expired = false;
      await connect(page);
      await queryLedger(page, kind);
      await expect(page.getByRole("button", { name: "准备历史检索", exact: true })).toBeVisible();
      if (action === "401") {
        expired = true;
        await page.getByRole("button", { name: "查询", exact: true }).click();
      } else if (action === "idle") await page.clock.fastForward(15 * 60_000 + 1);
      else if (action === "reload") await page.reload();
      else if (action === "pagehide")
        await page.evaluate(() => window.dispatchEvent(new Event("pagehide")));
      else await page.getByRole("button", { name: "断开连接", exact: true }).click();
      await expect(page.getByLabel("管理凭证", { exact: true })).toHaveValue("");
      await expect(page.getByRole("button", { name: "准备历史检索", exact: true })).toHaveCount(0);
      await expect(page.getByText("2026-09-20T08:10:30.123456Z", { exact: true })).toHaveCount(0);
      expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([
        0, 0,
      ]);
    }
  }
});

test("ledger edits and navigation discard late responses and cross-scope snapshots disconnect", async ({
  page,
}) => {
  let arrive = () => {};
  let release = () => {};
  let delay = Promise.resolve();
  let drift = false;
  await mockControl(page, async (url) => {
    if (url.pathname.endsWith(GRANT_ID) || url.pathname.endsWith(BINDING_ID)) {
      arrive();
      await delay;
    }
    if (url.pathname.includes("/grants/"))
      return {
        body: {
          ...grantFixture(url.pathname.split("/").at(-1)),
          tenant_id: drift ? "tenant_other" : "tenant_demo",
        },
      };
    if (url.pathname.includes("/auth-bindings/"))
      return {
        body: {
          ...bindingFixture(url.pathname.split("/").at(-1)),
          site_id: drift ? "site_other" : "site_demo",
        },
      };
    return undefined;
  });
  await connect(page);
  for (const kind of ["grant", "binding"] as const) {
    delay = new Promise<void>((resolve) => {
      release = resolve;
    });
    const arrived = new Promise<void>((resolve) => {
      arrive = resolve;
    });
    const settled = requestSettled(
      page,
      kind === "grant"
        ? `/control/v1/grants/${GRANT_ID}`
        : `/control/v1/auth-bindings/${BINDING_ID}`,
    );
    await queryLedger(page, kind);
    await arrived;
    await page
      .getByLabel(kind === "grant" ? "资格 ID" : "身份绑定 ID", { exact: true })
      .fill(kind === "grant" ? OTHER_GRANT_ID : OTHER_BINDING_ID);
    release();
    await settled;
    await paint(page);
    await expect(page.getByRole("button", { name: "准备历史检索", exact: true })).toHaveCount(0);
    await page.getByRole("button", { name: "查询", exact: true }).click();
    await expect(page.getByRole("button", { name: "准备历史检索", exact: true })).toBeVisible();
    drift = true;
    await page.getByRole("button", { name: "查询", exact: true }).click();
    await expect(page.getByRole("status")).toContainText("响应范围校验失败");
    await expect(page.getByLabel("管理凭证", { exact: true })).toHaveValue("");
    drift = false;
    await page.getByLabel("管理凭证", { exact: true }).fill(TOKEN);
    await page.getByRole("button", { name: "连接", exact: true }).click();
  }
});

test("ledger rejects malicious fields and drops undisclosed data before desktop and mobile rendering", async ({
  page,
}) => {
  let malicious = true;
  const injected = '<img src=x onerror="window.xshieldInjected=true">';
  const runtimeErrors: string[] = [];
  const consoleErrors: string[] = [];
  page.on("pageerror", (error) => runtimeErrors.push(error.message));
  page.on("console", (message) => {
    if (["warning", "error"].includes(message.type())) consoleErrors.push(message.text());
  });
  await mockControl(page, (url) => {
    if (url.pathname.includes("/grants/")) {
      const value = grantFixture();
      if (malicious) value.grant!.operation_id = injected;
      return {
        body: {
          ...value,
          subject: "PRIVATE_SUBJECT_SENTINEL",
          resource_fingerprint: "PRIVATE_FINGERPRINT_SENTINEL",
        },
      };
    }
    const value = bindingFixture();
    return {
      body: {
        ...value,
        binding: {
          ...value.binding,
          ...(malicious ? { stored_status: injected } : {}),
          waf_sid: "PRIVATE_SID_SENTINEL",
          credential_fingerprint: "PRIVATE_FINGERPRINT_SENTINEL",
        },
      },
    };
  });
  await connect(page);
  for (const kind of ["grant", "binding"] as const) {
    malicious = true;
    await queryLedger(page, kind);
    await expect(page.getByRole("alert")).toContainText("INVALID_RESPONSE");
    await expect(page.getByText(injected, { exact: true })).toHaveCount(0);
    malicious = false;
    await queryLedger(page, kind);
    await expect(page.getByRole("button", { name: "准备历史检索", exact: true })).toBeVisible();
    await expect(page).toHaveURL(
      new URL(
        "/investigation/" + (kind === "grant" ? "grants" : "bindings"),
        page.url(),
      ).toString(),
    );
    await expect(page).toHaveTitle(/Xshield/);
    await expect(page.locator("vite-error-overlay")).toHaveCount(0);
    await expect(page.locator("main img")).toHaveCount(0);
    await expect(page.getByText(/PRIVATE_.*_SENTINEL/)).toHaveCount(0);
    expect(await page.evaluate(() => Reflect.get(window, "xshieldInjected"))).toBeUndefined();
    for (const width of [1536, 390]) {
      await page.setViewportSize({ width, height: 1024 });
      expect(
        await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
      ).toBe(true);
      const screenshotDirectory = process.env.XSHIELD_CONSOLE_SCREENSHOT_DIR;
      if (screenshotDirectory) {
        await page.evaluate(() => window.scrollTo(0, 0));
        await page.screenshot({
          path: resolve(screenshotDirectory, `ledger-${kind}-${width}.png`),
          fullPage: true,
        });
        await page.screenshot({
          path: resolve(screenshotDirectory, `ledger-${kind}-${width}-viewport.png`),
          fullPage: false,
        });
      }
    }
  }
  expect(runtimeErrors).toEqual([]);
  expect(consoleErrors).toEqual([]);
});
