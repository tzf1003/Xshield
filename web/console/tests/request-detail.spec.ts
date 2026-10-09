import { expect, type Page, test } from "@playwright/test";
import { resolve } from "node:path";
import { type Call, mockControl, paint, requestSettled, sent } from "./control-mock";
import {
  ARTIFACT_ID,
  artifactFixture,
  errorFixture,
  EVENT_CURSOR,
  EVIDENCE_CURSOR,
  eventsFixture,
  OTHER_ARTIFACT_ID,
  OTHER_REQUEST_ID,
  REQUEST_ID,
  summaryFixture,
  TOKEN,
} from "./fixtures";
import { pasteId, QUIET_PAGE, signInQuietly } from "./investigation-helpers";
import { richEventId, richEventsFixture, richSummaryFixture } from "./request-fixtures";
import { signIn } from "./shell-helpers";

const eventId = (n: number) => `ev_018f2a3b-4c5d-7000-8000-${String(n).padStart(12, "0")}`;
/** Rows of the event timeline (other tabs keep their own tables mounted but hidden). */
const rows = (page: Page) =>
  page.getByRole("tabpanel", { name: "事件时间线" }).locator(".ant-table-row");
const banner = (page: Page) => page.getByRole("region", { name: "判定摘要" });
const stages = (page: Page) => page.getByRole("region", { name: "阶段", exact: true });
const index = (page: Page) => page.getByRole("status", { name: "请求索引状态" });
const paths = (calls: Call[]) => calls.map((call) => call.path);

/** Opens a request the way an operator pastes its ID: through the command palette. */
async function open(page: Page, id = REQUEST_ID) {
  await pasteId(page, id);
}

test("reads the summary before the timeline, with scoped bearer calls only", async ({ page }) => {
  const runtimeErrors: string[] = [];
  page.on("pageerror", (error) => runtimeErrors.push(error.message));
  const calls = await mockControl(page);
  await signInQuietly(page);
  expect(calls).toHaveLength(0);
  // An unrecognised ID opens nothing and reads nothing.
  await open(page, "invalid-request-id");
  expect(calls).toHaveLength(0);
  await page
    .context()
    .addCookies([{ name: "business_session", value: "synthetic", url: page.url() }]);
  await open(page);
  await expect(page.getByText("AUTH_BINDING_VALID", { exact: true })).toBeVisible();
  expect(paths(calls)).toEqual([
    `/control/v1/requests/${REQUEST_ID}`,
    `/control/v1/requests/${REQUEST_ID}/events`,
  ]);
  expect(
    calls.every((call) => call.authorized && call.method === "GET" && call.cookie === null),
  ).toBe(true);
  await expect(page).toHaveTitle(/Xshield/);
  await expect(page.getByRole("heading", { name: "请求调查", exact: true })).toBeVisible();
  await expect(page.locator("vite-error-overlay")).toHaveCount(0);
  await expect(page.getByText("tenant_demo", { exact: false }).first()).toBeVisible();
  // The fixture's index has two unpublished segments and a gap: both stay visible, with the caveat.
  await expect(index(page)).toContainText("索引存在缺口 · 2 个待发布段");
  await expect(index(page)).toContainText("当前结果可能不完整");
  await expect(index(page)).toContainText("水位仅代表配置的日志源");
  // A deterministic stage has no confidence and says why, rather than showing a number.
  await expect(stages(page)).toContainText("置信度：不适用");
  expect(page.url()).not.toContain(TOKEN);
  expect(calls.every((call) => !call.path.includes(TOKEN))).toBe(true);
  expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0]);
  const screenshotDirectory = process.env.XSHIELD_CONSOLE_SCREENSHOT_DIR;
  if (screenshotDirectory) {
    await page.setViewportSize({ width: 1536, height: 1024 });
    await page.screenshot({ path: resolve(screenshotDirectory, "desktop.png"), fullPage: false });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({ path: resolve(screenshotDirectory, "mobile.png"), fullPage: false });
  }
  expect(runtimeErrors).toEqual([]);
});

test("the decision banner states the verdict, the reason in words and what was forwarded", async ({
  page,
}) => {
  await mockControl(page);
  await signInQuietly(page);
  await open(page);
  await expect(banner(page)).toContainText("拒绝");
  await expect(banner(page)).toContainText("DENY");
  await expect(banner(page)).toContainText("界面动作不可用");
  await expect(banner(page).getByText("UI_ACTION_NOT_AVAILABLE", { exact: true })).toBeVisible();
  await expect(banner(page)).toContainText("没有为已验证的页面登记可用的动作映射");
  await expect(banner(page)).toContainText("建议：");
  await expect(banner(page)).toContainText("未转发到源站");
  await expect(banner(page)).toContainText("业务结果未确认");
  await expect(banner(page)).toContainText("HTTP 403");
  const facts = page.getByRole("region", { name: "关键事实" });
  await expect(facts).toContainText(REQUEST_ID);
  await expect(facts).toContainText("site_demo");
  await expect(facts).toContainText("GET");
  await expect(facts).toContainText("user.profile.read");
  await expect(facts).toContainText("该信息当前不在脱敏摘要中");
  // Local time with the exact UTC instant on the element.
  await expect(facts.locator("time")).toHaveAttribute("datetime", "2026-09-20T08:10:30.000Z");
});

test("an allowed request does not claim the business operation succeeded", async ({ page }) => {
  await mockControl(page, (url) => {
    if (url.pathname.endsWith("/events")) return { body: richEventsFixture() };
    if (url.pathname === `/control/v1/requests/${REQUEST_ID}`)
      return { body: richSummaryFixture() };
    return undefined;
  });
  await signInQuietly(page);
  await open(page);
  await expect(banner(page)).toContainText("放行");
  await expect(banner(page)).toContainText("已观察到转发意图（不等于源站已执行）");
  await expect(banner(page)).toContainText("已确认源站响应");
  await expect(banner(page)).toContainText("放行不表示业务执行成功");
  await expect(banner(page)).toContainText("源站响应已确认不等同于业务执行成功");
  await expect(index(page)).toContainText("未观察到索引缺口 · 0 个待发布段");
  await expect(index(page)).toContainText("已观察到请求终态");
});

test.describe("stage tree and evidence tabs", () => {
  const rich = (page: Page) =>
    mockControl(page, (url) => {
      if (url.pathname.endsWith("/events"))
        return { body: richEventsFixture(REQUEST_ID, url.searchParams.has("cursor")) };
      if (url.pathname === `/control/v1/requests/${REQUEST_ID}`)
        return { body: richSummaryFixture() };
      return undefined;
    });

  test("every observed stage shows its outcome, reason, proof and timing; skipped ones say why", async ({
    page,
  }) => {
    await rich(page);
    await signInQuietly(page);
    await open(page);
    const tree = stages(page);
    await expect(tree.locator("button.xs-stage")).toHaveCount(5);
    const names = await tree.locator("button.xs-stage .xs-stage-head strong").allTextContents();
    expect(names).toEqual(["操作准入", "请求解密", "模型判别", "证据采集", "响应加密"]);
    const admission = tree.locator("button.xs-stage").nth(0);
    await expect(admission).toContainText("通过");
    await expect(admission).toContainText("界面动作已准入");
    await expect(admission).toContainText("UI_ACTION_ALLOWED");
    await expect(admission).toContainText("耗时 24 µs");
    await expect(admission).toContainText("确定性规则");
    await expect(admission).toContainText("置信度：不适用");
    const model = tree.locator("button.xs-stage").nth(2);
    await expect(model).toContainText("模型判别");
    await expect(model).toContainText("置信度：0.8");
    await expect(model).toContainText("耗时 1.20 ms");
    const skipped = tree.locator("button.xs-stage").nth(4);
    await expect(skipped).toContainText("已跳过");
    await expect(skipped).toContainText("未执行：");
    await expect(skipped).toContainText("因站点结果而跳过");
    await expect(skipped).toContainText("SKIPPED_BY_SITE_UNAVAILABLE");
  });

  test("selecting a stage points the right-hand tabs at its evidence", async ({ page }) => {
    const calls = await rich(page);
    await signInQuietly(page);
    await open(page);
    const tree = stages(page);
    await tree.locator("button.xs-stage").nth(2).click();
    await expect(page.getByRole("tab", { name: "模型判别", selected: true })).toBeVisible();
    const modelCall = page.getByRole("link", { name: /mdl_018f2a3b-4c5d-7000-8000-000000000001/ });
    await expect(modelCall).toBeVisible();
    await tree.locator("button.xs-stage").nth(1).click();
    await expect(page.getByRole("tab", { name: "加密转换", selected: true })).toBeVisible();
    await expect(page.getByRole("region", { name: "请求解密" })).toContainText("请求已解密");
    await expect(
      page.getByText(/算法、密钥引用、报文 ID 与 nonce 摘要不在脱敏摘要中/),
    ).toBeVisible();
    // Evidence capture lives with the catalogue, which is read only when that tab opens.
    expect(paths(calls).some((path) => path.endsWith("/evidence"))).toBe(false);
    await tree.locator("button.xs-stage").nth(3).click();
    await expect(page.getByRole("tab", { name: "输入与输出", selected: true })).toBeVisible();
    await expect.poll(() => paths(calls).some((path) => path.endsWith("/evidence"))).toBe(true);
    // A stage without a dedicated tab filters the timeline instead.
    await tree.locator("button.xs-stage").nth(0).click();
    await expect(page.getByRole("tab", { name: "事件时间线", selected: true })).toBeVisible();
    await expect(page.getByText("仅看阶段：操作准入")).toBeVisible();
    await expect(rows(page)).toHaveCount(1);
    await page.getByLabel("清除阶段筛选").click();
    await expect(rows(page)).toHaveCount(5);
  });

  test("tabs show only what the summary carries and say so otherwise", async ({ page }) => {
    await mockControl(page);
    await signInQuietly(page);
    await open(page);
    // The default fixture has a single UI-source stage.
    await page.getByRole("tab", { name: "界面来源" }).click();
    await expect(page.getByRole("region", { name: "界面来源" })).toContainText("界面动作不可用");
    await expect(
      page.getByText(/页面构建、动作映射与来源动作的具体内容不在脱敏摘要中/),
    ).toBeVisible();
    for (const name of ["资源资格", "加密转换", "模型判别", "Agent"]) {
      await page.getByRole("tab", { name }).click();
      await expect(
        page.getByRole("tabpanel").getByRole("heading", { name: "该信息当前不在脱敏摘要中" }),
      ).toBeVisible();
    }
    await page.getByRole("tab", { name: "审计完整性" }).click();
    const audit = page.getByRole("status", { name: "审计完整性" });
    await expect(audit).toContainText("索引存在缺口 · 2 个待发布段");
    await expect(page.getByText("complete：已观察到请求终态")).toBeVisible();
    await expect(
      page.getByText(/「complete」表示观察到了该请求保留的终态，不表示索引没有缺口/),
    ).toBeVisible();
  });

  test("the model tab lists the model call and its confidence availability", async ({ page }) => {
    await rich(page);
    await signInQuietly(page);
    await open(page);
    await page.getByRole("tab", { name: "模型判别" }).click();
    const panel = page.getByRole("tabpanel", { name: "模型判别" });
    await expect(panel).toContainText("置信度：0.8");
    await expect(panel).toContainText("模型版本 jev-1.13.0");
    await expect(panel).toContainText("不在脱敏摘要中");
  });
});

test("the timeline loads more events on request and keeps the first page", async ({ page }) => {
  const calls = await mockControl(page);
  await signInQuietly(page);
  await open(page);
  await expect(page.getByText("AUTH_BINDING_VALID", { exact: true })).toBeVisible();
  expect(calls).toHaveLength(2);
  await expect(rows(page)).toHaveCount(3);
  await page.getByRole("button", { name: "加载更多", exact: true }).click();
  await expect(page.getByText("REQUEST_DENIED", { exact: true })).toBeVisible();
  await expect(rows(page)).toHaveCount(4);
  await expect(page.getByText("AUTH_BINDING_VALID", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "加载更多", exact: true })).toBeDisabled();
  expect(calls.at(-1)?.path).toBe(
    `/control/v1/requests/${REQUEST_ID}/events?cursor=${EVENT_CURSOR}`,
  );
});

test("evidence is read when its tab opens; only catalogue metadata is shown", async ({ page }) => {
  const calls = await mockControl(page);
  await signInQuietly(page);
  await open(page);
  await expect(rows(page)).toHaveCount(3);
  expect(calls.filter((call) => call.path.endsWith("/evidence"))).toHaveLength(0);
  await page.getByRole("tab", { name: "输入与输出" }).click();
  await expect(page.getByRole("button", { name: `查看元数据 ${ARTIFACT_ID}` })).toBeVisible();
  const evidencePanel = page.getByRole("tabpanel", { name: "输入与输出" });
  await expect(evidencePanel).toContainText("已脱敏");
  await expect(evidencePanel).toContainText("受限");
  await expect(evidencePanel).toContainText("256 字节");
  await page.getByRole("button", { name: "加载更多证据", exact: true }).click();
  await expect(page.getByRole("button", { name: `查看元数据 ${OTHER_ARTIFACT_ID}` })).toBeVisible();
  expect(calls.at(-1)?.path).toBe(
    `/control/v1/requests/${REQUEST_ID}/evidence?cursor=${EVIDENCE_CURSOR}`,
  );
  // Opening an artifact reads its catalogue entry once.
  await page.getByRole("button", { name: `查看元数据 ${ARTIFACT_ID}` }).click();
  const drawer = page.getByRole("dialog", { name: "证据元数据" });
  await expect(drawer).toContainText("application/json");
  await expect(drawer).toContainText("request_decoded");
  await expect(drawer).toContainText("目录记录用于定位证据");
  await expect(page.getByText("synthetic-vault-object.bin")).toHaveCount(0);
  await expect(page.getByText("synthetic-key-ref")).toHaveCount(0);
  await expect(page.getByText("a".repeat(64))).toHaveCount(0);
  expect(calls.some((call) => call.path.endsWith("/content"))).toBe(false);
  expect(calls.filter((call) => call.path === `/control/v1/artifacts/${ARTIFACT_ID}`)).toHaveLength(
    1,
  );
});

test("an artifact that is not available is a catalogue state, not an error", async ({ page }) => {
  await mockControl(page, (url) =>
    url.pathname.includes("/artifacts/")
      ? { body: { ...artifactFixture(), found: false, artifact: null } }
      : undefined,
  );
  await signInQuietly(page);
  await open(page);
  await page.getByRole("tab", { name: "输入与输出" }).click();
  await page.getByRole("button", { name: `查看元数据 ${ARTIFACT_ID}` }).click();
  const drawer = page.getByRole("dialog", { name: "证据元数据" });
  await expect(drawer).toContainText("证据当前不可用");
  await expect(drawer).toContainText("这不推断对象是否存在");
  await expect(page.getByRole("alert")).toHaveCount(0);
  await expect(page.getByText("synthetic-vault-object.bin")).toHaveCount(0);
});

test("a missing request and an index still publishing are different answers", async ({ page }) => {
  const calls = await mockControl(page, (url) => {
    if (url.pathname.endsWith("/events")) return undefined;
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
  await signInQuietly(page);
  await open(page);
  await expect(page.getByText("当前未找到请求", { exact: true })).toBeVisible();
  await expect(page.getByText(/未找到不推断请求不存在/)).toBeVisible();
  await expect(page.getByText("UI_ACTION_NOT_AVAILABLE", { exact: true })).toHaveCount(0);
  await expect(index(page)).toContainText("当前索引未命中 · 0 个待发布段");
  await open(page, OTHER_REQUEST_ID);
  await expect(page.getByText("索引待就绪", { exact: true })).toBeVisible();
  await expect(index(page)).toContainText("当前索引未命中 · 2 个待发布段");
  // Nothing to list, so the timeline is not read for a request the index does not know.
  expect(paths(calls).some((path) => path.endsWith("/events"))).toBe(false);
});

test("a missing decision, UNKNOWN and a request still waiting are three different states", async ({
  page,
}) => {
  await mockControl(page, (url) => {
    const id = url.pathname.split("/")[4];
    if (url.pathname.endsWith("/events")) return undefined;
    const response = summaryFixture(id);
    if (id === REQUEST_ID)
      return { body: { ...response, summary: { ...response.summary, decision: null } } };
    if (id === OTHER_REQUEST_ID)
      return { body: { ...response, summary: { ...response.summary, decision: "UNKNOWN" } } };
    return {
      body: {
        ...response,
        completeness: "pending",
        summary: {
          ...response.summary,
          terminal: false,
          decision: null,
          reason_code: null,
          status: null,
          origin_state: null,
          duration_us: null,
          forwarded: false,
          business_result_confirmed: false,
        },
      },
    };
  });
  await signInQuietly(page);
  await open(page);
  await expect(banner(page)).toContainText("未记录");
  await expect(banner(page)).toContainText("终态事件没有记录判定");
  await expect(banner(page).getByText("未知", { exact: true })).toHaveCount(0);
  await open(page, OTHER_REQUEST_ID);
  await expect(banner(page).getByText("未知", { exact: true })).toBeVisible();
  await expect(banner(page).getByText("UNKNOWN", { exact: true })).toBeVisible();
  await expect(banner(page)).not.toContainText("终态事件没有记录判定");
  await open(page, "req_018f2a3b-4c5d-7000-8000-000000000003");
  await expect(banner(page)).toContainText("等待终态");
  await expect(banner(page)).toContainText("尚未观察到请求终态");
  await expect(index(page)).toContainText("尚未观察到请求终态");
});

test("tabs follow the keyboard", async ({ page }) => {
  await mockControl(page);
  // Deep link: no command palette is involved, so no modal hands focus back after closing.
  await signIn(page, `/investigation/requests/${REQUEST_ID}`);
  await expect(page.getByText("AUTH_BINDING_VALID", { exact: true })).toBeVisible();
  const first = page.getByRole("tab", { name: "事件时间线" });
  const second = page.getByRole("tab", { name: "界面来源" });
  const last = page.getByRole("tab", { name: "审计完整性" });
  await expect(first).toHaveAttribute("aria-selected", "true");
  await first.focus();
  // Arrow keys move focus; Enter selects, as in the WAI-ARIA tabs pattern.
  await page.keyboard.press("ArrowRight");
  await expect(second).toBeFocused();
  await expect(first).toHaveAttribute("aria-selected", "true");
  await page.keyboard.press("Enter");
  await expect(second).toHaveAttribute("aria-selected", "true");
  await expect(first).toHaveAttribute("aria-selected", "false");
  await expect(page.getByRole("tabpanel", { name: "界面来源" })).toBeVisible();
  await page.keyboard.press("End");
  await expect(last).toBeFocused();
  await page.keyboard.press("Home");
  await expect(first).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(first).toHaveAttribute("aria-selected", "true");
});

test("a 401 while loading more clears everything on screen", async ({ page }) => {
  let expired = false;
  const calls = await mockControl(page, () =>
    expired ? { status: 401, body: errorFixture("CONTROL_AUTH_REQUIRED") } : undefined,
  );
  await signInQuietly(page);
  await open(page);
  await expect(page.getByText("AUTH_BINDING_VALID", { exact: true })).toBeVisible();
  expired = true;
  await page.getByRole("button", { name: "加载更多", exact: true }).click();
  await expect(page.getByLabel("管理凭证", { exact: true })).toHaveValue("");
  await expect(page.getByRole("button", { name: "连接", exact: true })).toBeVisible();
  await expect(page.getByText("AUTH_BINDING_VALID", { exact: true })).toHaveCount(0);
  await expect(page.getByText(REQUEST_ID, { exact: true })).toHaveCount(0);
  expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0]);
  expect(sent(calls)).toHaveLength(3);
});

test("fifteen idle minutes and a reload clear the session and what it showed", async ({ page }) => {
  await page.clock.install();
  const calls = await mockControl(page);
  await signInQuietly(page);
  await open(page);
  await expect(page.getByText("AUTH_BINDING_VALID", { exact: true })).toBeVisible();
  await page.clock.fastForward(15 * 60_000 + 1);
  await expect(page.getByRole("status")).toContainText("会话已因闲置断开");
  await expect(page.getByLabel("管理凭证", { exact: true })).toHaveValue("");
  await expect(page.getByText("AUTH_BINDING_VALID", { exact: true })).toHaveCount(0);
  await expect(page.getByText(REQUEST_ID, { exact: true })).toHaveCount(0);
  // The address still names the request: reconnecting reads it again, once per page.
  await page.getByLabel("管理凭证", { exact: true }).fill(TOKEN);
  await page.getByRole("button", { name: "连接", exact: true }).click();
  await expect(page.getByText("AUTH_BINDING_VALID", { exact: true })).toBeVisible();
  await page.reload();
  await expect(page.getByLabel("管理凭证", { exact: true })).toHaveValue("");
  await expect(page.getByText("AUTH_BINDING_VALID", { exact: true })).toHaveCount(0);
  expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0]);
  expect(paths(sent(calls))).toEqual([
    `/control/v1/requests/${REQUEST_ID}`,
    `/control/v1/requests/${REQUEST_ID}/events`,
    `/control/v1/requests/${REQUEST_ID}`,
    `/control/v1/requests/${REQUEST_ID}/events`,
  ]);
});

test("403 and 429 show the safe message and code and wait for an explicit retry", async ({
  page,
}) => {
  await page.clock.install();
  let status = 403;
  const calls = await mockControl(page, () => ({
    status,
    body: errorFixture(status === 403 ? "CONTROL_SCOPE_DENIED" : "CONTROL_RATE_LIMITED"),
  }));
  await signInQuietly(page);
  await open(page);
  await expect(page.getByRole("alert")).toContainText("CONTROL_SCOPE_DENIED");
  await expect(page.getByRole("alert")).toContainText("req_018f2a3b-4c5d-7000-8000-000000000099");
  await page.clock.fastForward(60_000);
  expect(sent(calls)).toHaveLength(1);
  status = 429;
  await page.getByRole("button", { name: "重新读取", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("CONTROL_RATE_LIMITED");
  await page.clock.fastForward(60_000);
  expect(sent(calls)).toHaveLength(2);
  await expect(page.getByText("Synthetic server detail must not be rendered")).toHaveCount(0);
});

test("switching requests keeps an earlier timeline from reappearing", async ({ page }) => {
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
  await signInQuietly(page);
  const settled = requestSettled(page, `/control/v1/requests/${REQUEST_ID}/events`);
  await open(page);
  await arrived;
  await open(page, OTHER_REQUEST_ID);
  await expect(page.getByText("REQUEST_DENIED", { exact: true })).toBeVisible();
  release();
  await settled;
  await paint(page);
  await expect(page.getByText("AUTH_BINDING_VALID", { exact: true })).toHaveCount(0);
  await expect(page.getByText(OTHER_REQUEST_ID, { exact: true }).first()).toBeVisible();
});

test("disconnecting keeps a late response outside the new session", async ({ page }) => {
  let release = () => {};
  const delayed = new Promise<void>((resolve) => {
    release = resolve;
  });
  let arrive = () => {};
  const arrived = new Promise<void>((resolve) => {
    arrive = resolve;
  });
  await mockControl(page, async (url) => {
    if (url.pathname !== `/control/v1/requests/${REQUEST_ID}`) return undefined;
    arrive();
    await delayed;
    return { body: summaryFixture() };
  });
  await signInQuietly(page);
  const settled = requestSettled(page, `/control/v1/requests/${REQUEST_ID}`);
  await open(page);
  await arrived;
  await page.getByRole("button", { name: "断开连接", exact: true }).click();
  release();
  await settled;
  await paint(page);
  await expect(page.getByLabel("管理凭证", { exact: true })).toHaveValue("");
  await expect(page.getByRole("button", { name: "连接", exact: true })).toBeVisible();
  await expect(page.getByText("UI_ACTION_NOT_AVAILABLE", { exact: true })).toHaveCount(0);
});

test("closing the evidence drawer discards a late artifact reply", async ({ page }) => {
  let release = () => {};
  let arrive = () => {};
  let delayed = Promise.resolve();
  await mockControl(page, async (url) => {
    if (!url.pathname.includes("/artifacts/")) return undefined;
    arrive();
    await delayed;
    return { body: artifactFixture() };
  });
  await signInQuietly(page);
  await open(page);
  await page.getByRole("tab", { name: "输入与输出" }).click();
  for (const how of ["escape", "close button"] as const) {
    delayed = new Promise<void>((resolve) => {
      release = resolve;
    });
    const arrived = new Promise<void>((resolve) => {
      arrive = resolve;
    });
    const settled = requestSettled(page, `/control/v1/artifacts/${ARTIFACT_ID}`);
    await page.getByRole("button", { name: `查看元数据 ${ARTIFACT_ID}` }).click();
    await arrived;
    await expect(page.getByRole("dialog", { name: "证据元数据" })).toBeVisible();
    if (how === "escape") await page.keyboard.press("Escape");
    else
      await page
        .getByRole("button", { name: /close|关闭/i })
        .first()
        .click();
    await expect(page.getByRole("dialog", { name: "证据元数据" })).toHaveCount(0);
    release();
    await settled;
    await paint(page);
    await expect(page.getByText("application/json", { exact: true })).toHaveCount(0);
    await expect(page.getByLabel("正在读取证据元数据")).toHaveCount(0);
  }
});

test("a timeline from another server scope ends the session", async ({ page }) => {
  await mockControl(page, (url) =>
    url.pathname.endsWith("/events")
      ? { body: { ...eventsFixture(), tenant_id: "tenant_other" } }
      : undefined,
  );
  await signInQuietly(page);
  await open(page);
  await expect(page.getByRole("status").filter({ hasText: "响应范围校验失败" })).toBeVisible();
  await expect(page.getByRole("button", { name: "连接", exact: true })).toBeVisible();
  await expect(page.getByText("AUTH_BINDING_VALID", { exact: true })).toHaveCount(0);
  await expect(page.getByText("tenant_other", { exact: true })).toHaveCount(0);
});

test("untrusted metadata is text, and the layout stays inside the viewport", async ({ page }) => {
  const injected = '<img src=x onerror="window.xshieldInjected=true">';
  await mockControl(page, (url) => {
    if (!url.pathname.includes("/artifacts/")) return undefined;
    const response = artifactFixture();
    response.artifact.content_type = injected;
    return { body: response };
  });
  await page.setViewportSize({ width: 1536, height: 1024 });
  await signInQuietly(page);
  await open(page);
  await page.getByRole("tab", { name: "输入与输出" }).click();
  await page.getByRole("button", { name: `查看元数据 ${ARTIFACT_ID}` }).click();
  await expect(page.getByText(injected, { exact: true })).toBeVisible();
  expect(await page.evaluate(() => Reflect.get(window, "xshieldInjected"))).toBeUndefined();
  await expect(page.locator("main img")).toHaveCount(0);
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog", { name: "证据元数据" })).toHaveCount(0);
  for (const width of [1536, 390]) {
    await page.setViewportSize({ width, height: 1024 });
    await expect(page.getByRole("heading", { name: "请求调查", exact: true })).toBeVisible();
    // Responsive columns settle a frame after a resize, so poll instead of sampling once.
    await expect
      .poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth))
      .toBe(true);
  }
});

test("a model reference opens the separately authorized lifecycle page", async ({ page }) => {
  const calls = await mockControl(page, (url) => {
    if (!url.pathname.endsWith("/events")) return undefined;
    const events = eventsFixture();
    Object.assign(events.events.at(-1) as object, {
      proof_kind: "model",
      model_revision: "jev-1.13.0",
      model_call_id: "mdl_018f2a3b-4c5d-7000-8000-000000000001",
      confidence: 0.8,
      confidence_status: "provided",
    });
    return { body: events };
  });
  await signInQuietly(page);
  await open(page);
  await page.getByRole("button", { name: `查看事件 ${eventId(3)}` }).click();
  const drawer = page.getByRole("dialog", { name: "事件详情" });
  await drawer.getByRole("link", { name: "mdl_018f2a3b-4c5d-7000-8000-000000000001" }).click();
  await expect(page.getByRole("heading", { name: "模型调用调查", exact: true })).toBeVisible();
  await expect
    .poll(() => paths(calls))
    .toEqual([
      `/control/v1/requests/${REQUEST_ID}`,
      `/control/v1/requests/${REQUEST_ID}/events`,
      "/control/v1/model-calls/mdl_018f2a3b-4c5d-7000-8000-000000000001",
    ]);
  expect(calls.every((call) => call.authorized && call.cookie === null)).toBe(true);
});

test.describe("mobile", () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test("no horizontal page scroll; tables scroll inside their container", async ({ page }) => {
    await mockControl(page, (url) => {
      if (url.pathname.endsWith("/events")) return { body: richEventsFixture() };
      if (url.pathname === `/control/v1/requests/${REQUEST_ID}`)
        return { body: richSummaryFixture() };
      return undefined;
    });
    await signIn(page, QUIET_PAGE);
    await open(page);
    await expect(rows(page)).toHaveCount(5);
    expect(
      await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
    ).toBe(true);
    expect(
      await page.evaluate(() => {
        const content = document.querySelector(".ant-table-content");
        return content ? content.scrollWidth > content.clientWidth : false;
      }),
    ).toBe(true);
    await page.getByRole("button", { name: `查看事件 ${richEventId(4)}` }).click();
    const drawer = page.getByRole("dialog", { name: "事件详情" });
    await expect(drawer).toBeVisible();
    // The drawer slides in; measure it once it has settled.
    await expect
      .poll(async () => {
        const box = await drawer.boundingBox();
        return box ? Math.round(box.x + box.width) : null;
      })
      .toBe(390);
    expect((await drawer.boundingBox())?.x).toBeGreaterThanOrEqual(0);
    expect(
      await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
    ).toBe(true);
  });
});
