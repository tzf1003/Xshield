import { expect, type Page, type Request, test } from "@playwright/test";
import type { CausalityPlan } from "../src/search.ts";
import { CASE_ID, OTHER_CASE_ID } from "./case-fixtures";
import { type Call, mockControl, paint, requestSettled } from "./control-mock";
import { ARTIFACT_ID, causalityFixture, errorFixture, eventsFixture, REQUEST_ID } from "./fixtures";
import { pasteId, signInQuietly } from "./investigation-helpers";

const eventId = (n: number) => `ev_018f2a3b-4c5d-7000-8000-${String(n).padStart(12, "0")}`;
const MISSING = eventId(99);
const drawer = (page: Page) => page.getByRole("dialog", { name: "事件详情" });
const causality = (calls: Call[]) => calls.filter((call) => call.path === "/control/v1/causality");
const searches = (calls: Call[]) => calls.filter((call) => call.path === "/control/v1/search");

/** The base timeline with recorded predecessors, keyed by the index of the event in the page. */
function withCauses(causes: Record<number, string[]>) {
  return (url: URL) => {
    if (!url.pathname.endsWith("/events")) return undefined;
    const events = eventsFixture();
    for (const [index, ids] of Object.entries(causes)) {
      Object.assign(events.events[Number(index)] as object, { cause_event_ids: ids });
    }
    return { body: events };
  };
}

async function openRequest(page: Page) {
  await signInQuietly(page);
  await pasteId(page, REQUEST_ID);
  await expect(page.getByText("AUTH_BINDING_VALID", { exact: true })).toBeVisible();
}

async function openEvent(page: Page, n: number) {
  await page.getByRole("button", { name: `查看事件 ${eventId(n)}` }).click();
  await expect(drawer(page).getByText(eventId(n), { exact: true })).toBeVisible();
}

const runCausality = (page: Page) =>
  drawer(page).getByRole("button", { name: "查看因果", exact: true }).click();
const causalResult = (page: Page) =>
  page.getByRole("region", { name: "服务端因果查询结果", exact: true });

test("an event drawer shows the redacted facts and opens evidence as metadata", async ({
  page,
}) => {
  const calls = await mockControl(page);
  await openRequest(page);
  await openEvent(page, 3);
  const facts = drawer(page);
  await expect(facts).toContainText("阶段完成");
  await expect(facts).toContainText("界面来源");
  await expect(facts).toContainText("拒绝");
  await expect(facts).toContainText("界面动作不可用");
  await expect(facts.getByText("UI_ACTION_NOT_AVAILABLE", { exact: true })).toBeVisible();
  await expect(facts).toContainText("确定性规则");
  await expect(facts).toContainText("无置信度（不适用）");
  await expect(facts).toContainText("policy-demo-r3");
  // Local time for reading, and the exact UTC text with microseconds for evidence.
  await expect(facts).toContainText("2026-09-20T08:10:30.000000Z");
  await expect(facts.locator("time")).toHaveAttribute("datetime", "2026-09-20T08:10:30.000000Z");
  // Evidence references are chips; one opens the catalogue entry on top of the drawer.
  await facts.getByRole("button", { name: ARTIFACT_ID, exact: true }).click();
  const metadata = page.getByRole("dialog", { name: "证据元数据" });
  await expect(metadata).toContainText("application/json");
  await expect(metadata).toContainText("目录记录用于定位证据");
  await page.keyboard.press("Escape");
  await expect(metadata).toHaveCount(0);
  await expect(facts).toBeVisible();
  // Less common fields are one click away.
  await facts.getByText("更多事件字段", { exact: true }).click();
  await expect(facts).toContainText("事件序号");
  await expect(facts).toContainText("内部");
  await expect(facts).toContainText("未记录前驱");
  expect(calls.some((call) => call.path.endsWith("/content"))).toBe(false);
  expect(searches(calls)).toHaveLength(0);
});

test("search actions only prepare the search form and never run it", async ({ page }) => {
  const calls = await mockControl(page);
  await openRequest(page);
  await openEvent(page, 3);
  await drawer(page).getByRole("button", { name: "查找直接后继", exact: true }).click();
  await expect(page).toHaveURL(
    new RegExp(`/investigation/search\\?prefill=caused_by_event_id%3A${eventId(3)}$`),
  );
  await paint(page);
  expect(searches(calls)).toHaveLength(0);
});

test("recorded predecessors prepare an exact event search and nothing more", async ({ page }) => {
  const calls = await mockControl(page, withCauses({ 2: [eventId(2)] }));
  await openRequest(page);
  await openEvent(page, 3);
  await drawer(page).getByText("更多事件字段", { exact: true }).click();
  await drawer(page).getByRole("button", { name: "在检索中查找", exact: true }).click();
  await expect(page).toHaveURL(new RegExp(`prefill=event_id%3A${eventId(2)}$`));
  await paint(page);
  expect(searches(calls)).toHaveLength(0);
});

test.describe("causal links among the loaded events", () => {
  const chain = withCauses({ 1: [eventId(1)], 2: [eventId(2), MISSING] });

  test("the neighbourhood is built from the page without any request", async ({ page }) => {
    const calls = await mockControl(page, chain);
    await openRequest(page);
    await openEvent(page, 3);
    const before = calls.length;
    await drawer(page)
      .getByText(/查看当前页因果关联（3 个节点）/)
      .click();
    const predecessors = drawer(page).getByRole("region", { name: "前驱方向", exact: true });
    await expect(predecessors).toContainText("第 1 跳");
    await expect(predecessors).toContainText("第 2 跳");
    await expect(predecessors).toContainText("引用事件未载入");
    await expect(drawer(page).getByRole("region", { name: "后继方向", exact: true })).toContainText(
      "没有关联节点",
    );
    expect(calls).toHaveLength(before);
  });

  test("a loaded neighbour opens in the same drawer", async ({ page }) => {
    const calls = await mockControl(page, chain);
    await openRequest(page);
    await openEvent(page, 3);
    const before = calls.length;
    await drawer(page)
      .getByText(/查看当前页因果关联/)
      .click();
    await drawer(page)
      .getByRole("button", { name: `查看因果事件 ${eventId(2)}` })
      .click();
    await expect(drawer(page).getByText(eventId(2), { exact: true })).toBeVisible();
    await expect(drawer(page)).toContainText("认证绑定");
    expect(calls).toHaveLength(before);
  });

  test("an unloaded reference only prepares an event search", async ({ page }) => {
    const calls = await mockControl(page, chain);
    await openRequest(page);
    await openEvent(page, 3);
    await drawer(page)
      .getByText(/查看当前页因果关联/)
      .click();
    await drawer(page)
      .getByRole("button", { name: `查看因果事件 ${MISSING}` })
      .click();
    await expect(page).toHaveURL(new RegExp(`prefill=event_id%3A${MISSING}$`));
    await paint(page);
    expect(searches(calls)).toHaveLength(0);
  });
});

test.describe("server causality", () => {
  // A half-hour offset: the window is an instant range, whatever the browser's clock says.
  test.use({ timezoneId: "Asia/Kolkata" });

  test("nothing is sent until the button; the default window is 15 minutes either side in UTC", async ({
    page,
  }) => {
    const calls = await mockControl(page);
    await openRequest(page);
    await openEvent(page, 2);
    await expect(drawer(page).getByRole("button", { name: "查看因果", exact: true })).toBeEnabled();
    await paint(page);
    expect(causality(calls)).toHaveLength(0);
    await runCausality(page);
    const result = causalResult(page);
    await expect(result).toContainText("已找到");
    await expect(result).toContainText("前驱方向");
    await expect(result).toContainText("后继方向");
    await expect(result).toContainText("第 1 跳");
    await expect(result).toContainText("2026-09-20T07:55:30Z 至 2026-09-20T08:25:31Z");
    await expect(result).toContainText("水位仅代表配置的日志源");
    expect(causality(calls)[0]?.body).toEqual({
      schema_version: 3,
      // 08:10:30Z, fifteen minutes either side, the half-open end one second later.
      start: "2026-09-20T07:55:30Z",
      end: "2026-09-20T08:25:31Z",
      event_id: eventId(2),
      direction: "both",
      max_depth: 2,
      max_nodes: 16,
    });
    expect(causality(calls)).toHaveLength(1);
    expect(calls.every((call) => call.authorized && call.cookie === null)).toBe(true);
  });

  test("limits live behind 高级; direction, depth and nodes are bounded", async ({ page }) => {
    const calls = await mockControl(page);
    await openRequest(page);
    await openEvent(page, 2);
    await drawer(page).getByText("高级", { exact: true }).click();
    await drawer(page).getByLabel("遍历方向").click();
    await page.getByTitle("仅后继").click();
    await drawer(page).getByLabel("最大跳数（1–4）").click();
    await page.getByTitle("3 跳").click();
    await drawer(page).getByLabel("最大节点数（1–16）").click();
    await page.getByTitle("4 个", { exact: true }).click();
    await runCausality(page);
    const result = causalResult(page);
    await expect(result).toContainText("后继方向");
    await expect(result.getByRole("region", { name: "前驱方向" })).toHaveCount(0);
    expect(causality(calls)[0]?.body).toMatchObject({
      direction: "successors",
      max_depth: 3,
      max_nodes: 4,
    });
    // A node is a redacted event: decision, type, stage and reason in words.
    const node = result.getByRole("button", { name: `打开因果节点 ${eventId(4)}` });
    await expect(node).toContainText("拒绝");
    await expect(node).toContainText("阶段完成");
    await expect(node).toContainText("准入检查");
    await node.click();
    await expect(drawer(page).getByText(eventId(4), { exact: true })).toBeVisible();
    // The node came from a search projection, so it also carries the trace for a trace search.
    await drawer(page).getByRole("button", { name: "同 Trace 检索", exact: true }).click();
    await expect(page).toHaveURL(/prefill=trace_id%3A018f2a3b4c5d70008000000000000003$/);
    expect(searches(calls)).toHaveLength(0);
  });

  test("editing a limit discards the result; a late reply for the old limits never shows", async ({
    page,
  }) => {
    let release = () => {};
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    let arrive = () => {};
    const arrived = new Promise<void>((resolve) => {
      arrive = resolve;
    });
    let delay = false;
    let received = 0;
    await mockControl(page, async (url, request) => {
      if (url.pathname !== "/control/v1/causality") return undefined;
      received += 1;
      if (!delay) return undefined;
      arrive();
      await held;
      return { body: await causalityFixture(request.postDataJSON() as CausalityPlan) };
    });
    await openRequest(page);
    await openEvent(page, 2);
    // First an answered query: editing afterwards clears it.
    await runCausality(page);
    const result = causalResult(page);
    await expect(result).toBeVisible();
    await drawer(page).getByText("高级", { exact: true }).click();
    await drawer(page).getByLabel("最大节点数（1–16）").click();
    await page.getByTitle("8 个", { exact: true }).click();
    await expect(result).toHaveCount(0);
    // Now a held query: changing the limits while it is in flight discards its reply.
    delay = true;
    const settled = requestSettled(page, "/control/v1/causality");
    await runCausality(page);
    await arrived;
    await expect(drawer(page).getByText("正在查询…")).toBeVisible();
    await drawer(page).getByLabel("最大节点数（1–16）").click();
    await page.getByTitle("2 个", { exact: true }).click();
    release();
    await settled;
    await paint(page);
    await expect(result).toHaveCount(0);
    await expect(drawer(page).getByRole("button", { name: "查看因果", exact: true })).toBeEnabled();
    // Both queries reached the server; the page abandoned the second one when the limits changed.
    expect(received).toBe(2);
  });

  test("a failure shows the safe message and waits for an explicit retry", async ({ page }) => {
    const calls = await mockControl(page, (url) =>
      url.pathname === "/control/v1/causality"
        ? { status: 403, body: errorFixture("CONTROL_SCOPE_DENIED") }
        : undefined,
    );
    await openRequest(page);
    await openEvent(page, 2);
    await runCausality(page);
    const alert = drawer(page).getByRole("alert");
    await expect(alert).toContainText("CONTROL_SCOPE_DENIED");
    await expect(page.getByText("Synthetic server detail must not be rendered")).toHaveCount(0);
    await paint(page);
    expect(causality(calls)).toHaveLength(1);
  });

  test("a truncated or empty answer is stated, not hidden", async ({ page }) => {
    await mockControl(page, async (url, request) => {
      if (url.pathname !== "/control/v1/causality") return undefined;
      const value = await causalityFixture(request.postDataJSON() as CausalityPlan);
      return { body: { ...value, found: false, nodes: [], truncated: true } };
    });
    await openRequest(page);
    await openEvent(page, 2);
    await runCausality(page);
    const result = causalResult(page);
    await expect(result).toContainText("当前窗口未找到");
    await expect(result).toContainText("结果已达到服务端有界遍历上限");
    await expect(result).toContainText("当前窗口没有该方向的关联节点");
  });
});

// ---------------------------------------------------------------------------------------------
// 加入案件
// ---------------------------------------------------------------------------------------------

const CASE_NEWEST = "case_018f2a3b-4c5d-7000-8000-000000000033";
const envelope = {
  request_id: "req_018f2a3b-4c5d-7000-8000-000000000099",
  tenant_id: "tenant_demo",
  site_id: "site_demo",
};

/** Three of the caller's cases, newest first, one of them closed. */
const caseList = () => ({
  ...envelope,
  schema_version: 3,
  as_of: "2026-09-20T08:10:30.123456Z",
  items: [
    {
      case_id: CASE_NEWEST,
      status: "open",
      purpose: "核对被拒绝的登录请求",
      created_at: "2026-09-20T08:03:00.000Z",
    },
    {
      case_id: OTHER_CASE_ID,
      status: "closed",
      purpose: "已关闭的旧调查",
      created_at: "2026-09-20T08:02:00.000Z",
    },
    {
      case_id: CASE_ID,
      status: "open",
      purpose: "核对资格撤销",
      created_at: "2026-09-20T08:01:00.000Z",
    },
  ],
  truncated: false,
  next_cursor: null,
});

const itemAdded = (caseId: string, replayed = false) => ({
  ...envelope,
  schema_version: 3,
  case_id: caseId,
  artifact_id: ARTIFACT_ID,
  added_by: "synthetic_investigator",
  added_at: "2026-09-20T08:05:00.000Z",
  replayed,
});

type Add = { path: string; key: string | null; body: unknown };
const itemsPath = /^\/control\/v1\/cases\/(case_[^/]+)\/items$/;

/** A case API that records every add and answers with `reply`. */
function caseApi(
  adds: Add[],
  reply: (caseId: string, attempt: number) => { status: number; body: unknown },
) {
  return async (url: URL, request: Request) => {
    if (url.pathname === "/control/v1/cases" && request.method() === "GET") {
      return { body: caseList() };
    }
    const match = itemsPath.exec(url.pathname);
    if (match && request.method() === "POST") {
      adds.push({
        path: url.pathname,
        key: await request.headerValue("idempotency-key"),
        body: request.postDataJSON(),
      });
      return reply(match[1] as string, adds.length);
    }
    return undefined;
  };
}

async function openEvidence(page: Page) {
  await page.getByRole("tab", { name: "输入与输出" }).click();
  await expect(page.getByRole("button", { name: `加入案件 ${ARTIFACT_ID}` })).toBeVisible();
}

const addDialog = (page: Page) => page.getByRole("dialog", { name: "加入案件" });
const confirmAdd = (page: Page) =>
  addDialog(page).getByRole("button", { name: "加入所选案件", exact: true });

test.describe("add evidence to a case", () => {
  test("lists only open cases, freezes the write and confirms it", async ({ page }) => {
    const adds: Add[] = [];
    const calls = await mockControl(
      page,
      caseApi(adds, (caseId) => ({ status: 201, body: itemAdded(caseId) })),
    );
    await openRequest(page);
    await openEvidence(page);
    // Nothing about cases is read until the dialog opens.
    expect(calls.some((call) => call.path === "/control/v1/cases")).toBe(false);
    await page.getByRole("button", { name: `加入案件 ${ARTIFACT_ID}` }).click();
    const dialog = addDialog(page);
    await expect(dialog).toContainText("核对被拒绝的登录请求");
    await expect(dialog).toContainText("核对资格撤销");
    await expect(dialog).not.toContainText("已关闭的旧调查");
    await expect(dialog).toContainText("加入不授予内容读取权限");
    await expect(confirmAdd(page)).toBeDisabled();
    await dialog.getByText("核对资格撤销").click();
    await confirmAdd(page).click();
    await expect(dialog.getByRole("status").filter({ hasText: "已加入案件" })).toBeVisible();
    expect(adds).toHaveLength(1);
    expect(adds[0]?.path).toBe(`/control/v1/cases/${CASE_ID}/items`);
    expect(adds[0]?.body).toEqual({ artifact_id: ARTIFACT_ID });
    expect(adds[0]?.key).toMatch(/^[A-Za-z0-9_.:-]{16,128}$/);
    // A confirmed write leaves the pending registry.
    await expect(page.getByRole("button", { name: /待确认操作/ })).toHaveCount(0);
    await dialog.getByRole("button", { name: "完成", exact: true }).click();
    await expect(dialog).toHaveCount(0);
  });

  test("an unknown result can only be resent exactly, under the original key", async ({ page }) => {
    const adds: Add[] = [];
    await mockControl(
      page,
      caseApi(adds, (caseId, attempt) =>
        attempt === 1
          ? { status: 503, body: errorFixture("CONTROL_CASE_EVIDENCE_STORE_UNAVAILABLE") }
          : { status: 200, body: itemAdded(caseId, true) },
      ),
    );
    await openRequest(page);
    await openEvidence(page);
    await page.getByRole("button", { name: `加入案件 ${ARTIFACT_ID}` }).click();
    const dialog = addDialog(page);
    await dialog.getByText("核对被拒绝的登录请求").click();
    await confirmAdd(page).click();
    await expect(dialog.getByRole("alert")).toContainText("结果未知");
    // The registry keeps the frozen request and the top bar says so.
    const chip = page.getByRole("button", { name: /待确认操作/ });
    await expect(chip).toContainText("1");
    // Nothing else can be sent meanwhile: the selection and the confirm button are locked.
    await expect(confirmAdd(page)).toBeDisabled();
    await dialog.getByRole("button", { name: "确认后原样重试", exact: true }).click();
    await expect(dialog.getByRole("status").filter({ hasText: "原请求已确认" })).toBeVisible();
    expect(adds).toHaveLength(2);
    expect(adds[1]).toEqual(adds[0]);
    await expect(chip).toHaveCount(0);
  });

  test("a clear refusal leaves nothing pending and allows a fresh attempt", async ({ page }) => {
    const adds: Add[] = [];
    await mockControl(
      page,
      caseApi(adds, (caseId, attempt) =>
        attempt === 1
          ? { status: 403, body: errorFixture("CONTROL_SCOPE_DENIED") }
          : { status: 201, body: itemAdded(caseId) },
      ),
    );
    await openRequest(page);
    await openEvidence(page);
    await page.getByRole("button", { name: `加入案件 ${ARTIFACT_ID}` }).click();
    const dialog = addDialog(page);
    await dialog.getByText("核对被拒绝的登录请求").click();
    await confirmAdd(page).click();
    await expect(dialog.getByRole("alert")).toContainText("CONTROL_SCOPE_DENIED");
    await expect(page.getByRole("button", { name: /待确认操作/ })).toHaveCount(0);
    await confirmAdd(page).click();
    await expect(dialog.getByRole("status").filter({ hasText: "已加入案件" })).toBeVisible();
    expect(adds).toHaveLength(2);
    // A refusal is final for that attempt, so the second one is a new operation with a new key.
    expect(adds[1]?.key).not.toBe(adds[0]?.key);
  });

  test("no open case and an unreadable case list are explained", async ({ page }) => {
    let mode: "none" | "denied" = "none";
    await mockControl(page, (url) => {
      if (url.pathname !== "/control/v1/cases") return undefined;
      if (mode === "denied") return { status: 403, body: errorFixture("CONTROL_SCOPE_DENIED") };
      const list = caseList();
      list.items = list.items.filter((item) => item.status !== "open");
      return { body: list };
    });
    await openRequest(page);
    await openEvidence(page);
    await page.getByRole("button", { name: `加入案件 ${ARTIFACT_ID}` }).click();
    await expect(addDialog(page)).toContainText("没有开放的案件");
    await expect(confirmAdd(page)).toBeDisabled();
    await addDialog(page).getByRole("button", { name: "取消", exact: true }).click();
    await expect(addDialog(page)).toHaveCount(0);
    mode = "denied";
    await page.getByRole("button", { name: `加入案件 ${ARTIFACT_ID}` }).click();
    await expect(addDialog(page).getByRole("alert")).toContainText("CONTROL_SCOPE_DENIED");
  });

  test("the artifact drawer offers the same action", async ({ page }) => {
    await mockControl(page, (url) =>
      url.pathname === "/control/v1/cases" ? { body: caseList() } : undefined,
    );
    await openRequest(page);
    await openEvidence(page);
    await page.getByRole("button", { name: `查看元数据 ${ARTIFACT_ID}` }).click();
    const metadata = page.getByRole("dialog", { name: "证据元数据" });
    await metadata.getByRole("button", { name: "加入案件", exact: true }).click();
    await expect(addDialog(page)).toContainText("核对资格撤销");
  });
});
