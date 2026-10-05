import { expect, type Page, test } from "@playwright/test";
import { caseCreatedFixture } from "./case-fixtures";
import { seamState, signIn } from "./shell-helpers";
import {
  apiCalls,
  type Call,
  CASE_ID,
  casesPage,
  expectQuiet,
  mockWork,
  OTHER_CASE_ID,
  refuse,
  writes,
} from "./work-helpers";

const PURPOSE = "核对合成请求的证据引用";
const keyPattern = /^[A-Za-z0-9_.:-]{16,128}$/;

/** Console errors and warnings (antd deprecations, React warnings) fail the test that saw them. */
function watch(page: Page): string[] {
  const seen: string[] = [];
  page.on("pageerror", (error) => seen.push(error.message));
  page.on("console", (message) => {
    if (["error", "warning"].includes(message.type())) seen.push(message.text());
  });
  return seen;
}

const dialog = (page: Page, name: string) => page.getByRole("dialog", { name });
const frozen = (call: Call) => ({
  path: call.path,
  method: call.method,
  key: call.key,
  body: call.body,
});
const beforeUnloadBlocked = (page: Page) =>
  page.evaluate(() => !window.dispatchEvent(new Event("beforeunload", { cancelable: true })));
const sidebar = (page: Page) => page.getByRole("complementary", { name: "后台导航" });

async function openCase(page: Page, caseId = OTHER_CASE_ID, tab?: string) {
  await sidebar(page).getByRole("link", { name: "案件工作台", exact: true }).click();
  await page.getByRole("link", { name: PURPOSE }).waitFor();
  await page.locator(`a[href="/cases/${caseId}"]`).first().click();
  await expect(page).toHaveURL(new RegExp(`/cases/${caseId}$`));
  if (tab) await page.getByRole("tab", { name: tab }).click();
}

test.describe("case list", () => {
  test("loads my cases when the page opens, filters them and never polls", async ({ page }) => {
    const seen = watch(page);
    const calls = await mockWork(page);
    await signIn(page, "/cases");
    await expect(page.getByRole("heading", { name: "案件工作台", exact: true })).toBeVisible();
    // No button press: the list is read because the page opened.
    await expect(page.getByRole("link", { name: PURPOSE })).toBeVisible();
    await expect(page.getByRole("link", { name: "已完成的合成调查" })).toBeVisible();
    await expect(page.getByText("观察于")).toBeVisible();
    expect(apiCalls(calls).every((call) => call.path === "/control/v1/cases")).toBe(true);
    expect(apiCalls(calls).every((call) => call.authorized)).toBe(true);

    const filter = page.getByRole("radiogroup", { name: "案件状态筛选" });
    await filter.getByText(/^开放/).click();
    await expect(page.getByRole("link", { name: "已完成的合成调查" })).toHaveCount(0);
    await filter.getByText(/^已关闭/).click();
    await expect(page.getByRole("link", { name: PURPOSE })).toHaveCount(0);
    await expect(page.getByRole("link", { name: "已完成的合成调查" })).toBeVisible();
    // A filter is a view of the page that was read; it asks the server for nothing.
    const before = apiCalls(calls).length;
    await filter.getByText(/^全部/).click();
    await expectQuiet(page, calls);
    expect(apiCalls(calls).length).toBe(before);
    expect(seen).toEqual([]);
  });

  test("pages by case-ID cursor, each page a fresh read bound to the cursor it was issued", async ({
    page,
  }) => {
    const cursor = `v1.${CASE_ID}.${"b".repeat(64)}`;
    const second = {
      ...casesPage(),
      as_of: "2026-09-20T08:11:00.000001Z",
      items: [
        {
          case_id: "case_018f2a3b-4c5d-7000-8000-000000000030",
          status: "open" as const,
          purpose: "第二页的案件",
          created_at: "2026-09-18T08:00:00.000Z",
        },
      ],
    };
    const calls = await mockWork(page, (url) => {
      if (url.pathname !== "/control/v1/cases") return undefined;
      if (url.searchParams.get("cursor") === cursor) return { body: second };
      return { body: { ...casesPage(), truncated: true, next_cursor: cursor } };
    });
    await signIn(page, "/cases");
    await expect(page.getByRole("link", { name: PURPOSE })).toBeVisible();
    await expect(page.getByRole("button", { name: "上一页" })).toBeDisabled();
    await page.getByRole("button", { name: "下一页" }).click();
    await expect(page.getByRole("link", { name: "第二页的案件" })).toBeVisible();
    // The page replaced the previous one; it does not append.
    await expect(page.getByRole("link", { name: PURPOSE })).toHaveCount(0);
    await expect(page.getByText("第 2 页")).toBeVisible();
    expect(apiCalls(calls).at(-1)?.path).toBe(
      `/control/v1/cases?cursor=${encodeURIComponent(cursor)}`,
    );
    await expect(page.getByRole("button", { name: "下一页" })).toBeDisabled();
    // Back to the first page: the cached observation is shown, a refresh reads it again.
    await page.getByRole("button", { name: "回到首页" }).click();
    await expect(page.getByRole("link", { name: PURPOSE })).toBeVisible();
    await expectQuiet(page, calls);
  });

  for (const [status, code] of [
    [403, "CONTROL_SCOPE_DENIED"],
    [429, "CONTROL_CASE_BUSY"],
    [503, "CONTROL_CASE_STORE_UNAVAILABLE"],
  ] as const) {
    test(`a ${status} refusal keeps its stable code until the operator retries`, async ({
      page,
    }) => {
      // The dev build mounts every page twice, so a refusal is switched by state, not by count.
      let failing = true;
      const calls = await mockWork(page, (url) =>
        url.pathname === "/control/v1/cases" && failing ? refuse(status, code) : undefined,
      );
      await signIn(page, "/cases");
      const alert = page.getByRole("alert").filter({ hasText: code });
      await expect(alert).toBeVisible();
      await expect(alert).toContainText(`HTTP ${status}`);
      await expect(alert).not.toContainText("Synthetic server detail");
      // The refusal stays until the operator asks again: no automatic retry.
      await expectQuiet(page, calls);
      failing = false;
      await alert.getByRole("button", { name: "重试" }).click();
      await expect(page.getByRole("link", { name: PURPOSE })).toBeVisible();
      await expect(page.getByRole("alert")).toHaveCount(0);
    });
  }

  test("a purpose is shown as text, never as markup", async ({ page }) => {
    const seen = watch(page);
    const injection = '<img src=x onerror="window.caseListInjected=true">';
    await mockWork(page, (url) => {
      if (url.pathname !== "/control/v1/cases") return undefined;
      const body = casesPage();
      body.items[0] = { ...body.items[0], purpose: injection } as (typeof body.items)[number];
      return { body };
    });
    await signIn(page, "/cases");
    await expect(page.getByRole("link", { name: injection, exact: true })).toBeVisible();
    await expect(page.locator(".xs-w img")).toHaveCount(0);
    expect(await page.evaluate(() => "caseListInjected" in window)).toBe(false);
    expect(seen).toEqual([]);
  });

  for (const field of ["tenant_id", "site_id"] as const) {
    test(`a ${field} mismatch disconnects and clears the rows`, async ({ page }) => {
      let armed = false;
      await mockWork(page, (url) => {
        if (url.pathname !== "/control/v1/cases" || !armed) return undefined;
        const body = casesPage();
        body[field] = "other_scope";
        body.items[0] = {
          ...body.items[0],
          purpose: "cross-scope-purpose",
        } as (typeof body.items)[number];
        return { body };
      });
      await signIn(page, "/cases");
      await expect(page.getByRole("link", { name: PURPOSE })).toBeVisible();
      armed = true;
      await page.getByRole("button", { name: "刷新", exact: true }).click();
      await expect(page.getByRole("heading", { name: "连接管理服务" })).toBeVisible();
      await expect(page.getByText("响应范围校验失败，连接已断开。")).toBeVisible();
      await expect(page.getByText("cross-scope-purpose")).toHaveCount(0);
      await expect(page.getByRole("link", { name: PURPOSE })).toHaveCount(0);
    });
  }

  test("a read that finishes after the operator left the page is never applied", async ({
    page,
  }) => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let delayNext = false;
    let delayed = false;
    await mockWork(page, async (url) => {
      if (url.pathname !== "/control/v1/cases" || !delayNext) return undefined;
      delayNext = false;
      delayed = true;
      await gate;
      const body = casesPage();
      body.items[0] = {
        ...body.items[0],
        purpose: "STALE-LATE-ROW",
      } as (typeof body.items)[number];
      return { body };
    });
    await signIn(page, "/cases");
    await expect(page.getByRole("link", { name: PURPOSE })).toBeVisible();
    delayNext = true;
    await page.getByRole("button", { name: "刷新", exact: true }).click();
    await expect.poll(() => delayed).toBe(true);
    await sidebar(page).getByRole("link", { name: "权限中心", exact: true }).click();
    // Release the reply only once the page it was meant for is gone.
    await expect(page).toHaveURL(/\/access\/session$/);
    await expect(page.getByRole("link", { name: PURPOSE })).toHaveCount(0);
    release();
    await page.waitForTimeout(300);
    await sidebar(page).getByRole("link", { name: "案件工作台", exact: true }).click();
    await expect(page.getByRole("link", { name: PURPOSE })).toBeVisible();
    await expect(page.getByText("STALE-LATE-ROW")).toHaveCount(0);
  });

  test("401 and fifteen idle minutes end the session and clear the frozen request", async ({
    page,
  }) => {
    await page.clock.install();
    let attempts = 0;
    await mockWork(page, (url, request) => {
      if (url.pathname === "/control/v1/cases" && request.method() === "POST") {
        attempts += 1;
        return { abort: "connectionreset" };
      }
      return undefined;
    });
    await signIn(page, "/cases");
    await page.getByRole("button", { name: "新建案件", exact: true }).click();
    await dialog(page, "新建案件").getByLabel("调查目的").fill(PURPOSE);
    await dialog(page, "新建案件").getByRole("button", { name: "创建案件", exact: true }).click();
    await expect(dialog(page, "新建案件").getByText("结果未知")).toBeVisible();
    expect((await seamState(page)).pending).toBe(1);
    expect(await beforeUnloadBlocked(page)).toBe(true);
    await page.clock.fastForward(15 * 60 * 1000 + 1);
    await expect(page.getByRole("heading", { name: "连接管理服务" })).toBeVisible();
    expect(await seamState(page)).toMatchObject({ status: "disconnected", pending: 0 });
    expect(await beforeUnloadBlocked(page)).toBe(false);
    expect(attempts).toBe(1);
  });
});

test.describe("creating a case", () => {
  async function fillPurpose(page: Page, value = PURPOSE) {
    await page.getByRole("button", { name: "新建案件", exact: true }).click();
    const box = dialog(page, "新建案件");
    await box.getByLabel("调查目的").fill(value);
    return box;
  }

  test("validates the purpose, sends a framework key and opens the new case", async ({ page }) => {
    const seen = watch(page);
    const calls = await mockWork(page, (url, request) =>
      url.pathname === "/control/v1/cases" && request.method() === "POST"
        ? { status: 201, body: caseCreatedFixture(PURPOSE) }
        : undefined,
    );
    await signIn(page, "/cases");
    await page.getByRole("button", { name: "新建案件", exact: true }).click();
    const box = dialog(page, "新建案件");
    const submit = box.getByRole("button", { name: "创建案件", exact: true });
    await expect(submit).toBeDisabled();
    // 171 CJK characters are 513 UTF-8 bytes: the limit is bytes.
    await box.getByLabel("调查目的").fill("中".repeat(171));
    await expect(box).toContainText("最多 512 字节（当前 513 字节）");
    await expect(submit).toBeDisabled();
    await box.getByLabel("调查目的").fill(" 前导空白");
    await expect(box).toContainText("首尾不能有空白");
    await expect(submit).toBeDisabled();
    await box.getByLabel("调查目的").fill(PURPOSE);
    await expect(submit).toBeEnabled();
    // The idempotency key is the framework's business, never a form field.
    await expect(box.getByLabel(/幂等键/)).toHaveCount(0);
    expect(writes(calls)).toEqual([]);
    await submit.click();
    await expect(page).toHaveURL(new RegExp(`/cases/${CASE_ID}$`));
    await expect(page.getByText("案件已创建")).toBeVisible();
    const [post] = writes(calls);
    expect(post).toMatchObject({
      path: "/control/v1/cases",
      body: { purpose: PURPOSE },
    });
    expect(post?.key).toMatch(keyPattern);
    expect(seen).toEqual([]);
    expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0]);
  });

  test("a first refusal keeps the form editable; a second submit is a new request", async ({
    page,
  }) => {
    let attempts = 0;
    const calls = await mockWork(page, (url, request) => {
      if (url.pathname === "/control/v1/cases" && request.method() === "POST") {
        attempts += 1;
        return attempts === 1 ? refuse(403, "CONTROL_SCOPE_DENIED") : undefined;
      }
      return undefined;
    });
    await signIn(page, "/cases");
    const box = await fillPurpose(page);
    await box.getByRole("button", { name: "创建案件", exact: true }).click();
    const alert = box.getByRole("alert").filter({ hasText: "CONTROL_SCOPE_DENIED" });
    await expect(alert).toBeVisible();
    await expect(alert).toContainText("服务端才是最终判断");
    await expect(box.getByLabel("调查目的")).toHaveValue(PURPOSE);
    expect((await seamState(page)).pending).toBe(0);
    await box.getByRole("button", { name: "创建案件", exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`/cases/${CASE_ID}$`));
    const [first, second] = writes(calls);
    // A refusal proves nothing was written, so the next attempt is a different request.
    expect(second?.key).not.toBe(first?.key);
  });

  for (const failure of ["network", "service", "contract"] as const) {
    test(`a ${failure} failure freezes the request; only an exact retry is possible, also after navigating`, async ({
      page,
    }) => {
      let attempts = 0;
      const calls = await mockWork(page, (url, request) => {
        if (url.pathname !== "/control/v1/cases" || request.method() !== "POST") return undefined;
        attempts += 1;
        if (attempts > 1) return { status: 200, body: caseCreatedFixture(PURPOSE, true) };
        if (failure === "network") return { abort: "connectionreset" };
        if (failure === "service") return refuse(503, "CONTROL_CASE_STORE_UNAVAILABLE");
        return { status: 201, body: caseCreatedFixture("a different purpose") };
      });
      await signIn(page, "/cases");
      const box = await fillPurpose(page);
      await box.getByRole("button", { name: "创建案件", exact: true }).click();
      await expect(box.getByText("结果未知")).toBeVisible();
      // The frozen request is shown exactly as it will be resent, and the form is gone.
      await expect(box.getByText("POST /control/v1/cases", { exact: true })).toBeVisible();
      await expect(box.locator("pre")).toContainText(JSON.stringify({ purpose: PURPOSE }, null, 2));
      await expect(box.getByLabel("调查目的")).toHaveCount(0);
      const [original] = writes(calls);
      await expect(box.getByText(original?.key ?? "missing", { exact: true })).toBeVisible();
      expect(await beforeUnloadBlocked(page)).toBe(true);

      // Leave the page: the chip and the unload warning keep the request alive.
      await box.getByRole("button", { name: "稍后处理" }).click();
      await sidebar(page).getByRole("link", { name: "权限中心", exact: true }).click();
      const chip = page.getByRole("button", { name: /待确认操作/ });
      await expect(chip).toContainText("1");
      expect(await beforeUnloadBlocked(page)).toBe(true);
      await sidebar(page).getByRole("link", { name: "案件工作台", exact: true }).click();
      await expect(page.getByText("创建案件：结果未知")).toBeVisible();
      await page.getByRole("button", { name: "查看并处理" }).click();
      await dialog(page, "新建案件").getByRole("button", { name: "原样重试" }).click();
      await expect(page).toHaveURL(new RegExp(`/cases/${CASE_ID}$`));
      const [first, retry] = writes(calls);
      expect(frozen(retry as Call)).toEqual(frozen(first as Call));
      expect(await beforeUnloadBlocked(page)).toBe(false);
      expect((await seamState(page)).pending).toBe(0);
    });
  }

  test("a later refusal never proves the first attempt did not commit", async ({ page }) => {
    let attempts = 0;
    const calls = await mockWork(page, (url, request) => {
      if (url.pathname !== "/control/v1/cases" || request.method() !== "POST") return undefined;
      attempts += 1;
      if (attempts === 1) return { abort: "connectionreset" };
      if (attempts === 2) return refuse(409, "CONTROL_IDEMPOTENCY_CONFLICT");
      return { status: 200, body: caseCreatedFixture(PURPOSE, true) };
    });
    await signIn(page, "/cases");
    const box = await fillPurpose(page);
    await box.getByRole("button", { name: "创建案件", exact: true }).click();
    await expect(box.getByText("结果未知")).toBeVisible();
    await box.getByRole("button", { name: "原样重试" }).click();
    await expect(box.getByText("CONTROL_IDEMPOTENCY_CONFLICT")).toBeVisible();
    // Still unknown, still frozen, still no way to start a different request.
    await expect(box.getByText("结果未知")).toBeVisible();
    await expect(box.getByLabel("调查目的")).toHaveCount(0);
    await expect(box.getByRole("button", { name: "创建案件", exact: true })).toHaveCount(0);
    expect((await seamState(page)).pending).toBe(1);
    await box.getByRole("button", { name: "原样重试" }).click();
    await expect(page).toHaveURL(new RegExp(`/cases/${CASE_ID}$`));
    const posts = writes(calls);
    expect(posts).toHaveLength(3);
    expect(frozen(posts[1] as Call)).toEqual(frozen(posts[0] as Call));
    expect(frozen(posts[2] as Call)).toEqual(frozen(posts[0] as Call));
  });

  test("a reply for another tenant disconnects and shows none of it", async ({ page }) => {
    await mockWork(page, (url, request) =>
      url.pathname === "/control/v1/cases" && request.method() === "POST"
        ? { status: 201, body: { ...caseCreatedFixture(PURPOSE), tenant_id: "other_tenant" } }
        : undefined,
    );
    await signIn(page, "/cases");
    const box = await fillPurpose(page);
    await box.getByRole("button", { name: "创建案件", exact: true }).click();
    await expect(page.getByRole("heading", { name: "连接管理服务" })).toBeVisible();
    await expect(page.getByText("响应范围校验失败，连接已断开。")).toBeVisible();
    await expect(page.getByText(PURPOSE)).toHaveCount(0);
    expect((await seamState(page)).pending).toBe(0);
  });

  test("a reply that arrives after the operator moved on is announced but does not pull them away", async ({
    page,
  }) => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const calls = await mockWork(page, async (url, request) => {
      if (url.pathname === "/control/v1/cases" && request.method() === "POST") {
        await gate;
        return { status: 201, body: caseCreatedFixture(PURPOSE) };
      }
      return undefined;
    });
    await signIn(page, "/cases");
    const box = await fillPurpose(page);
    await box.getByRole("button", { name: "创建案件", exact: true }).click();
    await expect.poll(() => writes(calls).length).toBe(1);
    // The request is on its way; the operator leaves the dialog and then the page.
    await box.getByRole("button", { name: "稍后处理" }).click();
    await sidebar(page).getByRole("link", { name: "权限中心", exact: true }).click();
    release();
    await expect(page.getByText("案件已创建")).toBeVisible();
    await expect(page).toHaveURL(/\/access\/session$/);
    expect((await seamState(page)).pending).toBe(0);
  });
});

test.describe("case detail", () => {
  test("shows the case and opens each tab through its own address", async ({ page }) => {
    const seen = watch(page);
    const calls = await mockWork(page);
    await signIn(page, "/cases");
    await openCase(page);
    await expect(page.getByRole("heading", { name: PURPOSE, exact: true })).toBeVisible();
    await expect(page.getByText("开放", { exact: true }).first()).toBeVisible();
    await expect(page.getByText("目录有效", { exact: true })).toBeVisible();
    await expect(page.getByText("已到期", { exact: true })).toBeVisible();
    for (const [tab, path, read] of [
      ["访问申请", "access", "/control/v1/evidence-access-requests?view=mine"],
      ["保留锁", "holds", `/control/v1/cases/${OTHER_CASE_ID}/holds`],
      ["导出", "exports", "/control/v1/exports?view=mine"],
      ["分析任务", "analysis", ""],
      ["证据集合", "", ""],
    ] as const) {
      const before = apiCalls(calls).length;
      await page.getByRole("tab", { name: tab }).click();
      await expect(page).toHaveURL(new RegExp(`/cases/${OTHER_CASE_ID}${path ? `/${path}` : ""}$`));
      if (read)
        await expect.poll(() => apiCalls(calls).some((call) => call.path === read)).toBe(true);
      else await page.waitForTimeout(150);
      // A tab reads what it shows when it opens, and nothing else (the dev build mounts twice,
      // so count distinct addresses, not requests).
      expect(
        new Set(
          apiCalls(calls)
            .slice(before)
            .map((call) => call.path),
        ).size,
      ).toBeLessThanOrEqual(1);
    }
    await expectQuiet(page, calls);
    expect(seen).toEqual([]);
  });

  test("an unknown case is explained without confirming that it exists", async ({ page }) => {
    await mockWork(page, (url) =>
      /\/cases\/case_[^/]+\/items$/.test(url.pathname)
        ? refuse(404, "CONTROL_CASE_NOT_AVAILABLE")
        : undefined,
    );
    await signIn(page, "/cases");
    await sidebar(page).getByRole("link", { name: "案件工作台", exact: true }).click();
    await page.locator(`a[href="/cases/${OTHER_CASE_ID}"]`).first().click();
    await expect(page.getByText("当前身份和范围内案件不可用")).toBeVisible();
    await expect(page.getByRole("tab")).toHaveCount(0);
  });

  test("closing a case needs a reason, freezes like every write and keeps the history readable", async ({
    page,
  }) => {
    let attempts = 0;
    const calls = await mockWork(page, (url) => {
      if (!url.pathname.endsWith("/close")) return undefined;
      attempts += 1;
      return attempts === 1 ? { abort: "connectionreset" } : undefined;
    });
    await signIn(page, "/cases");
    await openCase(page);
    await page.getByRole("button", { name: "关闭案件", exact: true }).click();
    const box = dialog(page, "关闭案件");
    await expect(box.getByRole("button", { name: "关闭案件", exact: true })).toBeDisabled();
    await box.getByLabel("关闭理由").fill("合成调查已完成");
    await box.getByRole("button", { name: "关闭案件", exact: true }).click();
    await expect(box.getByText("结果未知")).toBeVisible();
    await box.getByRole("button", { name: "原样重试" }).click();
    await expect(page.getByText("案件已关闭")).toBeVisible();
    const [first, retry] = writes(calls);
    expect(first).toMatchObject({
      path: `/control/v1/cases/${OTHER_CASE_ID}/close`,
      body: { reason: "合成调查已完成" },
    });
    expect(frozen(retry as Call)).toEqual(frozen(first as Call));
  });
});

test.describe("redirects from the retired addresses", () => {
  for (const [from, hint] of [
    ["/evidence/holds", "“证据保留”已并入案件"],
    ["/evidence/exports", "“调查导出”已并入案件"],
  ] as const) {
    test(`${from} leaves for the case center with its hint`, async ({ page }) => {
      await mockWork(page);
      await signIn(page, from);
      await expect(page).toHaveURL(/\/cases\?moved=/);
      await expect(page.getByText(hint)).toBeVisible();
      await expect(page.getByRole("link", { name: PURPOSE })).toBeVisible();
      await page
        .getByRole("button", { name: /close|关闭/i })
        .first()
        .click();
      await expect(page.getByText(hint)).toHaveCount(0);
      await expect(page).toHaveURL(/\/cases$/);
    });
  }
});

test("the list and the detail stay inside a 390px screen", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await mockWork(page);
  await signIn(page, "/cases");
  const overflow = () => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth);
  await expect(page.getByRole("link", { name: PURPOSE })).toBeVisible();
  expect(await overflow()).toBe(true);
  await page.getByRole("link", { name: PURPOSE }).click();
  await expect(page.getByRole("tab", { name: "证据集合" })).toBeVisible();
  await expect(page.getByText("目录有效", { exact: true })).toBeVisible();
  expect(await overflow()).toBe(true);
  for (const tab of ["访问申请", "保留锁", "导出", "分析任务"]) {
    await page.getByRole("tab", { name: tab }).click();
    await page.waitForTimeout(150);
    expect(await overflow()).toBe(true);
  }
});
