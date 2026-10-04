/**
 * The invariants that outlive a page: a frozen write belongs to the session, not to the screen;
 * a late or foreign reply never repaints anything; whatever ends the session clears everything.
 */
import { expect, type Page, test } from "@playwright/test";
import { caseCreatedFixture, caseItemFixture } from "./case-fixtures";
import { ARTIFACT_ID, OTHER_ARTIFACT_ID, TOKEN } from "./fixtures";
import { holdMutationFixture, holdRecordFixture } from "./hold-fixtures";
import { seamState, signIn, storageSnapshot } from "./shell-helpers";
import {
  type Call,
  CASE_ID,
  collection,
  HOLD_ID,
  holds,
  mockWork,
  OTHER_CASE_ID,
  refuse,
  writes,
} from "./work-helpers";

const sidebar = (page: Page) => page.getByRole("complementary", { name: "后台导航" });
const dialog = (page: Page, name: string) => page.getByRole("dialog", { name });
const frozen = (call: Call) => ({
  path: call.path,
  method: call.method,
  key: call.key,
  body: call.body,
});
const PURPOSE = "核对合成请求的证据引用";

async function openCase(page: Page, caseId: string, tab?: string) {
  await sidebar(page).getByRole("link", { name: "案件工作台", exact: true }).click();
  await page.locator(`a[href="/cases/${caseId}"]`).first().click();
  await expect(page).toHaveURL(new RegExp(`/cases/${caseId}$`));
  if (tab) await page.getByRole("tab", { name: tab }).click();
}

async function freezeCreate(page: Page) {
  await page.getByRole("button", { name: "新建案件", exact: true }).click();
  const box = dialog(page, "新建案件");
  await box.getByLabel("调查目的").fill(PURPOSE);
  await box.getByRole("button", { name: "创建案件", exact: true }).click();
  await expect(box.getByText("结果未知")).toBeVisible();
  return box;
}

test.describe("whatever ends the session clears the frozen request and the screens", () => {
  for (const end of ["401", "disconnect", "pagehide", "reload"] as const) {
    test(`${end}`, async ({ page }) => {
      let attempts = 0;
      await mockWork(page, (url, request) => {
        if (url.pathname !== "/control/v1/cases" || request.method() !== "POST") return undefined;
        attempts += 1;
        return attempts === 1 || end !== "401"
          ? { abort: "connectionreset" }
          : refuse(401, "CONTROL_AUTH_REQUIRED");
      });
      await signIn(page, "/cases");
      const box = await freezeCreate(page);
      const key = await box.locator("dd.mono").nth(1).textContent();
      expect(key).toMatch(/^[0-9a-f-]{36}$/);
      expect((await seamState(page)).pending).toBe(1);
      if (end === "401") await box.getByRole("button", { name: "原样重试" }).click();
      else if (end === "disconnect") {
        await box.getByRole("button", { name: "稍后处理" }).click();
        await page.getByRole("button", { name: "断开连接" }).click();
      } else if (end === "pagehide")
        await page.evaluate(() => window.dispatchEvent(new Event("pagehide")));
      else await page.reload();
      await expect(page.getByRole("heading", { name: "连接管理服务" })).toBeVisible();
      await expect(page.getByText(key ?? "missing")).toHaveCount(0);
      await expect(page.getByText(PURPOSE)).toHaveCount(0);
      expect(await storageSnapshot(page)).toEqual({ local: {}, session: {} });
      await page.getByLabel("管理凭证", { exact: true }).fill(TOKEN);
      await page.getByRole("button", { name: "连接", exact: true }).click();
      // Nothing of the earlier session survived: no banner, no registry entry, no unload warning.
      await sidebar(page).getByRole("link", { name: "案件工作台", exact: true }).click();
      await expect(page.getByRole("link", { name: PURPOSE })).toBeVisible();
      await expect(page.getByText("创建案件：结果未知")).toHaveCount(0);
      expect((await seamState(page)).pending).toBe(0);
      expect(
        await page.evaluate(
          () => !window.dispatchEvent(new Event("beforeunload", { cancelable: true })),
        ),
      ).toBe(false);
    });
  }
});

test.describe("a frozen write stays bound to the object it was frozen for", () => {
  test("a pending association on one case is not reachable from another, and resends to its own", async ({
    page,
  }) => {
    let attempts = 0;
    const calls = await mockWork(page, (url, request) => {
      if (request.method() === "POST" && url.pathname.endsWith("/items")) {
        attempts += 1;
        if (attempts === 1) return { abort: "connectionreset" };
      }
      return undefined;
    });
    await signIn(page, "/cases");
    await openCase(page, OTHER_CASE_ID);
    await page.getByRole("button", { name: "关联证据", exact: true }).click();
    const box = dialog(page, "关联证据");
    await box.getByLabel("证据 ID").fill(ARTIFACT_ID);
    await box.getByRole("button", { name: "关联证据", exact: true }).click();
    await expect(box.getByText("结果未知")).toBeVisible();
    await box.getByRole("button", { name: "稍后处理" }).click();

    // Another case has its own, empty slot: its form is the normal form.
    await sidebar(page).getByRole("link", { name: "案件工作台", exact: true }).click();
    await page.locator(`a[href="/cases/${CASE_ID}"]`).first().click();
    await expect(page.getByText("关联证据：结果未知")).toHaveCount(0);
    await page.getByRole("button", { name: "关联证据", exact: true }).click();
    await expect(dialog(page, "关联证据").getByLabel("证据 ID")).toBeVisible();
    await dialog(page, "关联证据").getByRole("button", { name: "取消" }).click();

    // Back on the first case the frozen request is waiting, and resends to that very case.
    await sidebar(page).getByRole("link", { name: "案件工作台", exact: true }).click();
    await page.locator(`a[href="/cases/${OTHER_CASE_ID}"]`).first().click();
    await page.getByRole("button", { name: "查看并处理" }).click();
    await dialog(page, "关联证据").getByRole("button", { name: "原样重试" }).click();
    await expect(page.getByText("证据已关联")).toBeVisible();
    const [first, retry] = writes(calls);
    expect(first?.path).toBe(`/control/v1/cases/${OTHER_CASE_ID}/items`);
    expect(frozen(retry as Call)).toEqual(frozen(first as Call));
  });

  test("the answer to another case's read never shows on the case being viewed", async ({
    page,
  }) => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let held = false;
    await mockWork(page, async (url) => {
      if (url.pathname !== `/control/v1/cases/${OTHER_CASE_ID}/items`) return undefined;
      held = true;
      await gate;
      const body = collection(OTHER_CASE_ID);
      body.case.purpose = "LATE-ANSWER-FOR-THE-OTHER-CASE";
      return { body };
    });
    await signIn(page, "/cases");
    await sidebar(page).getByRole("link", { name: "案件工作台", exact: true }).click();
    await page.locator(`a[href="/cases/${OTHER_CASE_ID}"]`).first().click();
    await expect.poll(() => held).toBe(true);
    await sidebar(page).getByRole("link", { name: "案件工作台", exact: true }).click();
    await page.locator(`a[href="/cases/${CASE_ID}"]`).first().click();
    await expect(page.getByRole("row").filter({ hasText: ARTIFACT_ID })).toBeVisible();
    release();
    await page.waitForTimeout(300);
    await expect(page.getByText("LATE-ANSWER-FOR-THE-OTHER-CASE")).toHaveCount(0);
  });
});

test.describe("replies that do not match what was frozen", () => {
  test("a hold reply for another artifact leaves the request unknown", async ({ page }) => {
    await mockWork(page, (url, request) =>
      request.method() === "POST" && url.pathname.endsWith("/holds")
        ? {
            status: 201,
            body: {
              ...holdMutationFixture(),
              case_id: OTHER_CASE_ID,
              artifact_id: OTHER_ARTIFACT_ID,
            },
          }
        : undefined,
    );
    await signIn(page, "/cases");
    await openCase(page, OTHER_CASE_ID, "保留锁");
    await page.getByRole("button", { name: "创建保留锁", exact: true }).click();
    const box = dialog(page, "创建保留锁");
    await box.getByLabel("证据", { exact: true }).fill(ARTIFACT_ID);
    await box.getByLabel("保留理由").fill("保留调查证据");
    await box.getByRole("button", { name: "创建保留锁", exact: true }).click();
    await expect(box.getByText("结果未知")).toBeVisible();
    await expect(box.getByText("INVALID_RESPONSE")).toBeVisible();
    await expect(box.locator("pre")).toContainText(ARTIFACT_ID);
    expect((await seamState(page)).pending).toBe(1);
  });

  test("a request timeout keeps the payload and a later refusal does not undo the uncertainty", async ({
    page,
  }) => {
    await page.clock.install();
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let attempts = 0;
    const calls = await mockWork(page, async (url, request) => {
      if (url.pathname !== "/control/v1/cases" || request.method() !== "POST") return undefined;
      attempts += 1;
      if (attempts === 1) {
        await gate;
        return { status: 201, body: caseCreatedFixture(PURPOSE) };
      }
      return refuse(403, "CONTROL_SCOPE_DENIED");
    });
    await signIn(page, "/cases");
    await page.getByRole("button", { name: "新建案件", exact: true }).click();
    const box = dialog(page, "新建案件");
    await box.getByLabel("调查目的").fill(PURPOSE);
    await box.getByRole("button", { name: "创建案件", exact: true }).click();
    await expect.poll(() => writes(calls).length).toBe(1);
    await page.clock.fastForward(15_001);
    await expect(box.getByText("结果未知")).toBeVisible();
    await expect(box.getByText("REQUEST_TIMEOUT")).toBeVisible();
    release();
    await box.getByRole("button", { name: "原样重试" }).click();
    await expect(box.getByText("CONTROL_SCOPE_DENIED")).toBeVisible();
    await expect(box.getByText("结果未知")).toBeVisible();
    expect(frozen(writes(calls)[1] as Call)).toEqual(frozen(writes(calls)[0] as Call));
  });
});

test.describe("text from the server is inert", () => {
  test("member and hold fields render as text, on a narrow screen without overflow", async ({
    page,
  }) => {
    const injected = '<img src=x onerror="window.caseInjected=true">';
    await page.setViewportSize({ width: 390, height: 844 });
    await mockWork(page, (url) => {
      const items = /\/cases\/(case_[^/]+)\/items$/.exec(url.pathname);
      if (items?.[1]) {
        const body = collection(items[1]);
        body.case.purpose = injected;
        body.items = [{ ...caseItemFixture("active", ARTIFACT_ID), added_by: injected }];
        return { body };
      }
      if (url.pathname.endsWith("/holds")) {
        const body = holds(OTHER_CASE_ID, [
          { ...holdRecordFixture(), reason: injected, hold_id: HOLD_ID },
        ]);
        return { body };
      }
      return undefined;
    });
    await signIn(page, "/cases");
    await page.locator(`a[href="/cases/${OTHER_CASE_ID}"]`).first().click();
    await expect(page.getByText(injected, { exact: true }).first()).toBeVisible();
    await page.getByRole("tab", { name: "保留锁" }).click();
    await expect(page.getByText(injected, { exact: true }).first()).toBeVisible();
    await expect(page.locator(".xs-w img")).toHaveCount(0);
    expect(await page.evaluate(() => "caseInjected" in window)).toBe(false);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(
      true,
    );
  });
});
