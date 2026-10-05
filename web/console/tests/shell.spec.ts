import { expect, test } from "@playwright/test";
import { errorFixture, REQUEST_ID } from "./fixtures";
import {
  CASE_ID,
  mockShellApi,
  seamState,
  signIn,
  storageSnapshot,
  TRACE_ID,
} from "./shell-helpers";

const palette = (page: import("@playwright/test").Page) =>
  page.getByRole("combobox", { name: "命令面板" });

test.describe("command palette", () => {
  test("a pasted request ID opens the existing detail route", async ({ page }) => {
    const calls = await mockShellApi(page);
    await signIn(page, "/");
    await page.keyboard.press("Control+KeyK");
    await expect(palette(page)).toBeFocused();
    // Pasted values often carry whitespace and quotes; nothing else is rewritten.
    await palette(page).fill(`  "${REQUEST_ID}" `);
    await expect(page.getByRole("option", { name: /打开请求调查/ })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(new RegExp(`/investigation/requests/${REQUEST_ID}$`));
    await expect(page.getByRole("heading", { name: "请求调查", exact: true })).toBeVisible();
    await expect(page.getByText("user.profile.read", { exact: true })).toBeVisible();
    expect(calls.some((call) => call.path === `/control/v1/requests/${REQUEST_ID}`)).toBe(true);
    await expect(palette(page)).toHaveCount(0);
  });

  test("a trace ID offers an event search that is prefilled but never submitted", async ({
    page,
  }) => {
    const calls = await mockShellApi(page);
    await signIn(page, "/");
    await page.keyboard.press("Control+KeyK");
    await palette(page).fill(TRACE_ID);
    const option = page.getByRole("option", { name: /在事件检索中查找 Trace ID/ });
    await expect(option).toBeVisible();
    await option.click();
    await expect(page).toHaveURL(/\/investigation\/search$/);
    await expect(page.getByLabel("条件 1 字段", { exact: true })).toHaveValue("trace_id");
    await expect(page.getByLabel("条件 1 值", { exact: true })).toHaveValue(TRACE_ID);
    await expect(page.getByLabel("开始时间（UTC，含）", { exact: true })).toHaveValue("");
    await expect(page.getByText("已预填目标引用，请确认 UTC 时间窗后提交历史检索。")).toBeVisible();
    expect(calls.some((call) => call.path === "/control/v1/search")).toBe(false);
  });

  test("IDs without a search preset open their owning page; malformed IDs explain themselves", async ({
    page,
  }) => {
    await mockShellApi(page);
    await signIn(page, "/");
    await page.keyboard.press("Control+KeyK");
    await palette(page).fill(CASE_ID);
    await expect(page.getByRole("option")).toHaveText([/打开案件详情/]);
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(new RegExp(`/cases/${CASE_ID}$`));
    await expect(page.getByRole("heading", { name: "案件工作台", exact: true })).toBeVisible();

    await page.keyboard.press("Control+KeyK");
    await palette(page).fill("req_123");
    await expect(page.getByText("格式不是规范的“前缀_UUIDv7”")).toBeVisible();
    // The half-typed prefix still finds the page that owns it.
    await expect(page.getByRole("option", { name: /请求调查/ })).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(palette(page)).toHaveCount(0);
  });

  test("keyboard use: arrows move the highlight, Enter runs it, Tab stays inside, Esc closes", async ({
    page,
  }) => {
    await mockShellApi(page);
    await signIn(page, "/");
    await page.keyboard.press("Control+KeyK");
    const options = page.getByRole("option");
    await expect(options.first()).toHaveText(/概览/);
    await expect(options.first()).toHaveAttribute("aria-selected", "true");
    await page.keyboard.press("ArrowDown");
    await expect(options.nth(1)).toHaveAttribute("aria-selected", "true");
    await expect(palette(page)).toHaveAttribute(
      "aria-activedescendant",
      (await options.nth(1).getAttribute("id")) ?? "",
    );
    await page.keyboard.press("ArrowUp");
    await page.keyboard.press("ArrowUp");
    await expect(options.last()).toHaveAttribute("aria-selected", "true");
    await expect(options.last()).toHaveText(/权限中心/);

    // Focus is trapped: Tab never rests on the page behind the dialog. With a single tabbable
    // field, leaving the document and coming back is the only other place it can be.
    for (let step = 0; step < 6; step++) {
      await page.keyboard.press("Tab");
      expect(
        await page.evaluate(
          () =>
            document.activeElement === document.body ||
            document.activeElement?.closest('[role="dialog"]') !== null,
        ),
      ).toBe(true);
    }
    await palette(page).focus();
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(/\/access\/session$/);

    await page.keyboard.press("Control+KeyK");
    await expect(palette(page)).toBeFocused();
    await page.keyboard.press("Control+KeyK");
    await expect(palette(page)).toHaveCount(0);
    await page.keyboard.press("Meta+KeyK");
    await expect(palette(page)).toBeFocused();
    await page.keyboard.press("Escape");
    await expect(palette(page)).toHaveCount(0);
  });

  test("fuzzy page search jumps to the right page", async ({ page }) => {
    await mockShellApi(page);
    await signIn(page, "/");
    await page.getByRole("button", { name: "打开命令面板" }).click();
    await palette(page).fill("audit");
    await expect(page.getByRole("option").first()).toHaveText(/审计发布状态/);
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(/\/operations\/audit$/);
    await page.keyboard.press("Control+KeyK");
    await palette(page).fill("没有这个页面zzz");
    await expect(page.getByText("没有匹配的页面或对象。")).toBeVisible();
  });
});

test.describe("theme and density", () => {
  test.describe("system dark", () => {
    test.use({ colorScheme: "dark" });

    test("the system preference applies with an empty storage until the operator chooses", async ({
      page,
    }) => {
      await mockShellApi(page);
      await page.goto("/");
      const root = page.locator("html");
      const canvas = () =>
        page.evaluate(() =>
          getComputedStyle(document.documentElement).getPropertyValue("--xs-canvas").trim(),
        );
      await expect(root).not.toHaveAttribute("data-theme", /.*/);
      expect(await canvas()).toBe("#0A0F1C");
      expect(await page.evaluate(() => getComputedStyle(document.body).backgroundColor)).toBe(
        "rgb(10, 15, 28)",
      );
      expect(await storageSnapshot(page)).toEqual({ local: {}, session: {} });

      await page.getByRole("button", { name: "主题与密度" }).click();
      await page.getByRole("menuitem", { name: "浅色" }).click();
      await expect(root).toHaveAttribute("data-theme", "light");
      expect(await canvas()).toBe("#F2F4F8");
      expect(await storageSnapshot(page)).toEqual({
        local: { "xshield.console.theme": "light" },
        session: {},
      });

      // The choice survives a reload, and "跟随系统" returns to the empty-storage default.
      await page.reload();
      await expect(root).toHaveAttribute("data-theme", "light");
      expect(await canvas()).toBe("#F2F4F8");
      await page.getByRole("button", { name: "主题与密度" }).click();
      await page.getByRole("menuitem", { name: "跟随系统" }).click();
      await expect(root).not.toHaveAttribute("data-theme", /.*/);
      expect(await canvas()).toBe("#0A0F1C");
      expect(await storageSnapshot(page)).toEqual({ local: {}, session: {} });
    });
  });

  test("a light system keeps the light palette, and density is a stored preference too", async ({
    page,
  }) => {
    await mockShellApi(page);
    await signIn(page, "/");
    const root = page.locator("html");
    const control = () =>
      page.evaluate(() =>
        getComputedStyle(document.documentElement).getPropertyValue("--xs-control-height").trim(),
      );
    expect(
      await page.evaluate(() =>
        getComputedStyle(document.documentElement).getPropertyValue("--xs-canvas").trim(),
      ),
    ).toBe("#F2F4F8");
    expect(await control()).toBe("40px");
    await page.getByRole("button", { name: "主题与密度" }).click();
    await page.getByRole("menuitem", { name: "紧凑" }).click();
    await expect(root).toHaveAttribute("data-density", "compact");
    expect(await control()).toBe("32px");
    await page.getByRole("button", { name: "主题与密度" }).click();
    await page.getByRole("menuitem", { name: "深色" }).click();
    await expect(root).toHaveAttribute("data-theme", "dark");
    expect(await storageSnapshot(page)).toEqual({
      local: { "xshield.console.density": "compact", "xshield.console.theme": "dark" },
      session: {},
    });
    await page.reload();
    await expect(root).toHaveAttribute("data-density", "compact");
    await expect(root).toHaveAttribute("data-theme", "dark");
  });

  test("blocked storage never breaks the console", async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    await page.addInitScript(() => {
      Object.defineProperty(window, "localStorage", {
        get() {
          throw new DOMException("blocked", "SecurityError");
        },
      });
    });
    await mockShellApi(page);
    await signIn(page, "/");
    await page.getByRole("button", { name: "主题与密度" }).click();
    await page.getByRole("menuitem", { name: "深色" }).click();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
    await expect(page.getByText("Alpha 官网").first()).toBeVisible();
    expect(errors).toEqual([]);
  });
});

test.describe("mobile navigation drawer", () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test("opens from the header, closes on navigation, Escape and growth", async ({ page }) => {
    await mockShellApi(page);
    await signIn(page, "/");
    const trigger = page.getByRole("button", { name: "打开导航" });
    const nav = page.getByRole("complementary", { name: "后台导航" });
    await expect(trigger).toBeVisible();
    await expect(nav).toBeHidden();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(
      true,
    );

    await trigger.click();
    await expect(nav).toBeVisible();
    await expect(
      nav.getByRole("navigation").getByRole("link", { name: "案件工作台", exact: true }),
    ).toBeVisible();
    await nav.getByRole("link", { name: "案件工作台", exact: true }).click();
    await expect(page).toHaveURL(/\/cases$/);
    await expect(nav).toBeHidden();

    await trigger.click();
    await expect(nav).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(nav).toBeHidden();

    await trigger.click();
    await expect(nav).toBeVisible();
    await nav.getByRole("button", { name: "关闭导航" }).click();
    await expect(nav).toBeHidden();

    await page.setViewportSize({ width: 1280, height: 800 });
    await expect(trigger).toBeHidden();
    await expect(nav).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(
      true,
    );
  });
});

test.describe("pending operations", () => {
  test("a write with an unknown outcome shows in the chip, warns on unload and resumes exactly", async ({
    page,
  }) => {
    await mockShellApi(page);
    await signIn(page, "/");
    await expect(page.getByText("Alpha 官网").first()).toBeVisible();
    const chip = page.getByRole("button", { name: /待确认操作/ });
    await expect(chip).toHaveCount(0);
    const beforeUnloadBlocked = () =>
      page.evaluate(() => !window.dispatchEvent(new Event("beforeunload", { cancelable: true })));
    expect(await beforeUnloadBlocked()).toBe(false);

    const id = await page.evaluate(async () => {
      const { runtime, runFrozenWrite } = window.__xshieldE2E;
      const keys: string[] = [];
      Reflect.set(window, "__e2eKeys", keys);
      let attempts = 0;
      const operation = runtime.pending.freeze({
        label: "创建案件",
        method: "POST",
        path: "/control/v1/cases",
        body: { purpose: "核对合成请求" },
        idempotencyKey: "e2e-operation-key-0001",
        execute: async (_client, _signal, key) => {
          keys.push(key);
          attempts += 1;
          if (attempts === 1) throw new TypeError("offline");
          return {
            request_id: "req_018f2a3b-4c5d-7000-8000-000000000001",
            tenant_id: "tenant_demo",
            site_id: "site_demo",
          };
        },
      });
      const first = await runFrozenWrite(runtime.store, runtime.pending, operation.id);
      return { id: operation.id, kind: first.kind };
    });
    expect(id.kind).toBe("unknown");

    await expect(chip).toContainText("1");
    await chip.click();
    const list = page.getByRole("list", { name: "待确认操作清单" });
    await expect(list).toContainText("创建案件");
    await expect(list).toContainText("结果未知");
    await expect(list).toContainText("POST /control/v1/cases");
    await expect(list).toContainText("e2e-operation-key-0001");
    expect(await beforeUnloadBlocked()).toBe(true);

    // The only way forward is the identical frozen request.
    const second = await page.evaluate(async (operationId) => {
      const { runtime, runFrozenWrite } = window.__xshieldE2E;
      const result = await runFrozenWrite(runtime.store, runtime.pending, operationId);
      return { kind: result.kind, keys: Reflect.get(window, "__e2eKeys") as string[] };
    }, id.id);
    expect(second.kind).toBe("confirmed");
    expect(second.keys).toEqual(["e2e-operation-key-0001", "e2e-operation-key-0001"]);
    await expect(chip).toHaveCount(0);
    expect(await beforeUnloadBlocked()).toBe(false);
    expect(await storageSnapshot(page)).toEqual({ local: {}, session: {} });
  });
});

test.describe("session end clears both layers", () => {
  test("a 401 on a guarded query clears the cache, the registry and every screen", async ({
    page,
  }) => {
    let expired = false;
    await mockShellApi(page, (url) =>
      expired && url.pathname === "/control/v1/workbench/overview"
        ? { status: 401, body: errorFixture("CONTROL_AUTH_REQUIRED") }
        : undefined,
    );
    await signIn(page, "/");
    await expect(page.getByText("Alpha 官网").first()).toBeVisible();
    expect((await seamState(page)).queries).toBeGreaterThan(0);
    await page.evaluate(() => {
      const { runtime } = window.__xshieldE2E;
      runtime.pending.freeze({
        label: "创建案件",
        method: "POST",
        path: "/control/v1/cases",
        execute: async () => ({}),
      });
    });
    expect((await seamState(page)).pending).toBe(1);

    expired = true;
    await page.getByRole("button", { name: "刷新快照" }).click();
    await expect(page.getByRole("status")).toContainText("管理会话已失效");
    await expect(page.getByRole("heading", { name: "连接管理服务" })).toBeVisible();
    await expect(page.getByLabel("管理凭证", { exact: true })).toHaveValue("");
    await expect(page.getByText("Alpha 官网")).toHaveCount(0);
    expect(await seamState(page)).toMatchObject({ status: "disconnected", queries: 0, pending: 0 });
    expect(await storageSnapshot(page)).toEqual({ local: {}, session: {} });
  });

  test("a 401 on a legacy read clears the guarded layer too", async ({ page }) => {
    let expired = false;
    await mockShellApi(page, (url) =>
      expired && url.pathname.startsWith("/control/v1/requests/")
        ? { status: 401, body: errorFixture("CONTROL_AUTH_REQUIRED") }
        : undefined,
    );
    await signIn(page, "/");
    await expect(page.getByText("Alpha 官网").first()).toBeVisible();
    await page.evaluate(() => {
      window.__xshieldE2E.runtime.pending.freeze({
        label: "创建案件",
        method: "POST",
        path: "/control/v1/cases",
        execute: async () => ({}),
      });
    });
    await page
      .getByRole("complementary", { name: "后台导航" })
      .getByRole("link", { name: "请求调查", exact: true })
      .click();
    expired = true;
    await page.getByLabel("请求 ID", { exact: true }).fill(REQUEST_ID);
    await page.getByRole("button", { name: "查询", exact: true }).click();
    await expect(page.getByRole("status")).toContainText("管理会话已失效");
    expect(await seamState(page)).toMatchObject({ status: "disconnected", queries: 0, pending: 0 });
    await expect(page.getByText(REQUEST_ID)).toHaveCount(0);
  });

  test("fifteen idle minutes clear the guarded layer and the registry", async ({ page }) => {
    await page.clock.install();
    await mockShellApi(page);
    await signIn(page, "/");
    await expect(page.getByText("Alpha 官网").first()).toBeVisible();
    await page.evaluate(() => {
      window.__xshieldE2E.runtime.pending.freeze({
        label: "创建案件",
        method: "POST",
        path: "/control/v1/cases",
        execute: async () => ({}),
      });
    });
    await page.clock.fastForward(15 * 60_000 + 1);
    await expect(page.getByRole("status")).toContainText("会话已因闲置断开");
    expect(await seamState(page)).toMatchObject({ status: "disconnected", queries: 0, pending: 0 });
    await expect(page.getByText("Alpha 官网")).toHaveCount(0);
    expect(await storageSnapshot(page)).toEqual({ local: {}, session: {} });
  });

  test("pagehide ends the session and clears both layers", async ({ page }) => {
    await mockShellApi(page);
    await signIn(page, "/");
    await expect(page.getByText("Alpha 官网").first()).toBeVisible();
    await page.evaluate(() => window.dispatchEvent(new Event("pagehide")));
    await expect(page.getByRole("heading", { name: "连接管理服务" })).toBeVisible();
    expect(await seamState(page)).toMatchObject({ status: "disconnected", queries: 0, pending: 0 });
  });
});

test.describe("routing strictness", () => {
  test("trailing slashes, case changes and malformed IDs are not found", async ({ page }) => {
    await mockShellApi(page);
    await signIn(page, "/cases/");
    await expect(page.getByRole("heading", { name: "页面不存在", exact: true })).toBeVisible();
    await expect(page.getByText("该地址没有对应页面，请从侧栏选择功能。")).toBeVisible();
    await expect(page.getByRole("region", { name: "我的案件" })).toHaveCount(0);
    for (const path of ["/Cases", "/investigation/requests/req_bad", "/sites/a/unknown"]) {
      await signIn(page, path);
      await expect(page.getByRole("heading", { name: "页面不存在", exact: true })).toBeVisible();
    }
  });
});
