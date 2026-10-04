/**
 * Cookie-session (OIDC) build: roles come from the server session, so these checks cover what the
 * machine-login build cannot - role-specific pages, hidden controls and the server's own verdict.
 */
import { expect, type Page, test } from "@playwright/test";
import {
  exportDownloadHeaders,
  exportFixture,
  exportListFixture,
  exportListItemFixture,
} from "./export-fixtures";
import { holdRecordFixture } from "./hold-fixtures";
import { ARTIFACT_ID } from "./fixtures";
import {
  apiCalls,
  CASE_ID,
  collection,
  EXPORT_ID,
  holds,
  type Mode,
  mockWork,
  OTHER_CASE_ID,
  type Override,
  refuse,
  writes,
} from "./work-helpers";

async function open(
  page: Page,
  baseURL: string | undefined,
  path: string,
  roles: string[],
  override?: Override,
  session?: Mode["session"],
) {
  const calls = await mockWork(page, override, {
    kind: "session",
    roles,
    session,
    origin: baseURL,
  });
  await page.goto(path);
  return calls;
}

test.describe("the case center follows the roles the server reports", () => {
  test("an investigator sees cases and four tabs, never the hold tab", async ({
    page,
    baseURL,
  }) => {
    const calls = await open(page, baseURL, "/cases", ["investigator"]);
    await expect(page.getByRole("link", { name: "核对合成请求的证据引用" })).toBeVisible();
    await expect(page.getByRole("button", { name: "新建案件", exact: true })).toBeVisible();
    await page.getByRole("link", { name: "核对合成请求的证据引用" }).click();
    await expect(page.getByRole("tab", { name: "证据集合" })).toBeVisible();
    await expect(page.getByRole("tab")).toHaveText(["证据集合", "访问申请", "导出", "分析任务"]);
    // Cookie mode carries no Bearer; reads need no CSRF header, and nothing was written.
    expect(apiCalls(calls).every((call) => call.authorized && call.csrf === null)).toBe(true);
    expect(writes(calls)).toEqual([]);
    // The signed-in subject is the case owner.
    await expect(page.getByText("负责人 test-subject")).toBeVisible();
  });

  test("writes carry the CSRF header and no Bearer", async ({ page, baseURL }) => {
    const calls = await open(page, baseURL, "/cases", ["investigator"]);
    await page.getByRole("button", { name: "新建案件", exact: true }).click();
    const box = page.getByRole("dialog", { name: "新建案件" });
    await box.getByLabel("调查目的").fill("核对合成请求的证据引用");
    await box.getByRole("button", { name: "创建案件", exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`/cases/${CASE_ID}$`));
    const [post] = writes(calls);
    expect(post?.csrf).toBe("a".repeat(64));
    expect(post?.authorized).toBe(true);
  });

  test("an audit administrator cannot list cases; the case is opened by ID and only holds show", async ({
    page,
    baseURL,
  }) => {
    const calls = await open(page, baseURL, "/cases", ["audit_administrator"], (url, request) =>
      request.method() === "GET" && url.pathname.endsWith("/holds")
        ? { body: holds(OTHER_CASE_ID, [holdRecordFixture()]) }
        : undefined,
    );
    await expect(page.getByText("按案件 ID 打开案件", { exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "新建案件", exact: true })).toHaveCount(0);
    expect(apiCalls(calls)).toEqual([]);
    const box = page.getByLabel("案件 ID", { exact: true });
    await box.fill("case_invalid");
    await expect(page.getByText("案件 ID 格式无效")).toBeVisible();
    await expect(page.getByRole("button", { name: "打开案件" })).toBeDisabled();
    await box.fill(OTHER_CASE_ID);
    await page.getByRole("button", { name: "打开案件" }).click();
    await expect(page).toHaveURL(new RegExp(`/cases/${OTHER_CASE_ID}$`));
    await expect(page.getByRole("tab")).toHaveText(["保留锁"]);
    await expect(page.getByText("仅显示保留锁")).toBeVisible();
    await expect(page.getByRole("row").filter({ hasText: "保留生效中" })).toBeVisible();
    // The case itself needs Investigator: the server was never asked for it.
    expect([...new Set(apiCalls(calls).map((call) => call.path))]).toEqual([
      `/control/v1/cases/${OTHER_CASE_ID}/holds`,
    ]);
    await page.getByRole("button", { name: "创建保留锁", exact: true }).click();
    const dialog = page.getByRole("dialog", { name: "创建保留锁" });
    await dialog.getByLabel("证据", { exact: true }).fill(ARTIFACT_ID);
    await dialog.getByLabel("保留理由").fill("保留调查证据");
    await dialog.getByRole("button", { name: "创建保留锁", exact: true }).click();
    await expect(page.getByText("保留锁已创建")).toBeVisible();
    expect(writes(calls)[0]?.csrf).toBe("a".repeat(64));
  });

  for (const role of ["observer", "sensitive_evidence_approver", "sensitive_evidence_reader"]) {
    test(`${role} is told the case list is not theirs and asks the server for nothing`, async ({
      page,
      baseURL,
    }) => {
      const calls = await open(page, baseURL, "/cases", [role]);
      await expect(page.getByText("当前角色不能读取案件列表")).toBeVisible();
      await expect(page.getByRole("button", { name: "新建案件", exact: true })).toHaveCount(0);
      expect(apiCalls(calls)).toEqual([]);
    });
  }

  test("hiding is a courtesy: the server's refusal of a listed page is shown with its code", async ({
    page,
    baseURL,
  }) => {
    await open(page, baseURL, "/cases", ["investigator"], (url) =>
      url.pathname === "/control/v1/cases" ? refuse(403, "CONTROL_SCOPE_DENIED") : undefined,
    );
    const alert = page.getByRole("alert").filter({ hasText: "CONTROL_SCOPE_DENIED" });
    await expect(alert).toContainText("服务端才是最终判断");
    await expect(alert).toContainText("HTTP 403");
  });

  test("an investigator without Observer gets the role hint, not a failure, for evidence metadata", async ({
    page,
    baseURL,
  }) => {
    await open(page, baseURL, "/cases", ["investigator"], (url) => {
      if (url.pathname.startsWith("/control/v1/artifacts/"))
        return refuse(403, "CONTROL_SCOPE_DENIED");
      const items = /\/cases\/(case_[^/]+)\/items$/.exec(url.pathname);
      return items?.[1] ? { body: collection(items[1]) } : undefined;
    });
    await page.getByRole("link", { name: "核对合成请求的证据引用" }).click();
    await page
      .getByRole("row")
      .filter({ hasText: ARTIFACT_ID })
      .getByRole("button", { name: "元数据" })
      .click();
    await expect(page.getByText("查看证据元数据需要 Observer 角色")).toBeVisible();
  });
});

const READER = ["investigator", "sensitive_evidence_reader"];
const PACKAGE = Buffer.from("0123456789abcdefg");

/** A ready export in the personal list and its detail, with the package bytes the client expects. */
function readyExport(): Override {
  return (url, request) => {
    if (request.method() !== "GET") return undefined;
    if (url.pathname === "/control/v1/exports") {
      const list = exportListFixture("mine");
      list.items = [exportListItemFixture("ready")];
      return { body: list };
    }
    if (url.pathname === `/control/v1/exports/${EXPORT_ID}`)
      return { body: exportFixture("ready") };
    return undefined;
  };
}

async function openExportDrawer(page: Page) {
  // The export belongs to the (closed) case of the fixtures.
  await page.locator(`a[href="/cases/${CASE_ID}"]`).first().click();
  await page.getByRole("tab", { name: "导出" }).click();
  await page.getByRole("button", { name: "查看并下载" }).click();
  return page.getByRole("dialog", { name: "导出详情" });
}

test.describe("in-place MFA step-up", () => {
  test("a refused download waits, the operator verifies in a window, and the same request repeats", async ({
    page,
    baseURL,
    context,
  }) => {
    const session: Record<string, unknown> = { step_up_valid: false };
    const base = readyExport();
    const calls = await open(
      page,
      baseURL,
      "/cases",
      READER,
      (url, request, call, count) => {
        if (url.pathname === `/control/v1/exports/${EXPORT_ID}/download`) {
          return session.step_up_valid
            ? { raw: PACKAGE, headers: exportDownloadHeaders(PACKAGE.length) }
            : refuse(403, "CONTROL_EXPORT_STEP_UP_REQUIRED");
        }
        return base(url, request, call, count);
      },
      session,
    );
    // The identity provider's page sends the operator back to the console root, as it really does.
    await context.route("**/__reauth**", async (route) => {
      session.step_up_valid = true;
      await route.fulfill({
        contentType: "text/html",
        body: '<!doctype html><title>idp</title><script>location.replace("/")</script>',
      });
    });
    await page.getByRole("link", { name: "核对合成请求的证据引用" }).waitFor();
    const drawer = await openExportDrawer(page);
    await expect(drawer).toContainText("剩余领取 2/2 次");
    await drawer.getByRole("button", { name: "下载导出包" }).click();

    const dialog = page.getByRole("dialog", { name: "需要 MFA 再认证" });
    await expect(dialog).toBeVisible();
    await expect(dialog).toContainText("原请求（相同的幂等键与内容）会自动重新发送");
    // Nothing is sent again until the operator verifies.
    expect(apiCalls(calls).filter((call) => call.path.endsWith("/download"))).toHaveLength(1);

    const popup = page.waitForEvent("popup");
    const download = page.waitForEvent("download");
    await dialog.getByRole("button", { name: "在新窗口验证" }).click();
    await (await popup).waitForEvent("close");
    expect((await download).suggestedFilename()).toBe("investigation-export.json");
    await expect(dialog).toHaveCount(0);

    const attempts = apiCalls(calls).filter((call) => call.path.endsWith("/download"));
    expect(attempts).toHaveLength(2);
    // The same request, resent: same address, no body, and the CSRF companion of the session.
    expect(attempts[1]).toEqual(attempts[0]);
    const start = calls.find((call) => call.path === "/control/v1/auth/oidc/reauth/start");
    expect(start).toMatchObject({ method: "POST", csrf: "a".repeat(64) });
    await expect(
      drawer.getByText("已发起附件保存：investigation-export.json（17 字节）"),
    ).toBeVisible();
  });

  test("cancelling ends the attempt with the server's own refusal; nothing is sent again", async ({
    page,
    baseURL,
  }) => {
    const base = readyExport();
    const calls = await open(page, baseURL, "/cases", READER, (url, request, call, count) =>
      url.pathname.endsWith("/download")
        ? refuse(403, "CONTROL_EXPORT_STEP_UP_REQUIRED")
        : base(url, request, call, count),
    );
    await page.getByRole("link", { name: "核对合成请求的证据引用" }).waitFor();
    const drawer = await openExportDrawer(page);
    await drawer.getByRole("button", { name: "下载导出包" }).click();
    const dialog = page.getByRole("dialog", { name: "需要 MFA 再认证" });
    await dialog.getByRole("button", { name: "取消，不再继续" }).click();
    await expect(dialog).toHaveCount(0);
    const alert = drawer.getByRole("alert").filter({ hasText: "CONTROL_EXPORT_STEP_UP_REQUIRED" });
    await expect(alert).toContainText("需要两分钟内的 MFA 再认证");
    await expect(alert).toContainText("最近 2 分钟内的 MFA 再认证");
    expect(apiCalls(calls).filter((call) => call.path.endsWith("/download"))).toHaveLength(1);
  });

  test("a blocked window keeps the operator in control with the reason and a way out", async ({
    page,
    baseURL,
  }) => {
    await page.addInitScript(() => {
      window.open = () => null;
    });
    const base = readyExport();
    await open(page, baseURL, "/cases", READER, (url, request, call, count) =>
      url.pathname.endsWith("/download")
        ? refuse(403, "CONTROL_EXPORT_STEP_UP_REQUIRED")
        : base(url, request, call, count),
    );
    await page.getByRole("link", { name: "核对合成请求的证据引用" }).waitFor();
    const drawer = await openExportDrawer(page);
    await drawer.getByRole("button", { name: "下载导出包" }).click();
    const dialog = page.getByRole("dialog", { name: "需要 MFA 再认证" });
    await dialog.getByRole("button", { name: "在新窗口验证" }).click();
    await expect(dialog).toContainText("浏览器拦截了新窗口");
    await expect(dialog.getByRole("button", { name: "在新窗口验证" })).toBeVisible();
    await dialog.getByRole("button", { name: "取消，不再继续" }).click();
    await expect(dialog).toHaveCount(0);
  });

  test("the session ending while the step-up waits ends the attempt and the dialog", async ({
    page,
    baseURL,
  }) => {
    const base = readyExport();
    await open(page, baseURL, "/cases", READER, (url, request, call, count) =>
      url.pathname.endsWith("/download")
        ? refuse(403, "CONTROL_EXPORT_STEP_UP_REQUIRED")
        : base(url, request, call, count),
    );
    await page.getByRole("link", { name: "核对合成请求的证据引用" }).waitFor();
    const drawer = await openExportDrawer(page);
    await drawer.getByRole("button", { name: "下载导出包" }).click();
    const dialog = page.getByRole("dialog", { name: "需要 MFA 再认证" });
    await expect(dialog).toBeVisible();
    await page.evaluate(() => window.dispatchEvent(new Event("pagehide")));
    await expect(page.getByRole("button", { name: "使用企业身份登录" })).toBeVisible();
    await expect(dialog).toHaveCount(0);
  });
});
