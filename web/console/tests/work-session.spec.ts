/**
 * Cookie-session (OIDC) build: roles come from the server session, so these checks cover what the
 * machine-login build cannot - role-specific pages, hidden controls and the server's own verdict.
 */
import { expect, type Page, test } from "@playwright/test";
import { ACCESS_ID, accessInspectionFixture, accessListFixture } from "./access-fixtures";
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
  type Call,
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
    // A malformed dialog (for example a <div> inside a <p>) is a React console error.
    const problems: string[] = [];
    page.on("pageerror", (error) => problems.push(error.message));
    page.on("console", (message) => {
      // The browser reports the deliberate 403 of the first attempt itself; that is not a bug.
      if (
        ["error", "warning"].includes(message.type()) &&
        !/^Failed to load resource/.test(message.text())
      )
        problems.push(message.text());
    });
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
    expect(problems).toEqual([]);
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

const APPROVER = ["sensitive_evidence_approver"];
/** The subject the synthetic session signs in as. */
const SUBJECT = "test-subject";

/** The three list sources of the approval center, whatever their query. */
const sourcesRead = (calls: Call[]) => [
  ...new Set(
    apiCalls(calls)
      .filter((call) => call.method === "GET")
      .map((call) => call.path.split("?")[0] ?? "")
      .filter((path) =>
        [
          "/control/v1/evidence-access-requests",
          "/control/v1/exports",
          "/control/v1/sites",
        ].includes(path),
      ),
  ),
];

/** Review queues and details whose requester is the signed-in subject itself. */
const selfRequested: Override = (url, request) => {
  if (request.method() !== "GET") return undefined;
  if (url.pathname === "/control/v1/evidence-access-requests") {
    const list = accessListFixture("review");
    for (const item of list.items) item.requested_by = SUBJECT;
    return { body: list };
  }
  if (url.pathname === `/control/v1/evidence-access-requests/${ACCESS_ID}`) {
    const detail = accessInspectionFixture();
    detail.access_request.requested_by = SUBJECT;
    return { body: detail };
  }
  if (url.pathname === "/control/v1/exports") {
    const list = exportListFixture("review");
    for (const item of list.items) item.requested_by = SUBJECT;
    return { body: list };
  }
  if (url.pathname === `/control/v1/exports/${EXPORT_ID}`)
    return { body: { ...exportFixture("pending_approval"), requested_by: SUBJECT } };
  return undefined;
};

test.describe("the approval center follows the roles the server reports", () => {
  test("an evidence approver reads the two evidence queues and never asks for the site list", async ({
    page,
    baseURL,
  }) => {
    const calls = await open(page, baseURL, "/approvals", APPROVER);
    await expect(page.getByRole("button", { name: `处理 ${ACCESS_ID}` })).toBeVisible();
    await expect(page.getByRole("button", { name: `处理 ${EXPORT_ID}` })).toBeVisible();
    expect(sourcesRead(calls).sort()).toEqual([
      "/control/v1/evidence-access-requests",
      "/control/v1/exports",
    ]);
    // The policy source is not offered either: no 策略 filter, no site banner.
    const filter = page.getByRole("radiogroup", { name: "待办类型筛选" });
    await expect(filter.getByText("策略", { exact: true })).toHaveCount(0);
    await expect(page.getByText("策略修订来自站点清单")).toHaveCount(0);
    expect(apiCalls(calls).every((call) => call.authorized && call.csrf === null)).toBe(true);
    expect(writes(calls)).toEqual([]);
  });

  test("a policy approver reads the site list only; the revisions are located, not decided", async ({
    page,
    baseURL,
  }) => {
    const calls = await open(page, baseURL, "/approvals", ["policy_approver"]);
    await page.getByRole("button", { name: "查看 site_alpha" }).waitFor();
    expect(sourcesRead(calls)).toEqual(["/control/v1/sites"]);
    const filter = page.getByRole("radiogroup", { name: "待办类型筛选" });
    await expect(filter.getByText("原文", { exact: true })).toHaveCount(0);
    await expect(filter.getByText("导出", { exact: true })).toHaveCount(0);
    await page.getByRole("button", { name: "查看 site_alpha" }).click();
    const pane = page.getByRole("region", { name: "审批详情" });
    await expect(pane.getByRole("link", { name: "前往站点发布页审阅并决定" })).toBeVisible();
    expect(writes(calls)).toEqual([]);
  });

  test("a policy approver without the right to list sites is told where the decision lives", async ({
    page,
    baseURL,
  }) => {
    await open(page, baseURL, "/approvals", ["policy_approver"], (url) =>
      url.pathname === "/control/v1/sites" ? refuse(403, "CONTROL_SCOPE_DENIED") : undefined,
    );
    const banner = page.getByRole("alert").filter({ hasText: "策略修订读取失败" });
    await expect(banner).toContainText("CONTROL_SCOPE_DENIED");
    await expect(page.getByText("读取站点清单需要 SystemAdmin")).toBeVisible();
    await expect(page.getByText("没有读取到待办；上方列出了读取失败的来源。")).toBeVisible();
  });

  test("an investigator has no queue of their own to review, only the history of their requests", async ({
    page,
    baseURL,
  }) => {
    const calls = await open(page, baseURL, "/approvals", ["investigator"]);
    await expect(page.getByText("待我审批只对审批角色开放")).toBeVisible();
    expect(apiCalls(calls)).toEqual([]);
    await page.getByRole("tab", { name: "我的申请" }).click();
    await expect(page).toHaveURL(/\/approvals\/mine$/);
    await expect(page.getByRole("button", { name: /^(查看并下载|详情) / }).first()).toBeVisible();
    expect(sourcesRead(calls).sort()).toEqual([
      "/control/v1/evidence-access-requests",
      "/control/v1/exports",
    ]);
    // Only the requester's own views were read; the review queues were not.
    expect(
      apiCalls(calls).every(
        (call) => call.path.includes("view=mine") || call.path.includes("/exports/"),
      ),
    ).toBe(true);
  });

  test("an observer is offered no approval center at all", async ({ page, baseURL }) => {
    const calls = await open(page, baseURL, "/", ["observer"]);
    await expect(page.getByRole("complementary", { name: "后台导航" })).toBeVisible();
    await expect(
      page.getByRole("complementary", { name: "后台导航" }).getByRole("link", { name: "审批中心" }),
    ).toHaveCount(0);
    expect(sourcesRead(calls)).toEqual([]);
  });

  test("a request filed by the signed-in subject offers no decision, and says why", async ({
    page,
    baseURL,
  }) => {
    const calls = await open(page, baseURL, "/approvals", APPROVER, selfRequested);
    await page.getByRole("button", { name: `处理 ${ACCESS_ID}` }).click();
    const pane = page.getByRole("region", { name: "审批详情" });
    await expect(pane.getByText("这是你自己提交的申请")).toBeVisible();
    await expect(pane).toContainText("职责分离");
    await expect(pane.getByLabel("审批理由")).toHaveCount(0);
    await expect(pane.getByRole("button", { name: "批准", exact: true })).toHaveCount(0);
    await expect(pane.getByRole("button", { name: "拒绝", exact: true })).toHaveCount(0);

    await page.getByRole("button", { name: `处理 ${EXPORT_ID}` }).click();
    await expect(pane.getByText("这是你自己提交的导出申请")).toBeVisible();
    await expect(pane.getByLabel("审批理由")).toHaveCount(0);
    await expect(pane.getByRole("button", { name: "批准", exact: true })).toHaveCount(0);
    await expect(pane.getByRole("button", { name: "拒绝", exact: true })).toHaveCount(0);
    expect(writes(calls)).toEqual([]);
  });

  test("approving an export waits for MFA, then repeats the same frozen request", async ({
    page,
    baseURL,
    context,
  }) => {
    const session: Record<string, unknown> = { step_up_valid: false };
    const calls = await open(
      page,
      baseURL,
      "/approvals",
      APPROVER,
      (url, request) =>
        url.pathname === `/control/v1/exports/${EXPORT_ID}/approve` && request.method() === "POST"
          ? session.step_up_valid
            ? undefined
            : refuse(403, "CONTROL_EXPORT_STEP_UP_REQUIRED")
          : undefined,
      session,
    );
    await context.route("**/__reauth**", async (route) => {
      session.step_up_valid = true;
      await route.fulfill({
        contentType: "text/html",
        body: '<!doctype html><title>idp</title><script>location.replace("/")</script>',
      });
    });
    await page.getByRole("button", { name: `处理 ${EXPORT_ID}` }).click();
    const pane = page.getByRole("region", { name: "审批详情" });
    await pane.getByLabel("审批理由").fill("独立复核通过");
    await pane.getByRole("button", { name: "批准", exact: true }).click();

    const dialog = page.getByRole("dialog", { name: "需要 MFA 再认证" });
    await expect(dialog).toBeVisible();
    await expect(dialog).toContainText("原请求（相同的幂等键与内容）会自动重新发送");
    expect(writes(calls)).toHaveLength(1);

    const popup = page.waitForEvent("popup");
    await dialog.getByRole("button", { name: "在新窗口验证" }).click();
    await (await popup).waitForEvent("close");
    await expect(page.getByText("已批准导出申请")).toBeVisible();
    await expect(dialog).toHaveCount(0);

    // The session's own re-authentication start is also a POST; the decision is what repeats.
    const posts = writes(calls).filter((call) => call.path.endsWith("/approve"));
    expect(posts).toHaveLength(2);
    const [first, second] = posts;
    expect(second).toEqual(first);
    expect(first).toMatchObject({
      path: `/control/v1/exports/${EXPORT_ID}/approve`,
      body: { reason: "独立复核通过" },
      csrf: "a".repeat(64),
    });
    expect(first?.key).toMatch(/^[A-Za-z0-9_.:-]{16,128}$/);
    // A decision that went through leaves no stale reason in the form.
    await expect(pane.getByLabel("审批理由")).toHaveValue("");
  });

  test("declining the step-up of a first attempt leaves nothing frozen; the form stays and a new submit is a new request", async ({
    page,
    baseURL,
  }) => {
    const calls = await open(page, baseURL, "/approvals", APPROVER, (url, request) =>
      url.pathname === `/control/v1/exports/${EXPORT_ID}/approve` && request.method() === "POST"
        ? refuse(403, "CONTROL_EXPORT_STEP_UP_REQUIRED")
        : undefined,
    );
    await page.getByRole("button", { name: `处理 ${EXPORT_ID}` }).click();
    const pane = page.getByRole("region", { name: "审批详情" });
    await pane.getByLabel("审批理由").fill("独立复核通过");
    const dialog = page.getByRole("dialog", { name: "需要 MFA 再认证" });
    await pane.getByRole("button", { name: "批准", exact: true }).click();
    await dialog.getByRole("button", { name: "取消，不再继续" }).click();
    await expect(dialog).toHaveCount(0);
    // The server did nothing, so nothing is frozen: the form is back with the reason intact and
    // the refusal explained, and leaving the page does not warn.
    const alert = pane.getByRole("alert").filter({ hasText: "CONTROL_EXPORT_STEP_UP_REQUIRED" });
    await expect(alert).toContainText("需要两分钟内的 MFA 再认证");
    await expect(pane.getByLabel("审批理由")).toHaveValue("独立复核通过");
    await expect(pane.getByText("冻结的请求")).toHaveCount(0);
    expect(
      await page.evaluate(
        () => !window.dispatchEvent(new Event("beforeunload", { cancelable: true })),
      ),
    ).toBe(false);
    // Deciding again freezes a new request under a new key.
    await pane.getByRole("button", { name: "批准", exact: true }).click();
    await dialog.getByRole("button", { name: "取消，不再继续" }).click();
    const posts = writes(calls).filter((call) => call.path.endsWith("/approve"));
    expect(posts).toHaveLength(2);
    expect(posts[0]?.key).not.toBe(posts[1]?.key);
    expect(posts[0]?.body).toEqual(posts[1]?.body);
  });

  test("a retry after an unknown outcome whose step-up is declined stays frozen and later repeats the same request", async ({
    page,
    baseURL,
  }) => {
    const session: Record<string, unknown> = { step_up_valid: false };
    let attempts = 0;
    const calls = await open(
      page,
      baseURL,
      "/approvals",
      APPROVER,
      (url, request) => {
        if (
          url.pathname !== `/control/v1/exports/${EXPORT_ID}/approve` ||
          request.method() !== "POST"
        )
          return undefined;
        attempts += 1;
        if (attempts === 1) return { abort: "connectionreset" };
        return session.step_up_valid ? undefined : refuse(403, "CONTROL_EXPORT_STEP_UP_REQUIRED");
      },
      session,
    );
    await page.getByRole("button", { name: `处理 ${EXPORT_ID}` }).click();
    const pane = page.getByRole("region", { name: "审批详情" });
    await pane.getByLabel("审批理由").fill("独立复核通过");
    await pane.getByRole("button", { name: "批准", exact: true }).click();
    await expect(pane.getByText("结果未知")).toBeVisible();

    // The retry is refused: the MFA window lapsed meanwhile. The operator declines to verify.
    const dialog = page.getByRole("dialog", { name: "需要 MFA 再认证" });
    await pane.getByRole("button", { name: "原样重试" }).click();
    await dialog.getByRole("button", { name: "取消，不再继续" }).click();
    await expect(dialog).toHaveCount(0);
    // The first attempt may have committed, so the refusal does not make it a clean failure:
    // the request stays frozen as unknown (not "waiting for MFA"), and leaving the page warns.
    await expect(pane.getByText("结果未知")).toBeVisible();
    await expect(pane.getByText("尚未成功发送")).toHaveCount(0);
    await expect(
      pane.getByRole("alert").filter({ hasText: "CONTROL_EXPORT_STEP_UP_REQUIRED" }),
    ).toBeVisible();
    await expect(pane.getByLabel("审批理由")).toHaveCount(0);
    expect(
      await page.evaluate(
        () => !window.dispatchEvent(new Event("beforeunload", { cancelable: true })),
      ),
    ).toBe(true);

    // Once the step-up is valid the identical request goes out and settles the question.
    session.step_up_valid = true;
    await pane.getByRole("button", { name: "原样重试" }).click();
    await expect(page.getByText("已批准导出申请")).toBeVisible();
    const posts = writes(calls).filter((call) => call.path.endsWith("/approve"));
    expect(posts).toHaveLength(3);
    for (const post of posts.slice(1)) {
      expect({ path: post.path, key: post.key, body: post.body }).toEqual({
        path: posts[0]?.path,
        key: posts[0]?.key,
        body: posts[0]?.body,
      });
    }
  });

  test("the retired evidence-access address redirects with the same hint in cookie mode", async ({
    page,
    baseURL,
  }) => {
    await open(page, baseURL, "/evidence/access", APPROVER);
    await expect(page).toHaveURL(/\/approvals\?moved=access$/);
    await expect(page.getByText("“证据访问”已并入审批中心")).toBeVisible();
  });
});
