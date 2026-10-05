import { expect, type Page, test } from "@playwright/test";
import { ACCESS_ID, accessInspectionFixture, accessListFixture } from "./access-fixtures";
import { caseItemFixture } from "./case-fixtures";
import { exportListFixture, exportListItemFixture } from "./export-fixtures";
import { ARTIFACT_ID, OTHER_ARTIFACT_ID } from "./fixtures";
import { holdRecordFixture } from "./hold-fixtures";
import { expectPrefilled } from "./investigation-helpers";
import { signIn } from "./shell-helpers";
import {
  apiCalls,
  type Call,
  CASE_ID,
  collection,
  EXPORT_ID,
  HOLD_ID,
  holds,
  mockWork,
  OTHER_CASE_ID,
  refuse,
  writes,
} from "./work-helpers";

const sidebar = (page: Page) => page.getByRole("complementary", { name: "后台导航" });
const dialog = (page: Page, name: string) => page.getByRole("dialog", { name });
const keyPattern = /^[A-Za-z0-9_.:-]{16,128}$/;
const frozen = (call: Call) => ({
  path: call.path,
  method: call.method,
  key: call.key,
  body: call.body,
});

function watch(page: Page): string[] {
  const seen: string[] = [];
  page.on("pageerror", (error) => seen.push(error.message));
  page.on("console", (message) => {
    if (["error", "warning"].includes(message.type())) seen.push(message.text());
  });
  return seen;
}

/** Sign in, open the case list and then one case (client-side, so the session survives). */
async function openCase(page: Page, caseId: string, tab?: string) {
  await sidebar(page).getByRole("link", { name: "案件工作台", exact: true }).click();
  await page.locator(`a[href="/cases/${caseId}"]`).first().click();
  await expect(page).toHaveURL(new RegExp(`/cases/${caseId}$`));
  if (tab) await page.getByRole("tab", { name: tab }).click();
}

test.describe("evidence tab", () => {
  test("lists members with explained catalog states and reads metadata only on demand", async ({
    page,
  }) => {
    const seen = watch(page);
    const calls = await mockWork(page, (url) =>
      url.pathname === `/control/v1/artifacts/${OTHER_ARTIFACT_ID}`
        ? refuse(403, "CONTROL_SCOPE_DENIED")
        : undefined,
    );
    await signIn(page, "/cases");
    await openCase(page, OTHER_CASE_ID);
    const row = (id: string) => page.getByRole("row").filter({ hasText: id });
    await expect(row(ARTIFACT_ID)).toContainText("目录有效");
    await expect(row(OTHER_ARTIFACT_ID)).toContainText("已到期");
    // Each state carries its explanation, and the page says once what a state does not prove.
    await expect(page.getByTitle(/不证明读取权/).first()).toBeVisible();
    await expect(
      page.getByText("目录状态只描述证据目录，不证明内容读取权或对象完整性"),
    ).toBeVisible();
    expect(apiCalls(calls).some((call) => call.path.includes("/artifacts/"))).toBe(false);

    await row(ARTIFACT_ID).getByRole("button", { name: "元数据" }).click();
    const drawer = page.getByRole("dialog", { name: "证据元数据" });
    await expect(drawer).toContainText("证据 ID");
    await expect(drawer).toContainText("受限");
    expect(
      apiCalls(calls).some((call) => call.path === `/control/v1/artifacts/${ARTIFACT_ID}`),
    ).toBe(true);
    await drawer
      .getByRole("button", { name: /关闭|close/i })
      .first()
      .click();

    // Observer is a separate role: the refusal is explained, not shown as a failure.
    await row(OTHER_ARTIFACT_ID).getByRole("button", { name: "元数据" }).click();
    await expect(
      page
        .getByRole("dialog", { name: "证据元数据" })
        .getByText("查看证据元数据需要 Observer 角色"),
    ).toBeVisible();
    expect(seen.filter((line) => !line.includes("403"))).toEqual([]);
  });

  test("pages members by artifact cursor and starts over on another case", async ({ page }) => {
    const next = caseItemFixture("active", "artifact_018f2a3b-4c5d-7000-8000-000000000013");
    const issued = `v1.${OTHER_ARTIFACT_ID}.${"a".repeat(64)}`;
    const calls = await mockWork(page, (url) => {
      const match = /\/cases\/(case_[^/]+)\/items$/.exec(url.pathname);
      if (!match?.[1]) return undefined;
      const body = collection(match[1]);
      if (url.searchParams.get("cursor") === issued) {
        body.items = [next];
        body.as_of = "2026-09-20T08:12:00.000001Z";
        return { body };
      }
      body.truncated = true;
      body.next_cursor = issued;
      return { body };
    });
    await signIn(page, "/cases");
    await openCase(page, OTHER_CASE_ID);
    await expect(page.getByRole("row").filter({ hasText: ARTIFACT_ID })).toBeVisible();
    await page.getByRole("button", { name: "下一页" }).click();
    await expect(page.getByRole("row").filter({ hasText: "000000000013" })).toBeVisible();
    await expect(page.getByRole("row").filter({ hasText: ARTIFACT_ID })).toHaveCount(0);
    expect(apiCalls(calls).at(-1)?.path).toBe(
      `/control/v1/cases/${OTHER_CASE_ID}/items?cursor=${encodeURIComponent(issued)}`,
    );
    // Another case never inherits this case's cursor.
    await sidebar(page).getByRole("link", { name: "案件工作台", exact: true }).click();
    await page.locator(`a[href="/cases/${CASE_ID}"]`).first().click();
    await expect(page.getByRole("row").filter({ hasText: ARTIFACT_ID })).toBeVisible();
    expect(apiCalls(calls).at(-1)?.path).toBe(`/control/v1/cases/${CASE_ID}/items`);
  });

  test("the association form refuses a malformed ID locally and sends the exact request", async ({
    page,
  }) => {
    const calls = await mockWork(page);
    await signIn(page, "/cases");
    await openCase(page, OTHER_CASE_ID);
    await page.getByRole("button", { name: "关联证据", exact: true }).click();
    const box = dialog(page, "关联证据");
    const submit = box.getByRole("button", { name: "关联证据", exact: true });
    await expect(submit).toBeDisabled();
    for (const bad of ["artifact_invalid", ARTIFACT_ID.toUpperCase(), `${ARTIFACT_ID}x`]) {
      await box.getByLabel("证据 ID").fill(bad);
      await expect(box).toContainText("请输入规范的证据 ID");
      await expect(submit).toBeDisabled();
    }
    expect(writes(calls)).toEqual([]);
    await box.getByLabel("证据 ID").fill(ARTIFACT_ID);
    await expect(submit).toBeEnabled();
    await submit.click();
    await expect(page.getByText("证据已关联")).toBeVisible();
    const [post] = writes(calls);
    expect(post).toMatchObject({
      path: `/control/v1/cases/${OTHER_CASE_ID}/items`,
      body: { artifact_id: ARTIFACT_ID },
    });
    expect(post?.key).toMatch(keyPattern);
    // The confirmed write marks the case lists stale: the members are read again.
    await expect
      .poll(
        () =>
          apiCalls(calls).filter((call) => call.path === `/control/v1/cases/${OTHER_CASE_ID}/items`)
            .length,
      )
      .toBeGreaterThanOrEqual(2);
  });

  test("a closed case cannot take new references", async ({ page }) => {
    await mockWork(page, (url) => {
      const match = /\/cases\/(case_[^/]+)\/items$/.exec(url.pathname);
      if (!match?.[1]) return undefined;
      const body = collection(match[1]);
      body.case.status = "closed";
      return { body };
    });
    await signIn(page, "/cases");
    await openCase(page, CASE_ID);
    await expect(page.getByText("案件已关闭", { exact: true }).first()).toBeVisible();
    await expect(page.getByRole("button", { name: "关联证据", exact: true })).toBeDisabled();
    await expect(page.getByRole("button", { name: "关闭案件", exact: true })).toBeDisabled();
    await expect(page.getByRole("button", { name: "申请原文访问" })).toHaveCount(0);
  });
});

test.describe("access tab", () => {
  const twoCases = () => {
    const list = accessListFixture("mine");
    const other = {
      ...list.items[0],
      access_request_id: `${ACCESS_ID.slice(0, -2)}40`,
      case_id: OTHER_CASE_ID,
    } as (typeof list.items)[number];
    list.items = [list.items[0] as (typeof list.items)[number], other];
    // Strictly falling identities, as the list contract requires.
    list.items.sort((a, b) => (a.access_request_id < b.access_request_id ? 1 : -1));
    return list;
  };

  test("keeps this case's requests from the personal list and says that it did", async ({
    page,
  }) => {
    await mockWork(page, (url) =>
      url.pathname === "/control/v1/evidence-access-requests" ? { body: twoCases() } : undefined,
    );
    await signIn(page, "/cases");
    await openCase(page, CASE_ID, "访问申请");
    await expect(page.getByText("已按本案件筛选")).toBeVisible();
    await expect(page.getByText("本页 2 条申请中有 1 条属于本案件")).toBeVisible();
    await expect(page.getByRole("row").filter({ hasText: ACCESS_ID })).toBeVisible();
    await expect(page.getByRole("row").filter({ hasText: "000000000040" })).toHaveCount(0);
  });

  test("requests original-content access for a member artifact, with a framework key", async ({
    page,
  }) => {
    const seen = watch(page);
    const calls = await mockWork(page);
    await signIn(page, "/cases");
    await openCase(page, OTHER_CASE_ID, "访问申请");
    await page.getByRole("button", { name: "申请原文访问", exact: true }).click();
    const box = dialog(page, "申请原文访问");
    const submit = box.getByRole("button", { name: "提交申请", exact: true });
    await expect(submit).toBeDisabled();
    await box.getByLabel("证据").fill("not-an-artifact");
    await expect(box).toContainText("请选择或输入规范的证据 ID");
    // Members of the case are offered; any member can be picked or pasted.
    await box.getByLabel("证据").fill(ARTIFACT_ID);
    await box.getByLabel("申请理由").fill("核查证据内容");
    await expect(box.getByLabel(/幂等键/)).toHaveCount(0);
    await submit.click();
    await expect(page.getByText("访问申请已提交，等待独立审批")).toBeVisible();
    const [post] = writes(calls);
    expect(post).toMatchObject({
      path: `/control/v1/artifacts/${ARTIFACT_ID}/access`,
      body: { case_id: OTHER_CASE_ID, access_kind: "sensitive_raw", justification: "核查证据内容" },
    });
    expect(post?.key).toMatch(keyPattern);
    expect(seen).toEqual([]);
  });

  test("a member row offers the same request with its artifact preselected", async ({ page }) => {
    const calls = await mockWork(page);
    await signIn(page, "/cases");
    await openCase(page, OTHER_CASE_ID);
    // Only a member whose catalog entry is active offers it.
    await expect(
      page.getByRole("row").filter({ hasText: OTHER_ARTIFACT_ID }).getByRole("button", {
        name: "申请原文访问",
      }),
    ).toHaveCount(0);
    await page
      .getByRole("row")
      .filter({ hasText: ARTIFACT_ID })
      .getByRole("button", { name: "申请原文访问" })
      .click();
    const box = dialog(page, "申请原文访问");
    await expect(box.getByLabel("证据")).toHaveValue(ARTIFACT_ID);
    await box.getByLabel("申请理由").fill("核查证据内容");
    await box.getByRole("button", { name: "提交申请", exact: true }).click();
    await expect(page.getByText("访问申请已提交，等待独立审批")).toBeVisible();
    expect(writes(calls)).toHaveLength(1);
  });

  test("a row opens the request in a drawer, read fresh and shown as text", async ({ page }) => {
    const injected = '<img src=x onerror="window.accessInjected=1">';
    const detail = accessInspectionFixture();
    detail.access_request.justification = injected;
    const calls = await mockWork(page, (url) =>
      /evidence-access-requests\/access_[^/]+$/.test(url.pathname) ? { body: detail } : undefined,
    );
    await signIn(page, "/cases");
    await openCase(page, CASE_ID, "访问申请");
    await page
      .getByRole("row")
      .filter({ hasText: ACCESS_ID })
      .getByRole("button", { name: "详情" })
      .click();
    const drawer = page.getByRole("dialog", { name: "访问申请详情" });
    await expect(drawer.getByText(injected, { exact: true })).toBeVisible();
    await expect(drawer.locator("img")).toHaveCount(0);
    expect(await page.evaluate(() => Reflect.get(window, "accessInjected"))).toBeUndefined();
    expect(apiCalls(calls).at(-1)?.path).toBe(`/control/v1/evidence-access-requests/${ACCESS_ID}`);
    await expect(drawer).toContainText("待审批");
    // The requester's own pending request offers no decision at all.
    await expect(drawer.getByRole("button", { name: "批准" })).toHaveCount(0);
  });
});

test.describe("holds tab", () => {
  test("explains once that a hold grants no read permission and shows each state", async ({
    page,
  }) => {
    // Hold IDs ascend; a release event must differ from the hold it releases.
    const expiredId = `${HOLD_ID.slice(0, -1)}3`;
    const releasedId = `${HOLD_ID.slice(0, -1)}4`;
    await mockWork(page, (url) => {
      if (!url.pathname.endsWith("/holds")) return undefined;
      const body = holds(OTHER_CASE_ID, [
        holdRecordFixture(),
        {
          ...holdRecordFixture(),
          hold_id: expiredId,
          hold_until: "2026-09-20T08:01:00.000Z",
          created_at: "2026-09-20T08:00:00.000Z",
        },
        { ...holdRecordFixture(true), hold_id: releasedId },
      ]);
      return { body };
    });
    await signIn(page, "/cases");
    await openCase(page, OTHER_CASE_ID, "保留锁");
    await expect(page.getByText("保留锁只推迟物理删除，不授予读取权限")).toHaveCount(1);
    const row = (id: string) => page.getByRole("row").filter({ hasText: id });
    await expect(row(HOLD_ID)).toContainText("保留生效中");
    await expect(row(expiredId)).toContainText("保留期限已过");
    await expect(row(releasedId)).toContainText("已释放");
    await expect(row(releasedId)).toContainText("调查已完成");
    // A released hold cannot be released again.
    await expect(row(releasedId).getByRole("button", { name: "释放" })).toBeDisabled();
    await expect(row(HOLD_ID).getByRole("button", { name: "释放" })).toBeEnabled();
  });

  test("creates a hold with a canonical UTC-millisecond deadline inside the server window", async ({
    page,
  }) => {
    const calls = await mockWork(page);
    await signIn(page, "/cases");
    await openCase(page, OTHER_CASE_ID, "保留锁");
    await page.getByRole("button", { name: "创建保留锁", exact: true }).click();
    const box = dialog(page, "创建保留锁");
    const submit = box.getByRole("button", { name: "创建保留锁", exact: true });
    await expect(submit).toBeDisabled();
    await box.getByLabel("证据", { exact: true }).fill(ARTIFACT_ID);
    await box.getByLabel("保留理由").fill("保留调查证据");
    await expect(submit).toBeEnabled();
    await expect(box).toContainText("将保留至");

    // A custom deadline outside the window is refused where the operator is looking.
    await box.getByText("自定义", { exact: true }).click();
    const custom = box.getByLabel("自定义保留截止时间（UTC）");
    await custom.fill("2026-09-20T08:03");
    await expect(box).toContainText("须晚于服务端当前时间至少 2 分钟");
    await expect(submit).toBeDisabled();
    await custom.fill("2026-10-30T08:00");
    await expect(box).toContainText("最多为服务端当前时间之后 720 小时");
    await expect(submit).toBeDisabled();
    await custom.fill("2026-09-22T08:00:30");
    await expect(submit).toBeEnabled();
    await submit.click();
    await expect(page.getByText("保留锁已创建")).toBeVisible();
    const [post] = writes(calls);
    expect(post?.path).toBe(`/control/v1/cases/${OTHER_CASE_ID}/holds`);
    expect(post?.body).toEqual({
      artifact_id: ARTIFACT_ID,
      reason: "保留调查证据",
      hold_until: "2026-09-22T08:00:30.000Z",
    });
    expect(post?.key).toMatch(keyPattern);
  });

  test("the maximum preset stays at least two minutes inside 720 hours of the server clock", async ({
    page,
  }) => {
    const calls = await mockWork(page);
    await signIn(page, "/cases");
    await openCase(page, OTHER_CASE_ID, "保留锁");
    await page.getByRole("button", { name: "创建保留锁", exact: true }).click();
    const box = dialog(page, "创建保留锁");
    await box.getByLabel("证据", { exact: true }).fill(ARTIFACT_ID);
    await box.getByLabel("保留理由").fill("保留调查证据");
    await box.getByText("30 天（上限）", { exact: true }).click();
    await box.getByRole("button", { name: "创建保留锁", exact: true }).click();
    await expect(page.getByText("保留锁已创建")).toBeVisible();
    const until = String((writes(calls)[0]?.body as { hold_until: string }).hold_until);
    expect(until).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    // The history page said 08:02:00 on the server; the deadline is that plus 720 h minus margin
    // (and the few seconds the page has been open).
    const base = Date.parse("2026-09-20T08:02:00.000Z");
    const delta = Date.parse(until) - base;
    expect(delta).toBeGreaterThanOrEqual(720 * 3_600_000 - 2 * 60_000);
    expect(delta).toBeLessThan(720 * 3_600_000 - 2 * 60_000 + 120_000);
  });

  test("releases a hold with a reason, and prepares a history search without submitting it", async ({
    page,
  }) => {
    const calls = await mockWork(page);
    await signIn(page, "/cases");
    await openCase(page, OTHER_CASE_ID, "保留锁");
    await page
      .getByRole("row")
      .filter({ hasText: HOLD_ID })
      .getByRole("button", { name: "释放" })
      .click();
    const box = dialog(page, "释放保留锁");
    const submit = box.getByRole("button", { name: "释放保留锁", exact: true });
    await expect(submit).toBeDisabled();
    await box.getByLabel("释放理由").fill("调查已完成");
    await submit.click();
    await expect(page.getByText("保留锁已释放")).toBeVisible();
    expect(writes(calls)[0]).toMatchObject({
      path: `/control/v1/evidence-holds/${HOLD_ID}/release`,
      body: { reason: "调查已完成" },
    });

    await page.getByRole("button", { name: `准备历史检索 ${HOLD_ID}` }).click();
    await expect(page).toHaveURL(
      new RegExp(`/investigation/search\\?prefill=evidence_hold_id%3A${HOLD_ID}$`),
    );
    await expectPrefilled(page, "保留锁 ID", HOLD_ID);
    expect(apiCalls(calls).some((call) => call.path === "/control/v1/search")).toBe(false);
  });

  test("a closed case cannot take a new hold, but its holds can be released", async ({ page }) => {
    await mockWork(page, (url) => {
      if (!url.pathname.endsWith("/holds")) return undefined;
      const body = holds(OTHER_CASE_ID);
      body.case_status = "closed";
      return { body };
    });
    await signIn(page, "/cases");
    await openCase(page, OTHER_CASE_ID, "保留锁");
    await expect(page.getByRole("button", { name: "创建保留锁", exact: true })).toBeDisabled();
    await expect(
      page.getByRole("row").filter({ hasText: HOLD_ID }).getByRole("button", { name: "释放" }),
    ).toBeEnabled();
  });
});

test.describe("exports tab", () => {
  test("keeps this case's exports from the personal list and requests a new one", async ({
    page,
  }) => {
    const calls = await mockWork(page);
    await signIn(page, "/cases");
    await openCase(page, CASE_ID, "导出");
    await expect(page.getByText("已按本案件筛选")).toBeVisible();
    await expect(page.getByRole("row").filter({ hasText: EXPORT_ID })).toContainText("待审批");
    await page.getByRole("button", { name: "申请导出", exact: true }).click();
    const box = dialog(page, "申请导出");
    const submit = box.getByRole("button", { name: "提交申请", exact: true });
    await expect(submit).toBeDisabled();
    await box.getByLabel("导出用途").fill("核对案件元数据");
    await submit.click();
    await expect(page.getByText("导出申请已提交，等待独立审批")).toBeVisible();
    expect(writes(calls)[0]).toMatchObject({
      path: "/control/v1/exports",
      body: { case_id: CASE_ID, purpose: "核对案件元数据" },
    });
    expect(writes(calls)[0]?.key).toMatch(keyPattern);
  });

  test("an approved or lapsed export shows its true state", async ({ page }) => {
    await mockWork(page, (url) => {
      if (url.pathname !== "/control/v1/exports") return undefined;
      const list = exportListFixture("mine");
      const ready = exportListItemFixture("ready", `${EXPORT_ID.slice(0, -2)}72`);
      // 08:25 expiry against an observation at 08:01 is still valid: make this one lapsed.
      ready.expires_at = "2026-09-20T08:10:00.000Z";
      ready.decided_at = "2026-09-20T08:05:00.000Z";
      list.items = [ready, exportListItemFixture("pending_approval")];
      list.as_of = "2026-09-20T08:30:00.000000Z";
      return { body: list };
    });
    await signIn(page, "/cases");
    await openCase(page, CASE_ID, "导出");
    await expect(page.getByRole("row").filter({ hasText: "000000000072" })).toContainText("已过期");
    await expect(page.getByRole("row").filter({ hasText: EXPORT_ID })).toContainText("待审批");
  });
});

test.describe("analysis tab", () => {
  test("waits for an explicit submit, shows the job counts and reads it again on request", async ({
    page,
  }) => {
    const calls = await mockWork(page);
    await signIn(page, "/cases");
    await openCase(page, OTHER_CASE_ID, "分析任务");
    await expect(page.getByText("尚未提交分析任务")).toBeVisible();
    expect(writes(calls)).toEqual([]);
    await page.getByRole("button", { name: "提交案件清单分析" }).click();
    await expect(page.getByText("分析任务已受理")).toBeVisible();
    const job = page.getByRole("region", { name: "分析任务状态" });
    await expect(job).toContainText("已完成");
    await expect(job.getByText("引用总数")).toBeVisible();
    await expect(job).toContainText("3");
    await expect(job).toContainText("当前有效引用");
    await expect(job).toContainText("inventory_committed");
    const [post] = writes(calls);
    expect(post).toMatchObject({ path: `/control/v1/cases/${OTHER_CASE_ID}/analyze` });
    expect(post?.key).toMatch(keyPattern);
    await job.getByRole("button", { name: "重新读取任务状态" }).click();
    await expect
      .poll(() => apiCalls(calls).some((call) => call.path.startsWith("/control/v1/jobs/job_")))
      .toBe(true);
    await job.getByRole("button", { name: "准备任务历史检索" }).click();
    await expect(page).toHaveURL(/\/investigation\/search\?prefill=job_id%3Ajob_/);
    await expect(page.getByRole("list", { name: "已添加的检索条件" })).toContainText(
      "任务 ID：job_",
    );
    await expect(page.getByText("已预填目标引用，请确认 UTC 时间窗后提交历史检索。")).toBeVisible();
    expect(apiCalls(calls).some((call) => call.path === "/control/v1/search")).toBe(false);
  });
});

/** The write kinds of the case center, each driven through its own dialog. */
type Kind = {
  name: string;
  open: (page: Page) => Promise<void>;
  fill: (page: Page) => Promise<void>;
  submit: (page: Page) => Promise<void>;
  path: RegExp;
  body: unknown;
  /** Where the retry is made (a dialog, or the inline frozen panel of the analysis tab). */
  scope: (page: Page) => ReturnType<Page["locator"]>;
};

const kinds: Kind[] = [
  {
    name: "close case",
    open: async (page) => {
      await openCase(page, OTHER_CASE_ID);
      await page.getByRole("button", { name: "关闭案件", exact: true }).click();
    },
    fill: async (page) => {
      await dialog(page, "关闭案件").getByLabel("关闭理由").fill("合成调查已完成");
    },
    submit: async (page) => {
      await dialog(page, "关闭案件").getByRole("button", { name: "关闭案件", exact: true }).click();
    },
    path: /\/cases\/case_[^/]+\/close$/,
    body: { reason: "合成调查已完成" },
    scope: (page) => dialog(page, "关闭案件"),
  },
  {
    name: "associate evidence",
    open: async (page) => {
      await openCase(page, OTHER_CASE_ID);
      await page.getByRole("button", { name: "关联证据", exact: true }).click();
    },
    fill: async (page) => {
      await dialog(page, "关联证据").getByLabel("证据 ID").fill(ARTIFACT_ID);
    },
    submit: async (page) => {
      await dialog(page, "关联证据").getByRole("button", { name: "关联证据", exact: true }).click();
    },
    path: /\/cases\/case_[^/]+\/items$/,
    body: { artifact_id: ARTIFACT_ID },
    scope: (page) => dialog(page, "关联证据"),
  },
  {
    name: "request access",
    open: async (page) => {
      await openCase(page, OTHER_CASE_ID, "访问申请");
      await page.getByRole("button", { name: "申请原文访问", exact: true }).click();
    },
    fill: async (page) => {
      const box = dialog(page, "申请原文访问");
      await box.getByLabel("证据").fill(ARTIFACT_ID);
      await box.getByLabel("申请理由").fill("核查证据内容");
    },
    submit: async (page) => {
      await dialog(page, "申请原文访问").getByRole("button", { name: "提交申请" }).click();
    },
    path: /\/artifacts\/artifact_[^/]+\/access$/,
    body: { case_id: OTHER_CASE_ID, access_kind: "sensitive_raw", justification: "核查证据内容" },
    scope: (page) => dialog(page, "申请原文访问"),
  },
  {
    name: "request export",
    open: async (page) => {
      await openCase(page, OTHER_CASE_ID, "导出");
      await page.getByRole("button", { name: "申请导出", exact: true }).click();
    },
    fill: async (page) => {
      await dialog(page, "申请导出").getByLabel("导出用途").fill("核对案件元数据");
    },
    submit: async (page) => {
      await dialog(page, "申请导出").getByRole("button", { name: "提交申请" }).click();
    },
    path: /\/exports$/,
    body: { case_id: OTHER_CASE_ID, purpose: "核对案件元数据" },
    scope: (page) => dialog(page, "申请导出"),
  },
  {
    name: "release hold",
    open: async (page) => {
      await openCase(page, OTHER_CASE_ID, "保留锁");
      await page
        .getByRole("row")
        .filter({ hasText: HOLD_ID })
        .getByRole("button", { name: "释放" })
        .click();
    },
    fill: async (page) => {
      await dialog(page, "释放保留锁").getByLabel("释放理由").fill("调查已完成");
    },
    submit: async (page) => {
      await dialog(page, "释放保留锁")
        .getByRole("button", { name: "释放保留锁", exact: true })
        .click();
    },
    path: /\/evidence-holds\/ev_[^/]+\/release$/,
    body: { reason: "调查已完成" },
    scope: (page) => dialog(page, "释放保留锁"),
  },
  {
    name: "create hold",
    open: async (page) => {
      await openCase(page, OTHER_CASE_ID, "保留锁");
      await page.getByRole("button", { name: "创建保留锁", exact: true }).click();
    },
    fill: async (page) => {
      const box = dialog(page, "创建保留锁");
      await box.getByLabel("证据", { exact: true }).fill(ARTIFACT_ID);
      await box.getByLabel("保留理由").fill("保留调查证据");
      await box.getByText("自定义", { exact: true }).click();
      await box.getByLabel("自定义保留截止时间（UTC）").fill("2026-09-22T08:00:30");
    },
    submit: async (page) => {
      await dialog(page, "创建保留锁")
        .getByRole("button", { name: "创建保留锁", exact: true })
        .click();
    },
    path: /\/cases\/case_[^/]+\/holds$/,
    body: {
      artifact_id: ARTIFACT_ID,
      reason: "保留调查证据",
      hold_until: "2026-09-22T08:00:30.000Z",
    },
    scope: (page) => dialog(page, "创建保留锁"),
  },
];

test.describe("every write is frozen at submit and can only be retried exactly", () => {
  for (const kind of kinds) {
    test(`${kind.name}: unknown outcome, later refusal, exact retry`, async ({ page }) => {
      let attempts = 0;
      const calls = await mockWork(page, (url, request) => {
        if (request.method() !== "POST" || !kind.path.test(url.pathname)) return undefined;
        attempts += 1;
        if (attempts === 1) return { abort: "connectionreset" };
        if (attempts === 2) return refuse(409, "CONTROL_IDEMPOTENCY_CONFLICT");
        return undefined;
      });
      await signIn(page, "/cases");
      await kind.open(page);
      await kind.fill(page);
      await kind.submit(page);
      const box = kind.scope(page);
      await expect(box.getByText("结果未知")).toBeVisible();
      // What will be resent is on screen, byte for byte, and cannot be edited.
      const [original] = writes(calls);
      await expect(box.getByText(original?.key ?? "missing", { exact: true })).toBeVisible();
      await expect(box.locator("pre")).toContainText(
        Object.values(kind.body as Record<string, string>)[0] ?? "",
      );
      expect(original?.body).toEqual(kind.body);
      await box.getByRole("button", { name: "原样重试" }).click();
      await expect(box.getByText("CONTROL_IDEMPOTENCY_CONFLICT")).toBeVisible();
      await expect(box.getByText("结果未知")).toBeVisible();
      await box.getByRole("button", { name: "原样重试" }).click();
      await expect.poll(() => writes(calls).length).toBe(3);
      const posts = writes(calls);
      expect(frozen(posts[1] as Call)).toEqual(frozen(posts[0] as Call));
      expect(frozen(posts[2] as Call)).toEqual(frozen(posts[0] as Call));
      await expect
        .poll(
          async () =>
            await page.evaluate(() => window.__xshieldE2E.runtime.pending.unresolvedCount),
        )
        .toBe(0);
    });
  }

  test("analysis: unknown outcome and exact retry", async ({ page }) => {
    let attempts = 0;
    const calls = await mockWork(page, (url, request) => {
      if (request.method() === "POST" && url.pathname.endsWith("/analyze")) {
        attempts += 1;
        if (attempts === 1) return { abort: "connectionreset" };
      }
      return undefined;
    });
    await signIn(page, "/cases");
    await openCase(page, OTHER_CASE_ID, "分析任务");
    await page.getByRole("button", { name: "提交案件清单分析" }).click();
    await expect(page.getByText("结果未知")).toBeVisible();
    await page.getByRole("button", { name: "原样重试" }).click();
    await expect(page.getByText("分析任务已受理")).toBeVisible();
    const [first, retry] = writes(calls);
    expect(frozen(retry as Call)).toEqual(frozen(first as Call));
  });
});
