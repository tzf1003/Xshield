import { expect, type Page, test } from "@playwright/test";
import { errorFixture } from "./fixtures";
import { signIn } from "./shell-helpers";
import { CASE_ID, JOB_ID } from "./work-helpers";
import { mockWorkbench, type Override, reads } from "./workbench-helpers";

// Audit publication, job lookup and the API key page in the machine-login build. The cookie
// session cases (roles, key administration) are in api-keys-session and operations-session.

const OTHER_JOB = "job_018f2a3b-4c5d-7000-8000-000000000042";

async function open(page: Page, path: string, override?: Override) {
  const calls = await mockWorkbench(page, { override });
  await signIn(page, path);
  return calls;
}

const paths = (calls: readonly { path: string }[]) => calls.map((call) => call.path);
// The my-jobs list is its own GET; these assertions count only the job-detail reads.
const detailReads = (calls: Parameters<typeof reads>[0]) =>
  reads(calls).filter((path) => path.startsWith("/control/v1/jobs/"));

test.describe("audit publication", () => {
  test("reads only when asked, and never again by itself", async ({ page }) => {
    await page.clock.install();
    const calls = await open(page, "/operations/audit");
    await expect(page.getByRole("heading", { name: "审计发布状态", level: 1 })).toBeVisible();
    await expect(page.getByText(/不代表业务准入、全部 Outbox 状态或系统整体健康/)).toBeVisible();
    await page.waitForTimeout(300);
    expect(calls).toHaveLength(0);
    await page.getByRole("button", { name: "读取发布状态" }).click();
    const result = page.getByRole("region", { name: "审计发布状态结果" });
    await expect(result).toContainText("发布观察到缺口");
    await expect(result.getByRole("list", { name: "封存段统计" })).toContainText("未封存段1");
    await expect(result).toContainText("32,768 字节（32.0 KiB）");
    await expect(result).toContainText("连续水位只覆盖配置 journal 的已确认封存段");
    const read = calls.length;
    await page.clock.fastForward(10 * 60_000);
    await page.evaluate(() => window.dispatchEvent(new Event("focus")));
    await page.waitForTimeout(300);
    expect(calls).toHaveLength(read);
    expect(paths(calls)).toEqual(["/control/v1/audit/health"]);
  });

  test("a refusal is a role hint, a failure an error; no stale result stays", async ({ page }) => {
    let status = 403;
    await open(page, "/operations/audit", (url) =>
      url.pathname === "/control/v1/audit/health"
        ? {
            status,
            body: errorFixture(
              status === 403 ? "CONTROL_SCOPE_DENIED" : "CONTROL_HEALTH_UNAVAILABLE",
            ),
          }
        : undefined,
    );
    await page.getByRole("button", { name: "读取发布状态" }).click();
    await expect(page.getByText("审计发布状态被服务端拒绝")).toBeVisible();
    status = 503;
    await page.getByRole("button", { name: "读取发布状态" }).click();
    await expect(page.getByRole("alert").filter({ hasText: "审计发布状态读取失败" })).toContainText(
      "CONTROL_HEALTH_UNAVAILABLE",
    );
    await expect(page.getByRole("region", { name: "审计发布状态结果" })).toHaveCount(0);
  });
});

test.describe("job lookup", () => {
  test("a pasted ID of another kind is named and its own page offered; nothing is read", async ({
    page,
  }) => {
    const calls = await open(page, "/operations/jobs");
    const input = page.getByLabel("任务 ID", { exact: true });
    await input.fill(CASE_ID);
    await page.getByRole("button", { name: "查询", exact: true }).click();
    await expect(page.getByText("这是案件 ID，不是任务 ID。可以直接打开它：")).toBeVisible();
    await expect(page.getByRole("link", { name: "打开案件详情" })).toHaveAttribute(
      "href",
      `/cases/${CASE_ID}`,
    );
    await input.fill("job_123");
    await page.getByRole("button", { name: "查询", exact: true }).click();
    await expect(page.getByText(/任务 ID 的格式不对/)).toBeVisible();
    await input.fill(JOB_ID.toUpperCase());
    await page.getByRole("button", { name: "查询", exact: true }).click();
    await expect(page.getByText(/任务 ID 的格式不对/)).toBeVisible();
    // The page's own my-jobs list may load; a rejected lookup must read no job.
    expect(detailReads(calls)).toEqual([]);
  });

  test("a valid ID becomes the address and is read once; the result explains itself", async ({
    page,
  }) => {
    await page.clock.install();
    const calls = await open(page, "/operations/jobs");
    await page.getByLabel("任务 ID", { exact: true }).fill(`  "${JOB_ID}" `);
    await page.getByRole("button", { name: "查询", exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`/operations/jobs\\?job=${JOB_ID}$`));
    const card = page.getByRole("region", { name: "任务状态" });
    await expect(card).toContainText("已完成");
    await expect(card).toContainText("清单分析完成");
    await expect(card).toContainText("没有读取证据内容、调用模型或创建任何资格");
    await expect(card.getByRole("link", { name: "打开该案件的分析页签" })).toHaveAttribute(
      "href",
      `/cases/${CASE_ID}/analysis`,
    );
    await expect.poll(() => detailReads(calls)).toEqual([`/control/v1/jobs/${JOB_ID}`]);
    const read = calls.length;
    await page.clock.fastForward(10 * 60_000);
    await page.waitForTimeout(300);
    expect(calls).toHaveLength(read);
    await card.getByRole("button", { name: "重新读取" }).click();
    await expect.poll(() => calls.length).toBe(read + 1);
  });

  test("my jobs lists the caller's jobs and opens one through the same detail read", async ({
    page,
  }) => {
    const calls = await open(page, "/operations/jobs");
    const mine = page.getByRole("region", { name: "我的任务" });
    await expect(mine).toContainText("已完成");
    await expect(mine).toContainText("运行中");
    await expect(mine.getByText(JOB_ID)).toBeVisible();
    await expect.poll(() => reads(calls)).toContain("/control/v1/jobs");
    expect(detailReads(calls)).toEqual([]);
    await mine.getByRole("button", { name: "查看", exact: true }).first().click();
    await expect(page).toHaveURL(new RegExp(`/operations/jobs\\?job=${JOB_ID}$`));
    await expect(page.getByRole("region", { name: "任务状态" })).toContainText("已完成");
    await expect.poll(() => detailReads(calls)).toEqual([`/control/v1/jobs/${JOB_ID}`]);
  });

  test("a deep link reads its job; an unknown job stays opaque", async ({ page }) => {
    const calls = await open(page, `/operations/jobs?job=${OTHER_JOB}`, (url) =>
      url.pathname === `/control/v1/jobs/${OTHER_JOB}`
        ? {
            body: {
              request_id: "req_018f2a3b-4c5d-7000-8000-000000000001",
              tenant_id: "tenant_demo",
              site_id: "site_demo",
              found: false,
              job: null,
            },
          }
        : undefined,
    );
    await expect(page.getByText("当前主体范围内未找到该任务")).toBeVisible();
    expect(detailReads(calls)).toEqual([`/control/v1/jobs/${OTHER_JOB}`]);
    // A malformed `?job=` is dropped by the route, so nothing is read for it.
    await page.goto("/operations/jobs?job=job_bad");
    await page
      .getByLabel("管理凭证", { exact: true })
      .fill("synthetic-observer-token-for-browser-tests-000000000000000000000000");
    await page.getByRole("button", { name: "连接", exact: true }).click();
    await expect(page.getByLabel("任务 ID", { exact: true })).toHaveValue("");
    await expect(page.getByRole("region", { name: "任务状态" })).toHaveCount(0);
    expect(detailReads(calls)).toEqual([`/control/v1/jobs/${OTHER_JOB}`]);
  });
});

test("the API key page explains why a machine credential cannot administer keys", async ({
  page,
}) => {
  const calls = await open(page, "/admin/api-keys");
  await expect(page.getByText("机器凭证测试模式不能管理 API Key")).toBeVisible();
  await page.waitForTimeout(300);
  expect(calls).toHaveLength(0);
});

test.describe("phone width", () => {
  test.use({ viewport: { width: 390, height: 844 } });

  for (const [path, ready] of [
    ["/", "Gamma 支付"],
    ["/operations/audit", "读取发布状态"],
    [`/operations/jobs?job=${JOB_ID}`, "清单分析完成"],
    ["/admin/api-keys", "机器凭证测试模式不能管理 API Key"],
    ["/access/session", "当前管理会话"],
  ] as const) {
    test(`${path} fits without scrolling the page sideways`, async ({ page }) => {
      await open(page, path);
      await expect(page.getByText(ready).first()).toBeVisible();
      if (path === "/operations/audit") {
        await page.getByRole("button", { name: "读取发布状态" }).click();
        await expect(page.getByRole("region", { name: "审计发布状态结果" })).toBeVisible();
      }
      expect(
        await page.evaluate(
          () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
        ),
      ).toBeLessThanOrEqual(0);
    });
  }
});
