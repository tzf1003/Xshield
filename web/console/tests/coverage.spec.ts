import { expect, test } from "@playwright/test";
import { errorFixture, REQUEST_ID } from "./fixtures";
import { SCOPE, signIn } from "./shell-helpers";
import { mockWorkbench, type Override } from "./workbench-helpers";

// The refusal and coverage page in the machine-login build: it reads only when asked, renders
// the three lists, and shows a failed read as an error without keeping an older result.

const PATH = "/control/v1/coverage-report";

/** A report for exactly the window the console asked, as the control plane would answer it. */
function report(url: URL, changes: Record<string, unknown> = {}) {
  const start = url.searchParams.get("start") ?? "";
  const end = url.searchParams.get("end") ?? "";
  const seen = new Date(Date.parse(start) + 1000).toISOString().replace("Z", "000Z");
  return {
    schema_version: 1,
    request_id: REQUEST_ID,
    ...SCOPE,
    watermark_scope: "configured_journal",
    as_of: end.replace("Z", ".000000Z"),
    index_watermark: null,
    has_gaps: false,
    pending_segments: 0,
    index_complete: true,
    report_digest: "c".repeat(64),
    start,
    end,
    completed_requests: 40,
    refused_requests: 5,
    observed_requests: 0,
    unrouted_refusals: 3,
    unshaped_unrouted_refusals: 1,
    routes: [{ operation_id: "orders.list", completed: 37, refused: 2, observed: 0 }],
    routes_truncated: false,
    refusals: [
      { operation_id: "", reason_code: "OPERATION_NOT_MATCHED", count: 3, last_seen: seen },
      { operation_id: "orders.list", reason_code: "AUTH_REQUIRED", count: 2, last_seen: seen },
    ],
    refusals_truncated: false,
    uncovered: [{ method: "GET", path_shape: "/api/users/{}", count: 2, last_seen: seen }],
    uncovered_truncated: false,
    ...changes,
  };
}

async function open(page: Parameters<typeof signIn>[0], override: Override) {
  const calls = await mockWorkbench(page, { override });
  await signIn(page, "/investigation/coverage");
  await expect(page.getByRole("heading", { name: "拒绝与覆盖统计", level: 1 })).toBeVisible();
  return calls;
}

const coverageReads = (calls: readonly { path: string }[]) =>
  calls.filter((call) => call.path.startsWith(PATH));

test("reads only when asked, then shows routes, refusals and uncovered shapes", async ({
  page,
}) => {
  const calls = await open(page, (url) =>
    url.pathname === PATH ? { body: report(url) } : undefined,
  );
  await page.waitForTimeout(300);
  expect(coverageReads(calls)).toHaveLength(0);

  await page.getByRole("button", { name: "生成统计" }).click();
  const result = page.getByRole("region", { name: "拒绝与覆盖统计结果" });
  await expect(result).toContainText("窗口内有请求因为没有匹配任何路由而被拒绝");
  await expect(result.getByRole("list", { name: "窗口内计数" })).toContainText("被拒绝5占 13%");
  await expect(result).toContainText("其中无路径形状 1");

  // One read; the development build's StrictMode remount may repeat the same request.
  const reads = [...new Set(coverageReads(calls).map((call) => call.path))];
  expect(reads).toHaveLength(1);
  const read = coverageReads(calls).length;
  const sent = new URL(reads[0] ?? "", "http://x").searchParams;
  // The default preset is 24 hours, in whole UTC seconds.
  expect(Date.parse(sent.get("end") ?? "") - Date.parse(sent.get("start") ?? "")).toBe(86_400_000);
  expect(sent.get("start")).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);

  const routes = page.getByRole("region", { name: "按路由的流量" });
  await expect(routes.getByRole("row", { name: /orders\.list/ })).toContainText("5.4%");
  const refusals = page.getByRole("region", { name: "按路由与原因的拒绝" });
  await expect(refusals).toContainText("（未匹配任何路由）");
  await expect(refusals).toContainText("AUTH_REQUIRED");
  const uncovered = page.getByRole("region", { name: "未覆盖端点" });
  await expect(uncovered.getByRole("row", { name: /GET/ })).toContainText("/api/users/{}");

  // Nothing reads again by itself.
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await page.waitForTimeout(300);
  expect(coverageReads(calls)).toHaveLength(read);
});

test("an index that is behind cannot judge; a failed read leaves no stale result", async ({
  page,
}) => {
  let failing = false;
  await open(page, (url) => {
    if (url.pathname !== PATH) return undefined;
    if (failing) {
      return { status: 503, body: errorFixture("CONTROL_COVERAGE_REPORT_INDEX_UNAVAILABLE") };
    }
    return { body: report(url, { pending_segments: 2, index_complete: false }) };
  });
  await page.getByRole("button", { name: "生成统计" }).click();
  await expect(page.getByRole("region", { name: "拒绝与覆盖统计结果" })).toContainText(
    "不足以判断",
  );
  failing = true;
  await page.getByRole("button", { name: "生成统计" }).click();
  await expect(page.getByRole("alert").filter({ hasText: "拒绝与覆盖统计读取失败" })).toContainText(
    "CONTROL_COVERAGE_REPORT_INDEX_UNAVAILABLE",
  );
  await expect(page.getByRole("region", { name: "拒绝与覆盖统计结果" })).toHaveCount(0);
});

test("a reply that does not add up is refused instead of rendered", async ({ page }) => {
  await open(page, (url) =>
    url.pathname === PATH ? { body: report(url, { refused_requests: 6 }) } : undefined,
  );
  await page.getByRole("button", { name: "生成统计" }).click();
  await expect(page.getByRole("alert").filter({ hasText: "拒绝与覆盖统计读取失败" })).toBeVisible();
  await expect(page.getByRole("region", { name: "拒绝与覆盖统计结果" })).toHaveCount(0);
});
