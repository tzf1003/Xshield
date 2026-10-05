import AxeBuilder from "@axe-core/playwright";
import { expect, type Page, test } from "@playwright/test";
import { errorFixture } from "./fixtures";
import {
  ACTIVE,
  applyBody,
  DIGEST,
  entryRoute,
  envelope,
  mockSite,
  route,
  type SiteMock,
  type SiteState,
  sectionLink,
  siteConfig,
  signInAt,
} from "./site-fixtures";

// The release page: what the edge serves next to what is staged, why a change needs approval,
// and every release action behind a dialog that shows the change and what follows. Local
// machine-login mode offers every action, so these specs exercise the page itself; the roles
// and the MFA step-up are covered in site-roles.spec.ts and site-release-session.spec.ts.

const serving = () => siteConfig();
const staged = () =>
  siteConfig({ display_name: "Alpha 新", upstream_address: "8.8.4.4:443" }, [
    entryRoute(),
    route("docs", "/docs"),
    route("orders.list", "/api/orders", { security_entry: "authenticated_root" }),
  ]);
const older = (name: string) => siteConfig({ display_name: name });

/** r4 is staged and waits for a second person; the edge still serves r3. */
const PENDING: SiteState = {
  desired_revision: 4,
  active_revision: 3,
  apply_state: "pending",
  requires_approval: true,
  reason_code: "CONTROL_SITE_APPROVAL_REQUIRED",
};
const history = () => [
  { revision: 4, config: staged() },
  { revision: 3, config: serving() },
  { revision: 2, config: older("Alpha 旧") },
];

async function release(page: Page, init: Partial<SiteMock> = {}): Promise<SiteMock> {
  const mock = await mockSite(page, {
    config: staged(),
    state: PENDING,
    revisions: history(),
    ...init,
  });
  await signInAt(page, "/sites/site_alpha/releases");
  await expect(page.getByRole("region", { name: "发布状态" })).toBeVisible();
  return mock;
}

const region = (page: Page, name: string) => page.getByRole("region", { name });
const dialogNamed = (page: Page, name: string) => page.getByRole("dialog", { name, exact: true });

/**
 * A dialog fades in over a couple of frames: scanning mid-way blends its text with the mask
 * behind it and reports contrast that nobody sees. Let the next frames start the motion, then
 * wait until nothing finite is still moving.
 */
async function settled(page: Page) {
  await page.evaluate(
    () =>
      new Promise<void>((resolve) =>
        requestAnimationFrame(() => requestAnimationFrame(() => resolve())),
      ),
  );
  await page.waitForFunction(() =>
    document
      .getAnimations()
      .every((animation) => animation.effect?.getComputedTiming().iterations === Infinity),
  );
}
async function serious(page: Page) {
  await settled(page);
  const results = await new AxeBuilder({ page }).analyze();
  return results.violations
    .filter((violation) => violation.impact === "critical" || violation.impact === "serious")
    .map((violation) => ({
      rule: violation.id,
      nodes: violation.nodes
        .slice(0, 3)
        .map((node) => `${node.target.join(" ")} :: ${node.failureSummary ?? ""}`),
    }));
}

// ---- the state and why approval is needed ---------------------------------------------------

test("the page shows what the edge serves next to what is staged, and why approval is needed", async ({
  page,
}) => {
  const mock = await release(page);
  const state = region(page, "发布状态");
  await expect(state.getByRole("heading", { name: "edge 正在服务" })).toBeVisible();
  await expect(state.getByRole("heading", { name: "已暂存" })).toBeVisible();
  await expect(state).toContainText("r3");
  await expect(state).toContainText("r4");
  await expect(state).toContainText("待审批");
  await expect(state).toContainText("author@example.test");
  await expect(state.getByRole("button", { name: "查看待发布差异（3 项）" })).toBeVisible();

  const why = region(page, "审批说明");
  await expect(why.getByRole("heading", { name: "为什么需要审批" })).toBeVisible();
  await expect(why).toContainText("上游变更");
  await expect(why).toContainText("源站地址");
  await expect(why).toContainText("8.8.8.8:443 → 8.8.4.4:443");
  await expect(why).toContainText("路由变更");
  await expect(why).toContainText("无需审批的修改：站点名称");
  // Reading and explaining send nothing.
  expect(mock.writes).toEqual([]);
});

test("the actions say why each is or is not available", async ({ page }) => {
  await release(page);
  const actions = region(page, "发布操作");
  await expect(actions.getByRole("button", { name: "验证配置" })).toBeEnabled();
  await expect(actions.getByRole("button", { name: "批准并应用" })).toBeEnabled();
  await expect(actions.getByRole("button", { name: "回滚上一版本" })).toBeEnabled();
  const apply = actions.getByRole("button", { name: "应用期望版本" });
  await expect(apply).toBeDisabled();
  await expect(apply).toHaveAccessibleDescription(/需要先批准/);
});

test("a change that needs no approval says so and offers apply instead of approve", async ({
  page,
}) => {
  await release(page, {
    state: { ...PENDING, requires_approval: false, reason_code: "EDGE_APPLY_NOT_CONFIRMED" },
  });
  const why = region(page, "审批说明");
  await expect(why.getByRole("heading", { name: "无需审批" })).toBeVisible();
  await expect(page.getByRole("button", { name: "批准并应用" })).toBeDisabled();
  await expect(page.getByRole("button", { name: "批准并应用" })).toHaveAccessibleDescription(
    /不需要审批/,
  );
  await expect(page.getByRole("button", { name: "应用期望版本" })).toBeEnabled();
});

test("where the server and the console's reading differ, the server's verdict stands and it says so", async ({
  page,
}) => {
  // Identical content, yet the server asks for approval: the console cannot name a reason.
  await release(page, {
    config: serving(),
    revisions: [
      { revision: 4, config: serving() },
      { revision: 3, config: serving() },
    ],
  });
  const why = region(page, "审批说明");
  await expect(why.getByRole("heading", { name: "为什么需要审批" })).toBeVisible();
  await expect(why).toContainText("控制台没有在已知字段里找到具体原因");
  await expect(why).toContainText("以服务端的结论为准");
});

test("a first activation is explained without an earlier revision", async ({ page }) => {
  await release(page, {
    config: siteConfig(),
    state: {
      desired_revision: 1,
      active_revision: null,
      apply_state: "pending",
      requires_approval: true,
      reason_code: "CONTROL_SITE_APPROVAL_REQUIRED",
    },
    revisions: [{ revision: 1, config: siteConfig() }],
  });
  await expect(region(page, "发布状态")).toContainText("未上线");
  await expect(region(page, "审批说明")).toContainText("上线");
  // Nothing to roll back to: the edge never served this site.
  await expect(page.getByRole("button", { name: "回滚上一版本" })).toBeDisabled();
});

test("when the revisions cannot be read the page says so and approval rests on the status digest", async ({
  page,
}) => {
  const mock = await mockSite(page, { config: staged(), state: PENDING, revisions: history() });
  mock.intercept = async (request, url) => {
    if (request.request().method() === "GET" && url.pathname.endsWith("/revisions")) {
      await request.fulfill({ status: 403, json: errorFixture("CONTROL_SCOPE_DENIED") });
      return true;
    }
    return false;
  };
  await signInAt(page, "/sites/site_alpha/releases");
  const historyCard = region(page, "修订历史");
  await expect(historyCard).toContainText("没有读到修订历史");
  await expect(historyCard).toContainText("CONTROL_SCOPE_DENIED");
  await expect(region(page, "发布状态")).toContainText("待审批");
  await page.getByRole("button", { name: "批准并应用" }).click();
  const dialog = dialogNamed(page, "批准并应用 r4");
  await expect(dialog).toContainText("无法显示差异");
  await dialog.getByRole("button", { name: "确认批准" }).click();
  await expect.poll(() => mock.writes.length).toBe(1);
  expect(mock.writes[0]?.digest).toBe(DIGEST);
});

test("a paused site is not described as being served", async ({ page }) => {
  await release(page, {
    config: siteConfig({ status: "paused" }),
    state: {
      desired_revision: 3,
      active_revision: 3,
      apply_state: "paused",
      requires_approval: false,
      reason_code: "CONTROL_SITE_PAUSED",
    },
    revisions: [{ revision: 3, config: siteConfig({ status: "paused" }) }],
  });
  const state = region(page, "发布状态");
  await expect(state).toContainText("暂停状态，不对外服务");
  await expect(state).not.toContainText("正在使用这个修订");
});

test("a draft says it is not published, so approval is not in play yet", async ({ page }) => {
  await release(page, {
    config: siteConfig({ status: "draft" }),
    state: {
      desired_revision: 1,
      active_revision: null,
      apply_state: "pending",
      requires_approval: false,
      reason_code: "CONTROL_SITE_DRAFT_NOT_APPLICABLE",
    },
    revisions: [{ revision: 1, config: siteConfig({ status: "draft" }) }],
  });
  await expect(region(page, "发布状态")).toContainText("草稿");
  const why = region(page, "审批说明");
  await expect(why).toContainText("草稿不会发布到 edge");
  await expect(why).toContainText("上线变更");
});

test("查看待发布差异 compares the staged revision with the one the edge serves", async ({
  page,
}) => {
  await release(page);
  await page.getByRole("button", { name: "查看待发布差异（3 项）" }).click();
  const dialog = dialogNamed(page, "待发布差异");
  await expect(dialog).toContainText("对比：edge 在用的 r3 → 暂存的 r4");
  await expect(dialog.locator("tbody tr.ant-table-row")).toHaveCount(3);
  await expect(dialog.getByText("上游变更", { exact: true })).toBeVisible();
  await expect(dialog.getByText("路由变更", { exact: true })).toBeVisible();
  await expect(dialog.getByText("无需审批", { exact: true })).toBeVisible();
  // The corner icon and the footer button are both named 关闭; the footer one is last.
  await dialog.getByRole("button", { name: "关闭", exact: true }).last().click();
  await expect(dialog).toBeHidden();
});

// ---- validate -------------------------------------------------------------------------------

test("validation runs at once, changes nothing and reports the server's verdict", async ({
  page,
}) => {
  const mock = await release(page);
  await page.getByRole("button", { name: "验证配置" }).click();
  await expect(page.getByRole("status")).toContainText("配置验证通过");
  expect(mock.writes.map((write) => write.path.split("/").at(-1))).toEqual(["validate"]);
  expect(mock.writes[0]?.key).toBeTruthy();
});

test("a failed validation names the rule and what to do about it", async ({ page }) => {
  const mock = await release(page);
  mock.intercept = async (request, url) => {
    if (!url.pathname.endsWith("/validate")) return false;
    await request.fulfill({
      status: 422,
      json: {
        ...envelope("site_alpha"),
        revision: 4,
        config_digest: DIGEST,
        valid: false,
        reason_code: "CONTROL_SITE_POLICY_INVALID",
      },
    });
    return true;
  };
  await page.getByRole("button", { name: "验证配置" }).click();
  await expect(page.getByRole("status")).toContainText("配置验证未通过");
  await expect(page.getByRole("status")).toContainText("路由或策略不合法");
});

// ---- approve --------------------------------------------------------------------------------

test("approving shows the change and what follows, then pins the approval to the digest that was read", async ({
  page,
}) => {
  const mock = await release(page);
  await page.getByRole("button", { name: "批准并应用" }).click();
  const dialog = dialogNamed(page, "批准并应用 r4");
  await expect(dialog).toContainText("绑定的配置摘要");
  await expect(dialog).toContainText("author@example.test");
  await expect(dialog.locator("tbody tr.ant-table-row")).toHaveCount(3);
  await expect(dialog).toContainText("提交人不能批准自己的修订");
  // Opening the dialog sent nothing.
  expect(mock.writes).toEqual([]);

  await dialog.getByRole("button", { name: "确认批准" }).click();
  await expect.poll(() => mock.writes.length).toBe(1);
  const [write] = mock.writes;
  expect(write?.method).toBe("POST");
  expect(write?.path).toBe("/control/v1/sites/site_alpha/approve");
  expect(write?.digest).toBe(DIGEST);
  expect(write?.key).toBeTruthy();
  expect(write?.body ?? "").toBe("");
  await expect(page.getByRole("status")).toContainText("已批准");
});

test("approving with unsaved edits keeps them, and says the action does not include them", async ({
  page,
}) => {
  const mock = await release(page);
  await sectionLink(page, "网络").click();
  await page.getByLabel("站点名称", { exact: true }).fill("Alpha 草稿中");
  await sectionLink(page, "发布").click();
  await expect(region(page, "发布操作")).toContainText("1 项未保存的修改");
  await expect(region(page, "发布操作")).toContainText("针对已保存的 r4");
  await page.getByRole("button", { name: "批准并应用" }).click();
  await dialogNamed(page, "批准并应用 r4").getByRole("button", { name: "确认批准" }).click();
  await expect.poll(() => mock.writes.length).toBe(1);
  await expect(page.getByRole("status")).toContainText("已批准");
  // The approval carried nothing of the draft, and the re-read afterwards did not replace it.
  expect(mock.writes[0]?.body ?? "").toBe("");
  await expect(region(page, "未保存的修改")).toContainText("1 项未保存修改");
  await sectionLink(page, "网络").click();
  await expect(page.getByLabel("站点名称", { exact: true })).toHaveValue("Alpha 草稿中");
});

test("an unknown approval outcome locks the release actions; only the exact request can be repeated, even after moving around", async ({
  page,
}) => {
  const mock = await release(page);
  const attempts: { key: string | null; digest: string | null; body: string | null }[] = [];
  mock.intercept = async (request, url) => {
    const req = request.request();
    if (req.method() !== "POST" || !url.pathname.endsWith("/approve")) return false;
    attempts.push({
      key: await req.headerValue("idempotency-key"),
      digest: await req.headerValue("x-xshield-expected-config-digest"),
      body: req.postData(),
    });
    if (attempts.length === 1) {
      // The server may or may not have acted: this is an unknown outcome, not a refusal.
      await request.fulfill({
        status: 503,
        json: errorFixture("CONTROL_SITE_APPLY_STATE_UNAVAILABLE"),
      });
    } else {
      await request.fulfill({
        json: applyBody("site_alpha", {
          ...PENDING,
          requires_approval: false,
          reason_code: "EDGE_APPLY_NOT_CONFIRMED",
        }),
      });
    }
    return true;
  };
  await page.getByRole("button", { name: "批准并应用" }).click();
  await dialogNamed(page, "批准并应用 r4").getByRole("button", { name: "确认批准" }).click();
  await expect(page.getByText("批准并应用的结果待确认")).toBeVisible();
  // Nothing else can be released until this is settled.
  for (const name of ["验证配置", "批准并应用", "回滚上一版本"]) {
    await expect(page.getByRole("button", { name })).toBeDisabled();
  }
  // Moving to another page of the same site keeps the question open.
  await sectionLink(page, "概览").click();
  await expect(page.getByText("批准并应用的结果待确认")).toBeVisible();
  await sectionLink(page, "发布").click();
  await page.getByRole("button", { name: "确认后原样重试" }).click();
  await expect.poll(() => attempts.length).toBe(2);
  // The repeat is the same request: same key, same digest, same (empty) body.
  expect(attempts[1]).toEqual(attempts[0]);
  expect(attempts[0]?.digest).toBe(DIGEST);
  await expect(page.getByRole("status")).toContainText("已批准");
  await expect(page.getByRole("button", { name: "回滚上一版本" })).toBeEnabled();
});

test("cancelling or pressing Escape sends nothing", async ({ page }) => {
  const mock = await release(page);
  await page.getByRole("button", { name: "批准并应用" }).click();
  await dialogNamed(page, "批准并应用 r4").getByRole("button", { name: "取消" }).click();
  await expect(dialogNamed(page, "批准并应用 r4")).toBeHidden();
  await page.getByRole("button", { name: "回滚上一版本" }).click();
  await expect(dialogNamed(page, "回滚站点配置")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(dialogNamed(page, "回滚站点配置")).toBeHidden();
  expect(mock.writes).toEqual([]);
});

test("a revision that changed between two reads cannot be approved from a stale page", async ({
  page,
}) => {
  const mock = await release(page, {
    revisions: [
      { revision: 4, config: staged(), digest: "c".repeat(64) },
      { revision: 3, config: serving() },
    ],
  });
  await page.getByRole("button", { name: "批准并应用" }).click();
  const dialog = dialogNamed(page, "批准并应用 r4");
  await expect(dialog).toContainText("页面上读到的修订与服务端当前暂存的不一致");
  await expect(dialog.getByRole("button", { name: "确认批准" })).toBeDisabled();
  expect(mock.writes).toEqual([]);
});

test("the server's refusal of a changed revision is shown with its reason and unlocks the page", async ({
  page,
}) => {
  const mock = await release(page);
  mock.intercept = async (request, url) => {
    if (!url.pathname.endsWith("/approve")) return false;
    await request.fulfill({
      status: 409,
      json: errorFixture("CONTROL_SITE_APPROVAL_REVISION_MISMATCH"),
    });
    return true;
  };
  await page.getByRole("button", { name: "批准并应用" }).click();
  await dialogNamed(page, "批准并应用 r4").getByRole("button", { name: "确认批准" }).click();
  const alert = page.getByRole("alert");
  await expect(alert).toContainText("批准没有成功");
  await expect(alert).toContainText("待审批的修订在您审阅之后发生了变化");
  await expect(alert).toContainText("CONTROL_SITE_APPROVAL_REVISION_MISMATCH");
  // A definite refusal is not an unknown outcome: nothing is locked, the page can read again.
  await expect(page.getByRole("button", { name: "批准并应用" })).toBeEnabled();
});

// ---- apply ----------------------------------------------------------------------------------

test("applying shows the change and what follows, then sends one request", async ({ page }) => {
  const mock = await release(page, {
    state: { ...PENDING, requires_approval: false, reason_code: "EDGE_APPLY_NOT_CONFIRMED" },
  });
  await page.getByRole("button", { name: "应用期望版本" }).click();
  const dialog = dialogNamed(page, "应用 r4");
  await expect(dialog).toContainText("服务端判定这次变更无需审批");
  await expect(dialog).toContainText("edge 确认之前仍在服务 r3");
  await expect(dialog.locator("tbody tr.ant-table-row")).toHaveCount(3);
  expect(mock.writes).toEqual([]);
  await dialog.getByRole("button", { name: "确认应用" }).click();
  await expect.poll(() => mock.writes.length).toBe(1);
  expect(mock.writes[0]?.path).toBe("/control/v1/sites/site_alpha/apply");
  expect(mock.writes[0]?.digest).toBeNull();
  expect(mock.writes[0]?.key).toBeTruthy();
});

// ---- rollback -------------------------------------------------------------------------------

test("with a change pending, rolling back restores the revision the edge serves and creates a new one", async ({
  page,
}) => {
  const mock = await release(page);
  await page.getByRole("button", { name: "回滚上一版本" }).click();
  const dialog = dialogNamed(page, "回滚站点配置");
  await expect(dialog).toContainText("回滚会放弃它，恢复为 edge 在用的 r3");
  await expect(dialog.getByRole("heading", { name: "将被放弃的变更（r3 → r4）" })).toBeVisible();
  await expect(dialog.locator("tbody tr.ant-table-row")).toHaveCount(3);
  await expect(dialog).toContainText("创建一个新修订 r5");
  await expect(dialog).toContainText("不会删除或改写任何旧修订");
  // The target is known, so there is nothing to choose.
  await expect(dialog.getByLabel("预览较早的修订")).toHaveCount(0);

  await dialog.getByRole("button", { name: "确认回滚" }).click();
  await expect.poll(() => mock.writes.length).toBe(1);
  const [write] = mock.writes;
  expect(write?.path).toBe("/control/v1/sites/site_alpha/rollback");
  expect(write?.key).toBeTruthy();
  // The API takes no target: no body, no digest.
  expect(write?.body ?? "").toBe("");
  expect(write?.digest).toBeNull();
});

test("with nothing pending the server picks the target; the console says so and previews older revisions", async ({
  page,
}) => {
  const mock = await release(page, {
    config: serving(),
    state: ACTIVE,
    revisions: [
      { revision: 3, config: serving() },
      { revision: 2, config: older("Alpha 旧") },
      {
        revision: 1,
        config: siteConfig({ display_name: "Alpha 初版", upstream_address: "8.8.4.4:443" }),
      },
    ],
  });
  await page.getByRole("button", { name: "回滚上一版本" }).click();
  const dialog = dialogNamed(page, "回滚站点配置");
  await expect(dialog).toContainText("没有待生效的变更：回滚会恢复上一个曾在 edge 生效的修订");
  await expect(dialog).toContainText("控制台读不到这个顺序");
  await expect(dialog.getByRole("heading", { name: /只用来对比，不决定回滚目标/ })).toBeVisible();
  // Only older revisions are offered, newest first, and never the one that is serving.
  await dialog.getByLabel("预览较早的修订").click();
  const options = page.locator(".ant-select-item-option");
  await expect(options).toHaveText(["r2 · author@example.test", "r1 · author@example.test"]);
  await options.first().click();
  await expect(dialog.locator("tbody tr.ant-table-row")).toHaveCount(1);
  await expect(dialog.locator("tbody")).toContainText("Alpha 旧");
  expect(mock.writes).toEqual([]);

  // Previewing changes nothing about the request: it still names no target.
  await dialog.getByRole("button", { name: "确认回滚" }).click();
  await expect.poll(() => mock.writes.length).toBe(1);
  expect(mock.writes[0]?.path).toBe("/control/v1/sites/site_alpha/rollback");
  expect(mock.writes[0]?.body ?? "").toBe("");
});

test("a revision that repeats an older one's content is labelled, which is how a rollback shows", async ({
  page,
}) => {
  await release(page, {
    config: serving(),
    state: { ...ACTIVE, desired_revision: 5, active_revision: 5 },
    revisions: [
      { revision: 5, config: serving() },
      { revision: 4, config: staged() },
      { revision: 3, config: serving() },
      { revision: 2, config: older("Alpha 旧") },
    ],
  });
  const history = region(page, "修订历史").locator("tbody tr.ant-table-row");
  await expect(history).toHaveCount(4);
  await expect(history.nth(0)).toContainText("r5");
  await expect(history.nth(0)).toContainText("内容与 r3 相同");
  await expect(history.nth(1)).not.toContainText("内容与");
  await expect(history.nth(2)).not.toContainText("内容与");
});

// ---- health and danger ---------------------------------------------------------------------

test("health is read only when asked, from the release page too", async ({ page }) => {
  const mock = await release(page);
  const health = region(page, "站点运行健康");
  const reads = () => mock.calls.filter((call) => call.endsWith("/health")).length;
  expect(reads()).toBe(0);
  await health.getByRole("button", { name: "读取健康状态" }).click();
  await expect(health).toContainText("观察于");
  expect(reads()).toBe(1);
  // No polling: waiting does not read again.
  await page.waitForTimeout(1500);
  expect(reads()).toBe(1);
});

test("deleting a site needs its ID typed out, then sends one DELETE and says what happened on the list", async ({
  page,
}) => {
  const mock = await release(page);
  const deletes: { key: string | null }[] = [];
  const inner = mock.intercept;
  mock.intercept = async (request, url) => {
    if (request.request().method() === "DELETE") {
      deletes.push({ key: await request.request().headerValue("idempotency-key") });
      await request.fulfill({
        json: { ...envelope("site_alpha"), reason_code: "CONTROL_SITE_DELETED" },
      });
      return true;
    }
    return (await inner?.(request, url)) ?? false;
  };
  const danger = region(page, "危险操作");
  await danger.getByRole("button", { name: "删除站点" }).click();
  const dialog = dialogNamed(page, "删除站点 site_alpha");
  const confirm = dialog.getByRole("button", { name: "确认删除" });
  const typed = dialog.getByLabel(/输入站点 ID/);
  await expect(confirm).toBeDisabled();
  // A correct start is not yet an error; a wrong one is.
  await typed.fill("site_alp");
  await expect(confirm).toBeDisabled();
  await expect(dialog.getByText("与站点 ID 不一致。")).toHaveCount(0);
  await typed.fill("other");
  await expect(dialog.getByText("与站点 ID 不一致。")).toBeVisible();
  await expect(confirm).toBeDisabled();
  await typed.fill("site_alpha ");
  await expect(confirm).toBeDisabled();
  await typed.fill("site_alpha");
  await expect(confirm).toBeEnabled();
  expect(deletes).toEqual([]);

  await confirm.click();
  await expect.poll(() => deletes.length).toBe(1);
  expect(deletes[0]?.key).toBeTruthy();
  await expect(page).toHaveURL(/\/sites$/);
  await expect(page.getByRole("status")).toContainText("站点已删除，监听端口已释放");
});

test("closing the delete dialog forgets what was typed", async ({ page }) => {
  await release(page);
  await region(page, "危险操作").getByRole("button", { name: "删除站点" }).click();
  await dialogNamed(page, "删除站点 site_alpha")
    .getByLabel(/输入站点 ID/)
    .fill("site_alpha");
  await dialogNamed(page, "删除站点 site_alpha").getByRole("button", { name: "取消" }).click();
  await expect(dialogNamed(page, "删除站点 site_alpha")).toBeHidden();
  await region(page, "危险操作").getByRole("button", { name: "删除站点" }).click();
  await expect(dialogNamed(page, "删除站点 site_alpha").getByLabel(/输入站点 ID/)).toHaveValue("");
  await expect(
    dialogNamed(page, "删除站点 site_alpha").getByRole("button", { name: "确认删除" }),
  ).toBeDisabled();
});

// ---- small screens and accessibility --------------------------------------------------------

test("the release page and its dialogs fit a 390 px screen without scrolling the page sideways", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await release(page);
  const overflow = () =>
    page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(await overflow()).toBeLessThanOrEqual(0);

  for (const [button, title] of [
    ["批准并应用", "批准并应用 r4"],
    ["回滚上一版本", "回滚站点配置"],
  ] as const) {
    await page.getByRole("button", { name: button }).click();
    const dialog = dialogNamed(page, title);
    await expect(dialog).toBeVisible();
    await settled(page);
    const box = await dialog.boundingBox();
    expect(box?.x ?? -1).toBeGreaterThanOrEqual(0);
    expect((box?.x ?? 0) + (box?.width ?? 999)).toBeLessThanOrEqual(390);
    expect(await overflow()).toBeLessThanOrEqual(0);
    await dialog.getByRole("button", { name: "取消" }).click();
    await expect(dialog).toBeHidden();
  }
  await region(page, "危险操作").getByRole("button", { name: "删除站点" }).click();
  await expect(dialogNamed(page, "删除站点 site_alpha")).toBeVisible();
  expect(await overflow()).toBeLessThanOrEqual(0);
});

for (const scheme of ["light", "dark"] as const) {
  test.describe(`release page accessibility (${scheme})`, () => {
    test.use({ colorScheme: scheme });

    test("the page and every dialog have no serious violations", async ({ page }) => {
      await release(page);
      expect(await serious(page)).toEqual([]);

      await page.getByRole("button", { name: "批准并应用" }).click();
      await expect(dialogNamed(page, "批准并应用 r4")).toBeVisible();
      expect(await serious(page)).toEqual([]);
      await dialogNamed(page, "批准并应用 r4").getByRole("button", { name: "取消" }).click();
      await expect(dialogNamed(page, "批准并应用 r4")).toBeHidden();

      await page.getByRole("button", { name: "回滚上一版本" }).click();
      await expect(dialogNamed(page, "回滚站点配置")).toBeVisible();
      expect(await serious(page)).toEqual([]);
      await dialogNamed(page, "回滚站点配置").getByRole("button", { name: "取消" }).click();
      await expect(dialogNamed(page, "回滚站点配置")).toBeHidden();

      await region(page, "危险操作").getByRole("button", { name: "删除站点" }).click();
      await expect(dialogNamed(page, "删除站点 site_alpha")).toBeVisible();
      await dialogNamed(page, "删除站点 site_alpha")
        .getByLabel(/输入站点 ID/)
        .fill("nope");
      expect(await serious(page)).toEqual([]);
    });
  });
}
