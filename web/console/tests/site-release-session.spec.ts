import { expect, type Page, test } from "@playwright/test";
import { errorFixture } from "./fixtures";
import { sessionBody } from "./shell-helpers";
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
  siteConfig,
} from "./site-fixtures";

// Cookie-session mode: approving a change that needs approval and deleting a site both need a
// fresh MFA step-up. The console warns, the server decides; a refusal executed nothing, keeps the
// frozen request, and the same request (same key, same body) is repeated after re-verifying.

const serving = () => siteConfig();
const staged = () =>
  siteConfig({ display_name: "Alpha 新", upstream_address: "8.8.4.4:443" }, [
    entryRoute(),
    route("docs", "/docs"),
    route("orders.list", "/api/orders", { security_entry: "authenticated_root" }),
  ]);
const PENDING: SiteState = {
  desired_revision: 4,
  active_revision: 3,
  apply_state: "pending",
  requires_approval: true,
  reason_code: "CONTROL_SITE_APPROVAL_REQUIRED",
};

type Attempt = { path: string; key: string | null; digest: string | null; body: string | null };

/** A session whose MFA step-up the test flips, and every attempt at one write recorded. */
async function asSession(
  page: Page,
  roles: string[],
  init: Partial<SiteMock>,
  write: { method: string; tail: string; refusal: { status: number; code: string }; ok: object },
) {
  const step = { fresh: false };
  const attempts: Attempt[] = [];
  const mock = await mockSite(page, init);
  mock.intercept = async (request, url) => {
    const req = request.request();
    if (url.pathname === "/control/v1/session" && req.method() === "GET") {
      await request.fulfill({
        json: sessionBody(roles, {
          step_up_valid: step.fresh,
          last_reauthenticated_at: step.fresh ? new Date().toISOString() : null,
        }),
      });
      return true;
    }
    if (req.method() === write.method && url.pathname.endsWith(write.tail)) {
      attempts.push({
        path: url.pathname,
        key: await req.headerValue("idempotency-key"),
        digest: await req.headerValue("x-xshield-expected-config-digest"),
        body: req.postData(),
      });
      if (step.fresh) await request.fulfill({ json: write.ok });
      else {
        await request.fulfill({
          status: write.refusal.status,
          json: errorFixture(write.refusal.code),
        });
      }
      return true;
    }
    return false;
  };
  return { step, attempts, mock };
}

const approving = (page: Page) =>
  asSession(
    page,
    ["observer", "policy_approver"],
    {
      config: staged(),
      state: PENDING,
      revisions: [
        { revision: 4, config: staged() },
        { revision: 3, config: serving() },
      ],
    },
    {
      method: "POST",
      tail: "/approve",
      refusal: { status: 401, code: "CONTROL_STEP_UP_REQUIRED" },
      ok: applyBody("site_alpha", {
        ...PENDING,
        requires_approval: false,
        reason_code: "EDGE_APPLY_NOT_CONFIRMED",
      }),
    },
  );

const approveDialog = (page: Page) =>
  page.getByRole("dialog", { name: "批准并应用 r4", exact: true });

test("approving without a fresh step-up is warned about first, refused without executing, then repeated unchanged", async ({
  page,
}) => {
  const { step, attempts } = await approving(page);
  await page.goto("/sites/site_alpha/releases");
  await page.getByRole("button", { name: "批准并应用" }).click();
  const dialog = approveDialog(page);
  await expect(dialog).toContainText("批准需要 2 分钟内完成的 MFA 再认证，当前未检测到");
  await expect(dialog.getByRole("button", { name: "重新验证高危操作" })).toBeVisible();
  await expect(dialog.getByRole("button", { name: "已完成再认证，重新读取会话" })).toBeVisible();
  // Advisory only: the server decides, so the confirmation stays available.
  await dialog.getByRole("button", { name: "确认批准" }).click();

  // A refusal for MFA is neither a sign-out nor an unknown outcome: nothing was executed.
  await expect(page.getByText("批准并应用需要先完成 MFA 再认证（请求没有执行）。")).toBeVisible();
  await expect(page.getByRole("region", { name: "站点运行与发布" })).toBeVisible();
  await expect(page.getByLabel("管理凭证", { exact: true })).toHaveCount(0);
  expect(attempts).toHaveLength(1);
  expect(attempts[0]?.digest).toBe(DIGEST);
  expect(attempts[0]?.key).toBeTruthy();

  step.fresh = true;
  await page.getByRole("button", { name: "已完成再认证，检查并重试" }).click();
  await expect.poll(() => attempts.length).toBe(2);
  // Exactly the same request: same path, same idempotency key, same digest, same (empty) body.
  expect(attempts[1]).toEqual(attempts[0]);
  await expect(
    page.getByRole("region", { name: "站点运行与发布" }).getByRole("status"),
  ).toContainText("已批准");
  await expect(page.getByText("批准并应用需要先完成 MFA 再认证（请求没有执行）。")).toBeHidden();
});

test("with a fresh step-up the dialog says how long it lasts and shows no warning", async ({
  page,
}) => {
  const { step } = await approving(page);
  step.fresh = true;
  await page.goto("/sites/site_alpha/releases");
  await page.getByRole("button", { name: "批准并应用" }).click();
  const dialog = approveDialog(page);
  await expect(dialog).toContainText("MFA 再认证有效");
  await expect(dialog).not.toContainText("当前未检测到");
  await expect(dialog.getByRole("button", { name: "重新验证高危操作" })).toHaveCount(0);
});

test("re-reading the session after re-verifying elsewhere clears the warning", async ({ page }) => {
  const { step } = await approving(page);
  await page.goto("/sites/site_alpha/releases");
  await page.getByRole("button", { name: "批准并应用" }).click();
  const dialog = approveDialog(page);
  await expect(dialog).toContainText("当前未检测到");
  // Re-verified in another window; nothing here knows yet. The re-read is explicit.
  step.fresh = true;
  await dialog.getByRole("button", { name: "已完成再认证，重新读取会话" }).click();
  await expect(dialog).toContainText("MFA 再认证有效");
  await expect(dialog).not.toContainText("当前未检测到");
});

const deleting = (page: Page) =>
  asSession(
    page,
    ["system_admin"],
    { config: serving(), state: ACTIVE, revisions: [] },
    {
      method: "DELETE",
      tail: "/site_alpha",
      refusal: { status: 403, code: "CONTROL_SITE_DELETE_STEP_UP_REQUIRED" },
      ok: { ...envelope("site_alpha"), reason_code: "CONTROL_SITE_DELETED" },
    },
  );

test("deleting needs MFA: the refused request is kept and repeated unchanged, then the list says what happened", async ({
  page,
}) => {
  const { step, attempts } = await deleting(page);
  await page.goto("/sites/site_alpha/releases");
  await page
    .getByRole("region", { name: "危险操作" })
    .getByRole("button", { name: "删除站点" })
    .click();
  const dialog = page.getByRole("dialog", { name: "删除站点 site_alpha", exact: true });
  await expect(dialog).toContainText("删除站点需要 2 分钟内完成的 MFA 再认证，当前未检测到");
  await dialog.getByLabel(/输入站点 ID/).fill("site_alpha");
  await dialog.getByRole("button", { name: "确认删除" }).click();

  await expect(page.getByText("删除站点需要先完成 MFA 再认证（请求没有执行）。")).toBeVisible();
  expect(attempts).toHaveLength(1);
  expect(attempts[0]?.key).toBeTruthy();
  // Nothing was deleted, so the operator is still on the site.
  await expect(page).toHaveURL(/\/sites\/site_alpha\/releases$/);

  step.fresh = true;
  await page.getByRole("button", { name: "已完成再认证，检查并重试" }).click();
  await expect.poll(() => attempts.length).toBe(2);
  expect(attempts[1]).toEqual(attempts[0]);
  await expect(page).toHaveURL(/\/sites$/);
  await expect(
    page.getByRole("region", { name: "受保护站点列表" }).getByRole("status"),
  ).toContainText("站点已删除，监听端口已释放");
});

// What each role is offered on the release page. Hiding is only a convenience (the server
// authorizes each call), but it must follow the roles exactly as the previous page did.
const offered: [string[], string[]][] = [
  [["observer"], []],
  [["observer", "policy_author"], ["验证配置"]],
  [["observer", "policy_approver"], ["批准并应用"]],
  [
    ["observer", "release_operator"],
    ["应用期望版本", "回滚上一版本"],
  ],
  [
    ["observer", "policy_author", "policy_approver", "release_operator"],
    ["验证配置", "批准并应用", "应用期望版本", "回滚上一版本"],
  ],
];
for (const [roles, names] of offered) {
  test(`the release actions offered to ${roles.join(" + ")}`, async ({ page }) => {
    await asSession(
      page,
      roles,
      { config: staged(), state: PENDING, revisions: [{ revision: 4, config: staged() }] },
      {
        method: "DELETE",
        tail: "/site_alpha",
        refusal: { status: 403, code: "CONTROL_SCOPE_DENIED" },
        ok: {},
      },
    );
    await page.goto("/sites/site_alpha/releases");
    await expect(page.getByRole("region", { name: "发布状态" })).toContainText("r4");
    const actions = page.getByRole("region", { name: "发布操作" });
    const all = ["验证配置", "批准并应用", "应用期望版本", "回滚上一版本"];
    for (const name of all) {
      await expect(actions.getByRole("button", { name })).toHaveCount(names.includes(name) ? 1 : 0);
    }
    // Nothing here is a write path for an observer, and nobody but an administrator can delete.
    await expect(page.getByRole("button", { name: "删除站点" })).toHaveCount(0);
  });
}

test("only a system administrator is offered deletion", async ({ page }) => {
  await asSession(
    page,
    ["observer", "policy_author", "policy_approver", "release_operator"],
    { config: staged(), state: PENDING, revisions: [{ revision: 4, config: staged() }] },
    {
      method: "DELETE",
      tail: "/site_alpha",
      refusal: { status: 403, code: "CONTROL_SCOPE_DENIED" },
      ok: {},
    },
  );
  await page.goto("/sites/site_alpha/releases");
  await expect(page.getByRole("region", { name: "发布操作" })).toBeVisible();
  await expect(page.getByRole("region", { name: "危险操作" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "删除站点" })).toHaveCount(0);
});
