import AxeBuilder from "@axe-core/playwright";
import { expect, type Page, test } from "@playwright/test";
import {
  ACTIVE,
  entryRoute,
  mockSite,
  route,
  type SiteState,
  siteConfig,
  signInAt,
  sectionLink,
} from "./site-fixtures";

const bar = (page: Page) => page.getByRole("region", { name: "未保存的修改" });
const header = (page: Page) => page.getByRole("region", { name: "站点概况" });

async function settled(page: Page) {
  await page.evaluate(() =>
    Promise.all(
      document.getAnimations().map((animation) => animation.finished.catch(() => undefined)),
    ),
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

// ---- lifecycle ----------------------------------------------------------------------------

const lifecycleCases: {
  name: string;
  state: SiteState;
  status?: string;
  pill: string;
  step: { process?: string; error?: string; finish: number };
  note?: RegExp;
}[] = [
  {
    name: "a draft is not published",
    state: {
      desired_revision: 1,
      active_revision: null,
      apply_state: "pending",
      requires_approval: false,
      reason_code: "CONTROL_SITE_DRAFT_NOT_APPLICABLE",
    },
    status: "draft",
    pill: "草稿",
    step: { process: "草稿", finish: 0 },
  },
  {
    name: "a change that needs approval waits for a second person",
    state: {
      desired_revision: 5,
      active_revision: 4,
      apply_state: "pending",
      requires_approval: true,
      reason_code: "CONTROL_SITE_APPROVAL_REQUIRED",
    },
    pill: "待审批",
    step: { process: "待审批", finish: 2 },
  },
  {
    name: "an approved change waits for the edge",
    state: {
      desired_revision: 4,
      active_revision: 3,
      apply_state: "pending",
      requires_approval: false,
      reason_code: "EDGE_APPLY_NOT_CONFIRMED",
    },
    pill: "待应用",
    step: { process: "应用中", finish: 3 },
  },
  { name: "a live site has every step done", state: ACTIVE, pill: "已生效", step: { finish: 5 } },
  {
    name: "a paused site ends at 已暂停",
    state: {
      desired_revision: 3,
      active_revision: 3,
      apply_state: "paused",
      requires_approval: false,
      reason_code: "CONTROL_SITE_PAUSED",
    },
    status: "paused",
    pill: "已暂停",
    step: { finish: 5 },
  },
  {
    name: "an edge failure stops at 应用中 and says why",
    state: {
      desired_revision: 4,
      active_revision: 3,
      apply_state: "failed",
      requires_approval: false,
      reason_code: "EDGE_UNAVAILABLE",
    },
    pill: "应用失败",
    step: { error: "应用中", finish: 3 },
    note: /控制面连不上 edge 的应用通道/,
  },
  {
    name: "a rejected configuration stops at 已校验",
    state: {
      desired_revision: 4,
      active_revision: 3,
      apply_state: "failed",
      requires_approval: false,
      reason_code: "CONTROL_SITE_POLICY_INVALID",
    },
    pill: "应用失败",
    step: { error: "已校验", finish: 1 },
    note: /路由或策略不合法/,
  },
];

for (const item of lifecycleCases) {
  test(`lifecycle: ${item.name}`, async ({ page }) => {
    await mockSite(page, {
      config: siteConfig(item.status ? { status: item.status } : {}),
      state: item.state,
    });
    await signInAt(page, "/sites/site_alpha/overview");
    await expect(header(page)).toContainText(item.pill);
    await expect(header(page).locator(".ant-steps-item-finish")).toHaveCount(item.step.finish);
    if (item.step.process) {
      await expect(header(page).locator(".ant-steps-item-process")).toContainText(
        item.step.process,
      );
    }
    if (item.step.error) {
      await expect(header(page).locator(".ant-steps-item-error")).toContainText(item.step.error);
    }
    if (item.note) await expect(header(page)).toContainText(item.note);
    await expect(header(page)).toContainText(`desired r${item.state.desired_revision}`);
  });
}

// ---- the change bar and the diff ------------------------------------------------------------

test("the change bar follows the operator across tabs and counts edits per tab", async ({
  page,
}) => {
  await mockSite(page);
  await signInAt(page, "/sites/site_alpha/network");
  await expect(bar(page)).toHaveCount(0);
  await page.getByLabel("站点名称", { exact: true }).fill("Alpha 新名");
  await expect(bar(page)).toContainText("1 项未保存修改");
  await expect(bar(page).getByRole("button", { name: "网络 1" })).toBeVisible();

  await sectionLink(page, "安全入口").click();
  await page.getByRole("radio", { name: /^公开/ }).check();
  await sectionLink(page, "WAF 与限流").click();
  await page.getByLabel("突发容量", { exact: true }).fill("3000");

  // The bar is still there, in another tab, with every tab's share of the edits.
  await expect(bar(page)).toBeVisible();
  await expect(bar(page).getByRole("button", { name: "网络 1" })).toBeVisible();
  await expect(bar(page).getByRole("button", { name: "安全入口 1" })).toBeVisible();
  await expect(bar(page).getByRole("button", { name: "WAF 与限流 1" })).toBeVisible();
  // Opening the public door also moves the protected.entry route (two fields of it).
  await expect(bar(page).getByRole("button", { name: "路由与操作 2" })).toBeVisible();
  await expect(bar(page)).toContainText("5 项未保存修改");
  // The tabs carry the counts too, without changing their accessible names.
  await expect(sectionLink(page, "WAF 与限流")).toBeVisible();
  await expect(sectionLink(page, "网络")).toHaveAccessibleDescription("1 项未保存修改");

  await bar(page).getByRole("button", { name: "网络 1" }).click();
  await expect(page).toHaveURL(/sites\/site_alpha\/network$/);
  await expect(page.getByLabel("站点名称", { exact: true })).toHaveValue("Alpha 新名");
});

test("the diff shows human field names with before and after, and 放弃 restores everything", async ({
  page,
}) => {
  await mockSite(page);
  await signInAt(page, "/sites/site_alpha/network");
  await page.getByLabel("站点名称", { exact: true }).fill("Alpha 新名");
  await page.getByLabel("监听端口", { exact: true }).fill("6200");
  await bar(page).getByRole("button", { name: "查看差异" }).click();
  const dialog = page.getByRole("dialog", { name: "未保存修改的差异" });
  await expect(dialog).toBeVisible();
  const row = (name: string) => dialog.getByRole("row", { name: new RegExp(name) });
  await expect(row("站点名称")).toContainText("Alpha 官网");
  await expect(row("站点名称")).toContainText("Alpha 新名");
  await expect(row("监听端口")).toContainText("6101");
  await expect(row("监听端口")).toContainText("6200");
  await expect(dialog).toContainText("对比：已保存的 r3 → 当前草稿");
  await dialog.getByRole("button", { name: "关闭" }).last().click();
  await expect(dialog).toHaveCount(0);

  await bar(page).getByRole("button", { name: "放弃" }).click();
  await page.getByRole("button", { name: "放弃", exact: true }).last().click();
  await expect(bar(page)).toHaveCount(0);
  await expect(page.getByLabel("站点名称", { exact: true })).toHaveValue("Alpha 官网");
  await expect(page.getByLabel("监听端口", { exact: true })).toHaveValue("6101");
});

test("a value put back by hand is no longer a change", async ({ page }) => {
  await mockSite(page);
  await signInAt(page, "/sites/site_alpha/network");
  const name = page.getByLabel("站点名称", { exact: true });
  await name.fill("Alpha 官网 2");
  await expect(bar(page)).toBeVisible();
  await name.fill("Alpha 官网");
  await expect(bar(page)).toHaveCount(0);
});

test("saving sends the draft once and the page shows where the new revision stands", async ({
  page,
}) => {
  const mock = await mockSite(page, {
    state: {
      desired_revision: 3,
      active_revision: 3,
      apply_state: "pending",
      requires_approval: true,
      reason_code: "CONTROL_SITE_APPROVAL_REQUIRED",
    },
  });
  await signInAt(page, "/sites/site_alpha/security-entry");
  await page.getByLabel("策略版本", { exact: true }).fill("policy-v4");
  await bar(page).getByRole("button", { name: "保存草稿", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("已保存为 r4");
  await expect(page.getByRole("status")).toContainText("需要独立审批");
  await expect(bar(page)).toHaveCount(0);
  const saves = mock.writes.filter((write) => write.method === "PUT");
  expect(saves).toHaveLength(1);
  expect(saves[0]?.key).toBeTruthy();
  const body = JSON.parse(saves[0]?.body ?? "{}") as {
    policy_revision: string;
    policy: { static_asset_max_path_depth: number; origin_object_access_enforced: boolean };
  };
  expect(body.policy_revision).toBe("policy-v4");
  // The two policy fields the server owns are sent back as read, never reset (the fixture
  // stores a depth of 5).
  expect(body.policy.static_asset_max_path_depth).toBe(5);
  expect(body.policy.origin_object_access_enforced).toBe(false);
});

test("a field the console used to drop is kept: object-access enforcement survives a save", async ({
  page,
}) => {
  const config = siteConfig();
  (
    config.policy as { origin_object_access_enforced: boolean; static_asset_max_path_depth: number }
  ).origin_object_access_enforced = true;
  (config.policy as { static_asset_max_path_depth: number }).static_asset_max_path_depth = 3;
  const mock = await mockSite(page, { config });
  await signInAt(page, "/sites/site_alpha/policies");
  await expect(page.getByLabel("源站对象级校验标记", { exact: true })).toBeChecked();
  await expect(page.getByLabel("静态资源兜底深度", { exact: true })).toHaveValue("3");
  await page.getByLabel("检查间隔", { exact: true }).fill("30");
  await bar(page).getByRole("button", { name: "保存草稿", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("已保存为");
  const body = JSON.parse(mock.writes.find((write) => write.method === "PUT")?.body ?? "{}") as {
    policy: Record<string, unknown>;
  };
  expect(body.policy.origin_object_access_enforced).toBe(true);
  expect(body.policy.static_asset_max_path_depth).toBe(3);
});

// ---- validation while typing ----------------------------------------------------------------

test("origin, upstream and server name are checked inline with the server's rules", async ({
  page,
}) => {
  await mockSite(page);
  await signInAt(page, "/sites/site_alpha/network");
  const save = bar(page).getByRole("button", { name: "保存草稿", exact: true });

  await page.getByLabel("公网入口", { exact: true }).fill("http://www.example.com");
  await expect(page.getByText("明文 http 只允许 localhost 或 127.x 本地靶场")).toBeVisible();
  await expect(save).toBeDisabled();
  await page.getByLabel("公网入口", { exact: true }).fill("https://www.example.com");

  await page.getByLabel("源站地址", { exact: true }).fill("10.0.0.5:443");
  await expect(page.getByText("内网地址（RFC 1918）不能作为上游")).toBeVisible();
  await page.getByLabel("源站地址", { exact: true }).fill("169.254.169.254:80");
  await expect(page.getByText("云平台元数据地址不能作为上游")).toBeVisible();
  await page.getByLabel("源站地址", { exact: true }).fill("origin.example.com:443");
  await expect(page.getByText("不能填域名")).toBeVisible();
  await page.getByLabel("源站地址", { exact: true }).fill("203.0.113.9:443");
  await expect(page.getByText("文档示例网段")).toBeVisible();
  await expect(save).toBeDisabled();
  await bar(page)
    .getByRole("button", { name: /项需要修正/ })
    .click();
  await expect(page.locator(".ant-popover").last()).toContainText("文档示例网段");

  // A loopback upstream is a warning: a lab deployment can opt in, so it never blocks.
  await page.getByLabel("源站地址", { exact: true }).fill("127.0.0.1:8080");
  await expect(page.getByText("回环地址只在部署方显式开启本地靶场放行时才被接受")).toBeVisible();
  await expect(save).toBeEnabled();

  await page.getByLabel("源站 Server Name", { exact: true }).fill("127.0.0.1");
  await expect(page.getByText("服务名不能是 IP 地址")).toBeVisible();
  await expect(save).toBeDisabled();
  await page.getByLabel("源站 Server Name", { exact: true }).fill("2130706433");
  await expect(page.getByText("服务名不能是 IP 地址")).toBeVisible();
  await page.getByLabel("源站 Server Name", { exact: true }).fill("origin.example.com");
  await expect(save).toBeEnabled();
});

// ---- routes: up to 256, in a table with a drawer --------------------------------------------

function manyRoutes(total: number) {
  return [
    entryRoute(),
    ...Array.from({ length: total - 1 }, (_, index) =>
      route(`api.r${index + 1}`, `/api/r${index + 1}`),
    ),
  ];
}

test("200 routes stay usable: search, paging, edit, duplicate, add, remove and one save", async ({
  page,
}) => {
  const mock = await mockSite(page, { config: siteConfig({}, manyRoutes(200)) });
  await signInAt(page, "/sites/site_alpha/routes");
  const rows = page.locator("tbody tr.ant-table-row");
  await expect(page.getByText("共 200 条路由（最多 256）")).toBeVisible();
  await expect(rows).toHaveCount(20);
  await expect(page.getByText("共 200 条", { exact: true })).toBeVisible();
  await page.getByRole("listitem", { name: "2", exact: true }).click();
  await expect(rows.first()).toContainText("/api/r20");

  const search = page.getByRole("textbox", { name: "搜索路由" });
  await search.fill("api.r150");
  await expect(rows).toHaveCount(1);

  // edit
  await page.getByRole("button", { name: "编辑路由 api.r150" }).click();
  const drawer = page.getByRole("dialog", { name: "编辑路由" });
  await expect(drawer).toBeVisible();
  await expect(drawer.getByLabel("路径", { exact: true })).toHaveValue("/api/r150");
  await drawer.getByLabel("路径", { exact: true }).fill("/api/changed");
  await drawer.getByRole("button", { name: "应用到草稿" }).click();
  await expect(drawer).toHaveCount(0);
  await search.fill("changed");
  await expect(rows).toHaveCount(1);
  await expect(bar(page).getByRole("button", { name: "路由与操作 1" })).toBeVisible();

  // duplicate: the copy collides until its path is changed
  await search.fill("api.r7");
  await page.getByRole("button", { name: "复制路由 api.r7" }).first().click();
  const copy = page.getByRole("dialog", { name: "复制路由" });
  await expect(copy.getByLabel("操作 ID", { exact: true })).toHaveValue("api.r7.copy");
  await expect(copy.getByText("已被另一条路由占用")).toBeVisible();
  await expect(copy.getByRole("button", { name: "应用到草稿" })).toBeDisabled();
  await copy.getByLabel("路径", { exact: true }).fill("/api/r7-copy");
  await expect(copy.getByRole("button", { name: "应用到草稿" })).toBeEnabled();
  await copy.getByRole("button", { name: "应用到草稿" }).click();

  // add
  await search.fill("");
  await page.getByRole("button", { name: "新增路由" }).click();
  const add = page.getByRole("dialog", { name: "新增路由" });
  await expect(add.getByLabel("操作 ID", { exact: true })).toHaveValue("route");
  await add.getByLabel("操作 ID", { exact: true }).fill("orders.new");
  await add.getByLabel("路径", { exact: true }).fill("/api/orders-new");
  await add.getByRole("button", { name: "应用到草稿" }).click();
  await expect(page.getByText("共 202 条路由（最多 256）")).toBeVisible();

  // remove (after confirming)
  await search.fill("api.r2");
  await page.getByRole("button", { name: "移除路由 api.r2", exact: true }).click();
  await page.getByRole("button", { name: "移除", exact: true }).click();
  await search.fill("");
  await expect(page.getByText("共 201 条路由（最多 256）")).toBeVisible();

  await bar(page).getByRole("button", { name: "保存草稿", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("已保存为");
  const body = JSON.parse(mock.writes.find((write) => write.method === "PUT")?.body ?? "{}") as {
    policy: { routes: { operation_id: string; path: string }[] };
  };
  const ids = body.policy.routes.map((item) => item.operation_id);
  expect(body.policy.routes).toHaveLength(201);
  expect(ids).toContain("orders.new");
  expect(ids).toContain("api.r7.copy");
  expect(ids).not.toContain("api.r2");
  expect(body.policy.routes.find((item) => item.operation_id === "api.r150")?.path).toBe(
    "/api/changed",
  );
});

test("the route drawer shows the server's route rules as you type", async ({ page }) => {
  await mockSite(page);
  await signInAt(page, "/sites/site_alpha/routes");
  await page.getByRole("button", { name: "新增路由" }).click();
  const drawer = page.getByRole("dialog", { name: "新增路由" });
  const apply = drawer.getByRole("button", { name: "应用到草稿" });
  // Exact names: the flow groups (“响应资源资格”, “由页面签发”) contain these words too.
  for (const group of ["匹配", "准入", "资源", "响应", "加密"]) {
    await expect(drawer.getByRole("region", { name: group, exact: true })).toBeVisible();
  }
  // A new route is a UI action: the flow groups it can take are offered, switched off.
  for (const [group, toggle] of [
    ["由页面签发", "由页面签发"],
    ["响应资源资格", "签发资源资格"],
  ] as const) {
    await expect(
      drawer
        .getByRole("region", { name: group, exact: true })
        .getByRole("switch", { name: toggle }),
    ).not.toBeChecked();
  }
  await expect(apply).toBeEnabled();

  // A resource binding needs GET, ui admission, a type, a profile and exactly one parameter.
  await drawer.getByLabel("资源类型", { exact: true }).fill("order");
  await expect(drawer.getByText("绑定资源时必须填写视图 profile。")).toBeVisible();
  await expect(
    drawer.getByText("资源查询字段与资源路径字段必须二选一，且只填一个。"),
  ).toBeVisible();
  await expect(apply).toBeDisabled();
  await drawer.getByLabel("视图 profile", { exact: true }).fill("customer");
  await drawer.getByLabel("资源路径字段", { exact: true }).fill("order_id");
  await drawer.getByLabel("路径", { exact: true }).fill("/api/orders/{order_id}");
  await expect(apply).toBeEnabled();
  await drawer.getByText("POST", { exact: true }).click();
  await expect(drawer.getByText("绑定资源的路由只能是 GET。")).toBeVisible();
  await drawer.getByText("GET", { exact: true }).click();

  // Admission and operation source go together.
  await drawer.getByRole("radio", { name: /^公开/ }).check();
  await expect(drawer.getByLabel("操作来源", { exact: true })).toBeDisabled();
  await expect(
    drawer.getByText("绑定资源的路由必须是“必须有界面操作来源”或“分享入口”。"),
  ).toBeVisible();
  await drawer.getByRole("radio", { name: /^必须有界面操作来源/ }).check();
  await expect(drawer.getByLabel("操作来源", { exact: true })).not.toHaveValue("");

  // Cancel leaves the draft untouched.
  await drawer.getByRole("button", { name: "取消" }).click();
  await expect(bar(page)).toHaveCount(0);
});

test("a site holds at most 256 routes", async ({ page }) => {
  await mockSite(page, { config: siteConfig({}, manyRoutes(256)) });
  await signInAt(page, "/sites/site_alpha/routes");
  await expect(page.getByText("共 256 条路由（最多 256）")).toBeVisible();
  await expect(page.getByRole("button", { name: "新增路由" })).toBeDisabled();
});

// ---- small screens ---------------------------------------------------------------------------

test("the workspace fits a 390 px screen without scrolling the page sideways", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await mockSite(page, { config: siteConfig({}, manyRoutes(30)) });
  await signInAt(page, "/sites/site_alpha/overview");
  for (const name of ["概览", "网络", "路由与操作", "WAF 与限流", "策略与健康", "发布"]) {
    await sectionLink(page, name).scrollIntoViewIfNeeded();
    await sectionLink(page, name).click();
    await expect(sectionLink(page, name)).toHaveAttribute("aria-current", "page");
    await page.waitForTimeout(250);
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
    );
    expect(overflow, name).toBeLessThanOrEqual(0);
  }
  await sectionLink(page, "网络").click();
  await page.getByLabel("站点名称", { exact: true }).fill("手机上改名");
  await expect(bar(page)).toBeVisible();
  const box = await bar(page).boundingBox();
  expect((box?.x ?? 0) + (box?.width ?? 0)).toBeLessThanOrEqual(390);
});

// ---- accessibility ---------------------------------------------------------------------------

for (const scheme of ["light", "dark"] as const) {
  test.describe(`site workspace accessibility (${scheme})`, () => {
    test.use({ colorScheme: scheme });
    for (const [section, label] of [
      ["overview", "概览"],
      ["network", "网络"],
      ["security-entry", "安全入口"],
      ["routes", "路由与操作"],
      ["identity", "身份"],
      ["crypto", "加密"],
      ["waf-limits", "WAF 与限流"],
      ["policies", "策略与健康"],
      ["releases", "发布"],
    ] as const) {
      test(`${section} has no serious violations`, async ({ page }) => {
        await mockSite(page, {
          state: {
            desired_revision: 4,
            active_revision: 3,
            apply_state: "pending",
            requires_approval: true,
            reason_code: "CONTROL_SITE_APPROVAL_REQUIRED",
          },
          revisions: [
            { revision: 4, config: siteConfig({ display_name: "Alpha 新" }) },
            { revision: 3, config: siteConfig() },
          ],
        });
        await signInAt(page, `/sites/site_alpha/${section}`);
        await expect(sectionLink(page, label)).toHaveAttribute("aria-current", "page");
        await expect(header(page)).toContainText("待审批");
        if (section === "network") await page.getByLabel("站点名称", { exact: true }).fill("改名");
        if (section === "policies")
          await page.getByRole("button", { name: "读取健康状态" }).click();
        if (section === "policies") await expect(page.getByText("观察于")).toBeVisible();
        expect(await serious(page)).toEqual([]);
      });
    }

    test("the route drawer and the diff dialog have no serious violations", async ({ page }) => {
      await mockSite(page);
      await signInAt(page, "/sites/site_alpha/routes");
      await page.getByRole("button", { name: "编辑路由 docs" }).click();
      await expect(page.getByRole("dialog", { name: "编辑路由" })).toBeVisible();
      await page.waitForTimeout(400);
      expect(await serious(page)).toEqual([]);
      await page
        .getByRole("dialog", { name: "编辑路由" })
        .getByLabel("路径", { exact: true })
        .fill("/docs2");
      await page.getByRole("button", { name: "应用到草稿" }).click();
      await bar(page).getByRole("button", { name: "查看差异" }).click();
      await expect(page.getByRole("dialog", { name: "未保存修改的差异" })).toBeVisible();
      await page.waitForTimeout(400);
      expect(await serious(page)).toEqual([]);
    });
  });
}
