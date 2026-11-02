// The interface-name rules of a configuration (console-design-objects-routes 2): the group sits between the session
// credential and the entries; a rule is added and deleted; its problems are shown; the tester reads a pasted request
// on the page; a route link opens the group with its path filled in; and an entry that a rule now hides is shown with
// the logical paths it could be written as.

import { expect, type Page, test } from "@playwright/test";
import { expectNoAxeViolations, setTheme, type Theme } from "./helpers/axe.ts";
import { mockApi } from "./helpers/mock-api.ts";
import { siteEmr } from "./helpers/fixtures.ts";
import { freezeClock } from "./helpers/sites-flow.ts";

const GATEWAY = "/weixin/wx/mp/wx361163d21a65f679/gateway";
const CALL = "bus.buriedPointService/saveBuriedPointList";
const OTHER_CALL = "bus.buriedPointService/queryBuriedPointList";
const FROM = ["header.X-Service-Id", "header.X-Service-Method"];
const GATEWAY_RULE = {
  path: GATEWAY,
  name_from: [["header.X-Service-Id"], ["header.X-Service-Method"]],
};

/** The recent records of the gateway: two named calls, and one request whose name could not be read. */
const RECENT = {
  rows: [
    { path: GATEWAY, logical_path: `${GATEWAY}/${CALL}`, api: { name: CALL, from: FROM } },
    {
      path: GATEWAY,
      logical_path: `${GATEWAY}/${OTHER_CALL}`,
      api: { name: OTHER_CALL, from: FROM },
    },
    {
      path: GATEWAY,
      logical_path: "unknown-api",
      api: { unknown: "missing", source: "header.X-Service-Method" },
    },
  ],
  next_cursor: null,
};

const COUNTS = {
  judged: 9812,
  attention: 21,
  blocked: 21,
  would_block: 0,
  unjudged: 0,
  jev: 412,
  no_session: 0,
  bypass: 0,
  unknown_site: 0,
  complete: true,
};

/** emr as the server would return it, with the given parts of its configuration changed. */
function emrWith(patch: Record<string, unknown>) {
  return { ...siteEmr, spec: { ...siteEmr.spec, ...patch } };
}

async function openConfig(page: Page, path: string, patch: Record<string, unknown>): Promise<void> {
  await freezeClock(page);
  await mockApi(page, {
    overrides: {
      "/api/sites/emr": emrWith(patch),
      "/api/requests": RECENT,
      "/api/requests/counts": COUNTS,
    },
  });
  await page.goto(path);
  await expect(page.getByRole("navigation", { name: "配置分组" })).toBeVisible();
}

test("接口名规则分组排在会话凭证之后、入口之前", async ({ page }) => {
  await openConfig(page, "/sites/emr?tab=config", {});

  await expect(page.getByRole("navigation", { name: "配置分组" }).getByRole("button")).toHaveText([
    /^基本信息/,
    /^会话凭证/,
    /^接口名规则/,
    /^入口/,
    /^绕过/,
    /^模式与 Jev 不可用/,
    /^高级判定参数/,
  ]);
});

test("添加一条接口名规则，再删除它", async ({ page }) => {
  await openConfig(page, "/sites/emr?tab=config&group=routes", {});

  await expect(page.getByText("还没有接口名规则")).toBeVisible();
  await page.getByRole("button", { name: "＋ 添加规则" }).click();
  const card = page.getByRole("region", { name: "接口名规则 1" });
  await expect(card).toBeVisible();
  await expect(
    page.getByRole("navigation", { name: "配置分组" }).getByRole("button", { name: /^接口名规则/ }),
  ).toContainText("1");

  await card.getByRole("button", { name: "删除规则" }).click();
  await expect(page.getByText("还没有接口名规则")).toBeVisible();
  await expect(page.getByText("未保存的改动")).toHaveCount(0);
});

test("路径重叠和名称不合法时，规则下面给出说明", async ({ page }) => {
  await openConfig(page, "/sites/emr?tab=config&group=routes", { routes: [GATEWAY_RULE] });

  const first = page.getByRole("region", { name: "接口名规则 1" });
  await first
    .getByRole("textbox", { name: "接口名第 1 段的第 1 个位置的名称" })
    .fill("X-Service/Id");
  await expect(first.getByRole("alert")).toContainText("请求头名只能含 HTTP 头名的字符");

  await page.getByRole("button", { name: "＋ 添加规则" }).click();
  const second = page.getByRole("region", { name: "接口名规则 2" });
  await second.getByRole("textbox", { name: "路径", exact: true }).fill(GATEWAY);
  await expect(second.getByText("与第 1 条规则的路径重叠")).toBeVisible();
});

test("规则测试读一个完整的请求：接口名、逻辑路径、判定和隐藏的凭证", async ({ page }) => {
  await openConfig(page, "/sites/emr?tab=config&group=routes", { routes: [GATEWAY_RULE] });

  const card = page.getByRole("region", { name: "接口名规则 1" });
  await expect(card.getByText("24 小时 9,812 次")).toBeVisible();
  await expect(card).toContainText(`示例 ${GATEWAY}/${CALL}`);
  await expect(card).toContainText("取不到 24 小时 1 次，按“未知接口”处理");
  await expect(card.getByRole("link", { name: "查看这些请求" })).toHaveAttribute(
    "href",
    /\/requests\?/,
  );
  // The two locations are single: the hint offers to confirm that the source reads only these.
  await expect(card).toContainText("每一段都只写了一个位置");

  await page
    .getByRole("textbox", { name: "规则测试" })
    .fill(
      [
        `POST ${GATEWAY} HTTP/1.1`,
        "Host: emr.example.com",
        "Cookie: JSESSIONID=abc123",
        "X-Access-Token: tok-9",
        "X-Service-Id: bus.buriedPointService",
        "X-Service-Method: saveBuriedPointList",
        "Content-Type: application/json",
        "",
        '{"ok":true}',
      ].join("\n"),
    );
  const result = page.getByRole("status").filter({ hasText: "逻辑路径" });
  await expect(result).toContainText(`接口名 ${CALL}（第 1 段：请求头 X-Service-Id`);
  await expect(result).toContainText(`逻辑路径 ${GATEWAY}/${CALL}`);
  await expect(result).toContainText("已隐藏 2 个凭证值（Cookie、X-Access-Token）");
  await expect(result).not.toContainText("abc123");
  await expect(result).not.toContainText("tok-9");

  await card.getByRole("button", { name: "我确认源站只认这里" }).click();
  await expect(card).not.toContainText("每一段都只写了一个位置");
});

test("接口名规则的链接打开分组，并预填路径", async ({ page }) => {
  await openConfig(page, `/sites/emr?tab=config&route=${GATEWAY}`, {});

  const groups = page.getByRole("navigation", { name: "配置分组" });
  await expect(groups.getByRole("button", { name: /^接口名规则/ })).toHaveAttribute(
    "aria-current",
    "true",
  );
  await expect(page.getByRole("textbox", { name: "路径", exact: true })).toHaveValue(GATEWAY);
  // The new rule reads a request header, and its name is for the user to fill in.
  await expect(page.getByText("名称不能为空")).toBeVisible();
  await expect(page.getByText("未保存的改动 1 处")).toBeVisible();
});

test("入口写成会被规则改写的路径时提示，并按最近记录补全逻辑路径", async ({ page }) => {
  await openConfig(page, "/sites/emr?tab=config&group=entries", {
    routes: [GATEWAY_RULE],
    entries: ["/login", GATEWAY],
  });

  const entries = page.getByRole("list", { name: "入口" });
  await expect(entries).toContainText("入口不再命中");
  await expect(entries.getByRole("button", { name: new RegExp(CALL) })).toBeVisible();

  // Typing under the rule lists the same completions below the input; the last match is that list.
  const input = page.getByRole("textbox", { name: "添加入口规则" });
  await input.fill(`${GATEWAY}/`);
  await page
    .getByRole("button", { name: new RegExp(OTHER_CALL) })
    .last()
    .click();
  await expect(input).toHaveValue(`${GATEWAY}/${OTHER_CALL}`);
});

for (const theme of ["light", "dark"] satisfies Theme[]) {
  test(`接口名规则分组在${theme === "light" ? "浅色" : "深色"}配色下通过 axe 检查`, async ({
    page,
  }) => {
    await setTheme(page, theme);
    await openConfig(page, "/sites/emr?tab=config&group=routes", { routes: [GATEWAY_RULE] });
    await expect(page.getByRole("region", { name: "接口名规则 1" })).toBeVisible();
    await expectNoAxeViolations(page);
  });
}
