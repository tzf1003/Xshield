// Creating a site (docs/06 6.4.8, P0): the single form with the YAML it produces beside it, or a configuration pasted
// as YAML. The server decides whether the configuration is valid and whether its Host is free, and a created site
// opens at once with its first version.

import { expect, type Page, test } from "@playwright/test";
import { expectNoAxeViolations, setTheme, type Theme } from "./helpers/axe.ts";
import { mockApi } from "./helpers/mock-api.ts";
import { callsTo, freezeClock } from "./helpers/sites-flow.ts";

const EDITOR = "站点配置，YAML 或 JSON";

const YAML_SITE = `name: yaml-shop
hosts:
  - yaml.example.com
origin: http://10.0.0.9:8080
session:
  cookie: JSESSIONID
entries:
  - /api/home
bypass: []
mode: observe
on_jev_unavailable: deny
`;

/** The same site with `mode: enforce`: the mode the YAML names is the mode the site is created with. */
const YAML_ENFORCE = YAML_SITE.replace("mode: observe", "mode: enforce");

/** The hint after creating an enforcing site from YAML: it has no observation period (docs/06 6.4.8). */
const ENFORCE_HINT = "新站点没有观察期，入口和绕过设错会直接拦截正常请求";

/** Fills the single form the way a user does: name, Host, origin, session cookie and one entry. */
async function fillForm(page: Page, name: string, host: string): Promise<void> {
  await page.getByLabel("站点名", { exact: true }).fill(name);
  const hosts = page.getByRole("textbox", { name: "添加Host" });
  await hosts.fill(host);
  await hosts.press("Enter");
  await page.getByLabel("源站地址", { exact: true }).fill("http://10.0.0.9:8080");
  await page.getByLabel("名称", { exact: true }).fill("JSESSIONID");
  const entries = page.getByRole("textbox", { name: "添加入口规则" });
  await entries.fill("/api/home");
  await entries.press("Enter");
}

test("a valid form is checked by the server, then creates the site, which opens at its first version", async ({
  page,
}) => {
  await freezeClock(page);
  await mockApi(page);
  await page.goto("/sites/new");

  await fillForm(page, "shop", "shop.example.com");
  await expect(page.getByText("✓ 服务端校验通过")).toBeVisible();
  expect(callsTo(page, "POST", "/api/sites/validate").at(-1)?.body).toMatchObject({
    spec: { name: "shop", hosts: ["shop.example.com"] },
  });

  await page.getByRole("button", { name: "创建站点" }).click();

  await expect(page).toHaveURL(/\/sites\/shop$/);
  await expect(page.getByText("已创建 v1。下一步：把 Host")).toBeVisible();
  const [created] = callsTo(page, "POST", "/api/sites");
  expect(created?.body).toMatchObject({
    spec: {
      name: "shop",
      hosts: ["shop.example.com"],
      origin: "http://10.0.0.9:8080",
      session: { cookie: "JSESSIONID" },
      entries: ["/api/home"],
      mode: "observe",
    },
  });
});

test("a Host another site serves is refused by the server, and the page names it", async ({
  page,
}) => {
  await freezeClock(page);
  await mockApi(page);
  await page.goto("/sites/new");

  await fillForm(page, "shop2", "juice.example.com");
  await expect(page.getByText("✓ 服务端校验通过")).toBeVisible();
  await page.getByRole("button", { name: "创建站点" }).click();

  await expect(page.getByRole("alert")).toContainText("Host juice.example.com 已属于其他站点");
  await expect(page).toHaveURL(/\/sites\/new$/);
  expect(callsTo(page, "POST", "/api/sites")).toHaveLength(1);
});

test("the YAML view starts from the configuration the form holds", async ({ page }) => {
  await freezeClock(page);
  await mockApi(page);
  await page.goto("/sites/new");

  await page.getByLabel("站点名", { exact: true }).fill("shop");
  await page.getByText("从 YAML 创建").click();

  await expect(page).toHaveURL(/from=yaml/);
  await expect(page.getByRole("textbox", { name: EDITOR })).toContainText("name: shop");
});

test("a configuration pasted as YAML is checked by the server, then creates the site", async ({
  page,
}) => {
  await freezeClock(page);
  await mockApi(page);
  await page.goto("/sites/new?from=yaml");

  await page.getByRole("textbox", { name: EDITOR }).fill(YAML_SITE);
  await expect(page.getByText("✓ 服务端校验通过")).toBeVisible();
  await page.getByRole("button", { name: "创建站点" }).click();

  await expect(page).toHaveURL(/\/sites\/yaml-shop$/);
  const [created] = callsTo(page, "POST", "/api/sites");
  expect(created?.body).toMatchObject({
    spec: { name: "yaml-shop", hosts: ["yaml.example.com"], entries: ["/api/home"] },
  });
});

test("a YAML that names enforce creates an enforce site, and the new site says what that means", async ({
  page,
}) => {
  await freezeClock(page);
  await mockApi(page);
  await page.goto("/sites/new?from=yaml");

  await page.getByRole("textbox", { name: EDITOR }).fill(YAML_ENFORCE);
  await expect(page.getByText("✓ 服务端校验通过")).toBeVisible();
  // The hint never stops the save: the create button is enabled before it is pressed.
  await expect(page.getByRole("button", { name: "创建站点" })).toBeEnabled();
  await page.getByRole("button", { name: "创建站点" }).click();

  await expect(page).toHaveURL(/\/sites\/yaml-shop$/);
  const [created] = callsTo(page, "POST", "/api/sites");
  expect(created?.body).toMatchObject({ spec: { name: "yaml-shop", mode: "enforce" } });
  await expect(page.getByText(ENFORCE_HINT)).toBeVisible();
});

test("a YAML without a mode creates an observe site, and no enforce hint is shown", async ({
  page,
}) => {
  await freezeClock(page);
  await mockApi(page);
  await page.goto("/sites/new?from=yaml");

  await page.getByRole("textbox", { name: EDITOR }).fill(YAML_SITE.replace("mode: observe\n", ""));
  await expect(page.getByText("✓ 服务端校验通过")).toBeVisible();
  await page.getByRole("button", { name: "创建站点" }).click();

  await expect(page).toHaveURL(/\/sites\/yaml-shop$/);
  await expect(page.getByText("已创建 v1。下一步：把 Host")).toBeVisible();
  const [created] = callsTo(page, "POST", "/api/sites");
  expect(created?.body).toMatchObject({ spec: { name: "yaml-shop" } });
  const sent = created?.body as { spec: Record<string, unknown> };
  expect(sent.spec).not.toHaveProperty("mode");
  await expect(page.getByText(ENFORCE_HINT)).toHaveCount(0);
});

test("a form created after a YAML that named enforce creates an observe site, and its mode control offers no enforce", async ({
  page,
}) => {
  await freezeClock(page);
  await mockApi(page);
  await page.goto("/sites/new?from=yaml");

  await page.getByRole("textbox", { name: EDITOR }).fill(YAML_ENFORCE);
  await expect(page.getByText("✓ 服务端校验通过")).toBeVisible();
  await page.getByText("表单", { exact: true }).click();

  // A new site starts in observe: the form shows that mode and no 拦截 choice; enforce is set on the site page.
  await expect(page).not.toHaveURL(/from=yaml/);
  await expect(page.getByText("✓ 服务端校验通过")).toBeVisible();
  await expect(page.getByText("观察模式", { exact: true })).toBeVisible();
  await expect(page.getByText("拦截", { exact: true })).toHaveCount(0);
  await expect(page.locator("pre.codeblock")).toContainText("mode: observe");
  await page.getByRole("button", { name: "创建站点" }).click();

  await expect(page).toHaveURL(/\/sites\/yaml-shop$/);
  const [created] = callsTo(page, "POST", "/api/sites");
  expect(created?.body).toMatchObject({ spec: { name: "yaml-shop", mode: "observe" } });
  await expect(page.getByText(ENFORCE_HINT)).toHaveCount(0);
});

test("a copy of an enforcing site opens the form in observe, and the copy is created in observe", async ({
  page,
}) => {
  await freezeClock(page);
  await mockApi(page);
  await page.goto("/sites/emr");

  await page.getByRole("button", { name: "更多操作" }).click();
  await page.getByRole("menuitem", { name: "复制为新站点" }).click();

  // emr enforces; the copy keeps its settings but not its mode, and the name is left for the user to set.
  await expect(page).toHaveURL(/\/sites\/new$/);
  await expect(page.getByLabel("站点名", { exact: true })).toHaveValue("");
  await expect(page.getByLabel("源站地址", { exact: true })).toHaveValue("http://10.0.0.5:8080");
  await expect(page.getByText("观察模式", { exact: true })).toBeVisible();
  await expect(page.getByText("拦截", { exact: true })).toHaveCount(0);

  await page.getByLabel("站点名", { exact: true }).fill("emr-copy");
  await page.getByRole("button", { name: "删除 emr.example.com" }).click();
  const hosts = page.getByRole("textbox", { name: "添加Host" });
  await hosts.fill("emr-copy.example.com");
  await hosts.press("Enter");
  await expect(page.getByText("✓ 服务端校验通过")).toBeVisible();
  await page.getByRole("button", { name: "创建站点" }).click();

  await expect(page).toHaveURL(/\/sites\/emr-copy$/);
  const [created] = callsTo(page, "POST", "/api/sites");
  expect(created?.body).toMatchObject({
    spec: {
      name: "emr-copy",
      hosts: ["emr-copy.example.com"],
      origin: "http://10.0.0.5:8080",
      session: { header: "Authorization" },
      mode: "observe",
    },
  });
  await expect(page.getByText(ENFORCE_HINT)).toHaveCount(0);
});

test("YAML that does not parse cannot be created", async ({ page }) => {
  await freezeClock(page);
  await mockApi(page);
  await page.goto("/sites/new?from=yaml");

  await page.getByRole("textbox", { name: EDITOR }).fill("name: [\nhosts: ");
  await expect(page.getByText("YAML 有错误，修好后才能创建站点。")).toBeVisible();
  await expect(page.getByRole("button", { name: "创建站点" })).toBeDisabled();
  expect(callsTo(page, "POST", "/api/sites")).toHaveLength(0);
});

test("from 768 px the form and its YAML sit side by side, and below it they stack", async ({
  page,
}) => {
  await freezeClock(page);
  await mockApi(page);
  await page.setViewportSize({ width: 800, height: 900 });
  await page.goto("/sites/new");

  const columns = () =>
    page
      .locator(".wizard-layout")
      .evaluate((el) => getComputedStyle(el).gridTemplateColumns.split(" ").length);
  await expect.poll(columns).toBe(2);

  await page.setViewportSize({ width: 390, height: 844 });
  await expect.poll(columns).toBe(1);
});

for (const theme of ["light", "dark"] satisfies Theme[]) {
  test(`the new-site form passes axe in the ${theme} theme`, async ({ page }) => {
    await freezeClock(page);
    await mockApi(page);
    await setTheme(page, theme);
    await page.goto("/sites/new");

    await expect(page.getByLabel("站点名", { exact: true })).toBeVisible();
    await expectNoAxeViolations(page);
  });

  test(`the new-site YAML passes axe in the ${theme} theme`, async ({ page }) => {
    await freezeClock(page);
    await mockApi(page);
    await setTheme(page, theme);
    await page.goto("/sites/new?from=yaml");

    await expect(page.getByRole("textbox", { name: EDITOR })).toBeVisible();
    await expectNoAxeViolations(page);
  });

  test(`the page of a site created from an enforce YAML passes axe in the ${theme} theme`, async ({
    page,
  }) => {
    await freezeClock(page);
    await mockApi(page);
    await setTheme(page, theme);
    await page.goto("/sites/new?from=yaml");

    await page.getByRole("textbox", { name: EDITOR }).fill(YAML_ENFORCE);
    await expect(page.getByText("✓ 服务端校验通过")).toBeVisible();
    await page.getByRole("button", { name: "创建站点" }).click();

    await expect(page.getByText(ENFORCE_HINT)).toBeVisible();
    await expectNoAxeViolations(page);
  });
}
