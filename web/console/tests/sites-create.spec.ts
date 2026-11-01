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
}
