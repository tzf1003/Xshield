// Sign-in (docs/06 6.4.1): a wrong password, the right one, the page that was asked for, sign-out from
// the user menu, the sign-in dialog a 401 opens, and axe on the login page and the dialog in both themes.

import { expect, type Page, test } from "@playwright/test";
import { expectNoAxeViolations, setTheme, type Theme } from "./helpers/axe.ts";
import { reply, servedRequests } from "./helpers/mock-api.ts";
import { failOnce, untilDialogOpen, useFixtures } from "./helpers/trace.ts";

const PASSWORD = "open-sesame";

async function submitPassword(page: Page, password: string): Promise<void> {
  await page.getByLabel("口令").fill(password);
  await page.getByRole("button", { name: "登录" }).click();
}

test("a wrong password says 口令不正确, and the right one opens the page that was asked for", async ({
  page,
}) => {
  await useFixtures(page, { signedIn: false, password: PASSWORD });
  await page.goto("/requests?chip=would_block");
  await expect(page).toHaveURL(/\/login\?next=/);

  await submitPassword(page, "not-the-password");
  await expect(page.getByRole("alert")).toHaveText("口令不正确");
  await expect(page).toHaveURL(/\/login/);

  await submitPassword(page, PASSWORD);
  await expect(page).toHaveURL(/\/requests\?chip=would_block$/);
  await expect(page.getByRole("button", { name: /^本应拦截/ })).toHaveAttribute(
    "aria-pressed",
    "true",
  );
  await expect(page.getByRole("table", { name: "请求列表" })).toBeVisible();

  const logins = servedRequests(page).filter((call) => call.path === "/api/login");
  expect(logins.map((call) => call.status)).toEqual([401, 204]);
});

test("too many attempts say 尝试次数过多, and the page stays on the login", async ({ page }) => {
  await useFixtures(page, {
    signedIn: false,
    overrides: { "POST /api/login": reply(429, { error: "LOGIN_RATE_LIMITED" }) },
  });
  await page.goto("/login");
  await submitPassword(page, "anything");
  await expect(page.getByRole("alert")).toHaveText("尝试次数过多，请 10 分钟后再试");
  await expect(page).toHaveURL(/\/login$/);
});

test("signing out from the user menu returns to the login page", async ({ page }) => {
  await useFixtures(page);
  await page.goto("/requests");
  await expect(page.getByRole("table", { name: "请求列表" })).toBeVisible();

  await page.getByRole("button", { name: "用户菜单" }).click();
  await page.getByRole("button", { name: "退出登录" }).click();

  await expect(page).toHaveURL(/\/login$/);
  await expect(page.getByRole("heading", { name: "Xshield 控制台" })).toBeVisible();
  expect(servedRequests(page).some((call) => call.path === "/api/logout")).toBe(true);
});

test("a 401 on a page opens the sign-in dialog and leaves the page where it is", async ({
  page,
}) => {
  await useFixtures(page);
  await failOnce(page, "/api/requests/counts", 401, "UNAUTHENTICATED");
  await page.goto("/requests?chip=would_block");

  const dialog = page.getByRole("dialog", { name: "登录已过期" });
  await expect(dialog).toBeVisible();
  await expect(page).toHaveURL(/\/requests\?chip=would_block$/);

  await dialog.getByLabel("口令").fill(PASSWORD);
  await dialog.getByRole("button", { name: "登录" }).click();

  await expect(dialog).toBeHidden();
  await expect(page).toHaveURL(/\/requests\?chip=would_block$/);
  await expect(page.getByRole("table", { name: "请求列表" })).toBeVisible();
});

test("outside HTTPS or localhost the page says the browser will not keep the sign-in", async ({
  page,
}) => {
  await useFixtures(page, { signedIn: false });
  await page.addInitScript(() => {
    Object.defineProperty(window, "isSecureContext", { value: false });
  });
  await page.goto("/login");
  await expect(page.getByRole("note")).toContainText("控制台需要经 HTTPS 或 localhost 访问");
});

for (const theme of ["light", "dark"] satisfies Theme[]) {
  test(`the login page passes axe in the ${theme} theme, with and without an error`, async ({
    page,
  }) => {
    await useFixtures(page, { signedIn: false, password: PASSWORD });
    await setTheme(page, theme);
    await page.goto("/login");
    await expect(page.getByLabel("口令")).toBeVisible();
    await expectNoAxeViolations(page);

    await submitPassword(page, "not-the-password");
    await expect(page.getByRole("alert")).toHaveText("口令不正确");
    await expectNoAxeViolations(page);
  });

  test(`the sign-in dialog passes axe in the ${theme} theme`, async ({ page }) => {
    await useFixtures(page);
    await setTheme(page, theme);
    await failOnce(page, "/api/requests/counts", 401, "UNAUTHENTICATED");
    await page.goto("/requests");
    await expect(page.getByRole("dialog", { name: "登录已过期" })).toBeVisible();
    await untilDialogOpen(page, "登录已过期");
    await expectNoAxeViolations(page);
  });
}
