import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

/**
 * No real backend exists in this environment (and never will in CI for this repo), so every
 * `/api/*` call is mocked at the network layer. These specs are smoke tests for the login flow
 * and a basic accessibility check, not a substitute for backend integration tests.
 */

test("shows the login form and has no detectable a11y violations", async ({ page }) => {
  await page.route("**/api/session", (route) =>
    route.fulfill({ status: 401, json: { authenticated: false } }),
  );
  await page.goto("/login");
  await expect(page.getByRole("heading", { name: "Xshield 管理控制台" })).toBeVisible();
  await expect(page.getByRole("button", { name: "登录" })).toBeVisible();

  const results = await new AxeBuilder({ page }).analyze();
  expect(results.violations).toEqual([]);
});

test("shows the server's error message on a failed login", async ({ page }) => {
  await page.route("**/api/session", (route) =>
    route.fulfill({ status: 401, json: { authenticated: false } }),
  );
  await page.route("**/api/login", (route) =>
    route.fulfill({ status: 401, json: { error: "INVALID_PASSWORD" } }),
  );
  await page.goto("/login");
  await page.getByLabel("管理员口令").fill("wrong-password");
  await page.getByRole("button", { name: "登录" }).click();
  await expect(page.getByRole("alert")).toContainText("口令不正确");
});

test("navigates to /sites after a successful login", async ({ page }) => {
  await page.route("**/api/session", (route) =>
    route.fulfill({ status: 401, json: { authenticated: false } }),
  );
  await page.route("**/api/login", (route) => route.fulfill({ status: 200, json: {} }));
  await page.route("**/api/sites", (route) => route.fulfill({ status: 200, json: [] }));
  await page.route("**/api/jev/status", (route) =>
    route.fulfill({ status: 200, json: { status: "unknown" } }),
  );
  await page.goto("/login");
  await page.getByLabel("管理员口令").fill("correct-password");
  await page.getByRole("button", { name: "登录" }).click();
  await expect(page).toHaveURL(/\/sites$/);
});
