import { expect, test } from "@playwright/test";

const SITE = {
  name: "emr",
  hosts: ["emr.example.com"],
  origin: "http://10.0.0.5:8080",
  session: { cookie: "SESSIONID" },
  entries: ["/login", "/api/home"],
  bypass: ["/static/*"],
  mode: "observe",
  on_jev_unavailable: "deny",
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-02T00:00:00Z",
};

test.beforeEach(async ({ page }) => {
  await page.route("**/api/session", (route) =>
    route.fulfill({ status: 200, json: { authenticated: true } }),
  );
  await page.route("**/api/jev/status", (route) =>
    route.fulfill({ status: 200, json: { status: "unknown" } }),
  );
});

test("lists sites and links through to the detail page", async ({ page }) => {
  await page.route("**/api/sites", (route) => route.fulfill({ status: 200, json: [SITE] }));
  await page.route("**/api/sites/emr", (route) => route.fulfill({ status: 200, json: SITE }));
  await page.route("**/api/sites/emr/history*", (route) =>
    route.fulfill({ status: 200, json: [] }),
  );

  await page.goto("/sites");
  await expect(page.getByRole("link", { name: "emr" })).toBeVisible();
  await expect(page.getByText("emr.example.com")).toBeVisible();

  await page.getByRole("link", { name: "emr" }).click();
  await expect(page).toHaveURL(/\/sites\/emr$/);
  await expect(page.getByRole("heading", { name: "站点：emr" })).toBeVisible();
});

test("redirects to /login when the session has expired", async ({ page }) => {
  await page.route("**/api/sites", (route) => route.fulfill({ status: 200, json: [SITE] }));
  await page.unroute("**/api/session");
  await page.route("**/api/session", (route) =>
    route.fulfill({ status: 401, json: { authenticated: false } }),
  );
  await page.goto("/sites");
  await expect(page).toHaveURL(/\/login$/);
});
