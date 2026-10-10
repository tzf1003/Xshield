import { expect, type Page, test } from "@playwright/test";
import { signIn } from "./shell-helpers";
import { mockWorkbench, type Override, reads } from "./workbench-helpers";

// The saved-search panel on the search page: the list loads on open and never reads by itself,
// and running a saved view is one ordinary audited search.

async function open(page: Page, path: string, override?: Override) {
  const calls = await mockWorkbench(page, { override });
  await signIn(page, path);
  return calls;
}

test("saved searches list on the search page, and running one submits its stored plan", async ({
  page,
}) => {
  const calls = await open(page, "/investigation/search");
  const panel = page.getByRole("region", { name: "保存的检索" });
  await expect(panel).toContainText("Weekly review");
  // Opening the page reads only the list (StrictMode may repeat it); no search runs until a view is opened.
  await expect.poll(() => reads(calls)).toEqual(["/control/v1/saved-views"]);
  expect(calls.filter((call) => call.path === "/control/v1/search")).toHaveLength(0);
  await panel.getByRole("button", { name: "运行", exact: true }).click();
  await expect
    .poll(() => calls.filter((call) => call.path === "/control/v1/search").length)
    .toBe(1);
  const search = calls.find((call) => call.path === "/control/v1/search");
  expect(search?.body).toMatchObject({ schema_version: 3, limit: 25, sort: "occurred_at_desc" });
  expect(search?.body).not.toHaveProperty("cursor");
});

test("a new view is saved from the submitted search and then listed", async ({ page }) => {
  const calls = await open(page, "/investigation/search");
  const panel = page.getByRole("region", { name: "保存的检索" });
  // Saving needs a submitted search: the button stays disabled until one runs.
  await expect(panel.getByRole("button", { name: "保存当前检索", exact: true })).toBeDisabled();
  await panel.getByRole("button", { name: "运行", exact: true }).click();
  await expect
    .poll(() => calls.filter((call) => call.path === "/control/v1/search").length)
    .toBe(1);
  await panel.getByLabel("视图名称", { exact: true }).fill("Morning triage");
  await panel.getByRole("button", { name: "保存当前检索", exact: true }).click();
  await expect
    .poll(
      () =>
        calls.filter((call) => call.method === "POST" && call.path === "/control/v1/saved-views")
          .length,
    )
    .toBe(1);
  const created = calls.find(
    (call) => call.method === "POST" && call.path === "/control/v1/saved-views",
  );
  expect(created?.body).toMatchObject({ schema_version: 1, name: "Morning triage" });
  expect(created?.body).toHaveProperty("search");
  expect(created?.body).not.toHaveProperty("search.cursor");
});

test("deleting a saved view sends one DELETE for that view and lists again", async ({ page }) => {
  const calls = await open(page, "/investigation/search");
  const panel = page.getByRole("region", { name: "保存的检索" });
  await expect(panel).toContainText("Weekly review");
  await panel.getByRole("button", { name: "删除", exact: true }).click();
  await expect.poll(() => calls.filter((call) => call.method === "DELETE").length).toBe(1);
  const removed = calls.find((call) => call.method === "DELETE");
  expect(removed?.path).toBe("/control/v1/saved-views/view_018f2a3b-4c5d-7000-8000-000000000001");
});
