import { expect, type Page } from "@playwright/test";
import { signIn } from "./shell-helpers";

/**
 * The search page right after another page handed over exactly one condition: that condition is
 * a tag, no time range is chosen, and the notice says nothing has been queried.
 */
export async function expectPrefilled(page: Page, label: string, value: string) {
  await expect(page.getByRole("heading", { name: "结构化事件检索", exact: true })).toBeVisible();
  const conditions = page.getByRole("list", { name: "已添加的检索条件" });
  await expect(conditions.getByRole("listitem")).toHaveCount(1);
  await expect(conditions).toContainText(`${label}：${value}`);
  await expect(
    page.getByRole("group", { name: "时间范围" }).getByRole("button", { pressed: true }),
  ).toHaveCount(0);
  await expect(page.getByText("已预填目标引用，请确认 UTC 时间窗后提交历史检索。")).toBeVisible();
  await expect(page.getByRole("region", { name: "搜索事件结果" })).toHaveCount(0);
}

/** A landing page that reads nothing, so call counts start at zero after sign-in. */
export const QUIET_PAGE = "/access/session";

/** Signs in on the quiet page (machine-login build). */
export async function signInQuietly(page: Page) {
  await signIn(page, QUIET_PAGE);
}

/**
 * Opens an object the way an operator pastes an ID: through the ⌘K palette. An ID the palette
 * does not recognise leaves it open, so it is closed again.
 */
export async function pasteId(page: Page, value: string) {
  await page.keyboard.press("Control+KeyK");
  const palette = page.getByRole("combobox", { name: "命令面板" });
  await palette.fill(value);
  await page.keyboard.press("Enter");
  if (await palette.isVisible()) await page.keyboard.press("Escape");
}

/** Chooses a custom range in the picker. With a UTC browser clock the plan carries the same text. */
export async function pickRange(page: Page, start: string, end: string) {
  await page.getByRole("button", { name: "自定义", exact: true }).click();
  await page.getByLabel("开始时间（本地，含）", { exact: true }).fill(start);
  await page.getByLabel("结束时间（本地，不含）", { exact: true }).fill(end);
}

export async function submitSearch(page: Page) {
  await page.getByRole("button", { name: "检索事件", exact: true }).click();
}
