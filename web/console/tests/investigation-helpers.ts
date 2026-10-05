import type { Page } from "@playwright/test";
import { signIn } from "./shell-helpers";

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
