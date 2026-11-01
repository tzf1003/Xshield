// Shared by the browser specs: the theme set before the first paint, and the axe check that
// docs/06 requires on every page in both themes (docs/07 7.10.8).

import AxeBuilder from "@axe-core/playwright";
import { expect, type Page } from "@playwright/test";

export type Theme = "light" | "dark";

/** Sets the theme that ThemeProvider reads at start-up. Call it before the first navigation. */
export async function setTheme(page: Page, theme: Theme): Promise<void> {
  await page.addInitScript((value: string) => {
    window.localStorage.setItem("xshield.console.theme", value);
  }, theme);
}

/** Runs axe on the page as it is now and fails, naming each rule that reports a violation. */
export async function expectNoAxeViolations(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).analyze();
  const found = results.violations.map((violation) => {
    const where = violation.nodes
      .slice(0, 3)
      .map((node) => node.target.join(" "))
      .join(" | ");
    return `${violation.id} (${violation.nodes.length}): ${where}`;
  });
  expect(found, "axe violations").toEqual([]);
}
