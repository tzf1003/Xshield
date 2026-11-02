// The first browser spec: the request list opens on the mock API and passes axe in both themes.
// It proves the harness (dev server, page.route fixtures, theme set before load) before the other
// specs are written against it.

import { expect, test } from "@playwright/test";
import { expectNoAxeViolations, setTheme, type Theme } from "./helpers/axe.ts";
import { mockApi } from "./helpers/mock-api.ts";
import { freezeClock } from "./helpers/sites-flow.ts";

for (const theme of ["light", "dark"] satisfies Theme[]) {
  test(`the request list passes axe in the ${theme} theme`, async ({ page }) => {
    await freezeClock(page);
    await mockApi(page);
    await setTheme(page, theme);
    await page.goto("/requests");
    await expect(page.getByRole("table", { name: "请求列表" })).toBeVisible();
    await expectNoAxeViolations(page);
  });
}
