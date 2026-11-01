// Helpers of the site specs (tests/sites-*.spec.ts): the frozen clock, impact previews shaped like the
// fixture so an override can say what a change would do, and reads of the calls the console made.
// Nothing here changes the samples in tests/fixtures.

import AxeBuilder from "@axe-core/playwright";
import { expect, type Page } from "@playwright/test";
import type { ImpactChange, ImpactPreview } from "../../src/api/types.ts";
import { preview } from "./fixtures.ts";
import { FIXTURE_NOW_MS, type ServedRequest, servedRequests } from "./mock-api.ts";

/**
 * Freezes the browser clock at the fixture instant, so the windows and the "observed for" texts read
 * the same on every run. Call it before the first navigation.
 */
export async function freezeClock(page: Page): Promise<void> {
  await page.clock.setFixedTime(FIXTURE_NOW_MS);
}

/** An impact preview with the given changes; everything else comes from the fixture. */
export function impactWith(
  changes: ImpactChange[],
  extra: Partial<Pick<ImpactPreview, "patterns" | "warnings">> = {},
): ImpactPreview {
  return { ...structuredClone(preview), changes, ...extra };
}

/** The calls of one method to one path, in the order the console made them. */
export function callsTo(page: Page, method: string, path: string): ServedRequest[] {
  return servedRequests(page).filter((call) => call.method === method && call.path === path);
}

/**
 * Axe over the open dialog only (antd's modal box). The page under the dialog's mask belongs to another
 * feature and is checked by that feature's spec: axe reads its colours without the mask's darkening, so a
 * whole-page check reports what sits under the dialog as well as the dialog itself.
 */
export async function expectDialogNoAxeViolations(page: Page): Promise<void> {
  // antd fades the box in, and axe would read its colours half-way through the fade: wait for it to end.
  await page.waitForFunction(() => {
    const root = document.querySelector(".ant-modal-root");
    return (
      root === null ||
      root.getAnimations({ subtree: true }).every((item) => item.playState !== "running")
    );
  });
  const results = await new AxeBuilder({ page }).include(".ant-modal").analyze();
  const found = results.violations.map((violation) => {
    const where = violation.nodes
      .slice(0, 3)
      .map(
        (node) => `${node.target.join(" ")} [${node.any.map((check) => check.message).join("; ")}]`,
      )
      .join(" | ");
    return `${violation.id} (${violation.nodes.length}): ${where}`;
  });
  expect(found, "axe violations in the dialog").toEqual([]);
}
