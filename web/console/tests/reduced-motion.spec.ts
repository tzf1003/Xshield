// Reduced motion: when the system asks for less motion, antd's own motion (the command palette,
// drawers and modals) stops too, so nothing slides or fades in. The console's own CSS animations are
// covered by the reduced-motion rules in global.css; this spec checks the antd overlays, whose motion
// comes from the theme.

import { expect, type Page, test } from "@playwright/test";
import { FIXTURE_NOW_MS, mockApi } from "./helpers/mock-api.ts";

type Sample = { running: string[]; observed: number };

/**
 * Opens the command palette (an antd Modal) and samples every frame while it opens: which elements of the
 * dialog run an animation or transition with a duration, and how many elements were looked at. The count
 * shows the sampler saw the dialog at all, so an empty `running` list cannot pass by looking at nothing.
 */
async function motionWhileOpening(page: Page): Promise<Sample> {
  await mockApi(page);
  await page.clock.setFixedTime(FIXTURE_NOW_MS);
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "总览", level: 1 })).toBeVisible();
  const sampled = page.evaluate(
    () =>
      new Promise<{ running: string[]; observed: number }>((resolve) => {
        const running = new Set<string>();
        let observed = 0;
        let frames = 0;
        const frame = () => {
          for (const element of document.querySelectorAll(".ant-modal-root, .ant-modal-root *")) {
            observed += 1;
            for (const animation of element.getAnimations()) {
              const duration = animation.effect?.getComputedTiming().duration;
              if (typeof duration === "number" && duration > 0) {
                running.add(`${element.tagName}.${element.getAttribute("class") ?? ""}`);
              }
            }
          }
          frames += 1;
          if (frames < 60) requestAnimationFrame(frame);
          else resolve({ running: [...running], observed });
        };
        requestAnimationFrame(frame);
      }),
  );
  await page.locator(".search-trigger").click();
  await expect(page.getByRole("dialog", { name: "命令面板" })).toBeVisible();
  return sampled;
}

test.describe("reduced motion", () => {
  test.use({ reducedMotion: "reduce" });

  test("the command palette starts no animation or transition", async ({ page }) => {
    const sample = await motionWhileOpening(page);
    expect(sample.observed).toBeGreaterThan(0);
    expect(sample.running).toEqual([]);
  });
});

test.describe("normal motion", () => {
  test("the same palette does animate, so the check above can fail", async ({ page }) => {
    const sample = await motionWhileOpening(page);
    expect(sample.running.length).toBeGreaterThan(0);
  });
});
