// Layout regression for the console's tables (docs/06 6.8). At each width, nothing in a table cell runs
// past that cell onto its neighbour. A text cell may cut a value that does not fit, with an ellipsis,
// when the cell or the cut element carries the whole value in a title. Numbers, times, tags, identifiers
// and cells marked .keep are never cut, and .wrap cells break onto more lines instead.
//
// The check is geometric (boxes and text runs against cell edges), not a pixel diff: glyph widths differ
// between machines, but an overlap is an overlap in every font.

import { expect, type Page, test } from "@playwright/test";
import { mockApi } from "./helpers/mock-api.ts";
import { freezeClock } from "./helpers/sites-flow.ts";

const WIDTHS = [1024, 1280, 1920];

const PAGES: [string, string][] = [
  ["site list", "/sites"],
  ["request list, 24 hours", "/requests"],
  ["request list, 7 days", "/requests?range=7d"],
  ["Jev calls", "/jev"],
  ["sessions", "/sessions"],
  ["gateway table", "/system?tab=edges"],
  ["storage table", "/system?tab=storage"],
  ["parameter table", "/system?tab=params"],
  ["overview", "/"],
];

/** Runs in the page: one line for each cell whose content spills out of it or is cut where it must not be. */
function layoutProblems(): string[] {
  const problems = new Set<string>();

  // The nearest element from `start` up to the cell (the cell included) that clips its overflow.
  const clipper = (start: Element | null, cell: Element): Element | null => {
    for (let el = start; el !== null && el !== cell; el = el.parentElement) {
      if (getComputedStyle(el).overflowX !== "visible") return el;
    }
    return getComputedStyle(cell).overflowX !== "visible" ? cell : null;
  };

  for (const table of Array.from(document.querySelectorAll("table"))) {
    if (table.getClientRects().length === 0) continue;
    const name = table.getAttribute("aria-label") ?? `table.${table.className}`;

    for (const cell of Array.from(table.querySelectorAll("td, th"))) {
      const box = cell.getBoundingClientRect();
      if (box.width === 0) continue;
      const text = (cell.textContent ?? "").trim().replace(/\s+/g, " ").slice(0, 40);
      const where = `${name}: "${text}"`;
      const mustShowWhole = cell.matches(".num, .tnum, .keep, .wrap");
      const hasTitle = cell.hasAttribute("title") || cell.querySelector("[title]") !== null;

      // `start` is the element that holds the content; its clipping ancestors decide whether it is cut.
      const check = (start: Element, rects: DOMRect[]) => {
        const left = Math.min(...rects.map((r) => r.left));
        const right = Math.max(...rects.map((r) => r.right));
        const clip = clipper(start, cell);
        if (clip === null) {
          if (left < box.left - 0.5 || right > box.right + 0.5) {
            problems.add(`${where} runs past its cell`);
          }
          return;
        }
        const clipBox = clip.getBoundingClientRect();
        if (left >= clipBox.left - 0.5 && right <= clipBox.right + 0.5) return;
        if (mustShowWhole) {
          problems.add(`${where} is cut, but its cell must show it whole`);
        } else if (!hasTitle && clip.closest("[title]") === null) {
          problems.add(`${where} is cut without a title`);
        }
      };

      const walker = document.createTreeWalker(cell, NodeFilter.SHOW_TEXT);
      for (let node = walker.nextNode(); node !== null; node = walker.nextNode()) {
        const parent = node.parentElement;
        if (parent === null || (node.textContent ?? "").trim() === "") continue;
        if (parent.closest(".sr-only") !== null) continue;
        const range = document.createRange();
        range.selectNodeContents(node);
        const rects = Array.from(range.getClientRects()).filter((r) => r.width > 0);
        if (rects.length > 0) check(parent, rects);
      }

      for (const el of Array.from(cell.querySelectorAll("*"))) {
        if (el.parentElement === null || el.closest(".sr-only") !== null) continue;
        const rect = el.getBoundingClientRect();
        if (rect.width > 0) check(el.parentElement, [rect]);
      }
    }
  }
  return [...problems];
}

async function expectWithinCells(page: Page, route: string) {
  for (const width of WIDTHS) {
    await page.setViewportSize({ width, height: 900 });
    await page.goto(route);
    await page.locator("table.tbl tbody tr").first().waitFor();
    const problems = await page.evaluate(layoutProblems);
    expect(problems, `${route} at ${width}px`).toEqual([]);
  }
}

test.describe("table cells stay within their columns", () => {
  test.beforeEach(async ({ page }) => {
    await freezeClock(page);
    await mockApi(page);
  });

  for (const [name, route] of PAGES) {
    test(`${name}, at ${WIDTHS.join(", ")} px`, async ({ page }) => {
      await expectWithinCells(page, route);
    });
  }

  test("request list beside the open preview, at 1024, 1280 and 1920 px", async ({ page }) => {
    await page.goto("/requests?range=7d");
    const row = page.locator('table[aria-label="请求列表"] tbody tr').first();
    await row.waitFor();
    const id = ((await row.getAttribute("id")) ?? "").replace(/^row-/, "");
    expect(id).not.toBe("");
    await expectWithinCells(page, `/requests?range=7d&peek=${id}`);
  });
});
