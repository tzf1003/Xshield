// Helpers of the traceability specs (login, palette, requests, detail, Jev, sessions, system, batch).
// They build on the shared mock (mock-api.ts) and leave it as it is.

import { expect, type Page } from "@playwright/test";
import type { TimelineRow } from "../../src/api/types.ts";
import { requestDetails, sessionTimeline } from "./fixtures.ts";
import { FIXTURE_NOW_MS, type MockOptions, mockApi } from "./mock-api.ts";

/** The fixed rows the specs open. Each one is described where the fixtures define it. */
export const IDS = {
  /** juice, GET /rest/basket/6: a would-block row whose Jev answer is DENY (request-detail fixture). */
  basket: "req_01a1973940107ebea1af2c54ce635f38",
  /** juice, GET /rest/basket/1: the request whose response first showed the value 6 (quantity). */
  basketSource: "req_01a1973698607cce885df41a7ec7609b",
  /** juice, POST /rest/user/login: the login that issued session 7c1e9a40d2b35f61. */
  login: "req_01a1971a07e079639a823d4257b43172",
  /** emr, POST /api/patients/search: blocked, Jev answers ATTACK (request-detail fixture). */
  search: "req_01a1973ed5c0732b8f29804d7fc746d3",
  /** The first judged row of the default list (newest first, 13:19:30 UTC). */
  newest: "req_01a19743ded079f89fa9c4b66aa44e9b",
  /** The request whose Jev call timed out (requests fixture). */
  timeout: "req_01a1973d010077e79b7c256f6f5567bb",
  /** The request whose Jev call the per-minute call limit refused (requests fixture). */
  callLimit: "req_01a1971b96507a2286dd038331d7fc77",
};

/** The session of juice whose timeline is in session-timeline.json (16 requests). */
export const SESSION = "7c1e9a40d2b35f61";

/** A request ID whose time is `ms` (Unix milliseconds), as the gateway builds them (docs/07 7.3.1). */
export function requestIdAt(ms: number): string {
  return `req_${ms.toString(16).padStart(12, "0")}${"0".repeat(20)}`;
}

/**
 * The clock and the fixtures: the frozen time the rows are written around, and the shared mock.
 * Call it before the first navigation.
 */
export async function useFixtures(page: Page, options: MockOptions = {}): Promise<void> {
  await page.clock.setFixedTime(FIXTURE_NOW_MS);
  await mockApi(page, options);
}

/**
 * Waits until the named dialog has finished opening. A dialog fades in from opacity 0, and axe reads the
 * colours on screen, so a check made while the dialog is still fading in reads the wrong background.
 */
export async function untilDialogOpen(page: Page, name: string): Promise<void> {
  await expect(page.getByRole("dialog", { name })).toHaveCSS("opacity", "1");
}

/** Whether a timeline row is inside a `only=` choice of the timeline (docs/07 7.9.6). */
function matchesOnly(row: TimelineRow, only: string): boolean {
  if (only === "jev") return row.jev !== null;
  if (only === "blocks") return row.outcome === "blocked" || row.outcome === "would_block";
  return row.outcome !== "unjudged";
}

/**
 * Answers the timeline of SESSION the way the server does with `only=` (docs/07 7.9.6). The shared
 * mock answers every choice with the same rows, so the filter would not narrow anything there.
 * Registered after useFixtures, so it answers first.
 */
export async function serveTimelineOnly(page: Page): Promise<void> {
  await page.route(
    (url) => url.pathname === `/api/sessions/${SESSION}`,
    async (route) => {
      const only = new URL(route.request().url()).searchParams.get("only") ?? "judged";
      const body = {
        ...sessionTimeline,
        rows: sessionTimeline.rows.filter((row) => matchesOnly(row, only)),
        next_cursor: null,
      };
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(body),
      });
    },
  );
}

/**
 * Answers the first call to `path` with `status`, and every later call with the shared mock. Used to
 * show what the page does when the server refuses once, such as a 401 in the middle of a visit.
 */
export async function failOnce(
  page: Page,
  path: string,
  status: number,
  error: string,
): Promise<void> {
  let answered = false;
  await page.route(
    (url) => url.pathname === path,
    async (route) => {
      if (answered) {
        await route.fallback();
        return;
      }
      answered = true;
      await route.fulfill({
        status,
        contentType: "application/json",
        body: JSON.stringify({ error }),
      });
    },
  );
}

/**
 * Answers the timeline of SESSION with its login as the first row, the shape the gateway now returns
 * (docs/06 6.4.7): the request that issued the session is marked as having issued it. The login is taken
 * from its request-detail fixture, so the row carries the same fields as the list.
 */
export async function serveTimelineWithLogin(page: Page): Promise<void> {
  const login = requestDetails.find((detail) => detail.summary.request_id === IDS.login)?.summary;
  if (login === undefined) throw new Error("the login fixture is missing");
  const loginRow: TimelineRow = {
    ...login,
    learned: 6,
    entry_passed: false,
    issued_session: SESSION,
    after_would_block: false,
  };
  await page.route(
    (url) => url.pathname === `/api/sessions/${SESSION}`,
    async (route) => {
      const body = {
        ...sessionTimeline,
        rows: [loginRow, ...sessionTimeline.rows],
        next_cursor: null,
      };
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(body),
      });
    },
  );
}
