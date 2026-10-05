/** Shared synthetic control API for browser tests: explicit HTTP responses, never captured data. */
import type { Page, Request } from "@playwright/test";
import type { CausalityPlan, SearchPlan } from "../src/search.ts";
import {
  agentRunFixture,
  artifactFixture,
  auditHealthFixture,
  calibrationReportFixture,
  causalityFixture,
  eventsFixture,
  evidenceFixture,
  modelCallFixture,
  modelCallListFixture,
  summaryFixture,
  TOKEN,
} from "./fixtures";
import { isStreamPlan, pagedSearchFixture, streamFixture } from "./investigation-fixtures";
import { bindingFixture, grantFixture } from "./ledger-fixtures";

export type Reply = { status?: number; body: unknown };
export type Override = (
  url: URL,
  request: Request,
) => Reply | undefined | Promise<Reply | undefined>;
export type Call = {
  path: string;
  method: string;
  authorized: boolean;
  cookie: string | null;
  body: unknown;
};

const abandonedCalls = new WeakMap<Call[], Call[]>();

/**
 * Requests the page sent and then abandoned (aborted) before an answer arrived, for example the
 * read of a plan that was superseded while it was in flight. They are kept apart from `calls`, so
 * a test can still prove that a superseded request went out and was dropped rather than answered.
 */
export function abandoned(calls: Call[]): Call[] {
  return abandonedCalls.get(calls) ?? [];
}

/** Browser checks exercise the real client with explicit synthetic HTTP responses. */
export async function mockControl(page: Page, override?: Override): Promise<Call[]> {
  const calls: Call[] = [];
  const dropped: Call[] = [];
  abandonedCalls.set(calls, dropped);
  const records = new Map<Request, { call: Call; graced: boolean }>();
  const forget = (call: Call) => {
    const index = calls.indexOf(call);
    if (index >= 0) calls.splice(index, 1);
    return index >= 0;
  };
  // The development build mounts every component twice (React StrictMode), and TanStack Query
  // cancels the first read of a query when its observer unmounts; the production build never
  // sends that duplicate. A call is recorded as soon as it arrives, but one the page aborts within
  // the short grace period below is that duplicate: it is forgotten and never reaches the
  // override. A call aborted later was sent and then abandoned, and moves to `abandoned(calls)`.
  page.on("requestfailed", (request) => {
    const entry = records.get(request);
    if (!entry || request.failure()?.errorText !== "net::ERR_ABORTED") return;
    if (forget(entry.call) && entry.graced) dropped.push(entry.call);
  });
  await page.route("**/control/v1/**", async (route) => {
    try {
      const request = route.request();
      const url = new URL(request.url());
      const record: Call = {
        path: `${url.pathname}${url.search}`,
        method: request.method(),
        authorized: (await request.headerValue("authorization")) === `Bearer ${TOKEN}`,
        cookie: await request.headerValue("cookie"),
        body: request.postDataJSON(),
      };
      const entry = { call: record, graced: false };
      calls.push(record);
      records.set(request, entry);
      // Let an abort that is already on its way (the StrictMode remount above) land first.
      await new Promise((resolve) => setTimeout(resolve, 25));
      if (request.failure()) {
        forget(record);
        return;
      }
      entry.graced = true;
      const custom = await override?.(url, request);
      let reply: Reply;
      if (custom) reply = custom;
      else if (url.pathname === "/control/v1/search") {
        const { cursor, ...plan } = request.postDataJSON();
        reply = {
          body: isStreamPlan(plan as SearchPlan)
            ? await streamFixture(plan as SearchPlan, cursor)
            : await pagedSearchFixture(plan as SearchPlan, cursor),
        };
      } else if (url.pathname === "/control/v1/causality") {
        reply = { body: await causalityFixture(request.postDataJSON() as CausalityPlan) };
      } else if (url.pathname.startsWith("/control/v1/grants/")) {
        reply = { body: grantFixture(url.pathname.split("/").at(-1)) };
      } else if (url.pathname.startsWith("/control/v1/auth-bindings/")) {
        reply = { body: bindingFixture(url.pathname.split("/").at(-1)) };
      } else if (url.pathname === "/control/v1/model-calls") {
        reply = { body: modelCallListFixture(url.searchParams.has("cursor")) };
      } else if (url.pathname === "/control/v1/audit/health") {
        reply = { body: auditHealthFixture() };
      } else if (url.pathname.startsWith("/control/v1/calibration-reports/")) {
        reply = { body: calibrationReportFixture(url.pathname.split("/").at(-1)) };
      } else if (url.pathname.startsWith("/control/v1/agent-runs/")) {
        reply = { body: agentRunFixture(url.pathname.split("/").at(-1)) };
      } else if (url.pathname.startsWith("/control/v1/model-calls/")) {
        reply = { body: modelCallFixture(url.pathname.split("/").at(-1)) };
      } else if (url.pathname.startsWith("/control/v1/artifacts/")) {
        reply = { body: artifactFixture(url.pathname.split("/").at(-1)) };
      } else {
        const id = url.pathname.split("/")[4];
        if (url.pathname.endsWith("/events")) {
          reply = { body: eventsFixture(id, url.searchParams.has("cursor")) };
        } else if (url.pathname.endsWith("/evidence")) {
          reply = { body: evidenceFixture(id, url.searchParams.has("cursor")) };
        } else reply = { body: summaryFixture(id) };
      }
      await route
        .fulfill({
          status: reply.status ?? 200,
          json: reply.body,
          headers: { "cache-control": "private, no-store" },
        })
        .catch(() => undefined);
    } catch {
      // The test (or the page) ended while this answer was being prepared.
    }
  });
  return calls;
}

/** Resolves when a request for `path` has finished or failed, whatever the page did with it. */
export function requestSettled(page: Page, path: string) {
  return new Promise<void>((resolve) => {
    const finish = (request: Request) => {
      if (new URL(request.url()).pathname !== path) return;
      page.off("requestfinished", finish);
      page.off("requestfailed", finish);
      resolve();
    };
    page.on("requestfinished", finish);
    page.on("requestfailed", finish);
  });
}

/** Two animation frames: a render the page was going to do has happened. */
export async function paint(page: Page) {
  await page.evaluate(
    () =>
      new Promise<void>((resolve) =>
        requestAnimationFrame(() => requestAnimationFrame(() => resolve())),
      ),
  );
}
