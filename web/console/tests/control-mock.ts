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
  searchFixture,
  summaryFixture,
  TOKEN,
} from "./fixtures";
import { isStreamPlan, streamFixture } from "./investigation-fixtures";
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

/** Browser checks exercise the real client with explicit synthetic HTTP responses. */
export async function mockControl(page: Page, override?: Override): Promise<Call[]> {
  const calls: Call[] = [];
  await page.route("**/control/v1/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    calls.push({
      path: `${url.pathname}${url.search}`,
      method: request.method(),
      authorized: (await request.headerValue("authorization")) === `Bearer ${TOKEN}`,
      cookie: await request.headerValue("cookie"),
      body: request.postDataJSON(),
    });
    const custom = await override?.(url, request);
    let reply: Reply;
    if (custom) reply = custom;
    else if (url.pathname === "/control/v1/search") {
      const { cursor, ...plan } = request.postDataJSON();
      reply = {
        body: isStreamPlan(plan as SearchPlan)
          ? await streamFixture(plan as SearchPlan, cursor)
          : await searchFixture(plan, Boolean(cursor)),
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
    await route.fulfill({
      status: reply.status ?? 200,
      json: reply.body,
      headers: { "cache-control": "private, no-store" },
    });
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
