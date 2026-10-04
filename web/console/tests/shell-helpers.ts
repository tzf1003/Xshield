import type { Page } from "@playwright/test";
import {
  errorFixture,
  eventsFixture,
  evidenceFixture,
  REQUEST_ID,
  summaryFixture,
  TOKEN,
} from "./fixtures";
import { workbenchOverviewFixture } from "./overview-fixtures";

export const SCOPE = { tenant_id: "tenant_demo", site_id: "site_demo" };
export const TRACE_ID = "018f2a3b4c5d70008000000000000003";
export const CASE_ID = "case_018f2a3b-4c5d-7000-8000-000000000031";

export type Reply = { status?: number; body: unknown };

/** Synthetic control API for shell tests: overview, sites, one request and a few empties. */
export async function mockShellApi(
  page: Page,
  override?: (url: URL, method: string) => Reply | undefined,
) {
  const calls: { path: string; method: string }[] = [];
  await page.route("**/control/v1/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    calls.push({ path: url.pathname + url.search, method: request.method() });
    const custom = override?.(url, request.method());
    let reply: Reply;
    if (custom) reply = custom;
    else if (url.pathname === "/control/v1/workbench/overview") {
      reply = { body: workbenchOverviewFixture() };
    } else if (url.pathname === "/control/v1/sites") {
      reply = {
        body: { request_id: REQUEST_ID, ...SCOPE, truncated: false, next_cursor: null, sites: [] },
      };
    } else if (url.pathname.endsWith("/events")) {
      reply = { body: eventsFixture(url.pathname.split("/")[4]) };
    } else if (url.pathname.endsWith("/evidence")) {
      reply = { body: evidenceFixture(url.pathname.split("/")[4]) };
    } else if (url.pathname.startsWith("/control/v1/requests/")) {
      reply = { body: summaryFixture(url.pathname.split("/")[4]) };
    } else reply = { status: 403, body: errorFixture("CONTROL_SCOPE_DENIED") };
    await route.fulfill({
      status: reply.status ?? 200,
      json: reply.body,
      headers: { "cache-control": "private, no-store" },
    });
  });
  return calls;
}

/** Machine-login sign-in (the Playwright-only Bearer form); deep links keep their URL. */
export async function signIn(page: Page, path = "/") {
  await page.goto(path);
  await page.getByLabel("管理凭证", { exact: true }).fill(TOKEN);
  await page.getByRole("button", { name: "连接", exact: true }).click();
}

/** Shape of the test-only seam exposed by the machine-login build (window.__xshieldE2E). */
export type E2ESeam = {
  runtime: {
    store: {
      getState(): { status: string; epoch: number; notice: string | null };
      disconnect(notice?: string | null): void;
    };
    queryClient: { getQueryCache(): { getAll(): unknown[] } };
    pending: {
      unresolvedCount: number;
      getSnapshot(): readonly { id: string; phase: string; attempts: number }[];
      freeze(input: {
        label: string;
        method: string;
        path: string;
        body?: unknown;
        idempotencyKey?: string;
        execute: (client: unknown, signal: AbortSignal, key: string) => Promise<unknown>;
      }): { id: string; idempotencyKey: string };
    };
  };
  runFrozenWrite(store: unknown, pending: unknown, id: string): Promise<{ kind: string }>;
};

declare global {
  interface Window {
    __xshieldE2E: E2ESeam;
  }
}

export const seamState = (page: Page) =>
  page.evaluate(() => {
    const { runtime } = window.__xshieldE2E;
    return {
      status: runtime.store.getState().status,
      notice: runtime.store.getState().notice,
      queries: runtime.queryClient.getQueryCache().getAll().length,
      pending: runtime.pending.unresolvedCount,
    };
  });

export const storageSnapshot = (page: Page) =>
  page.evaluate(() => ({ local: { ...localStorage }, session: { ...sessionStorage } }));

/** Server session for OIDC-mode tests (cookie session, roles from the server). */
export function sessionBody(roles: string[], overrides: Record<string, unknown> = {}) {
  return {
    subject: "test-subject",
    ...SCOPE,
    roles,
    csrf_token: "a".repeat(64),
    session_expires_at: "2027-01-01T08:00:00.000Z",
    idle_expires_at: "2027-01-01T00:15:00.000Z",
    last_reauthenticated_at: null,
    step_up_valid: false,
    ...overrides,
  };
}
