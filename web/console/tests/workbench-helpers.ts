import { expect, type Page, type Request } from "@playwright/test";
import { type SearchPlan, searchPlanDigest, validateSearchPlan } from "../src/search.ts";
import { accessListFixture } from "./access-fixtures";
import { exportListFixture } from "./export-fixtures";
import { auditHealthFixture, errorFixture, REQUEST_ID } from "./fixtures";
import { type OverviewOptions, workbenchOverviewFixture } from "./overview-fixtures";
import { SCOPE, sessionBody } from "./shell-helpers";
import { adminJobListFixture, JOB_ID, jobBody, jobListFixture } from "./work-helpers";

export type Reply = { status?: number; body?: unknown };
export type Call = {
  path: string;
  method: string;
  body: unknown;
  /** `Idempotency-Key` and `X-Xshield-CSRF` request headers, when sent. */
  key: string | null;
  csrf: string | null;
};
export type Override = (
  url: URL,
  request: Request,
) => Reply | undefined | Promise<Reply | undefined>;

export const KEY_ID = "key_018f2a3b-4c5d-7000-8000-000000000051";
export const NEW_KEY_ID = "key_018f2a3b-4c5d-7000-8000-000000000052";
export const SECRET = `xsk_5e1c7a0b${"9f".repeat(20)}`;
export { JOB_ID };

/** Key metadata as `GET /agent-api-keys` returns it: no scope, fingerprint or plaintext. */
export function keyRecord(overrides: Record<string, unknown> = {}) {
  return {
    api_key_id: KEY_ID,
    tenant_id: SCOPE.tenant_id,
    subject: "agent-deploy",
    display_name: "部署机器人",
    key_prefix: "xsk_a1b2c3d4",
    status: "active",
    expires_at: "2027-01-01T00:00:00+00:00",
    created_at: "2026-09-20T08:00:00+00:00",
    last_used_at: "2026-09-20T08:05:00+00:00",
    ...overrides,
  };
}

export function keyList(keys: unknown[] = [keyRecord()]) {
  return { request_id: REQUEST_ID, keys };
}

/** The issuing reply: the server echoes the request's scope rows and returns the plaintext once. */
export function issuedKey(
  request: { expires_at: string; scopes: unknown[] },
  apiKeyId = NEW_KEY_ID,
) {
  return {
    request_id: REQUEST_ID,
    api_key_id: apiKeyId,
    api_key: SECRET,
    key_prefix: SECRET.slice(0, 12),
    expires_at: request.expires_at,
    scopes: request.scopes,
  };
}

export const DENIED_REQUEST = "req_018f2a3b-4c5d-7000-8000-0000000000d1";
export const OTHER_DENIED_REQUEST = "req_018f2a3b-4c5d-7000-8000-0000000000d2";

/** The site list behind the snapshot: Beta waits for approval, Gamma failed to apply. */
export function workbenchSites(): Record<string, unknown> {
  const site = (
    id: string,
    name: string,
    applyState: string,
    status: string,
    requiresApproval: boolean,
    reason: string,
    active: number | null,
  ) => ({
    site_id: id,
    display_name: name,
    public_origin: `https://${id.replace(/_/g, "-")}.example`,
    listen_port: 6100,
    security_entry: "ui_action_required",
    sensor_enabled: false,
    policy_revision: "policy-v1",
    status,
    revision: 3,
    config_digest: "a".repeat(64),
    updated_by: "synthetic-author",
    updated_at: "2026-09-20T08:00:00.000Z",
    desired_revision: 3,
    active_revision: active,
    apply_id: "apply_fixture",
    apply_state: applyState,
    reason_code: reason,
    requires_approval: requiresApproval,
  });
  return {
    request_id: REQUEST_ID,
    ...SCOPE,
    truncated: false,
    next_cursor: null,
    sites: [
      site("site_alpha", "Alpha 官网", "active", "active", false, "CONTROL_SITE_APPLY_ACTIVE", 4),
      site(
        "site_beta",
        "Beta 商城",
        "pending",
        "active",
        true,
        "CONTROL_SITE_APPROVAL_REQUIRED",
        2,
      ),
      site("site_gamma", "Gamma 支付", "failed", "active", false, "EDGE_APPLY_REJECTED", 7),
    ],
  };
}

/** One explicit health read of a site; the envelope answers for that site. */
export function siteHealthFixture(siteId: string, upstream = "healthy") {
  return {
    request_id: REQUEST_ID,
    tenant_id: SCOPE.tenant_id,
    site_id: siteId,
    listen_port: 6100,
    desired_revision: 4,
    active_revision: 4,
    config_digest: "b".repeat(64),
    apply_state: "active",
    apply_id: "apply_fixture",
    reason_code: "CONTROL_SITE_HEALTH_OBSERVED",
    requires_approval: false,
    edge_health: { edge_state: "healthy", upstream_state: upstream, audit_state: "healthy" },
  };
}

/** Denied terminal request events inside the plan's own window, newest first. */
export async function deniedSearchFixture(plan: SearchPlan, events = 2) {
  const end = Date.parse(plan.end);
  const stamp = (ms: number, micros: string) =>
    `${new Date(ms).toISOString().slice(0, 19)}.${micros}Z`;
  const rows = [
    { request: DENIED_REQUEST, ms: end - 5 * 60_000, reason: "UI_ACTION_PROVENANCE_MISSING" },
    { request: OTHER_DENIED_REQUEST, ms: end - 2 * 3_600_000, reason: "AUTH_BINDING_MISMATCH" },
  ].slice(0, events);
  return {
    request_id: REQUEST_ID,
    ...SCOPE,
    schema_version: 3,
    query_digest: (await searchPlanDigest(plan)) ?? "0".repeat(64),
    as_of: plan.end,
    index_watermark: {
      producer_boot_id: "018f2a3b-4c5d-7000-8000-000000000088",
      producer_sequence: 42,
    },
    has_gaps: false,
    pending_segments: 0,
    scanned_rows: 1280,
    scanned_bytes: null,
    truncated: false,
    next_cursor: null,
    events: rows.map((row, index) => ({
      request_id: row.request,
      event_id: `ev_018f2a3b-4c5d-7000-8000-0000000000e${index + 1}`,
      trace_id: "018f2a3b4c5d70008000000000000003",
      event_type: "request.completed",
      stage: "admission",
      outcome: "DENY",
      reason_code: row.reason,
      proof_kind: "deterministic",
      confidence: null,
      confidence_status: "not_applicable",
      occurred_at: stamp(row.ms, "123456"),
      request_seq: 3,
      duration_us: 24,
      policy_revision: "policy-demo-r3",
      model_revision: null,
      model_call_id: null,
      evidence_refs: [],
      cause_event_ids: [],
      sensitivity: "INTERNAL",
    })),
  };
}

export type WorkbenchMock = {
  /** Snapshot options (partial projection, no audit). */
  overview?: OverviewOptions;
  /** Server roles for cookie-session tests; omit for the machine-login build. */
  roles?: string[];
  override?: Override;
};

/**
 * The control API behind the workbench and the operations pages. Unknown paths answer 403
 * CONTROL_SCOPE_DENIED, so a page that reads something unexpected shows it as a refusal.
 */
export async function mockWorkbench(page: Page, mock: WorkbenchMock = {}) {
  const calls: Call[] = [];
  await page.route("**/control/v1/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const path = `${url.pathname}${url.search}`;
    let body: unknown = null;
    try {
      body = request.postDataJSON();
    } catch {
      body = request.postData();
    }
    calls.push({
      path,
      method: request.method(),
      body,
      key: await request.headerValue("idempotency-key"),
      csrf: await request.headerValue("x-xshield-csrf"),
    });
    const custom = await mock.override?.(url, request);
    let reply: Reply;
    if (custom) reply = custom;
    else if (url.pathname === "/control/v1/session" && mock.roles) {
      reply = { body: sessionBody(mock.roles) };
    } else if (url.pathname === "/control/v1/workbench/overview") {
      reply = { body: workbenchOverviewFixture(mock.overview) };
    } else if (url.pathname === "/control/v1/sites" && request.method() === "GET") {
      reply = { body: workbenchSites() };
    } else if (path === "/control/v1/evidence-access-requests?view=review") {
      reply = { body: accessListFixture("review") };
    } else if (path === "/control/v1/exports?view=review") {
      reply = { body: exportListFixture("review") };
    } else if (/^\/control\/v1\/sites\/[^/]+\/health$/.test(url.pathname)) {
      reply = { body: siteHealthFixture(url.pathname.split("/")[4] ?? "") };
    } else if (url.pathname === "/control/v1/search") {
      reply = { body: await deniedSearchFixture(validateSearchPlan(request.postDataJSON())) };
    } else if (path === "/control/v1/audit/health") {
      reply = { body: auditHealthFixture() };
    } else if (path === "/control/v1/jobs") {
      reply = { body: jobListFixture() };
    } else if (path === "/control/v1/admin/jobs") {
      reply = { body: adminJobListFixture() };
    } else if (/^\/control\/v1\/jobs\/job_[0-9a-f-]+$/.test(url.pathname)) {
      reply = { body: jobBody(undefined, url.pathname.split("/").at(-1)) };
    } else if (path === "/control/v1/agent-api-keys" && request.method() === "GET") {
      reply = { body: keyList() };
    } else if (path === "/control/v1/agent-api-keys" && request.method() === "POST") {
      reply = { status: 201, body: issuedKey(request.postDataJSON()) };
    } else if (/^\/control\/v1\/agent-api-keys\/key_[0-9a-f-]+\/rotate$/.test(path)) {
      reply = { status: 201, body: issuedKey(request.postDataJSON()) };
    } else if (/^\/control\/v1\/agent-api-keys\/key_[0-9a-f-]+\/revoke$/.test(path)) {
      reply = {
        body: { request_id: REQUEST_ID, api_key_id: url.pathname.split("/")[4], status: "revoked" },
      };
    } else {
      reply = { status: 403, body: errorFixture("CONTROL_SCOPE_DENIED") };
    }
    if (reply.status === 204) {
      await route.fulfill({ status: 204 });
      return;
    }
    await route.fulfill({
      status: reply.status ?? 200,
      json: reply.body,
      headers: { "cache-control": "private, no-store" },
    });
  });
  return calls;
}

/**
 * The distinct GET paths read so far, sorted. React's development StrictMode mounts a page twice,
 * which can repeat a read in the dev build the tests run against; "nothing more is read" is
 * checked on the total count instead (see `settledReads`).
 */
export const reads = (calls: readonly Call[]) =>
  [...new Set(calls.filter((call) => call.method === "GET").map((call) => call.path))].sort();

/** Waits until exactly `expected` was read, then checks that nothing else follows by itself. */
export async function settledReads(
  page: Page,
  calls: readonly Call[],
  expected: readonly string[],
  quietMs = 400,
) {
  await expect.poll(() => reads(calls)).toEqual([...expected].sort());
  const count = calls.length;
  await page.waitForTimeout(quietMs);
  expect(reads(calls)).toEqual([...expected].sort());
  expect(calls).toHaveLength(count);
}
