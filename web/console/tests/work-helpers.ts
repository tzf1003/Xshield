/**
 * A synthetic control API for the case center and the approval center. Every route answers with
 * the shared contract fixtures; a test overrides single replies (an error, a delay, a dropped
 * connection) and reads back the exact requests the page sent.
 */
import { expect, type Page, type Request, type Route } from "@playwright/test";
import {
  ACCESS_ID,
  accessDecisionFixture,
  accessInspectionFixture,
  accessListFixture,
  accessRequestedFixture,
} from "./access-fixtures";
import {
  CASE_ID,
  caseClosedFixture,
  caseCollectionFixture,
  caseCreatedFixture,
  caseItemAddedFixture,
  caseItemFixture,
  caseListFixture,
  OTHER_CASE_ID,
} from "./case-fixtures";
import { EXPORT_ID, exportFixture, exportListFixture } from "./export-fixtures";
import { ARTIFACT_ID, artifactFixture, errorFixture, OTHER_ARTIFACT_ID, TOKEN } from "./fixtures";
import {
  HOLD_ID,
  holdCollectionFixture,
  holdMutationFixture,
  holdRecordFixture,
} from "./hold-fixtures";
import { sessionBody } from "./shell-helpers";

export const JOB_ID = "job_018f2a3b-4c5d-7000-8000-000000000041";
export const ENVELOPE = {
  request_id: "req_018f2a3b-4c5d-7000-8000-000000000099",
  tenant_id: "tenant_demo",
  site_id: "site_demo",
};

export type Reply = {
  status?: number;
  body?: unknown;
  headers?: Record<string, string>;
  /** Raw bytes instead of JSON (binary downloads). */
  raw?: Buffer;
  /** Drop the connection instead of answering. */
  abort?: string;
};
export type Call = {
  path: string;
  method: string;
  key: string | null;
  body: unknown;
  csrf: string | null;
  /** Machine mode: the synthetic Bearer was sent, and no cookie. */
  authorized: boolean;
};
export type Override = (
  url: URL,
  request: Request,
  call: Call,
  count: number,
) => Reply | undefined | Promise<Reply | undefined>;

export type Mode = {
  /** `session` is the OIDC cookie build; `machine` the Bearer test build. */
  kind: "machine" | "session";
  roles?: string[];
  /** Session fields (subject, step-up facts); may be changed while the test runs. */
  session?: Record<string, unknown>;
  /** Roles the server reports once `control.switched` is set. */
  origin?: string;
};

export function jobBody(caseId = CASE_ID, jobId = JOB_ID) {
  return {
    ...ENVELOPE,
    found: true,
    job: {
      job_id: jobId,
      kind: "case_analysis",
      status: "succeeded",
      checkpoint: "inventory_committed",
      reason_code: "CONTROL_CASE_ANALYSIS_COMPLETE",
      retryable: false,
      case_id: caseId,
      artifact_count: 3,
      active_artifact_count: 2,
      created_at: "2026-09-20T08:00:00.000Z",
      updated_at: "2026-09-20T08:00:00.123Z",
      completed_at: "2026-09-20T08:00:00.123Z",
      replayed: false,
    },
  };
}

/** The caller's own jobs: the lookup job and one older running job, newest identity first. */
export function jobListFixture() {
  // A list row carries no replay flag: that belongs to the write response only.
  const { replayed: _replayed, ...newer } = jobBody().job;
  return {
    ...ENVELOPE,
    schema_version: 1,
    as_of: "2026-09-20T08:01:00.123456Z",
    items: [
      newer,
      {
        ...newer,
        job_id: "job_018f2a3b-4c5d-7000-8000-000000000001",
        status: "running",
        checkpoint: "inventory_pending",
        reason_code: "CONTROL_CASE_ANALYSIS_RUNNING",
        completed_at: null,
      },
    ],
    truncated: false,
    next_cursor: null,
  };
}

/** Every job in the scope, with each submitter's reference, for the audit administrator. */
export function adminJobListFixture() {
  const mine = jobListFixture();
  return {
    ...mine,
    items: mine.items.map((item, index) => ({
      ...item,
      owner_ref: index === 0 ? "investigator-alpha" : "investigator-beta",
    })),
  };
}

/** One saved search owned by the caller, for the search page's saved-views panel. */
export function savedViewListFixture() {
  return {
    ...ENVELOPE,
    schema_version: 1,
    as_of: "2026-09-20T08:01:00.123456Z",
    items: [
      {
        view_id: "view_018f2a3b-4c5d-7000-8000-000000000001",
        name: "Weekly review",
        search: {
          schema_version: 3,
          start: "2026-09-20T00:00:00Z",
          end: "2026-09-21T00:00:00Z",
          filters: [],
          sort: "occurred_at_desc",
          limit: 25,
        },
        created_at: "2026-09-20T08:00:00.000Z",
      },
    ],
    truncated: false,
    next_cursor: null,
  };
}

/** Two cases on one page: an open one and a closed one, newest first. */
export function casesPage() {
  const base = caseListFixture();
  const open = { ...base.items[0], case_id: OTHER_CASE_ID, purpose: "核对合成请求的证据引用" };
  const closed = {
    case_id: CASE_ID,
    status: "closed" as const,
    purpose: "已完成的合成调查",
    created_at: "2026-09-19T08:00:00.000Z",
  };
  return {
    ...base,
    items: [open, closed].map((item) => ({ ...item })),
    truncated: false,
    next_cursor: null,
  };
}

/** The member list of the case detail: one active and one expired reference. */
export function collection(caseId = CASE_ID) {
  const body = caseCollectionFixture(caseId);
  body.items = [
    caseItemFixture("active", ARTIFACT_ID),
    caseItemFixture("expired", OTHER_ARTIFACT_ID),
  ];
  return body;
}

/** A site list with one revision awaiting a policy decision and one that is not. */
export function sitesPage() {
  const site = (id: string, name: string, requiresApproval: boolean) => ({
    site_id: id,
    display_name: name,
    public_origin: "https://example.test",
    listen_port: 6100,
    security_entry: "public",
    sensor_enabled: false,
    policy_revision: "policy-v1",
    status: "active",
    revision: 3,
    config_digest: "a".repeat(64),
    updated_by: "synthetic-author",
    updated_at: "2026-09-20T09:00:00.000Z",
    desired_revision: 3,
    active_revision: 2,
    apply_id: "apply_fixture",
    apply_state: requiresApproval ? "pending" : "active",
    reason_code: requiresApproval ? "CONTROL_SITE_APPROVAL_REQUIRED" : "EDGE_APPLY_CONFIRMED",
    requires_approval: requiresApproval,
  });
  return {
    ...ENVELOPE,
    truncated: false,
    next_cursor: null,
    sites: [site("site_alpha", "Alpha 站点", true), site("site_beta", "Beta 站点", false)],
  };
}

/** A hold history for one case; every record belongs to that case, as the contract requires. */
export function holds(caseId: string, items = holdCollectionFixture().items) {
  const base = holdCollectionFixture();
  return { ...base, case_id: caseId, items: items.map((item) => ({ ...item, case_id: caseId })) };
}

function defaults(url: URL, method: string, body: Record<string, unknown> | null): Reply {
  const path = url.pathname;
  if (method === "GET") {
    if (path === "/control/v1/cases") return { body: casesPage() };
    let match = /^\/control\/v1\/cases\/(case_[^/]+)\/items$/.exec(path);
    if (match?.[1]) return { body: collection(match[1]) };
    match = /^\/control\/v1\/cases\/(case_[^/]+)\/holds$/.exec(path);
    if (match?.[1]) return { body: holds(match[1]) };
    if (path === "/control/v1/evidence-access-requests") {
      const view = url.searchParams.get("view") === "review" ? "review" : "mine";
      return { body: accessListFixture(view) };
    }
    if (/^\/control\/v1\/evidence-access-requests\/access_[^/]+$/.test(path))
      return { body: accessInspectionFixture() };
    if (path === "/control/v1/exports") {
      const view = url.searchParams.get("view") === "review" ? "review" : "mine";
      return { body: exportListFixture(view) };
    }
    if (/^\/control\/v1\/exports\/export_[^/]+$/.test(path)) return { body: exportFixture() };
    if (path === "/control/v1/sites") return { body: sitesPage() };
    match = /^\/control\/v1\/jobs\/(job_[^/]+)$/.exec(path);
    if (match?.[1]) return { body: jobBody(CASE_ID, match[1]) };
    match = /^\/control\/v1\/artifacts\/(artifact_[^/]+)$/.exec(path);
    if (match?.[1]) return { body: artifactFixture(match[1]) };
    return { status: 403, body: errorFixture("CONTROL_SCOPE_DENIED") };
  }
  const caseId = /\/cases\/(case_[^/]+)\//.exec(path)?.[1] ?? CASE_ID;
  if (path === "/control/v1/cases")
    return { status: 201, body: caseCreatedFixture(String(body?.purpose ?? "")) };
  if (/\/cases\/case_[^/]+\/items$/.test(path))
    return {
      status: 201,
      body: {
        ...caseItemAddedFixture(String(body?.artifact_id ?? ARTIFACT_ID)),
        case_id: caseId,
      },
    };
  if (path.endsWith("/close")) return { body: { ...caseClosedFixture(), case_id: caseId } };
  if (path.endsWith("/analyze")) return { status: 202, body: jobBody(caseId) };
  if (/\/artifacts\/artifact_[^/]+\/access$/.test(path)) {
    const artifact = /\/artifacts\/(artifact_[^/]+)\//.exec(path)?.[1] ?? ARTIFACT_ID;
    return {
      status: 201,
      body: {
        ...accessRequestedFixture(),
        artifact_id: artifact,
        case_id: String(body?.case_id ?? CASE_ID),
      },
    };
  }
  if (path.endsWith("/approve") && path.includes("evidence-access-requests"))
    return { body: accessDecisionFixture("approved") };
  if (path.endsWith("/deny") && path.includes("evidence-access-requests"))
    return { body: accessDecisionFixture("denied") };
  if (path === "/control/v1/exports")
    return {
      status: 202,
      body: {
        ...exportFixture(),
        purpose: String(body?.purpose ?? ""),
        case_id: String(body?.case_id ?? CASE_ID),
      },
    };
  if (path.endsWith("/approve"))
    return { body: { ...exportFixture("ready"), decision_reason: String(body?.reason ?? "") } };
  if (path.endsWith("/deny"))
    return { body: { ...exportFixture("rejected"), decision_reason: String(body?.reason ?? "") } };
  if (/\/cases\/case_[^/]+\/holds$/.test(path)) {
    return {
      status: 201,
      body: {
        ...holdMutationFixture(),
        case_id: caseId,
        artifact_id: String(body?.artifact_id ?? ARTIFACT_ID),
        reason: String(body?.reason ?? ""),
        hold_until: String(body?.hold_until ?? ""),
        created_at: "2026-09-20T08:02:00.000Z",
      },
    };
  }
  if (path.endsWith("/release"))
    return {
      body: {
        ...holdMutationFixture(true),
        released_reason: String(body?.reason ?? ""),
      },
    };
  return { status: 404, body: errorFixture("CONTROL_SCOPE_DENIED") };
}

/**
 * Installs the synthetic API. In `session` mode the OIDC cookie session answers
 * `GET /session` and `POST /session/logout`, and re-authentication start returns an address
 * on the test origin; in `machine` mode every request must carry the synthetic Bearer only.
 */
export async function mockWork(
  page: Page,
  override?: Override,
  mode: Mode = { kind: "machine" },
): Promise<Call[]> {
  const calls: Call[] = [];
  await page.route("**/control/v1/**", async (route: Route) => {
    const request = route.request();
    const url = new URL(request.url());
    const method = request.method();
    if (mode.kind === "session") {
      if (url.pathname === "/control/v1/session" && method === "GET") {
        await route.fulfill({
          json: sessionBody(mode.roles ?? [], mode.session),
          headers: { "cache-control": "private, no-store" },
        });
        return;
      }
      if (url.pathname === "/control/v1/session/logout") {
        await route.fulfill({ status: 204 });
        return;
      }
      if (url.pathname === "/control/v1/auth/oidc/reauth/start") {
        calls.push({
          path: url.pathname,
          method,
          key: null,
          body: null,
          csrf: await request.headerValue("x-xshield-csrf"),
          authorized: true,
        });
        await route.fulfill({
          json: {
            schema_version: 3,
            request_id: ENVELOPE.request_id,
            tenant_id: ENVELOPE.tenant_id,
            site_id: ENVELOPE.site_id,
            authorization_url: `${mode.origin ?? "http://127.0.0.1"}/__reauth?state=synthetic`,
          },
        });
        return;
      }
    }
    let body: Record<string, unknown> | null = null;
    try {
      body = request.postDataJSON() as Record<string, unknown> | null;
    } catch {
      body = null;
    }
    const call: Call = {
      path: `${url.pathname}${url.search}`,
      method,
      key: await request.headerValue("idempotency-key"),
      body,
      csrf: await request.headerValue("x-xshield-csrf"),
      authorized:
        mode.kind === "machine"
          ? (await request.headerValue("authorization")) === `Bearer ${TOKEN}` &&
            (await request.headerValue("cookie")) === null
          : (await request.headerValue("authorization")) === null,
    };
    calls.push(call);
    const custom = await override?.(url, request, call, calls.length);
    const reply = custom ?? defaults(url, method, body);
    if (reply.abort) {
      await route.abort(reply.abort);
      return;
    }
    if (reply.raw) {
      await route.fulfill({ status: reply.status ?? 200, body: reply.raw, headers: reply.headers });
      return;
    }
    await route.fulfill({
      status: reply.status ?? 200,
      json: reply.body,
      headers: { "cache-control": "private, no-store", ...reply.headers },
    });
  });
  return calls;
}

export const apiCalls = (calls: Call[]) =>
  calls.filter((call) => call.path.startsWith("/control/v1/") && !call.path.includes("/session"));
export const writes = (calls: Call[]) => calls.filter((call) => call.method === "POST");

/** Error reply helper. */
export const refuse = (status: number, code: string): Reply => ({
  status,
  body: errorFixture(code),
});

/** No request is sent after the page settled: reads are audited and never polled. */
export async function expectQuiet(page: Page, calls: Call[], ms = 400) {
  const before = calls.length;
  await page.waitForTimeout(ms);
  expect(calls.length).toBe(before);
}

export {
  ACCESS_ID,
  ARTIFACT_ID,
  CASE_ID,
  EXPORT_ID,
  HOLD_ID,
  OTHER_ARTIFACT_ID,
  OTHER_CASE_ID,
  holdRecordFixture,
};
