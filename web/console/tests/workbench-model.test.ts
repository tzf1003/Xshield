import assert from "node:assert/strict";
import { test } from "node:test";
import type {
  SiteListItem,
  SiteListResponse,
  WorkbenchObservation,
  WorkbenchOverviewResponse,
  WorkbenchSite,
} from "../src/api.ts";
import { deniedRequestsPlan, scanStats } from "../src/operations/denied.ts";
import { deriveKpis, isServing, siteProjection } from "../src/operations/kpis.ts";
import { operationHome } from "../src/operations/operation-home.ts";
import { quickLinks } from "../src/operations/roles.ts";
import { type SourceState, sourceOf } from "../src/operations/sources.ts";
import { orderTodos, siteTodos, todoSources, writeTodos } from "../src/operations/todo.ts";
import { ApiError } from "../src/api-contract.ts";
import type { OperationSnapshot } from "../src/security/pending-operations.ts";
import { StaleSessionError } from "../src/security/errors.ts";
import { validateSearchPlan } from "../src/search.ts";

const AS_OF = "2026-10-04T02:00:00Z";
const ENVELOPE = {
  request_id: "req_018f2a3b-4c5d-7000-8000-000000000001",
  tenant_id: "tenant_demo",
  site_id: "site_demo",
};
const seen = (value: string | null, reason: string): WorkbenchObservation<string> => ({
  observed_at: AS_OF,
  source_state: value === null ? "unavailable" : "available",
  reason_code: reason,
  value,
});

function site(id: string, apply_state: string, current_revision: number | null): WorkbenchSite {
  return {
    site_id: id,
    display_name: id,
    public_origin: "https://example.test",
    edge: seen("healthy", "WORKBENCH_EDGE_PROBED"),
    upstream: seen(null, "WORKBENCH_UPSTREAM_NEVER_OBSERVED"),
    audit: seen("healthy", "WORKBENCH_EDGE_AUDIT_PROBED"),
    current_revision,
    apply_state,
    reason_code: "CONTROL_SITE_APPLY_ACTIVE",
    updated_at: AS_OF,
  };
}

function overview(
  sites: WorkbenchSite[],
  options: { completeness?: WorkbenchOverviewResponse["completeness"]; audit?: boolean } = {},
): WorkbenchOverviewResponse {
  const audit = options.audit ?? true;
  return {
    ...ENVELOPE,
    as_of: AS_OF,
    completeness: options.completeness ?? "complete",
    index_watermark: null,
    has_gaps: false,
    posture: seen("observed", "WORKBENCH_POSTURE_SCOPED"),
    sites,
    queues: [],
    recent_activity: [],
    audit: audit
      ? {
          observed_at: AS_OF,
          source_state: "available",
          reason_code: "WORKBENCH_AUDIT_READ",
          value: {
            target_id: "clickhouse_primary",
            table: "audit_events",
            as_of: AS_OF,
            metadata_retention_days: 30,
            closed_segments: 7,
            closed_segment_bytes: 1024,
            published_segments: 5,
            pending_segments: 2,
            unsealed_segments: 1,
            has_gaps: false,
            index_watermark: null,
          },
        }
      : {
          observed_at: AS_OF,
          source_state: "unavailable",
          reason_code: "WORKBENCH_AUDIT_NOT_AUTHORIZED",
          value: null,
        },
  };
}

function listed(id: string, overrides: Partial<SiteListItem> = {}): SiteListItem {
  return {
    site_id: id,
    display_name: `站点 ${id}`,
    public_origin: "https://example.test",
    listen_port: 6100,
    security_entry: "public",
    sensor_enabled: false,
    policy_revision: "policy-v1",
    status: "active",
    revision: 3,
    config_digest: "a".repeat(64),
    updated_by: "author",
    updated_at: AS_OF,
    desired_revision: 3,
    active_revision: 2,
    apply_id: "apply_1",
    apply_state: "active",
    reason_code: "CONTROL_SITE_APPLY_ACTIVE",
    requires_approval: false,
    ...overrides,
  } as SiteListItem;
}

const siteList = (sites: SiteListItem[], truncated = false): SiteListResponse => ({
  ...ENVELOPE,
  sites,
  truncated,
  next_cursor: truncated ? "cursor" : null,
});
const ok = <T>(data: T): SourceState<T> => ({ status: "ok", data, receivedAt: 1 });
const value = (kpis: ReturnType<typeof deriveKpis>, key: string) =>
  kpis.find((kpi) => kpi.key === key);

test("a site is serving when it was applied once and is not paused", () => {
  assert.equal(isServing(site("a", "active", 3)), true);
  assert.equal(isServing(site("b", "pending", 3)), true);
  assert.equal(isServing(site("c", "failed", 3)), true);
  assert.equal(isServing(site("d", "paused", 3)), false);
  assert.equal(isServing(site("e", "pending", null)), false);
});

test("KPIs count the snapshot and the site list, each with its own source", () => {
  const kpis = deriveKpis({
    overview: ok(
      overview([site("a", "active", 1), site("b", "failed", 2), site("c", "pending", null)]),
    ),
    sites: ok(
      siteList([listed("a"), listed("c", { requires_approval: true, apply_state: "pending" })]),
    ),
    roles: ["system_admin", "audit_administrator"],
  });
  assert.equal(value(kpis, "serving")?.value, "2");
  assert.equal(value(kpis, "serving")?.asOf, AS_OF);
  assert.equal(value(kpis, "failed")?.value, "1");
  assert.equal(value(kpis, "failed")?.tone, "error");
  assert.equal(value(kpis, "approval")?.value, "1");
  assert.equal(value(kpis, "approval")?.receivedAt, 1);
  assert.equal(value(kpis, "approval")?.asOf, null);
  assert.equal(value(kpis, "audit")?.value, "有待发布段");
  assert.equal(value(kpis, "audit")?.asOf, AS_OF);
});

test("a truncated site list or a full snapshot page is a lower bound", () => {
  const many = Array.from({ length: 128 }, (_, index) => site(`s${index}`, "active", 1));
  const kpis = deriveKpis({
    overview: ok(overview(many, { completeness: "partial" })),
    sites: ok(siteList([listed("a", { requires_approval: true })], true)),
    roles: null,
  });
  assert.equal(value(kpis, "serving")?.value, "128+");
  assert.equal(value(kpis, "approval")?.value, "1+");
});

test("unavailable sources are — with a reason, never 0", () => {
  const roles = ["observer"];
  const kpis = deriveKpis({
    overview: ok(overview([], { completeness: "partial", audit: false })),
    sites: { status: "denied", error: new ApiError("CONTROL_SCOPE_DENIED", 403) },
    roles,
  });
  for (const kpi of kpis) {
    assert.equal(kpi.value, null, kpi.key);
    assert.ok(kpi.detail.length > 0, kpi.key);
  }
  assert.match(value(kpis, "serving")?.detail ?? "", /只为 SystemAdmin 投影/);
  assert.match(value(kpis, "approval")?.detail ?? "", /需要 SystemAdmin/);
  assert.match(value(kpis, "audit")?.detail ?? "", /AuditAdministrator/);
  const loading = deriveKpis({
    overview: { status: "loading" },
    sites: { status: "skipped" },
    roles,
  });
  assert.ok(loading.every((kpi) => kpi.value === null));
  assert.match(value(loading, "approval")?.detail ?? "", /当前角色不读取/);
});

test("an empty partial snapshot is zero sites only when the site list confirms it", () => {
  const empty = overview([], { completeness: "partial", audit: false });
  assert.equal(siteProjection(empty, null, { status: "loading" }).projected, false);
  assert.equal(siteProjection(empty, ["system_admin"], ok(siteList([]))).projected, true);
  assert.equal(siteProjection(empty, ["system_admin"], ok(siteList([], true))).projected, false);
  assert.equal(siteProjection(overview([]), null, { status: "loading" }).projected, true);
  assert.equal(siteProjection(empty, ["investigator"], ok(siteList([]))).projected, false);
  assert.equal(
    siteProjection(overview([], { completeness: "unavailable" }), null, ok(siteList([]))).projected,
    false,
  );
});

test("an audit administrator whose read failed is told so, not told to get the role", () => {
  const kpis = deriveKpis({
    overview: ok(overview([site("a", "active", 1)], { completeness: "partial", audit: false })),
    sites: { status: "skipped" },
    roles: ["audit_administrator"],
  });
  assert.match(value(kpis, "audit")?.detail ?? "", /读取失败/);
});

test("sources: a 403 is a role hint, other failures are errors, a dead session is loading", () => {
  const base = { data: undefined, isSuccess: false, isError: true, dataUpdatedAt: 0 };
  assert.equal(
    sourceOf({ ...base, error: new ApiError("CONTROL_SCOPE_DENIED", 403) }, true).status,
    "denied",
  );
  assert.equal(
    sourceOf({ ...base, error: new ApiError("CONTROL_INDEX_UNAVAILABLE", 503) }, true).status,
    "failed",
  );
  assert.equal(
    sourceOf({ ...base, error: new StaleSessionError("epoch") }, true).status,
    "loading",
  );
  assert.equal(sourceOf({ ...base, error: null }, false).status, "skipped");
});

test("todo sources follow the roles", () => {
  assert.deepEqual(todoSources(null), { sites: true, review: true });
  assert.deepEqual(todoSources(["system_admin"]), { sites: true, review: false });
  assert.deepEqual(todoSources(["observer"]), { sites: true, review: false });
  assert.deepEqual(todoSources(["sensitive_evidence_approver"]), { sites: false, review: true });
  assert.deepEqual(todoSources(["investigator", "audit_administrator"]), {
    sites: false,
    review: false,
  });
});

function operation(overrides: Partial<OperationSnapshot>): OperationSnapshot {
  return {
    id: "op-1",
    label: "创建案件",
    method: "POST",
    path: "/control/v1/cases",
    body: null,
    idempotencyKey: "e2e-operation-key-0001",
    createdAt: Date.parse("2026-10-01T00:00:00Z"),
    phase: "unknown",
    attempts: 1,
    lastError: null,
    ...overrides,
  };
}

test("todo rows: one row per site, failed before approval; unknown writes first, then newest", () => {
  const sites = siteTodos([
    listed("failed", {
      apply_state: "failed",
      requires_approval: true,
      reason_code: "EDGE_UNAVAILABLE",
    }),
    listed("waiting", {
      apply_state: "pending",
      requires_approval: true,
      updated_at: "2026-10-03T00:00:00Z",
    }),
    listed("fine"),
  ]);
  assert.deepEqual(
    sites.map((item) => [item.kind, item.id, item.href]),
    [
      ["failed", "failed", "/sites/failed/releases"],
      ["site", "waiting", "/sites/waiting/releases"],
    ],
  );
  assert.match(sites[0]?.detail ?? "", /同时在等待审批/);
  const writes = writeTodos([operation({})]);
  assert.equal(writes[0]?.href, "/cases");
  assert.match(writes[0]?.detail ?? "", /幂等键 e2e-operation-key-0001/);
  const ordered = orderTodos(sites, writes);
  assert.deepEqual(
    ordered.map((item) => item.kind),
    ["write", "failed", "site"],
  );
});

test("a frozen write leads back to the page that owns it", () => {
  const caseId = "case_018f2a3b-4c5d-7000-8000-000000000031";
  const access = "access_018f2a3b-4c5d-7000-8000-000000000041";
  const home = (method: OperationSnapshot["method"], path: string, body: string | null = null) =>
    operationHome({ method, path, body });
  assert.deepEqual(home("PUT", "/control/v1/sites/site_a/config"), {
    to: "/sites/site_a/overview",
    label: "站点配置",
  });
  assert.equal(home("POST", "/control/v1/sites/site_a/approve")?.to, "/sites/site_a/releases");
  assert.equal(home("DELETE", "/control/v1/sites/site_a")?.to, "/sites");
  assert.equal(home("POST", "/control/v1/sites")?.to, "/sites");
  assert.equal(
    home("POST", `/control/v1/cases/${caseId}/analyze`)?.to,
    `/cases/${caseId}/analysis`,
  );
  assert.equal(home("POST", `/control/v1/cases/${caseId}/close`)?.to, `/cases/${caseId}`);
  assert.deepEqual(home("POST", `/control/v1/evidence-access-requests/${access}/approve`), {
    to: "/approvals",
    search: { item: access },
    label: "审批中心",
  });
  assert.equal(
    home(
      "POST",
      "/control/v1/artifacts/artifact_018f2a3b-4c5d-7000-8000-000000000011/access",
      JSON.stringify({ case_id: caseId }),
    )?.to,
    `/cases/${caseId}/access`,
  );
  assert.equal(home("POST", "/control/v1/exports", "{not json")?.to, "/cases");
  assert.equal(
    home("POST", "/control/v1/agent-api-keys/key_018f2a3b-4c5d-7000-8000-000000000051/rotate")?.to,
    "/admin/api-keys",
  );
  assert.equal(home("POST", "/control/v1/unknown"), null);
  assert.equal(home("POST", "/control/v1/sites/../x/approve"), null);
});

test("the denied-requests search is a valid 24 h plan of the newest ten denials", () => {
  const plan = deniedRequestsPlan(Date.parse("2026-10-05T08:00:00.987Z"));
  assert.deepEqual(validateSearchPlan(plan), plan);
  assert.equal(plan.end, "2026-10-05T08:00:00Z");
  assert.equal(plan.start, "2026-10-04T08:00:00Z");
  assert.equal(plan.sort, "occurred_at_desc");
  assert.equal(plan.limit, 10);
  assert.deepEqual(scanStats({ scanned_rows: 1280, scanned_bytes: null }), {
    rows: "1,280 行",
    bytes: "未知",
  });
  assert.equal(scanStats({ scanned_rows: 0, scanned_bytes: 0 }).rows, "0 行");
});

test("quick links follow the navigation of the roles, most action-bearing first", () => {
  assert.deepEqual(
    quickLinks(["investigator"], "site_demo").map((link) => link.href),
    [
      "/approvals",
      "/cases",
      "/investigation/search",
      "/investigation/requests",
      "/operations/jobs",
    ],
  );
  assert.deepEqual(
    quickLinks(["observer"], "site_demo").map((link) => link.href),
    ["/sites/site_demo/overview", "/investigation/requests"],
  );
  assert.ok(quickLinks(null, null).length <= 6);
  assert.ok(quickLinks(null, null).every((link) => link.href !== "/"));
});
