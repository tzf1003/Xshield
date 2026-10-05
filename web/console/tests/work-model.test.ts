import assert from "node:assert/strict";
import { test } from "node:test";
import type { SiteListItem } from "../src/api.ts";
import { ApiError } from "../src/api-contract.ts";
import type { HoldRecord } from "../src/evidence-holds.ts";
import type { OperationSnapshot } from "../src/security/pending-operations.ts";
import { describeCode, errorView, isStepUpCode, isStepUpRequired } from "../src/work/errors.ts";
import {
  formatAge,
  formatUtc,
  parseMs,
  shortId,
  textProblem,
  utf8Length,
} from "../src/work/format.ts";
import {
  estimateServerNowMs,
  formatUtcInput,
  HOLD_MARGIN_MS,
  holdState,
  holdUntilOf,
  holdUntilProblem,
  holdWindow,
  parseUtcInput,
  presetDeadlineMs,
} from "../src/work/holds.ts";
import {
  accessInboxItem,
  badgeCount,
  badgeLabel,
  exportInboxItem,
  filterInbox,
  mergeInbox,
  siteApprovals,
  siteNeedsApproval,
} from "../src/work/inbox.ts";
import { owners, viewOperation } from "../src/work/operations.ts";
import { isOwnRequest, requestIsOwn } from "../src/work/ownership.ts";
import { exportLapsed, exportPill } from "../src/work/status.ts";
import { formatTtl, ttlPresets, ttlProblem } from "../src/work/ttl.ts";
import { ACCESS_ID, accessListFixture } from "./access-fixtures.ts";
import { EXPORT_ID, exportListItemFixture } from "./export-fixtures.ts";

const HOUR = 3_600_000;

test("free text follows the server rule and says which part is wrong", () => {
  assert.equal(textProblem("核对证据", "理由"), null);
  assert.match(textProblem("", "理由") ?? "", /不能为空/);
  assert.match(textProblem(" 前导空白", "理由") ?? "", /首尾/);
  assert.match(textProblem("尾随空白　", "理由") ?? "", /首尾/);
  assert.match(textProblem("含\u0007控制字符", "理由") ?? "", /控制字符/);
  // 171 CJK characters are 513 bytes: the limit is bytes, not characters.
  assert.equal(utf8Length("中".repeat(170)), 510);
  assert.equal(textProblem("中".repeat(170), "理由"), null);
  assert.match(textProblem("中".repeat(171), "理由") ?? "", /513 字节/);
  assert.match(textProblem("\ud800", "理由") ?? "", /无法编码/);
});

test("times are shown in UTC and ages never run backwards", () => {
  assert.equal(formatUtc("2026-09-20T08:10:30.123456Z"), "2026-09-20 08:10:30 UTC");
  assert.equal(formatUtc(null), "—");
  assert.equal(formatUtc("not a time"), "not a time");
  assert.equal(formatAge(-5), "刚刚");
  assert.equal(formatAge(59_000), "刚刚");
  assert.equal(formatAge(5 * 60_000), "5 分钟");
  assert.equal(formatAge(3 * HOUR), "3 小时");
  assert.equal(formatAge(47 * HOUR), "47 小时");
  assert.equal(formatAge(72 * HOUR), "3 天");
  assert.equal(formatAge(Number.NaN), "刚刚");
  assert.ok(Number.isNaN(parseMs(null)));
  assert.equal(shortId("case_018f2a3b-4c5d-7000-8000-000000000031"), "case_018f2a3b…0031");
  assert.equal(shortId("short"), "short");
});

test("hold deadlines are canonical UTC milliseconds inside the server window", () => {
  const now = Date.parse("2026-09-20T08:00:00.000Z");
  const window = holdWindow(now);
  assert.equal(window.minMs - now, HOLD_MARGIN_MS);
  assert.equal(window.maxMs - now, 720 * HOUR - HOLD_MARGIN_MS);
  assert.equal(holdUntilProblem(presetDeadlineMs("1d", now), now), null);
  assert.equal(holdUntilProblem(presetDeadlineMs("7d", now), now), null);
  // The 30-day preset sits exactly on the safe edge and is accepted; one millisecond more is not.
  assert.equal(presetDeadlineMs("max", now), window.maxMs);
  assert.equal(holdUntilProblem(window.maxMs, now), null);
  assert.match(holdUntilProblem(window.maxMs + 1, now) ?? "", /720 小时/);
  assert.match(holdUntilProblem(window.minMs - 1, now) ?? "", /晚于/);
  assert.match(holdUntilProblem(now - HOUR, now) ?? "", /晚于/);
  assert.match(holdUntilProblem(null, now) ?? "", /有效的保留截止时间/);
  assert.match(holdUntilProblem(Number.NaN, now) ?? "", /有效的保留截止时间/);
  assert.equal(holdUntilOf(window.maxMs), new Date(window.maxMs).toISOString());
  assert.match(holdUntilOf(now + 1), /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.001Z$/);
  // The server clock is extrapolated from the last observation and never from the future.
  const asOf = "2026-09-20T08:00:00.500000Z";
  assert.equal(estimateServerNowMs(asOf, 1_000, 4_000), Date.parse(asOf) + 3_000);
  assert.equal(estimateServerNowMs(asOf, 4_000, 1_000), Date.parse(asOf));
});

test("datetime-local text is read as UTC and impossible dates are refused", () => {
  assert.equal(parseUtcInput("2026-09-20T08:00"), Date.parse("2026-09-20T08:00:00.000Z"));
  assert.equal(parseUtcInput("2026-09-20T08:00:30"), Date.parse("2026-09-20T08:00:30.000Z"));
  assert.equal(parseUtcInput("2026-09-20T08:00:30.5"), Date.parse("2026-09-20T08:00:30.500Z"));
  for (const bad of [
    "",
    "2026-02-30T08:00",
    "2026-09-20",
    "2026-09-20 08:00",
    "2026-13-01T00:00",
    "x",
  ])
    assert.equal(parseUtcInput(bad), null, bad);
  assert.equal(formatUtcInput(Date.parse("2026-09-20T08:00:30.999Z")), "2026-09-20T08:00:30");
});

function hold(over: Partial<HoldRecord> = {}): HoldRecord {
  return {
    hold_id: "ev_018f2a3b-4c5d-7000-8000-000000000061",
    case_id: "case_018f2a3b-4c5d-7000-8000-000000000031",
    artifact_id: "artifact_018f2a3b-4c5d-7000-8000-000000000011",
    created_by: "admin",
    reason: "保留",
    created_at: "2026-09-20T08:00:00.000Z",
    hold_until: "2026-09-25T08:00:00.000Z",
    released_event_id: null,
    released_by: null,
    released_reason: null,
    released_at: null,
    ...over,
  };
}

test("a hold is active, past its deadline, or released, with microsecond care at the edge", () => {
  assert.equal(holdState(hold(), "2026-09-20T08:02:00.000000Z"), "active");
  assert.equal(holdState(hold(), "2026-09-25T07:59:59.999999Z"), "active");
  assert.equal(holdState(hold(), "2026-09-25T08:00:00.000000Z"), "expired");
  assert.equal(holdState(hold(), "2026-09-26T08:00:00.000001Z"), "expired");
  const released = hold({
    released_event_id: "ev_018f2a3b-4c5d-7000-8000-000000000062",
    released_by: "admin",
    released_reason: "完成",
    released_at: "2026-09-20T08:01:00.000Z",
  });
  // Release wins over expiry: the durable fact beats the clock.
  assert.equal(holdState(released, "2026-10-01T00:00:00.000000Z"), "released");
});

test("approval lifetimes are capped by the server maximum", () => {
  assert.deepEqual(
    ttlPresets(86_400).map((p) => p.seconds),
    [900, 3600, 14_400],
  );
  assert.deepEqual(
    ttlPresets(3600).map((p) => p.seconds),
    [900, 3600],
  );
  assert.deepEqual(ttlPresets(600), []);
  assert.equal(ttlProblem(900, 3600), null);
  assert.equal(ttlProblem(3600, 3600), null);
  assert.match(ttlProblem(3601, 3600) ?? "", /最多 3600 秒/);
  assert.match(ttlProblem(0, 3600) ?? "", /至少/);
  assert.match(ttlProblem(null, 3600) ?? "", /请选择/);
  assert.match(ttlProblem(1.5, 3600) ?? "", /请选择/);
  assert.equal(formatTtl(45), "45 秒");
  assert.equal(formatTtl(900), "15 分钟");
  assert.equal(formatTtl(3600), "1 小时");
  assert.equal(formatTtl(5400), "1 小时 30 分钟");
  assert.equal(formatTtl(90), "1 分 30 秒");
});

function site(over: Partial<SiteListItem> = {}): SiteListItem {
  return {
    site_id: "site_alpha",
    display_name: "Alpha 站点",
    public_origin: "https://example.test",
    listen_port: 6100,
    security_entry: "public",
    sensor_enabled: false,
    policy_revision: "policy-v1",
    status: "active",
    revision: 3,
    config_digest: "a".repeat(64),
    updated_by: "author",
    updated_at: "2026-09-20T09:00:00.000Z",
    desired_revision: 3,
    active_revision: 2,
    apply_id: "apply_1",
    apply_state: "pending",
    reason_code: "CONTROL_SITE_APPROVAL_REQUIRED",
    requires_approval: true,
    ...over,
  };
}

test("the inbox merges three sources, newest first, with a stable tie-break", () => {
  const list = accessListFixture("review");
  const access = list.items.map(accessInboxItem);
  const exports = [exportInboxItem(exportListItemFixture())];
  const sites = siteApprovals([site(), site({ site_id: "site_beta", requires_approval: false })]);
  assert.deepEqual(
    sites.map((item) => item.id),
    ["site_alpha"],
    "only the site that requires approval is a task",
  );
  const merged = mergeInbox(access, exports, sites);
  // The 09:00 policy row first; the access and export rows share 08:00:00.000 and the key decides.
  assert.deepEqual(
    merged.map((item) => item.kind),
    ["site", "access", "export"],
  );
  assert.deepEqual(
    mergeInbox(sites, exports, access).map((item) => item.key),
    merged.map((item) => item.key),
    "the order does not depend on the argument order",
  );
  assert.equal(merged[1]?.id, ACCESS_ID);
  assert.equal(merged[2]?.id, EXPORT_ID);
  assert.deepEqual(
    filterInbox(merged, "export").map((item) => item.kind),
    ["export"],
  );
  assert.equal(filterInbox(merged, "all").length, 3);
  // A row without a usable time sinks, and equal times fall back to the key.
  const broken = { ...access[0]!, key: "access:zzz", at: "bad", atMs: Number.NaN };
  const same = { ...exports[0]!, key: "export:aaa" };
  const sorted = mergeInbox([broken], [exports[0]!], [same]);
  assert.deepEqual(
    sorted.map((item) => item.key),
    ["export:aaa", exports[0]?.key, "access:zzz"],
  );
});

test("a site awaits approval when the server says so, under either spelling", () => {
  assert.equal(siteNeedsApproval(site()), true);
  assert.equal(siteNeedsApproval(site({ requires_approval: false, apply_state: "active" })), false);
  assert.equal(
    siteNeedsApproval({ requires_approval: false, apply_state: "awaiting_approval" as "pending" }),
    true,
  );
});

test("the badge counts first pages, marks lower bounds and never hides a failed source", () => {
  const loaded = (count: number, truncated = false) => ({ loaded: true, count, truncated });
  assert.deepEqual(badgeCount([loaded(2), loaded(1), loaded(0)]), {
    count: 3,
    more: false,
    partial: false,
  });
  assert.equal(badgeLabel(badgeCount([loaded(2), loaded(1)])), "3");
  assert.equal(badgeLabel(badgeCount([loaded(2, true), loaded(1)])), "3+");
  const failed = { loaded: false, count: 0, truncated: false };
  assert.deepEqual(badgeCount([loaded(2), failed]), { count: 2, more: false, partial: true });
  assert.equal(badgeLabel(badgeCount([loaded(2), failed])), "2+");
  assert.equal(badgeLabel(badgeCount([loaded(150)])), "99+");
});

test("export states: approved and ready lapse at their expiry, judged at the observation time", () => {
  const ready = exportListItemFixture("ready");
  const expiry = Date.parse(ready.expires_at ?? "");
  assert.equal(exportLapsed(ready, expiry - 1), false);
  assert.equal(exportLapsed(ready, expiry), true);
  assert.equal(exportLapsed(exportListItemFixture("rejected"), expiry + HOUR), false);
  assert.equal(exportLapsed({ status: "ready", expires_at: null }, expiry), false);
  assert.equal(exportPill("ready").label, "可下载");
  assert.equal(exportPill("ready", true).label, "已过期");
  assert.equal(exportPill("pending_approval").tone, "warning");
});

test("errors keep the stable code and explain role, step-up and self-approval refusals", () => {
  const stepUp = new ApiError(
    "CONTROL_STEP_UP_REQUIRED",
    403,
    "req_018f2a3b-4c5d-7000-8000-000000000099",
  );
  assert.equal(isStepUpRequired(stepUp), true);
  assert.equal(isStepUpRequired(new ApiError("CONTROL_EXPORT_STEP_UP_REQUIRED", 403)), true);
  // A different status or code is not a step-up request, whatever the message says.
  assert.equal(isStepUpRequired(new ApiError("CONTROL_STEP_UP_REQUIRED", 500)), false);
  assert.equal(isStepUpRequired(new ApiError("CONTROL_SCOPE_DENIED", 403)), false);
  assert.equal(isStepUpRequired(new Error("CONTROL_STEP_UP_REQUIRED")), false);
  assert.equal(isStepUpCode("CONTROL_EXPORT_STEP_UP_REQUIRED"), true);
  assert.equal(isStepUpCode("CONTROL_SCOPE_DENIED"), false);
  const view = errorView(stepUp);
  assert.equal(view.code, "CONTROL_STEP_UP_REQUIRED");
  assert.equal(view.requestId, "req_018f2a3b-4c5d-7000-8000-000000000099");
  assert.match(view.hint ?? "", /MFA/);
  for (const code of [
    "CONTROL_EXPORT_SELF_APPROVAL",
    "CONTROL_EVIDENCE_ACCESS_SELF_APPROVAL_DENIED",
  ]) {
    const self = describeCode(code, 403);
    assert.match(self.hint ?? "", /职责分离/);
    assert.match(self.message, /另一位/);
  }
  assert.match(describeCode("CONTROL_SCOPE_DENIED", 403).hint ?? "", /服务端/);
  // Unknown codes never echo anything the server wrote.
  const odd = describeCode("SOMETHING_ELSE", 500);
  assert.equal(odd.message, "请求未完成，请核对结果后重试。");
  assert.equal(errorView(new TypeError("secret")).code, "CONSOLE_REQUEST_FAILED");
  assert.equal(errorView(new TypeError("secret")).message.includes("secret"), false);
});

function operation(over: Partial<OperationSnapshot> = {}): OperationSnapshot {
  return {
    id: "op1",
    label: "关闭案件",
    method: "POST",
    path: "/control/v1/cases/case_018f2a3b-4c5d-7000-8000-000000000031/close",
    body: '{"reason":"完成"}',
    idempotencyKey: "0123456789abcdef-key",
    createdAt: 1,
    phase: "unknown",
    attempts: 1,
    lastError: null,
    ...over,
  };
}

test("each control finds exactly its own unresolved writes", () => {
  const caseId = "case_018f2a3b-4c5d-7000-8000-000000000031";
  const other = "case_018f2a3b-4c5d-7000-8000-000000000032";
  const close = operation();
  assert.equal(owners.closeCase(caseId)(close), true);
  assert.equal(owners.closeCase(other)(close), false);
  assert.equal(owners.addEvidence(caseId)(close), false);
  assert.equal(owners.createCase()(operation({ path: "/control/v1/cases" })), true);
  assert.equal(owners.createCase()(close), false);
  const access = operation({
    path: "/control/v1/artifacts/artifact_018f2a3b-4c5d-7000-8000-000000000011/access",
    body: JSON.stringify({ case_id: caseId, access_kind: "sensitive_raw", justification: "x" }),
  });
  assert.equal(owners.requestAccess(caseId)(access), true);
  assert.equal(owners.requestAccess(other)(access), false);
  // Approve and deny share one slot: a frozen approval blocks a deny of the same request.
  const approve = operation({ path: `/control/v1/evidence-access-requests/${ACCESS_ID}/approve` });
  assert.equal(owners.decideAccess(ACCESS_ID)(approve), true);
  assert.equal(
    owners.decideAccess(ACCESS_ID)(operation({ path: approve.path.replace("approve", "deny") })),
    true,
  );
  assert.equal(owners.decideAccess(`${ACCESS_ID.slice(0, -1)}9`)(approve), false);
  const exportRequest = operation({
    path: "/control/v1/exports",
    body: JSON.stringify({ case_id: caseId, purpose: "p" }),
  });
  assert.equal(owners.requestExport(caseId)(exportRequest), true);
  assert.equal(owners.requestExport(other)(exportRequest), false);
  assert.equal(
    owners.decideExport(EXPORT_ID)(operation({ path: `/control/v1/exports/${EXPORT_ID}/approve` })),
    true,
  );
  assert.equal(owners.requestAccess(caseId)(operation({ body: "not json" })), false);
});

test("a frozen operation is shown exactly as it will be resent", () => {
  const view = viewOperation(operation());
  assert.equal(
    view.request,
    "POST /control/v1/cases/case_018f2a3b-4c5d-7000-8000-000000000031/close",
  );
  assert.equal(view.key, "0123456789abcdef-key");
  assert.equal(view.body, '{\n  "reason": "完成"\n}');
  assert.equal(view.phase, "unknown");
  assert.equal(view.phaseLabel, "结果未知");
  assert.equal(viewOperation(operation({ phase: "inflight" })).phaseLabel, "请求中");
  assert.equal(viewOperation(operation({ body: null })).body, "");
  const refusal = { code: "CONTROL_EXPORT_STEP_UP_REQUIRED", status: 403, requestId: null };
  // A first attempt the server refused before running anything: it waits for the MFA step-up.
  const stepUp = viewOperation(operation({ phase: "step_up", lastError: refusal }));
  assert.equal(stepUp.phase, "step-up");
  assert.equal(stepUp.error?.code, "CONTROL_EXPORT_STEP_UP_REQUIRED");
  // The same refusal of a retry says nothing about an earlier attempt that may have committed.
  const afterUnknown = viewOperation(operation({ phase: "unknown", lastError: refusal }));
  assert.equal(afterUnknown.phase, "unknown");
  assert.equal(afterUnknown.phaseLabel, "结果未知");
  assert.equal(afterUnknown.error?.code, "CONTROL_EXPORT_STEP_UP_REQUIRED");
  const failed = viewOperation(
    operation({ lastError: { code: "REQUEST_TIMEOUT", status: 0, requestId: null } }),
  );
  assert.equal(failed.phase, "unknown");
  assert.match(failed.error?.message ?? "", /超时/);
});

test("any witness that says a request is yours withholds the decision form", () => {
  // The list it came from and the signed-in subject are independent witnesses.
  assert.equal(requestIsOwn("alice", "alice"), true);
  assert.equal(requestIsOwn("alice", "bob"), false);
  assert.equal(requestIsOwn("alice", null), null);
  assert.equal(requestIsOwn("alice", null, "others"), false);
  assert.equal(requestIsOwn("alice", null, "mine"), true);
  // A review list that wrongly contained the subject's own request is overruled by the subject.
  assert.equal(requestIsOwn("alice", "alice", "others"), true);
  // And a "mine" list is never contradicted into a decision form by a differing subject.
  assert.equal(requestIsOwn("alice", "bob", "mine"), true);
  assert.equal(isOwnRequest("alice", "alice"), true);
  assert.equal(isOwnRequest("alice", null), null);
});
