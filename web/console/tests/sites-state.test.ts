import assert from "node:assert/strict";
import { test } from "node:test";
import type { SiteApplyResponse, SiteConfigResponse, SiteValidationResponse } from "../src/api.ts";
import type { OperationSnapshot } from "../src/security/pending-operations.ts";
import { siteAccess } from "../src/sites/access.ts";
import {
  describeApply,
  describeDelete,
  describeSave,
  describeValidation,
  standing,
} from "../src/sites/outcome.ts";
import { configSections, visibleSections } from "../src/sites/sections.ts";
import { operationKind, operationsOfSite } from "../src/sites/state/write-kinds.ts";

test("each role set is offered the sections the previous pages offered", () => {
  const all = [
    "overview",
    "network",
    "security-entry",
    "routes",
    "identity",
    "crypto",
    "waf-limits",
    "policies",
    "releases",
    "audit",
  ];
  assert.deepEqual(visibleSections(siteAccess(["system_admin"]), false), all);
  assert.deepEqual(
    visibleSections(siteAccess(null), false),
    all,
    "machine login offers everything",
  );
  assert.deepEqual(visibleSections(siteAccess(["observer"]), false), [
    "overview",
    "policies",
    "releases",
    "audit",
  ]);
  for (const role of ["policy_author", "policy_approver", "release_operator"]) {
    assert.deepEqual(visibleSections(siteAccess([role]), false), ["releases"], role);
  }
  assert.deepEqual(visibleSections(siteAccess(["investigator"]), false), []);
  assert.deepEqual(visibleSections(siteAccess(["observer", "release_operator"]), false), [
    "overview",
    "policies",
    "releases",
    "audit",
  ]);
  // While a site is being created only the editor sections exist.
  assert.deepEqual(visibleSections(siteAccess(["system_admin"]), true), [...configSections]);
});

const operation = (method: OperationSnapshot["method"], path: string): OperationSnapshot => ({
  id: "op",
  label: "x",
  method,
  path,
  body: null,
  idempotencyKey: "k".repeat(20),
  createdAt: 0,
  phase: "unknown",
  attempts: 1,
  lastError: null,
});

test("a registered write is recognised by its frozen method and path, never by its label", () => {
  const kinds: [OperationSnapshot["method"], string, ReturnType<typeof operationKind>][] = [
    ["POST", "/control/v1/sites", "create"],
    ["PUT", "/control/v1/sites/site_a/config", "save"],
    ["POST", "/control/v1/sites/site_a/validate", "validate"],
    ["POST", "/control/v1/sites/site_a/apply", "apply"],
    ["POST", "/control/v1/sites/site_a/approve", "approve"],
    ["POST", "/control/v1/sites/site_a/rollback", "rollback"],
    ["DELETE", "/control/v1/sites/site_a", "delete"],
    ["POST", "/control/v1/cases", null],
    ["PUT", "/control/v1/sites/site_a/apply", null],
    ["GET" as never, "/control/v1/sites/site_a/config", null],
    ["POST", "/control/v1/sites/site_a/other", null],
  ];
  for (const [method, path, expected] of kinds) {
    assert.equal(operationKind(operation(method, path)), expected, `${method} ${path}`);
  }
});

test("unresolved writes are attributed to their own site and to the site being created", () => {
  const operations = [
    operation("PUT", "/control/v1/sites/site_a/config"),
    operation("POST", "/control/v1/sites/site_b/apply"),
    operation("POST", "/control/v1/sites"),
    operation("DELETE", "/control/v1/sites/site_a"),
    operation("POST", "/control/v1/sites/site_ab/apply"),
  ];
  assert.deepEqual(
    operationsOfSite(operations, "site_a", false).map((item) => item.path),
    ["/control/v1/sites/site_a/config", "/control/v1/sites/site_a"],
    "site_ab is another site",
  );
  assert.deepEqual(
    operationsOfSite(operations, null, true).map((item) => item.path),
    ["/control/v1/sites"],
  );
  assert.deepEqual(operationsOfSite(operations, null, false), []);
});

const saved = (over: Partial<SiteConfigResponse> = {}): SiteConfigResponse =>
  ({
    request_id: "req_018f2a3b-4c5d-7000-8000-000000000001",
    tenant_id: "t",
    site_id: "s",
    found: true,
    desired_revision: 4,
    active_revision: 3,
    apply_state: "pending",
    apply_id: "a",
    reason_code: "CONTROL_SITE_APPROVAL_REQUIRED",
    requires_approval: true,
    config_digest: "a".repeat(64),
    config: { status: "active" } as SiteConfigResponse["config"],
    ...over,
  }) as SiteConfigResponse;

test("a saved revision says where it stands: awaiting approval, staged, live or failed", () => {
  const awaiting = describeSave(saved(), false);
  assert.equal(awaiting.tone, "info");
  assert.equal(awaiting.title, "已保存为 r4。");
  assert.match(awaiting.detail ?? "", /需要独立审批后才会应用；edge 仍在服务 r3/);

  const created = describeSave(saved({ active_revision: null, desired_revision: 1 }), true);
  assert.equal(created.title, "站点已创建，已保存为 r1。");
  assert.match(created.detail ?? "", /edge 目前没有服务该站点/);

  const draft = describeSave(
    saved({
      requires_approval: false,
      config: { status: "draft" } as SiteConfigResponse["config"],
    }),
    false,
  );
  assert.equal(draft.detail, "草稿不会发布到 edge。");

  const live = describeSave(
    saved({ requires_approval: false, apply_state: "active", active_revision: 4 }),
    false,
  );
  assert.equal(live.tone, "success");
  assert.match(live.detail ?? "", /edge 已确认 r4/);

  const failed = describeSave(
    saved({ requires_approval: false, apply_state: "failed", reason_code: "EDGE_UNAVAILABLE" }),
    false,
  );
  assert.equal(failed.tone, "warning");
  assert.match(failed.detail ?? "", /应用失败：控制面连不上 edge 的应用通道/);
});

test("validation, apply, approve, rollback and delete are worded for what they did", () => {
  const validation = (valid: boolean): SiteValidationResponse => ({
    request_id: "req_018f2a3b-4c5d-7000-8000-000000000001",
    tenant_id: "t",
    site_id: "s",
    revision: 4,
    config_digest: "a".repeat(64),
    valid,
    reason_code: valid ? "CONTROL_SITE_VALIDATED" : "CONTROL_SITE_CONFIG_REQUEST_INVALID",
  });
  assert.match(describeValidation(validation(true)).title, /^配置验证通过：已保存的 r4/);
  const failedValidation = describeValidation(validation(false));
  assert.equal(failedValidation.tone, "warning");
  assert.match(failedValidation.title, /配置验证未通过：配置没有通过服务端校验/);

  const apply = (over: Partial<SiteApplyResponse> = {}): SiteApplyResponse => ({
    request_id: "req_018f2a3b-4c5d-7000-8000-000000000001",
    tenant_id: "t",
    site_id: "s",
    listen_port: 6100,
    desired_revision: 5,
    active_revision: 5,
    config_digest: "a".repeat(64),
    apply_state: "active",
    apply_id: "a",
    reason_code: "EDGE_APPLY_CONFIRMED",
    requires_approval: false,
    ...over,
  });
  assert.equal(describeApply("approve", apply()).tone, "success");
  assert.match(describeApply("approve", apply()).title, /^已批准：当前暂存 r5/);
  assert.match(
    describeApply("apply", apply({ apply_state: "pending", active_revision: 4 })).detail ?? "",
    /等待 edge 确认；edge 仍在服务 r4/,
  );
  assert.match(describeApply("rollback", apply()).title, /已回滚（创建了新修订）/);
  assert.equal(
    describeApply(
      "apply",
      apply({ apply_state: "failed", reason_code: "EDGE_APPLY_STALE_REVISION" }),
    ).tone,
    "warning",
  );
  assert.match(
    describeDelete({
      request_id: "req_018f2a3b-4c5d-7000-8000-000000000001",
      tenant_id: "t",
      site_id: "s",
      reason_code: "CONTROL_SITE_DELETED",
    }).title,
    /站点已删除/,
  );
  assert.equal(
    standing(
      {
        apply_state: null,
        requires_approval: null,
        desired_revision: null,
        active_revision: null,
        reason_code: null,
      },
      null,
    ),
    "",
  );
});
