import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiError } from "../src/api-contract.ts";
import { StaleSessionError } from "../src/security/errors.ts";
import {
  type CompletenessInput,
  completenessHeadline,
  completenessKind,
  formatWatermark,
  mayBeIncomplete,
  watermarkScopeLabel,
} from "../src/ui/completeness.ts";
import { describeDecision } from "../src/ui/decision.ts";
import { GENERIC_PROBLEM, projectError } from "../src/ui/error-projection.ts";
import { abbreviateId, idPrefix } from "../src/ui/ids.ts";
import {
  confidenceText,
  eventTypeName,
  originStateName,
  stageName,
} from "../src/ui/request-vocab.ts";

const input = (overrides: Partial<CompletenessInput> = {}): CompletenessInput => ({
  hasGaps: false,
  pendingSegments: 0,
  observations: [],
  ...overrides,
});

test("completeness separates complete, pending, gap and not-indexed", () => {
  assert.equal(completenessKind(input()), "complete");
  assert.equal(completenessKind(input({ pendingSegments: 2 })), "pending");
  assert.equal(completenessKind(input({ hasGaps: true })), "gap");
  assert.equal(completenessKind(input({ hasGaps: true, pendingSegments: 2 })), "gap");
  // A miss is its own state whatever the gaps say: it never reads as "does not exist".
  assert.equal(completenessKind(input({ notFound: true, pendingSegments: 2 })), "not_indexed");
  assert.equal(completenessKind(input({ notFound: true })), "not_indexed");
});

test("the headline always states gaps and pending segments", () => {
  const read = (overrides: Partial<CompletenessInput>) => {
    const value = input(overrides);
    return completenessHeadline(completenessKind(value), value);
  };
  assert.equal(read({ hasGaps: true, pendingSegments: 2 }), "索引存在缺口 · 2 个待发布段");
  assert.equal(read({ pendingSegments: 3 }), "索引仍在同步 · 3 个待发布段");
  assert.equal(read({}), "未观察到索引缺口 · 0 个待发布段");
  assert.equal(read({ notFound: true, pendingSegments: 2 }), "当前索引未命中 · 2 个待发布段");
  assert.equal(mayBeIncomplete("gap"), true);
  assert.equal(mayBeIncomplete("pending"), true);
  assert.equal(mayBeIncomplete("complete"), false);
  assert.equal(mayBeIncomplete("not_indexed"), false);
});

test("watermarks and their scope are spelled out", () => {
  assert.equal(formatWatermark(null), "尚不可用");
  assert.equal(
    formatWatermark({
      producer_boot_id: "018f2a3b-4c5d-7000-8000-000000000088",
      producer_sequence: 42,
    }),
    "018f2a3b-4c5d-7000-8000-000000000088 / 42",
  );
  assert.equal(watermarkScopeLabel("configured_journal"), "配置的日志源");
  assert.equal(watermarkScopeLabel(undefined), "配置的日志源");
});

test("decisions carry a word, an icon and a tone, and missing is not unknown", () => {
  const view = (value: string | null | undefined, pending = false) =>
    describeDecision(value, { pending });
  assert.deepEqual(view("ALLOW"), { tone: "allow", icon: "allow", label: "放行", code: "ALLOW" });
  assert.deepEqual(view("DENY"), { tone: "deny", icon: "deny", label: "拒绝", code: "DENY" });
  assert.equal(view("ERROR").tone, "error");
  assert.equal(view("OBSERVE").tone, "observe");
  assert.equal(view("PASS").label, "通过");
  assert.equal(view("SKIPPED").label, "已跳过");
  assert.equal(view("CANCELLED").label, "已取消");
  assert.equal(view("UNKNOWN").label, "未知");
  // "no decision recorded" and "waiting for the terminal event" are not UNKNOWN.
  assert.equal(view(null).label, "未记录");
  assert.equal(view(undefined).label, "未记录");
  assert.equal(view("").label, "未记录");
  assert.equal(view("ALLOW", true).label, "等待终态");
  assert.equal(view("not_sent").tone, "unknown");
  for (const value of ["ALLOW", "DENY", "ERROR", "OBSERVE", "UNKNOWN", null]) {
    assert.ok(view(value).label.length > 0, String(value));
  }
});

test("errors project to message, stable code and management request id only", () => {
  const request = "req_018f2a3b-4c5d-7000-8000-000000000099";
  const problem = projectError(new ApiError("CONTROL_SCOPE_DENIED", 403, request));
  assert.deepEqual(problem, {
    message: "当前身份没有此作用域的操作权限。",
    code: "CONTROL_SCOPE_DENIED",
    status: 403,
    requestId: request,
  });
  assert.equal(projectError(new ApiError("NETWORK_UNAVAILABLE"))?.status, null);
  // Anything that is not an ApiError never leaks its own message.
  const generic = projectError(new Error("SECRET payload detail"));
  assert.deepEqual(generic, GENERIC_PROBLEM);
  assert.equal(JSON.stringify(generic).includes("SECRET"), false);
  // Nothing to show for a cancelled read or an ended session.
  assert.equal(projectError(new StaleSessionError("epoch")), null);
  assert.equal(projectError(new ApiError("REQUEST_ABORTED")), null);
  const cancelled = new Error("cancelled");
  cancelled.name = "CancelledError";
  assert.equal(projectError(cancelled), null);
  assert.equal(projectError(null), null);
});

test("IDs abbreviate in the middle and keep their prefix", () => {
  const id = "req_018f2a3b-4c5d-7000-8000-000000000001";
  assert.equal(abbreviateId(id), "req_018f2a3b…000001");
  assert.equal(abbreviateId("ev_1"), "ev_1");
  assert.equal(idPrefix(id), "req");
  assert.equal(idPrefix("018f2a3b4c5d70008000000000000003"), null);
});

test("request vocabulary names known values and shows unknown ones as received", () => {
  assert.equal(stageName("operation_admission").label, "操作准入");
  assert.equal(stageName("ui_action").label, "界面来源");
  assert.deepEqual(stageName("brand_new_stage"), { label: "brand_new_stage", known: false });
  assert.deepEqual(stageName(null), { label: "未记录", known: false });
  assert.equal(eventTypeName("request.completed").label, "请求完成");
  assert.equal(eventTypeName("custom.event").label, "custom.event");
  assert.equal(originStateName("not_sent").label, "未转发到源站");
  // A number only when the server gave one; deterministic and Noul stay numberless.
  assert.equal(confidenceText(0.8, "provided"), "0.8");
  assert.equal(confidenceText(null, "not_applicable"), "无置信度（不适用）");
  assert.equal(confidenceText(null, "unavailable"), "置信度不可用");
  assert.equal(confidenceText(null, "not_provided"), "置信度未提供");
  assert.equal(confidenceText(null, null), "未记录");
});
