import assert from "node:assert/strict";
import { test } from "node:test";
import type {
  FieldKindDeclaration,
  LearningSettings,
  RouteRule,
  SiteSpec,
} from "../src/api/types.ts";
import { semanticChanges } from "../src/lib/diff.ts";

// The changes of a configuration in words, for the version history and the save dialog: the interface-name rules
// and the object map settings, next to the entries and the other settings (docs/06 6.4.9, design 5).

const GATEWAY = "/weixin/wx/mp/wx361163d21a65f679/gateway";

const base: SiteSpec = {
  name: "juice",
  hosts: ["juice.example.com"],
  origin: "http://10.0.0.9:3000",
  session: { header: "Authorization" },
  entries: ["/rest/user/login"],
};

function withRoutes(routes: RouteRule[]): SiteSpec {
  return { ...base, routes };
}

function withKinds(fieldKinds: FieldKindDeclaration[]): SiteSpec {
  return { ...base, objects: { field_kinds: fieldKinds } };
}

const learning: LearningSettings = {
  auto_learn: true,
  auto_tighten: false,
  agent: { enabled: false, daily_limit: 20 },
  thresholds: { uses: 5, sessions: 3 },
  auto_pause: true,
};

test("接口名规则的增加、删除和改动各写一行", () => {
  const before = withRoutes([
    { path: GATEWAY, name_from: [["body.method"]] },
    { path: "/old/gateway", name_from: [["query.op"]] },
  ]);
  const after = withRoutes([
    { path: GATEWAY, name_from: [["body.method"], ["body.kind"]] },
    { path: "/new/gateway", name_from: [["query.op"]] },
  ]);

  assert.deepEqual(semanticChanges(before, after), [
    "接口名规则 ＋1：/new/gateway",
    "接口名规则 －1：/old/gateway",
    `接口名规则 改动：${GATEWAY}`,
  ]);
});

test("字段归类改成另一类时，写出响应的范围、字段和两个类别", () => {
  const before = withKinds([
    { field: "attachments[].doc_id", kind: "doctor", in: ["/api/records/{id}"] },
  ]);
  const after = withKinds([
    { field: "attachments[].doc_id", kind: "document", in: ["/api/records/{id}"] },
  ]);

  assert.deepEqual(semanticChanges(before, after), [
    "响应 /api/records/{id} attachments[].doc_id 从医生改为文档",
  ]);
});

test("没有范围的字段归类写作字段，增加时不带范围", () => {
  assert.deepEqual(semanticChanges(base, withKinds([{ field: "patient_no", kind: "patient" }])), [
    "字段归类 ＋1：patient_no 归为患者",
  ]);
  assert.deepEqual(
    semanticChanges(
      withKinds([{ field: "owner", kind: "doctor" }]),
      withKinds([{ field: "owner", kind: "patient" }]),
    ),
    ["字段 owner 从医生改为患者"],
  );
});

test("带范围的字段归类增加或删除时注明范围", () => {
  const before = withKinds([{ field: "idcard", kind: "patient", in: ["/api/files/*"] }]);
  const after = withKinds([
    { field: "doc_id", kind: "document", in: ["/api/records/*", "/api/files/*"] },
  ]);

  assert.deepEqual(semanticChanges(before, after), [
    "字段归类 ＋1：doc_id 归为文档（仅 /api/records/*、/api/files/*）",
    "字段归类 －1：idcard（仅 /api/files/*）",
  ]);
});

test("类别没有中文名时，写出类别编号本身", () => {
  assert.deepEqual(semanticChanges(base, withKinds([{ field: "sku", kind: "vendor_code" }])), [
    "字段归类 ＋1：sku 归为vendor_code",
  ]);
});

test("学习设置的每一项都写出来，没有学习设置的按默认值计", () => {
  assert.deepEqual(semanticChanges(base, { ...base, objects: { learning } }), [
    "学习 自动学习 默认 → 开",
    "学习 自动收紧 默认 → 关",
    "学习 自动暂停 默认 → 开",
    "学习 agent 默认 → 关",
    "学习 agent 每日上限 默认 → 20 次",
    "学习 学习阈值 默认 → 5 次 / 3 个会话",
  ]);
});

test("只有一项学习设置变了时，只写那一项", () => {
  const before: SiteSpec = { ...base, objects: { learning } };
  const after: SiteSpec = { ...base, objects: { learning: { ...learning, auto_tighten: true } } };

  assert.deepEqual(semanticChanges(before, after), ["学习 自动收紧 关 → 开"]);
});

test("没有变化时，路由和对象设置都不写出任何改动", () => {
  assert.deepEqual(semanticChanges(base, base), []);
  const same = withRoutes([{ path: GATEWAY, name_from: [["body.method"]] }]);
  assert.deepEqual(semanticChanges(same, structuredClone(same)), []);
  assert.deepEqual(semanticChanges(withKinds([]), { ...base, objects: {} }), []);
});
