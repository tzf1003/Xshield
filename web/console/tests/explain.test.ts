import assert from "node:assert/strict";
import { test } from "node:test";
import type { JevRecord, Trace, TraceSource, TraceValue } from "../src/api/types.ts";
import { apiTitle, unknownReasonText } from "../src/lib/api-name.ts";
import { explainRecord } from "../src/lib/explain.ts";

const ID = "req_01a1973f5b2a7c41a0d3e7f6b1c2d3e4";

function value(partial: Partial<TraceValue> & Pick<TraceValue, "at" | "value">): TraceValue {
  return {
    key: null,
    kind: "reference",
    inert: false,
    seen: false,
    verified: false,
    sources: [],
    ...partial,
  };
}

function trace(values: TraceValue[]): Trace {
  return { v: 1, values };
}

function jev(partial: Partial<JevRecord>): JevRecord {
  return {
    state: null,
    prompt: "jq_5c2e81d07a4b9f13",
    model: "typesafe-ai/jev",
    route: "gateway",
    timeout_ms: 2000,
    trim: 0,
    request_bytes: 3412,
    http_status: 200,
    response: null,
    usage: null,
    access: { ALLOW: 0.12, DENY: 0.86, UNKNOWN: 0.02 },
    attack: { BENIGN: 0.99, ATTACK: 0.01, UNKNOWN: 0 },
    conclusion: "deny",
    millis: 512,
    failure: null,
    ...partial,
  };
}

test("fast_allow names the object classes that the object map gave", () => {
  const text = explainRecord({
    decision_path: "fast_allow",
    outcome: "allowed",
    status: 200,
    host: "emr.example.com",
    jev: null,
    trace: trace([
      value({
        at: "path[1]",
        value: "5",
        verified: true,
        seen: true,
        object: "doctor",
        object_from: "map",
      }),
      value({
        at: "query.q",
        value: "x",
        verified: true,
        seen: true,
        object: "patient",
        object_from: "map",
      }),
      value({
        at: "body.n",
        value: "3",
        verified: true,
        seen: true,
        object: "doctor",
        object_from: "map",
      }),
    ]),
  });
  assert.equal(text, "3 个需核验的值都已核验（按对象表：doctor、patient），没有调用 Jev。");
});

test("fast_allow adds no class when the classes were only inferred from names", () => {
  const text = explainRecord({
    decision_path: "fast_allow",
    outcome: "allowed",
    status: 200,
    host: "emr.example.com",
    jev: null,
    trace: trace([
      value({ at: "path[1]", value: "5", verified: true, seen: true, object: "doctor" }),
    ]),
  });
  assert.equal(text, "1 个需核验的值都已核验，没有调用 Jev。");
});

test("a value that carries the interface name is not a checked value", () => {
  const text = explainRecord({
    decision_path: "fast_allow",
    outcome: "allowed",
    status: 200,
    host: "juice.example.com",
    jev: null,
    api: { name: "bus.buriedPointService/saveBuriedPointList", from: ["query.by"] },
    trace: trace([
      value({ at: "query.by", value: "saveBuriedPointList" }),
      value({ at: "path[2]", value: "6", verified: true, seen: true }),
    ]),
  });
  assert.equal(text, "1 个需核验的值都已核验，没有调用 Jev。");
});

test("a DENY on a value that the origin showed as another class says so", () => {
  const source: TraceSource = {
    field: "doc_id",
    request: "GET /api/records/7",
    request_id: ID,
    at_millis: 0,
    object: "document",
    object_from: "map",
  };
  const text = explainRecord({
    decision_path: "jev_deny",
    outcome: "blocked",
    status: 403,
    host: "emr.example.com",
    jev: jev({}),
    trace: trace([
      value({
        at: "path[1]",
        value: "5",
        seen: true,
        object: "doctor",
        object_from: "map",
        sources: [source],
      }),
    ]),
  });
  assert.equal(
    text,
    "Jev 判定越权（DENY 86%）：路径里的5 在这个会话里只以 document 出现过，现在用作 doctor。返回 403。",
  );
});

test("an unknown interface name is said first, with its reason", () => {
  const text = explainRecord({
    decision_path: "no_session",
    outcome: "would_block",
    status: 200,
    host: "emr.example.com",
    jev: null,
    api: { unknown: "repeated", source: "header.X-Service-Method" },
    trace: trace([]),
  });
  assert.equal(
    text,
    "未知接口：X-Service-Method 出现了多次，按未知接口处理（不算入口、不走绕过）。请求没有会话凭证，路径也不是入口。站点处于观察模式，请求照常转发。",
  );
});

test("a name says where each of its segments came from", () => {
  assert.equal(
    apiTitle({
      name: "bus.buriedPointService/saveBuriedPointList",
      from: ["header.X-Service-Id", "header.X-Service-Method"],
    }),
    "接口名来自请求头 X-Service-Id、X-Service-Method",
  );
  assert.equal(
    apiTitle({ name: "orders/list", from: ["query.by", "body.kind"] }),
    "接口名来自查询参数 by；正文字段 kind",
  );
});

test("a reason names its source, and a code the console does not know falls back", () => {
  assert.equal(unknownReasonText("invalid_name", "query.by"), "by 的值不合规");
  assert.equal(unknownReasonText("route_subpath"), "路径在规则之下还有子路径");
  assert.equal(unknownReasonText("bogus_code"), "未知原因（bogus_code）");
});

test("a function attempt is named before the reason, and no value is said never seen", () => {
  const text = explainRecord({
    decision_path: "jev_deny",
    outcome: "blocked",
    status: 403,
    host: "emr.example.com",
    jev: jev({}),
    trace: {
      v: 1,
      values: [],
      function: {
        key: "POST /api/admin/export",
        entry: "POST /api/admin/export",
        tier: "admin",
        attempt: "over_privilege",
      },
    },
  });
  assert.equal(
    text,
    "请求的是管理档功能 POST /api/admin/export，这个会话不是管理员。Jev 判定越权（DENY 86%）。返回 403。",
  );
  assert.equal(text.includes("从未出现过"), false);
});

test("an unknown function is named before the reason", () => {
  const text = explainRecord({
    decision_path: "jev_allow",
    outcome: "allowed",
    status: 200,
    host: "emr.example.com",
    jev: jev({
      access: { ALLOW: 0.97, DENY: 0.02, UNKNOWN: 0.01 },
      attack: { BENIGN: 0.99, ATTACK: 0.01, UNKNOWN: 0 },
    }),
    trace: { v: 1, values: [], function: { key: "GET /metrics", known: false } },
  });
  assert.equal(
    text,
    "功能 GET /metrics 不在功能表里。Jev 判定访问有依据（ALLOW 97%）、内容无攻击（BENIGN 99%）。",
  );
});

test("an administrator's session on an entry is not named in the explanation", () => {
  const text = explainRecord({
    decision_path: "jev_allow",
    outcome: "allowed",
    status: 200,
    host: "emr.example.com",
    jev: jev({
      access: { ALLOW: 0.97, DENY: 0.02, UNKNOWN: 0.01 },
      attack: { BENIGN: 0.99, ATTACK: 0.01, UNKNOWN: 0 },
    }),
    trace: {
      v: 1,
      values: [],
      function: { key: "GET /api/admin/y", entry: "GET /api/admin/y", tier: "admin" },
    },
  });
  assert.equal(text, "Jev 判定访问有依据（ALLOW 97%）、内容无攻击（BENIGN 99%）。");
});

test("a long function key is cut in the explanation", () => {
  const long = `POST /api/admin/${"x".repeat(100)}`;
  const attempt = explainRecord({
    decision_path: "jev_deny",
    outcome: "blocked",
    status: 403,
    host: "emr.example.com",
    jev: jev({}),
    trace: {
      v: 1,
      values: [],
      function: { key: long, entry: long, tier: "admin", attempt: "over_privilege" },
    },
  });
  assert.equal(
    attempt,
    `请求的是管理档功能 ${long.slice(0, 80)}…，这个会话不是管理员。Jev 判定越权（DENY 86%）。返回 403。`,
  );

  const unknown = explainRecord({
    decision_path: "jev_allow",
    outcome: "allowed",
    status: 200,
    host: "emr.example.com",
    jev: jev({
      access: { ALLOW: 0.97, DENY: 0.02, UNKNOWN: 0.01 },
      attack: { BENIGN: 0.99, ATTACK: 0.01, UNKNOWN: 0 },
    }),
    trace: { v: 1, values: [], function: { key: long, known: false } },
  });
  assert.equal(
    unknown,
    `功能 ${long.slice(0, 80)}… 不在功能表里。Jev 判定访问有依据（ALLOW 97%）、内容无攻击（BENIGN 99%）。`,
  );
});
