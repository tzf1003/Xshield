import assert from "node:assert/strict";
import { test } from "node:test";
import type { JevRecord, Trace, TraceValue } from "../src/api/types.ts";
import { alignRecent, alignValues, trimNote, valueHint } from "../src/lib/align.ts";
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

function trace(values: TraceValue[], extra: Partial<Trace> = {}): Trace {
  return { v: 1, values, ...extra };
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

test("a DENY explains the value and where the origin showed it", () => {
  const text = explainRecord({
    decision_path: "jev_deny",
    outcome: "would_block",
    status: 200,
    host: "juice.example.com",
    trace: trace([
      value({ at: "path[2]", value: "6", seen: true, sources: [{ field: "quantity", request: "GET /rest/basket/1", request_id: ID, at_millis: 0 }] }),
    ]),
    jev: jev({}),
  });
  assert.equal(
    text,
    "Jev 判定越权（DENY 86%）：路径里的6 在这个会话里没有以同类对象出现过，只以 quantity 出现在 GET /rest/basket/1 的响应里。站点处于观察模式，请求照常转发。",
  );
});

test("an attack is explained with the value that carried it", () => {
  const text = explainRecord({
    decision_path: "jev_deny",
    outcome: "blocked",
    status: 403,
    host: "emr.example.com",
    trace: trace([value({ at: "body.q", value: "x' OR sleep(5)=0 --", kind: "input" })]),
    jev: jev({ attack: { BENIGN: 0.04, ATTACK: 0.95, UNKNOWN: 0.01 } }),
  });
  assert.match(text, /^Jev 判定为攻击（ATTACK 95%）：请求体里的 body\.q 的值含 `x' OR sleep\(5\)=0 --`。返回 403。$/);
});

test("the other decision paths give their documented reason", () => {
  const base = { status: 200, host: "juice.example.com", jev: null };
  assert.equal(
    explainRecord({ ...base, decision_path: "bypass", outcome: "allowed", trace: trace([], { bypass: "/assets/*" }) }),
    "命中绕过规则 /assets/*，没有判定，直接转发。",
  );
  assert.equal(
    explainRecord({ ...base, decision_path: "fast_allow", outcome: "allowed", trace: trace([value({ at: "path[2]", value: "6", verified: true, seen: true })]) }),
    "1 个需核验的值都已核验，没有调用 Jev。",
  );
  assert.equal(
    explainRecord({ ...base, decision_path: "no_session", outcome: "would_block", trace: trace([]) }),
    "请求没有会话凭证，路径也不是入口。站点处于观察模式，请求照常转发。",
  );
  assert.equal(
    explainRecord({ ...base, status: null, decision_path: "unknown_site", outcome: "blocked", host: "other.example.com", trace: trace([]) }),
    "Host other.example.com 不属于任何站点。",
  );
  assert.equal(
    explainRecord({ ...base, decision_path: "jev_unavailable", outcome: "unjudged", trace: trace([]), jev: jev({ failure: "JEV_TIMEOUT", access: null, attack: null, timeout_ms: 3000 }) }),
    "Jev 调用超时（3000 ms）。站点设置为 Jev 不可用时放行，这个请求没有经过判定。",
  );
  assert.equal(
    explainRecord({ ...base, decision_path: "jev_unavailable", outcome: "blocked", context: "address", status: 403, trace: trace([]), jev: jev({ failure: "JEV_CALL_LIMIT", access: null, attack: null, state: null }) }),
    "本地址每分钟 Jev 调用已达上限，没有调用 Jev。返回 403。",
  );
});

test("an upstream failure is appended and an old record says so", () => {
  const text = explainRecord({
    decision_path: "fast_allow",
    outcome: "allowed",
    status: 502,
    host: "juice.example.com",
    trace: trace([], { upstream_error: "connect_refused" }),
    jev: null,
  });
  assert.equal(text, "请求里没有需要核验的值，没有调用 Jev。源站连接被拒绝，网关返回 502。");
  assert.equal(
    explainRecord({ decision_path: "jev_deny", outcome: "blocked", status: 403, host: "x", trace: { v: 0 }, jev: null }),
    "旧格式记录：没有判定依据。返回 403。",
  );
});

test("values align with the non-inert entries of the trace, in order", () => {
  const values = [
    value({ at: "path[0]", value: "rest", kind: "route", inert: true }),
    value({ at: "path[2]", value: "6" }),
    value({ at: "body.items[].id", value: "9" }),
  ];
  const aligned = alignValues(values);
  assert.deepEqual(
    aligned.map((item) => [item.jevIndex, item.traceIndex]),
    [
      [0, 1],
      [1, 2],
    ],
  );
});

test("the state's recent list is the tail of the trace's list", () => {
  const recent = [1, 2, 3, 4, 5].map((n) => ({ method: "GET", path: `/p/${n}`, status: 200, request_id: null, at_millis: n }));
  assert.deepEqual(alignRecent(2, recent).map((r) => r.path), ["/p/4", "/p/5"]);
  assert.deepEqual(alignRecent(9, recent).length, 5);
  assert.deepEqual(alignRecent(3, null), []);
});

test("trim levels say what was dropped", () => {
  assert.equal(trimNote(0), null);
  assert.equal(trimNote(1), "为满足 8 KiB 上限，最近访问从 10 条减到 3 条");
  assert.match(trimNote(4) ?? "", /128/);
});

test("the reading of a value follows the verified and seen flags", () => {
  assert.deepEqual(valueHint({ kind: "reference", seen_as: [], verified: false }), { tone: "bad", text: "从未见过" });
  assert.deepEqual(valueHint({ kind: "reference", seen_as: ["quantity @ GET /x"], verified: false }), {
    tone: "warn",
    text: "见过但不是同类对象",
  });
  assert.deepEqual(valueHint({ kind: "reference", seen_as: ["id"], verified: true }), { tone: "ok", text: "已核验" });
  assert.deepEqual(valueHint({ kind: "route", seen_as: [] }), { tone: "none", text: "路由词" });
});
