import assert from "node:assert/strict";
import { test } from "node:test";
import { parseFilter, serializeFilter } from "../src/lib/filter-dsl.ts";

test("keys in one term are alternatives, separate terms are combined", () => {
  const parsed = parseFilter("outcome:blocked,would_block path:/rest/* site:juice");
  assert.deepEqual(parsed.errors, []);
  assert.deepEqual(parsed.params, {
    outcome: "blocked,would_block",
    path: "/rest/*",
    site: "juice",
  });
});

test("comparisons map to the numeric parameters", () => {
  const parsed = parseFilter("conf<70% ms>1000 version:7 entry:true");
  assert.deepEqual(parsed.errors, []);
  assert.deepEqual(parsed.params, {
    max_confidence: "0.7",
    min_ms: "1000",
    site_version: "7",
    entry: "true",
  });
  assert.equal(parseFilter("conf<0.7").params.max_confidence, "0.7");
});

test("bare words are recognised by shape", () => {
  const parsed = parseFilter(
    "/rest/basket/6 req_01a19741107477ff9224781077354552 7c1e9a40d2b35f61 get",
  );
  assert.deepEqual(parsed.errors, []);
  assert.deepEqual(parsed.params, {
    path: "/rest/basket/6",
    request_id: "req_01a19741107477ff9224781077354552",
    session: "7c1e9a40d2b35f61",
    method: "GET",
  });
});

test("errors point at the term that caused them", () => {
  const parsed = parseFilter("outcome:bogus path:x status:99 flavour:red");
  assert.equal(parsed.errors.length, 4);
  assert.equal(parsed.errors[0]?.term, "outcome:bogus");
  assert.equal(parsed.errors[0]?.index, 0);
  assert.equal(parsed.errors[1]?.message, "路径必须以 / 开头");
  assert.equal(parsed.errors[3]?.message, "不认识的条件：flavour");
});

test("a key may appear only once", () => {
  const parsed = parseFilter("outcome:blocked outcome:allowed");
  assert.equal(parsed.errors.length, 1);
  assert.match(parsed.errors[0]?.message ?? "", /只能出现一次/);
});

test("serialising and parsing again gives the same parameters", () => {
  const cases: Record<string, string>[] = [
    { outcome: "blocked,would_block", path: "/rest/*", status: "4xx" },
    { decision_path: "jev_deny,no_session", method: "POST", entry: "false" },
    { jev_access: "DENY", jev_attack: "ATTACK", jev_failure: "JEV_TIMEOUT" },
    { max_confidence: "0.85", min_ms: "1500", site_version: "12", site: "emr" },
    { request_id: "req_01a19741107477ff9224781077354552", session: "7c1e9a40d2b35f61" },
    { client: "192.168.1.20" },
  ];
  for (const params of cases) {
    const text = serializeFilter(params);
    const again = parseFilter(text);
    assert.deepEqual(again.errors, [], text);
    assert.deepEqual(again.params, params, text);
  }
});

test("the interface name and the object class are conditions of their own", () => {
  const parsed = parseFilter("path:/weixin/* api:saveBuriedPointList object:doctor api:unknown");
  assert.deepEqual(parsed.errors, []);
  assert.deepEqual(parsed.params, {
    path: "/weixin/*",
    api: "saveBuriedPointList",
    object: "doctor",
    api_unknown: "any",
  });
});

test("api:unknown may name one reason code, and the code is checked", () => {
  assert.deepEqual(parseFilter("api:unknown:repeated").params, { api_unknown: "repeated" });
  const bad = parseFilter("api:unknown:bogus");
  assert.equal(bad.errors.length, 1);
  assert.match(bad.errors[0]?.message ?? "", /未知接口原因无效：bogus/);
  // Written twice, the unknown-name condition is a repeated key, whatever its reason.
  const twice = parseFilter("api:unknown api:unknown:repeated");
  assert.match(twice.errors[0]?.message ?? "", /只能出现一次/);
});

test("a malformed interface name or class id says why it is not valid", () => {
  const parsed = parseFilter("api: object:doc,tor api:a:b");
  assert.equal(parsed.errors.length, 3);
  assert.equal(parsed.errors[0]?.message, "接口名为 1 到 64 个字符，只能用字母、数字、. _ - /");
  assert.equal(parsed.errors[1]?.message, "类别 id 为 1 到 64 个字母、数字、_ 或 -");
});

test("the interface and object conditions serialise and parse back to the same parameters", () => {
  const cases: Record<string, string>[] = [
    { api: "bus.buriedPointService/saveBuriedPointList", path: "/weixin/*" },
    { api_unknown: "any", object: "doctor" },
    { api_unknown: "invalid_name", api: "save", decision_path: "jev_deny" },
  ];
  for (const params of cases) {
    const text = serializeFilter(params);
    const again = parseFilter(text);
    assert.deepEqual(again.errors, [], text);
    assert.deepEqual(again.params, params, text);
  }
  assert.equal(serializeFilter({ api_unknown: "any" }), "api:unknown");
});
