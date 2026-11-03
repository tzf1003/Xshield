// The model forms (lib/model-form.ts): the checks before a request goes out, what a form holds, the change list
// of a save, and what a test result says. Pinned here so the wording and the rules change on purpose.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { AgentModelValues, JevModelValues, ModelTestResult } from "../src/api/types.ts";
import {
  AGENT_TIMEOUT,
  agentKeyRequired,
  agentProblems,
  agentValues,
  changeText,
  clockText,
  describeTest,
  endpointProblem,
  formChanges,
  formFromValues,
  JEV_TIMEOUT,
  jevProblems,
  jevValues,
  keyProblem,
  modelProblem,
  presetModel,
  sameForm,
  testFailureText,
  timeoutMsOf,
  timeoutProblem,
  withChoice,
} from "../src/lib/model-form.ts";
import { MODEL_TEXT } from "../src/lib/vocab.ts";

const SAVED: JevModelValues = {
  route: "gateway",
  endpoint: "https://ai-gateway.vercel.sh/typesafe/v1/systemone",
  model: "typesafe-ai/jev",
  timeout_ms: 2000,
};

const AGENT_SAVED: AgentModelValues = {
  provider: "gateway",
  endpoint: "https://ai-gateway.vercel.sh/v1",
  model: "openai/gpt-4.1-mini",
  timeout_ms: 30000,
  share_key_with_jev: false,
};

const AT = "2026-11-01T13:19:50.000Z";

function passing(overrides: Partial<ModelTestResult> = {}): ModelTestResult {
  return {
    ok: true,
    latency_ms: 812,
    status: 200,
    failure: null,
    detail: null,
    answer_valid: true,
    answer_reason: null,
    ...overrides,
  };
}

test("endpointProblem takes https addresses and loopback http, and says what is wrong with the rest", () => {
  assert.equal(endpointProblem("https://ai-gateway.vercel.sh/v1"), null);
  assert.equal(endpointProblem("http://127.0.0.1:8080/v1"), null);
  assert.equal(endpointProblem("http://localhost:9000"), null);
  assert.equal(endpointProblem("http://llm.example.com/v1"), MODEL_TEXT.endpointScheme);
  assert.equal(endpointProblem("   "), MODEL_TEXT.endpointRequired);
  assert.equal(
    endpointProblem("https://user:secret@llm.example.com/v1"),
    MODEL_TEXT.endpointCredentials,
  );
  assert.equal(endpointProblem("https://llm.example.com/v1?key=1"), MODEL_TEXT.endpointQuery);
  assert.equal(endpointProblem("llm.example.com"), MODEL_TEXT.endpointUrl);
  assert.equal(endpointProblem(`https://${"a".repeat(2100)}.example.com`), MODEL_TEXT.endpointLong);
});

test("modelProblem asks for a model name in the characters the providers use", () => {
  assert.equal(modelProblem("typesafe-ai/jev"), null);
  assert.equal(modelProblem("openai/gpt-4.1-mini"), null);
  assert.equal(modelProblem(" "), MODEL_TEXT.modelRequired);
  assert.equal(modelProblem("gpt 4"), MODEL_TEXT.modelChars);
  assert.equal(modelProblem("a".repeat(201)), MODEL_TEXT.modelLong);
});

test("timeoutProblem keeps a whole number inside the range of its unit", () => {
  const range = MODEL_TEXT.timeoutRange(100, 30000, MODEL_TEXT.unitMs);
  assert.equal(timeoutProblem("2000", JEV_TIMEOUT, MODEL_TEXT.unitMs), null);
  assert.equal(timeoutProblem(" 100 ", JEV_TIMEOUT, MODEL_TEXT.unitMs), null);
  assert.equal(timeoutProblem("99", JEV_TIMEOUT, MODEL_TEXT.unitMs), range);
  assert.equal(timeoutProblem("30001", JEV_TIMEOUT, MODEL_TEXT.unitMs), range);
  assert.equal(timeoutProblem("2.5", JEV_TIMEOUT, MODEL_TEXT.unitMs), range);
  assert.equal(timeoutProblem("", JEV_TIMEOUT, MODEL_TEXT.unitMs), range);
  assert.equal(timeoutProblem("5", AGENT_TIMEOUT, MODEL_TEXT.unitSeconds), null);
  assert.equal(
    timeoutProblem("121", AGENT_TIMEOUT, MODEL_TEXT.unitSeconds),
    MODEL_TEXT.timeoutRange(5, 120, MODEL_TEXT.unitSeconds),
  );
});

test("keyProblem requires a key where none is saved, and refuses a blank inside one", () => {
  assert.equal(keyProblem("", true), MODEL_TEXT.keyRequired);
  assert.equal(keyProblem("", false), null);
  assert.equal(keyProblem("  sk-live-1  ", false), null);
  assert.equal(keyProblem("sk live", false), MODEL_TEXT.keyWhitespace);
});

test("jevProblems names each field that is wrong, and is empty for a valid form", () => {
  const form = formFromValues("jev", SAVED);
  assert.deepEqual(jevProblems(form, false), {});
  assert.deepEqual(jevProblems({ ...form, endpoint: "", timeout: "5" }, true), {
    endpoint: MODEL_TEXT.endpointRequired,
    timeout: MODEL_TEXT.timeoutRange(100, 30000, MODEL_TEXT.unitMs),
    key: MODEL_TEXT.keyRequired,
  });
});

test("agentProblems checks the timeout in seconds", () => {
  const form = formFromValues("agent", AGENT_SAVED);
  assert.deepEqual(agentProblems(form, false), {});
  assert.deepEqual(agentProblems({ ...form, timeout: "400" }, false), {
    timeout: MODEL_TEXT.timeoutRange(5, 120, MODEL_TEXT.unitSeconds),
  });
});

test("agentKeyRequired asks for the agent's own key once a form stops sharing Jev's", () => {
  // Sharing cleared the agent's own key, so a form that stops sharing has to bring one.
  assert.equal(agentKeyRequired(true, { set: true, shared_with_jev: true }), false);
  assert.equal(agentKeyRequired(false, { set: true, shared_with_jev: false }), false);
  assert.equal(agentKeyRequired(false, { set: false, shared_with_jev: false }), true);
  assert.equal(agentKeyRequired(false, { set: true, shared_with_jev: true }), true);
});

test("sameForm compares what a test tried, key included, ignoring blanks at the ends", () => {
  const form = formFromValues("jev", SAVED);
  assert.equal(sameForm(form, { ...form, endpoint: ` ${form.endpoint} ` }), true);
  assert.equal(sameForm(form, { ...form, timeout: "3000" }), false);
  assert.equal(sameForm(form, { ...form, key: "sk-new" }), false);
});

test("formFromValues and jevValues carry a configuration in and out", () => {
  const form = formFromValues("jev", SAVED);
  assert.deepEqual(form, {
    choice: "gateway",
    endpoint: SAVED.endpoint,
    model: SAVED.model,
    timeout: "2000",
    shareKey: false,
    key: "",
  });
  assert.deepEqual(jevValues({ ...form, timeout: " 3000 " }), { ...SAVED, timeout_ms: 3000 });
});

test("a preset line without a saved address or model takes the route's own", () => {
  const form = formFromValues("jev", {
    route: "direct",
    endpoint: null,
    model: null,
    timeout_ms: 3000,
  });
  assert.equal(form.endpoint, "https://api.typesafe.ai/v1/systemone");
  assert.equal(form.model, "typesafe-ai/jev");
  assert.equal(form.timeout, "3000");
});

test("an agent form shows its timeout in seconds, and agentValues sends milliseconds", () => {
  const form = formFromValues("agent", AGENT_SAVED);
  assert.equal(form.timeout, "30");
  assert.equal(form.shareKey, false);
  assert.deepEqual(agentValues(form), AGENT_SAVED);
});

test("withChoice puts a preset line's own address and model in, and keeps what a custom line typed", () => {
  const form = formFromValues("jev", SAVED);
  const direct = withChoice("jev", form, "direct");
  assert.equal(direct.endpoint, "https://api.typesafe.ai/v1/systemone");
  assert.equal(direct.model, "typesafe-ai/jev");
  const custom = withChoice(
    "jev",
    { ...form, endpoint: "https://llm.example.com/v1", model: "jev-x" },
    "custom",
  );
  assert.equal(custom.endpoint, "https://llm.example.com/v1");
  assert.equal(custom.model, "jev-x");
  assert.equal(presetModel("direct"), "typesafe-ai/jev");
  assert.equal(presetModel("custom"), null);
});

test("withChoice on the agent sets the gateway address, and drops the shared key on a custom provider", () => {
  const form = { ...formFromValues("agent", AGENT_SAVED), shareKey: true };
  const custom = withChoice("agent", form, "custom");
  assert.equal(custom.shareKey, false);
  assert.equal(custom.endpoint, AGENT_SAVED.endpoint);
  const gateway = withChoice("agent", custom, "gateway");
  assert.equal(gateway.endpoint, "https://ai-gateway.vercel.sh/v1");
});

test("formChanges lists the fields that differ, the key by its last four, and what a restore keeps", () => {
  const saved = formFromValues("jev", SAVED);
  assert.deepEqual(formChanges("jev", saved, saved, "9f3a"), []);
  const next = { ...saved, timeout: "3000", key: "sk-live-7d20" };
  assert.deepEqual(formChanges("jev", saved, next, "9f3a"), [
    { label: MODEL_TEXT.rowTimeout, detail: "2000 ms → 3000 ms" },
    { label: MODEL_TEXT.rowKey, detail: "已替换（…9f3a → …7d20）" },
  ]);
  assert.deepEqual(formChanges("jev", saved, saved, "9f3a", true), [
    { label: MODEL_TEXT.rowKey, detail: "保持当前的 …9f3a" },
  ]);
});

test("formChanges names a route switch and an agent's shared key in words", () => {
  const saved = formFromValues("jev", SAVED);
  const [route] = formChanges("jev", saved, withChoice("jev", saved, "direct"), "9f3a");
  assert.deepEqual(route, {
    label: MODEL_TEXT.rowRoute,
    detail: "Vercel AI Gateway → TypeSafe 直连",
  });
  const agent = formFromValues("agent", AGENT_SAVED);
  assert.deepEqual(formChanges("agent", agent, { ...agent, shareKey: true }, "c81d"), [
    { label: MODEL_TEXT.shareKeyLabel, detail: MODEL_TEXT.changeYes },
  ]);
});

test("testFailureText says a failure in words, with its status and the timeout", () => {
  assert.equal(testFailureText(401, null, 2000), MODEL_TEXT.testFailUnauthorized);
  assert.equal(testFailureText(451, null, 2000), MODEL_TEXT.testFailRegion);
  assert.equal(testFailureText(429, null, 2000), MODEL_TEXT.testFailRate);
  assert.equal(testFailureText(null, "JEV_TIMEOUT", 2000), "失败：超时（2,000 ms）");
  assert.equal(testFailureText(null, "dns", 2000), MODEL_TEXT.testFailDns);
  assert.equal(testFailureText(500, "JEV_HTTP_ERROR", 2000), "失败：500，服务出错");
  assert.equal(testFailureText(null, null, 2000), "失败：未知错误");
});

test("describeTest reads a passing test, an answer that does not parse, and a failure", () => {
  const ok = describeTest("jev", passing(), 2000, AT);
  assert.equal(ok.tone, "ok");
  assert.match(ok.text, /^\d{2}:\d{2}:\d{2} 成功 · 812 ms · 模型返回了合法的回答$/);
  assert.equal(ok.detail, null);

  const invalid = describeTest(
    "jev",
    passing({
      ok: false,
      failure: "answer_invalid",
      answer_valid: false,
      answer_reason: "缺少 access 字段",
    }),
    2000,
    AT,
  );
  assert.equal(invalid.tone, "warn");
  assert.equal(invalid.text, `${MODEL_TEXT.testAnswerInvalid}：缺少 access 字段`);
  assert.equal(invalid.hint, MODEL_TEXT.testWrongModelHint);

  const failed = describeTest(
    "agent",
    passing({ ok: false, status: 401, answer_valid: null, detail: "bad key" }),
    30000,
    AT,
  );
  assert.equal(failed.tone, "bad");
  assert.equal(failed.text, MODEL_TEXT.testFailUnauthorized);
  assert.equal(failed.detail, "bad key");
});

test("timeoutMsOf turns the typed timeout into milliseconds for each kind", () => {
  assert.equal(timeoutMsOf("jev", formFromValues("jev", SAVED)), 2000);
  assert.equal(timeoutMsOf("agent", formFromValues("agent", AGENT_SAVED)), 30000);
});

test("changeText says a history change in words, and the key by its last four", () => {
  assert.equal(
    changeText({ field: "route", old: "direct", new: "gateway" }, "jev"),
    "线路 TypeSafe 直连 → Vercel AI Gateway",
  );
  assert.equal(
    changeText({ field: "timeout_ms", old: "3000", new: "2000" }, "jev"),
    "超时 3000 ms → 2000 ms",
  );
  assert.equal(
    changeText({ field: "timeout_ms", old: "60000", new: "30000" }, "agent"),
    "超时 60 秒 → 30 秒",
  );
  assert.equal(
    changeText({ field: "key", old: "1c2e", new: "9f3a" }, "jev"),
    "已替换（…1c2e → …9f3a）",
  );
  assert.equal(changeText({ field: "key", old: "", new: "9f3a" }, "jev"), "已设置（…9f3a）");
  assert.equal(changeText({ field: "key", old: "9f3a", new: "" }, "jev"), "已清除（原 …9f3a）");
  assert.equal(
    changeText({ field: "share_key_with_jev", old: "false", new: "true" }, "agent"),
    "与 Jev 共用密钥 否 → 是",
  );
});

test("clockText shows the local time of day, and a time it cannot read as a dash", () => {
  assert.match(clockText(AT), /^\d{2}:\d{2}:\d{2}$/);
  assert.equal(clockText("not a time"), "—");
});
