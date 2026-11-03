// The status lines of the model cards and the grace period of a saved version (lib/model-status.ts, design 2.1 and
// 3.6). Each function takes the time as an argument, so the tests pin the boundaries without a clock.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { AgentModelsState, JevModelsState, ModelCall, ModelLoad } from "../src/api/types.ts";
import {
  agentStatusLine,
  callShort,
  jevNotLoaded,
  jevStatusLine,
  jevWaitingForLoad,
  LOAD_GRACE_MS,
  LOAD_POLL_MS,
  notLoadedSummary,
} from "../src/lib/model-status.ts";
import { MODEL_TEXT } from "../src/lib/vocab.ts";

const NOW = Date.parse("2026-11-01T13:20:00.000Z");
const RECENT = new Date(NOW - 30_000).toISOString();
const OLD = "2026-11-01T12:40:00.000Z";

function load(
  edge: string,
  version: number | null,
  error: string | null = null,
  online = true,
): ModelLoad {
  return { edge, online, version, error };
}

function jev(overrides: Partial<JevModelsState> = {}): JevModelsState {
  return {
    route: "gateway",
    endpoint: "https://ai-gateway.vercel.sh/typesafe/v1/systemone",
    model: "typesafe-ai/jev",
    timeout_ms: 2000,
    source: "console",
    version: 14,
    updated_at: OLD,
    key: { set: true, last4: "9f3a", updated_at: OLD },
    key_env: "AI_GATEWAY_API_KEY",
    env_overridden: [],
    env_available: true,
    loaded: [load("edge-1", 14), load("edge-2", 14)],
    usage: { window: "1h", calls: 0, failed: 0, p95_ms: null },
    last_call: null,
    impact: { sites: 2, fail_closed: [], timeout_overrides: 0 },
    ...overrides,
  };
}

function agent(overrides: Partial<AgentModelsState> = {}): AgentModelsState {
  return {
    provider: "vercel_gateway",
    endpoint: "https://ai-gateway.vercel.sh/v1",
    model: "openai/gpt-4.1-mini",
    timeout_ms: 30000,
    share_key_with_jev: false,
    configured: true,
    version: 3,
    updated_at: OLD,
    key: { set: true, last4: "c81d", updated_at: OLD, shared_with_jev: false },
    health: "ok",
    usage: { window: "today", calls: 0, ok: 0, failed: 0, top_failure: null, enabled_sites: 0 },
    sites: [],
    last_call: null,
    ...overrides,
  };
}

function call(overrides: Partial<ModelCall> = {}): ModelCall {
  return { at: OLD, ok: false, status: null, failure: null, ...overrides };
}

test("the grace period is a minute and the card polls every five seconds (design 2.5, 3.6)", () => {
  assert.equal(LOAD_GRACE_MS, 60_000);
  assert.equal(LOAD_POLL_MS, 5_000);
});

test("callShort names a failed call by its status first, then by its failure code", () => {
  assert.equal(callShort({ status: 401, failure: "JEV_HTTP_ERROR" }), "401 未授权");
  assert.equal(callShort({ status: 429, failure: null }), "429 服务限流");
  assert.equal(callShort({ status: null, failure: "JEV_TIMEOUT" }), "超时");
  assert.equal(callShort({ status: 500, failure: "JEV_HTTP_ERROR" }), "500 服务出错");
  assert.equal(callShort({ status: 404, failure: null }), "404 未知错误");
  assert.equal(callShort({ status: null, failure: null }), "未知错误");
});

test("an environment-supplied configuration shows how many gateways read it", () => {
  const env = jev({ source: "env", version: null, updated_at: null });
  assert.deepEqual(jevStatusLine(env, NOW), {
    tone: "ok",
    icon: "●",
    text: "2 个网关读取环境变量的配置",
  });
  assert.deepEqual(jevStatusLine({ ...env, loaded: [] }, NOW), {
    tone: "neutral",
    icon: "–",
    text: MODEL_TEXT.onlineNone,
  });
});

test("a console configuration that every online gateway runs reads as loaded", () => {
  assert.deepEqual(jevStatusLine(jev(), NOW), {
    tone: "ok",
    icon: "●",
    text: "2/2 个网关已加载第 14 版",
  });
});

test("an offline gateway is left out of the count", () => {
  const withOffline = jev({ loaded: [load("edge-1", 14), load("edge-3", 13, null, false)] });
  assert.equal(jevStatusLine(withOffline, NOW).text, "1/1 个网关已加载第 14 版");
});

test("a gateway behind the version waits inside the grace period, and is named after it", () => {
  const waiting = jev({
    updated_at: RECENT,
    loaded: [load("edge-1", 14), load("edge-2", 13)],
  });
  assert.deepEqual(jevStatusLine(waiting, NOW), {
    tone: "neutral",
    icon: "○",
    text: "等待网关加载第 14 版…",
  });
  const behind = jev({ loaded: [load("edge-1", 14), load("edge-2", 13)] });
  assert.deepEqual(jevStatusLine(behind, NOW), {
    tone: "warn",
    icon: "▲",
    text: "edge-2 仍在用第 13 版",
  });
});

test("a gateway that refused the version says why, even inside the grace period", () => {
  const refused = jev({
    updated_at: RECENT,
    loaded: [load("edge-1", 14), load("edge-2", 13, "MODEL_KEY_UNREADABLE")],
  });
  assert.deepEqual(jevStatusLine(refused, NOW), {
    tone: "warn",
    icon: "▲",
    text: "edge-2 仍在用第 13 版：密钥无法解密",
  });
});

test("a gateway with no version yet says it has not loaded a configuration", () => {
  const none = jev({ loaded: [load("edge-1", 14), load("edge-2", null)] });
  assert.equal(jevStatusLine(none, NOW).text, "edge-2 还没有加载配置");
  assert.equal(jevStatusLine(none, NOW).tone, "warn");
});

test("with no online gateway the card says so", () => {
  assert.equal(jevStatusLine(jev({ loaded: [] }), NOW).text, MODEL_TEXT.onlineNone);
});

test("the card polls only while a saved version is still on its way to a gateway", () => {
  assert.equal(jevWaitingForLoad(undefined, NOW), false);
  assert.equal(jevWaitingForLoad(jev({ source: "env", version: null }), NOW), false);
  assert.equal(
    jevWaitingForLoad(jev({ updated_at: RECENT, loaded: [load("edge-2", 13)] }), NOW),
    true,
  );
  assert.equal(jevWaitingForLoad(jev({ loaded: [load("edge-2", 13)] }), NOW), false);
  assert.equal(
    jevWaitingForLoad(jev({ updated_at: RECENT, loaded: [load("edge-2", 13, "X")] }), NOW),
    false,
  );
  assert.equal(jevWaitingForLoad(jev({ updated_at: RECENT }), NOW), false);
});

test("a gateway counts as not loaded only after the grace period, and only while online", () => {
  const behind = [load("edge-2", 13)];
  assert.deepEqual(jevNotLoaded(jev({ loaded: behind }), NOW), behind);
  assert.deepEqual(jevNotLoaded(jev({ updated_at: RECENT, loaded: behind }), NOW), []);
  const edge = (ms: number) => new Date(NOW - ms).toISOString();
  assert.deepEqual(jevNotLoaded(jev({ updated_at: edge(LOAD_GRACE_MS), loaded: behind }), NOW), []);
  assert.deepEqual(
    jevNotLoaded(jev({ updated_at: edge(LOAD_GRACE_MS + 1), loaded: behind }), NOW),
    behind,
  );
  assert.deepEqual(jevNotLoaded(jev({ loaded: [load("edge-3", 13, null, false)] }), NOW), []);
  assert.deepEqual(jevNotLoaded(jev({ source: "env", version: null }), NOW), []);
  assert.deepEqual(jevNotLoaded(jev({ updated_at: null, loaded: behind }), NOW), []);
});

test("notLoadedSummary names the gateways and the distinct reasons they give", () => {
  assert.deepEqual(
    notLoadedSummary([load("edge-1", 13, "MODEL_KEY_UNREADABLE"), load("edge-2", null)]),
    { edges: "edge-1、edge-2", reason: `密钥无法解密、${MODEL_TEXT.edgeNoLoadReason}` },
  );
  assert.deepEqual(
    notLoadedSummary([
      load("edge-1", 13, "MODEL_KEY_UNREADABLE"),
      load("edge-2", 13, "MODEL_KEY_UNREADABLE"),
    ]),
    { edges: "edge-1、edge-2", reason: "密钥无法解密" },
  );
  assert.equal(notLoadedSummary([load("edge-1", 13, "SOMETHING_NEW")]).reason, "SOMETHING_NEW");
});

test("the agent card says whether it is configured and how its last calls went", () => {
  assert.deepEqual(agentStatusLine(agent({ configured: false })), {
    tone: "neutral",
    icon: "–",
    text: MODEL_TEXT.unset,
  });
  assert.equal(agentStatusLine(agent()).text, MODEL_TEXT.noCallYet);
  assert.deepEqual(agentStatusLine(agent({ last_call: call({ ok: true, status: 200 }) })), {
    tone: "ok",
    icon: "●",
    text: MODEL_TEXT.lastOk,
  });
  assert.deepEqual(
    agentStatusLine(agent({ last_call: call({ status: null, failure: "JEV_TIMEOUT" }) })),
    { tone: "warn", icon: "▲", text: "最近一次失败：超时" },
  );
  assert.deepEqual(
    agentStatusLine(agent({ health: "failing", last_call: call({ status: 401 }) })),
    { tone: "warn", icon: "▲", text: "最近 5 次调用失败：401 未授权" },
  );
});
