// The status lines of the model cards and the grace period of a saved version (lib/model-status.ts, design 2.1 and
// 3.6). Each function takes the time as an argument, so the tests pin the boundaries without a clock.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { AgentModelsState, JevModelsState, ModelLoad } from "../src/api/types.ts";
import {
  agentFailureWord,
  agentStatusLine,
  agentTodayLine,
  failingStreak,
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
  return { edge, online, source: version === null ? null : "console", version, error };
}

function jev(overrides: Partial<JevModelsState> = {}): JevModelsState {
  return {
    configured: true,
    source: "console",
    version: 14,
    updated_at: OLD,
    route: "gateway",
    endpoint: null,
    endpoint_host: null,
    model: "typesafe-ai/jev",
    timeout_ms: 2000,
    key: { set: true, last4: "9f3a", updated_at: OLD, shared_with_jev: false },
    key_env: "AI_GATEWAY_API_KEY",
    env_available: true,
    env_overridden: [],
    loaded: [load("edge-1", 14), load("edge-2", 14)],
    impact: { sites: 2, fail_closed: [] },
    usage: { window_minutes: 5, calls: 0, failed: 0, p95_ms: null },
    ...overrides,
  };
}

function agent(overrides: Partial<AgentModelsState> = {}): AgentModelsState {
  return {
    configured: true,
    source: "console",
    version: 3,
    updated_at: OLD,
    provider: "gateway",
    endpoint: "https://ai-gateway.vercel.sh/v1",
    model: "openai/gpt-4.1-mini",
    timeout_ms: 30000,
    share_key_with_jev: false,
    key: { set: true, last4: "c81d", updated_at: OLD, shared_with_jev: false },
    recent_failures: [null, null, null, null, null],
    usage: {
      window: "today",
      calls: 52,
      ok: 50,
      failed: 2,
      top_failure: "timeout",
      enabled_sites: 2,
    },
    sites: [],
    ...overrides,
  };
}

test("the grace period is a minute and the card polls every five seconds (design 2.5, 3.6)", () => {
  assert.equal(LOAD_GRACE_MS, 60_000);
  assert.equal(LOAD_POLL_MS, 5_000);
});

test("an environment-supplied configuration shows how many gateways read it", () => {
  const readsEnv: ModelLoad[] = [
    { edge: "edge-1", online: true, source: "env", version: null, error: null },
    { edge: "edge-2", online: true, source: "env", version: null, error: null },
  ];
  const env = jev({ source: "env", updated_at: null, loaded: readsEnv });
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

test("neither a saved configuration nor an environment one reads as not configured", () => {
  const unset = jev({ source: null, version: 0, updated_at: null, loaded: [] });
  assert.deepEqual(jevStatusLine(unset, NOW), {
    tone: "neutral",
    icon: "–",
    text: MODEL_TEXT.unset,
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
  assert.equal(jevWaitingForLoad(jev({ source: "env" }), NOW), false);
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
  assert.deepEqual(jevNotLoaded(jev({ source: "env" }), NOW), []);
  assert.deepEqual(jevNotLoaded(jev({ source: null, version: 0 }), NOW), []);
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

test("the agent card says whether it is configured, and what its latest calls did (design 2.1)", () => {
  assert.deepEqual(agentStatusLine(agent({ configured: false, source: null, version: 0 })), {
    tone: "neutral",
    icon: "–",
    text: MODEL_TEXT.unset,
  });
  assert.deepEqual(agentStatusLine(agent({ recent_failures: [] })), {
    tone: "neutral",
    icon: "–",
    text: MODEL_TEXT.agentNoCalls,
  });
  assert.deepEqual(agentStatusLine(agent()), {
    tone: "ok",
    icon: "●",
    text: MODEL_TEXT.agentLastOk,
  });
});

test("a failing agent names how many calls failed in a row and why the newest one did", () => {
  const once = agentStatusLine(agent({ recent_failures: ["timeout", null, null] }));
  assert.deepEqual(once, {
    tone: "warn",
    icon: "▲",
    text: "最近一次失败：超时",
  });
  const twice = agentStatusLine(agent({ recent_failures: ["not_json", "timeout", null] }));
  assert.equal(twice.text, "最近 2 次失败：回答不能解析");
  const five = agentStatusLine(
    agent({ recent_failures: ["unavailable", "unavailable", "timeout", "timeout", "timeout"] }),
  );
  assert.equal(five.text, "最近 5 次失败：模型不可用");
  assert.equal(five.tone, "warn");
});

test("the failing streak counts from the newest call and stops at the first answer", () => {
  assert.equal(failingStreak([]), 0);
  assert.equal(failingStreak([null, "timeout"]), 0);
  assert.equal(failingStreak(["timeout", null, "timeout"]), 1);
  assert.equal(failingStreak(["timeout", "timeout", null, "timeout"]), 2);
  assert.equal(failingStreak(["timeout", "timeout", "timeout", "timeout", "timeout"]), 5);
});

test("a learning failure reads in words, and an unknown one is kept as itself", () => {
  assert.equal(agentFailureWord("timeout"), "超时");
  assert.equal(agentFailureWord("made_up"), "回答不可用（made_up）");
});

test("today's line counts the calls, the answers and the failures, with the reason most failed", () => {
  assert.equal(
    agentTodayLine({
      window: "today",
      calls: 52,
      ok: 50,
      failed: 2,
      top_failure: "timeout",
      enabled_sites: 3,
    }),
    "调用 52 · 成功 50 · 失败 2（超时） · 3 个站点开启了学习代理",
  );
  assert.equal(
    agentTodayLine({
      window: "today",
      calls: 0,
      ok: 0,
      failed: 0,
      top_failure: null,
      enabled_sites: 0,
    }),
    "调用 0 · 成功 0 · 失败 0 · 0 个站点开启了学习代理",
  );
});
