// The learning agent's rows of the overview's "需要处理" list (design 3.6): its latest five calls all failed, and a
// site with the agent on used its whole daily limit for days in a row. agentItems builds the rows, so these tests
// pin the wording and the thresholds without the page.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { AgentModelsState, AgentSiteUsage } from "../src/api/types.ts";
import { agentItems } from "../src/features/overview/attention.ts";

const SITE: AgentSiteUsage = {
  site: "emr",
  enabled: true,
  used: 0,
  limit: 200,
  failed: 0,
  last_call_at: null,
  full_days: 0,
};

function site(overrides: Partial<AgentSiteUsage> = {}): AgentSiteUsage {
  return { ...SITE, ...overrides };
}

function agent(overrides: Partial<AgentModelsState> = {}): AgentModelsState {
  return {
    configured: true,
    source: "console",
    version: 3,
    updated_at: "2026-10-30T09:00:00.000Z",
    provider: "gateway",
    endpoint: "https://ai-gateway.vercel.sh/v1",
    model: "openai/gpt-4.1-mini",
    timeout_ms: 30000,
    share_key_with_jev: false,
    key: {
      set: true,
      last4: "c81d",
      updated_at: "2026-10-30T09:00:00.000Z",
      shared_with_jev: false,
    },
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

const FIVE_TIMEOUTS = ["timeout", "timeout", "timeout", "timeout", "timeout"] as const;

test("five calls in a row that all failed are listed, with the newest reason and the sites on rules", () => {
  assert.deepEqual(
    agentItems(
      agent({ recent_failures: ["timeout", "timeout", "not_json", "timeout", "unavailable"] }),
    ),
    [
      {
        key: "agent-failing",
        level: "warn",
        text: "学习代理最近 5 次调用失败：超时，2 个站点的学习暂时只按规则进行",
        actions: [{ label: "查看模型配置", target: { kind: "system", tab: "models" } }],
      },
    ],
  );
});

test("the failing row names the newest reason, not the oldest one", () => {
  const [item] = agentItems(
    agent({ recent_failures: ["unavailable", "timeout", "timeout", "timeout", "timeout"] }),
  );
  assert.equal(item?.text, "学习代理最近 5 次调用失败：模型不可用，2 个站点的学习暂时只按规则进行");
});

test("four failures in a row, or a failure with an answer among the five, are not listed", () => {
  assert.deepEqual(
    agentItems(agent({ recent_failures: ["timeout", "timeout", "timeout", "timeout", null] })),
    [],
  );
  assert.deepEqual(
    agentItems(agent({ recent_failures: ["timeout", null, "timeout", "timeout", "timeout"] })),
    [],
  );
  assert.deepEqual(agentItems(agent({ recent_failures: [] })), []);
});

test("with no site on the agent, the failing row leaves the sites out", () => {
  const [item] = agentItems(
    agent({
      recent_failures: [...FIVE_TIMEOUTS],
      usage: { window: "today", calls: 0, ok: 0, failed: 0, top_failure: null, enabled_sites: 0 },
    }),
  );
  assert.equal(item?.text, "学习代理最近 5 次调用失败：超时");
});

test("an agent that is not configured lists nothing, whatever its calls say", () => {
  assert.deepEqual(
    agentItems(
      agent({
        configured: false,
        recent_failures: [...FIVE_TIMEOUTS],
        sites: [site({ full_days: 5 })],
      }),
    ),
    [],
  );
  assert.deepEqual(agentItems(undefined), []);
  assert.deepEqual(agentItems(null), []);
});

test("a site that used its whole limit for three days in a row is listed, with a link to its objects", () => {
  assert.deepEqual(agentItems(agent({ sites: [site({ full_days: 3 })] })), [
    {
      key: "agent-limit-emr",
      level: "warn",
      text: "emr 的学习代理连续 3 天用完 200 次上限",
      actions: [
        {
          label: "调整上限",
          target: { kind: "site", name: "emr", tab: "objects", group: undefined },
        },
      ],
    },
  ]);
});

test("a run that reaches the week's cap says it may be longer", () => {
  const [item] = agentItems(agent({ sites: [site({ full_days: 7 })] }));
  assert.equal(item?.text, "emr 的学习代理连续 7 天以上用完 200 次上限");
});

test("two full days are not yet a row, and a site whose agent is off is left out", () => {
  assert.deepEqual(agentItems(agent({ sites: [site({ full_days: 2 })] })), []);
  assert.deepEqual(agentItems(agent({ sites: [site({ enabled: false, full_days: 5 })] })), []);
});

test("the failing row comes first, then one row for each site with a run, in the order given", () => {
  const items = agentItems(
    agent({
      recent_failures: [...FIVE_TIMEOUTS],
      sites: [
        site({ site: "emr", full_days: 3 }),
        site({ site: "juice", limit: 100, full_days: 4 }),
      ],
    }),
  );
  assert.deepEqual(
    items.map((item) => item.key),
    ["agent-failing", "agent-limit-emr", "agent-limit-juice"],
  );
  assert.equal(items[2]?.text, "juice 的学习代理连续 4 天用完 100 次上限");
});
