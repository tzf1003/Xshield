import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiError } from "../src/api/client.ts";
import type { ObjectAgent, ObjectLearningState, ObjectRun } from "../src/api/types.ts";
import {
  askBlock,
  budgetUsed,
  choiceOf,
  disagrees,
  durationOf,
  failureWord,
  filtersOf,
  RUN_COOLDOWN_MS,
  refusalWord,
  runBlock,
  stampOf,
  weekCount,
} from "../src/features/sites/objects/objects-agent.ts";

const NOW = Date.parse("2026-11-03T12:00:00Z");

function agentOf(overrides: Partial<ObjectAgent>): ObjectAgent {
  return {
    status: "answered",
    asked_at: "2026-11-03T11:00:00Z",
    model: "example/model",
    attempts: 1,
    choice: "doctor",
    new_class: null,
    confidence: 0.86,
    cites: ["f1"],
    reason: "预约列表里 doc_id 的值之后 87% 用在医生详情",
    rule_choice: "doctor",
    failure: null,
    input: null,
    ...overrides,
  };
}

function runOf(overrides: Partial<ObjectRun>): ObjectRun {
  return {
    id: 1,
    at: "2026-11-03T11:00:00Z",
    trigger: "scheduled",
    duration_ms: 12000,
    proposals: 0,
    tightened: 0,
    paused: 0,
    agent: { asked: 0, answered: 0, failed: 0, skipped: 0 },
    error: null,
    ...overrides,
  };
}

function learningOf(overrides: Partial<ObjectLearningState>): ObjectLearningState {
  return {
    last: null,
    next_at: "2026-11-03T13:00:00Z",
    running: false,
    agent_today: { used: 0, limit: 200 },
    agent_waiting: 0,
    agent_failed: 0,
    ...overrides,
  };
}

test("an answer disagrees with the rules only when both name a kind and the kinds differ", () => {
  assert.equal(disagrees(agentOf({ rule_choice: "doctor", choice: "document" })), true);
  assert.equal(disagrees(agentOf({ rule_choice: "doctor", choice: "doctor" })), false);
  assert.equal(disagrees(agentOf({ rule_choice: null, choice: "document" })), false);
  assert.equal(disagrees(agentOf({ rule_choice: "doctor", choice: null })), false);
  assert.equal(disagrees(agentOf({ rule_choice: "doctor", choice: "new" })), true);
});

test("the day's budget is used up at the limit, and a limit of 0 counts as used", () => {
  assert.equal(budgetUsed({ used: 199, limit: 200 }), false);
  assert.equal(budgetUsed({ used: 200, limit: 200 }), true);
  assert.equal(budgetUsed({ used: 0, limit: 0 }), true);
});

test("a position is asked again only with the agent on and budget left, and the reason is said", () => {
  assert.equal(askBlock(false, { used: 0, limit: 200 }), "off");
  assert.equal(askBlock(false, { used: 500, limit: 200 }), "off");
  assert.equal(askBlock(true, { used: 200, limit: 200 }), "budget");
  assert.equal(askBlock(true, { used: 1, limit: 200 }), null);
});

test("a run cannot start while one runs, or within five minutes of a hand-started one", () => {
  assert.equal(runBlock(learningOf({ running: true }), NOW), "running");
  assert.equal(runBlock(learningOf({}), NOW), null);

  const manualRecently = learningOf({
    last: runOf({ trigger: "manual", at: new Date(NOW - RUN_COOLDOWN_MS + 1_000).toISOString() }),
  });
  assert.equal(runBlock(manualRecently, NOW), "cooldown");

  const manualLongAgo = learningOf({
    last: runOf({ trigger: "manual", at: new Date(NOW - RUN_COOLDOWN_MS - 1_000).toISOString() }),
  });
  assert.equal(runBlock(manualLongAgo, NOW), null);

  // Only a hand-started run holds the cooldown: a scheduled one does not.
  const scheduledRecently = learningOf({
    last: runOf({ trigger: "scheduled", at: new Date(NOW - 60_000).toISOString() }),
  });
  assert.equal(runBlock(scheduledRecently, NOW), null);
});

test("the source menu's choice and the URL's filters convert both ways", () => {
  assert.equal(choiceOf(undefined, undefined), "all");
  assert.equal(choiceOf("rule", undefined), "rule");
  assert.equal(choiceOf(undefined, "waiting"), "waiting");

  assert.deepEqual(filtersOf("all"), { source: undefined, agent: undefined });
  assert.deepEqual(filtersOf("admin"), { source: "admin", agent: undefined });
  assert.deepEqual(filtersOf("agent"), { source: "agent", agent: undefined });
  assert.deepEqual(filtersOf("waiting"), { source: undefined, agent: "waiting" });
  assert.deepEqual(filtersOf("failed"), { source: undefined, agent: "failed" });

  for (const choice of ["all", "admin", "rule", "agent", "waiting", "failed"] as const) {
    const filters = filtersOf(choice);
    assert.equal(choiceOf(filters.source, filters.agent), choice);
  }
});

test("a failure code reads in words, and an unknown code is kept as itself", () => {
  assert.equal(failureWord("timeout"), "超时");
  assert.equal(failureWord("not_json"), "回答不能解析");
  assert.equal(failureWord("made_up"), "回答不可用（made_up）");
});

test("the week's count of one kind of automatic change leaves out the older ones", () => {
  const day = 24 * 3_600_000;
  const events = [
    { kind: "auto_tighten", at: new Date(NOW - day).toISOString() },
    { kind: "auto_tighten", at: new Date(NOW - 8 * day).toISOString() },
    { kind: "auto_pause", at: new Date(NOW - day).toISOString() },
  ];
  assert.equal(weekCount(events, "auto_tighten", NOW), 1);
  assert.equal(weekCount(events, "auto_pause", NOW), 1);
  assert.equal(weekCount(events, "anomaly", NOW), 0);
});

test("a time reads as month-day and hour-minute, and a time that does not read is a dash", () => {
  assert.equal(stampOf(null), "—");
  assert.equal(stampOf("not a time"), "—");
  assert.match(stampOf("2026-11-03T05:00:00Z"), /^\d{2}-\d{2} \d{2}:\d{2}$/);
});

test("a duration is whole seconds, at least one, and a dash when the run has not finished", () => {
  assert.equal(durationOf(null), "—");
  assert.equal(durationOf(0), "1 秒");
  assert.equal(durationOf(499), "1 秒");
  assert.equal(durationOf(12_000), "12 秒");
});

test("a refused run or question reads the server's code in words", () => {
  const fallback = "没有成功";
  assert.equal(
    refusalWord(new ApiError(409, { error: "RUN_IN_PROGRESS" }), fallback),
    "学习任务正在运行",
  );
  assert.equal(
    refusalWord(new ApiError(429, { error: "RUN_TOO_SOON" }), fallback),
    "5 分钟内已手动运行过，稍后再试",
  );
  assert.equal(
    refusalWord(new ApiError(500, { error: "SOMETHING_NEW" }), fallback),
    "SOMETHING_NEW",
  );
  assert.equal(refusalWord(new Error("network down"), fallback), fallback);
});
