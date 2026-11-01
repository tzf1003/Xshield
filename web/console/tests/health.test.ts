import assert from "node:assert/strict";
import { test } from "node:test";

import type { GatewayProblem, JevHealth, StatusResponse } from "../src/api/types.ts";
import { fmtClock } from "../src/lib/format.ts";
import { gatewayLight, jevLight, lostReasons, problemText } from "../src/lib/health.ts";
import { FIXTURE_NOW_MS, status, statusDown } from "./helpers/fixtures.ts";

type LogGapProblem = Extract<GatewayProblem, { kind: "log_gap" }>;

/** The loss window of edge-1 in the status sample (the only log gap it lists). */
function gapOf(sample: StatusResponse): LogGapProblem {
  const gap = sample.gateway.problems.find((problem) => problem.kind === "log_gap");
  assert.ok(gap?.kind === "log_gap", "the status sample lists a log gap");
  return gap;
}

const GAP_FROM = FIXTURE_NOW_MS - 10 * 60_000;
const GAP_TO = FIXTURE_NOW_MS - 8 * 60_000;

/** The sentence for a loss window of edge-1 with the given counts. */
function gapSentence(dropped: number, droppedBypass: number, writeErrors: number): string {
  return problemText({
    kind: "log_gap",
    edge: "edge-1",
    from_ms: GAP_FROM,
    to_ms: GAP_TO,
    dropped,
    dropped_bypass: droppedBypass,
    write_errors: writeErrors,
  });
}

test("the gateway light takes its colour from the server and counts the online edges", () => {
  const light = gatewayLight(status);
  assert.equal(light.tone, "warn");
  assert.equal(light.label, "网关 2/3 在线");
  const gap = gapOf(status);
  assert.deepEqual(light.lines, [
    "emr v13 保存后未生效，edge-2 仍是 v12",
    `edge-1 ${fmtClock(gap.from_ms)}–${fmtClock(gap.to_ms)} 有 31 条判定记录未写入（队列满）`,
  ]);
});

test("a down gateway reads as down, and a fleet that never sent a heartbeat says so", () => {
  assert.deepEqual(gatewayLight(statusDown), {
    tone: "down",
    label: "网关 0/3 在线",
    lines: ["判定日志分区不足，未来只有 1 天"],
  });
  const silent: StatusResponse = {
    ...statusDown,
    gateway: { light: "down", edges: { online: 0, total: 0 }, problems: [] },
  };
  assert.equal(gatewayLight(silent).label, "网关 无心跳");
});

test("the gateway colours map straight through from the server", () => {
  for (const light of ["ok", "warn", "down"] as const) {
    const sample: StatusResponse = { ...status, gateway: { ...status.gateway, light } };
    assert.equal(gatewayLight(sample).tone, light);
  }
});

test("before the first answer both lights read as loading", () => {
  assert.deepEqual(gatewayLight(undefined), { tone: "unknown", label: "网关 读取中", lines: [] });
  assert.deepEqual(jevLight(undefined), { tone: "unknown", label: "Jev 读取中", lines: [] });
});

test("each problem kind has its own sentence", () => {
  assert.equal(
    problemText({
      kind: "site_load_failed",
      edge: "edge-2",
      site: "emr",
      error: "SITE_CONFIG_ORIGIN_INVALID",
    }),
    "edge-2 加载 emr 失败：源站地址必须是 http://主机[:端口] 或 https://主机[:端口]，不带路径",
  );
  assert.equal(
    problemText({ kind: "site_load_failed", edge: "edge-2", site: "emr", error: "TLS_FAILED" }),
    "edge-2 加载 emr 失败：请求失败（TLS_FAILED）",
  );
  assert.equal(
    problemText({ kind: "queue_pressure", edge: "edge-2", queue: 1200, capacity: 2048 }),
    "edge-2 发送队列 1200 / 2048",
  );
  assert.equal(problemText({ kind: "heartbeat_late", edge: "edge-3" }), "edge-3 心跳延迟");
  assert.equal(
    problemText({ kind: "partition_missing", days_ahead: 1 }),
    "判定日志分区不足，未来只有 1 天",
  );
});

test("the log gap sentence counts the lost decisions and names their causes in words", () => {
  // The count is dropped + write_errors; the brackets hold only the cause, never a number (docs/06 6.3.2).
  const span = `${fmtClock(GAP_FROM)}–${fmtClock(GAP_TO)}`;
  assert.equal(gapSentence(31, 6, 0), `edge-1 ${span} 有 31 条判定记录未写入（队列满）`);
  assert.equal(gapSentence(0, 0, 5), `edge-1 ${span} 有 5 条判定记录未写入（写入失败）`);
  assert.equal(gapSentence(2, 0, 3), `edge-1 ${span} 有 5 条判定记录未写入（队列满、写入失败）`);
});

test("bypass records dropped under pressure are a note, not lost decisions", () => {
  // Bypass records dropped under pressure are not lost decisions (docs/07 7.7.4): they get their own note.
  assert.equal(
    gapSentence(0, 6, 0),
    `edge-1 在 ${fmtClock(GAP_FROM)}–${fmtClock(GAP_TO)} 丢弃了 6 条绕过记录，判定记录不受影响`,
  );
});

test("the cause words come from the lost counts alone", () => {
  assert.equal(lostReasons({ dropped: 0, write_errors: 0 }), "");
  assert.equal(lostReasons({ dropped: 1, write_errors: 0 }), "队列满");
  assert.equal(lostReasons({ dropped: 0, write_errors: 1 }), "写入失败");
  assert.equal(lostReasons({ dropped: 9, write_errors: 4 }), "队列满、写入失败");
});

test("the Jev light reads the health word, the window and the latency", () => {
  assert.deepEqual(jevLight(status.jev), {
    tone: "ok",
    label: "Jev 正常",
    lines: ["最近 5 分钟 42 次调用，成功 42 次", "p50 540 ms · p95 910 ms", "最后一次失败：超时"],
  });
});

test("an idle Jev has no latency and no failure lines", () => {
  assert.deepEqual(jevLight(statusDown.jev), {
    tone: "idle",
    label: "Jev 空闲",
    lines: ["最近 5 分钟 0 次调用，成功 0 次"],
  });
});

test("failures are listed by name and count, then the last one", () => {
  const degraded = jevLight({
    ...status.jev,
    health: "degraded",
    failures: { JEV_TIMEOUT: 3, JEV_CALL_LIMIT: 11 },
  });
  assert.equal(degraded.tone, "warn");
  assert.equal(degraded.label, "Jev 降级");
  assert.deepEqual(degraded.lines, [
    "最近 5 分钟 42 次调用，成功 42 次",
    "p50 540 ms · p95 910 ms",
    "失败：超时 3，达到上限 11",
    "最后一次失败：超时",
  ]);
});

test("each Jev health word has its tone and label", () => {
  const expected: Array<[JevHealth, string, string]> = [
    ["ok", "ok", "Jev 正常"],
    ["idle", "idle", "Jev 空闲"],
    ["degraded", "warn", "Jev 降级"],
    ["down", "down", "Jev 不可用"],
  ];
  for (const [health, tone, label] of expected) {
    const light = jevLight({ ...status.jev, health });
    assert.equal(light.tone, tone, health);
    assert.equal(light.label, label, health);
  }
});
