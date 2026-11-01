// The two status lights of the top bar (docs/06 6.3.2, docs/07 7.9.13). Both read GET /api/status: the
// server decides the gateway light and lists its problems, and this file only words them, so the page
// and the tests read the same wording. Pure functions, no React.

import type {
  GatewayLight,
  GatewayProblem,
  JevFailure,
  JevHealth,
  StatusResponse,
} from "../api/types.ts";
import { fmtClock } from "./format.ts";
import { errorText, FAILURE_INFO } from "./vocab.ts";

export type Tone = "ok" | "warn" | "down" | "idle" | "unknown";
export type Light = { tone: Tone; label: string; lines: string[] };

const GATEWAY_TONE: Record<GatewayLight, Tone> = { ok: "ok", warn: "warn", down: "down" };

/** One line of the gateway problem list, in words (docs/06 6.3.2). */
export function problemText(problem: GatewayProblem): string {
  switch (problem.kind) {
    case "site_load_failed":
      return `${problem.edge} 加载 ${problem.site} 失败：${errorText(problem.error)}`;
    case "version_behind":
      return `${problem.site} v${problem.expected} 保存后未生效，${problem.edge} 仍是 v${problem.loaded}`;
    case "log_gap":
      return `${problem.edge} ${fmtClock(problem.from_ms)}–${fmtClock(problem.to_ms)} 有 ${problem.dropped + problem.dropped_bypass + problem.write_errors} 条记录未写入（队列丢弃 ${problem.dropped}，压力下丢弃绕过简记录 ${problem.dropped_bypass}，写入出错 ${problem.write_errors}）`;
    case "queue_pressure":
      return `${problem.edge} 发送队列 ${problem.queue} / ${problem.capacity}`;
    case "partition_missing":
      return `判定日志分区不足，未来只有 ${problem.days_ahead} 天`;
    case "heartbeat_late":
      return `${problem.edge} 心跳延迟`;
  }
}

/** The gateway light: the server's colour, with the online count as its word. */
export function gatewayLight(status: StatusResponse | undefined): Light {
  if (!status) return { tone: "unknown", label: "网关 读取中", lines: [] };
  const { light, edges, problems } = status.gateway;
  const label = edges.total === 0 ? "网关 无心跳" : `网关 ${edges.online}/${edges.total} 在线`;
  return { tone: GATEWAY_TONE[light], label, lines: problems.map(problemText) };
}

const JEV_LIGHT: Record<JevHealth, { tone: Tone; label: string }> = {
  ok: { tone: "ok", label: "Jev 正常" },
  idle: { tone: "idle", label: "Jev 空闲" },
  degraded: { tone: "warn", label: "Jev 降级" },
  down: { tone: "down", label: "Jev 不可用" },
};

/** The Jev light, from the `jev` part of GET /api/status (the same fields as /api/jev/status). */
export function jevLight(jev: StatusResponse["jev"] | undefined): Light {
  if (!jev) return { tone: "unknown", label: "Jev 读取中", lines: [] };
  const base = JEV_LIGHT[jev.health];
  const lines = [`最近 ${jev.window_minutes} 分钟 ${jev.calls} 次调用，成功 ${jev.ok} 次`];
  if (jev.p50_ms !== null && jev.p95_ms !== null) {
    lines.push(`p50 ${jev.p50_ms} ms · p95 ${jev.p95_ms} ms`);
  }
  const failed = (Object.keys(jev.failures) as JevFailure[]).map(
    (code) => `${FAILURE_INFO[code].short} ${jev.failures[code] ?? 0}`,
  );
  if (failed.length > 0) lines.push(`失败：${failed.join("，")}`);
  if (jev.last_failure) {
    lines.push(`最后一次失败：${FAILURE_INFO[jev.last_failure.failure].short}`);
  }
  return { ...base, lines };
}
