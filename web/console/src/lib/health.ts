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
import { fmtClock, fmtInt } from "./format.ts";
import { errorText, FAILURE_INFO } from "./vocab.ts";

export type Tone = "ok" | "warn" | "down" | "idle" | "unknown";
export type Light = { tone: Tone; label: string; lines: string[] };

const GATEWAY_TONE: Record<GatewayLight, Tone> = { ok: "ok", warn: "warn", down: "down" };

/**
 * The cause a gap names in brackets after its count, in words: 队列满, 写入失败, or both (docs/06, the log
 * gap notice). The count itself is `dropped + write_errors`.
 */
export function lostReasons(gap: { dropped: number; write_errors: number }): string {
  const reasons: string[] = [];
  if (gap.dropped > 0) reasons.push("队列满");
  if (gap.write_errors > 0) reasons.push("写入失败");
  return reasons.join("、");
}

/** One line of the gateway problem list, in words (docs/06 6.3.2). */
export function problemText(problem: GatewayProblem): string {
  switch (problem.kind) {
    case "site_load_failed":
      return `${problem.edge} 加载 ${problem.site} 失败：${errorText(problem.error)}`;
    case "version_behind":
      return `${problem.site} v${problem.expected} 保存后未生效，${problem.edge} 仍是 v${problem.loaded}`;
    case "log_gap": {
      const lost = problem.dropped + problem.write_errors;
      const span = `${fmtClock(problem.from_ms)}–${fmtClock(problem.to_ms)}`;
      // Bypass records dropped under pressure are a note, not lost decisions (docs/06, the log gap notice).
      if (lost === 0)
        return `${problem.edge} 在 ${span} 丢弃了 ${fmtInt(problem.dropped_bypass)} 条绕过记录，判定记录不受影响`;
      return `${problem.edge} ${span} 有 ${fmtInt(lost)} 条判定记录未写入（${lostReasons(problem)}）`;
    }
    case "queue_pressure":
      return `${problem.edge} 发送队列 ${problem.queue} / ${problem.capacity}`;
    case "partition_missing":
      return `判定日志分区不足，未来只有 ${problem.days_ahead} 天`;
    case "heartbeat_late":
      return `${problem.edge} 心跳延迟`;
    case "edge_offline": {
      const stuck = Object.entries(problem.loaded)
        .map(([site, version]) => `${site} v${version}`)
        .join("、");
      return `实例 ${problem.edge} 离线，最后心跳 ${fmtClock(problem.last_seen_ms)}${stuck ? `，停在 ${stuck}` : ""}`;
    }
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
