// The health card of the Jev page (docs/06 6.4.6): the health word and icon, the calls and successes of
// the last five minutes, the failure codes, p50 and p95, the last success and failure, and the Jev line
// configuration that the gateway reports in its heartbeat (docs/07 7.9.7).

import type { JevFailure, JevStatus } from "../../api/types.ts";
import { fmtAgo, fmtClock, fmtInt, fmtMs } from "../../lib/format.ts";
import { FAILURE_INFO, ROUTE_LABEL } from "../../lib/vocab.ts";
import { HealthTag } from "../../ui/Badges.tsx";
import { Card, ErrorBar, Kv, Loading } from "../../ui/Page.tsx";
import { SafeText } from "../../ui/SafeText.tsx";
import { shortPrompt } from "./jev-model.ts";

type Props = {
  status: JevStatus | undefined;
  isPending: boolean;
  isError: boolean;
  error: unknown;
  onRetry: () => void;
  now: number;
};

function isJevFailure(code: string): code is JevFailure {
  return Object.hasOwn(FAILURE_INFO, code);
}

/** Local clock time of an RFC 3339 instant, `HH:mm:ss`, or null when there is none. */
function clockOf(iso: string | null): string | null {
  if (iso === null) return null;
  const ms = Date.parse(iso);
  return Number.isFinite(ms) ? fmtClock(ms).slice(0, 8) : null;
}

function agoOf(iso: string, now: number): string {
  const ms = Date.parse(iso);
  return Number.isFinite(ms) ? fmtAgo(ms, now) : "";
}

export function JevHealthCard({ status, isPending, isError, error, onRetry, now }: Props) {
  if (isPending) {
    return (
      <Card title="健康">
        <Loading height={96} />
      </Card>
    );
  }
  if (isError || status === undefined) {
    return (
      <Card title="健康">
        <ErrorBar error={error} onRetry={onRetry} />
      </Card>
    );
  }

  const failed = Object.entries(status.failures)
    .filter((entry): entry is [JevFailure, number] => isJevFailure(entry[0]) && (entry[1] ?? 0) > 0)
    .sort((a, b) => b[1] - a[1]);
  const failedText =
    failed.length === 0
      ? "没有失败"
      : failed.map(([code, count]) => `${FAILURE_INFO[code].short} ${fmtInt(count)}`).join(" · ");

  const callsText =
    status.calls === 0
      ? "没有调用"
      : status.ok === status.calls
        ? `${fmtInt(status.calls)} 次，全部成功`
        : `${fmtInt(status.calls)} 次，成功 ${fmtInt(status.ok)} 次`;

  const okClock = clockOf(status.last_ok_at);
  const okText =
    okClock === null || status.last_ok_at === null
      ? "没有记录"
      : `${okClock}（${agoOf(status.last_ok_at, now)}）`;

  const failure = status.last_failure;
  const failureClock = failure === null ? null : clockOf(failure.at);
  const failureText =
    failure === null ? (
      "没有记录"
    ) : (
      <>
        {failureClock ?? "—"} {FAILURE_INFO[failure.failure].short}
        {failure.site !== null ? (
          <>
            （<SafeText text={failure.site} />）
          </>
        ) : null}
      </>
    );

  const config = status.config;
  // The configuration values are gateway data: shown as text, never as markup (docs/06 6.5.5).
  const routeNode =
    config === null ? null : (
      <>
        {ROUTE_LABEL[config.route]} · <SafeText text={config.endpoint_host} />
      </>
    );
  const modelNode = config === null ? null : <SafeText text={config.model} />;
  const promptNode =
    config === null ? null : <span className="mono">{shortPrompt(config.prompt)}</span>;

  return (
    <Card title="健康">
      <div className="row jev-health-head">
        <HealthTag health={status.health} />
        <span className="small muted">最近 {fmtInt(status.window_minutes)} 分钟</span>
      </div>
      <Kv
        items={[
          ["调用", callsText],
          ["耗时", `p50 ${fmtMs(status.p50_ms)} · p95 ${fmtMs(status.p95_ms)}`],
          ["失败", failedText],
          ["最近成功", okText],
          ["最后失败", failureText],
        ]}
      />
      <div className="jev-health-config">
        {config === null ? (
          <span className="small dim">网关没有上报线路配置</span>
        ) : (
          <Kv
            items={[
              ["线路", routeNode],
              ["模型", modelNode],
              ["默认超时", fmtMs(config.default_timeout_ms)],
              ["指令", promptNode],
            ]}
          />
        )}
      </div>
    </Card>
  );
}
