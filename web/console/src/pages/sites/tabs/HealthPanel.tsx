import { HeartOutlined } from "@ant-design/icons";
import { Button } from "antd";
import { safeError } from "../../../security/errors.ts";
import { useSiteHealth } from "../../../sites/state/detail-queries.ts";
import { IdChip } from "../../../ui/IdChip";
import { ProblemAlert } from "../../../ui/ProblemAlert";
import { reasonText } from "../../../ui/reason-codes.ts";
import { StatePill } from "../../../ui/StatePill";
import { siteDisplayState } from "../../../ui/state-model.ts";
import { TimeStamp } from "../../../ui/TimeStamp";
import { busy } from "../fields";

const rows = [
  ["edge_state", "Edge"],
  ["upstream_state", "源站"],
  ["audit_state", "审计"],
] as const;

/**
 * Edge, upstream and audit health, read only when the operator asks: every read is audited
 * server-side and inserts a row, so nothing here polls or refreshes by itself. The previous
 * observation is dropped before each read and never shown beside a failure.
 */
export function HealthPanel({ siteId }: { siteId: string }) {
  const health = useSiteHealth(siteId);
  const data = health.data;
  const facts = (data?.edge_health ?? {}) as Record<string, unknown>;
  const upstream =
    typeof facts.upstream_health === "object" && facts.upstream_health !== null
      ? (facts.upstream_health as Record<string, unknown>)
      : null;
  const upstreamReason = typeof upstream?.reason_code === "string" ? upstream.reason_code : null;
  return (
    <section className="xs-card xs-health" aria-label="站点运行健康">
      <div className="xs-health-head">
        <h3>运行健康</h3>
        <Button
          icon={<HeartOutlined aria-hidden="true" />}
          loading={busy(health.isFetching)}
          onClick={() => void health.read()}
        >
          读取健康状态
        </Button>
      </div>
      <p className="muted">
        手动读取，不会自动刷新；每次读取都会在服务端写入一条审计记录。读取的是 edge
        与源站当前的观察值，不代替业务检查。
      </p>
      {health.isError && <ProblemAlert problem={safeError(health.error)} />}
      {data && !health.isError && (
        <div className="xs-health-result">
          <dl className="xs-facts">
            {rows.map(([key, label]) => (
              <div key={key}>
                <dt>{label}</dt>
                <dd>
                  <StatePill kind="health" value={facts[key]} showRaw />
                </dd>
              </div>
            ))}
            <div>
              <dt>配置状态</dt>
              <dd>
                <StatePill
                  kind="apply"
                  state={siteDisplayState({
                    apply_state: data.apply_state,
                    requires_approval: data.requires_approval,
                  })}
                />
              </dd>
            </div>
            <div>
              <dt>管理请求 ID</dt>
              <dd>
                <IdChip value={data.request_id} label="请求 ID" maxLength={30} />
              </dd>
            </div>
          </dl>
          {upstreamReason && (
            <p className="xs-health-upstream">
              源站探测：{reasonText(upstreamReason).text}
              {typeof upstream?.status === "number" && (
                <span className="mono">
                  {" "}
                  （返回 {upstream.status}
                  {typeof upstream.expected_status === "number" &&
                    `，期望 ${upstream.expected_status}`}
                  ）
                </span>
              )}
              {reasonText(upstreamReason).tone !== "success" && (
                <> 建议：{reasonText(upstreamReason).action}</>
              )}
            </p>
          )}
          <p className="muted xs-observed-line">
            观察于 <TimeStamp value={health.dataUpdatedAt} />
            （控制台收到响应的时间；服务端不提供独立的观察时刻）
          </p>
        </div>
      )}
    </section>
  );
}
