import { CloudSyncOutlined } from "@ant-design/icons";
import { Alert, Button, Skeleton } from "antd";
import type { AuditHealthResponse } from "../../api.ts";
import { RoleHint } from "../../operations/Parts";
import { isRoleRefusal } from "../../operations/sources.ts";
import { useGuardedQuery } from "../../security/hooks";
import { MANUAL_REFRESH } from "../../security/query-client.ts";
import { TimeStamp } from "../../ui/TimeStamp";
import { ErrorNotice, Facts, IdChip, TonePill } from "../../work/Parts";
import { useRoles } from "../../work/roles.ts";
import { WorkRoot } from "../../work/WorkRoot";
import "../../operations/operations.css";

export const auditHealthKey = ["operations", "audit-health"] as const;

/** `32,768 字节（32.0 KiB）`: the exact count first, a readable size beside it. */
function bytes(value: number): string {
  const exact = `${value.toLocaleString("zh-CN")} 字节`;
  if (value < 1024) return exact;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let size = value / 1024;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${exact}（${size.toFixed(1)} ${units[unit]}）`;
}

function publication(response: AuditHealthResponse) {
  if (response.has_gaps) {
    return { label: "发布观察到缺口", tone: "error" as const };
  }
  if (response.pending_segments > 0) {
    return { label: "未观察到发布缺口 · 有待发布段", tone: "warning" as const };
  }
  return { label: "未观察到发布缺口 · 已连续发布", tone: "success" as const };
}

/**
 * Published, pending and unsealed segments as one bar; the numbers are in the facts beside it,
 * so the bar is decoration for sighted readers only.
 */
function SegmentBar({ response }: { response: AuditHealthResponse }) {
  // published + pending = closed, and the unsealed segments are part of the pending ones.
  const total = Math.max(response.closed_segments, 1);
  const sealedPending = Math.max(response.pending_segments - response.unsealed_segments, 0);
  const part = (count: number) => `${(count / total) * 100}%`;
  return (
    <div className="xs-op-bar" aria-hidden="true">
      <span className="is-published" style={{ width: part(response.published_segments) }} />
      <span className="is-pending" style={{ width: part(sealedPending) }} />
      <span className="is-unsealed" style={{ width: part(response.unsealed_segments) }} />
    </div>
  );
}

function Result({ response, busy }: { response: AuditHealthResponse; busy: boolean }) {
  const state = publication(response);
  return (
    <section className="xs-w-card" aria-label="审计发布状态结果" aria-busy={busy}>
      <div className="xs-w-between">
        <h2 className="xs-op-title">发布快照</h2>
        <TonePill tone={state.tone} label={state.label} />
      </div>
      <ul className="xs-op-stats" aria-label="封存段统计">
        <li>
          <span>关闭段</span>
          <strong>{response.closed_segments.toLocaleString("zh-CN")}</strong>
        </li>
        <li>
          <span>已发布段</span>
          <strong>{response.published_segments.toLocaleString("zh-CN")}</strong>
        </li>
        <li>
          <span>待发布段</span>
          <strong>{response.pending_segments.toLocaleString("zh-CN")}</strong>
        </li>
        <li>
          <span>未封存段</span>
          <strong>{response.unsealed_segments.toLocaleString("zh-CN")}</strong>
        </li>
      </ul>
      <SegmentBar response={response} />
      <p className="xs-w-muted">
        已发布 + 待发布 = 关闭段；未封存段计入待发布段，在封存前不会发布。
      </p>
      <Facts
        rows={[
          ["观察时间", <TimeStamp key="t" value={response.as_of} />],
          [
            "索引目标",
            <span key="g" className="mono">
              {response.target_id}
            </span>,
          ],
          [
            "目标表",
            <span key="b" className="mono">
              {response.table}
            </span>,
          ],
          ["元数据保留", `${response.metadata_retention_days} 天`],
          ["关闭段字节", bytes(response.closed_segment_bytes)],
          ["发布缺口", response.has_gaps ? "存在" : "未观察到"],
          [
            "连续索引水位",
            response.index_watermark ? (
              <span key="w" className="mono">
                {response.index_watermark.producer_boot_id} /{" "}
                {response.index_watermark.producer_sequence}
              </span>
            ) : (
              "尚无连续已发布封存段"
            ),
          ],
          ["管理请求", <IdChip key="r" id={response.request_id} label="管理请求 ID" />],
        ]}
      />
      <Alert
        type={response.has_gaps ? "warning" : "info"}
        showIcon
        title="连续水位的覆盖范围"
        description="连续水位只覆盖配置 journal 的已确认封存段；后续孤岛、未封存数据和其他发布路径须分别判断。"
      />
    </section>
  );
}

/**
 * 审计发布状态: one configured audit journal's publication into its index, read only when the
 * operator asks. Each read is authorized and audited by the server (`console.health.read`); the
 * page never reads on arrival, on a timer or on focus.
 */
function AuditBody() {
  const { roles } = useRoles();
  const query = useGuardedQuery({
    key: auditHealthKey,
    enabled: false,
    staleTime: MANUAL_REFRESH,
    fetch: (client, signal) => client.health(signal),
  });
  const auditRole = roles === null || roles.includes("audit_administrator");
  const response = query.isError ? undefined : query.data;
  return (
    <div className="xs-w-stack">
      {!auditRole && (
        <RoleHint title="需要 AuditAdministrator 角色">
          当前身份没有
          AuditAdministrator，服务端会拒绝这次读取。导航隐藏只是提示，授权由服务端决定。
        </RoleHint>
      )}
      <section className="xs-w-card" aria-label="审计发布状态说明">
        <h2 className="xs-op-title">配置日志发布观察</h2>
        <p>
          此处仅观察一个配置 audit journal 到其索引目标的封存段发布状态。它不代表业务准入、全部
          Outbox 状态或系统整体健康。
        </p>
        <p className="xs-w-muted">
          每次读取均由服务端单独重新鉴权并写入管理审计；控制台不会自动轮询，也不会在打开页面时读取。
        </p>
        <span>
          <Button
            type="primary"
            icon={<CloudSyncOutlined aria-hidden="true" />}
            loading={query.isFetching}
            onClick={() => void query.refetch()}
          >
            {response ? "手动刷新发布状态" : "读取发布状态"}
          </Button>
        </span>
      </section>
      {query.isError &&
        (isRoleRefusal(query.error) ? (
          <RoleHint title="审计发布状态被服务端拒绝">读取需要 AuditAdministrator 角色。</RoleHint>
        ) : (
          <ErrorNotice error={query.error} title="审计发布状态读取失败" />
        ))}
      {query.isFetching && !response && (
        <div aria-busy="true">
          <Skeleton active paragraph={{ rows: 4 }} />
        </div>
      )}
      {response && <Result response={response} busy={query.isFetching} />}
    </div>
  );
}

export function AuditPage() {
  return (
    <WorkRoot>
      <AuditBody />
    </WorkRoot>
  );
}
