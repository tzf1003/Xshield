import { ApiError } from "../api-contract.ts";
import { useGuardedQuery } from "../security/hooks";
import { Facts, IdChip, LoadState, Time } from "./Parts";
import { specs } from "./queries.ts";
import { Alert } from "antd";

const names: Record<string, string> = {
  complete: "已采集",
  entity_exact: "实体精确",
  semantic: "语义保真",
  redacted: "已脱敏",
  INTERNAL: "内部",
  SENSITIVE: "敏感",
  RESTRICTED: "受限",
};
const label = (value: string) => names[value] ?? value;

/**
 * Catalog metadata of one evidence artifact. Reading it needs Observer, which Investigator does
 * not imply, so a refusal is explained rather than treated as a failure. No object locator, key
 * reference or digest reaches the page, and nothing here grants a content read.
 */
export function ArtifactMeta({ artifactId }: { artifactId: string }) {
  const query = useGuardedQuery(specs.artifact(artifactId));
  const refused =
    query.error instanceof ApiError && query.error.status === 403 ? query.error : null;
  return (
    <div className="xs-w-stack">
      {refused && (
        <Alert
          type="info"
          showIcon
          title="查看证据元数据需要 Observer 角色"
          description="Investigator 不隐含 Observer。服务端每次独立授权，当前身份被拒绝；案件成员关系与原文访问申请不受影响。"
        />
      )}
      <LoadState
        pending={query.isPending}
        error={refused ? null : query.error}
        onRetry={() => void query.refetch()}
      >
        {query.data && !query.data.artifact && !refused && (
          <Alert
            type="warning"
            showIcon
            title="证据当前不可用"
            description="服务端未返回当前范围内的有效目录记录，不能据此推断对象是否存在。"
          />
        )}
        {query.data?.artifact && (
          <Facts
            rows={[
              ["证据 ID", <IdChip key="id" id={query.data.artifact.artifact_id} label="证据 ID" />],
              [
                "请求 ID",
                <span key="rq" className="mono">
                  {query.data.artifact.request_id}
                </span>,
              ],
              ["类型", query.data.artifact.kind],
              ["媒体类型", query.data.artifact.content_type],
              ["采集状态", label(query.data.artifact.capture_status)],
              ["保真度", label(query.data.artifact.fidelity)],
              ["分级", label(query.data.artifact.classification)],
              ["观察字节", query.data.artifact.bytes_observed.toLocaleString("en-US")],
              ["保存字节", query.data.artifact.bytes_saved.toLocaleString("en-US")],
              ["记录时间", <Time key="rec" value={query.data.artifact.recorded_at} />],
              ["到期时间", <Time key="exp" value={query.data.artifact.expires_at} />],
            ]}
          />
        )}
      </LoadState>
      <p className="xs-w-muted">目录记录用于定位证据，不证明内容读取权或对象完整性。</p>
    </div>
  );
}
