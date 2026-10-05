import { FolderAddOutlined, SearchOutlined } from "@ant-design/icons";
import { Button, Descriptions, Drawer, Skeleton } from "antd";
import { useInvestigationNavigate, requestPath } from "../../investigation/navigation.ts";
import { useGuardedQuery } from "../../security/hooks";
import { MANUAL_REFRESH } from "../../security/query-client.ts";
import { IdChip } from "../../ui/IdChip";
import { captureName } from "../../ui/request-vocab.ts";
import { EmptyState, ErrorState } from "../../ui/states";
import { TimeStamp } from "../../ui/TimeStamp";
import "./drawers.css";
import "./investigation.css";

type Props = {
  /** The artifact whose catalogue metadata is shown; `null` closes the drawer. */
  artifactId: string | null;
  onClose: () => void;
  /** Whether the session may add evidence to a case (Investigator; the server still decides). */
  canAddToCase: boolean;
  onAddToCase: (artifactId: string) => void;
};

/**
 * Catalogue metadata of one evidence reference, read when the drawer opens (one audited read).
 * It shows what the catalogue records, never the content: reading content needs its own access
 * request and approval, and `found=false` is "not available now", not proof that nothing exists.
 */
export function ArtifactDrawer({ artifactId, onClose, canAddToCase, onAddToCase }: Props) {
  return (
    <Drawer
      open={artifactId !== null}
      onClose={onClose}
      title="证据元数据"
      size={520}
      destroyOnHidden
      styles={{ wrapper: { maxWidth: "100vw" } }}
    >
      {artifactId ? (
        <ArtifactBody
          key={artifactId}
          artifactId={artifactId}
          canAddToCase={canAddToCase}
          onAddToCase={onAddToCase}
        />
      ) : null}
    </Drawer>
  );
}

function ArtifactBody({
  artifactId,
  canAddToCase,
  onAddToCase,
}: {
  artifactId: string;
  canAddToCase: boolean;
  onAddToCase: (artifactId: string) => void;
}) {
  const navigateTo = useInvestigationNavigate();
  const query = useGuardedQuery({
    key: ["investigation", "artifact", artifactId],
    fetch: (client, signal) => client.artifact(artifactId, signal),
    staleTime: MANUAL_REFRESH,
  });
  if (query.isPending && query.isFetching) {
    return <Skeleton active paragraph={{ rows: 6 }} aria-label="正在读取证据元数据" />;
  }
  if (query.isError) {
    return <ErrorState error={query.error} onRetry={() => void query.refetch()} />;
  }
  const response = query.data;
  if (!response) return null;
  const artifact = response.artifact;
  if (!artifact) {
    return (
      <EmptyState title="证据当前不可用" icon="search">
        服务端未返回当前范围内的有效目录记录。已删除、已到期、不存在或不在当前作用域的证据都会得到同样的结果，这不推断对象是否存在。
        <br />
        <span className="mono">{response.source_artifact_id}</span>
      </EmptyState>
    );
  }
  return (
    <div className="xs-drawer-body">
      <Descriptions
        bordered
        size="small"
        column={1}
        items={[
          {
            key: "id",
            label: "证据 ID",
            children: <IdChip value={artifact.artifact_id} wrap />,
          },
          {
            key: "request",
            label: "请求 ID",
            children: (
              <IdChip
                value={artifact.request_id}
                wrap
                href={requestPath(artifact.request_id)}
                onOpen={() => navigateTo.go(requestPath(artifact.request_id))}
              />
            ),
          },
          { key: "kind", label: "类型", children: <span className="mono">{artifact.kind}</span> },
          {
            key: "type",
            label: "媒体类型",
            children: <span className="mono">{artifact.content_type}</span>,
          },
          {
            key: "capture",
            label: "采集状态",
            children: captureName(artifact.capture_status).label,
          },
          { key: "fidelity", label: "保真度", children: captureName(artifact.fidelity).label },
          { key: "class", label: "分级", children: captureName(artifact.classification).label },
          {
            key: "observed",
            label: "观察字节",
            children: artifact.bytes_observed.toLocaleString(),
          },
          { key: "saved", label: "保存字节", children: artifact.bytes_saved.toLocaleString() },
          {
            key: "recorded",
            label: "记录时间",
            children: <TimeStamp value={artifact.recorded_at} precision="millisecond" />,
          },
          {
            key: "expires",
            label: "到期时间",
            children: <TimeStamp value={artifact.expires_at} precision="millisecond" />,
          },
          {
            key: "parents",
            label: "父级引用",
            children:
              artifact.parent_refs.length === 0 ? (
                "无"
              ) : (
                <span className="xs-chips">
                  {artifact.parent_refs.map((ref) => (
                    <IdChip key={ref} value={ref} short />
                  ))}
                </span>
              ),
          },
        ]}
      />
      <p className="xs-foot">
        目录记录用于定位证据。内容读取权限与对象完整性需独立校验；本页不请求、不显示任何内容。
      </p>
      <div className="xs-drawer-actions">
        {canAddToCase ? (
          <Button
            type="primary"
            icon={<FolderAddOutlined aria-hidden="true" />}
            onClick={() => onAddToCase(artifact.artifact_id)}
          >
            加入案件
          </Button>
        ) : null}
        <Button
          icon={<SearchOutlined aria-hidden="true" />}
          onClick={() =>
            navigateTo.openSearch({ kind: "artifact_id", value: artifact.artifact_id })
          }
        >
          查找引用此证据的事件
        </Button>
      </div>
    </div>
  );
}
