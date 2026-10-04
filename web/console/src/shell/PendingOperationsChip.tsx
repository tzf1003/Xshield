import { ClockCircleOutlined } from "@ant-design/icons";
import { Badge, Button, Popover } from "antd";
import { usePendingOperations } from "../security/hooks";
import type { OperationSnapshot } from "../security/pending-operations.ts";

function formatTime(value: number): string {
  return new Date(value).toLocaleString("zh-CN", { hour12: false });
}

function OperationList({ operations }: { operations: readonly OperationSnapshot[] }) {
  return (
    <div className="xs-pending">
      <p className="xs-pending-note">
        结果未知的写入只能用原路径、原幂等键和原正文精确重试；刷新页面、闲置或退出后这些信息会被清除，
        请先保存下列内容。
      </p>
      <ul className="xs-pending-list" aria-label="待确认操作清单">
        {operations.map((operation) => (
          <li key={operation.id}>
            <strong>{operation.label}</strong>
            <span className="xs-pending-phase">
              {operation.phase === "inflight" ? "请求中" : "结果未知"}
              {operation.attempts > 1 ? ` · 已尝试 ${operation.attempts} 次` : ""}
            </span>
            <code className="mono">
              {operation.method} {operation.path}
            </code>
            <span>
              幂等键 <code className="mono">{operation.idempotencyKey}</code>
            </span>
            <span>创建于 {formatTime(operation.createdAt)}</span>
            {operation.lastError && (
              <span className="mono">
                {operation.lastError.code}
                {operation.lastError.status ? ` · HTTP ${operation.lastError.status}` : ""}
                {operation.lastError.requestId ? ` · ${operation.lastError.requestId}` : ""}
              </span>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Appears only while a write is in flight or its outcome is unknown. Read-only in Phase 0. */
export function PendingOperationsChip() {
  const operations = usePendingOperations();
  if (operations.length === 0) return null;
  return (
    <Popover
      trigger="click"
      placement="bottomRight"
      title="待确认操作"
      content={<OperationList operations={operations} />}
    >
      <Button size="small" icon={<ClockCircleOutlined />} className="xs-pending-chip">
        待确认操作
        <Badge count={operations.length} size="small" color="orange" />
      </Button>
    </Popover>
  );
}
