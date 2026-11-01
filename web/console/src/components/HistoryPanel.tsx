import { Button, Empty, Popconfirm } from "antd";
import { diffSiteSpec, FIELD_LABELS, formatFieldValue } from "../diff.ts";
import type { HistoryEntry } from "../types.ts";

interface HistoryPanelProps {
  entries: HistoryEntry[];
  onRollback: (id: number) => void;
  rollingBackId: number | null;
}

export function HistoryPanel({ entries, onRollback, rollingBackId }: HistoryPanelProps) {
  if (entries.length === 0) {
    return <Empty description="暂无历史记录" />;
  }
  return (
    <div>
      {entries.map((entry) => {
        const changes = diffSiteSpec(entry.before, entry.after);
        const kind = entry.before === null ? "创建" : entry.after === null ? "删除" : "修改";
        return (
          <div className="xs-history-item" key={entry.id}>
            <div className="xs-history-item-head">
              <span>
                <strong>#{entry.id}</strong> · {kind} · {entry.changed_at}
              </span>
              {entry.after !== null && (
                <Popconfirm
                  title="回滚到此版本？"
                  description="当前配置会被替换为该版本的内容。"
                  onConfirm={() => onRollback(entry.id)}
                >
                  <Button size="small" loading={rollingBackId === entry.id}>
                    回滚到这一版
                  </Button>
                </Popconfirm>
              )}
            </div>
            {changes.length === 0 ? (
              <span style={{ color: "rgba(0,0,0,0.45)" }}>没有字段变化</span>
            ) : (
              changes.map((change) => (
                <div className="xs-diff-field" key={change.field}>
                  <span className="xs-diff-name">{FIELD_LABELS[change.field] ?? change.field}</span>
                  <span className="xs-diff-before">{formatFieldValue(change.before)}</span>
                  <span>→</span>
                  <span className="xs-diff-after">{formatFieldValue(change.after)}</span>
                </div>
              ))
            )}
          </div>
        );
      })}
    </div>
  );
}
