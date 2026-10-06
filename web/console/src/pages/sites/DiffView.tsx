import { Button, Modal, Table, type TableColumnsType } from "antd";
import { type FieldChange, groupLabel } from "../../sites/model/diff.ts";
import { riskText } from "../../ui/reason-codes.ts";

type TableProps = {
  changes: readonly FieldChange[];
  /** Show which approval reason each field falls under (release dialogs). */
  showRisk?: boolean;
  empty?: string;
};

const kindLabel: Record<FieldChange["kind"], string> = {
  changed: "修改",
  added: "新增",
  removed: "移除",
};

/** Field-level differences: what changes, from what, to what. */
export function DiffTable({ changes, showRisk = false, empty = "没有差异。" }: TableProps) {
  const columns: TableColumnsType<FieldChange> = [
    {
      title: "字段",
      key: "field",
      width: 220,
      render: (_, change) => (
        <div className="xs-diff-field">
          <span>{change.label}</span>
          <small className="muted">
            {groupLabel[change.group]}
            {change.kind !== "changed" && ` · ${kindLabel[change.kind]}`}
          </small>
        </div>
      ),
    },
    {
      title: "修改前",
      dataIndex: "before",
      render: (value: string) => <span className="mono xs-diff-value">{value}</span>,
    },
    {
      title: "修改后",
      dataIndex: "after",
      render: (value: string) => <span className="mono xs-diff-value xs-diff-after">{value}</span>,
    },
  ];
  if (showRisk) {
    columns.push({
      title: "审批",
      key: "risk",
      width: 190,
      // The token pills of the rest of the console: legible in both themes, unlike a preset tag.
      // A route of the browser provenance flow also names every flow facet it takes part in:
      // those reasons need an independent approver, so the operator must see them per field.
      render: (_, change) => {
        if (!change.risk) return <span className="xs-pill xs-pill--sm">无需审批</span>;
        const tokens = [change.risk, ...(change.facets ?? []).filter((t) => t !== change.risk)];
        return (
          <span className="xs-risk-pills">
            {tokens.map((token) => (
              <span key={token} className="xs-pill xs-pill--sm xs-pill--observe">
                {riskText(token).label}
              </span>
            ))}
          </span>
        );
      },
    });
  }
  return (
    <Table<FieldChange>
      className="xs-diff-table"
      size="small"
      rowKey="id"
      columns={columns}
      dataSource={[...changes]}
      pagination={changes.length > 50 ? { pageSize: 50, showSizeChanger: false } : false}
      locale={{ emptyText: empty }}
      scroll={{ x: 520 }}
    />
  );
}

type ModalProps = {
  open: boolean;
  onClose: () => void;
  title: string;
  /** What is compared with what, in one line. */
  caption: string;
  changes: readonly FieldChange[];
  showRisk?: boolean;
};

export function DiffModal({ open, onClose, title, caption, changes, showRisk }: ModalProps) {
  return (
    <Modal
      open={open}
      onCancel={onClose}
      title={title}
      width={820}
      destroyOnHidden
      footer={
        <Button type="primary" onClick={onClose}>
          关闭
        </Button>
      }
    >
      <p className="muted">{caption}</p>
      <DiffTable changes={changes} showRisk={showRisk} />
    </Modal>
  );
}
