// Export (docs/06 6.4.3, docs/07 7.9.9): the rows the current filter selects, as JSON lines (the full
// records) or CSV (the list columns). The file holds request values and client addresses, so the
// dialog says so before the download starts.

import { Modal, Radio } from "antd";
import { useState } from "react";
import { fmtInt } from "../../lib/format.ts";

export const EXPORT_LIMIT = 100_000;

type Props = {
  open: boolean;
  onClose: () => void;
  /** The list query of the page (without paging). */
  query: string;
  /** Rows the filter matches, from the counts; null while unknown. */
  estimate: number | null;
  complete: boolean;
};

export function exportHref(query: string, format: "jsonl" | "csv"): string {
  const base = query.length > 0 ? query : "?";
  const joiner = base.endsWith("?") ? "" : "&";
  return `/api/requests/export${base}${joiner}format=${format}`;
}

export function ExportDialog({ open, onClose, query, estimate, complete }: Props) {
  const [format, setFormat] = useState<"jsonl" | "csv">("jsonl");
  const tooMany = estimate !== null && estimate > EXPORT_LIMIT;
  return (
    <Modal open={open} onCancel={onClose} footer={null} title="导出请求" width={520}>
      <div className="stack">
        <div className="field">
          <div className="field-label">格式</div>
          <Radio.Group
            value={format}
            onChange={(event) => setFormat(event.target.value as "jsonl" | "csv")}
            options={[
              { label: "JSONL（完整记录，每行一条）", value: "jsonl" },
              { label: "CSV（列表中的列）", value: "csv" },
            ]}
          />
        </div>
        <div className="small">
          预计行数：{estimate === null ? "计算中" : `${fmtInt(estimate)} 行`}
          {complete ? "" : "（按前 200 万条记录计算）"}
        </div>
        {tooMany ? (
          <div className="notice">
            超过 {fmtInt(EXPORT_LIMIT)} 行，导出会被截断。请缩小时间范围或增加条件后再导出。
          </div>
        ) : null}
        <div className="notice info">
          导出文件包含请求值、查询串和客户端 IP，属于个人信息，请按数据规定保管。
        </div>
        <div className="row" style={{ justifyContent: "flex-end" }}>
          <button type="button" className="btn" onClick={onClose}>
            取消
          </button>
          <a className="btn-primary" href={exportHref(query, format)} download>
            下载 {format === "jsonl" ? "JSONL" : "CSV"}
          </a>
        </div>
      </div>
    </Modal>
  );
}
