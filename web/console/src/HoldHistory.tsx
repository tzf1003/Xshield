import type { HoldCollection, HoldRecord } from "./evidence-holds";
import { Rows } from "./panels";

/** Canonical UTC fractions are normalized before comparison, preserving micros. */
function atOrBefore(left: string, right: string) {
  return left.replace(/\.(\d+)Z$/, (_, part: string) => `.${part.padEnd(6, "0")}Z`) <=
    right.replace(/\.(\d+)Z$/, (_, part: string) => `.${part.padEnd(6, "0")}Z`);
}

export function HoldHistory({ page, busy, canSelect, onSelect, onHistory, onNext }: {
  page: HoldCollection;
  busy: boolean;
  canSelect: boolean;
  onSelect: (hold: HoldRecord) => void;
  onHistory: (holdId: string) => void;
  onNext: (cursor: string) => void;
}) {
  return <>
    <div className="case-snapshot detail-body">
      <Rows entries={[
        ["历史案件", page.case_id], ["案件状态", page.case_status],
        ["数据库 as_of", page.as_of], ["管理请求 ID", page.request_id],
      ]} />
    </div>
    {page.items.length === 0 ? <p className="empty">当前案件没有保留历史。</p> : page.items.map((hold) => {
      const expired = atOrBefore(hold.hold_until, page.as_of);
      return <article className="case-item case-snapshot" key={hold.hold_id}>
        <strong className="mono">{hold.hold_id}</strong>
        <span className="badge">{hold.released_at ? "已释放" : expired ? "保留期限已过" : "保留生效中"}</span>
        <Rows entries={[
          ["证据", hold.artifact_id], ["创建人", hold.created_by],
          ["保留理由", hold.reason], ["创建时间", hold.created_at],
          ["保留至", hold.hold_until], ["持久释放状态", hold.released_at ? "released · 已释放" : "unreleased · 未释放"],
          ["保留期限已过", expired ? "是" : "否"],
          ["释放人", hold.released_by ?? "—"], ["释放理由", hold.released_reason ?? "—"],
          ["释放时间", hold.released_at ?? "—"], ["释放事件", hold.released_event_id ?? "—"],
        ]} />
        <div className="case-actions">
          <button className="text-button" disabled={busy || !canSelect || hold.released_at !== null}
            onClick={() => onSelect(hold)}>选择释放 {hold.hold_id}</button>
          <button type="button" className="text-button" disabled={busy}
            aria-label={`准备历史检索 ${hold.hold_id}`}
            onClick={() => onHistory(hold.hold_id)}>准备历史检索</button>
        </div>
        <p className="footnote">
          历史检索仅预填保留锁引用；仍需填写 UTC 时间窗并由服务端独立校验权限。
        </p>
      </article>;
    })}
    <div className="pagination">
      <button className="outline" disabled={busy || !page.next_cursor}
        onClick={() => { if (page.next_cursor) onNext(page.next_cursor); }}>下一页保留历史</button>
      <span className="muted">本页 {page.items.length} 条 · {page.truncated ? "还有后续记录" : "已到当前列表末页"}</span>
    </div>
  </>;
}
