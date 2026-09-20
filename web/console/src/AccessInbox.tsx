/** Explicitly loaded access metadata. Opening a row always obtains new detail
 * authorization; listing does not establish an approval or download capability. */
import { useEffect, useState } from "react";
import { ApiError } from "./api";
import type { ControlClient, Envelope } from "./api";
import type { AccessList, AccessListView } from "./evidence-access";
import { Rows } from "./panels";

type Run = <T extends Envelope>(
  fetcher: (api: ControlClient, signal: AbortSignal) => Promise<T>,
  apply: (response: T) => void,
  fail: (error: unknown) => void,
) => Promise<boolean>;

export function AccessInbox({ active, busy, onInvalidate, onRun, onOpen }: {
  active: boolean;
  busy: boolean;
  onInvalidate: () => void;
  onRun: Run;
  onOpen: (accessId: string) => void;
}) {
  const [view, setView] = useState<AccessListView>("mine");
  const [page, setPage] = useState<AccessList | null>(null);
  const [error, setError] = useState<unknown>(null);
  useEffect(() => {
    if (!active) {
      setPage(null);
      setError(null);
    }
  }, [active]);
  function read(cursor?: string) {
    if (busy || !active) return;
    onInvalidate();
    setPage(null);
    setError(null);
    void onRun<AccessList>(
      (api, signal) => api.evidenceAccessList(view, cursor, signal),
      setPage,
      setError,
    );
  }
  return (
    <section className="panel access-inbox" aria-label="访问申请列表" aria-busy={busy}>
      <div className="panel-heading">
        <h2>访问申请列表</h2>
        <span className="muted">本人历史 · 独立复核</span>
      </div>
      <div className="case-form">
        <label htmlFor="access-list-view">申请列表范围</label>
        <select id="access-list-view" value={view} onChange={(event) => {
          onInvalidate();
          setPage(null);
          setError(null);
          setView(event.target.value as AccessListView);
        }}>
          <option value="mine">我的申请</option>
          <option value="review">审批待办</option>
        </select>
        <p className="muted">
          我的申请展示本人历史记录，需 Investigator、SensitiveEvidenceReader 或 SensitiveEvidenceApprover。
          审批待办展示其他申请人的待决记录，需 SensitiveEvidenceApprover。
          列表由服务端按当前身份与作用域筛选；审批时再次校验角色、归属与状态。
        </p>
        <button disabled={busy} onClick={() => read()}>读取申请列表 / 刷新</button>
      </div>
      {Boolean(error) && <div className="notice danger" role="alert">
        <div>{error instanceof ApiError ? error.message : "申请列表读取未完成，请重试。"}
          <small className="mono">
            {error instanceof ApiError ? error.code : "CONSOLE_REQUEST_FAILED"}
            {error instanceof ApiError && error.requestId ? ` · ${error.requestId}` : ""}
          </small>
        </div>
      </div>}
      {page ? <div aria-live="polite">
        <Rows entries={[
          ["列表观察时间", page.as_of],
          ["管理请求 ID", page.request_id],
          ["本页申请数", page.items.length],
        ]} />
        {page.items.length === 0 && <p className="empty">
          {page.view === "mine" ? "当前范围内暂无本人申请。" : "当前范围内暂无审批待办。"}
        </p>}
        {page.items.map((item) => <article className="case-result" key={item.access_request_id}>
          <Rows entries={[
            ["申请 ID", <span className="mono">{item.access_request_id}</span>],
            ["申请人", item.requested_by],
            ["记录状态", item.stored_status],
            ["申请时间", item.requested_at],
            ["案件 ID", <span className="mono">{item.case_id}</span>],
            ["证据 ID", <span className="mono">{item.artifact_id}</span>],
          ]} />
          <button className="outline" disabled={busy}
            aria-label={`打开申请 ${item.access_request_id}`}
            onClick={() => onOpen(item.access_request_id)}>打开申请</button>
        </article>)}
        <p className="muted">每页按申请 ID 倒序读取当前记录；新增或已处理申请可通过刷新查看。</p>
        {page.next_cursor && <button className="outline" disabled={busy}
          onClick={() => read(page.next_cursor ?? undefined)}>下一页申请</button>}
      </div> : !error && <p className="empty">选择范围并读取申请列表，再打开申请复核详情。</p>}
    </section>
  );
}
