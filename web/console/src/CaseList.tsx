/** Owner-scoped case discovery. Opening a row reauthorizes its live collection. */
import { useEffect, useState } from "react";
import { ApiError } from "./api";
import type { CaseList as CaseListPage } from "./cases";

export function CaseList({
  active,
  busy,
  onLoad,
  onOpen,
}: {
  active: boolean;
  busy: boolean;
  onLoad: (
    cursor: string | undefined,
    apply: (page: CaseListPage) => void,
    fail: (error: unknown) => void,
  ) => void;
  onOpen: (caseId: string) => void;
}) {
  const [page, setPage] = useState<CaseListPage | null>(null);
  const [error, setError] = useState<unknown>(null);
  useEffect(() => {
    if (!active) {
      setPage(null);
      setError(null);
    }
  }, [active]);
  function load(cursor?: string) {
    setPage(null);
    setError(null);
    onLoad(cursor, setPage, setError);
  }

  return (
    <section className="panel case-list" aria-label="我的案件" aria-busy={busy}>
      <div className="panel-heading">
        <h2>我的案件</h2>
        <button className="outline" disabled={busy} onClick={() => load()}>
          读取我的案件 / 刷新列表
        </button>
      </div>
      <p className="footnote">
        包含本人开放和已关闭案件，按案件 ID
        降序。每页为独立观察；创建或关闭后请刷新。
      </p>
      {error !== null && (
        <div className="notice danger" role="alert">
          <div>
            {error instanceof ApiError
              ? error.message
              : "案件列表读取未完成，请重试。"}
            <small className="mono">
              {error instanceof ApiError
                ? error.code
                : "CONSOLE_REQUEST_FAILED"}
              {error instanceof ApiError && error.requestId
                ? ` · ${error.requestId}`
                : ""}
            </small>
          </div>
        </div>
      )}
      {page ? (
        <>
          <div className="case-list-observation">
            <span>
              数据库 as_of：<span className="mono">{page.as_of}</span>
            </span>
            <span>
              管理请求 ID：<span className="mono">{page.request_id}</span>
            </span>
          </div>
          {page.items.length === 0 ? (
            <p className="empty">当前页没有本人案件。</p>
          ) : (
            page.items.map((item) => (
              <article className="case-item" key={item.case_id}>
                <strong className="mono">{item.case_id}</strong>
                <span className="badge">
                  {item.status === "open" ? "open · 开放" : "closed · 已关闭"}
                </span>
                <p className="case-list-purpose">{item.purpose}</p>
                <p className="muted">
                  创建时间：<span className="mono">{item.created_at}</span>
                </p>
                <button
                  className="text-button"
                  disabled={busy}
                  onClick={() => onOpen(item.case_id)}
                >
                  打开案件 {item.case_id}
                </button>
              </article>
            ))
          )}
          <div className="pagination">
            <button
              className="outline"
              disabled={busy || !page.next_cursor}
              onClick={() => {
                if (page.next_cursor) load(page.next_cursor);
              }}
            >
              下一页案件
            </button>
            <span className="muted">
              本页 {page.items.length} 条 ·{" "}
              {page.truncated ? "还有后续案件" : "已到当前列表末页"}
            </span>
          </div>
        </>
      ) : (
        !error && (
          <p className="empty">读取本人案件后，选择一项打开证据集合。</p>
        )
      )}
    </section>
  );
}
