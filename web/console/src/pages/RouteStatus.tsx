/** Shown while a lazily loaded page chunk is fetched. No live region: one status at a time. */
export function RoutePending() {
  return (
    <p className="empty" aria-busy="true">
      正在加载页面…
    </p>
  );
}

/** A page threw while rendering. Nothing about the failure is echoed into the DOM. */
export function RouteFailure({ error }: { error: unknown }) {
  void error;
  return (
    <div className="notice danger">
      <div>
        页面渲染失败，请刷新页面后重试。
        <small className="mono">CONSOLE_RENDER_FAILED</small>
      </div>
    </div>
  );
}
