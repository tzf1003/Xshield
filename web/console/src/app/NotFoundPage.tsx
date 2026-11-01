// Any address the route tree does not know. Pages with a missing record show their own "not found"
// state instead (docs/06 6.2.2), so this page is only for the address itself.

import { Link } from "@tanstack/react-router";

export function NotFoundPage() {
  return (
    <div className="login-page">
      <div className="notfound">
        <div className="empty-title">找不到这个页面</div>
        <p className="muted">地址可能写错了，或者页面已经移动。</p>
        <Link to="/">回到总览</Link>
      </div>
    </div>
  );
}
