// The error page of a route. A render error replaces that page's content only: the shell stays, and the
// visitor can retry or go back to the request list. The message is shown as text, never as markup.

import { type ErrorComponentProps, Link } from "@tanstack/react-router";
import { SafeText } from "../ui/SafeText.tsx";
import { keepScope } from "./scope.ts";

export function RouteError({ error, reset }: ErrorComponentProps) {
  const message = error instanceof Error ? error.message : String(error);
  return (
    <div className="route-error" role="alert">
      <h1 className="empty-title">这个页面出错了</h1>
      <div className="small dim">页面没能显示出来。可以重试；如果还是出错，回到请求追溯。</div>
      <div className="mono small dim">
        <SafeText text={message} />
      </div>
      <div className="row">
        <button type="button" className="btn" onClick={() => reset()}>
          重试
        </button>
        <Link to="/requests" search={keepScope}>
          返回请求追溯
        </Link>
      </div>
    </div>
  );
}
