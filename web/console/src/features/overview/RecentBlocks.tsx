// The latest blocked and would-block requests (docs/06 6.4.2): ten rows, each opening its record. The
// path is shown as text (it comes from the request), and the link is built only from a request id that
// passes the format check.

import { Link } from "@tanstack/react-router";
import type { ReactNode } from "react";
import { useRequests } from "../../api/queries.ts";
import { keepScope, type Scope, scopeQuery, useGlobalSearch } from "../../app/scope.ts";
import { fmtLocalDateTime } from "../../lib/format.ts";
import { isRequestId } from "../../lib/ids.ts";
import { DecisionTag, JevCell, OutcomeTag } from "../../ui/Badges.tsx";
import { Card, Empty, ErrorBar, Loading } from "../../ui/Page.tsx";
import { SafeText } from "../../ui/SafeText.tsx";
import { hms } from "./clock.ts";

const ROWS = 10;

function PathLink({ id, path }: { id: string; path: string }) {
  if (!isRequestId(id)) return <span className="path">{path}</span>;
  return (
    <Link
      to="/requests/$requestId"
      params={{ requestId: id }}
      search={keepScope}
      className="path"
      title={id}
    >
      <SafeText text={path} />
    </Link>
  );
}

export function RecentBlocks({ scope }: { scope: Scope }) {
  const rows = useRequests(scopeQuery(scope, { outcome: "blocked,would_block", limit: ROWS }));
  const globalSearch = useGlobalSearch();

  let body: ReactNode;
  if (rows.isPending) {
    body = <Loading height={120} />;
  } else if (!rows.data) {
    body = <ErrorBar error={rows.error} onRetry={() => void rows.refetch()} />;
  } else if (rows.data.rows.length === 0) {
    body = (
      <Empty title="最近没有拦截，也没有本应拦截的请求。">
        <Link to="/requests" search={{ ...globalSearch, chip: "attention" }}>
          查看请求追溯
        </Link>
      </Empty>
    );
  } else {
    body = (
      <div className="tbl-wrap">
        <table className="tbl ov-recent">
          <thead>
            <tr>
              <th scope="col">时间</th>
              <th scope="col">站点</th>
              <th scope="col">方法</th>
              <th scope="col">路径</th>
              <th scope="col">结论</th>
              <th scope="col">判定与 Jev</th>
            </tr>
          </thead>
          <tbody>
            {rows.data.rows.map((row) => (
              <tr key={row.request_id}>
                <td className="tnum" title={fmtLocalDateTime(row.at_millis)}>
                  {hms(row.at_millis)}
                </td>
                <td>{row.site ?? "—"}</td>
                <td className="mono small">{row.method}</td>
                <td className="path-cell">
                  <PathLink id={row.request_id} path={row.path} />
                </td>
                <td>
                  <OutcomeTag outcome={row.outcome} />
                </td>
                <td>
                  <span className="ov-judge">
                    <DecisionTag path={row.decision_path} />
                    <JevCell jev={row.jev} />
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  return (
    <Card
      title="最近的拦截与本应拦截"
      aside={
        <Link to="/requests" search={{ ...globalSearch, chip: "attention" }}>
          全部 →
        </Link>
      }
    >
      {body}
    </Card>
  );
}
