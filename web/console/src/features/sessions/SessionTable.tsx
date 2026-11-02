// The session list as a table (docs/06 6.4.7): the label (first eight characters, the full one on hover)
// opens the session's timeline; the times are relative and their exact value is on hover. The
// issuing request (the login that created the session) links to its record.

import { Link } from "@tanstack/react-router";
import type { SessionRow } from "../../api/types.ts";
import { keepScope } from "../../app/scope.ts";
import { fmtAgo, fmtInt, fmtLocalDateTime } from "../../lib/format.ts";
import { isSessionLabel, shortSession } from "../../lib/ids.ts";
import { ContextTag } from "../../ui/Badges.tsx";
import { RequestLink } from "../../ui/RequestRef.tsx";
import { SafeText } from "../../ui/SafeText.tsx";

const COLUMNS: Array<{ key: string; label: string; width: number; num?: boolean }> = [
  { key: "session", label: "会话", width: 112 },
  { key: "context", label: "上下文", width: 76 },
  { key: "site", label: "站点", width: 100 },
  { key: "first", label: "首次活动", width: 116 },
  { key: "last", label: "最后活动", width: 116 },
  { key: "requests", label: "请求", width: 72, num: true },
  { key: "jev", label: "Jev 调用", width: 92, num: true },
  { key: "blocked", label: "拦截", width: 72, num: true },
  { key: "would", label: "本应拦截", width: 96, num: true },
  { key: "issued", label: "签发它的请求", width: 132 },
];

function Head() {
  return (
    <thead>
      <tr>
        {COLUMNS.map((column) => (
          <th
            key={column.key}
            scope="col"
            className={column.num ? "num" : undefined}
            style={{ width: column.width }}
          >
            {column.label}
          </th>
        ))}
      </tr>
    </thead>
  );
}

const SKELETON_ROWS = ["a", "b", "c", "d", "e", "f"];

/** The first load of the list: skeleton rows that keep the table's shape (docs/06 6.7.1). */
export function SessionTableSkeleton() {
  return (
    <div className="tbl-wrap" aria-busy="true">
      <div className="sr-only" role="status">
        正在加载
      </div>
      <table className="tbl" aria-label="会话列表">
        <Head />
        <tbody>
          {SKELETON_ROWS.map((row) => (
            <tr key={row}>
              {COLUMNS.map((column) => (
                <td key={column.key}>
                  <span
                    className="skeleton"
                    aria-hidden="true"
                    style={{ width: "70%", height: 12 }}
                  />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function SessionTable({ rows, now }: { rows: SessionRow[]; now: number }) {
  return (
    <div className="tbl-wrap">
      <table className="tbl" aria-label="会话列表">
        <Head />
        <tbody>
          {rows.map((row) => (
            <SessionLine key={row.label} row={row} now={now} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function SessionLine({ row, now }: { row: SessionRow; now: number }) {
  return (
    <tr>
      <td className="keep">
        {isSessionLabel(row.label) ? (
          <Link
            to="/sessions/$label"
            params={{ label: row.label }}
            search={keepScope}
            className="mono"
            title={row.label}
            aria-label={`会话 ${row.label} 的时间线`}
          >
            {shortSession(row.label)}
          </Link>
        ) : (
          <span className="mono">{shortSession(row.label)}</span>
        )}
      </td>
      <td className="keep">
        <ContextTag context={row.context} />
      </td>
      <td className="keep" title={row.site ?? undefined}>
        {row.site === null ? <span className="dim">—</span> : <SafeText text={row.site} />}
      </td>
      <td className="tnum" title={fmtLocalDateTime(row.first_at_millis)}>
        {fmtAgo(row.first_at_millis, now)}
      </td>
      <td className="tnum" title={fmtLocalDateTime(row.last_at_millis)}>
        {fmtAgo(row.last_at_millis, now)}
      </td>
      <td className="num tnum">{fmtInt(row.requests)}</td>
      <td className="num tnum">{fmtInt(row.jev_calls)}</td>
      <td className="num tnum">{fmtInt(row.blocked)}</td>
      <td className="num tnum">{fmtInt(row.would_block)}</td>
      <td className="keep">
        {row.issued_by === null ? (
          <span className="dim">—</span>
        ) : (
          <RequestLink id={row.issued_by} />
        )}
      </td>
    </tr>
  );
}
