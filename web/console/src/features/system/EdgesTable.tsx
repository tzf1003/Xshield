// The "网关" tab (docs/06 6.4.11): one row per gateway instance with its heartbeat, its counters and,
// behind "详情", the load result of each site and the Jev line the instance runs with (its endpoint and
// model, never a key). The instance's own gap history sits in the details as well.

import { useState } from "react";
import type { EdgeStatus, LogGap } from "../../api/types.ts";
import { fmtAgo, fmtInt, fmtLocalDateTime, fmtMs } from "../../lib/format.ts";
import { errorText, ROUTE_LABEL } from "../../lib/vocab.ts";
import { Empty } from "../../ui/Page.tsx";
import { hm, parseTime, shortDateTime } from "./clock.ts";

const GAP_REASON: Record<LogGap["reason"], string> = {
  queue_full: "队列满",
  write_error: "写入失败",
};

type SiteState = { version?: number; error?: string };

export function EdgesTable({
  edges,
  gaps,
  now,
}: {
  edges: EdgeStatus[];
  gaps: LogGap[];
  now: number;
}) {
  if (edges.length === 0) {
    return (
      <Empty title="还没有网关上报过心跳。">
        <p>网关上线后，每个实例会在这里出现一行。</p>
      </Empty>
    );
  }
  return (
    <div className="tbl-wrap">
      <table className="tbl">
        <caption className="sr-only">网关实例</caption>
        <thead>
          <tr>
            <th scope="col">实例</th>
            <th scope="col">状态</th>
            <th scope="col">心跳</th>
            <th scope="col">启动时间</th>
            <th scope="col">构建版本</th>
            <th scope="col">监听</th>
            <th scope="col">TLS</th>
            <th scope="col" className="num">
              会话
            </th>
            <th scope="col" className="num">
              发送队列
            </th>
            <th scope="col" className="num">
              已写入
            </th>
            <th scope="col" className="num">
              丢弃
            </th>
            <th scope="col" className="num">
              写入失败
            </th>
            <th scope="col">
              <span className="sr-only">详情</span>
            </th>
          </tr>
        </thead>
        {edges.map((edge) => (
          <EdgeRows
            key={edge.edge}
            edge={edge}
            gaps={gaps.filter((gap) => gap.edge === edge.edge)}
            now={now}
          />
        ))}
      </table>
    </div>
  );
}

function EdgeRows({ edge, gaps, now }: { edge: EdgeStatus; gaps: LogGap[]; now: number }) {
  const [open, setOpen] = useState(false);
  const seen = parseTime(edge.seen_at);
  const started = parseTime(edge.started_at);
  const detailId = `sys-edge-${edge.edge.replace(/[^a-zA-Z0-9_-]/g, "_")}`;
  const sites = Object.entries(edge.sites).sort(([a], [b]) => a.localeCompare(b));

  return (
    <tbody>
      <tr>
        <td>
          <span className="sys-name">{edge.edge}</span>
        </td>
        <td>
          <span className={`dot ${edge.online ? "dot-ok" : "dot-down"}`} aria-hidden="true" />{" "}
          {edge.online ? "在线" : "离线"}
        </td>
        <td className="tnum" title="30 秒内有心跳为在线">
          {seen === null ? "—" : fmtAgo(seen, now)}
        </td>
        <td className="tnum">{started === null ? "—" : fmtLocalDateTime(started)}</td>
        <td className="mono small">{edge.build}</td>
        <td className="mono small">{edge.listen}</td>
        <td>{edge.tls ? "是" : "否"}</td>
        <td className="num tnum">{fmtInt(edge.sessions)}</td>
        <td className="num tnum">{fmtInt(edge.queue)}</td>
        <td className="num tnum">{fmtInt(edge.written)}</td>
        <td className="num tnum">{fmtInt(edge.dropped)}</td>
        <td className="num tnum">{fmtInt(edge.write_errors)}</td>
        <td>
          <button
            type="button"
            className="linkbtn"
            aria-expanded={open}
            aria-controls={detailId}
            onClick={() => setOpen((value) => !value)}
          >
            {open ? "收起" : "详情"}
          </button>
        </td>
      </tr>
      <tr id={detailId} hidden={!open} className="sys-detail">
        <td colSpan={13}>{open ? <EdgeDetail edge={edge} sites={sites} gaps={gaps} /> : null}</td>
      </tr>
    </tbody>
  );
}

function EdgeDetail({
  edge,
  sites,
  gaps,
}: {
  edge: EdgeStatus;
  sites: Array<[string, SiteState]>;
  gaps: LogGap[];
}) {
  return (
    <div className="sys-detail-grid">
      <section>
        <h3 className="sys-h">站点加载</h3>
        {sites.length === 0 ? (
          <p className="muted small">这个实例还没有加载任何站点。</p>
        ) : (
          <table className="tbl sys-mini">
            <thead>
              <tr>
                <th scope="col">站点</th>
                <th scope="col">结果</th>
              </tr>
            </thead>
            <tbody>
              {sites.map(([name, state]) => (
                <tr key={name}>
                  <td className="mono">{name}</td>
                  <td>
                    {state.error ? (
                      <span className="hint-bad">
                        {errorText(state.error)}{" "}
                        <span className="mono small dim">{state.error}</span>
                      </span>
                    ) : state.version === undefined ? (
                      "未加载"
                    ) : (
                      `已加载 v${fmtInt(state.version)}`
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
      <section>
        <h3 className="sys-h">Jev 线路</h3>
        <dl className="kv">
          <dt>线路</dt>
          <dd>{ROUTE_LABEL[edge.jev.route]}</dd>
          <dt>端点主机名</dt>
          <dd className="mono">{edge.jev.endpoint_host}</dd>
          <dt>模型</dt>
          <dd className="mono">{edge.jev.model}</dd>
          <dt>默认超时</dt>
          <dd>{fmtMs(edge.jev.default_timeout_ms)}</dd>
          <dt>指令版本</dt>
          <dd className="mono">{edge.jev.prompt}</dd>
        </dl>
      </section>
      <section>
        <h3 className="sys-h">这个实例的日志缺口</h3>
        {gaps.length === 0 ? (
          <p className="muted small">最近 24 小时没有缺口。</p>
        ) : (
          <ul className="sys-list">
            {gaps.map((gap) => (
              <li key={`${gap.from_millis}-${gap.reason}`}>
                {`${shortDateTime(gap.from_millis)} – ${hm(gap.to_millis)}：${fmtInt(gap.rows)} 条判定记录（${GAP_REASON[gap.reason]}）`}
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
