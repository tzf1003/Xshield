// The "网关" tab (docs/06 6.4.11): one row per gateway instance with its heartbeat and its counters. Behind
// "详情" sit the load result of each site, the Jev line the instance runs with (its endpoint and model,
// never a key) and the instance's own loss windows (docs/07 7.7.4, 7.9.8).

import { useState } from "react";
import type { EdgeStatus } from "../../api/types.ts";
import { fmtAgo, fmtInt, fmtLocalDateTime, fmtMs, fmtUtc } from "../../lib/format.ts";
import { errorText, ROUTE_LABEL } from "../../lib/vocab.ts";
import { Empty } from "../../ui/Page.tsx";
import { hm, parseTime, shortDateTime } from "./clock.ts";

/** Columns of the instance table; the detail row spans all of them. */
const COLUMNS = 14;

type SiteState = { version?: number; error?: string; loaded_at_millis?: number };

/** "已加载 v13", with when the instance loaded that version: local time, UTC on hover (docs/06 6.6.6). */
function LoadedVersion({ version, loaded_at_millis }: SiteState) {
  const text = `已加载 v${fmtInt(version)}`;
  if (loaded_at_millis === undefined) {
    return <>{text}</>;
  }
  return (
    <span title={fmtUtc(loaded_at_millis)}>{`${text}（${shortDateTime(loaded_at_millis)}）`}</span>
  );
}

export function EdgesTable({ edges, now }: { edges: EdgeStatus[]; now: number }) {
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
            <th scope="col" className="num" title="队列满时丢弃的判定记录">
              丢弃
            </th>
            <th scope="col" className="num" title="队列压力下主动丢弃的绕过简记录">
              绕过丢弃
            </th>
            <th scope="col" className="num" title="写入失败丢失的行数">
              写入失败
            </th>
            <th scope="col">
              <span className="sr-only">详情</span>
            </th>
          </tr>
        </thead>
        {edges.map((edge) => (
          <EdgeRows key={edge.edge} edge={edge} now={now} />
        ))}
      </table>
    </div>
  );
}

function EdgeRows({ edge, now }: { edge: EdgeStatus; now: number }) {
  const [open, setOpen] = useState(false);
  const seen = parseTime(edge.seen_at);
  const started = parseTime(edge.started_at);
  const detailId = `sys-edge-${edge.edge.replace(/[^a-zA-Z0-9_-]/g, "_")}`;
  const sites = Object.entries(edge.sites).sort(([a], [b]) => a.localeCompare(b));

  return (
    <tbody>
      <tr>
        <td className="keep">
          <span className="sys-name">{edge.edge}</span>
        </td>
        <td className="keep">
          <span className={`dot ${edge.online ? "dot-ok" : "dot-down"}`} aria-hidden="true" />{" "}
          {edge.online ? "在线" : "离线"}
        </td>
        <td className="tnum" title="30 秒内有心跳为在线">
          {seen === null ? "—" : fmtAgo(seen, now)}
        </td>
        <td className="tnum wrap">{started === null ? "—" : fmtLocalDateTime(started)}</td>
        <td className="mono small wrap">{edge.build}</td>
        <td className="mono small keep">{edge.listen}</td>
        <td className="keep">{edge.tls ? "是" : "否"}</td>
        <td className="num tnum">{fmtInt(edge.sessions)}</td>
        <td className="num tnum">{fmtInt(edge.queue)}</td>
        <td className="num tnum">{fmtInt(edge.written)}</td>
        <td className="num tnum">{fmtInt(edge.dropped)}</td>
        <td className="num tnum">{fmtInt(edge.dropped_bypass)}</td>
        <td className="num tnum">{fmtInt(edge.write_errors)}</td>
        <td className="keep">
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
        <td colSpan={COLUMNS}>{open ? <EdgeDetail edge={edge} sites={sites} /> : null}</td>
      </tr>
    </tbody>
  );
}

function EdgeDetail({ edge, sites }: { edge: EdgeStatus; sites: Array<[string, SiteState]> }) {
  const gaps = [...edge.gaps].sort((a, b) => b.from_ms - a.from_ms);
  return (
    <div className="sys-detail-grid">
      <section>
        <h2 className="sys-h">站点加载</h2>
        {sites.length === 0 ? (
          <p className="muted small">这个实例还没有加载任何站点。</p>
        ) : (
          <div className="tbl-wrap">
            <table className="tbl sys-mini">
              <caption className="sr-only">这个实例的站点加载结果</caption>
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
                        <>
                          <span className="hint-bad">
                            {errorText(state.error)}{" "}
                            <span className="mono small dim">{state.error}</span>
                          </span>
                          {state.version === undefined ? null : (
                            <div className="small dim">
                              <LoadedVersion {...state} />
                            </div>
                          )}
                        </>
                      ) : state.version === undefined ? (
                        "未加载"
                      ) : (
                        <LoadedVersion {...state} />
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      <section>
        <h2 className="sys-h">Jev 线路</h2>
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
        <h2 className="sys-h">这个实例的日志缺口</h2>
        {gaps.length === 0 ? (
          <p className="muted small">这个实例没有上报过缺口。</p>
        ) : (
          <div className="tbl-wrap">
            <table className="tbl sys-mini">
              <caption className="sr-only">这个实例的日志缺口</caption>
              <thead>
                <tr>
                  <th scope="col">起止时间</th>
                  <th scope="col" className="num">
                    丢弃
                  </th>
                  <th scope="col" className="num">
                    绕过丢弃
                  </th>
                  <th scope="col" className="num">
                    写入失败
                  </th>
                </tr>
              </thead>
              <tbody>
                {gaps.map((gap) => (
                  <tr key={gap.from_ms}>
                    <td className="tnum">{`${shortDateTime(gap.from_ms)} – ${hm(gap.to_ms)}`}</td>
                    <td className="num tnum">{fmtInt(gap.dropped)}</td>
                    <td className="num tnum">{fmtInt(gap.dropped_bypass)}</td>
                    <td className="num tnum">{fmtInt(gap.write_errors)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
