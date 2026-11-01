// The site list at /sites (docs/06 6.4.8): one row per site with its hosts, origin, mode, the state of the gateways
// for its current version, and the figures of the last 24 hours. "新建站点" opens the new-site page.

import { Link } from "@tanstack/react-router";
import { useSites } from "../../api/queries.ts";
import type { SiteSummary } from "../../api/types.ts";
import { useNowBucket } from "../../app/scope.ts";
import { fmtInt } from "../../lib/format.ts";
import { Empty, ErrorBar, Loading, PageHead } from "../../ui/Page.tsx";
import { observedText } from "./Readiness.tsx";
import { rolloutListText } from "./rollout.ts";
import "./sites.css";

function modeText(site: SiteSummary, now: number): string {
  if (site.mode === "enforce") return "拦截";
  if (site.observing_since_millis === null) return "观察";
  return `观察 ${observedText(now - site.observing_since_millis)}`;
}

export function SitesPage() {
  const sites = useSites();
  const now = useNowBucket(30_000);
  const list = sites.data?.sites ?? [];

  return (
    <>
      <PageHead
        title="站点"
        sub={sites.data ? `${fmtInt(list.length)} 个站点` : sites.isError ? "无法读取" : "正在读取"}
        actions={
          <Link to="/sites/new" className="btn-primary">
            新建站点
          </Link>
        }
      />

      {sites.isPending ? <Loading height={200} /> : null}
      {sites.isError ? <ErrorBar error={sites.error} onRetry={() => void sites.refetch()} /> : null}

      {sites.data && list.length === 0 ? (
        <Empty title="还没有站点">
          <Link to="/sites/new" className="linkbtn">
            新建站点
          </Link>
          ，把第一个 Host 接入网关。
        </Empty>
      ) : null}

      {list.length > 0 ? (
        <div className="tbl-wrap">
          <table className="tbl" aria-label="站点列表">
            <thead>
              <tr>
                <th scope="col">名称</th>
                <th scope="col">Host</th>
                <th scope="col">源站</th>
                <th scope="col">模式</th>
                <th scope="col">版本与生效</th>
                <th scope="col" className="num">
                  24 小时请求
                </th>
                <th scope="col" className="num">
                  拦截 / 本应拦截
                </th>
                <th scope="col" className="num">
                  Jev 调用
                </th>
                <th scope="col" className="num">
                  待处理建议
                </th>
              </tr>
            </thead>
            <tbody>
              {list.map((site) => {
                // The state is the glyph and the words (docs/06 6.5.3): the text itself stays in ink.
                const status = rolloutListText(site.rollout, site.updated_at, now);
                return (
                  <tr key={site.name}>
                    <td className="cell-name">
                      <Link to="/sites/$name" params={{ name: site.name }} className="site-name">
                        {site.name}
                      </Link>
                    </td>
                    <td className="mono">{site.hosts.join("、")}</td>
                    <td className="mono">{site.origin}</td>
                    <td>{modeText(site, now)}</td>
                    <td>{status.text}</td>
                    <td className="num tnum">{fmtInt(site.requests_24h)}</td>
                    <td className="num tnum">
                      {site.mode === "enforce"
                        ? `${fmtInt(site.blocked_24h)} 拦截`
                        : `${fmtInt(site.would_block_24h)} 本应拦截`}
                    </td>
                    <td className="num tnum">{fmtInt(site.jev_calls_24h)}</td>
                    <td className="num tnum">
                      {site.suggestions > 0 ? fmtInt(site.suggestions) : "—"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : null}
    </>
  );
}
