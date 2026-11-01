// The overview of a site (docs/06 6.4.9): the 24-hour figures, the paths that would have been blocked most, and,
// while the site observes, the readiness checklist. The trend line of 6.4.2 is not shown here. The Jev evidence
// is not read here: the Advanced group of the configuration tab reads it when it opens (docs/07 7.10.4).

import { useInsights } from "../../api/queries.ts";
import type { SiteDetail } from "../../api/types.ts";
import { fmtInt } from "../../lib/format.ts";
import { Card, ErrorBar, Loading, Tile } from "../../ui/Page.tsx";
import { ReadinessList } from "./Readiness.tsx";

type Props = {
  site: SiteDetail;
  now: number;
  onInsights: () => void;
};

export function OverviewTab({ site, now, onInsights }: Props) {
  const observing = site.mode === "observe";
  const insights = useInsights(site.name);
  const hot = [...(insights.data?.suggestions ?? [])]
    .filter((item) => item.kind === "hot_would_block")
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);

  return (
    <div className="stack">
      <div className="tiles">
        <Tile
          label="24 小时请求"
          value={fmtInt(site.requests_24h)}
          to="/requests"
          search={{ site: site.name }}
        />
        <Tile
          label={observing ? "本应拦截" : "拦截"}
          value={fmtInt(observing ? site.would_block_24h : site.blocked_24h)}
          sub={observing ? "观察模式只记录，不拦截" : "返回 401 / 403"}
          to="/requests"
          search={{ site: site.name, chip: observing ? "would_block" : "blocked" }}
        />
        <Tile
          label="Jev 调用"
          value={fmtInt(site.jev_calls_24h)}
          to="/jev"
          search={{ site: site.name }}
        />
        <Tile
          label="待处理建议"
          value={fmtInt(site.suggestions)}
          sub={
            <button type="button" className="linkbtn" onClick={onInsights}>
              查看调优建议
            </button>
          }
        />
      </div>

      <div className="grid-main-side">
        <div className="stack">
          <Card
            title="本应拦截最多的路径"
            aside={insights.data ? `最近 ${fmtInt(insights.data.window_hours)} 小时` : undefined}
          >
            {insights.isPending ? (
              <Loading height={80} />
            ) : insights.isError ? (
              <ErrorBar error={insights.error} onRetry={() => void insights.refetch()} />
            ) : hot.length === 0 ? (
              <div className="small muted">没有集中的本应拦截路径。</div>
            ) : (
              <ul className="changes" aria-label="本应拦截最多的路径">
                {hot.map((item) => (
                  <li key={item.id}>
                    <span className="mono">
                      {item.method ? `${item.method} ` : ""}
                      {item.path ?? ""}
                    </span>{" "}
                    <span className="tnum">{fmtInt(item.count)} 次</span>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </div>

        {observing ? (
          <div className="stack">
            <Card title="就绪检查">
              {insights.isPending ? (
                <Loading height={120} />
              ) : (
                <ReadinessList
                  readiness={insights.data?.readiness ?? null}
                  now={now}
                  site={site.name}
                />
              )}
            </Card>
          </div>
        ) : null}
      </div>
    </div>
  );
}
