// The sites card of the overview (docs/06 6.4.2): one entry per site with its mode (and how long it has
// observed), its current version and whether the gateways run it, the last 24 hours, and the open
// suggestions. The rollout words follow docs/07 7.9.13.

import { Link } from "@tanstack/react-router";
import type { ReactNode } from "react";
import { useSites } from "../../api/queries.ts";
import type { SiteSummary } from "../../api/types.ts";
import { useNowBucket } from "../../app/scope.ts";
import { fmtInt } from "../../lib/format.ts";
import { isSiteName } from "../../lib/ids.ts";
import { errorText } from "../../lib/vocab.ts";
import { Card, Empty, ErrorBar, Loading } from "../../ui/Page.tsx";

const DAY_MS = 86_400_000;

type Rollout = { dot: string; text: string; tone: string };

/** The line under a site's name: "● v13 已生效", "1/2 个网关已生效", or the load error the gateway reported. */
function rolloutOf(site: SiteSummary): Rollout {
  const { rollout } = site;
  const offline = rollout.edges.filter((edge) => !edge.online).map((edge) => edge.edge);
  const suffix = offline.length > 0 ? `（${offline.join("、")} 离线）` : "";
  if (rollout.edges_online === 0) {
    return {
      dot: "dot-idle",
      text: "没有在线的网关，配置已保存，网关上线后加载",
      tone: "dim",
    };
  }
  const failed = rollout.edges.find((edge) => edge.online && edge.error !== null);
  if (failed?.error) {
    return {
      dot: "dot-down",
      text: `${failed.edge}：${errorText(failed.error)}`,
      tone: "hint-bad",
    };
  }
  if (rollout.edges_loaded > 0 && rollout.edges_loaded === rollout.edges_online) {
    return { dot: "dot-ok", text: `v${rollout.version} 已生效${suffix}`, tone: "" };
  }
  return {
    dot: "dot-warn",
    text: `${rollout.edges_loaded}/${rollout.edges_online} 个网关已生效${suffix}`,
    tone: "hint-warn",
  };
}

function SiteEntry({ site, now }: { site: SiteSummary; now: number }) {
  const rollout = rolloutOf(site);
  const observing = site.observing_since_millis;
  const days = observing === null ? null : Math.max(0, Math.floor((now - observing) / DAY_MS));
  const observed =
    days === null ? "" : days === 0 ? " · 今天开始观察" : ` · 已观察 ${fmtInt(days)} 天`;
  const mode = site.mode === "observe" ? `观察模式${observed}` : "拦截模式";
  const counted =
    site.mode === "observe"
      ? `本应拦截 ${fmtInt(site.would_block_24h)}`
      : `拦截 ${fmtInt(site.blocked_24h)}`;
  const linkable = isSiteName(site.name);
  const name: ReactNode = linkable ? (
    <Link to="/sites/$name" params={{ name: site.name }} className="ov-site-name">
      {site.name}
    </Link>
  ) : (
    <span className="ov-site-name">{site.name}</span>
  );

  return (
    <li className="ov-site">
      <div className="ov-site-head">
        {name}
        <span className={`ov-rollout ${rollout.tone}`}>
          <span className={`dot ${rollout.dot}`} aria-hidden="true" /> {rollout.text}
        </span>
      </div>
      <div className="ov-site-meta">
        {mode} · v{fmtInt(site.version)} · 24 小时 {fmtInt(site.requests_24h)} · {counted}
        {site.suggestions > 0 ? ` · 待处理建议 ${fmtInt(site.suggestions)}` : ""}
      </div>
    </li>
  );
}

export function SitesCard() {
  const sites = useSites();
  const now = useNowBucket();
  const list = sites.data?.sites ?? [];

  let body: ReactNode;
  if (sites.isPending) {
    body = <Loading height={64} />;
  } else if (!sites.data) {
    body = <ErrorBar error={sites.error} onRetry={() => void sites.refetch()} />;
  } else if (list.length === 0) {
    body = (
      <Empty title="还没有站点。">
        <p>新建一个站点，把它的 Host 解析到网关，就能开始观察。</p>
        <Link className="btn btn-primary" to="/sites/new">
          新建站点
        </Link>
      </Empty>
    );
  } else {
    body = (
      <ul className="ov-sites">
        {list.map((site) => (
          <SiteEntry key={site.name} site={site} now={now} />
        ))}
      </ul>
    );
  }

  return <Card title="站点">{body}</Card>;
}
