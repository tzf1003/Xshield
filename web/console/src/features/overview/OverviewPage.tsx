// The overview at "/" (docs/06 6.4.2): in thirty seconds, whether everything is normal and what needs
// handling. The sections read the status, the sites, the summary, the hourly series and the latest
// blocks; each one shows its own loading, empty and error states.

import { useScope } from "../../app/scope.ts";
import { RANGE_LABEL } from "../../lib/vocab.ts";
import { PageHead } from "../../ui/Page.tsx";
import { NeedsAttention } from "./NeedsAttention.tsx";
import { RecentBlocks } from "./RecentBlocks.tsx";
import { SitesCard } from "./SitesCard.tsx";
import { SummaryTiles } from "./SummaryTiles.tsx";
import { TrendCard } from "./TrendChart.tsx";
import "./overview.css";

export function OverviewPage() {
  const scope = useScope();
  const siteText = scope.site ? `站点 ${scope.site}` : "全部站点";
  const windowText = scope.range === "custom" ? "自定义时间段" : `最近 ${RANGE_LABEL[scope.range]}`;

  return (
    <>
      <PageHead title="总览" sub={`${siteText} · ${windowText}`} />
      <section className="ov-section">
        <NeedsAttention />
      </section>
      <section className="ov-section">
        <SummaryTiles scope={scope} />
      </section>
      <div className="ov-section grid-main-side">
        <TrendCard scope={scope} />
        <SitesCard />
      </div>
      <section className="ov-section">
        <RecentBlocks scope={scope} />
      </section>
    </>
  );
}
