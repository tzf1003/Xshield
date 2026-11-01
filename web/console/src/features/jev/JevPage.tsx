// The Jev page (docs/06 6.4.6): the health card, the latency and confidence histograms, the answers by
// hour, the quick chips with their counts, the condition line, and the list of requests that carry a
// Jev exchange. Everything follows the global scope (site and time window) and the page's own search
// (`chip`, `q`), so a copied link opens the same view.

import { useSearch } from "@tanstack/react-router";
import { useMemo } from "react";
import { useJevStats, useJevStatus, useSite } from "../../api/queries.ts";
import { scopeQuery, useNowBucket, useScope, useSetSearch } from "../../app/scope.ts";
import type { JevChip } from "../../app/search-schema.ts";
import { fmtInt, fmtMs } from "../../lib/format.ts";
import { RANGE_LABEL } from "../../lib/vocab.ts";
import { Card, ErrorBar, Loading, PageHead } from "../../ui/Page.tsx";
import { JevChips, JevCondition } from "./JevFilters.tsx";
import { JevHealthCard } from "./JevHealthCard.tsx";
import { type HistMarker, type HistTick, JevHistogram } from "./JevHistogram.tsx";
import { JevHourly } from "./JevHourly.tsx";
import { JevRequestList } from "./JevRequestList.tsx";
import { CONFIDENCE_LINE, planJevList } from "./jev-model.ts";
import "./jev.css";

const DAY_MS = 24 * 60 * 60 * 1000;
const BUCKET_MS = 100;

function latencyName(index: number, buckets: number): string {
  const from = index * BUCKET_MS;
  return index === buckets - 1
    ? `${fmtInt(from)} ms 及以上`
    : `${fmtInt(from)}–${fmtInt(from + BUCKET_MS)} ms`;
}

function confidenceName(index: number): string {
  return `${(index / 10).toFixed(1)}–${((index + 1) / 10).toFixed(1)}`;
}

/** Axis labels every second up to the timeout; `at` is in bucket units. */
function latencyTicks(timeoutMs: number, buckets: number): HistTick[] {
  const ticks: HistTick[] = [{ at: 0, text: "0" }];
  for (let ms = 1000; ms <= timeoutMs; ms += 1000) {
    const at = ms / BUCKET_MS;
    if (at <= buckets) ticks.push({ at, text: `${ms / 1000} s` });
  }
  return ticks;
}

function Pending({
  title,
  error,
  isError,
  onRetry,
}: {
  title: string;
  error: unknown;
  isError: boolean;
  onRetry: () => void;
}) {
  return (
    <Card title={title}>
      {isError ? <ErrorBar error={error} onRetry={onRetry} /> : <Loading height={120} />}
    </Card>
  );
}

export function JevPage() {
  const search = useSearch({ from: "/jev" });
  const setSearch = useSetSearch();
  const scope = useScope();
  const now = useNowBucket();
  const status = useJevStatus();
  const stats = useJevStats(scopeQuery(scope));
  const site = useSite(scope.site ?? null);

  const q = search.q ?? "";
  const chip: JevChip = search.chip ?? "all";
  const p95 = stats.data?.p95_ms ?? null;
  const plan = useMemo(() => planJevList({ q, chip, scope, p95 }), [q, chip, scope, p95]);

  const rangeLabel =
    scope.range === "custom" ? "自定义时间范围" : `最近 ${RANGE_LABEL[scope.range]}`;
  const windowText = scope.range === "custom" ? "这段时间" : `最近 ${RANGE_LABEL[scope.range]}`;
  const showDate = scope.until - scope.since > DAY_MS;
  const data = stats.data;
  const dimmed = stats.isPlaceholderData;
  const siteTimeout = site.data?.spec.advanced?.jev_timeout_ms ?? null;

  const retryStats = () => void stats.refetch();

  let latency = (
    <Pending
      title={`耗时分布（${BUCKET_MS} ms 一档）`}
      error={stats.error}
      isError={stats.isError}
      onRetry={retryStats}
    />
  );
  let confidence = (
    <Pending title="置信度分布" error={stats.error} isError={stats.isError} onRetry={retryStats} />
  );
  let hourly = (
    <Card title="结论与失败（按小时）">
      {stats.isError ? (
        <ErrorBar error={stats.error} onRetry={retryStats} />
      ) : (
        <Loading height={170} />
      )}
    </Card>
  );

  if (data !== undefined) {
    const timeout = data.latency_histogram.timeout_ms;
    const counts = data.latency_histogram.counts;
    const markers: HistMarker[] = [
      { at: timeout / BUCKET_MS, text: `超时 ${fmtInt(timeout)} ms`, strong: true },
    ];
    // The site's own timeout is marked when the chart reaches it; beyond the chart it is only named.
    const beyond = siteTimeout !== null && siteTimeout > timeout;
    if (siteTimeout !== null && siteTimeout !== timeout && !beyond) {
      markers.push({ at: siteTimeout / BUCKET_MS, text: `站点 ${fmtInt(siteTimeout)} ms` });
    }

    latency = (
      <JevHistogram
        title={`耗时分布（${BUCKET_MS} ms 一档）`}
        counts={counts}
        labelAt={(index) => latencyName(index, counts.length)}
        ticks={latencyTicks(timeout, counts.length)}
        markers={markers}
        summary={`耗时直方图，共 ${fmtInt(data.calls)} 次调用，超时 ${fmtInt(timeout)} 毫秒`}
        dimmed={dimmed}
        footnote={
          <>
            p50 {fmtMs(data.p50_ms)} · p95 {fmtMs(data.p95_ms)}
            {beyond ? " · 站点超时超出图的范围" : ""}
          </>
        }
      />
    );

    const confCounts = data.confidence_histogram.counts;
    confidence = (
      <JevHistogram
        title="置信度分布"
        counts={confCounts}
        labelAt={confidenceName}
        ticks={[
          { at: 0, text: "0" },
          { at: confCounts.length / 2, text: "0.5" },
          { at: confCounts.length, text: "1.0" },
        ]}
        markers={[{ at: Math.round(CONFIDENCE_LINE * 10), text: "70%", strong: true }]}
        summary={`置信度直方图，共 ${fmtInt(data.calls)} 次调用，低于 70% 的 ${fmtInt(data.low_confidence)} 次`}
        dimmed={dimmed}
        footnote={<>低于 70%：{fmtInt(data.low_confidence)} 次</>}
      />
    );

    hourly = (
      <JevHourly
        hourly={data.hourly}
        withDate={showDate}
        dimmed={dimmed}
        emptyTitle={`${windowText}没有 Jev 调用`}
      />
    );
  }

  return (
    <>
      <PageHead title="Jev 调用" sub={`${scope.site ?? "全部站点"} · ${rangeLabel}`} />

      <div className="jev-top">
        <JevHealthCard
          status={status.data}
          isPending={status.isPending}
          isError={status.isError}
          error={status.error}
          onRetry={() => void status.refetch()}
          now={now}
        />
        {latency}
        {confidence}
      </div>
      {data !== undefined && !data.complete ? (
        <div className="toolbar-note jev-complete-note">按前 200 万条记录计算</div>
      ) : null}

      <div className="jev-hourly-row">{hourly}</div>

      <JevChips
        chip={chip}
        stats={data}
        onChip={(next) => setSearch({ chip: next === "all" ? undefined : next })}
      />
      <JevCondition
        value={q}
        onCommit={(text) => setSearch({ q: text.length > 0 ? text : undefined })}
      />

      <JevRequestList
        query={plan.query}
        scope={scope}
        chip={chip}
        q={q}
        windowText={windowText}
        impossible={plan.impossible}
        noThreshold={plan.noThreshold}
      />
    </>
  );
}
