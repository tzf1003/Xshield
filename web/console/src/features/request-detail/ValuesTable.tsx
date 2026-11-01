// The request values tab (docs/06 6.4.4): every value the trace recorded, with its location, field,
// kind, whether the gateway has seen and verified it, its sources, and its number in Jev's request.
// Inert values fold away; the values that still need checking carry an amber bar. The value that a
// link asked for is scrolled to and highlighted.

import { Switch } from "antd";
import { useEffect, useRef, useState } from "react";
import type { RequestDetail, TraceValue } from "../../api/types.ts";
import { useSite } from "../../api/queries.ts";
import { useSetSearch } from "../../app/scope.ts";
import { alignValues } from "../../lib/align.ts";
import { countHits } from "../../lib/highlight.ts";
import { isSiteName } from "../../lib/ids.ts";
import { VALUE_KIND_LABEL } from "../../lib/vocab.ts";
import { Empty, Notice } from "../../ui/Page.tsx";
import { SafeText } from "../../ui/SafeText.tsx";
import { SourceChip } from "../../ui/SourceChip.tsx";
import { REDACTED, secretMatchOf } from "./detail-model.ts";
import { keyed, ValueText, useFlash } from "./parts.tsx";

/** At most this many source tags per value; the rest are counted (docs/06 6.4.4). */
const SOURCE_TAGS = 3;

export function ValuesTable({ detail, hl }: { detail: RequestDetail; hl: number | undefined }) {
  const { summary, trace, sources } = detail;
  const values = trace.values ?? [];
  const siteName = summary.site !== null && isSiteName(summary.site) ? summary.site : null;
  const site = useSite(siteName);
  const extraWords = site.data?.spec.advanced?.secret_fields ?? [];
  const setSearch = useSetSearch();
  const [onlyNeeds, setOnlyNeeds] = useState(false);
  const [showInert, setShowInert] = useState(false);
  const [query, setQuery] = useState("");
  const containerRef = useRef<HTMLDivElement | null>(null);
  const flashing = useFlash(hl);

  useEffect(() => {
    if (hl === undefined) return;
    containerRef.current
      ?.querySelector<HTMLElement>(`[data-trace-index="${hl}"]`)
      ?.scrollIntoView({ block: "center" });
  }, [hl]);

  if (values.length === 0) {
    return (
      <Empty title="这个请求没有拆出请求值">
        <div className="small">只有进入判定的请求才会拆出请求值；绕过和未知站点的请求不拆。</div>
      </Empty>
    );
  }

  const jevNumbers = new Map<number, number>();
  for (const item of alignValues(values)) jevNumbers.set(item.traceIndex, item.jevIndex);
  const inertCount = values.filter((value) => value.inert).length;
  const rows = values
    .map((value, traceIndex) => ({ value, traceIndex }))
    .filter(({ value }) =>
      onlyNeeds ? !value.inert && !value.verified : !value.inert || showInert,
    );
  const term = query.trim();
  const hits =
    term === ""
      ? 0
      : rows.reduce(
          (sum, { value }) =>
            sum +
            countHits(value.at, term) +
            countHits(value.key ?? "", term) +
            (value.value === REDACTED ? 0 : countHits(value.value, term)),
          0,
        );

  return (
    <div className="rd-values" ref={containerRef}>
      {detail.trace.values_truncated ? (
        <Notice>请求体未结构化或超过 64 KiB 解析上限，只拆出了部分值。</Notice>
      ) : null}
      <div className="rd-valuebar">
        <input
          type="search"
          className="native-input rd-search"
          placeholder="在请求值中搜索"
          aria-label="在请求值中搜索"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
        <span className="small dim" role="status">
          {term === "" ? "" : `${hits} 处`}
        </span>
        <Switch
          id="rd-only-needs"
          size="small"
          checked={onlyNeeds}
          onChange={(checked) => setOnlyNeeds(checked)}
        />
        <label htmlFor="rd-only-needs" className="check">
          只看需核验的值
        </label>
      </div>

      <div className="tbl-wrap rd-tbl-wrap">
        <table className="tbl rd-table">
          <thead>
            <tr>
              <th scope="col">位置</th>
              <th scope="col">字段</th>
              <th scope="col">值</th>
              <th scope="col">类型</th>
              <th scope="col">已见</th>
              <th scope="col">已核验</th>
              <th scope="col">来源</th>
              <th scope="col">Jev 序号</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(({ value, traceIndex }) => (
              <ValueRow
                key={traceIndex}
                value={value}
                traceIndex={traceIndex}
                jevNumber={jevNumbers.get(traceIndex) ?? null}
                summaries={sources}
                secret={value.value === REDACTED ? secretTitle(value, extraWords) : null}
                query={term}
                highlighted={flashing && hl === traceIndex}
                onJev={() => setSearch({ tab: "jev", hl: traceIndex })}
              />
            ))}
          </tbody>
        </table>
      </div>

      {!onlyNeeds && inertCount > 0 ? (
        <div className="rd-fold">
          <button
            type="button"
            className="linkbtn"
            aria-expanded={showInert}
            onClick={() => setShowInert((open) => !open)}
          >
            {`另有 ${inertCount} 个惰性值（路由词、分页参数）· ${showInert ? "收起" : "显示"}`}
          </button>
        </div>
      ) : null}
    </div>
  );
}

function secretTitle(value: TraceValue, extra: readonly string[]): string {
  const match = secretMatchOf(value, extra);
  if (match === null) return "已脱敏";
  return `字段名含 ${match.word}（${match.builtin ? "内置" : "本站点追加"}）`;
}

function ValueRow({
  value,
  traceIndex,
  jevNumber,
  summaries,
  secret,
  query,
  highlighted,
  onJev,
}: {
  value: TraceValue;
  traceIndex: number;
  jevNumber: number | null;
  summaries: RequestDetail["sources"];
  secret: string | null;
  query: string;
  highlighted: boolean;
  onJev: () => void;
}) {
  const needs = !value.inert && !value.verified;
  const classes = ["rd-row"];
  if (needs) classes.push("rd-needs");
  if (value.inert) classes.push("rd-inert");
  if (highlighted) classes.push("rd-flash");
  return (
    <tr className={classes.join(" ")} data-trace-index={traceIndex}>
      <td className="mono rd-clip" title={value.at}>
        <SafeText text={value.at} query={query} />
      </td>
      <td className="mono rd-clip">
        {value.key === null ? (
          <span className="dim">—</span>
        ) : (
          <SafeText text={value.key} query={query} />
        )}
      </td>
      <td className="rd-valcell">
        <span className="mono rd-clip">
          <ValueText
            value={value.value}
            len={value.len ?? null}
            clipped={value.clipped === true}
            secret={secret}
            query={query}
          />
        </span>
      </td>
      <td>
        {VALUE_KIND_LABEL[value.kind]}
        {value.inert ? " · 惰性" : ""}
      </td>
      <td className="tnum">{value.seen ? "✓" : "–"}</td>
      <td className="tnum">{value.verified ? "✓" : "–"}</td>
      <td>
        {value.sources.length > 0 ? (
          <span className="rd-srcs">
            {keyed(
              value.sources.slice(0, SOURCE_TAGS),
              (source) => `${source.field}|${source.request}|${source.request_id ?? ""}`,
            ).map(({ key, item }) => (
              <SourceChip key={key} source={item} sources={summaries} copyable />
            ))}
            {value.sources.length > SOURCE_TAGS ? (
              <span className="small dim">另 {value.sources.length - SOURCE_TAGS} 个</span>
            ) : null}
          </span>
        ) : (
          <span className="dim">—</span>
        )}
      </td>
      <td className="tnum">
        {jevNumber === null ? (
          <span className="dim">–</span>
        ) : (
          <button
            type="button"
            className="linkbtn"
            onClick={onJev}
            title="在 Jev 上下文中查看这个值"
          >
            #{jevNumber}
          </button>
        )}
      </td>
    </tr>
  );
}
