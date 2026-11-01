// The structured view of the Jev tab (docs/06 6.4.5): on the left, the values Jev received, one card
// each with its location, kind, value, the gateway's reading and the sources; on the right, the session
// the request came in. A value that lacks evidence opens by default; with more than eight values the
// rest fold into one line.

import { useEffect, useRef, useState } from "react";
import type { RequestId, SourceSummary, Trace } from "../../api/types.ts";
import { fmtInt } from "../../lib/format.ts";
import { VALUE_KIND_LABEL } from "../../lib/vocab.ts";
import { Card, Empty } from "../../ui/Page.tsx";
import { SafeText } from "../../ui/SafeText.tsx";
import { SourceChip } from "../../ui/SourceChip.tsx";
import { SessionSummary, newestFirst } from "./SessionPanel.tsx";
import {
  type SentRow,
  type SessionView,
  REDACTED,
  needsEvidence,
  readingOf,
} from "./detail-model.ts";
import { CopyAction, HintMark, keyed, useFlash, ValueText } from "./parts.tsx";

const FOLD_ABOVE = 8;

type Props = {
  rows: SentRow[];
  session: SessionView;
  trace: Trace;
  sessionLabel: string;
  requestId: string;
  summaries: Record<RequestId, SourceSummary>;
  query: string;
  hl: number | undefined;
};

export function JevStructured({ rows, session, trace, sessionLabel, requestId, summaries, query, hl }: Props) {
  const flashing = useFlash(hl);
  const [calmOpen, setCalmOpen] = useState(false);
  const container = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (hl === undefined) return;
    container.current
      ?.querySelector<HTMLElement>(`[data-trace-index="${hl}"]`)
      ?.scrollIntoView({ block: "center" });
  }, [hl]);

  const attention = rows.filter(needsEvidence);
  const calm = rows.filter((row) => !needsEvidence(row));
  const folded = rows.length > FOLD_ABOVE && !calmOpen;
  const shownCalm = folded ? [] : calm;
  const missing = attention.length;

  return (
    <div className="rd-jev-cols" ref={container}>
      <Card title="本次请求" aside={`发给 Jev ${fmtInt(rows.length)} 个值，其中 ${fmtInt(missing)} 个缺少佐证`}>
        {rows.length === 0 ? (
          <Empty title="这次调用没有发出请求值" />
        ) : (
          <div className="rd-vlist">
            {keyed(attention, (row) => `${row.at}|${row.traceIndex ?? ""}`).map(({ key, item }) => (
              <ValueCard
                key={key}
                row={item}
                summaries={summaries}
                query={query}
                highlighted={flashing && item.traceIndex === hl}
              />
            ))}
            {keyed(shownCalm, (row) => `${row.at}|${row.traceIndex ?? ""}`).map(({ key, item }) => (
              <ValueCard
                key={key}
                row={item}
                summaries={summaries}
                query={query}
                highlighted={flashing && item.traceIndex === hl}
              />
            ))}
            {rows.length > FOLD_ABOVE ? (
              <button type="button" className="linkbtn rd-foldbtn" aria-expanded={!folded} onClick={() => setCalmOpen((open) => !open)}>
                {folded ? `另有 ${fmtInt(calm.length)} 个值无异常 · 展开` : "收起无异常的值"}
              </button>
            ) : null}
          </div>
        )}
      </Card>

      <Card title="会话">
        <SessionSummary
          trace={trace}
          entries={session.entries}
          recent={newestFirst(session.recent)}
          sessionLabel={sessionLabel}
          requestId={requestId}
        />
      </Card>
    </div>
  );
}

function ValueCard({
  row,
  summaries,
  query,
  highlighted,
}: {
  row: SentRow;
  summaries: Record<RequestId, SourceSummary>;
  query: string;
  highlighted: boolean;
}) {
  const [open, setOpen] = useState(needsEvidence(row));
  const reading = readingOf({ kind: row.kind, seen: row.seen, verified: row.verified });
  const redacted = row.value === REDACTED;
  const classes = ["rd-vcard"];
  if (needsEvidence(row)) classes.push("rd-attn");
  if (highlighted) classes.push("rd-flash");
  const position = row.traceIndex !== null ? `trace.values[${row.traceIndex}] · ${row.at}` : row.at;

  return (
    <article className={classes.join(" ")} data-trace-index={row.traceIndex ?? undefined} title={position}>
      <header className="rd-vhead">
        <span className="mono small tnum">#{row.jevIndex}</span>
        <span className="mono small rd-clip">
          <SafeText text={row.at} query={query} />
        </span>
        <span className="small dim">{VALUE_KIND_LABEL[row.kind]}</span>
        <button type="button" className="linkbtn small" aria-expanded={open} onClick={() => setOpen((value) => !value)}>
          {open ? "收起" : "展开"}
        </button>
      </header>

      {open ? (
        <div className="rd-vbody">
          <div className="rd-val mono">
            <ValueText value={row.value} len={row.len} clipped={row.clipped} query={query} />
          </div>
          <div className="small">
            <HintMark reading={reading} />
          </div>
          {row.sources.length > 0 ? (
            <div className="rd-srcs">
              {keyed(row.sources, (source) => `${source.field}|${source.request}|${source.request_id ?? ""}`).map(
                ({ key, item }) => (
                  <SourceChip key={key} source={item} sources={summaries} copyable />
                ),
              )}
            </div>
          ) : null}
          {row.sources.length === 0 && row.seenAs.length > 0 ? (
            <div className="rd-srcs">
              {keyed(row.seenAs, (text) => text).map(({ key, item }) => (
                <span key={key} className="srcchip">
                  <SafeText text={item} query={query} />
                </span>
              ))}
            </div>
          ) : null}
          {redacted ? null : <CopyAction text={row.value} label="复制值" />}
        </div>
      ) : (
        <div className="rd-vline small">
          <span className="mono rd-clip">
            <ValueText value={row.value} len={row.len} clipped={row.clipped} query={query} />
          </span>{" "}
          <HintMark reading={reading} />
        </div>
      )}
    </article>
  );
}
