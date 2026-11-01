// Hand-drawn SVG charts (docs/07 7.10.1, docs/06 6.5.4): stacked bars, a histogram, a sparkline, and
// the Jev answer bar. Every chart has a title for hover and assistive technology; the pages offer the
// same numbers as a table, so no reading depends on colour.

import type { ReactNode } from "react";
import { fmtInt, pct } from "../lib/format.ts";

export type SeriesClass = "s1" | "s2" | "s3" | "neutral";

export type Series = { name: string; cls: SeriesClass };

const W = 600;

/** A stacked bar per row; values follow the order of `series`. */
export function StackedBars({
  rows,
  series,
  height = 150,
  label,
}: {
  rows: Array<{ label: string; values: number[] }>;
  series: Series[];
  height?: number;
  label: string;
}) {
  const totals = rows.map((row) => row.values.reduce((sum, value) => sum + value, 0));
  const max = Math.max(1, ...totals);
  const plot = height - 26;
  const slot = rows.length > 0 ? W / rows.length : W;
  const bar = Math.min(24, slot * 0.72);
  return (
    <svg className="chart" viewBox={`0 0 ${W} ${height}`} role="img" aria-label={label}>
      <title>{label}</title>
      <line className="axis-line" x1="0" x2={W} y1={plot} y2={plot} />
      {rows.map((row, index) => {
        const x = index * slot + (slot - bar) / 2;
        let base = plot;
        const tip = row.values
          .map((value, i) => `${series[i]?.name ?? ""} ${fmtInt(value)}`)
          .join("，");
        return (
          <g key={`${row.label}`}>
            <title>{`${row.label}：${tip}`}</title>
            {row.values.map((value, i) => {
              const segment = (value / max) * (plot - 6);
              base -= segment;
              const cls = series[i]?.cls ?? "neutral";
              return (
                <rect
                  key={series[i]?.name ?? i}
                  className={cls}
                  x={x}
                  y={base}
                  width={bar}
                  height={Math.max(0, segment - (segment > 0 ? 2 : 0))}
                  rx={2}
                />
              );
            })}
          </g>
        );
      })}
      {rows.length > 0 ? (
        <>
          <text x={0} y={height - 6}>
            {rows[0]?.label}
          </text>
          <text x={W} y={height - 6} textAnchor="end">
            {rows[rows.length - 1]?.label}
          </text>
        </>
      ) : null}
    </svg>
  );
}

/** Bars of one series, with an optional threshold line drawn at a bucket index. */
export function Histogram({
  counts,
  labelAt,
  cls = "s1",
  height = 120,
  threshold,
  label,
}: {
  counts: number[];
  labelAt: (index: number) => string;
  cls?: SeriesClass;
  height?: number;
  threshold?: { index: number; text: string };
  label: string;
}) {
  const max = Math.max(1, ...counts);
  const plot = height - 24;
  const slot = counts.length > 0 ? W / counts.length : W;
  const bar = Math.min(24, slot * 0.8);
  const thresholdX = threshold ? threshold.index * slot + slot / 2 : null;
  return (
    <svg className="chart" viewBox={`0 0 ${W} ${height}`} role="img" aria-label={label}>
      <title>{label}</title>
      <line className="axis-line" x1="0" x2={W} y1={plot} y2={plot} />
      {counts.map((count, index) => {
        const h = (count / max) * (plot - 6);
        return (
          <rect
            key={labelAt(index)}
            className={cls}
            x={index * slot + (slot - bar) / 2}
            y={plot - h}
            width={bar}
            height={Math.max(0, h)}
            rx={2}
          >
            <title>{`${labelAt(index)}：${fmtInt(count)}`}</title>
          </rect>
        );
      })}
      {thresholdX !== null && threshold ? (
        <>
          <line className="threshold" x1={thresholdX} x2={thresholdX} y1={0} y2={plot} />
          <text x={thresholdX + 4} y={10}>
            {threshold.text}
          </text>
        </>
      ) : null}
      {counts.length > 0 ? (
        <>
          <text x={0} y={height - 6}>
            {labelAt(0)}
          </text>
          <text x={W} y={height - 6} textAnchor="end">
            {labelAt(counts.length - 1)}
          </text>
        </>
      ) : null}
    </svg>
  );
}

/** A tiny trend line for a metric card; decorative, with the figure in the card's text. */
export function Sparkline({ values, width = 120, height = 26 }: { values: number[]; width?: number; height?: number }) {
  if (values.length < 2) return null;
  const max = Math.max(1, ...values);
  const step = width / (values.length - 1);
  const points = values
    .map((value, index) => `${(index * step).toFixed(1)},${(height - (value / max) * (height - 3) - 1).toFixed(1)}`)
    .join(" ");
  return (
    <svg className="chart" width={width} height={height} viewBox={`0 0 ${width} ${height}`} aria-hidden="true">
      <polyline className="spark-line" points={points} />
    </svg>
  );
}

export type AnswerSegment = { key: string; label: string; value: number; cls: "seg-pass" | "seg-fail" | "seg-unknown" };

/** The two Jev questions as segmented bars: pass, fail, unknown; widths follow the probabilities. */
export function AnswerBar({ segments }: { segments: AnswerSegment[] }) {
  const total = segments.reduce((sum, segment) => sum + segment.value, 0);
  return (
    <div className="answerbar" role="img" aria-label={segments.map((s) => `${s.label} ${pct(s.value)}`).join("，")}>
      {segments.map((segment) => {
        const width = total > 0 ? (segment.value / total) * 100 : 0;
        if (width <= 0) return null;
        return (
          <span
            key={segment.key}
            className={segment.cls}
            style={{ width: `${width}%` }}
            title={`${segment.label} ${pct(segment.value)}`}
          >
            {width >= 14 ? `${segment.label} ${pct(segment.value)}` : null}
          </span>
        );
      })}
    </div>
  );
}

export function Legend({ items }: { items: Array<{ name: string; cls: SeriesClass }> }): ReactNode {
  return (
    <div className="legend">
      {items.map((item) => (
        <span key={item.name}>
          <i className={item.cls} aria-hidden="true" />
          {item.name}
        </span>
      ))}
    </div>
  );
}
