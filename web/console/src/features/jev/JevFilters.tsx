// The quick chips of the Jev list and its condition line (docs/06 6.4.6, 6.4.3). Chips show the numbers
// of the statistics for the same window, so a chip and its count always agree. The condition text uses
// the request filter syntax; a text with errors is not sent, and the last valid one stays in force.

import { useEffect, useMemo, useState } from "react";
import type { JevStats } from "../../api/types.ts";
import type { JevChip } from "../../app/search-schema.ts";
import { JEV_CHIPS } from "../../app/search-schema.ts";
import { type FilterError, parseFilter } from "../../lib/filter-dsl.ts";
import { fmtInt } from "../../lib/format.ts";
import { chipCount, JEV_CHIP_INFO } from "./jev-model.ts";

export function JevChips({
  chip,
  stats,
  onChip,
}: {
  chip: JevChip;
  stats: JevStats | undefined;
  onChip: (next: JevChip) => void;
}) {
  return (
    <fieldset className="chips jev-chips">
      <legend className="sr-only">快捷筛选</legend>
      {JEV_CHIPS.map((id) => {
        const info = JEV_CHIP_INFO[id];
        const count = chipCount(id, stats);
        // The p95 chip needs a p95: without a successful call in the window there is none to compare.
        const unavailable = id === "slow" && stats !== undefined && stats.p95_ms === null;
        return (
          <button
            type="button"
            key={id}
            className="chip"
            aria-pressed={chip === id}
            title={unavailable ? "这段时间没有成功的调用，无法算出 p95" : info.title}
            disabled={unavailable}
            onClick={() => onChip(id)}
          >
            {info.label}
            {count === null ? null : (
              <span className="count">{count === undefined ? "…" : fmtInt(count)}</span>
            )}
          </button>
        );
      })}
    </fieldset>
  );
}

export function JevCondition({
  value,
  onCommit,
}: {
  value: string;
  onCommit: (text: string) => void;
}) {
  const [draft, setDraft] = useState(value);
  useEffect(() => setDraft(value), [value]);

  const errors: FilterError[] = useMemo(() => parseFilter(draft).errors, [draft]);

  const commit = (text: string) => {
    const next = text.trim();
    if (parseFilter(next).errors.length > 0) return;
    if (next !== value) onCommit(next);
  };

  return (
    <div className="stack jev-condition">
      <div className="filterbar">
        <label className="jev-condition-field">
          <span className="ico dim" aria-hidden="true">
            ⌕
          </span>
          <input
            data-filter
            className="native-input jev-condition-input"
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter") commit(draft);
              if (event.key === "Escape") setDraft(value);
            }}
            onBlur={() => commit(draft)}
            placeholder="条件，例如 path:/rest/* conf<70% decision:jev_deny"
            aria-label="筛选条件"
            aria-invalid={errors.length > 0}
            aria-describedby={errors.length > 0 ? "jev-condition-errors" : undefined}
          />
        </label>
      </div>
      {errors.length > 0 ? (
        <div id="jev-condition-errors" className="field-error" role="alert">
          {errors.slice(0, 3).map((error) => (
            <div key={`${error.index}-${error.term}`}>
              “{error.term}”：{error.message}
            </div>
          ))}
        </div>
      ) : null}
    </div>
  );
}
