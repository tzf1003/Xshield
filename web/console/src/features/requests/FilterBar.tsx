// The filter line (docs/06 6.4.3): the condition text with live error reporting, the "＋条件" menu that
// adds a term without remembering the syntax, the switch that includes bypass and unknown-site rows,
// and the live toggle. A text with errors is not sent; the last valid filter stays in force until it
// is fixed.

import { Button, Dropdown, Switch } from "antd";
import { useEffect, useMemo, useState } from "react";
import { type FilterError, parseFilter } from "../../lib/filter-dsl.ts";
import { CONDITION_MENU } from "./query.ts";

type Props = {
  value: string;
  onCommit: (text: string) => void;
  /** The switch: include bypass and unknown-site rows (scope=all). */
  allOn: boolean;
  onAll: (on: boolean) => void;
  /** True when the list includes them anyway, for a lookup by request ID, session or exact path. */
  includesAll: boolean;
  live: boolean;
  onLive: (on: boolean) => void;
  liveDisabled: boolean;
};

export function FilterBar({
  value,
  onCommit,
  allOn,
  onAll,
  includesAll,
  live,
  onLive,
  liveDisabled,
}: Props) {
  const [draft, setDraft] = useState(value);
  useEffect(() => setDraft(value), [value]);

  const parsed = useMemo(() => parseFilter(draft), [draft]);
  const errors: FilterError[] = parsed.errors;

  const commit = (text: string) => {
    const next = text.trim();
    if (parseFilter(next).errors.length > 0) return;
    if (next !== value) onCommit(next);
  };

  const menu = {
    items: CONDITION_MENU.map((condition) => ({
      key: condition.term,
      label: condition.label,
      onClick: () => {
        const next = [draft.trim(), condition.term].filter((part) => part.length > 0).join(" ");
        setDraft(next);
        commit(next);
      },
    })),
  };

  return (
    <div className="stack" style={{ gap: 6 }}>
      <div className="filterbar" style={{ margin: 0 }}>
        <input
          data-filter
          className="native-input grow"
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") commit(draft);
            if (event.key === "Escape") setDraft(value);
          }}
          onBlur={() => commit(draft)}
          placeholder="条件，例如 outcome:blocked,would_block path:/rest/* ；按 / 聚焦"
          aria-label="筛选条件"
          aria-invalid={errors.length > 0}
          aria-describedby={errors.length > 0 ? "filter-errors" : undefined}
          style={{ minWidth: 260, maxWidth: 680 }}
        />
        <Dropdown menu={menu} trigger={["click"]}>
          <Button>＋条件</Button>
        </Dropdown>
        <span className="check">
          <Switch
            size="small"
            checked={allOn}
            onChange={onAll}
            aria-label="含绕过和未知站点的请求"
          />
          含绕过和未知站点
        </span>
        <span className="check">
          <Switch
            size="small"
            checked={live}
            disabled={liveDisabled}
            onChange={onLive}
            aria-label="实时模式"
          />
          实时
        </span>
        {includesAll && !allOn ? (
          <span className="toolbar-note">
            已包含绕过和未知站点的请求（按请求 ID、会话或精确路径查找时自动包含）
          </span>
        ) : null}
      </div>
      {errors.length > 0 ? (
        <div id="filter-errors" className="field-error" role="alert">
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
