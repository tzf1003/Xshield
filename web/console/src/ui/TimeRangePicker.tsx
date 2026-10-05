import { Button, Input } from "antd";
import { useId } from "react";
import {
  DEFAULT_PRESET,
  localOffsetLabel,
  type RangeIntent,
  type RangePreset,
  type RangeResolution,
  rangePresets,
  rangeProblemText,
  resolveRange,
  toLocalInput,
  type UtcWindow,
} from "./time-range.ts";
import "./kit.css";

type Props = {
  value: RangeIntent;
  /** Called with the new choice and what it resolves to right now (presets: against the clock). */
  onChange: (intent: RangeIntent, resolution: RangeResolution) => void;
  /**
   * The page's own plan validator (`validateSearchPlan` and friends) run on the resolved window.
   * It stays the single gate; the picker only turns its refusal into a visible message.
   */
  accepts?: (window: UtcWindow) => boolean;
  presets?: readonly RangePreset[];
  disabled?: boolean;
  /** Accessible name of the whole control. */
  label?: string;
};

/** Resolution plus the page validator's verdict. */
export function checkedResolution(
  intent: RangeIntent,
  nowMs: number,
  accepts?: (window: UtcWindow) => boolean,
): RangeResolution {
  const resolution = resolveRange(intent, nowMs);
  if (resolution.window && accepts && !accepts(resolution.window)) {
    return { window: null, problem: "invalid" };
  }
  return resolution;
}

/**
 * Time range choice: 15 分钟 / 1 小时 / 24 小时 / 7 天 presets or a custom local-time window.
 * Operators work in local time; the server receives a whole-second UTC half-open window
 * `[start, end)` of at most 31 days, which is shown beneath the inputs.
 */
export function TimeRangePicker({
  value,
  onChange,
  accepts,
  presets = rangePresets.map((entry) => entry.id),
  disabled = false,
  label = "时间范围",
}: Props) {
  const id = useId();
  const now = Date.now();
  const resolution = checkedResolution(value, now, accepts);
  const custom = value.kind === "custom";

  function choose(intent: RangeIntent) {
    onChange(intent, checkedResolution(intent, Date.now(), accepts));
  }

  function startCustom() {
    if (custom) return;
    // Start from what the previous choice meant, so the inputs are never blank or surprising.
    const base = resolveRange(
      value.kind === "none" ? { kind: "preset", preset: DEFAULT_PRESET } : value,
      Date.now(),
    );
    const startMs = base.window ? Date.parse(base.window.start) : Date.now() - 3_600_000;
    const endMs = base.window ? Date.parse(base.window.end) : Date.now();
    choose({ kind: "custom", start: toLocalInput(startMs), end: toLocalInput(endMs) });
  }

  return (
    <fieldset className="xs-range">
      <legend className="xs-visually-hidden">{label}</legend>
      <div className="xs-range-presets">
        {rangePresets
          .filter((entry) => presets.includes(entry.id))
          .map((entry) => {
            const selected = value.kind === "preset" && value.preset === entry.id;
            return (
              <Button
                key={entry.id}
                size="small"
                type={selected ? "primary" : "default"}
                aria-pressed={selected}
                disabled={disabled}
                onClick={() => choose({ kind: "preset", preset: entry.id })}
              >
                {entry.label}
              </Button>
            );
          })}
        <Button
          size="small"
          type={custom ? "primary" : "default"}
          aria-pressed={custom}
          disabled={disabled}
          onClick={startCustom}
        >
          自定义
        </Button>
      </div>
      {value.kind === "custom" ? (
        <div className="xs-range-custom">
          <div className="xs-range-field">
            <label htmlFor={`${id}-start`}>开始时间（本地，含）</label>
            <Input
              id={`${id}-start`}
              type="datetime-local"
              step={1}
              min="1970-01-01T00:00:00"
              max="2300-01-01T00:00:00"
              value={value.start}
              disabled={disabled}
              onChange={(event) =>
                choose({ kind: "custom", start: event.target.value, end: value.end })
              }
            />
          </div>
          <div className="xs-range-field">
            <label htmlFor={`${id}-end`}>结束时间（本地，不含）</label>
            <Input
              id={`${id}-end`}
              type="datetime-local"
              step={1}
              min="1970-01-01T00:00:00"
              max="2300-01-01T00:00:00"
              value={value.end}
              disabled={disabled}
              onChange={(event) =>
                choose({ kind: "custom", start: value.start, end: event.target.value })
              }
            />
          </div>
        </div>
      ) : null}
      {resolution.problem ? (
        <p
          className={`xs-range-hint${value.kind === "none" ? "" : " is-error"}`}
          aria-live="polite"
        >
          {rangeProblemText[resolution.problem]}
        </p>
      ) : value.kind === "custom" ? (
        <p className="xs-range-hint">
          将查询 UTC <span className="mono">{resolution.window.start}</span> 至{" "}
          <span className="mono">{resolution.window.end}</span>（含起不含止，整秒；本地{" "}
          {localOffsetLabel(now)}，最长 31 天）。
        </p>
      ) : (
        <p className="xs-range-hint">
          提交时按当前时间换算为 UTC 整秒半开窗口（含起不含止，最长 31 天）。
        </p>
      )}
    </fieldset>
  );
}
