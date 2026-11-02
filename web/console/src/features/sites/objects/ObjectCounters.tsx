// The counters of the object map (console design 3.1): the classes and the positions in each learning state.
// They are exclusive: the chosen one is written to the URL as `state` and narrows the table and the search.

import type { ObjectCounts, ObjectState } from "../../../api/types.ts";
import { fmtInt } from "../../../lib/format.ts";
import { OBJECT_STATE_INFO, OBJECT_TEXT } from "../../../lib/vocab.ts";

type Item = { key: string; label: string; count: number; state: ObjectState | undefined };

type Props = {
  counts: ObjectCounts;
  state: ObjectState | undefined;
  onState: (state: ObjectState | undefined) => void;
};

export function ObjectCounters({ counts, state, onState }: Props) {
  const items: Item[] = [
    { key: "all", label: OBJECT_TEXT.classes, count: counts.classes, state: undefined },
    {
      key: "confirmed",
      label: OBJECT_STATE_INFO.confirmed.name,
      count: counts.confirmed,
      state: "confirmed",
    },
    {
      key: "proposed",
      label: OBJECT_STATE_INFO.proposed.name,
      count: counts.proposed,
      state: "proposed",
    },
    {
      key: "ambiguous",
      label: OBJECT_STATE_INFO.ambiguous.name,
      count: counts.ambiguous,
      state: "ambiguous",
    },
    {
      key: "suspended",
      label: OBJECT_STATE_INFO.suspended.name,
      count: counts.suspended,
      state: "suspended",
    },
    {
      key: "pending",
      label: OBJECT_STATE_INFO.pending.name,
      count: counts.pending,
      state: "pending",
    },
  ];
  return (
    <fieldset
      className="chips"
      aria-label={OBJECT_TEXT.tab}
      style={{ border: 0, margin: 0, padding: 0, minWidth: 0 }}
    >
      {items.map((item) => (
        <button
          key={item.key}
          type="button"
          className="chip"
          aria-pressed={state === item.state}
          onClick={() => onState(item.state)}
        >
          <span>{item.label}</span>
          <span className="count">{fmtInt(item.count)}</span>
        </button>
      ))}
    </fieldset>
  );
}
