// The position table of the object map (console design 3.1): one row per position with its side and path, its
// class and state, where it came from, the evidence in one line and when it last appeared. A row opens the
// position's drawer (3.2). Text from the records goes through SafeText, so hidden characters show as escapes.

import type { ObjectClass, ObjectSlotRow, ObjectState } from "../../../api/types.ts";
import {
  OBJECT_SIDE_INFO,
  OBJECT_SOURCE_LABEL,
  OBJECT_STATE_INFO,
  OBJECT_TEXT,
} from "../../../lib/vocab.ts";
import { SafeText } from "../../../ui/SafeText.tsx";
import { classNameOf, seenText } from "./objects-model.ts";

/** A state as a tag: the icon and the name, with the state's meaning as its title. */
export function StateTag({ state }: { state: ObjectState }) {
  const info = OBJECT_STATE_INFO[state];
  return (
    <span className={`tag tag-${info.tone}`} title={info.desc}>
      <span className="ico" aria-hidden="true">
        {info.icon}
      </span>
      {info.name}
    </span>
  );
}

type Props = {
  rows: readonly ObjectSlotRow[];
  classes: readonly ObjectClass[];
  /** The position whose drawer is open, marked in the table. */
  selected: string | null;
  now: number;
  onOpen: (id: string) => void;
};

export function SlotTable({ rows, classes, selected, now, onOpen }: Props) {
  return (
    <div className="tbl-wrap">
      <table className="tbl" aria-label={OBJECT_TEXT.table}>
        <thead>
          <tr>
            <th scope="col">{OBJECT_TEXT.columns.slot}</th>
            <th scope="col">{OBJECT_TEXT.columns.state}</th>
            <th scope="col">{OBJECT_TEXT.columns.source}</th>
            <th scope="col">{OBJECT_TEXT.columns.basis}</th>
            <th scope="col" className="num">
              {OBJECT_TEXT.columns.seen}
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const side = OBJECT_SIDE_INFO[row.side];
            return (
              <tr
                key={row.id}
                id={`slot-${row.id}`}
                className="row-click"
                aria-selected={selected === row.id}
                onClick={() => onOpen(row.id)}
              >
                <td>
                  <span className="obj-side" aria-hidden="true" title={side.desc}>
                    {side.icon}
                  </span>
                  <span className="obj-code" title={row.key}>
                    <SafeText text={row.key} />
                  </span>
                </td>
                <td className="wrap">
                  <SafeText text={classNameOf(classes, row.class)} /> <StateTag state={row.state} />
                </td>
                <td className="keep">{OBJECT_SOURCE_LABEL[row.source]}</td>
                <td className="wrap">
                  <SafeText text={row.basis} />
                </td>
                <td className="num">{seenText(row.last_seen, now)}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
