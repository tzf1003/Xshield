// The position table of the object map (console design 3.1): one row per position with its side and path, its
// class and state, where it came from, the evidence in one line and when it last appeared. A row opens the
// position's drawer (3.2). Text from the records goes through SafeText, so hidden characters show as escapes.

import type { ObjectClass, ObjectSlotRow, ObjectState } from "../../../api/types.ts";
import {
  OBJECT_JUDGEMENT,
  OBJECT_SIDE_INFO,
  OBJECT_SOURCE_LABEL,
  OBJECT_STATE_INFO,
  OBJECT_TEXT,
  percentOf,
} from "../../../lib/vocab.ts";
import { SafeText } from "../../../ui/SafeText.tsx";
import { judgementWords } from "../../../lib/judgement.ts";
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

/** The judgement a declared position carries, in words under its class: its identity, its tier and reliability, or its
 *  acceptance of public sources (docs/07 7.9.15, 7.9.16). Nothing for a position that carries none. */
export function JudgementLine({ row }: { row: ObjectSlotRow }) {
  const words = judgementWords(row);
  if (words === null) return null;
  return (
    <div className="small muted obj-judge-line" title={OBJECT_JUDGEMENT.editor.title}>
      <SafeText text={words} />
    </div>
  );
}

/** The short cause of a pause, for the 依据 column (console design 3.1); a row without a pause reason keeps its basis. */
function causeOf(row: ObjectSlotRow): string {
  const reason = row.suspension?.reason ?? null;
  if (reason === null) return row.basis;
  switch (reason.code) {
    case "origin_4xx_rise":
      return `${reason.status ?? 404} 比例 ${percentOf(reason.before)} → ${percentOf(reason.after)}`;
    case "jev_deny_rise":
      return `Jev 拒绝 ${reason.before ?? "—"} → ${reason.after ?? "—"}`;
    case "evidence_drift":
      return `证据转向 ${percentOf(reason.after)}`;
    case "split":
      return `拆分 ${(reason.classes ?? []).join(" / ")}`;
  }
}

/** A paused row's class and state: the class it fell back from when it is stopped, its class with a warning when in effect. */
function PausedCell({ row, classes }: { row: ObjectSlotRow; classes: readonly ObjectClass[] }) {
  const previous = row.suspension?.previous?.class ?? null;
  return (
    <>
      <StateTag state={row.state} />{" "}
      {row.in_effect ? (
        <span className="field-warn">
          <SafeText
            text={`${classNameOf(classes, row.class)} · ${OBJECT_TEXT.suspension.inEffectShort}`}
          />
        </span>
      ) : (
        <SafeText text={`${classNameOf(classes, previous)} → ${OBJECT_TEXT.suspension.nameOnly}`} />
      )}
    </>
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
                  {row.suspension === null ? (
                    <>
                      <SafeText text={classNameOf(classes, row.class)} />{" "}
                      <StateTag state={row.state} />
                      <JudgementLine row={row} />
                    </>
                  ) : (
                    <>
                      <PausedCell row={row} classes={classes} />
                      <JudgementLine row={row} />
                    </>
                  )}
                </td>
                <td className="keep">{OBJECT_SOURCE_LABEL[row.source]}</td>
                <td className="wrap">
                  <SafeText text={row.suspension === null ? row.basis : causeOf(row)} />
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
