// The card of one class beside the class list (console design 3.1): its name and id, what it means, the fields it is
// usually seen with and the routes it is used on, then its positions. Rename, merge and split are shown disabled:
// the console has no endpoint for them yet, and the note under the header says so.

import type { ObjectClass, ObjectSlotRow } from "../../../api/types.ts";
import { OBJECT_TEXT } from "../../../lib/vocab.ts";
import { Card, Empty, Kv } from "../../../ui/Page.tsx";
import { SafeText } from "../../../ui/SafeText.tsx";
import { SlotTable } from "./SlotTable.tsx";

type Props = {
  cls: ObjectClass;
  /** The positions of the class that the filters let through. */
  rows: readonly ObjectSlotRow[];
  classes: readonly ObjectClass[];
  /** Whether the site declares a user identity. */
  identified: boolean;
  selected: string | null;
  now: number;
  onOpen: (id: string) => void;
};

export function ObjectClassCard({ cls, rows, classes, identified, selected, now, onOpen }: Props) {
  const unavailable = OBJECT_TEXT.classCard.unavailable;
  return (
    <Card
      className="obj-card"
      title={
        <span className="obj-card-title">
          <span className="obj-class-name">
            <SafeText text={cls.name} />
          </span>
          <span className="mono small dim">
            <SafeText text={cls.id} />
          </span>
        </span>
      }
      aside={
        <span className="obj-card-actions">
          <button type="button" className="linkbtn" disabled title={unavailable}>
            {OBJECT_TEXT.classCard.rename}
          </button>
          <button type="button" className="linkbtn" disabled title={unavailable}>
            {OBJECT_TEXT.classCard.merge}
          </button>
          <button type="button" className="linkbtn" disabled title={unavailable}>
            {OBJECT_TEXT.classCard.split}
          </button>
        </span>
      }
    >
      <div className="stack-tight">
        <div className="small muted">{unavailable}</div>
        <Kv
          items={[
            [
              OBJECT_TEXT.classCard.description,
              <SafeText key="description" text={cls.description} />,
            ],
            [
              OBJECT_TEXT.classCard.fields,
              cls.fields.length > 0 ? <SafeText key="fields" text={cls.fields.join(" · ")} /> : "—",
            ],
            [
              OBJECT_TEXT.classCard.routes,
              cls.routes.length > 0 ? (
                <span key="routes" className="obj-ref-list">
                  {cls.routes.map((route) => (
                    <span key={route} className="obj-code">
                      <SafeText text={route} />
                    </span>
                  ))}
                </span>
              ) : (
                "—"
              ),
            ],
          ]}
        />
      </div>
      <div className="field-label">{OBJECT_TEXT.classCard.positions}</div>
      {rows.length === 0 ? (
        <Empty title={OBJECT_TEXT.none} />
      ) : (
        <SlotTable
          rows={rows}
          classes={classes}
          identified={identified}
          selected={selected}
          now={now}
          onOpen={onOpen}
        />
      )}
    </Card>
  );
}
