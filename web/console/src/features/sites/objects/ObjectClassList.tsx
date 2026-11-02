// The classes of the object map, at the left of the by-class view (console design 3.1): the name, the id, how many
// positions the class has and how often it was used in the last 24 hours. The chosen class is marked for assistive
// tech with aria-current.

import type { ObjectClass } from "../../../api/types.ts";
import { fmtInt } from "../../../lib/format.ts";
import { OBJECT_TEXT } from "../../../lib/vocab.ts";
import { SafeText } from "../../../ui/SafeText.tsx";

type Props = {
  classes: readonly ObjectClass[];
  selected: string | null;
  onSelect: (id: string) => void;
};

export function ObjectClassList({ classes, selected, onSelect }: Props) {
  return (
    <nav aria-label={OBJECT_TEXT.classes}>
      <ul className="obj-classes">
        {classes.map((item) => (
          <li key={item.id}>
            <button
              type="button"
              className="obj-class"
              aria-current={item.id === selected ? "true" : undefined}
              onClick={() => onSelect(item.id)}
            >
              <span className="obj-class-line">
                <span className="obj-class-name">
                  <SafeText text={item.name} />
                </span>
                <span className="obj-class-id mono small">
                  <SafeText text={item.id} />
                </span>
              </span>
              <span className="obj-class-meta">
                {fmtInt(item.slot_count)} {OBJECT_TEXT.classCard.positions} · {OBJECT_TEXT.uses24h}{" "}
                {fmtInt(item.uses_24h)} 次
              </span>
            </button>
          </li>
        ))}
      </ul>
    </nav>
  );
}
