// The label of a path position (console design 4.1): the route the position reads, its number among the route's
// parameters, and the route with the segment the judge reads bracketed and shaded. A position that is not a path
// position renders nothing.

import { pathSlotOf } from "../../../lib/objects-validate.ts";
import { OBJECT_TEXT } from "../../../lib/vocab.ts";
import { SafeText } from "../../../ui/SafeText.tsx";

export function PathSlotLabel({ slotKey }: { slotKey: string }) {
  const slot = pathSlotOf(slotKey);
  if (slot === null) return null;
  const segments = slot.route.replace(/^\//, "").split("/");
  const head = segments.slice(0, slot.segment).join("/");
  const tail = segments.slice(slot.segment + 1).join("/");
  const words =
    slot.ordinal === null
      ? OBJECT_TEXT.pathParam.literal(slot.method, slot.route, slot.segment)
      : OBJECT_TEXT.pathParam.label(slot.method, slot.route, slot.ordinal, slot.segment);
  return (
    <span className="obj-path-label">
      <span className="small">
        <SafeText text={words} />
      </span>
      <span className="obj-code obj-route" title={OBJECT_TEXT.pathParam.template}>
        <SafeText text={`/${head.length === 0 ? "" : `${head}/`}`} />
        <span className="obj-seg-hl">
          ［<SafeText text={segments[slot.segment] ?? ""} />］
        </span>
        {tail.length === 0 ? null : <SafeText text={`/${tail}`} />}
      </span>
    </span>
  );
}
