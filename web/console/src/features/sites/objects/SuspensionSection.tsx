// The paused part of a position's drawer (console design 3.2): when and by whom it was paused and why, the confirmed
// class before the pause, what the judge does now (name inference, or the value still checked against the class), and
// the evidence the values have now. The buttons belong to the drawer's footer, with the state they act on.

import type { ObjectClass, ObjectSlotRow, ObjectSuspension } from "../../../api/types.ts";
import { OBJECT_TEXT, percentOf, reasonText } from "../../../lib/vocab.ts";
import { RequestLink } from "../../../ui/RequestRef.tsx";
import { SafeText } from "../../../ui/SafeText.tsx";
import { classNameOf, seenText } from "./objects-model.ts";

type Props = {
  slot: ObjectSlotRow;
  suspension: ObjectSuspension;
  examples: readonly string[];
  classes: readonly ObjectClass[];
  /** Whether the learning settings still pause positions on their own. */
  autoPause: boolean;
  /** Whether the gateway applies a pause to the judgment yet (`features.auto_pause`). */
  pauseApplied: boolean;
  now: number;
};

/** The name rule's basis as the judge names it, e.g. `路由词 doctor`; empty when no name is left. */
function basisText(basis: ObjectSuspension["fallback"]["basis"], word: string | null): string {
  if (basis === "none") return "";
  if (basis === "route_word") return `路由词 ${word ?? "—"}`;
  if (basis === "field_name") return `字段名 ${word ?? "—"}`;
  if (basis === "parent_name") return `父对象名 ${word ?? "—"}`;
  return `接口名 ${word ?? "—"}`;
}

export function SuspensionSection({
  slot,
  suspension,
  examples,
  classes,
  autoPause,
  pauseApplied,
  now,
}: Props) {
  const text = OBJECT_TEXT.suspension;
  const { reason, previous, fallback } = suspension;
  const previousClass = previous?.class ?? null;
  const className = (id: string | null) => (id === null ? "—" : classNameOf(classes, id));
  const basis = basisText(fallback.basis, fallback.word);
  let nowLine: string;
  if (slot.in_effect) {
    nowLine = text.inEffect(className(previousClass));
  } else if (fallback.kind === null) {
    nowLine = text.nowNone;
  } else if (fallback.kind === previousClass) {
    nowLine = text.nowSame(basis, className(fallback.kind));
  } else {
    nowLine = text.nowDiff(basis, className(fallback.kind));
  }

  return (
    <section className="obj-section obj-suspension" aria-label={text.title}>
      <div className="field-label">{text.title}</div>
      <div className="small">
        <span className="field-warn">▲ {text.paused}</span>{" "}
        <span className="muted">
          {suspension.auto
            ? text.pausedBy(seenText(suspension.at, now), suspension.version)
            : text.pausedByAdmin(seenText(suspension.at, now))}
        </span>
      </div>
      {reason === null ? null : (
        <div className="small">
          <span className="muted">{text.reason}：</span>
          <SafeText text={reasonText(reason, slot.side, previousClass)} />
        </div>
      )}
      {examples.length === 0 ? null : (
        <div className="small obj-ref-list">
          <span className="muted">{text.examples}：</span>
          {examples.map((id) => (
            <RequestLink key={id} id={id} />
          ))}
        </div>
      )}
      <div className="small">
        <span className="muted">{text.previous}：</span>
        {previous === null || previousClass === null ? (
          <span>{text.previousNone}</span>
        ) : (
          <SafeText
            text={text.previousLine(
              `${className(previousClass)} ${previousClass}`,
              seenText(previous.confirmed_at, now),
              previous.confirmed_by ?? "—",
            )}
          />
        )}
      </div>
      <div className="small">
        <span className="muted">{text.now}：</span>
        <SafeText text={nowLine} />
      </div>
      {slot.in_effect ? (
        <div className="field-warn small">
          ▲ {autoPause ? (pauseApplied ? "" : text.notApplied) : text.effectOff}
        </div>
      ) : (
        <div className="field-warn small">▲ {text.warn}</div>
      )}
      {suspension.evidence_now.length === 0 ? null : (
        <div className="small">
          <span className="muted">{text.evidence}：</span>
          <SafeText
            text={suspension.evidence_now
              .map((item) => `${className(item.class)} ${percentOf(item.share)}`)
              .join(" · ")}
          />
        </div>
      )}
    </section>
  );
}
