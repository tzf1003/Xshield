// The list of automatic changes (console design 2.3 and 2.4): the learning task's tightenings, pauses and anomalies of
// the window, newest first. Undo and re-confirm put the entry from before the change back into the draft and open the
// save dialog, carrying the event so the save marks it undone. Knowing, keeping a pause and keeping it in effect only
// mark the event handled. A change that a later version overtook cannot be undone here: its position's drawer has it.

import { Drawer } from "antd";
import { useAckEvent, useObjectEvents } from "../../../api/queries.ts";
import type { ObjectClass, ObjectEvent, ObjectEventKind, SiteSpec } from "../../../api/types.ts";
import { OBJECT_EVENT_KINDS } from "../../../app/search-schema.ts";
import { useSetSearch } from "../../../app/scope.ts";
import { fmtInt } from "../../../lib/format.ts";
import {
  IMPACT_INFO,
  OBJECT_EVENT_INFO,
  OBJECT_SIDE_INFO,
  OBJECT_TEXT,
  reasonText,
} from "../../../lib/vocab.ts";
import { ErrorBar, Loading } from "../../../ui/Page.tsx";
import { RequestLink } from "../../../ui/RequestRef.tsx";
import { SafeText } from "../../../ui/SafeText.tsx";
import {
  type ApplyOptions,
  classNameOf,
  draftTouches,
  revertEvent,
  seenText,
} from "./objects-model.ts";

type Props = {
  site: string;
  /** The window's open changes, from the map: the header counts them whatever the list shows. */
  openEvents: readonly ObjectEvent[];
  classes: readonly ObjectClass[];
  /** The saved configuration, and the draft: an undo is refused when the draft already changes its position. */
  saved: SiteSpec;
  working: SiteSpec;
  now: number;
  status: "open" | "all";
  kind: ObjectEventKind | undefined;
  onClose: () => void;
  onApply: (spec: SiteSpec, options?: ApplyOptions) => void;
  onChangeFilter: (next: { status?: "open" | "all"; kind?: ObjectEventKind }) => void;
};

/** The list covers the last 30 days, as the map's events do. */
const WINDOW_DAYS = 30;

/** The change of one event in words: a pause marks the entry as paused, a tightening moves the position to another class. */
function changeText(event: ObjectEvent, classes: readonly ObjectClass[]): string {
  if (event.kind === "anomaly") return OBJECT_TEXT.events.anomalyNote;
  const before = classNameOf(classes, event.before?.class ?? null);
  if (event.kind === "auto_pause") return `${before} → ${OBJECT_TEXT.suspension.paused}`;
  return `${before} → ${classNameOf(classes, event.after?.class ?? null)}`;
}

/** Why an undo or a re-confirm cannot be written now, or null when it can. */
function blockedOf(event: ObjectEvent, saved: SiteSpec, working: SiteSpec): string | null {
  if (event.status === "superseded") return OBJECT_TEXT.events.blockedAfter;
  if (draftTouches(saved, working, event.key)) return OBJECT_TEXT.events.blockedDraft;
  return revertEvent(working, event) === null ? OBJECT_TEXT.events.nothingToUndo : null;
}

export function ObjectEventsDrawer({
  site,
  openEvents,
  classes,
  saved,
  working,
  now,
  status,
  kind,
  onClose,
  onApply,
  onChangeFilter,
}: Props) {
  const setSearch = useSetSearch();
  const ack = useAckEvent();
  // The server filters the list by status and kind; the header counts the open changes of the map.
  const list = useObjectEvents(site, { status, kind, days: WINDOW_DAYS });
  const shown = list.data?.events ?? [];
  const openCount = openEvents.filter((event) => event.status === "open").length;

  const statusText = (event: ObjectEvent): string => {
    if (event.status === "superseded") return OBJECT_TEXT.events.superseded;
    if (event.status === "undone") return OBJECT_TEXT.events.undone(event.handled?.version ?? null);
    if (event.status === "acknowledged" && event.handled !== null) {
      return OBJECT_TEXT.events.acknowledged(event.handled.by, seenText(event.handled.at, now));
    }
    return OBJECT_TEXT.events.statusOpen;
  };

  const restore = (event: ObjectEvent) => {
    const spec = revertEvent(working, event);
    if (spec === null || blockedOf(event, saved, working) !== null) return;
    const note =
      event.kind === "auto_pause"
        ? OBJECT_TEXT.events.noteReconfirm(event.key, event.version)
        : event.version === null
          ? undefined
          : OBJECT_TEXT.events.noteUndo(event.version);
    onApply(spec, { note, objectEvent: event.id });
    onClose();
  };

  const handle = (event: ObjectEvent) => {
    ack.mutate({ name: site, id: event.id });
  };

  const openPosition = (event: ObjectEvent) => {
    setSearch({ slot: event.slot_id ?? undefined, objevents: undefined, objkind: undefined }, true);
  };

  const viewVersion = (version: number) => {
    setSearch({ tab: "history", diff: String(version), objevents: undefined, objkind: undefined });
  };

  const title = (
    <span className="obj-card-title">
      <span>{OBJECT_TEXT.events.title}</span>
      <span className="small muted">{OBJECT_TEXT.events.meta(WINDOW_DAYS, openCount)}</span>
    </span>
  );

  return (
    <Drawer open placement="right" size={560} mask={false} onClose={onClose} title={title}>
      <div className="stack">
        <div className="obj-tools-line" role="radiogroup" aria-label={OBJECT_TEXT.events.title}>
          <label className="adv-radio">
            <input
              type="radio"
              name="object-events-status"
              checked={status === "open"}
              onChange={() => onChangeFilter({ status: "open" })}
            />
            {OBJECT_TEXT.events.open}
          </label>
          <label className="adv-radio">
            <input
              type="radio"
              name="object-events-status"
              checked={status === "all"}
              onChange={() => onChangeFilter({ status: "all" })}
            />
            {OBJECT_TEXT.events.all}
          </label>
          <label className="small">
            {OBJECT_TEXT.events.kind}{" "}
            <select
              className="native-input"
              value={kind ?? ""}
              onChange={(event) =>
                onChangeFilter({
                  kind:
                    event.target.value === "" ? undefined : (event.target.value as ObjectEventKind),
                })
              }
            >
              <option value="">{OBJECT_TEXT.events.kindAll}</option>
              {OBJECT_EVENT_KINDS.map((item) => (
                <option key={item} value={item}>
                  {OBJECT_TEXT.events.kinds[item]}
                </option>
              ))}
            </select>
          </label>
        </div>

        {ack.isError ? <ErrorBar error={ack.error} /> : null}
        {list.isError ? <ErrorBar error={list.error} onRetry={() => void list.refetch()} /> : null}
        {list.isPending ? <Loading height={160} /> : null}
        {list.isSuccess && shown.length === 0 ? (
          <div className="small muted">{OBJECT_TEXT.events.empty}</div>
        ) : null}

        {shown.map((event) => {
          const blocked = event.status === "open" ? blockedOf(event, saved, working) : null;
          const reason =
            event.reason === null
              ? null
              : reasonText(event.reason, event.side, event.before?.class ?? null);
          return (
            <section
              key={event.id}
              className="obj-section"
              aria-label={OBJECT_EVENT_INFO[event.kind].name}
            >
              <div className="row small">
                <span className="mono">{seenText(event.at, now)}</span>
                <span>
                  {OBJECT_EVENT_INFO[event.kind].icon} {OBJECT_EVENT_INFO[event.kind].name}
                </span>
                <span className="muted">
                  {event.version === null
                    ? OBJECT_TEXT.events.task
                    : `${OBJECT_TEXT.events.version(event.version)} · ${OBJECT_TEXT.events.task}`}
                </span>
              </div>
              <div>
                <span className="muted">{OBJECT_SIDE_INFO[event.side].name} </span>
                <span className="obj-code">
                  <SafeText text={event.key} />
                </span>
              </div>
              <div>{changeText(event, classes)}</div>
              {reason === null ? null : (
                <div className="small">
                  {OBJECT_TEXT.events.reason}：<SafeText text={reason} />
                </div>
              )}
              {event.impact.length === 0 ? null : (
                <div className="small">
                  {OBJECT_TEXT.events.impact}：
                  {event.impact
                    .map((change) => `${IMPACT_INFO[change.kind]} ${fmtInt(change.count)} 次`)
                    .join(" · ")}
                </div>
              )}
              {event.examples.length === 0 ? null : (
                <div className="small obj-ref-list">
                  {OBJECT_TEXT.events.sample}：
                  {event.examples.map((id) => (
                    <RequestLink key={id} id={id} />
                  ))}
                </div>
              )}
              <div className="small muted">{statusText(event)}</div>
              {blocked === null ? null : <div className="small muted">{blocked}</div>}

              <div className="obj-foot">
                {event.status !== "open" ? null : event.kind === "auto_tighten" ? (
                  <>
                    <button
                      type="button"
                      className="btn"
                      disabled={ack.isPending}
                      onClick={() => handle(event)}
                    >
                      {OBJECT_TEXT.events.actions.knowIt}
                    </button>
                    <button
                      type="button"
                      className="btn"
                      disabled={blocked !== null}
                      title={blocked ?? undefined}
                      onClick={() => restore(event)}
                    >
                      {OBJECT_TEXT.events.actions.undo}
                    </button>
                  </>
                ) : event.kind === "auto_pause" ? (
                  <>
                    <button type="button" className="btn" onClick={() => openPosition(event)}>
                      {OBJECT_TEXT.events.actions.open}
                    </button>
                    <button
                      type="button"
                      className="btn"
                      disabled={ack.isPending}
                      onClick={() => handle(event)}
                    >
                      {OBJECT_TEXT.events.actions.keepPaused}
                    </button>
                    <button
                      type="button"
                      className="btn-primary"
                      disabled={blocked !== null}
                      title={blocked ?? undefined}
                      onClick={() => restore(event)}
                    >
                      {OBJECT_TEXT.events.actions.reconfirm}
                    </button>
                  </>
                ) : (
                  <>
                    <button type="button" className="btn" onClick={() => openPosition(event)}>
                      {OBJECT_TEXT.events.actions.open}
                    </button>
                    <button
                      type="button"
                      className="btn"
                      disabled={ack.isPending}
                      onClick={() => handle(event)}
                    >
                      {OBJECT_TEXT.events.actions.keepEffect}
                    </button>
                  </>
                )}
                {event.version === null || event.status === "superseded" ? null : (
                  <button
                    type="button"
                    className="btn"
                    onClick={() => viewVersion(event.version ?? 0)}
                  >
                    {OBJECT_TEXT.events.actions.viewVersion}
                  </button>
                )}
              </div>
            </section>
          );
        })}
      </div>
    </Drawer>
  );
}
