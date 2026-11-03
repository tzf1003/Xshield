// The banner of the object map (console design 2.2): one line for each kind of unhandled event. Pauses and anomalies are
// warnings: a single event opens its position, several open the list of their kind. Automatic tightenings are neutral
// and have 知道了 (known), which marks their batch handled. A pause has no 知道了: each paused position is handled by
// its own action, since a pause changes what the judge does.

import { useAckEvent } from "../../../api/queries.ts";
import type { ObjectEvent } from "../../../api/types.ts";
import { useSetSearch } from "../../../app/scope.ts";
import { hm } from "../../../features/system/clock.ts";
import { OBJECT_TEXT, reasonText } from "../../../lib/vocab.ts";
import { SafeText } from "../../../ui/SafeText.tsx";
import { bannerGroups } from "./objects-model.ts";

type Props = { site: string; events: readonly ObjectEvent[] };

/** An event written out: its position, then the reason it happened, e.g. `GET /doctor/{id} path[1] 快速放行后……`. */
function lineOf(event: ObjectEvent): string {
  if (event.reason === null) return event.key;
  return `${event.key} ${reasonText(event.reason, event.side, event.before?.class ?? null)}`;
}

/** The clock of a learning pass in the banner: `HH:mm` of the same day, `—` when the time is not readable. */
function clockOf(at: string): string {
  const ms = Date.parse(at);
  return Number.isNaN(ms) ? "—" : hm(ms);
}

export function ObjectsBanner({ site, events }: Props) {
  const setSearch = useSetSearch();
  const ack = useAckEvent();
  const groups = bannerGroups(events.filter((event) => event.status === "open"));
  if (groups.paused.length === 0 && groups.anomaly.length === 0 && groups.tightened.length === 0) {
    return null;
  }

  const warnLine = (list: ObjectEvent[], head: string, kind: "auto_pause" | "anomaly") => {
    const only = list.length === 1 ? list[0] : undefined;
    const view = () => {
      if (only?.slot_id)
        setSearch({ slot: only.slot_id, objevents: undefined, objkind: undefined }, true);
      else setSearch({ objevents: "open", objkind: kind, slot: undefined }, true);
    };
    return (
      <div key={kind} className="banner warn" role="status">
        <div className="grow">
          <span>▲ {head}</span> <SafeText text={list[0] === undefined ? "" : lineOf(list[0])} />
          {list.length > 1 ? <span> {OBJECT_TEXT.banner.more}</span> : null}
        </div>
        <button type="button" className="linkbtn" onClick={view}>
          {OBJECT_TEXT.banner.view}
        </button>
      </div>
    );
  };

  return (
    <div className="obj-stack">
      {groups.paused.length === 0
        ? null
        : warnLine(
            groups.paused,
            OBJECT_TEXT.banner.pausedLine(groups.paused.length),
            "auto_pause",
          )}
      {groups.anomaly.length === 0
        ? null
        : warnLine(
            groups.anomaly,
            OBJECT_TEXT.banner.anomalyLine(groups.anomaly.length),
            "anomaly",
          )}
      {groups.tightened.map((group) => (
        <div key={group.at} className="banner" role="status">
          <div className="grow">
            <span>{OBJECT_TEXT.banner.taskLine(clockOf(group.at), group.events.length)}</span>{" "}
            {group.events[0] === undefined ? null : <SafeText text={lineOf(group.events[0])} />}
            {group.events.length > 1 ? <span> {OBJECT_TEXT.banner.more}</span> : null}
          </div>
          <button
            type="button"
            className="linkbtn"
            onClick={() =>
              setSearch({ objevents: "open", objkind: "auto_tighten", slot: undefined }, true)
            }
          >
            {OBJECT_TEXT.banner.view}
          </button>
          <button
            type="button"
            className="linkbtn"
            disabled={ack.isPending}
            onClick={() => {
              for (const event of group.events) ack.mutate({ name: site, id: event.id });
            }}
          >
            {OBJECT_TEXT.events.actions.knowIt}
          </button>
        </div>
      ))}
    </div>
  );
}
