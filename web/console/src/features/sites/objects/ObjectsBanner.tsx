// The banner of the object map (console design 3.1): only what needs a person. An automatic pause is a warning
// that opens the paused positions; an automatic tightening is neutral, with a link to its version and 撤销 (undo),
// which opens the history at that version. Nothing shows when there are no such events.

import type { ObjectEvent } from "../../../api/types.ts";
import { useSetSearch } from "../../../app/scope.ts";
import { hm } from "../../../features/system/clock.ts";
import { OBJECT_TEXT } from "../../../lib/vocab.ts";
import { SafeText } from "../../../ui/SafeText.tsx";

type Props = { events: readonly ObjectEvent[] };

export function ObjectsBanner({ events }: Props) {
  const setSearch = useSetSearch();
  if (events.length === 0) return null;
  return (
    <div className="obj-stack">
      {events.map((event) => {
        const key = `${event.kind}|${event.at}|${event.text}`;
        if (event.kind === "auto_pause") {
          return (
            <div key={key} className="banner warn" role="status">
              <div className="grow">
                <span>▲ {OBJECT_TEXT.banner.paused}：</span>
                <SafeText text={event.text} />
              </div>
              <button
                type="button"
                className="linkbtn"
                onClick={() =>
                  setSearch({ state: "suspended", view: "slot", slot: undefined }, true)
                }
              >
                {OBJECT_TEXT.banner.view}
              </button>
            </div>
          );
        }
        const at = Date.parse(event.at);
        const clock = Number.isNaN(at) ? "—" : hm(at);
        const history = {
          tab: "history",
          diff: event.version === null ? undefined : String(event.version),
        };
        return (
          <div key={key} className="banner" role="status">
            <div className="grow">
              <span>{OBJECT_TEXT.banner.task(clock)} </span>
              <SafeText text={event.text} />
            </div>
            <button type="button" className="linkbtn" onClick={() => setSearch(history)}>
              {OBJECT_TEXT.banner.view}
            </button>
            {event.version === null ? null : (
              <button type="button" className="linkbtn" onClick={() => setSearch(history)}>
                {OBJECT_TEXT.banner.undo}
              </button>
            )}
          </div>
        );
      })}
    </div>
  );
}
