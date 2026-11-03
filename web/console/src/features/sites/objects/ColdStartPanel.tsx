// The cold start of an empty object map (console design 1): the named positions the recent requests read, offered as
// the starting point of learning. Confirming writes the chosen ones into the draft through the save dialog; skipping
// hides the list here, and learning goes on without it. The wizard's fifth step shows the same list.

import { useBootstrap } from "../../../api/queries.ts";
import type { ObjectClass, SiteSpec } from "../../../api/types.ts";
import { OBJECT_TEXT } from "../../../lib/vocab.ts";
import { Card, Empty, ErrorBar, Loading } from "../../../ui/Page.tsx";
import { BootstrapList, useBootstrapSelection } from "./BootstrapList.tsx";
import { withPlan } from "./objects-model.ts";

type Props = {
  site: string;
  working: SiteSpec;
  classes: readonly ObjectClass[];
  /** The gateway runs the path-parameter confirmation (`features.path_confirm`). */
  pathConfirm: boolean;
  onApply: (spec: SiteSpec) => void;
  onLater: () => void;
};

export function ColdStartPanel({ site, working, classes, pathConfirm, onApply, onLater }: Props) {
  const boot = useBootstrap(site);
  const selection = useBootstrapSelection(
    boot.data?.candidates ?? [],
    classes,
    working,
    pathConfirm,
  );
  const data = boot.data;
  const noTraffic = data !== undefined && data.records === 0;

  return (
    <Card title={OBJECT_TEXT.coldStart.title}>
      <div className="stack">
        {boot.isPending ? <Loading height={160} /> : null}
        {boot.isError ? (
          <>
            <ErrorBar error={boot.error} onRetry={() => void boot.refetch()} />
            <div className="small muted">{OBJECT_TEXT.coldStart.errorHint}</div>
          </>
        ) : null}
        {data === undefined ? null : noTraffic ? (
          <Empty title={OBJECT_TEXT.coldStart.noTraffic}>
            <div className="small muted">{OBJECT_TEXT.coldStart.noTrafficText}</div>
          </Empty>
        ) : (
          <BootstrapList
            selection={selection}
            classes={classes}
            windowHours={data.window_hours}
            records={data.records}
          />
        )}
        <div className="obj-foot">
          <button type="button" className="btn" onClick={onLater}>
            {OBJECT_TEXT.coldStart.later}
          </button>
          {data === undefined || noTraffic ? null : (
            <button
              type="button"
              className="btn-primary"
              disabled={selection.chosen.length === 0 || selection.messages.length > 0}
              onClick={() => onApply(withPlan(working, selection.plan))}
            >
              {OBJECT_TEXT.coldStart.confirm(selection.chosen.length)}
            </button>
          )}
        </div>
      </div>
    </Card>
  );
}
