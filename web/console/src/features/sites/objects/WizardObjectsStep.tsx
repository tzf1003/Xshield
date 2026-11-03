// The fifth step of the new-site wizard (console design 1.1): after the site exists, its named positions are offered as
// the starting point of learning. Confirming opens the save dialog with the chosen entries in the draft; skipping goes
// to the site. Nothing here is written by itself.

import { useBootstrap, useSiteObjects } from "../../../api/queries.ts";
import type { SiteDetail, SiteSpec } from "../../../api/types.ts";
import { OBJECT_TEXT } from "../../../lib/vocab.ts";
import { Card, Empty, ErrorBar, Loading } from "../../../ui/Page.tsx";
import { BootstrapList, useBootstrapSelection } from "./BootstrapList.tsx";
import { withPlan } from "./objects-model.ts";

type Props = {
  site: SiteDetail;
  onSkip: () => void;
  onConfirm: (spec: SiteSpec, count: number) => void;
};

export function WizardObjectsStep({ site, onSkip, onConfirm }: Props) {
  const boot = useBootstrap(site.name);
  const working = site.spec;
  // The map's features tell whether the gateway confirms path positions; until the map has loaded, they do not.
  const pathConfirm = useSiteObjects(site.name).data?.features.path_confirm === true;
  const selection = useBootstrapSelection(boot.data?.candidates ?? [], [], working, pathConfirm);
  const data = boot.data;
  const noTraffic = data !== undefined && data.records === 0;

  return (
    <Card title={OBJECT_TEXT.wizard.step}>
      <div className="stack">
        {boot.isPending ? <Loading height={200} /> : null}
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
            classes={[]}
            windowHours={data.window_hours}
            records={data.records}
          />
        )}
        <div className="obj-foot">
          <button type="button" className="btn" onClick={onSkip}>
            {noTraffic ? OBJECT_TEXT.coldStart.enter : OBJECT_TEXT.coldStart.skip}
          </button>
          {data === undefined || noTraffic ? null : (
            <button
              type="button"
              className="btn-primary"
              disabled={selection.chosen.length === 0 || selection.messages.length > 0}
              onClick={() => onConfirm(withPlan(working, selection.plan), selection.chosen.length)}
            >
              {OBJECT_TEXT.coldStart.confirm(selection.chosen.length)}
            </button>
          )}
        </div>
      </div>
    </Card>
  );
}
