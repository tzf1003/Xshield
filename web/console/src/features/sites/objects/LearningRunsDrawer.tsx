// The learning task's run record (console design 3.3): the newest runs of the site, one line each. A click opens the
// calls the agent got in that run; a run that failed as a whole shows its reason only.

import { Drawer } from "antd";
import { Fragment, type ReactNode, useState } from "react";
import { useLearningRun, useLearningRuns } from "../../../api/queries.ts";
import type { ObjectRunCall } from "../../../api/types.ts";
import { OBJECT_AGENT_TEXT } from "../../../lib/vocab.ts";
import { Empty, ErrorBar, Loading } from "../../../ui/Page.tsx";
import { SafeText } from "../../../ui/SafeText.tsx";
import { durationOf, failureWord, stampOf } from "./objects-agent.ts";

type Props = { site: string; onClose: () => void };

/** One call in words: the kind the agent chose, a new kind's name, or the failure. */
function resultOf(call: ObjectRunCall): string {
  if (call.status === "queued") return OBJECT_AGENT_TEXT.status.queued.name;
  if (call.status === "skipped_budget") return OBJECT_AGENT_TEXT.status.skipped_budget.name;
  if (call.status === "failed")
    return `${OBJECT_AGENT_TEXT.status.failed.name}：${failureWord(call.failure ?? "unavailable")}`;
  if (call.choice === "new") return `${OBJECT_AGENT_TEXT.newClass}：${call.new_class?.name ?? ""}`;
  return call.choice ?? "—";
}

function CallList({ calls, skipped }: { calls: readonly ObjectRunCall[]; skipped: number }) {
  const t = OBJECT_AGENT_TEXT.runs;
  if (calls.length === 0) return <div className="small muted">{t.noCalls}</div>;
  return (
    <>
      <div className="field-label">{t.calls}</div>
      <table className="tbl" aria-label={t.calls}>
        <thead>
          <tr>
            <th scope="col">{t.call.position}</th>
            <th scope="col">{t.call.result}</th>
            <th scope="col" className="num">
              {t.call.latency}
            </th>
          </tr>
        </thead>
        <tbody>
          {calls.map((call) => (
            <tr key={call.id}>
              <td className="wrap">
                <span className="obj-code">
                  <SafeText text={call.key} />
                </span>
              </td>
              <td className="wrap">
                <SafeText text={resultOf(call)} />
              </td>
              <td className="num">{durationOf(call.latency_ms)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {skipped > 0 ? (
        <div className="small muted">
          {t.skipped}：{skipped}
        </div>
      ) : null}
    </>
  );
}

export function LearningRunsDrawer({ site, onClose }: Props) {
  const runs = useLearningRuns(site);
  const [openId, setOpenId] = useState<number | null>(null);
  const detail = useLearningRun(site, openId);
  const t = OBJECT_AGENT_TEXT.runs;

  let body: ReactNode;
  if (runs.isError) body = <ErrorBar error={runs.error} onRetry={() => void runs.refetch()} />;
  else if (runs.data === undefined) body = <Loading height={160} />;
  else if (runs.data.runs.length === 0) body = <Empty title={t.empty} />;
  else
    body = (
      <div className="tbl-wrap">
        <table className="tbl" aria-label={t.title}>
          <thead>
            <tr>
              <th scope="col">{t.columns.time}</th>
              <th scope="col">{t.columns.trigger}</th>
              <th scope="col" className="num">
                {t.columns.duration}
              </th>
              <th scope="col" className="num">
                {t.columns.proposals}
              </th>
              <th scope="col" className="num">
                {t.columns.tightened}
              </th>
              <th scope="col" className="num">
                {t.columns.paused}
              </th>
              <th scope="col">{t.columns.agent}</th>
            </tr>
          </thead>
          <tbody>
            {runs.data.runs.map((run) => {
              const open = openId === run.id;
              return (
                <Fragment key={run.id}>
                  <tr
                    className="row-click"
                    aria-selected={open}
                    onClick={() => setOpenId(open ? null : run.id)}
                  >
                    <td>{stampOf(run.at)}</td>
                    {run.error === null ? (
                      <>
                        <td>{t.trigger[run.trigger]}</td>
                        <td className="num">{durationOf(run.duration_ms)}</td>
                        <td className="num">{run.proposals}</td>
                        <td className="num">{run.tightened}</td>
                        <td className="num">{run.paused}</td>
                        <td>
                          {`${run.agent.asked} / ${run.agent.answered} / ${run.agent.failed} / ${run.agent.skipped}`}
                        </td>
                      </>
                    ) : (
                      <td colSpan={6} className="field-warn">
                        <SafeText text={t.error(run.error)} />
                      </td>
                    )}
                  </tr>
                  {open ? (
                    <tr>
                      <td colSpan={7}>
                        {detail.isPending ? (
                          <Loading height={60} />
                        ) : detail.isError ? (
                          <ErrorBar error={detail.error} />
                        ) : (
                          <CallList calls={detail.data.calls} skipped={run.agent.skipped} />
                        )}
                      </td>
                    </tr>
                  ) : null}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    );

  return (
    <Drawer open placement="right" size={640} onClose={onClose} title={t.title}>
      {body}
    </Drawer>
  );
}
