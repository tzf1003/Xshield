// The learning task's line and the agent's line, under the counters of the object map (console design 3.2): when the last
// run was and what it proposed, when the next one is, and the buttons for the run record and a run now. With the agent
// on, its day and its waiting and failed positions follow. A count is a link: the proposals show the positions waiting
// for a decision, and the agent's counts filter the table to the positions it waits for or failed on.

import { type ReactNode, useEffect, useState } from "react";
import { useRunObjects } from "../../../api/queries.ts";
import type {
  ObjectAgentFilter,
  ObjectAgentHealth,
  ObjectLearningState,
} from "../../../api/types.ts";
import { hm } from "../../../features/system/clock.ts";
import { OBJECT_AGENT_TEXT } from "../../../lib/vocab.ts";
import { ModelsLink } from "./ModelsLink.tsx";
import { budgetUsed, durationOf, refusalWord, runBlock } from "./objects-agent.ts";

type Props = {
  site: string;
  learning: ObjectLearningState;
  /** Automatic learning is on in the saved configuration, so a run also happens on its own. */
  autoLearn: boolean;
  /** The agent is on in the saved configuration. */
  agentOn: boolean;
  agentHealth: ObjectAgentHealth;
  now: number;
  onRuns: () => void;
  /** The new proposals are the positions waiting for a decision; the agent's counts filter by its state. */
  onFilter: (next: { state: "proposed" } | { agent: ObjectAgentFilter }) => void;
};

export function LearningStatusBar({
  site,
  learning,
  autoLearn,
  agentOn,
  agentHealth,
  now,
  onRuns,
  onFilter,
}: Props) {
  const run = useRunObjects();
  // The id of the last run before a run started here: the result is shown once a newer run record appears.
  const [before, setBefore] = useState<number | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const last = learning.last;
  const bar = OBJECT_AGENT_TEXT.bar;

  useEffect(() => {
    if (before === null || learning.running || last === null || last.id === before) return;
    setMessage(OBJECT_AGENT_TEXT.bar.result(last.proposals, last.agent.answered));
    setBefore(null);
  }, [before, learning.running, last]);

  const block = runBlock(learning, now);
  const busy = learning.running || run.isPending;
  const runTitle = busy
    ? bar.running
    : block === "cooldown"
      ? OBJECT_AGENT_TEXT.runError.RUN_TOO_SOON
      : undefined;
  const next = learning.next_at === null ? null : hm(Date.parse(learning.next_at));

  const start = () => {
    setMessage(null);
    setBefore(last?.id ?? 0);
    run.mutate(
      { name: site },
      {
        onError: (error) => {
          setBefore(null);
          setMessage(refusalWord(error, bar.notStarted));
        },
      },
    );
  };

  let first: ReactNode;
  if (!autoLearn) first = bar.manualOnly;
  else if (last === null) first = bar.never;
  else
    first = (
      <>
        {bar.last(hm(Date.parse(last.at)), durationOf(last.duration_ms))}
        {" · "}
        <button type="button" className="linkbtn" onClick={() => onFilter({ state: "proposed" })}>
          {bar.proposals(last.proposals)}
        </button>
        {" · "}
        {bar.tightened(last.tightened)}
      </>
    );

  const used = budgetUsed(learning.agent_today);

  return (
    <div className="obj-status">
      <div className="obj-status-line">
        <span className="obj-status-name">{bar.learning}</span>
        <span>{first}</span>
        {autoLearn && next !== null ? <span className="muted"> · {bar.next(next)}</span> : null}
        <span className="obj-status-actions">
          <button type="button" className="linkbtn" onClick={onRuns}>
            {bar.runs}
          </button>
          {autoLearn ? (
            <button
              type="button"
              className="btn"
              disabled={block !== null || run.isPending}
              title={runTitle}
              onClick={start}
            >
              {busy ? bar.running : bar.runNow}
            </button>
          ) : null}
        </span>
      </div>
      {agentOn ? (
        <div className="obj-status-line">
          <span className="obj-status-name">{OBJECT_AGENT_TEXT.name}</span>
          <span>{bar.today(learning.agent_today.used, learning.agent_today.limit)}</span>
          {" · "}
          <button type="button" className="linkbtn" onClick={() => onFilter({ agent: "waiting" })}>
            {bar.waiting(learning.agent_waiting)}
          </button>
          {" · "}
          <button type="button" className="linkbtn" onClick={() => onFilter({ agent: "failed" })}>
            {bar.failing(learning.agent_failed)}
          </button>
          {used && learning.agent_waiting > 0 ? (
            <span className="muted"> · {bar.atLimit(learning.agent_waiting)}</span>
          ) : null}
          {agentHealth === "failing" ? (
            <span className="field-warn">
              {" · "}
              {bar.modelFailing} · <ModelsLink>{bar.modelLink}</ModelsLink>
            </span>
          ) : null}
        </div>
      ) : null}
      {message === null ? null : <div className="small muted">{message}</div>}
    </div>
  );
}
