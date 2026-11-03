// The learning agent's conclusion for one position (console design 3.4). It shows what the agent chose and why. When it
// names another kind than the rules, the position is ambiguous until someone decides: the two kinds sit side by side,
// with the actions to choose from. A kind the agent proposes that does not exist yet shows its proposed words. While
// the agent waits, has failed or the day's budget is used up, the section says so and offers to ask again. The reason
// and the words of a new kind are model output, shown as text only.

import { type ReactNode, useState } from "react";
import type { ObjectAgent, ObjectClass, ObjectState } from "../../../api/types.ts";
import { hm } from "../../../features/system/clock.ts";
import { pct } from "../../../lib/format.ts";
import { OBJECT_AGENT_TEXT, OBJECT_STATE_INFO, OBJECT_TEXT } from "../../../lib/vocab.ts";
import { Kv } from "../../../ui/Page.tsx";
import { SafeText } from "../../../ui/SafeText.tsx";
import { AgentInputView } from "./AgentInputView.tsx";
import { askBlock, disagrees, failureWord, stampOf } from "./objects-agent.ts";
import { classNameOf } from "./objects-model.ts";

/** A button of a disagreement: a kind the administrator confirms, or keeping the position ambiguous. */
export type VerdictAction = {
  id: string;
  label: string;
  disabled: boolean;
  title?: string;
  onClick: () => void;
};

type Props = {
  agent: ObjectAgent;
  /** The position's state: a confirmed position is not asked about again. */
  state: ObjectState;
  classes: readonly ObjectClass[];
  /** The agent is on for this site, as the saved configuration says. */
  agentOn: boolean;
  today: { used: number; limit: number };
  /** RFC 3339 UTC: the next learning run, or null when automatic learning is off. */
  nextAt: string | null;
  asking: boolean;
  onAsk: () => void;
  onHighlight: (cite: string) => void;
  /** The buttons of a decision (a disagreement, or a proposed new kind), in order. None when the position is settled. */
  actions: readonly VerdictAction[];
};

/** A kind in words: a class by its name and id, a new kind by its proposed name, or an ambiguous position. */
function kindWord(agent: ObjectAgent, id: string, classes: readonly ObjectClass[]): string {
  if (id === "ambiguous") return OBJECT_STATE_INFO.ambiguous.name;
  if (id === "new") {
    const created = agent.new_class;
    return created === null
      ? OBJECT_AGENT_TEXT.newClass
      : `${OBJECT_AGENT_TEXT.newClass}：${created.name} ${created.id}`;
  }
  return `${classNameOf(classes, id)} ${id}`;
}

function Cites({
  cites,
  onHighlight,
}: {
  cites: readonly string[];
  onHighlight: (cite: string) => void;
}) {
  if (cites.length === 0) return <>—</>;
  return (
    <span className="obj-ref-list">
      {cites.map((cite) =>
        /^f[0-9]+$/.test(cite) ? (
          <button key={cite} type="button" className="linkbtn" onClick={() => onHighlight(cite)}>
            {cite}
          </button>
        ) : (
          <span key={cite} className="obj-code">
            <SafeText text={cite} />
          </span>
        ),
      )}
    </span>
  );
}

export function AgentVerdict({
  agent,
  state,
  classes,
  agentOn,
  today,
  nextAt,
  asking,
  onAsk,
  onHighlight,
  actions,
}: Props) {
  const [showInput, setShowInput] = useState(false);
  const blocked = askBlock(agentOn, today);
  const askReason =
    blocked === "off"
      ? OBJECT_AGENT_TEXT.askOff
      : blocked === "budget"
        ? OBJECT_AGENT_TEXT.askBudget
        : null;
  // A confirmed position is not asked about again, and a queued one is already waiting for the next pass.
  const showAsk = state !== "confirmed" && agent.status !== "queued";
  const stamp = stampOf(agent.asked_at);
  const model = agent.model === null ? "" : ` · ${agent.model}`;
  const decisions =
    actions.length === 0 ? null : (
      <div className="obj-foot">
        {actions.map((action) => (
          <button
            key={action.id}
            type="button"
            className="btn"
            disabled={action.disabled}
            title={action.title}
            onClick={action.onClick}
          >
            {action.label}
          </button>
        ))}
      </div>
    );

  let body: ReactNode;
  if (agent.status === "queued") {
    body = (
      <div className="small">
        {OBJECT_AGENT_TEXT.queuedNext(nextAt === null ? null : hm(Date.parse(nextAt)))}
      </div>
    );
  } else if (agent.status === "skipped_budget") {
    body = <div className="small muted">{OBJECT_AGENT_TEXT.budgetLine}</div>;
  } else if (agent.status === "failed") {
    body = (
      <div className="field-warn">
        <SafeText
          text={OBJECT_AGENT_TEXT.failedAt(
            stamp,
            failureWord(agent.failure ?? "unavailable"),
            agent.attempts,
          )}
        />
      </div>
    );
  } else if (agent.choice !== null && disagrees(agent)) {
    body = (
      <>
        <div className="field-warn">▲ {OBJECT_AGENT_TEXT.disagree}</div>
        <Kv
          items={[
            [
              OBJECT_AGENT_TEXT.ruleLabel,
              <SafeText key="rule" text={kindWord(agent, agent.rule_choice ?? "", classes)} />,
            ],
            [
              OBJECT_AGENT_TEXT.agentLabel,
              <SafeText
                key="agent"
                text={`${kindWord(agent, agent.choice, classes)} · ${pct(agent.confidence)}`}
              />,
            ],
          ]}
        />
        <div className="small muted">{OBJECT_AGENT_TEXT.disagreeNote}</div>
        {decisions}
      </>
    );
  } else if (agent.choice === "new") {
    body = (
      <>
        <Kv
          items={[
            [
              OBJECT_TEXT.drawer.agentChoice,
              <SafeText key="choice" text={kindWord(agent, "new", classes)} />,
            ],
            [
              OBJECT_AGENT_TEXT.description,
              <SafeText key="description" text={agent.new_class?.description ?? "—"} />,
            ],
            [OBJECT_TEXT.drawer.agentConfidence, pct(agent.confidence)],
            [
              OBJECT_TEXT.drawer.agentCites,
              <Cites key="cites" cites={agent.cites} onHighlight={onHighlight} />,
            ],
          ]}
        />
        <div className="small muted">{OBJECT_TEXT.drawer.agentReason}</div>
        <div>
          <SafeText text={agent.reason ?? "—"} />
        </div>
        {decisions}
      </>
    );
  } else {
    body = (
      <>
        <Kv
          items={[
            [
              OBJECT_TEXT.drawer.agentChoice,
              <SafeText
                key="choice"
                text={agent.choice === null ? "—" : kindWord(agent, agent.choice, classes)}
              />,
            ],
            [OBJECT_TEXT.drawer.agentConfidence, pct(agent.confidence)],
            [
              OBJECT_TEXT.drawer.agentCites,
              <Cites key="cites" cites={agent.cites} onHighlight={onHighlight} />,
            ],
          ]}
        />
        <div className="small muted">{OBJECT_TEXT.drawer.agentReason}</div>
        <div>
          <SafeText text={agent.reason ?? "—"} />
        </div>
      </>
    );
  }

  return (
    <section className="obj-section">
      <div className="field-label">{OBJECT_TEXT.drawer.agent}</div>
      <div className="small muted">
        {stamp}
        {model}
      </div>
      {body}
      <div className="obj-foot">
        {showAsk ? (
          <button
            type="button"
            className="btn"
            disabled={askReason !== null || asking}
            title={askReason ?? undefined}
            onClick={onAsk}
          >
            {OBJECT_AGENT_TEXT.askAgain}
          </button>
        ) : null}
        {agent.input === null ? null : (
          <button
            type="button"
            className="linkbtn"
            aria-expanded={showInput}
            onClick={() => setShowInput((value) => !value)}
          >
            {showInput ? OBJECT_AGENT_TEXT.inputHide : OBJECT_AGENT_TEXT.inputShow}
          </button>
        )}
      </div>
      {showAsk && askReason !== null ? <div className="small muted">{askReason}</div> : null}
      {showInput && agent.input !== null ? <AgentInputView input={agent.input} /> : null}
    </section>
  );
}
