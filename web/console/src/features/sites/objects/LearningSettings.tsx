// The learning settings of a site's object map (console design 3.1 and 3.5): what learns on its own, what tightens by
// itself, the learning agent with its state and its daily cap, the thresholds, and the automatic pause. They are part of
// the site's configuration: a change goes through the save dialog and makes a new version. The agent's switch stays off
// while no model is configured, but an agent that is on can always be switched off; its line shows what the agent waits
// for and offers the sample of what it is given.

import { Drawer, Switch } from "antd";
import { type ReactNode, useState } from "react";
import type {
  LearningSettings as Learning,
  ObjectAgentHealth,
  ObjectEvent,
  ObjectEventKind,
  ObjectFeatures,
  ObjectLearningState,
  SiteSpec,
} from "../../../api/types.ts";
import { hm } from "../../../features/system/clock.ts";
import { effectiveLearning } from "../../../lib/objects-validate.ts";
import { OBJECT_AGENT_TEXT, OBJECT_TEXT } from "../../../lib/vocab.ts";
import { AgentSampleDialog } from "./AgentSampleDialog.tsx";
import { ModelsLink } from "./ModelsLink.tsx";
import { weekCount } from "./objects-agent.ts";
import { withLearning } from "./objects-model.ts";

type Props = {
  /** The site's name: the sample of the agent's question is read for it. */
  site: string;
  working: SiteSpec;
  /** A model is configured: its address, its name and its key are all there (console design 3.1). */
  agentConfigured: boolean;
  agentHealth: ObjectAgentHealth;
  /** What the gateway runs now: a part it does not run yet still saves, and its line says so. */
  features: ObjectFeatures;
  learning: ObjectLearningState;
  /** The automatic changes the map lists: the counts of the last week come from them. */
  events: readonly ObjectEvent[];
  now: number;
  /** Opens the list of automatic changes filtered to one kind (the counts in the status lines link to it). */
  onOpenEvents: (kind: ObjectEventKind) => void;
  onClose: () => void;
  onApply: (spec: SiteSpec) => void;
};

const text = OBJECT_TEXT.learning;
const agentText = OBJECT_AGENT_TEXT.settings;

/**
 * Whether the drawer can save a change. The gateway takes `objects.learning` since #124; set it to false to show the
 * values read-only again if the gateway ever refuses the key.
 */
export const LEARNING_SAVE_READY = true;

/**
 * Whether the drawer can turn the agent on. The gateway refuses `agent.enabled: true` while no model is configured, so
 * the switch stays off then; with the switch off no model is needed, and an agent that is on can always be switched off.
 */
export const AGENT_SAVE_READY = true;

function sameLearning(a: Learning, b: Learning): boolean {
  return (
    a.auto_learn === b.auto_learn &&
    a.auto_tighten === b.auto_tighten &&
    a.auto_pause === b.auto_pause &&
    a.agent.enabled === b.agent.enabled &&
    a.agent.daily_limit === b.agent.daily_limit &&
    a.thresholds.uses === b.thresholds.uses &&
    a.thresholds.sessions === b.thresholds.sessions
  );
}

function NumberField({
  label,
  value,
  min,
  max,
  disabled = false,
  onChange,
}: {
  label: string;
  value: number;
  min: number;
  max: number;
  disabled?: boolean;
  onChange: (value: number) => void;
}) {
  return (
    <input
      type="number"
      className="native-input obj-number"
      aria-label={label}
      min={min}
      max={max}
      step={1}
      value={value}
      disabled={disabled}
      onChange={(event) => onChange(Number(event.target.value))}
    />
  );
}

export function LearningSettings({
  site,
  working,
  agentConfigured,
  agentHealth,
  features,
  learning,
  events,
  now,
  onOpenEvents,
  onClose,
  onApply,
}: Props) {
  const saved = effectiveLearning(working.objects?.learning);
  const [value, setValue] = useState<Learning>(saved);
  const [sampleOpen, setSampleOpen] = useState(false);
  const editable = LEARNING_SAVE_READY;
  const changed = !sameLearning(value, saved);
  // The gateway's ranges (objects.learning in #124): thresholds 1 to 10000, the daily cap 0 to 100000.
  const countsOk =
    Number.isInteger(value.thresholds.uses) &&
    value.thresholds.uses >= 1 &&
    value.thresholds.uses <= 10000 &&
    Number.isInteger(value.thresholds.sessions) &&
    value.thresholds.sessions >= 1 &&
    value.thresholds.sessions <= 10000 &&
    Number.isInteger(value.agent.daily_limit) &&
    value.agent.daily_limit >= 0 &&
    value.agent.daily_limit <= 100000;
  const canSave = editable && changed && countsOk;
  const agentOn = value.agent.enabled;
  const canTurnOn = AGENT_SAVE_READY && agentConfigured;
  const agentSwitchDisabled = !editable || (!agentOn && !canTurnOn);

  const last = learning.last;
  const lastPass =
    last === null ? text.status.never : text.status.schedule(hm(Date.parse(last.at)));
  const next = learning.next_at === null ? null : hm(Date.parse(learning.next_at));
  const tightened = weekCount(events, "auto_tighten", now);
  const paused = weekCount(events, "auto_pause", now);

  // The agent's state under its switch (console design 3.1): no model, a failing model, or the positions it waits for.
  const agentNotes: ReactNode[] = [];
  if (!agentConfigured) {
    agentNotes.push(
      <span key="model" className="field-warn">
        {agentText.noModel} · <ModelsLink>{agentText.configure}</ModelsLink>
      </span>,
    );
  } else if (agentHealth === "failing") {
    agentNotes.push(
      <span key="model" className="field-warn">
        {agentText.failingModel} · <ModelsLink>{agentText.viewModel}</ModelsLink>
      </span>,
    );
  }
  if (agentConfigured && learning.agent_waiting > 0) {
    agentNotes.push(
      <span key="waiting">
        {agentText.waiting(learning.agent_waiting)} ·{" "}
        <button type="button" className="linkbtn" onClick={() => setSampleOpen(true)}>
          {agentText.sample}
        </button>
      </span>,
    );
  }

  return (
    <Drawer open placement="right" size={460} onClose={onClose} title={text.title}>
      <div className="stack">
        <div className="small muted">{text.intro}</div>
        {editable ? null : <div className="small muted">{text.pending}</div>}

        <div className="obj-learning-row">
          <span>{text.autoLearn.name}</span>
          <Switch
            aria-label={text.autoLearn.name}
            checked={value.auto_learn}
            disabled={!editable}
            checkedChildren={text.on}
            unCheckedChildren={text.off}
            onChange={(checked) => setValue({ ...value, auto_learn: checked })}
          />
          <span className="obj-learning-help">{text.autoLearn.help}</span>
        </div>

        <div className="obj-learning-row">
          <span>{text.autoTighten.name}</span>
          <Switch
            aria-label={text.autoTighten.name}
            checked={value.auto_tighten}
            disabled={!editable}
            checkedChildren={text.on}
            unCheckedChildren={text.off}
            onChange={(checked) => setValue({ ...value, auto_tighten: checked })}
          />
          <span className="obj-learning-help">{text.autoTighten.help}</span>
          <span className="small muted">
            {lastPass} ·{" "}
            <button type="button" className="linkbtn" onClick={() => onOpenEvents("auto_tighten")}>
              {text.status.tightened(tightened)}
            </button>
            {features.auto_tighten ? null : (
              <span className="field-warn"> · {text.status.notApplied}</span>
            )}
          </span>
        </div>

        <div className="obj-learning-row">
          <span>{text.agent.name}</span>
          <Switch
            aria-label={text.agent.name}
            checked={agentOn}
            disabled={agentSwitchDisabled}
            checkedChildren={text.on}
            unCheckedChildren={text.off}
            onChange={(checked) =>
              setValue({ ...value, agent: { ...value.agent, enabled: checked } })
            }
          />
          <span className="obj-learning-help">{text.agent.help}</span>
          {agentNotes.length === 0 ? null : (
            <div className="obj-learning-wide small">{agentNotes}</div>
          )}
          {agentOn ? (
            <div className="obj-learning-wide">
              <span className="row small">
                <span>{text.agent.daily}</span>
                <NumberField
                  label={text.agent.daily}
                  value={value.agent.daily_limit}
                  min={0}
                  max={100000}
                  disabled={!editable}
                  onChange={(daily) =>
                    setValue({ ...value, agent: { ...value.agent, daily_limit: daily } })
                  }
                />
                <span>{agentText.dailyUnit}</span>
                <span className="muted">{agentText.usage(learning.agent_today.used, next)}</span>
              </span>
              <span className="obj-learning-help">{agentText.hint}</span>
            </div>
          ) : null}
        </div>

        <div className="obj-learning-row">
          <span>{text.thresholds.name}</span>
          <span className="row small">
            <span>{OBJECT_TEXT.learning.thresholds.atLeast}</span>
            <NumberField
              label={text.thresholds.usesLabel}
              value={value.thresholds.uses}
              min={1}
              max={10000}
              disabled={!editable}
              onChange={(uses) => setValue({ ...value, thresholds: { ...value.thresholds, uses } })}
            />
            <span>{text.thresholds.uses}</span>
            <NumberField
              label={text.thresholds.sessionsLabel}
              value={value.thresholds.sessions}
              min={1}
              max={10000}
              disabled={!editable}
              onChange={(sessions) =>
                setValue({ ...value, thresholds: { ...value.thresholds, sessions } })
              }
            />
            <span>{text.thresholds.sessions}</span>
          </span>
          <span className="obj-learning-help">{text.thresholds.help}</span>
        </div>

        <div className="obj-learning-row">
          <span>{text.autoPause.name}</span>
          <Switch
            aria-label={text.autoPause.name}
            checked={value.auto_pause}
            disabled={!editable}
            checkedChildren={text.on}
            unCheckedChildren={text.off}
            onChange={(checked) => setValue({ ...value, auto_pause: checked })}
          />
          <span className="obj-learning-help">{text.autoPause.help}</span>
          <span className="small muted">
            <button type="button" className="linkbtn" onClick={() => onOpenEvents("auto_pause")}>
              {text.status.paused(paused)}
            </button>
            {features.auto_pause ? null : (
              <span className="field-warn"> · {text.status.notApplied}</span>
            )}
          </span>
        </div>

        <div className="obj-foot">
          {changed ? null : <span className="small muted">{text.unchanged}</span>}
          <button
            type="button"
            className="btn-primary"
            disabled={!canSave}
            onClick={() => onApply(withLearning(working, value))}
          >
            {text.save}
          </button>
        </div>
      </div>
      {sampleOpen ? <AgentSampleDialog site={site} onClose={() => setSampleOpen(false)} /> : null}
    </Drawer>
  );
}
