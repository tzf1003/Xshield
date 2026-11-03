// The learning settings of a site's object map (console design 3.5): what learns on its own, what tightens by itself,
// the agent and its daily cap, the thresholds, and the automatic pause. They are part of the site's configuration:
// a change goes through the save dialog and makes a new version. The agent is greyed out with its reason when no
// model is configured.

import { Drawer, Switch } from "antd";
import type { LearningStatus, ObjectEventKind, ObjectFeatures } from "../../../api/types.ts";
import { hm } from "../../../features/system/clock.ts";
import { useState } from "react";
import type { LearningSettings as Learning, SiteSpec } from "../../../api/types.ts";
import { effectiveLearning } from "../../../lib/objects-validate.ts";
import { OBJECT_TEXT } from "../../../lib/vocab.ts";
import { withLearning } from "./objects-model.ts";

type Props = {
  working: SiteSpec;
  agentConfigured: boolean;
  /** What the gateway runs now: a part it does not run yet still saves, and its line says so. */
  features: ObjectFeatures;
  status: LearningStatus;
  /** Opens the list of automatic changes filtered to one kind (the counts in the status lines link to it). */
  onOpenEvents: (kind: ObjectEventKind) => void;
  onClose: () => void;
  onApply: (spec: SiteSpec) => void;
};

const text = OBJECT_TEXT.learning;

/**
 * Whether the drawer can save a change. The gateway takes `objects.learning` since #124; set it to false to show the
 * values read-only again if the gateway ever refuses the key.
 */
export const LEARNING_SAVE_READY = true;

/**
 * Whether the drawer can turn the agent on. The learning agent is not on the gateway yet, and the gateway refuses
 * `agent.enabled: true` until it is, so the switch stays off.
 */
export const AGENT_SAVE_READY = false;

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
  working,
  agentConfigured,
  features,
  status,
  onOpenEvents,
  onClose,
  onApply,
}: Props) {
  const passAt = status.last_pass_at === null ? NaN : Date.parse(status.last_pass_at);
  const lastPass = Number.isNaN(passAt) ? text.status.never : text.status.schedule(hm(passAt));
  const saved = effectiveLearning(working.objects?.learning);
  const [value, setValue] = useState<Learning>(saved);
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
  const agentReady = AGENT_SAVE_READY && agentConfigured;
  const agentOn = agentReady && value.agent.enabled;

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
              {text.status.tightened(status.auto_tighten_7d)}
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
            disabled={!agentReady || !editable}
            checkedChildren={text.on}
            unCheckedChildren={text.off}
            onChange={(checked) =>
              setValue({ ...value, agent: { ...value.agent, enabled: checked } })
            }
          />
          <span className="obj-learning-help">
            {text.agent.help}
            {agentReady
              ? ""
              : `。${agentConfigured ? text.agent.notReady : text.agent.unavailable}`}
          </span>
          <span className="small">{text.agent.daily}</span>
          <NumberField
            label={text.agent.daily}
            value={value.agent.daily_limit}
            min={0}
            max={100000}
            disabled={!agentOn || !editable}
            onChange={(daily) =>
              setValue({ ...value, agent: { ...value.agent, daily_limit: daily } })
            }
          />
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
              {text.status.paused(status.auto_pause_7d)}
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
    </Drawer>
  );
}
