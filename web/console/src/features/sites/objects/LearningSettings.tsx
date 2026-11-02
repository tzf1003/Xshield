// The learning settings of a site's object map (console design 3.5): what learns on its own, what tightens by itself,
// the agent and its daily cap, the thresholds, and the automatic pause. They are part of the site's configuration:
// a change goes through the save dialog and makes a new version. The agent is greyed out with its reason when no
// model is configured.

import { Drawer, Switch } from "antd";
import { useState } from "react";
import type { LearningSettings as Learning, SiteSpec } from "../../../api/types.ts";
import { effectiveLearning } from "../../../lib/objects-validate.ts";
import { OBJECT_TEXT } from "../../../lib/vocab.ts";
import { withLearning } from "./objects-model.ts";

type Props = {
  working: SiteSpec;
  agentConfigured: boolean;
  onClose: () => void;
  onApply: (spec: SiteSpec) => void;
};

const text = OBJECT_TEXT.learning;

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
  disabled = false,
  onChange,
}: {
  label: string;
  value: number;
  min: number;
  disabled?: boolean;
  onChange: (value: number) => void;
}) {
  return (
    <input
      type="number"
      className="native-input obj-number"
      aria-label={label}
      min={min}
      step={1}
      value={value}
      disabled={disabled}
      onChange={(event) => onChange(Number(event.target.value))}
    />
  );
}

export function LearningSettings({ working, agentConfigured, onClose, onApply }: Props) {
  const saved = effectiveLearning(working.objects?.learning);
  const [value, setValue] = useState<Learning>(saved);
  const changed = !sameLearning(value, saved);
  const countsOk =
    Number.isInteger(value.thresholds.uses) &&
    value.thresholds.uses >= 1 &&
    Number.isInteger(value.thresholds.sessions) &&
    value.thresholds.sessions >= 1 &&
    Number.isInteger(value.agent.daily_limit) &&
    value.agent.daily_limit >= 0;
  const canSave = changed && countsOk;
  const agentOn = agentConfigured && value.agent.enabled;

  return (
    <Drawer open placement="right" size={460} onClose={onClose} title={text.title}>
      <div className="stack">
        <div className="small muted">{text.intro}</div>

        <div className="obj-learning-row">
          <span>{text.autoLearn.name}</span>
          <Switch
            aria-label={text.autoLearn.name}
            checked={value.auto_learn}
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
            checkedChildren={text.on}
            unCheckedChildren={text.off}
            onChange={(checked) => setValue({ ...value, auto_tighten: checked })}
          />
          <span className="obj-learning-help">{text.autoTighten.help}</span>
        </div>

        <div className="obj-learning-row">
          <span>{text.agent.name}</span>
          <Switch
            aria-label={text.agent.name}
            checked={agentOn}
            disabled={!agentConfigured}
            checkedChildren={text.on}
            unCheckedChildren={text.off}
            onChange={(checked) =>
              setValue({ ...value, agent: { ...value.agent, enabled: checked } })
            }
          />
          <span className="obj-learning-help">
            {text.agent.help}
            {agentConfigured ? "" : `。${text.agent.unavailable}`}
          </span>
          <span className="small">{text.agent.daily}</span>
          <NumberField
            label={text.agent.daily}
            value={value.agent.daily_limit}
            min={0}
            disabled={!agentOn}
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
              onChange={(uses) => setValue({ ...value, thresholds: { ...value.thresholds, uses } })}
            />
            <span>{text.thresholds.uses}</span>
            <NumberField
              label={text.thresholds.sessionsLabel}
              value={value.thresholds.sessions}
              min={1}
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
            checkedChildren={text.on}
            unCheckedChildren={text.off}
            onChange={(checked) => setValue({ ...value, auto_pause: checked })}
          />
          <span className="obj-learning-help">{text.autoPause.help}</span>
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
