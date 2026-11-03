// The edit form of a model card (design agent-model-ui 2.2). It turns the card's body into fields in place, so the
// status above stays in view. A preset line's address is read-only; switching to another line puts its address and
// model in, and asks first when the model was typed by hand.

import { App, Radio } from "antd";
import { useId, useState } from "react";
import type { JevRoute, ModelKind } from "../../api/types.ts";
import {
  AGENT_TIMEOUT,
  type FormChoice,
  type FormProblems,
  JEV_TIMEOUT,
  type ModelForm as Form,
  type ProblemKey,
  presetModel,
  type TestLine,
  withChoice,
} from "../../lib/model-form.ts";
import { MODEL_PROVIDER_LABEL, MODEL_ROUTE_LABEL, MODEL_TEXT } from "../../lib/vocab.ts";
import { ModelTestResult } from "./ModelTestResult.tsx";
import { SecretField } from "./SecretField.tsx";

export type ModelFormProps = {
  kind: ModelKind;
  form: Form;
  onChange: (next: Form) => void;
  problems: FormProblems;
  /** A key must be typed: none is saved yet, or the console is taking over from the environment. */
  keyRequired: boolean;
  /** What the key row says about the saved key when it is not being replaced. */
  keySummary: string;
  /** Agent: the form can share Jev's key (both sides on the Vercel AI Gateway, design 2.2). */
  shareAllowed: boolean;
  test: {
    line: TestLine | null;
    testing: boolean;
    cooldown: number;
    onTest: () => void;
    onCancelTest: () => void;
  };
  footnote: string;
  canSave: boolean;
  onCancel: () => void;
  onSave: () => void;
};

const JEV_CHOICES: JevRoute[] = ["gateway", "direct", "custom"];

export function ModelForm(props: ModelFormProps) {
  const {
    kind,
    form,
    onChange,
    problems,
    keyRequired,
    keySummary,
    shareAllowed,
    test,
    footnote,
    canSave,
    onCancel,
    onSave,
  } = props;
  const base = useId();
  // The app's own modal instance: a static Modal.confirm does not follow the theme (antd warns about it).
  const { modal } = App.useApp();
  const [touched, setTouched] = useState<ProblemKey[]>([]);
  const [replacing, setReplacing] = useState(keyRequired);

  const touch = (key: ProblemKey) => {
    setTouched((previous) => (previous.includes(key) ? previous : [...previous, key]));
  };
  const shown = (key: ProblemKey): string | undefined =>
    touched.includes(key) ? problems[key] : undefined;

  const choice = form.choice;
  const preset = kind === "jev" ? presetModel(choice as JevRoute) : null;
  const fixedEndpoint = kind === "jev" ? preset !== null : choice === "vercel_gateway";
  const choiceOptions: Array<{ value: FormChoice; label: string }> =
    kind === "jev"
      ? JEV_CHOICES.map((value) => ({ value, label: MODEL_ROUTE_LABEL[value] }))
      : [
          { value: "vercel_gateway", label: MODEL_PROVIDER_LABEL.vercel_gateway },
          { value: "custom", label: MODEL_PROVIDER_LABEL.custom },
        ];

  const choose = (next: FormChoice) => {
    if (next === choice) return;
    const switched = withChoice(kind, form, next);
    if (kind === "jev") {
      const nextPreset = presetModel(next as JevRoute);
      const typed = form.model.trim();
      const previous = presetModel(choice as JevRoute);
      if (nextPreset !== null && typed !== "" && typed !== previous && typed !== nextPreset) {
        modal.confirm({
          title: MODEL_TEXT.modelSwitchTitle(nextPreset),
          okText: MODEL_TEXT.modelSwitchYes(nextPreset),
          cancelText: MODEL_TEXT.modelSwitchKeep,
          onOk: () => onChange(switched),
          onCancel: () => onChange({ ...switched, model: form.model }),
        });
        return;
      }
    }
    onChange(switched);
  };

  const keyHelpId = `${base}-key-help`;
  const timeoutHelpId = `${base}-timeout-help`;
  const keyProblem = shown("key");
  const range = kind === "jev" ? JEV_TIMEOUT : AGENT_TIMEOUT;
  const timeoutHint = kind === "jev" ? MODEL_TEXT.timeoutHintJev : MODEL_TEXT.timeoutHintAgent;

  return (
    <div className="sys-form">
      <fieldset className="field sys-choice">
        <legend className="field-label">
          {kind === "jev" ? MODEL_TEXT.lineGateway : MODEL_TEXT.rowProvider}
        </legend>
        <Radio.Group
          name={`${base}-choice`}
          value={choice}
          onChange={(event) => choose(event.target.value as FormChoice)}
        >
          {choiceOptions.map((option) => (
            <Radio key={option.value} value={option.value}>
              {option.label}
            </Radio>
          ))}
        </Radio.Group>
        {kind === "jev" && choice === "direct" ? (
          <div className="field-warn">{MODEL_TEXT.directWarn}</div>
        ) : null}
      </fieldset>

      <div className="field">
        <label className="field-label" htmlFor={`${base}-endpoint`}>
          {MODEL_TEXT.rowEndpoint}
        </label>
        <input
          id={`${base}-endpoint`}
          className="native-input mono"
          value={form.endpoint}
          readOnly={fixedEndpoint}
          onChange={(event) => {
            touch("endpoint");
            onChange({ ...form, endpoint: event.currentTarget.value });
          }}
          onBlur={() => touch("endpoint")}
          aria-invalid={shown("endpoint") === undefined ? undefined : true}
          aria-describedby={shown("endpoint") === undefined ? undefined : `${base}-endpoint-error`}
        />
        {fixedEndpoint ? <div className="field-help">{MODEL_TEXT.endpointFixed}</div> : null}
        {shown("endpoint") === undefined ? null : (
          <div id={`${base}-endpoint-error`} className="field-error">
            {shown("endpoint")}
          </div>
        )}
      </div>

      <div className="field">
        <div className="sys-inline">
          <label className="field-label" htmlFor={`${base}-model`}>
            {MODEL_TEXT.rowModel}
          </label>
          {preset !== null && preset !== form.model ? (
            <button
              type="button"
              className="linkbtn"
              onClick={() => {
                touch("model");
                onChange({ ...form, model: preset });
              }}
            >
              {MODEL_TEXT.btnRestoreDefault}
            </button>
          ) : null}
        </div>
        <input
          id={`${base}-model`}
          className="native-input mono"
          value={form.model}
          placeholder={kind === "agent" ? MODEL_TEXT.modelPlaceholder : undefined}
          onChange={(event) => {
            touch("model");
            onChange({ ...form, model: event.currentTarget.value });
          }}
          onBlur={() => touch("model")}
          aria-invalid={shown("model") === undefined ? undefined : true}
          aria-describedby={shown("model") === undefined ? undefined : `${base}-model-error`}
        />
        {shown("model") === undefined ? null : (
          <div id={`${base}-model-error`} className="field-error">
            {shown("model")}
          </div>
        )}
      </div>

      <div className="field">
        <span className="field-label" id={`${base}-key-label`}>
          {MODEL_TEXT.rowKey}
        </span>
        {kind === "agent" && form.shareKey ? (
          <div className="sys-keyrow">{MODEL_TEXT.keyShared}</div>
        ) : replacing ? (
          <div>
            <SecretField
              id={`${base}-key`}
              value={form.key}
              onChange={(value) => {
                touch("key");
                onChange({ ...form, key: value });
              }}
              onBlur={() => touch("key")}
              error={keyProblem}
              helpId={keyHelpId}
              labelledBy={`${base}-key-label`}
            />
            {keyRequired ? null : (
              <button
                type="button"
                className="linkbtn"
                onClick={() => {
                  setReplacing(false);
                  onChange({ ...form, key: "" });
                }}
              >
                {MODEL_TEXT.btnCancelReplace}
              </button>
            )}
          </div>
        ) : (
          <div className="sys-keyrow">
            <span>{keySummary}</span>
            <button type="button" className="btn" onClick={() => setReplacing(true)}>
              {MODEL_TEXT.btnReplaceKey}
            </button>
          </div>
        )}
        <div id={keyHelpId} className="field-help">
          {kind === "agent" && form.shareKey
            ? MODEL_TEXT.shareKeyHelp
            : keyRequired
              ? MODEL_TEXT.keyEnvHelp
              : MODEL_TEXT.keyHelp}
        </div>
      </div>

      {kind === "agent" ? (
        <div className="field">
          <label className="check">
            <input
              type="checkbox"
              checked={form.shareKey}
              disabled={!shareAllowed}
              onChange={(event) =>
                onChange({
                  ...form,
                  shareKey: event.currentTarget.checked,
                  key: event.currentTarget.checked ? "" : form.key,
                })
              }
            />{" "}
            {MODEL_TEXT.shareKeyLabel}
          </label>
          <div className="field-help">{MODEL_TEXT.shareKeyHelp}</div>
        </div>
      ) : null}

      <div className="field">
        <label className="field-label" htmlFor={`${base}-timeout`}>
          {MODEL_TEXT.rowTimeout}（{kind === "jev" ? MODEL_TEXT.unitMs : MODEL_TEXT.unitSeconds}）
        </label>
        <input
          id={`${base}-timeout`}
          className="native-input"
          inputMode="numeric"
          value={form.timeout}
          onChange={(event) => {
            touch("timeout");
            onChange({ ...form, timeout: event.currentTarget.value });
          }}
          onBlur={() => touch("timeout")}
          aria-describedby={`${base}-timeout-help`}
          aria-invalid={shown("timeout") === undefined ? undefined : true}
        />
        <div id={timeoutHelpId} className="field-help">
          {MODEL_TEXT.timeoutHelp(range.min, range.max, range.fallback, timeoutHint)}
        </div>
        {shown("timeout") === undefined ? null : (
          <div className="field-error">{shown("timeout")}</div>
        )}
      </div>

      <ModelTestResult line={test.line} />
      <p className="muted small sys-footnote">{footnote}</p>
      <div className="sys-form-foot">
        <button type="button" className="btn" onClick={onCancel}>
          {MODEL_TEXT.btnCancel}
        </button>
        {test.testing ? (
          <button type="button" className="linkbtn" onClick={test.onCancelTest}>
            {MODEL_TEXT.btnCancelTest}
          </button>
        ) : null}
        <button
          type="button"
          className="btn"
          disabled={test.testing || test.cooldown > 0}
          onClick={test.onTest}
        >
          {test.testing
            ? MODEL_TEXT.btnTesting
            : test.cooldown > 0
              ? MODEL_TEXT.testCooldown(test.cooldown)
              : MODEL_TEXT.btnTest}
        </button>
        <button type="button" className="btn btn-primary" disabled={!canSave} onClick={onSave}>
          {MODEL_TEXT.btnSave}
        </button>
      </div>
    </div>
  );
}
