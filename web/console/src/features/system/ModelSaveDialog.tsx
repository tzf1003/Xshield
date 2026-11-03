// The save dialog of a model (design agent-model-ui 2.5): what changes, what it reaches, whether the configuration
// tested successfully, and a note. A configuration that did not test is saved only after the person says so, and
// the save records that. A stale version (409) shows the version now in use and offers a reload.

import { Modal } from "antd";
import { useId, useState } from "react";
import { type ChangeRow, NOTE_MAX } from "../../lib/model-form.ts";
import { MODEL_TEXT } from "../../lib/vocab.ts";
import { Notice } from "../../ui/Page.tsx";

export type ModelSaveDialogProps = {
  title: string;
  defaultNote: string;
  changes: ChangeRow[];
  /** One line per reach of the save, e.g. how many sites load the new configuration. */
  impact: string[];
  /** Sites that refuse requests when Jev fails after this save (design 2.5). */
  failClosed: string[];
  tested: boolean;
  /** The line for a configuration that tested successfully, shown in place of the warning. */
  testedLine: string | null;
  saving: boolean;
  /** The version in use now, after a 409: the save is blocked until the form is reloaded. */
  conflict: number | null;
  error: string | null;
  saveLabel: string;
  onSave: (note: string) => void;
  onClose: () => void;
  onReload: () => void;
};

export function ModelSaveDialog(props: ModelSaveDialogProps) {
  const base = useId();
  const [note, setNote] = useState(props.defaultNote);
  const [acknowledged, setAcknowledged] = useState(false);
  const blocked = !props.tested && !acknowledged;

  return (
    <Modal
      open
      title={props.title}
      onCancel={props.onClose}
      footer={null}
      width={560}
      destroyOnHidden
    >
      {props.conflict === null ? null : (
        <Notice tone="warn">
          <div>{MODEL_TEXT.conflict(props.conflict)}</div>
          <button type="button" className="btn" onClick={props.onReload}>
            {MODEL_TEXT.btnReload}
          </button>
        </Notice>
      )}
      {props.error === null ? null : <Notice tone="bad">{props.error}</Notice>}

      <section className="sys-dialog-section">
        <h3 className="sys-h">{MODEL_TEXT.sectionChanges}</h3>
        {props.changes.length === 0 ? (
          <p className="muted small">{MODEL_TEXT.noChanges}</p>
        ) : (
          <div className="changes">
            {props.changes.map((row) => (
              <div key={`${row.label}-${row.detail}`} className="sys-change">
                <span className="muted">{row.label}</span> {row.detail}
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="sys-dialog-section">
        <h3 className="sys-h">{MODEL_TEXT.sectionImpact}</h3>
        <div className="impact">
          {props.impact.map((line) => (
            <div key={line}>{line}</div>
          ))}
          {props.failClosed.length === 0 ? null : (
            <div className="hint-warn">{MODEL_TEXT.impactFailClosed(props.failClosed)}</div>
          )}
        </div>
      </section>

      <section className="sys-dialog-section">
        <h3 className="sys-h">{MODEL_TEXT.sectionTest}</h3>
        {props.tested ? (
          <div className="hint-ok">{props.testedLine}</div>
        ) : (
          <>
            <div className="hint-warn">{MODEL_TEXT.testedMissing}</div>
            <label className="check sys-ack">
              <input
                type="checkbox"
                checked={acknowledged}
                onChange={(event) => setAcknowledged(event.currentTarget.checked)}
              />{" "}
              {MODEL_TEXT.ackUntested}
            </label>
            {props.failClosed.length === 0 ? null : (
              <div className="field-warn">{MODEL_TEXT.failClosedSave}</div>
            )}
          </>
        )}
      </section>

      <label className="field" htmlFor={`${base}-note`}>
        <span className="field-label">{MODEL_TEXT.noteLabel}</span>
        <input
          id={`${base}-note`}
          className="native-input"
          maxLength={NOTE_MAX}
          value={note}
          placeholder={MODEL_TEXT.notePlaceholder}
          onChange={(event) => setNote(event.currentTarget.value)}
        />
      </label>

      <div className="sys-dialog-foot">
        <button type="button" className="btn" onClick={props.onClose}>
          {MODEL_TEXT.btnCancel}
        </button>
        <button
          type="button"
          className="btn btn-primary"
          disabled={blocked || props.saving || props.conflict !== null}
          onClick={() => props.onSave(note.trim())}
        >
          {props.saving ? MODEL_TEXT.savingNow : props.saveLabel}
        </button>
      </div>
    </Modal>
  );
}
