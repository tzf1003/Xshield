// The key field of a model form (design agent-model-ui 2.3). The key is write-only: the field shows dots, and the
// text is visible only while the eye button is held. A paste keeps the text but drops blanks at its ends; a blank
// inside the key is an error the form names. The value lives in the form's state and nowhere else.

import type { ClipboardEvent, KeyboardEvent } from "react";
import { useState } from "react";
import { MODEL_TEXT } from "../../lib/vocab.ts";

type Props = {
  id: string;
  value: string;
  onChange: (value: string) => void;
  onBlur?: () => void;
  error?: string;
  helpId?: string;
  /** The id of the visible label, so the field has an accessible name. */
  labelledBy?: string;
};

export function SecretField({ id, value, onChange, onBlur, error, helpId, labelledBy }: Props) {
  const [reveal, setReveal] = useState(false);
  const errorId = `${id}-error`;
  const describedBy = [helpId, error === undefined ? undefined : errorId]
    .filter((item): item is string => item !== undefined)
    .join(" ");

  const paste = (event: ClipboardEvent<HTMLInputElement>) => {
    const text = event.clipboardData.getData("text");
    if (text.length === 0) return;
    event.preventDefault();
    const input = event.currentTarget;
    const start = input.selectionStart ?? value.length;
    const end = input.selectionEnd ?? value.length;
    onChange(`${value.slice(0, start)}${text.trim()}${value.slice(end)}`);
  };

  const holdKey = (event: KeyboardEvent<HTMLButtonElement>) => {
    if (event.key === " " || event.key === "Enter") setReveal(true);
  };
  const releaseKey = (event: KeyboardEvent<HTMLButtonElement>) => {
    if (event.key === " " || event.key === "Enter") setReveal(false);
  };

  return (
    <div className="sys-secret">
      <div className="sys-secret-row">
        <input
          id={id}
          className="native-input mono"
          type={reveal ? "text" : "password"}
          autoComplete="off"
          spellCheck={false}
          value={value}
          onChange={(event) => onChange(event.currentTarget.value)}
          onBlur={onBlur}
          onPaste={paste}
          aria-labelledby={labelledBy}
          aria-invalid={error === undefined ? undefined : true}
          aria-describedby={describedBy.length > 0 ? describedBy : undefined}
        />
        <button
          type="button"
          className="btn sys-eye"
          aria-label={MODEL_TEXT.revealKey}
          onPointerDown={() => setReveal(true)}
          onPointerUp={() => setReveal(false)}
          onPointerLeave={() => setReveal(false)}
          onPointerCancel={() => setReveal(false)}
          onKeyDown={holdKey}
          onKeyUp={releaseKey}
          onBlur={() => setReveal(false)}
        >
          <span aria-hidden="true">👁</span>
        </button>
      </div>
      {error === undefined ? null : (
        <div id={errorId} className="field-error">
          {error}
        </div>
      )}
    </div>
  );
}
