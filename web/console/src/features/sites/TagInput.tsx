// A list of short words shown as removable tags, with a box to add one (docs/06 6.4.9: Host, and the extra
// secret words). Built-in words are shown as dashed tags with no remove control, under their own label.

import { useState } from "react";

type Props = {
  id: string;
  label: string;
  values: string[];
  onChange: (values: string[]) => void;
  /** Returns the reason a new word is refused, or null when it is accepted. */
  check: (value: string) => string | null;
  max: number;
  placeholder: string;
  locked?: string[];
  /** A small label before the built-in words, e.g. 内置. */
  lockedLabel?: string;
  lockedTitle?: string;
  /** A small label before the words the site adds, e.g. 本站点. */
  ownLabel?: string;
  error?: string | null;
  warning?: string | null;
};

export function TagInput({
  id,
  label,
  values,
  onChange,
  check,
  max,
  placeholder,
  locked = [],
  lockedLabel,
  lockedTitle = "内置词，不能删除",
  ownLabel,
  error = null,
  warning = null,
}: Props) {
  const [text, setText] = useState("");
  const [problem, setProblem] = useState<string | null>(null);

  const add = () => {
    const raw = text.trim();
    if (raw.length === 0) return;
    if (values.includes(raw) || locked.includes(raw)) {
      setProblem("已经在列表里");
      return;
    }
    if (values.length >= max) {
      setProblem(`最多 ${max} 个`);
      return;
    }
    const refused = check(raw);
    if (refused) {
      setProblem(refused);
      return;
    }
    onChange([...values, raw]);
    setText("");
    setProblem(null);
  };

  const shown = problem ?? error;
  return (
    <div className="stack-tight">
      <fieldset
        className="taglist"
        aria-label={label}
        style={{ border: 0, margin: 0, padding: 0, minWidth: 0 }}
      >
        {locked.length > 0 && lockedLabel ? (
          <span className="small muted">{lockedLabel}</span>
        ) : null}
        {locked.map((word) => (
          <span
            key={`locked-${word}`}
            className="tag-chip builtin builtin-chip"
            title={lockedTitle}
          >
            {word}
          </span>
        ))}
        {ownLabel ? <span className="small muted">{ownLabel}</span> : null}
        {values.map((value) => (
          <span key={value} className="tag-chip">
            {value}
            <button
              type="button"
              className="iconbtn"
              aria-label={`删除 ${value}`}
              onClick={() => onChange(values.filter((item) => item !== value))}
            >
              ×
            </button>
          </span>
        ))}
      </fieldset>
      <input
        id={id}
        className="native-input mono"
        value={text}
        placeholder={placeholder}
        aria-label={`添加${label}`}
        aria-invalid={shown ? true : undefined}
        onChange={(event) => {
          setText(event.target.value);
          setProblem(null);
        }}
        onKeyDown={(event) => {
          if (event.key === "Enter" || event.key === ",") {
            event.preventDefault();
            add();
          }
        }}
        onBlur={add}
      />
      {shown ? (
        <div className="field-error" role="alert">
          {shown}
        </div>
      ) : null}
      {warning ? <div className="field-warn">▲ {warning}</div> : null}
    </div>
  );
}
