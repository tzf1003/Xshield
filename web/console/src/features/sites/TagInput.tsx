// A list of short words shown as removable tags, with a box to add one (docs/06 6.4.9: Host, and the extra
// secret words). Built-in words are shown locked and cannot be removed.

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
  lockedTitle?: string;
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
  lockedTitle = "内置词，不能删除",
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
      <div className="taglist" aria-label={label}>
        {locked.map((word) => (
          <span key={`locked-${word}`} className="tag-chip builtin" title={lockedTitle}>
            <span aria-hidden="true">🔒</span>
            {word}
          </span>
        ))}
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
      </div>
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
