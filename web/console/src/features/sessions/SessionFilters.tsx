// The filter line of the session list (docs/06 6.4.7): three quick chips (全部, 有拦截, 有 Jev 调用) that
// the server applies, and a label prefix that filters the rows already loaded. Both live in the URL.
// Typing keeps a local draft and writes the URL after a short pause, so a router round-trip never
// overwrites a keystroke.

import { useEffect, useRef, useState } from "react";
import { normalisePrefix } from "./sessions-model.ts";

const PREFIX_DELAY_MS = 250;

export type SessionFlag = "blocked" | "jev";

const FLAGS: ReadonlyArray<{ value: SessionFlag | undefined; label: string }> = [
  { value: undefined, label: "全部" },
  { value: "blocked", label: "有拦截" },
  { value: "jev", label: "有 Jev 调用" },
];

type Props = {
  flag: SessionFlag | undefined;
  /** The prefix as the URL holds it. */
  q: string;
  onFlag: (flag: SessionFlag | undefined) => void;
  onQ: (text: string) => void;
};

export function SessionFilters({ flag, q, onFlag, onQ }: Props) {
  const [draft, setDraft] = useState(q);
  const committed = useRef(q);

  // The URL changed from outside (back button, a copied link): show what it holds.
  useEffect(() => {
    if (q !== committed.current) {
      committed.current = q;
      setDraft(q);
    }
  }, [q]);

  // Write the typed prefix once typing pauses; the URL is replaced, not pushed, so Back still works.
  useEffect(() => {
    const timer = window.setTimeout(() => {
      const next = draft.trim();
      if (next === committed.current) return;
      committed.current = next;
      onQ(next);
    }, PREFIX_DELAY_MS);
    return () => window.clearTimeout(timer);
  }, [draft, onQ]);

  const { valid } = normalisePrefix(draft);

  return (
    <div className="session-filters">
      <fieldset className="chips session-chips">
        <legend className="sr-only">快捷筛选</legend>
        {FLAGS.map((item) => (
          <button
            type="button"
            key={item.label}
            className="chip"
            aria-pressed={flag === item.value}
            onClick={() => onFlag(item.value)}
          >
            {item.label}
          </button>
        ))}
      </fieldset>
      <div className="session-prefix">
        <label className="session-prefix-field">
          <span className="ico dim" aria-hidden="true">
            ⌕
          </span>
          <input
            data-filter
            className="native-input session-prefix-input"
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Escape") setDraft(committed.current);
            }}
            placeholder="按标签前缀搜索，例如 7c1e"
            aria-label="按会话标签前缀搜索"
            aria-invalid={!valid}
            aria-describedby={valid ? undefined : "session-prefix-hint"}
          />
        </label>
        {valid ? null : (
          <span id="session-prefix-hint" className="small hint-warn">
            会话标签只含 0–9 和 a–f
          </span>
        )}
      </div>
    </div>
  );
}
