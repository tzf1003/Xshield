// The bell of the top bar (docs/06 6.3.2): the "需要处理" rows, each with the links it carries, in a dropdown
// that opens from every page. The badges count the rows. A serious or warning row is an alert: its count takes
// the tint of its level (red for 严重, amber for 警告) with that level's mark. A hint is counted apart, in the
// accent tint with the ringed i (docs/06 6.5.3), so a hint never reads as an alert.

import { Link } from "@tanstack/react-router";
import { Popover } from "antd";
import { type ReactNode, useEffect, useRef, useState } from "react";
import { fmtInt } from "../../lib/format.ts";
import { ErrorBar, Loading, Notice } from "../../ui/Page.tsx";
import { type Action, type AttentionItem, countsText, type Level } from "./attention.ts";
import { type NeedsAttention, useNeedsAttention } from "./attention-state.ts";
import { hms } from "./clock.ts";
import "./overview.css";

const LEVEL: Record<Level, { glyph: string; word: string; cls: string }> = {
  serious: { glyph: "■", word: "严重", cls: "lvl-serious" },
  warn: { glyph: "▲", word: "警告", cls: "lvl-warn" },
  // docs/06 6.5.3 reserves the filled dot for "正常"; the prototype marks a hint with a ringed i.
  info: { glyph: "i", word: "提示", cls: "lvl-info ov-mark-ring" },
};

function ActionLink({ action }: { action: Action }) {
  const { label, target } = action;
  switch (target.kind) {
    case "system":
      return (
        <Link className="btn ov-btn" to="/system" search={{ tab: target.tab }}>
          {label}
        </Link>
      );
    case "site":
      return (
        <Link
          className="btn ov-btn"
          to="/sites/$name"
          params={{ name: target.name }}
          search={{ tab: target.tab, group: target.group }}
        >
          {label}
        </Link>
      );
    case "requests":
      return (
        <Link className="btn ov-btn" to="/requests" search={target.search}>
          {label}
        </Link>
      );
    case "jev":
      return (
        <Link className="btn ov-btn" to="/jev">
          {label}
        </Link>
      );
  }
}

function AttentionRow({ item }: { item: AttentionItem }) {
  const level = LEVEL[item.level];
  return (
    <li className="attn-row ov-attn-row">
      <span className="ov-level">
        {/* The status colour goes on the mark only; the word stays in ink (docs/06 6.5.3). */}
        <span aria-hidden="true" className={level.cls}>
          {level.glyph}
        </span>{" "}
        {level.word}
      </span>
      <span className="text">{item.text}</span>
      {item.actions.length > 0 ? (
        <span className="ov-actions">
          {item.actions.map((action) => (
            <ActionLink key={action.label} action={action} />
          ))}
        </span>
      ) : null}
    </li>
  );
}

/** What the list says in place of its count while its rows are not settled yet; null once they are. */
function pendingWord(attention: NeedsAttention): string | null {
  if (attention.loading) return "正在读取";
  if (attention.failed) return "读取失败";
  if (attention.items.length === 0 && attention.checking) return "正在读取";
  return null;
}

function PanelBody({ attention }: { attention: NeedsAttention }) {
  if (attention.loading) return <Loading height={44} />;
  if (attention.failed) {
    return <ErrorBar error={attention.error} onRetry={attention.retryStatus} />;
  }
  if (attention.items.length > 0) {
    return (
      <ul className="attn ov-attn" aria-label="需要处理">
        {attention.items.map((item) => (
          <AttentionRow key={item.key} item={item} />
        ))}
      </ul>
    );
  }
  if (attention.checking) return <Loading height={44} />;
  // A failed read is said above, and the panel does not claim all is well over it.
  if (attention.notices.length > 0) return null;
  return (
    <div className="all-good ov-all-good">
      <span aria-hidden="true" className="ov-ok-mark">
        ●
      </span>{" "}
      一切正常 <span className="small muted">· 最后检查 {hms(attention.lastCheck)}</span>
    </div>
  );
}

/**
 * The dropdown's body. It takes focus when it opens, so the keyboard reaches its links. Escape dismisses it and
 * gives focus back to the bell. A click on a link closes it, because the page the link opens is what the user wants.
 */
function AttentionPanel({ onDismiss, onFollow }: { onDismiss: () => void; onFollow: () => void }) {
  const attention = useNeedsAttention();
  const panel = useRef<HTMLDivElement>(null);
  useEffect(() => {
    panel.current?.focus({ preventScroll: true });
  }, []);

  const pending = pendingWord(attention);
  let notices: ReactNode = null;
  if (attention.notices.length > 0) {
    notices = attention.notices.map((notice) => (
      <Notice key={notice.key} tone="warn">
        {notice.text}
        <button type="button" className="linkbtn" onClick={notice.retry}>
          重试
        </button>
      </Notice>
    ));
  }

  return (
    <section
      ref={panel}
      aria-label="需要处理"
      tabIndex={-1}
      className="ov-attn-panel"
      onKeyDown={(event) => {
        if (event.key !== "Escape") return;
        event.stopPropagation();
        onDismiss();
      }}
      onClick={(event) => {
        if (event.target instanceof Element && event.target.closest("a") !== null) onFollow();
      }}
    >
      <div className="ov-attn-head">
        需要处理
        <span className="small muted">{pending ?? countsText(attention.counts)}</span>
      </div>
      {notices}
      <PanelBody attention={attention} />
    </section>
  );
}

/** The bell drawn in the console's stroke style, so it takes the text colour of either theme. */
function BellIcon() {
  return (
    <svg
      width="16"
      height="16"
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      <path d="M4 6.5a4 4 0 0 1 8 0c0 3 1 4 1.5 4.5h-11C3 10.5 4 9.5 4 6.5Z" />
      <path d="M6.5 13.5a1.5 1.5 0 0 0 3 0" />
    </svg>
  );
}

export function AttentionBell() {
  const attention = useNeedsAttention();
  const [open, setOpen] = useState(false);
  const bell = useRef<HTMLButtonElement>(null);
  const { alert, hint, serious } = attention.counts;
  const pending = pendingWord(attention);

  const dismiss = () => {
    setOpen(false);
    bell.current?.focus();
  };

  return (
    <Popover
      open={open}
      onOpenChange={setOpen}
      trigger="click"
      placement="bottomRight"
      arrow={false}
      destroyOnHidden
      content={<AttentionPanel onDismiss={dismiss} onFollow={() => setOpen(false)} />}
    >
      <button
        ref={bell}
        type="button"
        className="ov-bell"
        aria-label={`需要处理（${pending ?? countsText(attention.counts)}）`}
        aria-expanded={open}
      >
        <BellIcon />
        {alert > 0 ? (
          <span
            aria-hidden="true"
            className={`ov-bell-count ${serious ? "ov-bell-serious" : "ov-bell-warn"}`}
          >
            <span className={serious ? "lvl-serious" : "lvl-warn"}>{serious ? "■" : "▲"}</span>
            {fmtInt(alert)}
          </span>
        ) : null}
        {hint > 0 ? (
          <span aria-hidden="true" className="ov-bell-count ov-bell-hint">
            <span className="lvl-info ov-mark-ring">i</span>
            {fmtInt(hint)}
          </span>
        ) : null}
      </button>
    </Popover>
  );
}
