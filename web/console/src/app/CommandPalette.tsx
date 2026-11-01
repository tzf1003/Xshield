// The command palette (docs/06 6.3.3). What is typed or pasted decides the list (palette.ts); the
// empty palette lists what was opened last. Enter opens the first or selected item, Cmd/Ctrl+Enter
// opens it in a new tab.

import { Modal } from "antd";
import { useEffect, useMemo, useRef, useState } from "react";
import { useSites } from "../api/queries.ts";
import { type PaletteGroup, type PaletteItem, classifyInput } from "../lib/palette.ts";
import { readRecent } from "./recent.ts";
import { hrefFor } from "./href.ts";
import { writeText } from "../lib/storage.ts";
import { useNavigate } from "@tanstack/react-router";
import { useTheme } from "../theme/ThemeProvider.tsx";
import type { ThemePreference } from "../theme/tokens.ts";

/** Where pasted text waits for the batch dialog that opens with `?batch=1`. */
export const BATCH_TEXT_KEY = "xshield.console.batch";

const RECENT_PATH = { request: "/requests/", session: "/sessions/", site: "/sites/" } as const;

function recentGroups(): PaletteGroup[] {
  const items = readRecent().map<PaletteItem>((entry) => ({
    id: `recent:${entry.kind}:${entry.id}`,
    label: entry.title,
    sub: entry.kind === "request" ? "请求" : entry.kind === "session" ? "会话" : "站点",
    action: { kind: "route", to: `${RECENT_PATH[entry.kind]}${entry.id}` },
  }));
  return items.length > 0 ? [{ title: "最近打开", items }] : [];
}

function nextPreference(current: ThemePreference): ThemePreference {
  if (current === "system") return "light";
  if (current === "light") return "dark";
  return "system";
}

type Props = {
  open: boolean;
  onClose: () => void;
  onHelp: () => void;
};

export function CommandPalette({ open, onClose, onHelp }: Props) {
  const navigate = useNavigate();
  const theme = useTheme();
  const sites = useSites();
  const [text, setText] = useState("");
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const siteNames = useMemo(() => (sites.data?.sites ?? []).map((site) => site.name), [sites.data]);

  const groups = useMemo<PaletteGroup[]>(
    () => (text.trim().length > 0 ? classifyInput(text, siteNames) : recentGroups()),
    [text, siteNames],
  );
  const items = groups.flatMap((group) => group.items);

  useEffect(() => {
    if (!open) return undefined;
    setText("");
    setActive(0);
    const timer = window.setTimeout(() => inputRef.current?.focus(), 0);
    return () => window.clearTimeout(timer);
  }, [open]);

  const run = (item: PaletteItem, newTab: boolean) => {
    if (item.disabled) return;
    const action = item.action;
    onClose();
    if (action.kind === "command") {
      if (action.command === "theme") theme.setPreference(nextPreference(theme.preference));
      if (action.command === "copy-link") void navigator.clipboard?.writeText(window.location.href);
      if (action.command === "help") onHelp();
      return;
    }
    if (item.id === "batch") writeText(BATCH_TEXT_KEY, text, "session");
    const href = hrefFor(action.to, action.search ?? {});
    if (newTab) window.open(href, "_blank", "noopener");
    else void navigate({ href });
  };

  const onKeyDown = (event: React.KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setActive((index) => Math.min(index + 1, Math.max(items.length - 1, 0)));
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setActive((index) => Math.max(index - 1, 0));
    } else if (event.key === "Enter") {
      const item = items[active];
      if (item) {
        event.preventDefault();
        run(item, event.metaKey || event.ctrlKey);
      }
    }
  };

  let flatIndex = -1;
  return (
    <Modal open={open} onCancel={onClose} footer={null} closable={false} width={640} title={null}>
      <div className="palette">
        <div className="palette-input">
          <input
            ref={inputRef}
            value={text}
            onChange={(event) => {
              setText(event.target.value);
              setActive(0);
            }}
            onKeyDown={onKeyDown}
            placeholder="粘贴请求 ID、会话标签、路径、站点名，或输入 outcome:blocked 这类条件"
            aria-label="命令面板"
            aria-controls="palette-list"
            aria-activedescendant={items[active] ? `palette-${items[active].id}` : undefined}
            role="combobox"
            aria-expanded="true"
            aria-autocomplete="list"
          />
        </div>
        <div className="palette-list" id="palette-list" role="listbox">
          {groups.length === 0 ? (
            <div className="empty small">
              {text.trim().length === 0 ? "还没有打开过请求、会话或站点。" : "没有匹配的结果。"}
            </div>
          ) : null}
          {groups.map((group) => (
            <div key={group.title} role="group" aria-label={group.title}>
              <div className="palette-group">{group.title}</div>
              {group.items.map((item) => {
                flatIndex += 1;
                const index = flatIndex;
                return (
                  <button
                    type="button"
                    key={item.id}
                    id={`palette-${item.id}`}
                    role="option"
                    aria-selected={index === active}
                    aria-disabled={item.disabled !== undefined}
                    disabled={item.disabled !== undefined}
                    className="palette-item"
                    title={item.disabled}
                    onMouseEnter={() => setActive(index)}
                    onClick={(event) => run(item, event.metaKey || event.ctrlKey)}
                  >
                    <span>{item.label}</span>
                    {item.sub ? <span className="sub">{item.sub}</span> : null}
                  </button>
                );
              })}
            </div>
          ))}
        </div>
        <div className="palette-foot">
          <span>↑ ↓ 选择</span>
          <span>⏎ 打开</span>
          <span>⌘ ⏎ 新标签页</span>
          <span>Esc 关闭</span>
        </div>
      </div>
    </Modal>
  );
}
