// Keyboard handling (docs/06 6.3.4). Bindings are plain key names: `j`, `Escape`, `[`, or `Mod+k` for
// Cmd on macOS and Ctrl elsewhere. While the focus is in a text field only Escape and Mod combinations
// reach a binding, so typing never triggers a shortcut.

import { useEffect, useRef } from "react";

export type KeyHandler = (event: KeyboardEvent) => void;

/** True when the event target takes text, so single keys must not act as shortcuts. */
export function isTypingTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  if (target.isContentEditable || target.closest(".cm-editor")) return true;
  return target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.tagName === "SELECT";
}

function matches(spec: string, event: KeyboardEvent): boolean {
  if (spec.startsWith("Mod+")) {
    const key = spec.slice(4).toLowerCase();
    return (event.metaKey || event.ctrlKey) && !event.altKey && event.key.toLowerCase() === key;
  }
  if (event.metaKey || event.ctrlKey || event.altKey) return false;
  return event.key === spec;
}

/** Binds keys on the window while `enabled` is true. The latest handlers are always used. */
export function useKeys(bindings: Record<string, KeyHandler>, enabled = true): void {
  const latest = useRef(bindings);
  useEffect(() => {
    latest.current = bindings;
  });
  useEffect(() => {
    if (!enabled) return undefined;
    const onKey = (event: KeyboardEvent) => {
      const typing = isTypingTarget(event.target);
      for (const [spec, handler] of Object.entries(latest.current)) {
        if (!matches(spec, event)) continue;
        const allowed = spec === "Escape" || spec.startsWith("Mod+");
        if (typing && !allowed) continue;
        handler(event);
        return;
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [enabled]);
}
