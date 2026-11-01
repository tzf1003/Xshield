// Small pieces that the request detail tabs share: a request link that is built only from a valid id,
// a copy button for long text, a value's text with its redaction and clipping notes, the reading mark
// of a value, a gauge bar, and the short highlight that marks a value someone asked for.

import { Link } from "@tanstack/react-router";
import { type ReactNode, useEffect, useState } from "react";
import { keepScope } from "../../app/scope.ts";
import { fmtInt } from "../../lib/format.ts";
import { isRequestId } from "../../lib/ids.ts";
import { SafeText } from "../../ui/SafeText.tsx";
import { REDACTED, type Reading } from "./detail-model.ts";

/** A request as a link to its record; without a valid id the text stays plain (docs/07 7.10.6). */
export function LinkedRequest({
  id,
  className,
  children,
}: {
  id: string | null;
  className?: string;
  children: ReactNode;
}) {
  if (id === null || !isRequestId(id)) return <span className={className}>{children}</span>;
  return (
    <Link
      to="/requests/$requestId"
      params={{ requestId: id }}
      search={keepScope}
      className={className}
      title={id}
    >
      {children}
    </Link>
  );
}

/** A copy button whose accessible name is its own label, so a long text never becomes the name. */
export function CopyAction({
  text,
  label,
  className = "copy-btn",
}: {
  text: string;
  label: string;
  className?: string;
}) {
  const [done, setDone] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setDone(true);
      window.setTimeout(() => setDone(false), 1500);
    } catch {
      setDone(false);
    }
  };
  return (
    <button type="button" className={className} onClick={() => void copy()}>
      {done ? "已复制" : label}
    </button>
  );
}

/**
 * A value as text. A redacted value says so with its length and the redaction word in the title; a
 * clipped one says how long the original was (docs/06 6.4.4).
 */
export function ValueText({
  value,
  len,
  clipped = false,
  secret = null,
  query = "",
}: {
  value: string;
  len?: number | null;
  clipped?: boolean;
  secret?: string | null;
  query?: string;
}) {
  if (value === REDACTED) {
    return (
      <span className="redacted" title={secret ?? "已脱敏"}>
        {`🔒 已脱敏${len !== null && len !== undefined ? ` · ${fmtInt(len)} 字符` : ""}`}
      </span>
    );
  }
  return (
    <>
      <SafeText text={value} query={query} />
      {clipped ? (
        <span className="small dim">{` 已截断${len !== null && len !== undefined ? ` · 原长 ${fmtInt(len)}` : ""}`}</span>
      ) : null}
    </>
  );
}

/** The reading of a value: a neutral mark and its text, coloured by the tone (docs/06 6.5.3). */
export function HintMark({ reading }: { reading: Reading }) {
  return (
    <span className={`rd-hint hint-${reading.tone}`}>
      <span aria-hidden="true">{reading.mark}</span> {reading.text}
    </span>
  );
}

/** A thin bar for a ratio of 0 to 1; amber when the reading is near its limit. */
export function Gauge({
  ratio,
  warn = false,
  label,
}: {
  ratio: number;
  warn?: boolean;
  label: string;
}) {
  const clamped = Math.min(1, Math.max(0, Number.isFinite(ratio) ? ratio : 0));
  return (
    <div
      className={warn ? "bar-line rd-gauge rd-warn" : "bar-line rd-gauge"}
      role="img"
      aria-label={label}
      title={label}
    >
      <span style={{ width: `${clamped * 100}%` }} />
    </div>
  );
}

/** True for two seconds after `key` changes: the highlight of a value that was asked for (docs/06 6.4.5). */
export function useFlash(key: number | undefined): boolean {
  const [on, setOn] = useState(false);
  useEffect(() => {
    if (key === undefined) return undefined;
    setOn(true);
    const timer = window.setTimeout(() => setOn(false), 2000);
    return () => window.clearTimeout(timer);
  }, [key]);
  return on;
}

/** Pairs each item with a key that is unique within the list, without using the position as the key. */
export function keyed<T>(items: T[], idOf: (item: T) => string): Array<{ key: string; item: T }> {
  const seen = new Map<string, number>();
  return items.map((item) => {
    const base = idOf(item);
    const count = (seen.get(base) ?? 0) + 1;
    seen.set(base, count);
    return { key: `${base}#${count}`, item };
  });
}
