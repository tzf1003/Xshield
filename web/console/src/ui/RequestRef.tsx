// A request identifier wherever one appears: a short link to its record, with a copy button. Links
// are only built from identifiers that pass the format check (docs/07 7.10.6).

import { Link } from "@tanstack/react-router";
import { useState } from "react";
import { isRequestId, shortRequestId } from "../lib/ids.ts";
import { keepScope } from "../app/scope.ts";

export function CopyButton({ text, label = "复制" }: { text: string; label?: string }) {
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
    <button
      type="button"
      className="copy-btn"
      onClick={() => void copy()}
      aria-label={`${label} ${text}`}
    >
      {done ? "已复制" : label}
    </button>
  );
}

/** The short form of a request id that links to its record. Unknown formats render as plain text. */
export function RequestLink({ id, className = "reqid" }: { id: string; className?: string }) {
  if (!isRequestId(id)) return <span className={className}>{id}</span>;
  return (
    <Link
      to="/requests/$requestId"
      params={{ requestId: id }}
      search={keepScope}
      className={className}
      title={id}
    >
      {shortRequestId(id)}
    </Link>
  );
}
