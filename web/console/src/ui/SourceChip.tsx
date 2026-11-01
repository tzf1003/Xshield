// A value's source: the request whose response showed the value under a field name (docs/06 6.4.4).
// Sources learned before a restart carry no id, and sources past retention are missing from the
// detail's summaries; both say so instead of linking. With `copyable`, a copy button for the request
// id sits beside the chip.

import { Link } from "@tanstack/react-router";
import type { RequestId, SourceSummary, TraceSource } from "../api/types.ts";
import { keepScope } from "../app/scope.ts";
import { isRequestId, shortRequestId } from "../lib/ids.ts";
import { DECISION_INFO } from "../lib/vocab.ts";
import { CopyButton } from "./RequestRef.tsx";
import { SafeText } from "./SafeText.tsx";

export function SourceChip({
  source,
  sources,
  copyable = false,
}: {
  source: TraceSource;
  sources?: Record<RequestId, SourceSummary>;
  copyable?: boolean;
}) {
  const label = (
    <>
      <SafeText text={source.field} /> · <SafeText text={source.request} />
    </>
  );
  const id =
    source.request_id !== null && isRequestId(source.request_id) ? source.request_id : null;

  const chip = (() => {
    if (id === null) {
      return (
        <span className="srcchip" title="这条来源没有记录请求 ID">
          {label}
        </span>
      );
    }
    const summary = sources?.[id];
    if (sources !== undefined && summary === undefined) {
      return (
        <span className="srcchip dim" title="来源请求已过保留期">
          {label} · 已过保留期
        </span>
      );
    }
    const title = summary
      ? `${summary.method} ${summary.path} · ${DECISION_INFO[summary.decision_path].name}`
      : id;
    return (
      <Link
        to="/requests/$requestId"
        params={{ requestId: id }}
        search={keepScope}
        className="srcchip"
        title={title}
      >
        {label}
        <span className="dim"> {shortRequestId(id)}</span>
      </Link>
    );
  })();

  if (!copyable || id === null) return chip;
  return (
    <span className="rd-srcwrap">
      {chip}
      <CopyButton text={id} label="复制 ID" />
    </span>
  );
}
