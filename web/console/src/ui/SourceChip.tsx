// A value's source: the request whose response showed the value under a field name (docs/06 6.4.4).
// Sources learned before a restart carry no id, and sources past retention are missing from the
// detail's summaries; both say so instead of linking.

import { Link } from "@tanstack/react-router";
import type { RequestId, SourceSummary, TraceSource } from "../api/types.ts";
import { keepScope } from "../app/scope.ts";
import { isRequestId, shortRequestId } from "../lib/ids.ts";
import { DECISION_INFO } from "../lib/vocab.ts";

export function SourceChip({
  source,
  sources,
}: {
  source: TraceSource;
  sources?: Record<RequestId, SourceSummary>;
}) {
  const label = `${source.field} · ${source.request}`;
  if (source.request_id === null || !isRequestId(source.request_id)) {
    return (
      <span className="srcchip" title="来源请求在网关重启前，未记录 ID">
        {label}
      </span>
    );
  }
  const summary = sources?.[source.request_id];
  if (sources !== undefined && summary === undefined) {
    return (
      <span className="srcchip dim" title="来源请求已过保留期">
        {label} · 已过保留期
      </span>
    );
  }
  const title = summary
    ? `${summary.method} ${summary.path} · ${DECISION_INFO[summary.decision_path].name}`
    : source.request_id;
  return (
    <Link
      to="/requests/$requestId"
      params={{ requestId: source.request_id }}
      search={keepScope}
      className="srcchip"
      title={title}
    >
      {label}
      <span className="dim"> {shortRequestId(source.request_id)}</span>
    </Link>
  );
}
