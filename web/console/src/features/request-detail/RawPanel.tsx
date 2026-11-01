// The raw record tab (docs/06 6.4.4): the whole record as a JSON tree, searchable, with a copy of the
// full text. The tree holds the summary, the trace and the Jev record, as the gateway stored them.

import { useState } from "react";
import type { RequestDetail } from "../../api/types.ts";
import { JsonTree } from "../../ui/JsonTree.tsx";
import { CopyAction } from "./parts.tsx";

export function RawPanel({ detail }: { detail: RequestDetail }) {
  const [query, setQuery] = useState("");
  const record = { summary: detail.summary, trace: detail.trace, jev: detail.jev };
  return (
    <div className="stack">
      <div className="row rd-viewtools">
        <input
          type="search"
          className="native-input rd-search"
          placeholder="在记录中搜索"
          aria-label="在记录中搜索"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
        <CopyAction text={JSON.stringify(record, null, 2)} label="复制 JSON" />
      </div>
      <JsonTree value={record} openDepth={2} query={query} />
    </div>
  );
}
