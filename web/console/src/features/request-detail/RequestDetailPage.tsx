// The request detail page (docs/06 6.4.4, 6.4.5, 6.7.2): the head with the verdict, the five tabs of the
// record, the related rail, and the quick rule dialog that the rail's operations open. The record view
// is keyed by request ID, so every neighbour starts with its own tab state and no stale highlight.

import { Link, useNavigate, useParams, useSearch } from "@tanstack/react-router";
import { Tabs } from "antd";
import { useEffect, useState } from "react";
import { ApiError } from "../../api/client.ts";
import { useRequestDetail, useStatus } from "../../api/queries.ts";
import type { RequestDetail } from "../../api/types.ts";
import { keepScope, useNowBucket, useSetSearch } from "../../app/scope.ts";
import { type KeyHandler, isTypingTarget, useKeys } from "../../app/keys.ts";
import { pushRecent } from "../../app/recent.ts";
import {
  DETAIL_TABS,
  type DetailSearch,
  type DetailTab,
  type JevDoc,
  JEV_VIEWS,
  type JevView,
} from "../../app/search-schema.ts";
import { isRequestId } from "../../lib/ids.ts";
import { ErrorBar, Loading } from "../../ui/Page.tsx";
import { SafeText } from "../../ui/SafeText.tsx";
import { type QuickTarget, QuickRuleDialog } from "../sites/QuickRuleDialog.tsx";
import { DetailHead, neighborSearch } from "./DetailHead.tsx";
import { logGaps, missingReason } from "./detail-model.ts";
import { JevInspector } from "./JevInspector.tsx";
import { Pipeline } from "./Pipeline.tsx";
import { RawPanel } from "./RawPanel.tsx";
import { RelatedRail } from "./RelatedRail.tsx";
import { SessionTab } from "./SessionPanel.tsx";
import { ValuesTable } from "./ValuesTable.tsx";
import "./request-detail.css";

const TAB_LABELS: Record<DetailTab, string> = {
  pipeline: "判定过程",
  values: "请求值",
  jev: "Jev 上下文",
  session: "会话上下文",
  raw: "原始记录",
};

export function RequestDetailPage() {
  const { requestId } = useParams({ from: "/requests/$requestId" });
  const search = useSearch({ from: "/requests/$requestId" });
  const valid = isRequestId(requestId);
  const detail = useRequestDetail(valid ? requestId : null);

  if (!valid) return <NotFound requestId={requestId} />;
  if (detail.isPending) return <Loading height={160} />;
  if (detail.isError) {
    if (detail.error instanceof ApiError && detail.error.status === 404)
      return <NotFound requestId={requestId} />;
    return <ErrorBar error={detail.error} onRetry={() => void detail.refetch()} />;
  }
  return <DetailView key={requestId} requestId={requestId} detail={detail.data} search={search} />;
}

function DetailView({
  requestId,
  detail,
  search,
}: {
  requestId: string;
  detail: RequestDetail;
  search: DetailSearch;
}) {
  const navigate = useNavigate();
  const setSearch = useSetSearch();
  const [quick, setQuick] = useState<QuickTarget | null>(null);
  const tab: DetailTab = search.tab ?? "pipeline";
  const view: JevView = search.jev_view ?? "structured";
  const doc: JevDoc = search.jev_doc ?? "state";
  const { neighbors, jev, summary } = detail;

  // The palette's empty state lists what was opened last (docs/06 6.3.3).
  useEffect(() => {
    pushRecent({
      kind: "request",
      id: summary.request_id,
      title: `${summary.method} ${summary.path}`,
    });
  }, [summary.request_id, summary.method, summary.path]);

  const openNeighbour = (target: string) => {
    void navigate({
      to: "/requests/$requestId",
      params: { requestId: target },
      search: neighborSearch,
    });
  };

  const bindings: Record<string, KeyHandler> = {
    "1": () => setSearch({ tab: "pipeline" }),
    "2": () => setSearch({ tab: "values" }),
    "3": () => setSearch({ tab: "jev" }),
    "4": () => setSearch({ tab: "session" }),
    "5": () => setSearch({ tab: "raw" }),
    "[": () => {
      if (neighbors.prev !== null && isRequestId(neighbors.prev)) openNeighbour(neighbors.prev);
    },
    "]": () => {
      if (neighbors.next !== null && isRequestId(neighbors.next)) openNeighbour(neighbors.next);
    },
    c: () => {
      void navigator.clipboard.writeText(requestId).catch(() => undefined);
    },
    v: () => {
      if (tab === "jev") setSearch({ jev_view: nextView(view) });
    },
    Escape: () => {
      if (!isTypingTarget(document.activeElement))
        void navigate({ to: "/requests", search: keepScope });
    },
  };
  useKeys(bindings, quick === null);

  const items = DETAIL_TABS.map((key) => ({
    key,
    label: key === "jev" && jev === null ? `${TAB_LABELS.jev}（未调用）` : TAB_LABELS[key],
    children:
      key === tab ? (
        <TabPanel
          tab={key}
          detail={detail}
          requestId={requestId}
          hl={search.hl}
          view={view}
          doc={doc}
        />
      ) : null,
  }));

  return (
    <div className="rd-page">
      <DetailHead detail={detail} requestId={requestId} />
      <div className="rd-main">
        <div className="rd-tabs">
          <Tabs activeKey={tab} onChange={(key) => setSearch({ tab: key })} items={items} />
        </div>
        <aside className="rd-rail" aria-label="相关">
          <RelatedRail detail={detail} requestId={requestId} onOperation={setQuick} />
        </aside>
      </div>
      <QuickRuleDialog target={quick} onClose={() => setQuick(null)} />
    </div>
  );
}

function TabPanel({
  tab,
  detail,
  requestId,
  hl,
  view,
  doc,
}: {
  tab: DetailTab;
  detail: RequestDetail;
  requestId: string;
  hl: number | undefined;
  view: JevView;
  doc: JevDoc;
}) {
  switch (tab) {
    case "pipeline":
      return <Pipeline detail={detail} />;
    case "values":
      return <ValuesTable detail={detail} hl={hl} />;
    case "jev":
      return <JevInspector detail={detail} requestId={requestId} view={view} doc={doc} hl={hl} />;
    case "session":
      return <SessionTab detail={detail} requestId={requestId} />;
    case "raw":
      return <RawPanel detail={detail} />;
  }
}

/** The next Jev view in the cycle that the `v` key walks. */
function nextView(view: JevView): JevView {
  const index = JEV_VIEWS.indexOf(view);
  return JEV_VIEWS[(index + 1) % JEV_VIEWS.length] ?? "structured";
}

/** A request that the gateway does not hold: the reason comes from the time inside its ID (docs/06 6.7.2). */
function NotFound({ requestId }: { requestId: string }) {
  const now = useNowBucket();
  const status = useStatus();
  const gaps = logGaps(status.data?.gateway.problems ?? []);
  return (
    <div className="rd-notfound">
      <div className="empty">
        <h1 className="empty-title">找不到这个请求</h1>
        <div className="mono small">
          <SafeText text={requestId} />
        </div>
        <div className="small">{missingReason(requestId, now, gaps)}</div>
      </div>
      <div className="row">
        <Link to="/requests" search={keepScope}>
          返回请求追溯
        </Link>
        <Link to="/system">查看网关状态</Link>
      </div>
    </div>
  );
}
