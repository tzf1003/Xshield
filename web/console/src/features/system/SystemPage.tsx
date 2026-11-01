// The system page at /system (docs/06 6.4.11): four tabs, kept in the address (`?tab=`) so a link opens
// the same one. The gateway, storage and parameter tabs read GET /api/system (useSystem); the import tab
// needs nothing else. The page adds no polling of its own.

import { Tabs } from "antd";
import { useSearch } from "@tanstack/react-router";
import type { ReactNode } from "react";
import { useSystem } from "../../api/queries.ts";
import { useNowBucket, useSetSearch } from "../../app/scope.ts";
import type { SystemTab } from "../../app/search-schema.ts";
import { ErrorBar, Loading, PageHead } from "../../ui/Page.tsx";
import { EdgesTable } from "./EdgesTable.tsx";
import { ImportPanel } from "./ImportPanel.tsx";
import { ParamsPanel } from "./ParamsPanel.tsx";
import { StoragePanel } from "./StoragePanel.tsx";
import "./system.css";

const TABS: Array<{ key: SystemTab; label: string }> = [
  { key: "edges", label: "网关" },
  { key: "storage", label: "日志存储" },
  { key: "params", label: "运行参数" },
  { key: "import", label: "导入" },
];

export function SystemPage() {
  const search = useSearch({ from: "/system" });
  const setSearch = useSetSearch();
  const tab: SystemTab = search.tab ?? "edges";
  const system = useSystem();
  const now = useNowBucket(5_000);
  const data = system.data;

  let body: ReactNode;
  if (tab === "import") {
    body = <ImportPanel />;
  } else if (system.isPending) {
    body = <Loading height={160} />;
  } else if (!data) {
    body = <ErrorBar error={system.error} onRetry={() => void system.refetch()} />;
  } else if (tab === "edges") {
    body = <EdgesTable edges={data.edges} now={now} />;
  } else if (tab === "storage") {
    body = <StoragePanel system={data} now={now} />;
  } else {
    body = <ParamsPanel system={data} />;
  }

  return (
    <>
      <PageHead
        title="系统"
        sub={data ? `控制面 ${data.control_build} · PostgreSQL ${data.postgres}` : "正在读取"}
      />
      <div className="tabs-wrap">
        <Tabs
          activeKey={tab}
          onChange={(key) => setSearch({ tab: key })}
          items={TABS.map((item) => ({ key: item.key, label: item.label }))}
        />
      </div>
      {body}
    </>
  );
}
