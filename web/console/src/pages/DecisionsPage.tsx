import { Alert, Button, DatePicker, Input, Select, Table, Tag } from "antd";
import { useMemo, useState } from "react";
import type { Dayjs } from "dayjs";
import { useInfiniteQuery } from "@tanstack/react-query";
import { api, describeApiError } from "../api.ts";
import { DecisionDrawer } from "../components/DecisionDrawer.tsx";
import type { DecisionLogRow, DecisionOutcome } from "../types.ts";

const { RangePicker } = DatePicker;

const OUTCOME_COLORS: Record<DecisionOutcome, string> = {
  blocked: "red",
  would_block: "orange",
  allowed: "green",
  unjudged: "default",
};

const OUTCOME_OPTIONS: { value: DecisionOutcome | ""; label: string }[] = [
  { value: "", label: "全部结论" },
  { value: "allowed", label: "放行 allowed" },
  { value: "blocked", label: "拦截 blocked" },
  { value: "would_block", label: "本应拦截 would_block" },
  { value: "unjudged", label: "未判定 unjudged" },
];

interface Filters {
  site: string;
  session: string;
  path: string;
  outcome: DecisionOutcome | "";
  range: [Dayjs, Dayjs] | null;
}

const EMPTY_FILTERS: Filters = { site: "", session: "", path: "", outcome: "", range: null };

export function DecisionsPage() {
  const [filters, setFilters] = useState<Filters>(EMPTY_FILTERS);
  const [selectedRow, setSelectedRow] = useState<DecisionLogRow | null>(null);

  const query = useMemo(
    () => ({
      site: filters.site || undefined,
      session: filters.session || undefined,
      path: filters.path || undefined,
      outcome: filters.outcome || undefined,
      since_millis: filters.range ? filters.range[0].valueOf() : undefined,
      until_millis: filters.range ? filters.range[1].valueOf() : undefined,
    }),
    [filters],
  );

  const { data, fetchNextPage, hasNextPage, isFetchingNextPage, isLoading, error } =
    useInfiniteQuery({
      queryKey: ["decisions", query],
      queryFn: ({ pageParam }: { pageParam: number | undefined }) =>
        api.decisions({ ...query, limit: 50, before_id: pageParam }),
      initialPageParam: undefined as number | undefined,
      getNextPageParam: (lastPage) =>
        lastPage.length > 0 ? lastPage[lastPage.length - 1]?.id : undefined,
    });

  const rows = data?.pages.flat() ?? [];

  return (
    <div>
      <h1 style={{ fontSize: 20 }}>判定日志</h1>
      <div style={{ display: "flex", gap: 12, marginBottom: 16, flexWrap: "wrap" }}>
        <Input
          placeholder="站点名"
          style={{ width: 160 }}
          value={filters.site}
          onChange={(event) => setFilters((prev) => ({ ...prev, site: event.target.value }))}
        />
        <Input
          placeholder="会话前缀"
          style={{ width: 160 }}
          value={filters.session}
          onChange={(event) => setFilters((prev) => ({ ...prev, session: event.target.value }))}
        />
        <Input
          placeholder="路径前缀"
          style={{ width: 200 }}
          value={filters.path}
          onChange={(event) => setFilters((prev) => ({ ...prev, path: event.target.value }))}
        />
        <Select<DecisionOutcome | "">
          style={{ width: 200 }}
          value={filters.outcome}
          options={OUTCOME_OPTIONS}
          onChange={(value) => setFilters((prev) => ({ ...prev, outcome: value }))}
        />
        <RangePicker
          showTime
          value={filters.range}
          onChange={(range) =>
            setFilters((prev) => ({
              ...prev,
              range: range?.[0] && range[1] ? [range[0], range[1]] : null,
            }))
          }
        />
        <Button onClick={() => setFilters(EMPTY_FILTERS)}>重置</Button>
      </div>

      {error && <Alert type="error" title={describeApiError(error)} showIcon />}

      <Table<DecisionLogRow>
        rowKey="id"
        loading={isLoading}
        dataSource={rows}
        pagination={false}
        onRow={(row) => ({ onClick: () => setSelectedRow(row), style: { cursor: "pointer" } })}
        columns={[
          {
            title: "时间",
            dataIndex: "at_millis",
            render: (ms: number) => new Date(ms).toLocaleString(),
          },
          { title: "站点", dataIndex: "site" },
          { title: "会话", dataIndex: "session" },
          { title: "方法", dataIndex: "method" },
          { title: "路径", dataIndex: "path" },
          { title: "状态", dataIndex: "status" },
          { title: "判定路径", dataIndex: "decision_path" },
          {
            title: "结论",
            dataIndex: "outcome",
            render: (outcome: DecisionOutcome) => (
              <Tag color={OUTCOME_COLORS[outcome]}>{outcome}</Tag>
            ),
          },
        ]}
      />

      {hasNextPage && (
        <div style={{ textAlign: "center", marginTop: 16 }}>
          <Button onClick={() => fetchNextPage()} loading={isFetchingNextPage}>
            加载更多
          </Button>
        </div>
      )}

      <DecisionDrawer row={selectedRow} onClose={() => setSelectedRow(null)} />
    </div>
  );
}
