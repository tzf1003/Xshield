import {
  DeleteOutlined,
  PlayCircleOutlined,
  ReloadOutlined,
  SaveOutlined,
} from "@ant-design/icons";
import { Button, Input, Space, Table, type TableColumnsType } from "antd";
import { useState } from "react";
import type { SavedView, SavedViewCreated, SavedViewDeleted } from "../../saved-views.ts";
import type { SearchPlan } from "../../search.ts";
import { useGuardedMutation, useGuardedQuery } from "../../security/hooks";
import { ErrorNotice, IdChip, labelled, LoadState, Observed, Time } from "../../work/Parts";
import { specs } from "../../work/queries.ts";

/**
 * 保存的检索: the caller's named searches. Saving stores the submitted plan's parameters only;
 * opening one runs it as an ordinary search, so the result is audited on the search path.
 */
export function SavedViewsPanel({
  current,
  onRun,
}: {
  /** The plan of the search on screen, if one was submitted. */
  current: SearchPlan | null;
  onRun: (plan: SearchPlan) => void;
}) {
  const query = useGuardedQuery(specs.savedViews());
  const [name, setName] = useState("");
  const [problem, setProblem] = useState<unknown>(null);
  const save = useGuardedMutation<{ name: string; plan: SearchPlan }, SavedViewCreated>({
    label: "保存检索视图",
    method: "POST",
    path: () => "/control/v1/saved-views",
    body: (vars) => ({ schema_version: 1, name: vars.name, search: vars.plan }),
    execute: (client, vars, context) =>
      client.createSavedView(vars.name, vars.plan, context.signal),
  });
  const remove = useGuardedMutation<{ viewId: string }, SavedViewDeleted>({
    label: "删除检索视图",
    method: "DELETE",
    path: (vars) => `/control/v1/saved-views/${vars.viewId}`,
    execute: (client, vars, context) => client.deleteSavedView(vars.viewId, context.signal),
  });
  const page = query.data;

  async function saveCurrent() {
    if (!current || name.trim() === "") return;
    setProblem(null);
    try {
      await save.submit({ name: name.trim(), plan: current });
      setName("");
      await query.refetch();
    } catch (error) {
      setProblem(error);
    }
  }

  async function deleteView(view: SavedView) {
    setProblem(null);
    try {
      await remove.submit({ viewId: view.view_id });
      await query.refetch();
    } catch (error) {
      setProblem(error);
    }
  }

  const columns: TableColumnsType<SavedView> = [
    {
      title: "名称",
      key: "name",
      onCell: labelled("名称"),
      render: (_, row) => row.name,
    },
    {
      title: "视图",
      key: "id",
      onCell: labelled("视图"),
      render: (_, row) => <IdChip id={row.view_id} label="视图 ID" short />,
    },
    {
      title: "保存时间",
      key: "created",
      onCell: labelled("保存时间"),
      render: (_, row) => <Time value={row.created_at} />,
    },
    {
      title: "操作",
      key: "actions",
      onCell: labelled("操作"),
      render: (_, row) => (
        <Space wrap>
          <Button
            size="small"
            icon={<PlayCircleOutlined aria-hidden="true" />}
            onClick={() => onRun(row.search)}
          >
            运行
          </Button>
          <Button
            size="small"
            danger
            icon={<DeleteOutlined aria-hidden="true" />}
            loading={remove.isPending}
            onClick={() => void deleteView(row)}
          >
            删除
          </Button>
        </Space>
      ),
    },
  ];

  return (
    <section className="xs-w-card" aria-label="保存的检索">
      <div className="xs-w-between xs-w-toolbar">
        {page ? <Observed asOf={page.as_of} requestId={page.request_id} /> : <span />}
        <Button
          icon={<ReloadOutlined aria-hidden="true" />}
          loading={query.isFetching}
          onClick={() => void query.refetch()}
        >
          刷新
        </Button>
      </div>
      <Space.Compact className="xs-w-toolbar">
        <Input
          aria-label="视图名称"
          placeholder="为当前检索命名"
          maxLength={160}
          value={name}
          onChange={(event) => setName(event.target.value)}
        />
        <Button
          type="primary"
          icon={<SaveOutlined aria-hidden="true" />}
          disabled={!current || name.trim() === ""}
          loading={save.isPending}
          onClick={() => void saveCurrent()}
        >
          保存当前检索
        </Button>
      </Space.Compact>
      {!current && <p className="xs-toolbar-hint">先提交一次检索，再保存它的条件。</p>}
      {problem !== null && <ErrorNotice error={problem} title="保存或删除未完成" />}
      <LoadState pending={query.isPending} error={query.error} onRetry={() => void query.refetch()}>
        {page && page.items.length === 0 && <p className="xs-toolbar-hint">还没有保存的检索。</p>}
        {page && page.items.length > 0 && (
          <Table<SavedView>
            className="xs-w-table"
            rowKey="view_id"
            size="middle"
            pagination={false}
            columns={columns}
            dataSource={page.items}
            loading={query.isFetching && !query.isPending}
          />
        )}
      </LoadState>
    </section>
  );
}
