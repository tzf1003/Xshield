import { Alert, Button, Table } from "antd";
import { Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { api, describeApiError } from "../api.ts";
import type { SiteRecord } from "../types.ts";

export function SitesListPage() {
  const { data, isLoading, error } = useQuery({
    queryKey: ["sites"],
    queryFn: () => api.listSites(),
  });

  return (
    <div>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: 16,
        }}
      >
        <h1 style={{ fontSize: 20, margin: 0 }}>站点</h1>
        <Link to="/sites/new">
          <Button type="primary">新建站点</Button>
        </Link>
      </div>
      {error && <Alert type="error" title={describeApiError(error)} showIcon />}
      <Table<SiteRecord>
        rowKey="name"
        loading={isLoading}
        dataSource={data ?? []}
        pagination={false}
        columns={[
          {
            title: "名称",
            dataIndex: "name",
            render: (name: string) => (
              <Link to="/sites/$name" params={{ name }}>
                {name}
              </Link>
            ),
          },
          {
            title: "域名",
            dataIndex: "hosts",
            render: (hosts: string[]) => hosts.join(", "),
          },
          { title: "模式", dataIndex: "mode" },
          { title: "更新时间", dataIndex: "updated_at" },
        ]}
      />
    </div>
  );
}
