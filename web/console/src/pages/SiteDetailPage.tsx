import { Alert, Button, Popconfirm } from "antd";
import { useMemo, useState } from "react";
import { useNavigate, useParams } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, describeApiError } from "../api.ts";
import { HistoryPanel } from "../components/HistoryPanel.tsx";
import { specToFormValues, SiteForm } from "../components/SiteForm.tsx";
import type { SiteSpecJson } from "../types.ts";

export function SiteDetailPage() {
  const { name } = useParams({ from: "/sites/$name" });
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [rollingBackId, setRollingBackId] = useState<number | null>(null);

  const siteQuery = useQuery({
    queryKey: ["site", name],
    queryFn: () => api.getSite(name),
  });
  const historyQuery = useQuery({
    queryKey: ["site-history", name],
    queryFn: () => api.siteHistory(name),
  });

  const saveMutation = useMutation({
    mutationFn: (spec: SiteSpecJson) => api.updateSite(name, spec),
    onSuccess: (record) => {
      queryClient.setQueryData(["site", name], record);
      queryClient.invalidateQueries({ queryKey: ["site-history", name] });
      queryClient.invalidateQueries({ queryKey: ["sites"] });
      setErrorMessage(null);
    },
    onError: (error) => setErrorMessage(describeApiError(error)),
  });

  const deleteMutation = useMutation({
    mutationFn: () => api.deleteSite(name),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["sites"] });
      navigate({ to: "/sites" });
    },
    onError: (error) => setErrorMessage(describeApiError(error)),
  });

  const rollbackMutation = useMutation({
    mutationFn: (id: number) => api.rollbackSite(name, id),
    onMutate: (id) => setRollingBackId(id),
    onSuccess: (record) => {
      queryClient.setQueryData(["site", name], record);
      queryClient.invalidateQueries({ queryKey: ["site-history", name] });
      queryClient.invalidateQueries({ queryKey: ["sites"] });
    },
    onError: (error) => setErrorMessage(describeApiError(error)),
    onSettled: () => setRollingBackId(null),
  });

  const initialValues = useMemo(
    () => (siteQuery.data ? specToFormValues(siteQuery.data) : null),
    [siteQuery.data],
  );

  return (
    <div>
      <h1 style={{ fontSize: 20 }}>站点：{name}</h1>
      {errorMessage && (
        <Alert type="error" title={errorMessage} showIcon style={{ marginBottom: 16 }} />
      )}
      {siteQuery.isLoading && <p>加载中…</p>}
      {siteQuery.error && <Alert type="error" title={describeApiError(siteQuery.error)} showIcon />}
      {initialValues && (
        <SiteForm
          key={siteQuery.data?.updated_at}
          initialValues={initialValues}
          nameEditable={false}
          submitting={saveMutation.isPending}
          submitLabel="保存"
          onSubmit={(spec) => saveMutation.mutate({ ...spec, name })}
          extraActions={
            <Popconfirm
              title="删除站点？"
              description="删除后网关将不再为该站点路由流量，此操作不可撤销。"
              onConfirm={() => deleteMutation.mutate()}
            >
              <Button danger loading={deleteMutation.isPending}>
                删除站点
              </Button>
            </Popconfirm>
          }
        />
      )}

      <h2 className="xs-section-title">配置历史</h2>
      {historyQuery.isLoading && <p>加载中…</p>}
      {historyQuery.error && (
        <Alert type="error" title={describeApiError(historyQuery.error)} showIcon />
      )}
      {historyQuery.data && (
        <HistoryPanel
          entries={historyQuery.data}
          onRollback={(id) => rollbackMutation.mutate(id)}
          rollingBackId={rollingBackId}
        />
      )}
    </div>
  );
}
