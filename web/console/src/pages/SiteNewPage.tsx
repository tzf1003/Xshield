import { Alert } from "antd";
import { useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api, describeApiError } from "../api.ts";
import { EMPTY_SITE_FORM_VALUES, SiteForm } from "../components/SiteForm.tsx";
import type { SiteSpecJson } from "../types.ts";

export function SiteNewPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: (spec: SiteSpecJson) => api.createSite(spec),
    onSuccess: (record) => {
      queryClient.invalidateQueries({ queryKey: ["sites"] });
      navigate({ to: "/sites/$name", params: { name: record.name } });
    },
    onError: (error) => {
      setErrorMessage(describeApiError(error));
    },
  });

  return (
    <div>
      <h1 style={{ fontSize: 20 }}>新建站点</h1>
      {errorMessage && (
        <Alert type="error" title={errorMessage} showIcon style={{ marginBottom: 16 }} />
      )}
      <SiteForm
        initialValues={EMPTY_SITE_FORM_VALUES}
        nameEditable
        submitting={mutation.isPending}
        submitLabel="创建"
        onSubmit={(spec) => {
          setErrorMessage(null);
          mutation.mutate(spec);
        }}
      />
    </div>
  );
}
