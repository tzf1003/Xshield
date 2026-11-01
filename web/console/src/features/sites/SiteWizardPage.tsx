// The new-site page at /sites/new (docs/06 6.4.8, P0): the configuration form on the left, the YAML it produces on
// the right, and "从 YAML 创建" to paste a whole configuration instead. Advanced parameters are set after
// creation. The four-step wizard (P1) is not built yet. A site is created only when the server accepts the
// configuration, and the page then opens the new site.

import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { Segmented } from "antd";
import { Suspense, useEffect, useMemo, useState } from "react";
import { useSaveSite, useValidate } from "../../api/queries.ts";
import type { SiteSpec } from "../../api/types.ts";
import { useSetSearch } from "../../app/scope.ts";
import { validateSpec } from "../../lib/site-validate.ts";
import { specToYaml } from "../../lib/yaml.ts";
import { Card, Loading, PageHead } from "../../ui/Page.tsx";
import { ConfigForm, FORM_GROUP_LABEL, type FormGroup } from "./ConfigForm.tsx";
import { useDebounced } from "./hooks.ts";
import { emptySpec, sameJson } from "./spec-model.ts";
import { requestProblem, serverProblem } from "./site-messages.ts";
import { clearCopy, readCopy, writeCreated } from "./site-storage.ts";
import { LazyYamlEditor } from "./yaml-lazy.ts";
import "./sites.css";

const FORM_GROUPS: FormGroup[] = ["basics", "session", "entries", "bypass", "mode"];

export function SiteWizardPage() {
  const search = useSearch({ from: "/sites/new" });
  const setSearch = useSetSearch();
  const navigate = useNavigate();
  const yamlMode = search.from === "yaml";
  // A configuration copied from a site ("复制为新站点") starts the form; the copy is used once. A new site starts
  // in observe, so the copy's mode is set back to observe here: enforce is not carried over.
  const [spec, setSpec] = useState<SiteSpec>(() => ({
    ...(readCopy() ?? emptySpec()),
    mode: "observe",
  }));
  const [yamlBroken, setYamlBroken] = useState(false);
  // What the page creates. The YAML view creates the mode its text names (observe when it names none). The form
  // always creates observe, even when a YAML that named enforce was pasted before the switch to the form.
  const toCreate = useMemo<SiteSpec>(
    () => (yamlMode ? spec : { ...spec, mode: "observe" }),
    [spec, yamlMode],
  );
  const settled = useDebounced(toCreate, 600);
  const issues = validateSpec(toCreate);
  const localOk = issues.errors.length === 0;
  const settledOk = validateSpec(settled).errors.length === 0;
  const validate = useValidate();
  const validateRemote = validate.mutate;
  const create = useSaveSite();

  useEffect(() => {
    clearCopy();
  }, []);

  useEffect(() => {
    if (settledOk) validateRemote(settled);
  }, [settled, settledOk, validateRemote]);

  // The server's answer counts only for the configuration on the page now, not for an older one.
  const remote =
    validate.variables !== undefined && sameJson(validate.variables, toCreate)
      ? validate.data
      : undefined;
  const remoteFailed = validate.isError && sameJson(validate.variables, toCreate);
  const remoteProblem =
    remote && !remote.valid ? serverProblem(remote.error, remote.field, toCreate) : null;
  const canCreate = localOk && !yamlBroken && remote?.valid === true && !create.isPending;

  const submit = () => {
    create.mutate(
      { name: null, spec: toCreate, body: { spec: toCreate } },
      {
        onSuccess: (site) => {
          writeCreated(site.name, site.version, site.mode);
          void navigate({ to: "/sites/$name", params: { name: site.name } });
        },
      },
    );
  };

  return (
    <>
      <PageHead
        title="新建站点"
        crumbs={<Link to="/sites">站点</Link>}
        sub="名称、Host、源站、会话凭证和入口；高级判定参数创建后再调。"
        actions={
          <Segmented
            value={yamlMode ? "yaml" : "form"}
            onChange={(value) => setSearch({ from: value === "yaml" ? "yaml" : undefined }, true)}
            options={[
              { label: "表单", value: "form" },
              { label: "从 YAML 创建", value: "yaml" },
            ]}
          />
        }
      />

      <div className="wizard-layout">
        <div className="stack">
          {yamlMode ? (
            <Card title="粘贴 YAML 或 JSON">
              <Suspense fallback={<Loading height={240} />}>
                <LazyYamlEditor
                  spec={spec}
                  onParsed={(result) => {
                    setYamlBroken(!result.ok);
                    if (result.ok) setSpec(result.spec);
                  }}
                />
              </Suspense>
            </Card>
          ) : (
            FORM_GROUPS.map((id) => (
              <Card key={id} title={FORM_GROUP_LABEL[id]}>
                <ConfigForm
                  group={id}
                  mode="create"
                  spec={toCreate}
                  saved={null}
                  onChange={setSpec}
                  issues={issues.errors}
                  warnings={issues.warnings}
                  hits={undefined}
                  impact={[]}
                />
              </Card>
            ))
          )}
        </div>

        <aside className="wizard-side stack">
          <Card title="将要创建的配置">
            <pre className="codeblock">{specToYaml(toCreate)}</pre>
          </Card>

          <Card title="检查">
            <div className="stack-tight">
              {issues.errors.map((item) => (
                <div key={`${item.field}-${item.message}`} className="field-error">
                  {item.message}
                </div>
              ))}
              {issues.warnings.map((item) => (
                <div key={`${item.field}-${item.message}`} className="field-warn">
                  ▲ {item.message}
                </div>
              ))}
              {yamlBroken ? (
                <div className="field-error">YAML 有错误，修好后才能创建站点。</div>
              ) : null}
              <div aria-live="polite" className="small">
                {!localOk ? (
                  <span className="muted">修正上面的错误后，再检查服务端规则。</span>
                ) : validate.isPending && remote === undefined ? (
                  <span className="muted">正在校验…</span>
                ) : remoteFailed ? (
                  <span className="field-error" role="alert">
                    {requestProblem(validate.error, toCreate)}
                  </span>
                ) : remoteProblem ? (
                  <span className="field-error" role="alert">
                    {remoteProblem}
                  </span>
                ) : remote?.valid === true ? (
                  <span>✓ 服务端校验通过</span>
                ) : null}
              </div>
              {create.isError ? (
                <div className="errbar" role="alert">
                  {requestProblem(create.error, toCreate)}
                </div>
              ) : null}
              <div className="row" style={{ justifyContent: "flex-end" }}>
                <Link to="/sites" className="btn">
                  取消
                </Link>
                <button
                  type="button"
                  className="btn-primary"
                  disabled={!canCreate}
                  onClick={submit}
                >
                  {create.isPending ? "正在创建…" : "创建站点"}
                </button>
              </div>
            </div>
          </Card>
        </aside>
      </div>
    </>
  );
}
