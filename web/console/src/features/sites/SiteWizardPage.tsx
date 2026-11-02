// The new-site wizard at /sites/new (docs/06 6.4.8, P1): four steps that set the fields of one configuration, with
// the YAML it produces beside them. Step 1 can take a whole configuration instead ("粘贴已有配置"), and a valid one
// goes straight to the last step. A site is created only when the server accepts the configuration, and the page
// then opens the new site.

import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { Suspense, useEffect, useState } from "react";
import { useSaveSite, useValidate } from "../../api/queries.ts";
import type { SiteSpec } from "../../api/types.ts";
import { useSetSearch } from "../../app/scope.ts";
import { validateSpec } from "../../lib/site-validate.ts";
import { specToYaml } from "../../lib/yaml.ts";
import { Card, Loading, PageHead } from "../../ui/Page.tsx";
import { ConfigForm, type FormGroup } from "./ConfigForm.tsx";
import { useDebounced } from "./hooks.ts";
import { emptySpec, sameJson } from "./spec-model.ts";
import { requestProblem, serverProblem } from "./site-messages.ts";
import { clearCopy, readCopy, writeCreated } from "./site-storage.ts";
import { LazyYamlEditor } from "./yaml-lazy.ts";
import "./sites.css";

/** The four steps and the form groups each one sets. The last step confirms the mode and the Jev choice. */
const STEPS: ReadonlyArray<{ title: string; groups: readonly FormGroup[] }> = [
  { title: "基本信息", groups: ["basics"] },
  { title: "会话凭证", groups: ["session"] },
  { title: "入口与绕过", groups: ["entries", "bypass"] },
  { title: "确认", groups: ["mode"] },
];

const LAST_STEP = STEPS.length;

export function SiteWizardPage() {
  const search = useSearch({ from: "/sites/new" });
  const setSearch = useSetSearch();
  const navigate = useNavigate();
  // `from=yaml` shows the paste view in place of the steps ("粘贴已有配置").
  const pasting = search.from === "yaml";
  const step = search.step ?? 1;
  const active = STEPS[step - 1];

  // A configuration copied from a site ("复制为新站点") starts the wizard; the copy is used once. A new site starts
  // in observe, so the copy's mode is set back to observe here: enforce is not carried over. A pasted YAML keeps the
  // mode it names.
  const [spec, setSpec] = useState<SiteSpec>(() => ({
    ...(readCopy() ?? emptySpec()),
    mode: "observe",
  }));
  const [yamlBroken, setYamlBroken] = useState(false);
  const issues = validateSpec(spec);
  const localOk = issues.errors.length === 0;
  const settled = useDebounced(spec, 600);
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
    validate.variables !== undefined && sameJson(validate.variables, spec)
      ? validate.data
      : undefined;
  const remoteFailed = validate.isError && sameJson(validate.variables, spec);
  const remoteProblem =
    remote && !remote.valid ? serverProblem(remote.error, remote.field, spec) : null;
  const canCreate = localOk && !yamlBroken && remote?.valid === true && !create.isPending;
  // A step's own errors keep "下一步" disabled; the other steps' errors are shown in the check card.
  const stepErrors = issues.errors.filter((issue) =>
    (active?.groups ?? []).some((group) => group === issue.group),
  );

  const goTo = (target: number) => setSearch({ step: target, from: undefined });

  const submit = () => {
    create.mutate(
      { name: null, spec, body: { spec } },
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
        sub="按四步填写：基本信息、会话凭证、入口与绕过、确认。高级判定参数创建后再调。"
      />

      <div className="wizard-layout">
        <div className="stack">
          <ol className="wizard-steps" aria-label="接入步骤">
            {STEPS.map((item, index) => (
              <li key={item.title}>
                <button
                  type="button"
                  className="wizard-step"
                  aria-current={!pasting && index + 1 === step ? "step" : undefined}
                  onClick={() => goTo(index + 1)}
                >
                  <span aria-hidden="true">{index + 1} </span>
                  {item.title}
                </button>
              </li>
            ))}
          </ol>

          {pasting ? (
            <Card title="粘贴 YAML 或 JSON">
              <Suspense fallback={<Loading height={240} />}>
                <LazyYamlEditor
                  spec={spec}
                  onParsed={(result) => {
                    setYamlBroken(!result.ok);
                    if (!result.ok) return;
                    setSpec(result.spec);
                    // A configuration that is valid as it stands goes straight to the confirmation (docs/06 6.4.8).
                    if (validateSpec(result.spec).errors.length === 0) {
                      setSearch({ step: LAST_STEP, from: undefined }, true);
                    }
                  }}
                />
              </Suspense>
              <div className="row">
                <button type="button" className="linkbtn" onClick={() => goTo(1)}>
                  ← 返回基本信息
                </button>
              </div>
            </Card>
          ) : (
            <Card title={active?.title ?? ""}>
              {(active?.groups ?? []).map((group) => (
                <ConfigForm
                  key={group}
                  group={group}
                  mode="create"
                  spec={spec}
                  saved={null}
                  onChange={setSpec}
                  issues={issues.errors}
                  warnings={issues.warnings}
                  hits={undefined}
                  impact={[]}
                />
              ))}
              {step === 1 ? (
                <div className="row">
                  <button
                    type="button"
                    className="linkbtn"
                    onClick={() => setSearch({ from: "yaml" })}
                  >
                    粘贴已有配置
                  </button>
                </div>
              ) : null}
              {step === LAST_STEP ? (
                <div className="notice soft">高级判定参数全部使用默认值，创建后可调整。</div>
              ) : null}
            </Card>
          )}

          <div className="row" style={{ justifyContent: "flex-end" }}>
            <Link to="/sites" className="btn">
              取消
            </Link>
            {pasting ? null : step > 1 ? (
              <button type="button" className="btn" onClick={() => goTo(step - 1)}>
                上一步
              </button>
            ) : null}
            {pasting ? null : step < LAST_STEP ? (
              <button
                type="button"
                className="btn-primary"
                disabled={stepErrors.length > 0}
                onClick={() => goTo(step + 1)}
              >
                下一步
              </button>
            ) : (
              <button type="button" className="btn-primary" disabled={!canCreate} onClick={submit}>
                {create.isPending ? "正在创建…" : "创建站点"}
              </button>
            )}
          </div>
        </div>

        <aside className="wizard-side stack">
          <Card title="将要创建的配置">
            <pre className="codeblock">{specToYaml(spec)}</pre>
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
                    {requestProblem(validate.error, spec)}
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
                  {requestProblem(create.error, spec)}
                </div>
              ) : null}
            </div>
          </Card>
        </aside>
      </div>
    </>
  );
}
