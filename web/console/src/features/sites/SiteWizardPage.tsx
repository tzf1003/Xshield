// The new-site wizard at /sites/new (docs/06 6.4.8, P1): four steps that set the fields of one configuration, with
// the YAML it produces beside them. Step 1 can take a whole configuration instead ("粘贴已有配置"), and a valid one
// goes straight to the last step. A site is created only when the server accepts the configuration. The fifth step
// (console design 1.1) is the object map's start: it opens once the site exists, and confirming it hands the chosen
// entries to the site page's save dialog.

import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { type ReactNode, Suspense, useEffect, useState } from "react";
import { useSaveSite, useSite, useValidate } from "../../api/queries.ts";
import type { SiteSpec } from "../../api/types.ts";
import { useSetSearch } from "../../app/scope.ts";
import { validateSpec } from "../../lib/site-validate.ts";
import { OBJECT_TEXT } from "../../lib/vocab.ts";
import { specToYaml } from "../../lib/yaml.ts";
import { Card, Kv, Loading, PageHead } from "../../ui/Page.tsx";
import { ConfigForm, type FormGroup } from "./ConfigForm.tsx";
import { useDebounced } from "./hooks.ts";
import { WizardObjectsStep } from "./objects/WizardObjectsStep.tsx";
import { emptySpec, sameJson } from "./spec-model.ts";
import { requestProblem, serverProblem } from "./site-messages.ts";
import { clearCopy, readCopy, writeCreated, writeDraft } from "./site-storage.ts";
import { LazyYamlEditor } from "./yaml-lazy.ts";
import "./sites.css";

/** The four form steps and the form groups each one sets. The last step confirms the mode and the Jev choice. */
const STEPS: ReadonlyArray<{ title: string; groups: readonly FormGroup[] }> = [
  { title: "基本信息", groups: ["basics"] },
  { title: "会话凭证", groups: ["session"] },
  { title: "接口名、入口与绕过", groups: ["routes", "entries", "bypass"] },
  { title: "确认", groups: ["mode"] },
];

const LAST_STEP = STEPS.length;
/** The object map's start (console design 1.1): the fifth step, after the site is created. */
const OBJECT_STEP = LAST_STEP + 1;

export function SiteWizardPage() {
  const search = useSearch({ from: "/sites/new" });
  const setSearch = useSetSearch();
  const navigate = useNavigate();
  // `from=yaml` shows the paste view in place of the steps ("粘贴已有配置").
  const pasting = search.from === "yaml";
  const step = search.step ?? 1;
  const onObjectStep = step === OBJECT_STEP;
  const active = STEPS[step - 1];
  // The fifth step works on the site it names, which exists by then; without one the page goes back to the list.
  const siteName = onObjectStep ? (search.site ?? null) : null;
  const created = useSite(siteName);

  // A configuration copied from a site ("复制为新站点") starts the wizard; the copy is used once. A new site starts
  // in observe, so the copy's mode is set back to observe here: enforce is not carried over. A pasted YAML keeps the
  // mode it names.
  const [spec, setSpec] = useState<SiteSpec>(() => ({
    ...(readCopy() ?? emptySpec()),
    mode: "observe",
  }));
  const [yamlBroken, setYamlBroken] = useState(false);
  // The object map's start is offered once the site exists: the new site can open on it (console design 1.1).
  const [openObjects, setOpenObjects] = useState(true);
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

  useEffect(() => {
    if (onObjectStep && (search.site === undefined || created.isError)) {
      void navigate({ to: "/sites" });
    }
  }, [onObjectStep, search.site, created.isError, navigate]);

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

  const goTo = (target: number) =>
    setSearch(
      {
        step: target,
        from: undefined,
        site: target === OBJECT_STEP ? search.site : undefined,
      },
      false,
    );

  const submit = () => {
    create.mutate(
      { name: null, spec, body: { spec } },
      {
        onSuccess: (site) => {
          writeCreated(site.name, site.version, site.mode);
          if (openObjects) {
            void navigate({ to: "/sites/new", search: { step: OBJECT_STEP, site: site.name } });
            return;
          }
          void navigate({ to: "/sites/$name", params: { name: site.name }, search: {} });
        },
      },
    );
  };

  // The chosen entries become the draft of the new site and open its save dialog (console design 1.4): the save is
  // the same as any other, a new version with the note "接入时确认对象表起点".
  const confirmObjects = (next: SiteSpec, count: number) => {
    const site = created.data;
    if (site === undefined) return;
    writeDraft(site.name, { base: site.version, spec: next });
    void navigate({
      to: "/sites/$name",
      params: { name: site.name },
      search: { tab: "objects", save: "1", bootstrap: count },
    });
  };

  const titles = [...STEPS.map((item) => item.title), OBJECT_TEXT.wizard.step];

  let content: ReactNode;
  if (onObjectStep) {
    content =
      created.data === undefined ? (
        <Card title={OBJECT_TEXT.wizard.step}>
          <Loading height={240} />
        </Card>
      ) : (
        <WizardObjectsStep
          site={created.data}
          onSkip={() =>
            void navigate({ to: "/sites/$name", params: { name: created.data.name }, search: {} })
          }
          onConfirm={confirmObjects}
        />
      );
  } else if (pasting) {
    content = (
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
    );
  } else {
    content = (
      <Card title={active?.title ?? ""}>
        {(active?.groups ?? []).map((group) => (
          <ConfigForm
            key={group}
            group={group}
            mode="create"
            site={null}
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
            <button type="button" className="linkbtn" onClick={() => setSearch({ from: "yaml" })}>
              粘贴已有配置
            </button>
          </div>
        ) : null}
        {step === LAST_STEP ? (
          <div className="notice soft">高级判定参数全部使用默认值，创建后可调整。</div>
        ) : null}
        {step === LAST_STEP ? (
          <div className="stack-tight">
            <div className="field-label">{OBJECT_TEXT.wizard.title}</div>
            <div className="small muted">{OBJECT_TEXT.wizard.text}</div>
            <label className="row small">
              <input
                type="checkbox"
                checked={openObjects}
                onChange={(event) => setOpenObjects(event.target.checked)}
              />
              {OBJECT_TEXT.wizard.open}
            </label>
          </div>
        ) : null}
      </Card>
    );
  }

  return (
    <>
      <PageHead
        title="新建站点"
        crumbs={<Link to="/sites">站点</Link>}
        sub="按四步填写：基本信息、会话凭证、入口与绕过、确认。创建后可以在第五步确认对象表起点（可跳过）；高级判定参数创建后再调。"
      />

      <div className="wizard-layout">
        <div className="stack">
          <ol className="wizard-steps" aria-label="接入步骤">
            {titles.map((title, index) => {
              const number = index + 1;
              const isObjectStep = number === OBJECT_STEP;
              // The form steps are done once the site exists, so they read as done and do not go back.
              const done = onObjectStep && !isObjectStep;
              const locked = isObjectStep ? search.site === undefined : onObjectStep;
              return (
                <li key={title}>
                  <button
                    type="button"
                    className="wizard-step"
                    aria-current={!pasting && number === step ? "step" : undefined}
                    disabled={locked}
                    onClick={() => goTo(number)}
                  >
                    <span aria-hidden="true">{done ? "✓ " : `${number} `}</span>
                    {title}
                  </button>
                </li>
              );
            })}
          </ol>

          {content}

          {onObjectStep ? null : (
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
                <button
                  type="button"
                  className="btn-primary"
                  disabled={!canCreate}
                  onClick={submit}
                >
                  {create.isPending ? "正在创建…" : "创建站点"}
                </button>
              )}
            </div>
          )}
        </div>

        <aside className="wizard-side stack">
          {onObjectStep ? (
            <Card title="站点">
              <Kv
                items={[
                  ["名称", created.data?.name ?? "—"],
                  ["版本", created.data === undefined ? "—" : `v${created.data.version}`],
                ]}
              />
              <div className="small muted">站点的其他配置在站点详情里改。</div>
            </Card>
          ) : (
            <>
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
            </>
          )}
        </aside>
      </div>
    </>
  );
}
