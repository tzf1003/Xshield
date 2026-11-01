// The configuration tab of a site (docs/06 6.4.9): a form and a YAML view of the same draft, grouped, with the
// impact of the draft shown as the user types (600 ms) and the draft bar at the bottom when there are changes.

import { Segmented } from "antd";
import { Suspense, useState } from "react";
import { usePreview } from "../../api/queries.ts";
import type { SiteDetail, SiteSpec } from "../../api/types.ts";
import { fmtInt } from "../../lib/format.ts";
import { type FieldIssue, validateSpec } from "../../lib/site-validate.ts";
import { Loading } from "../../ui/Page.tsx";
import { AdvancedParams } from "./AdvancedParams.tsx";
import { ConfigForm, FORM_GROUP_LABEL, type FormGroup } from "./ConfigForm.tsx";
import { useDebounced } from "./hooks.ts";
import { observedText } from "./Readiness.tsx";
import { customAdvanced, type SpecText } from "./spec-model.ts";
import { LazyYamlEditor } from "./yaml-lazy.ts";

export type ConfigGroupId = FormGroup | "advanced";

export const CONFIG_GROUPS: ConfigGroupId[] = [
  "basics",
  "session",
  "entries",
  "bypass",
  "mode",
  "advanced",
];

export function isConfigGroup(value: string | undefined): value is ConfigGroupId {
  return CONFIG_GROUPS.some((group) => group === value);
}

type Props = {
  site: SiteDetail;
  draft: SiteSpec;
  dirty: boolean;
  changeCount: number;
  issues: { errors: FieldIssue[]; warnings: FieldIssue[] };
  edit: "form" | "yaml";
  group: ConfigGroupId;
  onEdit: (edit: "form" | "yaml") => void;
  onGroup: (group: ConfigGroupId) => void;
  onDraft: (next: SiteSpec) => void;
  onDiscard: () => void;
  onReview: () => void;
  onSwitchMode: () => void;
};

function focusIdFor(issue: FieldIssue): string {
  if (issue.field.startsWith("hosts")) return "site-field-hosts";
  if (issue.field === "name") return "site-field-name";
  if (issue.field === "origin") return "site-field-origin";
  if (issue.field === "session") return "site-field-session";
  if (issue.field === "secret_fields") return "site-field-secret";
  return "";
}

export function ConfigTab({
  site,
  draft,
  dirty,
  changeCount,
  issues,
  edit,
  group,
  onEdit,
  onGroup,
  onDraft,
  onDiscard,
  onReview,
  onSwitchMode,
}: Props) {
  const [yamlProblem, setYamlProblem] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const hasErrors = issues.errors.length > 0;
  const settled = useDebounced(draft, 600);
  const settledValid = validateSpec(settled).errors.length === 0;
  const preview = usePreview(site.name, settledValid ? settled : null);
  const impact = preview.data?.changes ?? [];
  const hits = preview.data?.patterns;
  const customCount = customAdvanced(draft.advanced).length;
  const observed = site.observing_since_millis;
  const observingText = observed === null ? null : observedText(Date.now() - observed);

  const blockedMessage = yamlProblem
    ? `${yamlProblem}，修好后才能切回表单`
    : hasErrors
      ? `YAML 中有 ${fmtInt(issues.errors.length)} 项需要修正：${issues.errors[0]?.message ?? ""}`
      : null;

  const changeEdit = (value: string) => {
    if (value === "form" && edit === "yaml" && blockedMessage !== null) {
      setNotice(blockedMessage);
      return;
    }
    setNotice(null);
    setYamlProblem(null);
    onEdit(value === "yaml" ? "yaml" : "form");
  };

  const parsed = (result: SpecText) => {
    if (result.ok) {
      setYamlProblem(null);
      onDraft(result.spec);
    } else {
      setYamlProblem(result.message);
    }
  };

  const reviewFirst = () => {
    const first = issues.errors[0];
    if (!first) {
      onReview();
      return;
    }
    onGroup(first.group);
    setNotice(`有 ${fmtInt(issues.errors.length)} 项需要修正：${first.message}`);
    const id = focusIdFor(first);
    if (id) window.setTimeout(() => document.getElementById(id)?.focus(), 60);
  };

  const groupError = (id: ConfigGroupId) => issues.errors.some((issue) => issue.group === id);
  const groupCount = (id: ConfigGroupId): string | null => {
    if (id === "entries") return String(draft.entries.length);
    if (id === "bypass") return String((draft.bypass ?? []).length);
    if (id === "advanced") return customCount > 0 ? `已自定义 ${customCount} 项` : null;
    return null;
  };

  return (
    <div className="stack">
      <div className="row between">
        <Segmented
          value={edit}
          options={[
            { label: "表单", value: "form" },
            { label: "YAML", value: "yaml" },
          ]}
          onChange={(value) => changeEdit(String(value))}
        />
        {notice ? (
          <span className="field-error" role="alert">
            {notice}
          </span>
        ) : null}
      </div>

      {edit === "yaml" ? (
        <Suspense fallback={<Loading height={240} />}>
          <LazyYamlEditor spec={draft} onParsed={parsed} />
        </Suspense>
      ) : (
        <div className="cfg-layout">
          <nav className="cfg-nav" aria-label="配置分组">
            {CONFIG_GROUPS.map((id) => {
              const label = id === "advanced" ? "高级判定参数" : FORM_GROUP_LABEL[id];
              const count = groupCount(id);
              return (
                <button
                  key={id}
                  type="button"
                  aria-current={id === group ? "true" : undefined}
                  onClick={() => onGroup(id)}
                >
                  <span>{label}</span>
                  {count ? <span className="count">{count}</span> : null}
                  {groupError(id) ? (
                    <span className="err-dot" role="img" aria-label="有需要修正的内容" />
                  ) : null}
                </button>
              );
            })}
          </nav>
          <div className="cfg-panel">
            {group === "advanced" ? (
              <AdvancedParams
                name={site.name}
                spec={draft}
                onChange={onDraft}
                issues={issues.errors}
                warnings={issues.warnings}
                impact={impact}
              />
            ) : (
              <ConfigForm
                group={group}
                mode="edit"
                spec={draft}
                saved={site.spec}
                onChange={onDraft}
                issues={issues.errors}
                warnings={issues.warnings}
                hits={hits}
                impact={impact}
                onSwitchMode={onSwitchMode}
                observingText={observingText}
              />
            )}
          </div>
        </div>
      )}

      {dirty ? (
        <section className="draftbar" aria-label="未保存的改动">
          <span className="tnum">未保存的改动 {fmtInt(Math.max(1, changeCount))} 处</span>
          {hasErrors ? (
            <span className="field-error">
              有 {fmtInt(issues.errors.length)} 项需要修正，修好后才能保存
            </span>
          ) : null}
          <span className="grow" />
          <button type="button" className="btn" onClick={reviewFirst}>
            查看差异
          </button>
          <button type="button" className="btn" onClick={onDiscard}>
            放弃
          </button>
          <button type="button" className="btn-primary" onClick={reviewFirst}>
            预估影响并保存 ⌘S
          </button>
        </section>
      ) : null}
    </div>
  );
}
