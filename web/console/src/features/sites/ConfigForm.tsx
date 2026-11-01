// The configuration form, one group at a time (docs/06 6.4.9): basics, session credential, entries, bypass,
// mode and Jev-unavailable. The same fields serve the new-site page (all groups, editable mode) and the
// configuration tab of a site (one group, mode switched through its own dialog).

import { Segmented } from "antd";
import type { ReactNode } from "react";
import type { ImpactChange, ImpactPreview, SiteSpec } from "../../api/types.ts";
import { fmtInt } from "../../lib/format.ts";
import { validHost, type FieldGroup, type FieldIssue } from "../../lib/site-validate.ts";
import { PatternListEditor } from "./PatternListEditor.tsx";
import { PatternTester } from "./PatternTester.tsx";
import { TagInput } from "./TagInput.tsx";
import {
  LOGIN_PATHS,
  STATIC_PATHS,
  SESSION_NAMES,
  sessionKind,
  sessionName,
  withSession,
} from "./spec-model.ts";

export type FormGroup = "basics" | "session" | "entries" | "bypass" | "mode";

export const FORM_GROUP_LABEL: Record<FormGroup, string> = {
  basics: "基本信息",
  session: "会话凭证",
  entries: "入口",
  bypass: "绕过",
  mode: "模式与 Jev 不可用",
};

type Props = {
  group: FormGroup;
  mode: "create" | "edit";
  spec: SiteSpec;
  /** The saved configuration (edit mode): the session warning compares against it. */
  saved: SiteSpec | null;
  onChange: (next: SiteSpec) => void;
  issues: FieldIssue[];
  warnings: FieldIssue[];
  hits: ImpactPreview["patterns"] | undefined;
  impact: ImpactChange[];
  /** Edit mode: opens the mode switch dialog. */
  onSwitchMode?: () => void;
  /** Edit mode: the observation start, in words. */
  observingText?: string | null;
};

/** The messages of a field, including the messages of its list items (`hosts[2]`). */
export function problemsOf(issues: FieldIssue[], group: FieldGroup, field: string): string[] {
  return issues
    .filter(
      (issue) =>
        issue.group === group && (issue.field === field || issue.field.startsWith(`${field}[`)),
    )
    .map((issue) => issue.message);
}

function Field({
  label,
  htmlFor,
  help,
  errors = [],
  warnings = [],
  children,
}: {
  label: string;
  htmlFor?: string;
  help?: ReactNode;
  errors?: string[];
  warnings?: string[];
  children: ReactNode;
}) {
  return (
    <div className="field">
      {htmlFor ? (
        <label className="field-label" htmlFor={htmlFor}>
          {label}
        </label>
      ) : (
        <div className="field-label">{label}</div>
      )}
      {children}
      {help ? <div className="field-help">{help}</div> : null}
      {errors.map((message) => (
        <div key={message} className="field-error" role="alert">
          {message}
        </div>
      ))}
      {warnings.map((message) => (
        <div key={message} className="field-warn">
          ▲ {message}
        </div>
      ))}
    </div>
  );
}

function BasicsGroup({
  spec,
  mode,
  onChange,
  issues,
}: Pick<Props, "spec" | "mode" | "onChange" | "issues">) {
  return (
    <div className="stack">
      <Field
        label="站点名"
        htmlFor={mode === "create" ? "site-field-name" : undefined}
        help={
          mode === "create"
            ? "小写字母、数字、-、_，最长 64 个字符。创建后不能改名，改名用“复制为新站点”。"
            : "站点名创建后只读（改名用“复制为新站点”）。"
        }
        errors={problemsOf(issues, "basics", "name")}
      >
        {mode === "create" ? (
          <input
            id="site-field-name"
            className="native-input mono"
            value={spec.name}
            placeholder="例如 shop"
            aria-invalid={problemsOf(issues, "basics", "name").length > 0 ? true : undefined}
            onChange={(event) => onChange({ ...spec, name: event.target.value })}
          />
        ) : (
          <span className="mono">{spec.name}</span>
        )}
      </Field>
      <Field
        label="Host"
        htmlFor="site-field-hosts"
        help="浏览器访问这个 Host 时流量经过网关。最多 16 个。Host 被其他站点占用时，保存会被拒绝。"
      >
        <TagInput
          id="site-field-hosts"
          label="Host"
          values={spec.hosts}
          max={16}
          placeholder="例如 shop.example.com，按 Enter 添加"
          check={(value) => (validHost(value) ? null : "Host 需要是有效的主机名")}
          onChange={(hosts) => onChange({ ...spec, hosts })}
          error={problemsOf(issues, "basics", "hosts")[0] ?? null}
        />
      </Field>
      <Field
        label="源站地址"
        htmlFor="site-field-origin"
        help="http://主机[:端口] 或 https://主机[:端口]，不带路径。"
        errors={problemsOf(issues, "basics", "origin")}
      >
        <input
          id="site-field-origin"
          className="native-input mono"
          value={spec.origin}
          placeholder="http://10.0.0.5:8080"
          aria-invalid={problemsOf(issues, "basics", "origin").length > 0 ? true : undefined}
          onChange={(event) => onChange({ ...spec, origin: event.target.value })}
        />
      </Field>
    </div>
  );
}

function SessionGroup({
  spec,
  saved,
  mode,
  onChange,
  issues,
}: Pick<Props, "spec" | "saved" | "mode" | "onChange" | "issues">) {
  const kind = sessionKind(spec);
  const name = sessionName(spec);
  const changed =
    mode === "edit" &&
    saved !== null &&
    (sessionKind(saved) !== kind || sessionName(saved) !== name);
  const errors = problemsOf(issues, "session", "session");
  return (
    <div className="stack">
      <Field
        label="凭证位置"
        help="登录后浏览器每次都带给源站的那个凭证：Cookie 写在 Cookie 头里，请求头则是单独的一个头。"
      >
        <Segmented
          value={kind}
          options={[
            { label: "Cookie", value: "cookie" },
            { label: "请求头", value: "header" },
          ]}
          onChange={(value) =>
            onChange(withSession(spec, value === "header" ? "header" : "cookie", name))
          }
        />
      </Field>
      <Field
        label="名称"
        htmlFor="site-field-session"
        errors={errors}
        warnings={
          changed ? ["修改会话凭证后，现有会话的上下文全部作废，用户需要重新从入口进入"] : []
        }
      >
        <input
          id="site-field-session"
          className="native-input mono"
          value={name}
          placeholder={kind === "cookie" ? "例如 JSESSIONID" : "例如 Authorization"}
          aria-invalid={errors.length > 0 ? true : undefined}
          onChange={(event) => onChange(withSession(spec, kind, event.target.value))}
        />
        <div className="taglist" style={{ marginTop: 8 }}>
          {SESSION_NAMES.map((common) => (
            <button
              key={common}
              type="button"
              className="chip"
              aria-pressed={name === common}
              onClick={() => onChange(withSession(spec, kind, common))}
            >
              {common}
            </button>
          ))}
        </div>
      </Field>
    </div>
  );
}

function EntriesGroup({
  spec,
  saved,
  mode,
  hits,
  onChange,
  issues,
}: Pick<Props, "spec" | "saved" | "mode" | "hits" | "onChange" | "issues">) {
  return (
    <div className="stack">
      <Field
        label="入口"
        help="没有会话凭证也要判定的路径：登录、注册这类请求。每条以 / 开头，* 只能写在末尾。至少一条。"
      >
        <PatternListEditor
          kind="entries"
          label="入口"
          rules={spec.entries}
          hits={hits?.entries}
          issues={issues}
          presets={mode === "create" ? [{ label: "常见登录路径", rules: LOGIN_PATHS }] : []}
          onChange={(entries) => onChange({ ...spec, entries })}
        />
      </Field>
      <PatternTester
        entries={spec.entries}
        bypass={spec.bypass ?? []}
        savedEntries={saved?.entries ?? []}
        savedBypass={saved?.bypass ?? []}
      />
    </div>
  );
}

function BypassGroup({
  spec,
  saved,
  mode,
  hits,
  impact,
  onChange,
  issues,
}: Pick<Props, "spec" | "saved" | "mode" | "hits" | "impact" | "onChange" | "issues">) {
  const change = impact.find((item) => item.kind === "judged_to_bypass");
  const notice = change
    ? `这条绕过会让 ${fmtInt(change.count)} 个原本判定的请求不再判定${
        change.would_block !== undefined ? `，其中本应拦截 ${fmtInt(change.would_block)} 个` : ""
      }`
    : null;
  return (
    <div className="stack">
      <Field
        label="绕过"
        help="命中绕过的请求不判定，直接转发。只用于静态资源，或确实需要上传大文件的接口。"
      >
        <PatternListEditor
          kind="bypass"
          label="绕过"
          rules={spec.bypass ?? []}
          hits={hits?.bypass}
          issues={issues}
          notice={notice}
          presets={mode === "create" ? [{ label: "常见静态资源", rules: STATIC_PATHS }] : []}
          onChange={(bypass) => onChange({ ...spec, bypass })}
        />
      </Field>
      <PatternTester
        entries={spec.entries}
        bypass={spec.bypass ?? []}
        savedEntries={saved?.entries ?? []}
        savedBypass={saved?.bypass ?? []}
      />
    </div>
  );
}

function ModeGroup({
  spec,
  mode,
  onChange,
  onSwitchMode,
  observingText,
}: Pick<Props, "spec" | "mode" | "onChange" | "onSwitchMode" | "observingText">) {
  const current = spec.mode ?? "observe";
  return (
    <div className="stack">
      <Field
        label="模式"
        help={
          mode === "create"
            ? "表单创建的站点从观察模式开始：照常转发，只记录本应拦截的请求。拦截模式在站点创建后，到站点页用“切换到拦截模式…”设置。"
            : "切换模式会生成新版本，并需要先看就绪检查。"
        }
      >
        {mode === "create" ? (
          <span>观察模式</span>
        ) : (
          <div className="row">
            <span>
              {current === "enforce"
                ? "拦截模式"
                : `观察模式${observingText ? `（${observingText}）` : ""}`}
            </span>
            <button type="button" className="btn" onClick={onSwitchMode}>
              切换…
            </button>
          </div>
        )}
      </Field>
      <Field
        label="Jev 不可用时"
        help={
          spec.on_jev_unavailable === "allow"
            ? undefined
            : "Jev 超时、出错或达到调用上限时，请求按拒绝处理（推荐）。"
        }
        warnings={
          spec.on_jev_unavailable === "allow"
            ? ["Jev 不可用时请求不经判定直接放行，记录标为“未经判定”。"]
            : []
        }
      >
        <Segmented
          value={spec.on_jev_unavailable ?? "deny"}
          options={[
            { label: "拒绝（推荐）", value: "deny" },
            { label: "放行", value: "allow" },
          ]}
          onChange={(value) =>
            onChange({ ...spec, on_jev_unavailable: value === "allow" ? "allow" : "deny" })
          }
        />
      </Field>
    </div>
  );
}

/** One group of the configuration form. */
export function ConfigForm(props: Props) {
  switch (props.group) {
    case "basics":
      return <BasicsGroup {...props} />;
    case "session":
      return <SessionGroup {...props} />;
    case "entries":
      return <EntriesGroup {...props} />;
    case "bypass":
      return <BypassGroup {...props} />;
    case "mode":
      return <ModeGroup {...props} />;
  }
}
