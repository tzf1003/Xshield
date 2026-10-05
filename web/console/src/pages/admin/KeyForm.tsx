import { DeleteOutlined, PlusOutlined, WarningOutlined } from "@ant-design/icons";
import { Alert, AutoComplete, Button, Checkbox, Input, Radio } from "antd";
import { useId } from "react";
import type { SiteListItem } from "../../api.ts";
import {
  applyDirectWarning,
  type Capability,
  type CapabilityInfo,
  capabilityCatalog,
  EXPIRY_MAX_MS,
  type ExpiryChoice,
  expiryInstant,
  issuerGaps,
  type KeyDraft,
  SCOPES_MAX,
  type ScopeRow,
  scopeProblems,
} from "../../operations/api-keys.ts";
import { roleName } from "../../operations/roles.ts";
import { TimeStamp } from "../../ui/TimeStamp";
import { Field } from "../../work/Parts";

const siteCapabilities = capabilityCatalog.filter((info) => !info.tenantWide);
const tenantCapabilities = capabilityCatalog.filter((info) => info.tenantWide);

let rowCounter = 0;
export function newScopeRow(target: ScopeRow["target"] = "site"): ScopeRow {
  rowCounter += 1;
  return { id: `scope-${rowCounter}`, target, siteId: "", capabilities: [] };
}

export type KeyFormProblems = Readonly<{
  subject: string | null;
  displayName: string | null;
  expiry: string | null;
}>;

function CapabilityBox({
  info,
  checked,
  onChange,
}: {
  info: CapabilityInfo;
  checked: boolean;
  onChange: (checked: boolean) => void;
}) {
  const direct = info.name === "site.config.apply_direct";
  return (
    <div className={`xs-key-cap${direct ? " is-direct" : ""}`}>
      <Checkbox checked={checked} onChange={(event) => onChange(event.target.checked)}>
        <span className="xs-key-cap-name">{info.label}</span>{" "}
        <code className="mono xs-key-cap-code">{info.name}</code>
      </Checkbox>
      <small className="xs-key-cap-help">{info.description}</small>
      {direct && (
        <small className="xs-key-cap-warn">
          <WarningOutlined aria-hidden="true" /> {applyDirectWarning}
        </small>
      )}
    </div>
  );
}

function ScopeEditor({
  row,
  index,
  sites,
  sitesHint,
  problems,
  removable,
  onChange,
  onRemove,
}: {
  row: ScopeRow;
  index: number;
  sites: readonly SiteListItem[];
  sitesHint: string | null;
  problems: readonly string[];
  removable: boolean;
  onChange: (row: ScopeRow) => void;
  onRemove: () => void;
}) {
  const siteInput = useId();
  const catalog = row.target === "tenant" ? tenantCapabilities : siteCapabilities;
  const set = (name: Capability, on: boolean) =>
    onChange({
      ...row,
      capabilities: on
        ? [...row.capabilities.filter((value) => value !== name), name]
        : row.capabilities.filter((value) => value !== name),
    });
  return (
    <fieldset className="xs-key-scope">
      <legend>范围 {index + 1}</legend>
      <div className="xs-w-between">
        <Radio.Group
          value={row.target}
          optionType="button"
          aria-label={`范围 ${index + 1} 的对象`}
          options={[
            { value: "site", label: "一个站点" },
            { value: "tenant", label: "整个租户（仅创建站点）" },
          ]}
          onChange={(event) =>
            onChange({
              ...row,
              target: event.target.value as ScopeRow["target"],
              siteId: "",
              capabilities: event.target.value === "tenant" ? ["site.create"] : [],
            })
          }
        />
        {removable && (
          <Button
            type="text"
            danger
            icon={<DeleteOutlined aria-hidden="true" />}
            aria-label={`删除范围 ${index + 1}`}
            onClick={onRemove}
          >
            删除
          </Button>
        )}
      </div>
      {row.target === "site" ? (
        <div className="xs-w-field">
          <label htmlFor={siteInput}>站点</label>
          <AutoComplete
            id={siteInput}
            value={row.siteId}
            placeholder="选择站点，或输入站点 ID"
            options={sites.map((site) => ({
              value: site.site_id,
              label: `${site.display_name}（${site.site_id}）`,
            }))}
            filterOption={(input, option) =>
              String(option?.label ?? "")
                .toLowerCase()
                .includes(input.toLowerCase())
            }
            onChange={(value: string) => onChange({ ...row, siteId: value.trim() })}
          />
          {sitesHint && <small className="xs-w-muted">{sitesHint}</small>}
        </div>
      ) : (
        <p className="xs-w-muted">
          “创建站点”不依附于任何已存在的站点，只能授予整个租户（服务端标记为 <code>__tenant__</code>
          ）；这一行不能搭配其他能力。
        </p>
      )}
      <fieldset className="xs-key-caps">
        <legend className="xs-visually-hidden">范围 {index + 1} 的能力</legend>
        {catalog.map((info) => (
          <CapabilityBox
            key={info.name}
            info={info}
            checked={row.capabilities.includes(info.name)}
            onChange={(on) => set(info.name, on)}
          />
        ))}
      </fieldset>
      {problems.length > 0 && (
        <ul className="xs-key-problems" aria-label={`范围 ${index + 1} 的问题`}>
          {problems.map((problem) => (
            <li key={problem}>{problem}</li>
          ))}
        </ul>
      )}
    </fieldset>
  );
}

const presets: readonly { value: string; label: string; choice: ExpiryChoice }[] = [
  { value: "7", label: "7 天", choice: { kind: "preset", days: 7 } },
  { value: "30", label: "30 天", choice: { kind: "preset", days: 30 } },
  { value: "90", label: "90 天（上限）", choice: { kind: "preset", days: 90 } },
];

function expiryValue(choice: ExpiryChoice): string {
  return choice.kind === "preset" ? String(choice.days) : "custom";
}

/**
 * The fields of a create or rotate request: name, agent subject, expiry and the scope rows.
 * `showProblems` turns on the per-field messages after the first submit attempt; the issuer
 * warning and the direct-apply warning are always live.
 */
export function KeyForm({
  draft,
  onChange,
  roles,
  sites,
  sitesHint,
  showProblems,
  problems,
  identityLocked = false,
}: {
  draft: KeyDraft;
  onChange: (draft: KeyDraft) => void;
  roles: readonly string[] | null;
  sites: readonly SiteListItem[];
  sitesHint: string | null;
  showProblems: boolean;
  problems: KeyFormProblems;
  identityLocked?: boolean;
}) {
  const ids = { name: useId(), subject: useId(), expiry: useId() };
  const scopeCheck = scopeProblems(draft.scopes);
  const gaps = issuerGaps(draft.scopes, roles);
  const now = Date.now();
  const instant = expiryInstant(draft.expiry, now);
  const latest = new Date(now + EXPIRY_MAX_MS);
  const customMax = `${latest.getFullYear()}-${String(latest.getMonth() + 1).padStart(2, "0")}-${String(latest.getDate()).padStart(2, "0")}T00:00`;
  return (
    <div className="xs-w-stack">
      <Field
        id={ids.name}
        label="名称"
        help="给人看的名字，1–128 个字符，可以使用中文。"
        error={showProblems ? problems.displayName : null}
      >
        <Input
          id={ids.name}
          value={draft.displayName}
          maxLength={128}
          disabled={identityLocked}
          aria-describedby={`${ids.name}-help`}
          status={showProblems && problems.displayName ? "error" : undefined}
          onChange={(event) => onChange({ ...draft, displayName: event.target.value })}
        />
      </Field>
      <Field
        id={ids.subject}
        label="Agent 主体"
        help="写入审计的标签，例如 agent-deploy-bot：1–128 个 ASCII 字母、数字或 . _ : @ / -，以字母或数字开头。审计主体会是 apikey:{Key ID}:{主体}。"
        error={showProblems ? problems.subject : null}
      >
        <Input
          id={ids.subject}
          className="mono"
          value={draft.subject}
          maxLength={128}
          autoComplete="off"
          spellCheck={false}
          disabled={identityLocked}
          aria-describedby={`${ids.subject}-help`}
          status={showProblems && problems.subject ? "error" : undefined}
          onChange={(event) => onChange({ ...draft, subject: event.target.value })}
        />
      </Field>
      <div className="xs-w-field">
        <span className="xs-key-label" id={`${ids.expiry}-label`}>
          到期时间
        </span>
        <Radio.Group
          aria-labelledby={`${ids.expiry}-label`}
          value={expiryValue(draft.expiry)}
          optionType="button"
          options={[
            ...presets.map((preset) => ({ value: preset.value, label: preset.label })),
            { value: "custom", label: "自定义" },
          ]}
          onChange={(event) => {
            const preset = presets.find((item) => item.value === event.target.value);
            onChange({
              ...draft,
              expiry: preset ? preset.choice : { kind: "custom", local: "" },
            });
          }}
        />
        {draft.expiry.kind === "custom" && (
          <Input
            id={ids.expiry}
            type="datetime-local"
            aria-label="自定义到期时间（本地时间）"
            value={draft.expiry.local}
            max={customMax}
            status={showProblems && problems.expiry ? "error" : undefined}
            onChange={(event) =>
              onChange({ ...draft, expiry: { kind: "custom", local: event.target.value } })
            }
          />
        )}
        <small
          className={showProblems && problems.expiry ? "xs-w-error" : "xs-w-muted"}
          aria-live="polite"
        >
          {instant.ms !== null ? (
            <>
              将于 <TimeStamp value={instant.ms} /> 到期。服务端只接受 90 天以内的到期时间。
            </>
          ) : (
            (instant.problem ?? "")
          )}
        </small>
      </div>
      <div className="xs-w-stack">
        <div>
          <span className="xs-key-label">范围</span>
          <p className="xs-w-muted">
            Key 没有角色，只有逐行列出的“站点 ×
            能力”。每一行单独授权，不会合并多行，也不会把一种能力当作另一种的超集；Key
            永远不能访问调查、证据、案件、会话或 Key 管理接口，也不能删除或批准站点。
          </p>
        </div>
        {draft.scopes.map((row, index) => (
          <ScopeEditor
            key={row.id}
            row={row}
            index={index}
            sites={sites}
            sitesHint={sitesHint}
            problems={showProblems ? (scopeCheck.rows.get(row.id) ?? []) : []}
            removable={draft.scopes.length > 1}
            onChange={(next) =>
              onChange({
                ...draft,
                scopes: draft.scopes.map((item) => (item.id === row.id ? next : item)),
              })
            }
            onRemove={() =>
              onChange({ ...draft, scopes: draft.scopes.filter((item) => item.id !== row.id) })
            }
          />
        ))}
        {showProblems && scopeCheck.overall.length > 0 && (
          <p className="xs-w-error">{scopeCheck.overall.join("；")}</p>
        )}
        <span>
          <Button
            icon={<PlusOutlined aria-hidden="true" />}
            disabled={draft.scopes.length >= SCOPES_MAX}
            onClick={() => onChange({ ...draft, scopes: [...draft.scopes, newScopeRow()] })}
          >
            添加一行范围
          </Button>
        </span>
      </div>
      {gaps.length > 0 && (
        <Alert
          type="warning"
          showIcon
          title="当前会话可能无权签发其中的能力"
          description={
            <>
              <p>
                签发者只能授予自己能行使的能力；只要有一项超出，服务端就以
                CONTROL_API_KEY_SCOPE_FORBIDDEN 拒绝整个请求，不会裁剪后继续。
              </p>
              <ul className="xs-key-problems">
                {gaps.map((gap) => (
                  <li key={gap.capability}>
                    <code className="mono">{gap.capability}</code> 需要{" "}
                    {gap.missing.map(roleName).join(" 与 ")}
                  </li>
                ))}
              </ul>
            </>
          }
        />
      )}
    </div>
  );
}
