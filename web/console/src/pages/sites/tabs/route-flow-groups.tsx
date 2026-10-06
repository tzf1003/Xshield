import { DeleteOutlined, PlusOutlined } from "@ant-design/icons";
import { Button, Input, Select } from "antd";
import { type ReactNode, useId, useState } from "react";
import type {
  SiteAuthBinding,
  SiteIssuedBy,
  SitePageActions,
  SiteResourceGrant,
  SiteRouteConfig,
  SiteSensorHtmlAdapter,
} from "../../../api.ts";
import {
  blockOffered,
  emptySensorBuild,
  type FlowBlock,
  grantTargetOptions,
  MAX_SENSOR_BUILDS,
  pageRootOptions,
  type RouteOption,
  sensorBuilds,
} from "../../../sites/model/route-flow.ts";
import { formatBytes, formatSeconds } from "../../../sites/model/units.ts";
import type { Issue } from "../../../sites/model/validation.ts";
import { Field, IssueLine, NumInput, Toggle } from "../fields";
import { PageDigestPanel } from "./PageDigestPanel";

/** What every flow group needs from the drawer. */
export type FlowGroupProps = Readonly<{
  route: SiteRouteConfig;
  /** The draft's routes; `self` is this route's index among them (`null` while adding). */
  routes: readonly SiteRouteConfig[];
  self: number | null;
  issueFor: (field: string) => Issue | undefined;
  disabled: boolean;
  /** Switches a block on (with the last typed or default values) or off. */
  onToggle: (block: FlowBlock, on: boolean) => void;
  /** Replaces one block's value. */
  onBlock: <K extends FlowBlock>(block: K, value: SiteRouteConfig[K]) => void;
  /** Replaces the page builds (primary first). */
  onBuilds: (builds: SiteSensorHtmlAdapter[]) => void;
}>;

/**
 * Policy-revision reminder for the blocks that make up the edge's action descriptor set: the
 * edge binds that set to the site's policy revision label and refuses a different set under a
 * label it already knows, so the label has to move with the set.
 */
const DESCRIPTOR_NOTE =
  "页面签发动作、由页面签发的路由（操作来源、方法、路径）和资源资格目标共同构成 edge 的动作描述集合（期限与容量不在其中）。改变它时请同时在“安全入口”提升“策略版本”标签：edge 拒绝在已用过的策略版本下换用另一套描述，应用会以 EDGE_APPLY_DESCRIPTOR_CONFLICT 失败。";

/** One flow block: what it does, its switch, the block-level finding, then its fields. */
function FlowGroup({
  title,
  note,
  toggle,
  issue,
  children,
}: {
  title: string;
  note: ReactNode;
  toggle?: { label: string; checked: boolean; onChange: (on: boolean) => void; disabled: boolean };
  issue: Issue | undefined;
  children?: ReactNode;
}) {
  const noteId = useId();
  const issueId = useId();
  return (
    <section className="xs-drawer-group xs-flow-group" aria-label={title}>
      <h4>{title}</h4>
      <p id={noteId} className="muted">
        {note}
      </p>
      {toggle && (
        <div className="xs-flow-toggle">
          <Toggle
            label={toggle.label}
            checked={toggle.checked}
            onChange={toggle.onChange}
            disabled={toggle.disabled}
            onText="开启"
            describedBy={issue ? `${noteId} ${issueId}` : noteId}
          />
        </div>
      )}
      <IssueLine id={issueId} issue={issue} />
      {children}
    </section>
  );
}

const optionLabel = (option: RouteOption) =>
  option.note ? `${option.label}（${option.note}）` : option.label;

/**
 * A route chosen from the draft; a stored value that is no longer offered stays visible. `id`,
 * `status` and `aria-describedby` come from the surrounding `Field` (rc-select puts the aria
 * attributes on its input, so the label and the messages describe the control).
 */
function RouteSelect({
  id,
  status,
  "aria-describedby": describedBy,
  value,
  options,
  empty,
  disabled,
  onChange,
}: {
  id?: string;
  status?: "error" | "warning";
  "aria-describedby"?: string;
  value: string;
  options: readonly RouteOption[];
  empty: string;
  disabled: boolean;
  onChange: (value: string) => void;
}) {
  const known = options.some((option) => option.value === value);
  return (
    <Select
      id={id}
      status={status}
      aria-describedby={describedBy}
      className="xs-route-select"
      value={value === "" ? undefined : value}
      placeholder={options.length === 0 ? empty : "选择一条路由"}
      disabled={disabled}
      notFoundContent={empty}
      onChange={onChange}
      options={[
        ...options.map((option) => ({ value: option.value, label: optionLabel(option) })),
        ...(value !== "" && !known
          ? [{ value, label: `${value}（草稿里没有这条可选的路由）` }]
          : []),
      ]}
    />
  );
}

/** 身份建立: an authentication entry that commits a binding from a strict JSON login response. */
export function AuthBindingGroup(props: FlowGroupProps) {
  const { route, issueFor, disabled, onToggle, onBlock } = props;
  const binding = route.auth_binding;
  if (!binding && !blockOffered(route, "auth_binding")) return null;
  const set = (change: Partial<SiteAuthBinding>) =>
    binding && onBlock("auth_binding", { ...binding, ...change });
  const pointer = (key: keyof SiteAuthBinding, label: string, hint: string) =>
    binding && (
      <Field
        id={`flow-binding-${key}`}
        label={label}
        required
        issue={issueFor(`auth_binding.${key}`)}
        hint={hint}
      >
        <Input
          className="mono"
          value={String(binding[key])}
          maxLength={512}
          spellCheck={false}
          onChange={(event) => set({ [key]: event.target.value } as Partial<SiteAuthBinding>)}
        />
      </Field>
    );
  return (
    <FlowGroup
      title="身份建立"
      note="认证入口在成功验证之前仍是匿名的。开启后，源站以下面的成功状态码返回严格 JSON 时，edge 按三个 JSON 指针读取主体、授权上下文和业务凭证，先提交新的身份绑定、签发 WAF 会话 Cookie，再释放正文；形状不符、状态码不符或提交失败都不建立身份。关闭时这条入口只放行请求，不建立身份。"
      toggle={{
        label: "建立身份",
        checked: binding !== undefined,
        onChange: (on) => onToggle("auth_binding", on),
        disabled,
      }}
      issue={issueFor("auth_binding")}
    >
      {binding && (
        <div className="xs-flow-fields">
          <Field
            id="flow-binding-status"
            label="成功状态码"
            issue={issueFor("auth_binding.success_status")}
            hint="2xx，不能是 204（没有正文就读不到身份）。"
          >
            <NumInput
              value={binding.success_status}
              min={200}
              max={299}
              onChange={(value) => set({ success_status: value })}
            />
          </Field>
          {pointer(
            "principal_pointer",
            "主体指针",
            "JSON 指针，指向登录响应里当前用户的稳定标识，例如 /identity/id；它决定“这是谁”。",
          )}
          {pointer(
            "authorization_context_pointer",
            "授权上下文指针",
            "指向表示当前权限上下文的值（租户、角色组合等），例如 /identity/authorization_context；上下文不同就是另一个身份，旧资格不会被继承。",
          )}
          {pointer(
            "bearer_pointer",
            "业务凭证指针",
            "指向源站签发给浏览器的业务凭证（Bearer），例如 /access_token；之后每个受保护请求都必须同时出示它和 WAF Cookie。三个指针互不相同。",
          )}
          <Field
            id="flow-binding-credential"
            label="凭证期限"
            issue={issueFor("auth_binding.credential_ttl_seconds")}
            hint={`1–86400 秒，不长于会话期限。当前 = ${formatSeconds(binding.credential_ttl_seconds)}。`}
          >
            <NumInput
              value={binding.credential_ttl_seconds}
              min={1}
              max={86_400}
              unit="秒"
              onChange={(value) => set({ credential_ttl_seconds: value })}
            />
          </Field>
          <Field
            id="flow-binding-session"
            label="会话期限"
            issue={issueFor("auth_binding.session_ttl_seconds")}
            hint={`身份绑定的绝对期限，1–86400 秒；到期后必须重新登录。当前 = ${formatSeconds(binding.session_ttl_seconds)}。`}
          >
            <NumInput
              value={binding.session_ttl_seconds}
              min={1}
              max={86_400}
              unit="秒"
              onChange={(value) => set({ session_ttl_seconds: value })}
            />
          </Field>
        </div>
      )}
    </FlowGroup>
  );
}

/** 身份撤销: a logout whose confirmed response revokes the binding's credentials. */
export function AuthRevokeGroup(props: FlowGroupProps) {
  const { route, issueFor, disabled, onToggle, onBlock } = props;
  const revoke = route.auth_revoke;
  if (!revoke && !blockOffered(route, "auth_revoke")) return null;
  return (
    <FlowGroup
      title="身份撤销"
      note="登出：源站以成功状态码返回、且响应完整通过缓冲校验后，edge 撤销当前身份绑定的全部凭证；之后这个 WAF 会话的请求都失败关闭。"
      toggle={{
        label: "撤销身份",
        checked: revoke !== undefined,
        onChange: (on) => onToggle("auth_revoke", on),
        disabled,
      }}
      issue={issueFor("auth_revoke")}
    >
      {revoke && (
        <div className="xs-flow-fields">
          <Field
            id="flow-revoke-status"
            label="成功状态码"
            issue={issueFor("auth_revoke.success_status")}
            hint="2xx，不能是 204–206：edge 要看到完整正文才撤销。"
          >
            <NumInput
              value={revoke.success_status}
              min={200}
              max={299}
              onChange={(value) => onBlock("auth_revoke", { success_status: value })}
            />
          </Field>
        </div>
      )}
    </FlowGroup>
  );
}

/** One approved build: its revision, digest and offset, and the helper that computes the two. */
function BuildFields({
  index,
  build,
  route,
  issueFor,
  disabled,
  onChange,
  onRemove,
}: {
  index: number;
  build: SiteSensorHtmlAdapter;
  route: SiteRouteConfig;
  issueFor: (field: string) => Issue | undefined;
  disabled: boolean;
  onChange: (build: SiteSensorHtmlAdapter) => void;
  onRemove?: () => void;
}) {
  const [helper, setHelper] = useState(false);
  const at = index === 0 ? "sensor_html" : `sensor_html.additional_adapters.${index - 1}`;
  const name = index === 0 ? "主构建" : `附加构建 ${index}`;
  const id = `flow-build-${index}`;
  return (
    <fieldset className="xs-flow-build">
      <legend>{name}</legend>
      <Field
        id={`${id}-revision`}
        label="构建版本"
        required
        issue={issueFor(`${at}.adapter_revision`)}
        hint="给这一版页面起的标识，例如 app-r1；字母、数字和 _ . -。"
      >
        <Input
          value={build.adapter_revision}
          maxLength={128}
          spellCheck={false}
          onChange={(event) => onChange({ ...build, adapter_revision: event.target.value })}
        />
      </Field>
      <Field
        id={`${id}-digest`}
        label="页面摘要（SHA-256）"
        required
        issue={issueFor(`${at}.origin_sha256`)}
        hint="源站返回的完整页面字节的 SHA-256，64 位小写十六进制。"
      >
        <Input
          className="mono"
          value={build.origin_sha256}
          maxLength={64}
          spellCheck={false}
          onChange={(event) => onChange({ ...build, origin_sha256: event.target.value })}
        />
      </Field>
      <Field
        id={`${id}-offset`}
        label="注入偏移（字节）"
        required
        issue={issueFor(`${at}.injection_offset`)}
        hint={`第一个 </head> 在页面字节中的位置（字节，不是字符），须小于响应上限（${formatBytes(route.max_response_bytes)}）。`}
      >
        <NumInput
          value={build.injection_offset}
          min={0}
          unit="字节"
          onChange={(value) => onChange({ ...build, injection_offset: value })}
        />
      </Field>
      <div className="xs-flow-build-actions">
        <Button
          aria-expanded={helper}
          aria-controls={`${id}-helper`}
          disabled={disabled}
          onClick={() => setHelper((open) => !open)}
        >
          {index === 0 ? "从页面源码计算" : `从页面源码计算（${name}）`}
        </Button>
        {onRemove && (
          <Button
            danger
            icon={<DeleteOutlined aria-hidden="true" />}
            disabled={disabled}
            onClick={onRemove}
          >
            移除{name}
          </Button>
        )}
      </div>
      {helper && (
        <div id={`${id}-helper`}>
          <PageDigestPanel
            id={id}
            maxResponseBytes={route.max_response_bytes}
            disabled={disabled}
            onDigest={(digest) =>
              onChange({
                ...build,
                origin_sha256: digest.sha256,
                injection_offset: digest.injectionOffset,
              })
            }
          />
        </div>
      )}
    </fieldset>
  );
}

/** SENSOR_HTML 页面构建: the approved builds of a static page (the response mode turns it on). */
export function SensorHtmlGroup(props: FlowGroupProps) {
  const { route, issueFor, disabled, onBuilds } = props;
  if (!route.sensor_html) return null;
  const builds = sensorBuilds(route);
  const replace = (at: number, build: SiteSensorHtmlAdapter) =>
    onBuilds(builds.map((item, index) => (index === at ? build : item)));
  return (
    <FlowGroup
      title="SENSOR_HTML 页面构建"
      note="edge 只放行完整字节的 SHA-256 与某个已批准构建一致的源站页面，并在该构建的 </head> 处注入浏览器探针；其他字节在释放前一律拒绝。页面必须是 UTF-8、GET，且站点要启用浏览器探针。源站发布新页面时，把新构建加为附加构建，确认生效后再移除旧的。"
      issue={issueFor("sensor_html")}
    >
      {builds.map((build, index) => (
        <BuildFields
          // A build has no identity of its own while its revision is being typed.
          // biome-ignore lint/suspicious/noArrayIndexKey: builds are positional
          key={index}
          index={index}
          build={build}
          route={route}
          issueFor={issueFor}
          disabled={disabled}
          onChange={(next) => replace(index, next)}
          onRemove={
            index === 0 ? undefined : () => onBuilds(builds.filter((_, at) => at !== index))
          }
        />
      ))}
      <Button
        icon={<PlusOutlined aria-hidden="true" />}
        disabled={disabled || builds.length >= MAX_SENSOR_BUILDS}
        onClick={() => onBuilds([...builds, emptySensorBuild()])}
      >
        添加附加构建
      </Button>
      <p className="muted xs-flow-count">
        共 {builds.length} 个构建（最多 {MAX_SENSOR_BUILDS} 个）。
      </p>
    </FlowGroup>
  );
}

/** 页面签发动作: a page root that issues first-hop UI actions on every verified delivery. */
export function PageActionsGroup(props: FlowGroupProps) {
  const { route, routes, self, issueFor, disabled, onToggle, onBlock } = props;
  const page = route.page_actions;
  if (!page && !blockOffered(route, "page_actions")) return null;
  const set = (change: Partial<SitePageActions>) =>
    page && onBlock("page_actions", { ...page, ...change });
  const issued = routes
    .filter((item, index) => index !== self && item.issued_by?.page_operation_id !== undefined)
    .filter((item) => item.issued_by?.page_operation_id === route.operation_id)
    .map((item) => item.operation_id);
  return (
    <FlowGroup
      title="页面签发动作"
      note="每次这个页面通过摘要校验交付时，edge 为当前身份签发由它签发的首跳动作（1–16 个：在列表等路由的“由页面签发”里选择这个页面）。页面根准入只认 WAF 会话，签发的一切都绑定当前身份与代际。"
      toggle={{
        label: "签发页面动作",
        checked: page !== undefined,
        onChange: (on) => onToggle("page_actions", on),
        disabled,
      }}
      issue={issueFor("page_actions")}
    >
      {page && (
        <div className="xs-flow-fields">
          <Field
            id="flow-page-mapping"
            label="映射修订"
            required
            issue={issueFor("page_actions.mapping_revision")}
            hint="页面证据与它签发的全部动作共用的映射修订，例如 app-map-r1；同一操作来源在同一映射修订下只能有一种含义。"
          >
            <Input
              value={page.mapping_revision}
              maxLength={128}
              spellCheck={false}
              onChange={(event) => set({ mapping_revision: event.target.value })}
            />
          </Field>
          <Field
            id="flow-page-capacity"
            label="活动页面上限"
            issue={issueFor("page_actions.max_active_pages")}
            hint="同一身份同时有效的页面实例数，1–1000；达到上限时页面照常交付，但不再签发动作。"
          >
            <NumInput
              value={page.max_active_pages}
              min={1}
              max={1_000}
              onChange={(value) => set({ max_active_pages: value })}
            />
          </Field>
          <p className="muted xs-flow-count">
            {issued.length === 0
              ? "草稿里还没有路由由这个页面签发。"
              : `由它签发：${issued.join("、")}（${issued.length}/16）。`}
          </p>
          <p className="muted xs-flow-count">{DESCRIPTOR_NOTE}</p>
        </div>
      )}
    </FlowGroup>
  );
}

/** 由页面签发: a first-hop UI action that exists only for a session that loaded its page. */
export function IssuedByGroup(props: FlowGroupProps) {
  const { route, routes, self, issueFor, disabled, onToggle, onBlock } = props;
  const issued = route.issued_by;
  if (!issued && !blockOffered(route, "issued_by")) return null;
  const set = (change: Partial<SiteIssuedBy>) =>
    issued && onBlock("issued_by", { ...issued, ...change });
  const options = pageRootOptions(routes, self);
  return (
    <FlowGroup
      title="由页面签发"
      note="首跳界面操作：只有当前身份在本会话中打开过下面这个页面，edge 才会为它签发这个动作，浏览器探针出示动作引用后请求才被放行；没有页面就拒绝。只用于不绑定资源的路由，且这类路由不接受查询串。"
      toggle={{
        label: "由页面签发",
        checked: issued !== undefined,
        onChange: (on) => onToggle("issued_by", on),
        disabled,
      }}
      issue={issueFor("issued_by")}
    >
      {issued && (
        <div className="xs-flow-fields">
          <Field
            id="flow-issued-page"
            label="签发页面"
            required
            issue={issueFor("issued_by.page_operation_id")}
            hint="从草稿里的 SENSOR_HTML 页面中选择；页面需要开启“页面签发动作”。"
          >
            <RouteSelect
              value={issued.page_operation_id}
              options={options}
              empty="草稿里还没有 SENSOR_HTML 页面路由"
              disabled={disabled}
              onChange={(value) => set({ page_operation_id: value })}
            />
          </Field>
          <Field
            id="flow-issued-ttl"
            label="动作期限"
            issue={issueFor("issued_by.ttl_seconds")}
            hint={`1–86400 秒；实际期限取它与身份绑定绝对期限中的较小值。当前 = ${formatSeconds(issued.ttl_seconds)}。`}
          >
            <NumInput
              value={issued.ttl_seconds}
              min={1}
              max={86_400}
              unit="秒"
              onChange={(value) => set({ ttl_seconds: value })}
            />
          </Field>
        </div>
      )}
    </FlowGroup>
  );
}

/** 响应资源资格: a verified list response qualifies each listed resource for one detail action. */
export function ResourceGrantGroup(props: FlowGroupProps) {
  const { route, routes, self, issueFor, disabled, onToggle, onBlock } = props;
  const grant = route.resource_grant;
  if (!grant && !blockOffered(route, "resource_grant")) return null;
  const set = (change: Partial<SiteResourceGrant>) =>
    grant && onBlock("resource_grant", { ...grant, ...change });
  const num = (key: keyof SiteResourceGrant, label: string, hint: string, max: number) =>
    grant && (
      <Field
        id={`flow-grant-${key}`}
        label={label}
        issue={issueFor(`resource_grant.${key}`)}
        hint={hint}
      >
        <NumInput
          value={Number(grant[key])}
          min={1}
          max={max}
          unit={key === "ttl_seconds" ? "秒" : undefined}
          onChange={(value) => set({ [key]: value } as Partial<SiteResourceGrant>)}
        />
      </Field>
    );
  const text = (key: keyof SiteResourceGrant, label: string, hint: string, mono = false) =>
    grant && (
      <Field
        id={`flow-grant-${key}`}
        label={label}
        required
        issue={issueFor(`resource_grant.${key}`)}
        hint={hint}
      >
        <Input
          className={mono ? "mono" : undefined}
          value={String(grant[key])}
          maxLength={key.endsWith("pointer") ? 512 : 128}
          spellCheck={false}
          onChange={(event) => set({ [key]: event.target.value } as Partial<SiteResourceGrant>)}
        />
      </Field>
    );
  return (
    <FlowGroup
      title="响应资源资格"
      note="列表响应以成功状态码返回且通过严格 JSON 校验后，edge 为其中每一项向当前身份签发一个详情动作资格，并把不透明引用写进每项的“动作引用字段”；浏览器打开详情时出示它。开启后这条路由不接受任何查询串，调用者不能借参数选择列出谁的对象。"
      toggle={{
        label: "签发资源资格",
        checked: grant !== undefined,
        onChange: (on) => onToggle("resource_grant", on),
        disabled,
      }}
      issue={issueFor("resource_grant")}
    >
      {grant && (
        <div className="xs-flow-fields">
          <Field
            id="flow-grant-status"
            label="成功状态码"
            issue={issueFor("resource_grant.success_status")}
            hint="2xx，不能是 204。"
          >
            <NumInput
              value={grant.success_status}
              min={200}
              max={299}
              onChange={(value) => set({ success_status: value })}
            />
          </Field>
          {text(
            "items_pointer",
            "列表指针",
            "JSON 指针，指向响应里的条目数组，例如 /orders。",
            true,
          )}
          {text(
            "resource_pointer",
            "资源指针",
            "相对于每一项的 JSON 指针，指向资源值，例如 /id；这个值必须就是详情路由里的资源参数。",
            true,
          )}
          {text(
            "action_ref_field",
            "动作引用字段",
            "edge 写入不透明引用的条目成员名，例如 _xshield_action_ref；源站必须把它留空。",
          )}
          <Field
            id="flow-grant-target"
            label="目标详情路由"
            required
            issue={issueFor("resource_grant.target_operation_id")}
            hint="从草稿里绑定资源的“必须有界面操作来源”路由中选择。"
          >
            <RouteSelect
              value={grant.target_operation_id}
              options={grantTargetOptions(routes, self)}
              empty="草稿里还没有绑定资源的界面操作路由"
              disabled={disabled}
              onChange={(value) => set({ target_operation_id: value })}
            />
          </Field>
          {text(
            "target_mapping_revision",
            "目标映射修订",
            "详情动作描述的映射修订，例如 orders-map-r1。",
          )}
          {num("ttl_seconds", "资格期限", "1–86400 秒。", 86_400)}
          {num("max_items", "单次最多项数", "一次响应最多为多少项签发资格，1–1000。", 1_000)}
          {num("max_active_grants", "活动资格上限", "同一身份同时有效的资格数，1–5000。", 5_000)}
          <p className="muted xs-flow-count">{DESCRIPTOR_NOTE}</p>
        </div>
      )}
    </FlowGroup>
  );
}
