import { Button, Input, Select } from "antd";
import { type ReactNode, useId } from "react";
import type {
  PaginationKind,
  SiteAuthBinding,
  SiteQueryPagination,
  SiteIssuedBy,
  SitePageActions,
  SiteResourceGrant,
  SiteRouteConfig,
  SiteSensorHtmlAdapter,
} from "../../../api.ts";
import {
  blockOffered,
  DEFAULT_MAX_PAGE_SIZE,
  emptyQueryParameter,
  type FlowBlock,
  grantTargetOptions,
  MAX_QUERY_PARAMETERS,
  PAGE_SIZE_CEILING,
  pageRootOptions,
  type RouteOption,
  withQueryParameter,
} from "../../../sites/model/route-flow.ts";
import { formatSeconds } from "../../../sites/model/units.ts";
import type { Issue } from "../../../sites/model/validation.ts";
import { Field, IssueLine, NumInput, Toggle } from "../fields";

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
  "页面签发动作、由页面签发的路由（操作来源、方法、路径）和资源资格目标共同构成 edge 的动作描述集合（期限与容量不在其中）。改变它时请同时在“安全入口”提升“策略版本”标签：同一个标签只能对应一套描述，控制面在保存、校验、批准和应用时都会拒绝重用（CONTROL_SITE_POLICY_REVISION_REUSED），edge 也不接受（EDGE_APPLY_DESCRIPTOR_CONFLICT）。";

/** One flow block: what it does, its switch, the block-level finding, then its fields. */
export function FlowGroup({
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
export function RouteSelect({
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
      note="列表响应以成功状态码返回且通过严格 JSON 校验后，edge 为其中每一项向当前身份签发一个详情动作资格，并把不透明引用写进每项的“动作引用字段”；浏览器打开详情时出示它。默认这条路由不接受任何查询串，调用者不能借参数选择列出谁的对象；需要翻页时在下方“分页参数”声明。"
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

const KIND_LABEL: Readonly<Record<PaginationKind, string>> = {
  page: "页码 page（1–10000）",
  page_size: "页长 page_size（1–上限）",
  offset: "偏移 offset（0–1000000）",
};

/**
 * 分页参数: the only query string a list that issues grants (or a non-resource UI action) may
 * carry. Values are plain digits within fixed ranges and the origin receives a query the edge
 * rebuilt, so the caller still cannot choose whose objects are listed.
 */
export function QueryPaginationGroup(props: FlowGroupProps) {
  const { route, issueFor, disabled, onToggle, onBlock } = props;
  const block = route.query_pagination;
  if (!block && !blockOffered(route, "query_pagination")) return null;
  const replace = (next: SiteQueryPagination) => onBlock("query_pagination", next);
  return (
    <FlowGroup
      title="分页参数"
      note="默认这条路由不接受任何查询串。声明后只接受下列分页参数，每个至多一次，值只能是十进制数字（不带前导零、不做任何编码），否则以 FIELD_NOT_ALLOWED 拒绝；转发给源站的查询串由 edge 按声明顺序重建。没有游标或不透明类型：它们可能编码出“列出谁的对象”。变更需独立审批人批准。"
      toggle={{
        label: "接受分页参数",
        checked: block !== undefined,
        onChange: (on) => onToggle("query_pagination", on),
        disabled,
      }}
      issue={issueFor("query_pagination")}
    >
      {block && (
        <div className="xs-flow-fields">
          {block.parameters.map((parameter, at) => {
            const field = `query_pagination.parameters.${at}`;
            return (
              // biome-ignore lint/suspicious/noArrayIndexKey: parameters have no identity; they are edited in place by position
              <fieldset key={at} className="xs-flow-fields" aria-label={`分页参数 ${at + 1}`}>
                <Field
                  id={`flow-paging-name-${at}`}
                  label={`参数名 ${at + 1}`}
                  required
                  issue={issueFor(`${field}.name`)}
                  hint="小写字母 a–z 与下划线，1–32 个字符，例如 page；不能与任何路由的资源参数同名。"
                >
                  <Input
                    className="mono"
                    value={parameter.name}
                    maxLength={64}
                    spellCheck={false}
                    onChange={(event) =>
                      replace(withQueryParameter(block, at, { name: event.target.value }))
                    }
                  />
                </Field>
                <Field id={`flow-paging-kind-${at}`} label={`类型 ${at + 1}`}>
                  <Select<PaginationKind>
                    value={parameter.kind}
                    disabled={disabled}
                    options={(Object.keys(KIND_LABEL) as PaginationKind[]).map((value) => ({
                      value,
                      label: KIND_LABEL[value],
                    }))}
                    onChange={(value) => replace(withQueryParameter(block, at, { kind: value }))}
                  />
                </Field>
                {parameter.kind === "page_size" && (
                  <Field
                    id={`flow-paging-max-${at}`}
                    label={`页长上限 ${at + 1}`}
                    issue={issueFor(`${field}.max_value`)}
                    hint={`1–${PAGE_SIZE_CEILING}，留空为默认 ${DEFAULT_MAX_PAGE_SIZE}。`}
                  >
                    <NumInput
                      value={parameter.max_value ?? Number.NaN}
                      min={1}
                      max={PAGE_SIZE_CEILING}
                      onChange={(value) =>
                        replace(
                          withQueryParameter(block, at, {
                            max_value: Number.isFinite(value) ? value : undefined,
                          }),
                        )
                      }
                    />
                  </Field>
                )}
                <Button
                  size="small"
                  disabled={disabled || block.parameters.length <= 1}
                  onClick={() =>
                    replace({ parameters: block.parameters.filter((_, index) => index !== at) })
                  }
                >
                  删除参数 {at + 1}
                </Button>
              </fieldset>
            );
          })}
          <Button
            size="small"
            disabled={disabled || block.parameters.length >= MAX_QUERY_PARAMETERS}
            onClick={() => replace({ parameters: [...block.parameters, emptyQueryParameter()] })}
          >
            添加参数
          </Button>
        </div>
      )}
    </FlowGroup>
  );
}
