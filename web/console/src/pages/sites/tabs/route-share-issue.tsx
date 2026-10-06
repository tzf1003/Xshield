import { Input } from "antd";
import type { SiteShareIssue } from "../../../api.ts";
import { blockOffered, shareTargetOptions } from "../../../sites/model/route-flow.ts";
import { formatSeconds } from "../../../sites/model/units.ts";
import { Field, NumInput } from "../fields";
import { FlowGroup, type FlowGroupProps, RouteSelect } from "./route-flow-groups";

/**
 * Where the rule row comes from. The edge issues only under a `share_issuance_rules` row keyed by
 * (tenant, site, policy_revision, rule id); the control plane writes exactly that row, derived
 * from this block and the two routes it names, in the transaction of the independent approval
 * that makes the revision eligible, and never rewrites it.
 */
const RULE_NOTE =
  "发放规则 ID 对应 xshield.share_issuance_rules 里的一行（租户、站点、策略版本、规则 ID、发放方与分享入口的操作和视图、最长期限＝期限秒数）。控制面在独立审批通过时按这一块自动登记这一行，登记后不会被改写：之后改变期限、视图或目标，请换一个新的发放规则 ID（或策略版本）。同时需要 edge 启动时配置分享令牌密钥。";

/**
 * 分享凭据发放: a successful JSON response from a UI-action resource route gets one extra
 * member carrying a reusable read-only credential for exactly the resource the request was
 * qualified for, redeemable only at the chosen 分享入口 route and nowhere else.
 */
export function ShareIssueGroup(props: FlowGroupProps) {
  const { route, routes, self, issueFor, disabled, onToggle, onBlock } = props;
  const share = route.share_issue;
  if (!share && !blockOffered(route, "share_issue")) return null;
  const set = (change: Partial<SiteShareIssue>) =>
    share && onBlock("share_issue", { ...share, ...change });
  const num = (
    key: "max_active_shares" | "ttl_seconds",
    label: string,
    hint: string,
    max: number,
  ) =>
    share && (
      <Field
        id={`flow-share-${key}`}
        label={label}
        issue={issueFor(`share_issue.${key}`)}
        hint={hint}
      >
        <NumInput
          value={share[key]}
          min={1}
          max={max}
          unit={key === "ttl_seconds" ? "秒" : undefined}
          onChange={(value) => set({ [key]: value })}
        />
      </Field>
    );
  const text = (key: "token_field" | "issuance_rule_id", label: string, hint: string) =>
    share && (
      <Field
        id={`flow-share-${key}`}
        label={label}
        required
        issue={issueFor(`share_issue.${key}`)}
        hint={hint}
      >
        <Input
          value={share[key]}
          maxLength={128}
          spellCheck={false}
          onChange={(event) => set({ [key]: event.target.value })}
        />
      </Field>
    );
  return (
    <FlowGroup
      title="分享凭据发放"
      note="这条路由的成功 JSON 响应通过校验、且 edge 已提交分享记录后，响应对象里会多出一个“凭据字段”，装着只读、可重复使用的分享凭据，只对本次请求已被资格限定的那一个资源有效，只能在下面选定的“分享入口”路由出示。源站响应里不能已有这个字段（null 也算已有）；响应不能加密。"
      toggle={{
        label: "发放分享凭据",
        checked: share !== undefined,
        onChange: (on) => onToggle("share_issue", on),
        disabled,
      }}
      issue={issueFor("share_issue")}
    >
      {share && (
        <div className="xs-flow-fields">
          <Field
            id="flow-share-status"
            label="成功状态码"
            issue={issueFor("share_issue.success_status")}
            hint="2xx，不能是 204–206：edge 要看到完整 JSON 正文才追加凭据。"
          >
            <NumInput
              value={share.success_status}
              min={200}
              max={299}
              onChange={(value) => set({ success_status: value })}
            />
          </Field>
          {text("token_field", "凭据字段名", "edge 追加到响应对象里的成员名，例如 share_token。")}
          <Field
            id="flow-share-target"
            label="目标分享入口"
            required
            issue={issueFor("share_issue.target_operation_id")}
            hint="从草稿里的“分享入口”GET 路由中选择：资源类型须与本路由相同，并以查询字段定位资源。"
          >
            <RouteSelect
              value={share.target_operation_id}
              options={shareTargetOptions(routes, self)}
              empty="草稿里还没有“分享入口”路由"
              disabled={disabled}
              onChange={(value) => set({ target_operation_id: value })}
            />
          </Field>
          {text(
            "issuance_rule_id",
            "发放规则 ID",
            "独立批准的发放规则标识，例如 record-share-r1。",
          )}
          {num(
            "ttl_seconds",
            "分享期限",
            `1–86400 秒；实际期限不会超过规则行允许的最长期限。当前 = ${formatSeconds(share.ttl_seconds)}。`,
            86_400,
          )}
          {num("max_active_shares", "活动分享上限", "同一身份同时有效的分享数，1–5000。", 5_000)}
          <p className="muted xs-flow-count">{RULE_NOTE}</p>
        </div>
      )}
    </FlowGroup>
  );
}
