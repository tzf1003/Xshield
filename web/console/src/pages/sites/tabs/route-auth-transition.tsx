import { Input } from "antd";
import type { SiteAuthTransition } from "../../../api.ts";
import { blockOffered, type FlowBlock } from "../../../sites/model/route-flow.ts";
import { formatSeconds } from "../../../sites/model/units.ts";
import { Field, NumInput } from "../fields";
import { FlowGroup, type FlowGroupProps } from "./route-flow-groups";

type Key = Extract<FlowBlock, "auth_refresh" | "auth_context_switch">;

const COPY: Readonly<Record<Key, { label: string; note: string; id: string }>> = {
  auth_refresh: {
    label: "刷新凭证",
    id: "refresh",
    note: "同一主体、同一授权上下文换发新的业务凭证：源站以成功状态码返回严格 JSON 且主体与上下文都与当前绑定一致时，edge 先提交新凭证再释放正文；不一致、形状不符或提交失败都不替换。不延长会话期限。",
  },
  auth_context_switch: {
    label: "切换授权上下文",
    id: "switch",
    note: "账号或授权上下文切换：edge 按三个 JSON 指针读取新的授权上下文，先提交新的身份代际（旧上下文的资格不会被继承）再释放正文，并让探针丢弃已缓存的引用。它决定之后的请求对谁的数据有效。",
  },
};

function Transition({ block, ...props }: FlowGroupProps & { block: Key }) {
  const { route, issueFor, disabled, onToggle, onBlock } = props;
  const value = route[block];
  if (!value && !blockOffered(route, block)) return null;
  const copy = COPY[block];
  const set = (change: Partial<SiteAuthTransition>) =>
    value && onBlock(block, { ...value, ...change });
  const pointer = (
    key: "principal_pointer" | "authorization_context_pointer" | "bearer_pointer",
    label: string,
    hint: string,
  ) =>
    value && (
      <Field
        id={`flow-${copy.id}-${key}`}
        label={label}
        required
        issue={issueFor(`${block}.${key}`)}
        hint={hint}
      >
        <Input
          className="mono"
          value={value[key]}
          maxLength={512}
          spellCheck={false}
          onChange={(event) => set({ [key]: event.target.value })}
        />
      </Field>
    );
  return (
    <FlowGroup
      title={copy.label}
      note={`${copy.note} 只有独立审批人能批准它的变更。`}
      toggle={{
        label: copy.label,
        checked: value !== undefined,
        onChange: (on) => onToggle(block, on),
        disabled,
      }}
      issue={issueFor(block)}
    >
      {value && (
        <div className="xs-flow-fields">
          <Field
            id={`flow-${copy.id}-status`}
            label="成功状态码"
            issue={issueFor(`${block}.success_status`)}
            hint="2xx，不能是 204（没有正文就读不到身份）。"
          >
            <NumInput
              value={value.success_status}
              min={200}
              max={299}
              onChange={(next) => set({ success_status: next })}
            />
          </Field>
          {pointer(
            "principal_pointer",
            "主体指针",
            "JSON 指针，指向响应里当前用户的稳定标识，例如 /identity/id。",
          )}
          {pointer(
            "authorization_context_pointer",
            "授权上下文指针",
            "指向表示权限上下文的值，例如 /identity/authorization_context；上下文不同就是另一个身份。",
          )}
          {pointer(
            "bearer_pointer",
            "业务凭证指针",
            "指向替换后的业务凭证（Bearer），例如 /access_token。三个指针互不相同。",
          )}
          <Field
            id={`flow-${copy.id}-credential`}
            label="凭证期限"
            issue={issueFor(`${block}.credential_ttl_seconds`)}
            hint={`1–86400 秒。当前 = ${formatSeconds(value.credential_ttl_seconds)}。`}
          >
            <NumInput
              value={value.credential_ttl_seconds}
              min={1}
              max={86_400}
              unit="秒"
              onChange={(next) => set({ credential_ttl_seconds: next })}
            />
          </Field>
        </div>
      )}
    </FlowGroup>
  );
}

/**
 * 凭证刷新与上下文切换: two switchable blocks of an authenticated root. Each is its own
 * section (heading, switch, fields) so they read and scan like the other flow groups.
 */
export function AuthTransitionGroup(props: FlowGroupProps) {
  return (
    <>
      <Transition {...props} block="auth_refresh" />
      <Transition {...props} block="auth_context_switch" />
    </>
  );
}
