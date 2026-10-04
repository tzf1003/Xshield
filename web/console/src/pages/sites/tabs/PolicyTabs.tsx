import { DeleteOutlined, PlusOutlined } from "@ant-design/icons";
import { Button, Card, Form, Input, Radio, Select, Table, type TableColumnsType, Tag } from "antd";
import { useEffect, useState } from "react";
import type { SiteSecretReference } from "../../../api.ts";
import { MAX_SECRET_REFS } from "../../../sites/model/config.ts";
import { formatBytes, formatMillis, formatSeconds } from "../../../sites/model/units.ts";
import { Field, NumInput, Toggle } from "../fields";
import type { WorkspaceApi } from "../workspace/use-workspace.ts";
import { HealthPanel } from "./HealthPanel";

const off = (ws: WorkspaceApi) => ws.locked || !ws.access.canConfigure;

/** 身份: the identity binding settings and the cookie/header the policy fixes. */
export function IdentityTab({ ws }: { ws: WorkspaceApi }) {
  const draft = ws.draft;
  if (!draft) return null;
  const identity = draft.policy.identity;
  const patch = (change: Partial<typeof identity>) =>
    ws.setPolicy("identity", { ...identity, ...change });
  return (
    <Form layout="vertical" className="xs-form" disabled={off(ws)}>
      <div className="xs-cards">
        <Card title="身份绑定" className="xs-card">
          <Form.Item
            label="启用身份绑定"
            extra="控制是否启用站点的身份绑定设置。入口或路由要求认证、界面来源时，edge 会按需建立身份存储。"
          >
            <Toggle
              label="启用身份绑定"
              checked={identity.enabled}
              onChange={(enabled) => patch({ enabled })}
            />
          </Form.Item>
          <Field
            id="identity-profile"
            label="身份 profile"
            issue={ws.issueFor("identity.profile")}
            hint="身份绑定使用的 profile 名称，默认 default；它与调查页里的资格、绑定记录对应。"
          >
            <Input
              value={identity.profile}
              maxLength={128}
              spellCheck={false}
              onChange={(event) => patch({ profile: event.target.value })}
            />
          </Field>
          <Field
            id="identity-ttl"
            label="会话期限"
            issue={ws.issueFor("identity.session_ttl_seconds")}
            hint={`匿名会话的有效期，1–86400 秒。当前 = ${formatSeconds(identity.session_ttl_seconds)}。`}
          >
            <NumInput
              value={identity.session_ttl_seconds}
              min={1}
              max={86_400}
              unit="秒"
              onChange={(value) => patch({ session_ttl_seconds: value })}
            />
          </Field>
          <Field
            id="identity-generation"
            label="身份代际"
            issue={ws.issueFor("identity.generation")}
            hint="随绑定记录一并校验的代际号，不小于 1。修改它属于安全相关变更，需要审批。"
          >
            <NumInput
              value={identity.generation}
              min={1}
              onChange={(value) => patch({ generation: value })}
            />
          </Field>
        </Card>
        <Card title="固定项" className="xs-card">
          <Field
            id="identity-cookie"
            label="会话 Cookie"
            hint="由安全策略固定，避免跨站身份绑定被改写。"
          >
            <Input value={identity.cookie_name} readOnly />
          </Field>
          <Field id="identity-header" label="业务凭证头" hint="由安全策略固定，不能修改。">
            <Input value={identity.credential_header} readOnly />
          </Field>
        </Card>
      </div>
    </Form>
  );
}

const stateText: Record<SiteSecretReference["state"], { label: string; color: string }> = {
  active: { label: "使用中", color: "success" },
  pending_rotation: { label: "待轮换", color: "warning" },
  retired: { label: "已退役", color: "default" },
  unavailable: { label: "不可用", color: "error" },
};
const kindText: Record<SiteSecretReference["kind"], string> = {
  tls: "TLS",
  session_hmac: "会话 HMAC",
  request_crypto: "请求加密",
  response_crypto: "响应加密",
  model: "模型",
};

/** 加密: the protocol adapter and the secret references (references only, never secrets). */
export function CryptoTab({ ws }: { ws: WorkspaceApi }) {
  const draft = ws.draft;
  if (!draft) return null;
  const { crypto, secret_refs: secrets } = draft.policy;
  const patch = (change: Partial<typeof crypto>) =>
    ws.setPolicy("crypto", { ...crypto, ...change });
  const patchSecret = (index: number, change: Partial<SiteSecretReference>) =>
    ws.setPolicy(
      "secret_refs",
      secrets.map((secret, at) => (at === index ? { ...secret, ...change } : secret)),
    );
  const used = new Set(secrets.map((secret) => secret.kind));
  const nextKind = (Object.keys(kindText) as SiteSecretReference["kind"][]).find(
    (kind) => !used.has(kind),
  );
  type SecretRow = { secret: SiteSecretReference; index: number };
  const columns: TableColumnsType<SecretRow> = [
    {
      title: "用途",
      key: "kind",
      width: 150,
      render: (_, { secret, index }) => (
        <Select
          aria-label={`密钥引用 ${index + 1} 用途`}
          value={secret.kind}
          options={Object.entries(kindText).map(([value, label]) => ({ value, label }))}
          onChange={(kind) => patchSecret(index, { kind })}
        />
      ),
    },
    {
      title: "Secret reference",
      key: "ref",
      render: (_, { secret, index }) => {
        const issue = ws.issueFor(`secret_refs[${index}].secret_ref`);
        return (
          <Input
            aria-label={`密钥引用 ${index + 1} Secret reference`}
            status={issue ? "error" : undefined}
            placeholder="secret://sites/shop/session"
            value={secret.secret_ref}
            maxLength={512}
            spellCheck={false}
            onChange={(event) => patchSecret(index, { secret_ref: event.target.value })}
          />
        );
      },
    },
    {
      title: "Key ID",
      key: "key",
      width: 180,
      render: (_, { secret, index }) => {
        const issue = ws.issueFor(`secret_refs[${index}].key_id`);
        return (
          <Input
            aria-label={`密钥引用 ${index + 1} Key ID`}
            status={issue ? "error" : undefined}
            value={secret.key_id}
            maxLength={128}
            spellCheck={false}
            onChange={(event) => patchSecret(index, { key_id: event.target.value })}
          />
        );
      },
    },
    {
      title: "状态",
      key: "state",
      width: 150,
      render: (_, { secret, index }) => (
        <Select
          aria-label={`密钥引用 ${index + 1} 状态`}
          value={secret.state}
          options={Object.entries(stateText).map(([value, item]) => ({
            value,
            label: <Tag color={item.color}>{item.label}</Tag>,
          }))}
          onChange={(state) => patchSecret(index, { state })}
        />
      ),
    },
    {
      title: "",
      key: "remove",
      width: 90,
      render: (_, { index }) => (
        <Button
          type="text"
          danger
          icon={<DeleteOutlined aria-hidden="true" />}
          aria-label={`移除密钥引用 ${index + 1}`}
          onClick={() =>
            ws.setPolicy(
              "secret_refs",
              secrets.filter((_, at) => at !== index),
            )
          }
        />
      ),
    },
  ];
  const secretIssues = ws.issues.filter((issue) => issue.path.startsWith("secret_refs"));
  return (
    <Form layout="vertical" className="xs-form" disabled={off(ws)}>
      <div className="xs-cards">
        <Card title="协议适配" className="xs-card">
          <Field
            id="crypto-adapter"
            label="协议适配器"
            issue={ws.issueFor("crypto.adapter_revision")}
            hint="加密适配器的版本标识，例如 observe-v1。"
          >
            <Input
              value={crypto.adapter_revision}
              maxLength={128}
              spellCheck={false}
              onChange={(event) => patch({ adapter_revision: event.target.value })}
            />
          </Field>
          <Field
            id="crypto-failure"
            group
            label="失败策略"
            issue={ws.issueFor("crypto.failure_strategy")}
          >
            <Radio.Group
              aria-label="失败策略"
              className="xs-choice"
              value={crypto.failure_strategy}
              onChange={(event) => patch({ failure_strategy: event.target.value })}
            >
              <Radio value="fail_closed">
                <span className="xs-choice-title">严格拒绝</span>
                <span className="xs-choice-hint">解密或校验失败的请求被拒绝。</span>
              </Radio>
              <Radio value="observe">
                <span className="xs-choice-title">仅观察</span>
                <span className="xs-choice-hint">只记录失败，不拒绝请求。</span>
              </Radio>
            </Radio.Group>
          </Field>
          <Field id="crypto-protocol" label="协议版本" hint="可选，例如 v2；留空表示不指定。">
            <Input
              value={crypto.protocol_version ?? ""}
              maxLength={128}
              spellCheck={false}
              onChange={(event) => patch({ protocol_version: event.target.value || null })}
            />
          </Field>
        </Card>
        <Card
          title="密钥引用"
          className="xs-card xs-card-wide"
          extra={
            <Button
              icon={<PlusOutlined aria-hidden="true" />}
              disabled={off(ws) || secrets.length >= MAX_SECRET_REFS || nextKind === undefined}
              onClick={() =>
                nextKind &&
                ws.setPolicy("secret_refs", [
                  ...secrets,
                  { kind: nextKind, secret_ref: "", key_id: "", state: "pending_rotation" },
                ])
              }
            >
              新增密钥引用
            </Button>
          }
        >
          <Table<SecretRow>
            size="small"
            rowKey="index"
            columns={columns}
            dataSource={secrets.map((secret, index) => ({ secret, index }))}
            pagination={false}
            scroll={{ x: 640 }}
            locale={{ emptyText: "没有密钥引用。" }}
          />
          {secretIssues.length > 0 && (
            <ul className="xs-issue-list">
              {secretIssues.map((issue) => (
                <li key={`${issue.path}-${issue.message}`}>{issue.message}</li>
              ))}
            </ul>
          )}
          <p className="footnote">
            这里只保存引用、Key ID
            和轮换状态；密钥正文由部署侧秘密管理系统提供，控制台从不显示。每种用途最多一条引用，引用必须以
            secret:// 开头。
          </p>
        </Card>
      </div>
    </Form>
  );
}

const parseLines = (text: string) =>
  text
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);

/** One fragment per line; typing a new line must not be eaten by the parser. */
function LinesField({
  id,
  label,
  hint,
  values,
  issue,
  onChange,
}: {
  id: string;
  label: string;
  hint: string;
  values: string[];
  issue: WorkspaceApi["issues"][number] | undefined;
  onChange: (values: string[]) => void;
}) {
  const [text, setText] = useState(values.join("\n"));
  useEffect(() => {
    // The draft changed from outside (discard, refresh): show it, unless it is what was typed.
    setText((current) =>
      JSON.stringify(parseLines(current)) === JSON.stringify(values) ? current : values.join("\n"),
    );
  }, [values]);
  return (
    <Field id={id} label={label} hint={hint} issue={issue}>
      <Input.TextArea
        rows={4}
        value={text}
        spellCheck={false}
        onChange={(event) => {
          setText(event.target.value);
          onChange(parseLines(event.target.value));
        }}
      />
    </Field>
  );
}

/** WAF 与限流: request filtering and the size and rate limits. */
export function WafLimitsTab({ ws }: { ws: WorkspaceApi }) {
  const draft = ws.draft;
  if (!draft) return null;
  const { waf, limits } = draft.policy;
  const patchWaf = (change: Partial<typeof waf>) => ws.setPolicy("waf", { ...waf, ...change });
  const patchLimits = (change: Partial<typeof limits>) =>
    ws.setPolicy("limits", { ...limits, ...change });
  return (
    <Form layout="vertical" className="xs-form" disabled={off(ws)}>
      <div className="xs-cards">
        <Card title="基础 WAF" className="xs-card">
          <Form.Item label="启用基础 WAF" extra="关闭后不再按下面的规则过滤请求。">
            <Toggle
              label="启用基础 WAF"
              checked={waf.enabled}
              onChange={(enabled) => patchWaf({ enabled })}
            />
          </Form.Item>
          <Field
            id="waf-headers"
            label="拦截请求头"
            issue={ws.issueFor("waf.blocked_headers")}
            hint="带有这些请求头的请求会被拦截，例如 X-Debug。输入后按回车或逗号确认；不区分大小写，最多 64 个。"
          >
            <Select
              mode="tags"
              open={false}
              tokenSeparators={[",", " "]}
              value={waf.blocked_headers}
              onChange={(values: string[]) =>
                patchWaf({ blocked_headers: values.map((value) => value.trim()).filter(Boolean) })
              }
            />
          </Field>
          <LinesField
            id="waf-fragments"
            label="查询阻断片段（每行一条，3–128 个 ASCII 字符）"
            hint="按一次解码后的查询串匹配，例如 <script 或 ' or 1=1--；不区分大小写，最多 32 条。保存前请先用正常业务样本核对。"
            values={waf.blocked_query_fragments}
            issue={ws.issueFor("waf.blocked_query_fragments")}
            onChange={(values) => patchWaf({ blocked_query_fragments: values })}
          />
          <Field
            id="waf-cookie"
            label="Cookie 上限"
            issue={ws.issueFor("waf.max_cookie_bytes")}
            hint={`请求 Cookie 的最大字节数，1–1 MiB。当前 = ${formatBytes(waf.max_cookie_bytes)}。`}
          >
            <NumInput
              value={waf.max_cookie_bytes}
              min={1}
              max={1_048_576}
              unit="字节"
              onChange={(value) => patchWaf({ max_cookie_bytes: value })}
            />
          </Field>
        </Card>
        <Card title="大小与速率限额" className="xs-card">
          <Field
            id="limits-request"
            label="请求体上限"
            issue={ws.issueFor("limits.max_request_body_bytes")}
            hint={`单个请求体的最大字节数，最大 16 MiB。当前 = ${formatBytes(limits.max_request_body_bytes)}。`}
          >
            <NumInput
              value={limits.max_request_body_bytes}
              min={1}
              max={16_777_216}
              unit="字节"
              onChange={(value) => patchLimits({ max_request_body_bytes: value })}
            />
          </Field>
          <Field
            id="limits-response"
            label="响应体上限"
            issue={ws.issueFor("limits.max_response_body_bytes")}
            hint={`单个响应体的最大字节数，最大 16 MiB；路由的响应上限不能超过它。当前 = ${formatBytes(limits.max_response_body_bytes)}。`}
          >
            <NumInput
              value={limits.max_response_body_bytes}
              min={1}
              max={16_777_216}
              unit="字节"
              onChange={(value) => patchLimits({ max_response_body_bytes: value })}
            />
          </Field>
          <Field
            id="limits-rps"
            label="每秒请求数"
            issue={ws.issueFor("limits.requests_per_second")}
            hint="站点的持续速率，1–1,000,000。调高同样需要审批。"
          >
            <NumInput
              value={limits.requests_per_second}
              min={1}
              max={1_000_000}
              unit="次/秒"
              onChange={(value) => patchLimits({ requests_per_second: value })}
            />
          </Field>
          <Field
            id="limits-burst"
            label="突发容量"
            issue={ws.issueFor("limits.burst")}
            hint="短时间允许的突发请求数，不能小于每秒请求数，最大 2,000,000。"
          >
            <NumInput
              value={limits.burst}
              min={1}
              max={2_000_000}
              unit="次"
              onChange={(value) => patchLimits({ burst: value })}
            />
          </Field>
        </Card>
      </div>
    </Form>
  );
}

/** 策略与健康: the upstream health probe, two edge fallbacks, and the manual runtime health. */
export function PoliciesTab({ ws }: { ws: WorkspaceApi }) {
  const draft = ws.draft;
  const canEdit = ws.access.canConfigure && draft !== null;
  return (
    <div className="xs-cards">
      {canEdit && draft && (
        <Form layout="vertical" className="xs-form xs-cards-form" disabled={off(ws)}>
          <Card title="健康检查（上游探测）" className="xs-card">
            <Field
              id="health-path"
              label="健康检查路径"
              issue={ws.issueFor("health_check.path")}
              hint="控制面向源站探测的路径，例如 /health；必须以 / 开头，不含 ? 或 #。"
            >
              <Input
                value={draft.policy.health_check.path}
                maxLength={256}
                spellCheck={false}
                onChange={(event) =>
                  ws.setPolicy("health_check", {
                    ...draft.policy.health_check,
                    path: event.target.value,
                  })
                }
              />
            </Field>
            <Field
              id="health-interval"
              label="检查间隔"
              issue={ws.issueFor("health_check.interval_seconds")}
              hint={`1–3600 秒。当前 = ${formatSeconds(draft.policy.health_check.interval_seconds)}。`}
            >
              <NumInput
                value={draft.policy.health_check.interval_seconds}
                min={1}
                max={3600}
                unit="秒"
                onChange={(value) =>
                  ws.setPolicy("health_check", {
                    ...draft.policy.health_check,
                    interval_seconds: value,
                  })
                }
              />
            </Field>
            <Field
              id="health-timeout"
              label="超时"
              issue={ws.issueFor("health_check.timeout_ms")}
              hint={`100–30000 毫秒。当前 = ${formatMillis(draft.policy.health_check.timeout_ms)}。`}
            >
              <NumInput
                value={draft.policy.health_check.timeout_ms}
                min={100}
                max={30_000}
                unit="毫秒"
                onChange={(value) =>
                  ws.setPolicy("health_check", { ...draft.policy.health_check, timeout_ms: value })
                }
              />
            </Field>
            <Field
              id="health-status"
              label="期望状态码"
              issue={ws.issueFor("health_check.expected_status")}
              hint="源站健康路径应返回的 HTTP 状态码，例如 200。"
            >
              <NumInput
                value={draft.policy.health_check.expected_status}
                min={100}
                max={599}
                onChange={(value) =>
                  ws.setPolicy("health_check", {
                    ...draft.policy.health_check,
                    expected_status: value,
                  })
                }
              />
            </Field>
          </Card>
          <Card title="静态资源与对象级校验" className="xs-card">
            <Field
              id="static-depth"
              label="静态资源兜底深度"
              issue={ws.issueFor("static_asset_max_path_depth")}
              hint="公开 GET 静态资源（js、css、字体、图片等）可使用的最大路径深度，0 表示关闭，默认 5，最大 16。超过深度或非静态扩展名仍按精确路由拒绝。"
            >
              <NumInput
                value={draft.policy.static_asset_max_path_depth}
                min={0}
                max={16}
                onChange={(value) => ws.setPolicy("static_asset_max_path_depth", value)}
              />
            </Field>
            <Form.Item
              label="源站对象级校验标记"
              extra="开启后 edge 删除客户端同名请求头，并向源站加入受信标记，由源站执行对象所有者校验。仅用于对象级实验站点。"
            >
              <Toggle
                label="源站对象级校验标记"
                checked={draft.policy.origin_object_access_enforced}
                onChange={(checked) => ws.setPolicy("origin_object_access_enforced", checked)}
              />
            </Form.Item>
          </Card>
        </Form>
      )}
      {ws.access.canObserve && ws.siteId && <HealthPanel siteId={ws.siteId} />}
    </div>
  );
}
