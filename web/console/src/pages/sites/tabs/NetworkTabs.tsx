import { Card, Form, Input, Radio } from "antd";
import { checkUpstreamAddress } from "../../../sites/model/upstream.ts";
import { Field, NumInput, Toggle } from "../fields";
import type { WorkspaceApi } from "../workspace/use-workspace.ts";

const entryOptions = [
  {
    value: "ui_action_required",
    title: "必须有界面操作来源",
    hint: "请求必须带有页面上的操作来源，适合业务页面入口。",
  },
  {
    value: "authenticated_root",
    title: "已认证根",
    hint: "访问者需要持有有效的已认证根凭证。",
  },
  { value: "public", title: "公开", hint: "任何人都可以访问，不做身份校验。" },
] as const;

const statusOptions = [
  { value: "draft", title: "草稿", hint: "保存后不会发布到 edge，可随时修改。" },
  { value: "active", title: "启用", hint: "edge 对外服务。首次启用需要独立审批。" },
  { value: "paused", title: "暂停", hint: "edge 不对外服务。暂停正在服务的站点需要审批。" },
] as const;

const formClass = "xs-form";
const off = (ws: WorkspaceApi) => ws.locked || !ws.access.canConfigure;

/** 网络: who the site is, where visitors arrive, where traffic goes and which port serves it. */
export function NetworkTab({ ws }: { ws: WorkspaceApi }) {
  const draft = ws.draft;
  if (!draft) return null;
  const verdict = checkUpstreamAddress(draft.upstream_address);
  return (
    <Form layout="vertical" className={formClass} disabled={off(ws)}>
      <div className="xs-cards">
        <Card title="站点标识" className="xs-card">
          <Field
            id="site-id"
            label="站点 ID"
            required={ws.creating}
            issue={ws.creating ? ws.issueFor("site_id") : undefined}
            hint={
              ws.creating
                ? "字母、数字和 _ . -，最长 123 个字符，例如 shop_cn。创建后不能修改。"
                : "站点的稳定标识，创建后不能修改。"
            }
          >
            <Input
              value={ws.creating ? ws.newSiteId : (ws.siteId ?? "")}
              readOnly={!ws.creating}
              maxLength={128}
              spellCheck={false}
              onChange={(event) => ws.setNewSiteId(event.target.value)}
            />
          </Field>
          <Field
            id="display-name"
            label="站点名称"
            required
            issue={ws.issueFor("display_name")}
            hint="给运营同事看的名字，可随时修改，不需要审批。"
          >
            <Input
              value={draft.display_name}
              maxLength={128}
              onChange={(event) => ws.set("display_name", event.target.value)}
            />
          </Field>
        </Card>

        <Card title="公网入口" className="xs-card">
          <Field
            id="public-origin"
            label="公网入口"
            required
            issue={ws.issueFor("public_origin")}
            hint="访问者使用的完整 origin，例如 https://www.example.com 或 https://shop.example.com:8443。必须是 https（本地靶场可用 http://localhost）。修改它需要审批。"
          >
            <Input
              value={draft.public_origin}
              maxLength={512}
              spellCheck={false}
              onChange={(event) => ws.set("public_origin", event.target.value)}
            />
          </Field>
          <Field
            id="entry-path"
            label="入口路径"
            required
            issue={ws.issueFor("entry_path")}
            hint="站点第一道门所在的路径，通常是 /。它与“安全入口”共同决定默认入口路由 protected.entry。"
          >
            <Input
              value={draft.entry_path}
              maxLength={256}
              spellCheck={false}
              onChange={(event) => ws.setEntry({ entry_path: event.target.value })}
            />
          </Field>
        </Card>

        <Card title="源站（上游）" className="xs-card">
          <Field
            id="upstream-address"
            label="源站地址"
            required
            issue={
              ws.issueFor("upstream_address") ??
              (verdict.severity === "ok" || draft.upstream_address === ""
                ? undefined
                : {
                    path: "upstream_address",
                    group: "network",
                    severity: verdict.severity,
                    message: verdict.message ?? "",
                  })
            }
            hint="源站的 IP:端口，例如 8.8.8.8:443；IPv6 写作 [2001:4860:4860::8888]:443。控制面不解析域名；内网、回环、云元数据地址会被安全策略拒绝。"
          >
            <Input
              value={draft.upstream_address}
              maxLength={128}
              spellCheck={false}
              onChange={(event) => ws.set("upstream_address", event.target.value)}
            />
          </Field>
          <Field
            id="upstream-server-name"
            label="源站 Server Name"
            required
            issue={ws.issueFor("upstream_server_name")}
            hint="源站的域名，用作 TLS SNI 与 Host，例如 origin.example.com。必须是域名，不能是 IP。"
          >
            <Input
              value={draft.upstream_server_name}
              maxLength={253}
              spellCheck={false}
              onChange={(event) => ws.set("upstream_server_name", event.target.value)}
            />
          </Field>
          <Form.Item label="上游 TLS" extra="开启后 edge 以 TLS 连接源站；明文 HTTP 源站请关闭。">
            <Toggle
              label="上游 TLS"
              checked={draft.upstream_tls}
              onChange={(checked) => ws.set("upstream_tls", checked)}
            />
          </Form.Item>
        </Card>

        <Card title="监听" className="xs-card">
          <Field
            id="listen-port"
            label="监听端口"
            issue={ws.issueFor("listen_port")}
            hint="edge 为该站点监听的内部端口。填 0 由租户端口池自动分配；也可指定 6100–65535 内未被占用的端口。"
          >
            <NumInput
              value={draft.listen_port}
              min={0}
              max={65535}
              onChange={(value) => ws.set("listen_port", value)}
            />
          </Field>
        </Card>
      </div>
    </Form>
  );
}

/** 安全入口: who may enter, whether the site is served, the browser probe and the policy label. */
export function SecurityEntryTab({ ws }: { ws: WorkspaceApi }) {
  const draft = ws.draft;
  if (!draft) return null;
  const creatingActive = ws.creating && draft.status === "active";
  return (
    <Form layout="vertical" className={formClass} disabled={off(ws)}>
      <div className="xs-cards">
        <Card title="入口准入" className="xs-card">
          <Field
            id="security-entry"
            group
            label="安全入口"
            hint="修改入口准入会同步更新入口路由 protected.entry，并需要审批。"
          >
            <Radio.Group
              aria-label="安全入口"
              className="xs-choice"
              value={draft.security_entry}
              onChange={(event) => ws.setEntry({ security_entry: event.target.value })}
            >
              {entryOptions.map((option) => (
                <Radio key={option.value} value={option.value}>
                  <span className="xs-choice-title">{option.title}</span>
                  <span className="xs-choice-hint">{option.hint}</span>
                </Radio>
              ))}
            </Radio.Group>
          </Field>
        </Card>

        <Card title="运行状态" className="xs-card">
          <Field
            id="site-status"
            group
            label="状态"
            hint={
              creatingActive
                ? "创建为“启用”后仍需要独立审批，批准前 edge 不会服务该站点。"
                : "状态变化是否需要审批取决于 edge 当前在服务什么：启用、暂停、恢复都属于上线或下线。"
            }
          >
            <Radio.Group
              aria-label="状态"
              className="xs-choice"
              value={draft.status}
              onChange={(event) => ws.set("status", event.target.value)}
            >
              {statusOptions.map((option) => (
                <Radio key={option.value} value={option.value}>
                  <span className="xs-choice-title">{option.title}</span>
                  <span className="xs-choice-hint">{option.hint}</span>
                </Radio>
              ))}
            </Radio.Group>
          </Field>
        </Card>

        <Card title="探针与策略标签" className="xs-card">
          <Form.Item
            label="启用浏览器探针运行时"
            extra="在页面中注入浏览器探针运行时。需要公网入口使用 https；本地靶场只允许 localhost 与 127.0.0.1。"
          >
            <Toggle
              label="启用浏览器探针运行时"
              checked={draft.sensor_enabled}
              onChange={(checked) => ws.set("sensor_enabled", checked)}
            />
          </Form.Item>
          <Field
            id="policy-revision"
            label="策略版本"
            required
            issue={ws.issueFor("policy_revision")}
            hint="给这一版策略起的标签，例如 policy-v2。仅用于识别，修改它不触发审批。"
          >
            <Input
              value={draft.policy_revision}
              maxLength={128}
              spellCheck={false}
              onChange={(event) => ws.set("policy_revision", event.target.value)}
            />
          </Field>
        </Card>
      </div>
    </Form>
  );
}
