import { PlusOutlined, ReloadOutlined } from "@ant-design/icons";
import { Alert, Button, Empty, Skeleton, Space, Table, type TableColumnsType } from "antd";
import { useState, useSyncExternalStore } from "react";
import type { ManagementApiKeyRecord } from "../../api.ts";
import { canIssueAnything, keyStatus, scopeSummary } from "../../operations/api-keys.ts";
import { keySecrets } from "../../operations/key-secret.ts";
import { keyListSpec, keyOwners } from "../../operations/key-writes.ts";
import { RoleHint } from "../../operations/Parts";
import { isRoleRefusal } from "../../operations/sources.ts";
import { useGuardedQuery, usePendingOperations } from "../../security/hooks";
import { useSession } from "../../security/SessionProvider";
import { PageActions } from "../../shell/page-actions";
import { TimeStamp } from "../../ui/TimeStamp";
import { specs } from "../../work/queries.ts";
import { ErrorNotice, labelled, TonePill } from "../../work/Parts";
import { useRoles } from "../../work/roles.ts";
import { viewOperation } from "../../work/operations.ts";
import { WorkRoot } from "../../work/WorkRoot";
import { CreateKeyDialog, RevokeKeyDialog, RotateKeyDialog } from "./KeyDialogs";
import { SecretModal } from "./SecretModal";
import "../../operations/operations.css";
import "./api-keys.css";

const statusPills = {
  active: { tone: "success", label: "有效", hint: "未撤销且未到期。" },
  expired: {
    tone: "warning",
    label: "已过期",
    hint: "按浏览器时间判断已过期；服务端以自己的时钟拒绝过期 Key。",
  },
  revoked: { tone: "default", label: "已撤销", hint: "已撤销，不能再使用。" },
} as const;

type Dialog =
  | { kind: "create" }
  | { kind: "rotate"; key: ManagementApiKeyRecord }
  | { kind: "revoke"; key: ManagementApiKeyRecord }
  | null;

const adminRoles = ["key_administrator", "system_admin"];

/**
 * Agent API keys (`/admin/api-keys`): list, create, rotate and revoke. Only a browser OIDC session
 * holding KeyAdministrator or SystemAdmin may administer keys (the server refuses the machine
 * Bearer and every key). Reads happen on opening and on "刷新" only; writes go through the
 * frozen-write layer, and an issued key's plaintext is shown once (SecretModal).
 */
function ApiKeysBody() {
  const { roles, machine } = useRoles();
  const { runtime } = useSession();
  const admin = roles !== null && adminRoles.some((role) => roles.includes(role));
  const list = useGuardedQuery(keyListSpec(runtime, admin && !machine));
  const [dialog, setDialog] = useState<Dialog>(null);
  // The site picker reads the first page of the site list, only while a form is open.
  const formOpen = dialog?.kind === "create" || dialog?.kind === "rotate";
  const sites = useGuardedQuery(specs.siteApprovals(formOpen));
  const memory = useSyncExternalStore(
    keySecrets(runtime).subscribe,
    keySecrets(runtime).getSnapshot,
  );
  const pending = usePendingOperations().filter((operation) =>
    operation.path.startsWith("/control/v1/agent-api-keys"),
  );
  const now = Date.now();

  if (machine) {
    return (
      <Alert
        type="info"
        showIcon
        title="机器凭证测试模式不能管理 API Key"
        description="服务端只接受带 CSRF 的浏览器管理会话（持有 KeyAdministrator 或 SystemAdmin）创建、列出、撤销和轮换 Key；静态机器 Bearer 和任何 API Key 都会被拒绝（403 CONTROL_SCOPE_DENIED），所以本页不发起读取。请使用企业身份登录。"
      />
    );
  }
  if (!admin) {
    return (
      <RoleHint title="需要 KeyAdministrator 或 SystemAdmin 角色">
        当前身份不能管理 Agent API Key，服务端会拒绝相关请求。导航隐藏只是提示，授权由服务端决定。
      </RoleHint>
    );
  }

  const issueAllowed = canIssueAnything(roles);
  const context = {
    roles,
    sites: sites.data?.sites ?? [],
    sitesHint: sites.isError
      ? isRoleRefusal(sites.error)
        ? "站点清单需要 SystemAdmin 才能读取；可以直接输入站点 ID。"
        : "站点清单读取失败；可以直接输入站点 ID。"
      : sites.data?.truncated
        ? "只列出了站点清单首页；其他站点可以直接输入站点 ID。"
        : null,
  };

  const columns: TableColumnsType<ManagementApiKeyRecord> = [
    {
      title: "名称",
      key: "name",
      onCell: labelled("名称"),
      render: (_, key) => (
        <span className="xs-key-name">
          <strong>{key.display_name}</strong>
          <small className="mono" title={key.api_key_id}>
            {key.api_key_id}
          </small>
        </span>
      ),
    },
    {
      title: "Agent 主体",
      key: "subject",
      onCell: labelled("主体"),
      render: (_, key) => <span className="mono xs-w-nowrap">{key.subject}</span>,
    },
    {
      title: "前缀",
      key: "prefix",
      onCell: labelled("前缀"),
      render: (_, key) => <span className="mono xs-w-nowrap">{key.key_prefix}</span>,
    },
    {
      title: "范围",
      key: "scopes",
      onCell: labelled("范围"),
      render: (_, key) => {
        const scopes = memory.scopes.get(key.api_key_id);
        return scopes ? (
          <span className="xs-key-tags">
            {scopeSummary(scopes).map((line) => (
              <TonePill key={line} tone="brand" label={line} />
            ))}
          </span>
        ) : (
          <span
            className="xs-w-muted"
            title="服务端的 Key 列表不返回范围；本次会话中创建或轮换的 Key 会显示签发时的范围。"
          >
            列表不含范围
          </span>
        );
      },
    },
    {
      title: "状态",
      key: "status",
      onCell: labelled("状态"),
      render: (_, key) => {
        const pill = statusPills[keyStatus(key, now)];
        return <TonePill tone={pill.tone} label={pill.label} hint={pill.hint} />;
      },
    },
    {
      title: "到期",
      key: "expires",
      onCell: labelled("到期"),
      render: (_, key) => <TimeStamp value={key.expires_at} compact />,
    },
    {
      title: "最近使用",
      key: "used",
      onCell: labelled("最近使用"),
      render: (_, key) =>
        key.last_used_at ? (
          <span title="每分钟最多记录一次">
            <TimeStamp value={key.last_used_at} compact />
          </span>
        ) : (
          <span className="xs-w-muted">从未使用</span>
        ),
    },
    {
      title: "操作",
      key: "actions",
      onCell: labelled("操作"),
      render: (_, key) => {
        const unresolved = pending.find(keyOwners.key(key.api_key_id));
        if (unresolved) {
          return (
            <Button
              size="small"
              onClick={() =>
                setDialog({
                  kind: unresolved.path.endsWith("/rotate") ? "rotate" : "revoke",
                  key,
                })
              }
            >
              查看待确认操作
            </Button>
          );
        }
        if (key.status === "revoked") return <span className="xs-w-muted">—</span>;
        return (
          <Space size={4} wrap>
            <Button
              size="small"
              aria-label={`轮换 ${key.display_name}`}
              onClick={() => setDialog({ kind: "rotate", key })}
            >
              轮换
            </Button>
            <Button
              size="small"
              danger
              aria-label={`撤销 ${key.display_name}`}
              onClick={() => setDialog({ kind: "revoke", key })}
            >
              撤销
            </Button>
          </Space>
        );
      },
    },
  ];

  const createPending = pending.find(keyOwners.create());
  const keys = list.data?.keys ?? [];

  return (
    <div className="xs-w-stack">
      <PageActions>
        <Button
          icon={<ReloadOutlined aria-hidden="true" />}
          loading={list.isFetching}
          onClick={() => void list.refetch()}
        >
          刷新
        </Button>
        <Button
          type="primary"
          icon={<PlusOutlined aria-hidden="true" />}
          disabled={!issueAllowed}
          title={issueAllowed ? undefined : "当前角色不能签发任何带权限的 Key"}
          onClick={() => setDialog({ kind: "create" })}
        >
          创建 API Key
        </Button>
      </PageActions>
      {!issueAllowed && (
        <RoleHint title="只能撤销，不能签发">
          签发者只能授予自己能行使的能力，而当前角色不能行使任何一项站点能力（例如只持有
          KeyAdministrator）。创建和轮换都会被服务端以 CONTROL_API_KEY_SCOPE_FORBIDDEN
          拒绝；撤销不受影响。
        </RoleHint>
      )}
      {createPending && (
        <Alert
          type="warning"
          showIcon
          title={`创建 API Key：${viewOperation(createPending).phaseLabel}`}
          description="这次创建的请求已冻结在内存中；刷新页面会丢失。"
          action={
            <Button size="small" onClick={() => setDialog({ kind: "create" })}>
              查看并处理
            </Button>
          }
        />
      )}
      <section className="xs-w-card" aria-label="Agent API Key 列表">
        <p className="xs-w-muted">
          Key 只有逐行列出的“站点 ×
          能力”，没有角色；明文只在创建或轮换成功时显示一次。列表只含元数据：服务端不返回范围、指纹或明文。每次读取都会被服务端审计。
        </p>
        {list.isError ? (
          isRoleRefusal(list.error) ? (
            <RoleHint title="服务端拒绝了当前身份">
              管理 API Key 需要带 CSRF 的浏览器会话，并持有 KeyAdministrator 或 SystemAdmin。
            </RoleHint>
          ) : (
            <ErrorNotice
              error={list.error}
              title="Key 列表读取失败"
              action={
                <Button size="small" onClick={() => void list.refetch()}>
                  重试
                </Button>
              }
            />
          )
        ) : list.isPending ? (
          <div aria-busy="true">
            <Skeleton active paragraph={{ rows: 3 }} />
          </div>
        ) : keys.length === 0 ? (
          <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="还没有 Agent API Key。" />
        ) : (
          <Table<ManagementApiKeyRecord>
            className="xs-w-table"
            rowKey="api_key_id"
            size="middle"
            columns={columns}
            dataSource={[...keys]}
            pagination={false}
          />
        )}
        {list.data && (
          <small className="xs-w-muted">
            读取于 <TimeStamp value={list.dataUpdatedAt} compact />
            （浏览器时间）· 管理请求 <span className="mono">{list.data.request_id}</span>
          </small>
        )}
      </section>
      {dialog?.kind === "create" && (
        <CreateKeyDialog open onClose={() => setDialog(null)} context={context} />
      )}
      {dialog?.kind === "rotate" && (
        <RotateKeyDialog
          record={dialog.key}
          knownScopes={memory.scopes.get(dialog.key.api_key_id)}
          onClose={() => setDialog(null)}
          context={context}
        />
      )}
      {dialog?.kind === "revoke" && (
        <RevokeKeyDialog record={dialog.key} onClose={() => setDialog(null)} />
      )}
      <SecretModal />
    </div>
  );
}

export function ApiKeysPage() {
  return (
    <WorkRoot>
      <ApiKeysBody />
    </WorkRoot>
  );
}
