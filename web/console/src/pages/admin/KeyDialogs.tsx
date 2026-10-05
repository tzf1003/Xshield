import { Alert, Button, Modal, Popconfirm, Space } from "antd";
import { type ReactNode, useState } from "react";
import type { ManagementApiKeyRecord, SiteListItem } from "../../api.ts";
import {
  buildKeyRequest,
  type ExpiryChoice,
  type KeyDraft,
  type ScopeRow,
  TENANT_WIDE,
} from "../../operations/api-keys.ts";
import type { IssuedScope } from "../../operations/key-secret.ts";
import {
  type CreateVars,
  createKey,
  type IssuedKey,
  keyListKey,
  keyOwners,
  keyPaths,
  type Revoked,
  revokeKey,
  type RevokeVars,
  type RotateVars,
  rotateKey,
} from "../../operations/key-writes.ts";
import { safeError } from "../../security/errors.ts";
import { useSession } from "../../security/SessionProvider";
import { ProblemAlert } from "../../ui/ProblemAlert";
import { TimeStamp } from "../../ui/TimeStamp";
import { Facts } from "../../work/Parts";
import { useWrite, type Write } from "../../work/use-write.ts";
import { FrozenOperation } from "../../work/WriteDialog";
import { KeyForm, newScopeRow } from "./KeyForm";

/** Rows for the editor from the scopes this session saw issued for a key. */
export function rowsFromScopes(scopes: readonly IssuedScope[] | undefined): ScopeRow[] {
  if (!scopes || scopes.length === 0) return [newScopeRow()];
  return scopes.map((scope) => ({
    ...newScopeRow(scope.site_id === TENANT_WIDE ? "tenant" : "site"),
    siteId: scope.site_id === TENANT_WIDE ? "" : scope.site_id,
    capabilities: scope.capabilities as ScopeRow["capabilities"],
  }));
}

const defaultExpiry: ExpiryChoice = { kind: "preset", days: 30 };

/**
 * A key write in a dialog. While nothing is unresolved it shows the form (a refusal above it,
 * explained from the dictionary; nothing was written). Once a request is in flight or its outcome
 * is unknown it shows the frozen request with the exact retry only.
 */
function KeyWriteModal<TVars, T extends IssuedKey | Revoked>({
  title,
  open,
  onClose,
  write,
  submitText,
  danger = false,
  onSubmit,
  recovery,
  children,
}: {
  title: string;
  open: boolean;
  onClose: () => void;
  write: Write<TVars, T>;
  submitText: string;
  danger?: boolean;
  onSubmit: () => void;
  /** Extra guidance shown with the frozen request. */
  recovery?: ReactNode;
  children: ReactNode;
}) {
  const operation = write.operation;
  return (
    <Modal
      open={open}
      title={title}
      onCancel={onClose}
      width={720}
      destroyOnHidden
      mask={{ closable: false }}
      footer={
        operation ? (
          <Button onClick={onClose}>稍后处理</Button>
        ) : (
          <Space>
            <Button onClick={onClose}>取消</Button>
            <Button type="primary" danger={danger} loading={write.busy} onClick={onSubmit}>
              {submitText}
            </Button>
          </Space>
        )
      }
    >
      {operation ? (
        <div className="xs-w-stack">
          {recovery}
          <FrozenOperation
            operation={operation}
            busy={write.busy}
            onRetry={() => void write.retry()}
          />
        </div>
      ) : (
        <div className="xs-w-stack">
          {write.rejection !== null && <ProblemAlert problem={safeError(write.rejection)} />}
          {children}
        </div>
      )}
    </Modal>
  );
}

function useDraft(initial: () => KeyDraft) {
  const [draft, setDraft] = useState<KeyDraft>(initial);
  const [attempted, setAttempted] = useState(false);
  return { draft, setDraft, attempted, setAttempted };
}

type FormContext = Readonly<{
  roles: readonly string[] | null;
  sites: readonly SiteListItem[];
  sitesHint: string | null;
}>;

/** 创建 API Key. The plaintext of the new key is shown by the one-time dialog, not here. */
export function CreateKeyDialog({
  open,
  onClose,
  context,
}: {
  open: boolean;
  onClose: () => void;
  context: FormContext;
}) {
  const { runtime, state } = useSession();
  const form = useDraft(() => ({
    displayName: "",
    subject: "",
    expiry: defaultExpiry,
    scopes: [newScopeRow()],
  }));
  const write = useWrite<CreateVars, IssuedKey>(
    {
      label: "创建 API Key",
      path: () => keyPaths.collection,
      body: (vars) => vars.request,
      owner: keyOwners.create(),
      invalidate: [keyListKey],
      run: (client, vars, context) =>
        createKey(runtime, runtime.store.getState().epoch, client, vars, context),
    },
    () => {
      form.setAttempted(false);
      onClose();
    },
  );
  const built = buildKeyRequest(form.draft, state.scope?.tenant_id ?? "", Date.now());
  const problems = built.ok
    ? { subject: null, displayName: null, expiry: null }
    : { subject: built.subject, displayName: built.displayName, expiry: built.expiry };
  return (
    <KeyWriteModal
      title="创建 API Key"
      open={open}
      onClose={onClose}
      write={write}
      submitText="创建并显示明文"
      onSubmit={() => {
        form.setAttempted(true);
        const request = buildKeyRequest(form.draft, state.scope?.tenant_id ?? "", Date.now());
        if (request.ok) void write.submit({ request: request.request });
      }}
      recovery={
        write.operation?.phase === "unknown" && (
          <Alert
            type="warning"
            showIcon
            title="服务端不按幂等键对“创建 API Key”去重"
            description={
              <div className="xs-w-stack">
                <span>
                  如果先前那次已经提交，原样重试会再创建一把
                  Key，而第一把的明文已无法取回。请先关闭本对话框、刷新列表，核对是否已经出现这把
                  Key（同名、同主体）。已出现时撤销它，再决定是否重试或放弃。
                </span>
                <span>
                  <Popconfirm
                    title="放弃这次创建请求？"
                    description="放弃后不能再原样重试；先前那次可能已经创建了 Key，请在列表中核对并撤销。"
                    okText="放弃"
                    cancelText="取消"
                    onConfirm={() => {
                      const operation = write.operation;
                      if (operation) runtime.pending.abandon(operation.id);
                      onClose();
                    }}
                  >
                    <Button danger size="small">
                      放弃这次请求（不再重试）
                    </Button>
                  </Popconfirm>
                </span>
              </div>
            }
          />
        )
      }
    >
      <KeyForm
        draft={form.draft}
        onChange={form.setDraft}
        roles={context.roles}
        sites={context.sites}
        sitesHint={context.sitesHint}
        showProblems={form.attempted}
        problems={problems}
      />
    </KeyWriteModal>
  );
}

/** 轮换: one transaction revokes the old key and issues a new one with the same body shape. */
export function RotateKeyDialog({
  record,
  knownScopes,
  onClose,
  context,
}: {
  record: ManagementApiKeyRecord;
  knownScopes: readonly IssuedScope[] | undefined;
  onClose: () => void;
  context: FormContext;
}) {
  const { runtime, state } = useSession();
  const form = useDraft(() => ({
    displayName: record.display_name,
    subject: record.subject,
    expiry: defaultExpiry,
    scopes: rowsFromScopes(knownScopes),
  }));
  const write = useWrite<RotateVars, IssuedKey>(
    {
      label: "轮换 API Key",
      path: (vars) => keyPaths.rotate(vars.apiKeyId),
      body: (vars) => vars.request,
      owner: keyOwners.rotate(record.api_key_id),
      invalidate: [keyListKey],
      run: (client, vars, context) =>
        rotateKey(runtime, runtime.store.getState().epoch, client, vars, context),
    },
    () => onClose(),
  );
  const built = buildKeyRequest(form.draft, state.scope?.tenant_id ?? "", Date.now());
  const problems = built.ok
    ? { subject: null, displayName: null, expiry: null }
    : { subject: built.subject, displayName: built.displayName, expiry: built.expiry };
  return (
    <KeyWriteModal
      title={`轮换 API Key：${record.display_name}`}
      open
      onClose={onClose}
      write={write}
      submitText="轮换并显示新明文"
      onSubmit={() => {
        form.setAttempted(true);
        const request = buildKeyRequest(form.draft, state.scope?.tenant_id ?? "", Date.now());
        if (request.ok)
          void write.submit({ apiKeyId: record.api_key_id, request: request.request });
      }}
      recovery={
        write.operation?.phase === "unknown" && (
          <Alert
            type="info"
            showIcon
            title="轮换只会成功一次"
            description="服务端在一个事务里撤销旧 Key 并签发新 Key。如果先前那次已经提交，旧 Key 已被撤销，原样重试会得到 CONTROL_API_KEY_NOT_FOUND，不会再签发第二把；那一次的新明文已无法取回，需要时请再创建一把。"
          />
        )
      }
    >
      <Alert
        type="info"
        showIcon
        title="轮换在一个事务中撤销旧 Key 并签发新 Key"
        description="请求被拒绝时旧 Key 保持有效；成功后旧 Key 立即失效，请尽快把新明文部署给 Agent。"
      />
      {!knownScopes && (
        <Alert
          type="warning"
          showIcon
          title="列表不返回这把 Key 的范围"
          description="请重新选择新 Key 的范围：轮换用这里填写的范围签发新 Key，而不是沿用旧范围。"
        />
      )}
      <KeyForm
        draft={form.draft}
        onChange={form.setDraft}
        roles={context.roles}
        sites={context.sites}
        sitesHint={context.sitesHint}
        showProblems={form.attempted}
        problems={problems}
      />
    </KeyWriteModal>
  );
}

/** 撤销: the key stops working at once; there is no undo. */
export function RevokeKeyDialog({
  record,
  onClose,
}: {
  record: ManagementApiKeyRecord;
  onClose: () => void;
}) {
  const { runtime } = useSession();
  const write = useWrite<RevokeVars, Revoked>(
    {
      label: "撤销 API Key",
      path: (vars) => keyPaths.revoke(vars.apiKeyId),
      owner: keyOwners.revoke(record.api_key_id),
      invalidate: [keyListKey],
      run: (client, vars, context) => revokeKey(runtime, client, vars, context),
    },
    () => onClose(),
  );
  return (
    <KeyWriteModal
      title={`撤销 API Key：${record.display_name}`}
      open
      onClose={onClose}
      write={write}
      submitText="确认撤销"
      danger
      onSubmit={() => void write.submit({ apiKeyId: record.api_key_id })}
      recovery={
        write.operation?.phase === "unknown" && (
          <Alert
            type="info"
            showIcon
            title="重试只会撤销一次"
            description="如果先前那次已经撤销，原样重试会得到 CONTROL_API_KEY_NOT_FOUND；刷新列表即可确认这把 Key 的状态。"
          />
        )
      }
    >
      <p>
        撤销后这把 Key 立即失效：使用它的 Agent 会收到 401
        CONTROL_API_KEY_INVALID。撤销不能恢复，需要时请创建或轮换出新 Key。
      </p>
      <Facts
        rows={[
          ["名称", record.display_name],
          [
            "Agent 主体",
            <span key="s" className="mono">
              {record.subject}
            </span>,
          ],
          [
            "前缀",
            <span key="p" className="mono">
              {record.key_prefix}
            </span>,
          ],
          [
            "Key ID",
            <span key="k" className="mono">
              {record.api_key_id}
            </span>,
          ],
          ["到期", <TimeStamp key="e" value={record.expires_at} />],
        ]}
      />
    </KeyWriteModal>
  );
}
