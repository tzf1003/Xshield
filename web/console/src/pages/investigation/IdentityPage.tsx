import {
  CheckCircleFilled,
  ClockCircleOutlined,
  CloseCircleFilled,
  HistoryOutlined,
  QuestionCircleFilled,
  ReloadOutlined,
} from "@ant-design/icons";
import { useParams, useRouterState } from "@tanstack/react-router";
import { Button, Descriptions, Input, Skeleton, Tabs } from "antd";
import { type ReactNode, useState } from "react";
import { bindingPattern, grantPattern } from "../../api-contract.ts";
import {
  bindingListPath,
  bindingPath,
  grantListPath,
  grantPath,
  requestPath,
  useInvestigationNavigate,
} from "../../investigation/navigation.ts";
import { ROLE_OBSERVER_TEXT } from "../../investigation/roles.ts";
import type { Binding, BindingResponse, Grant, GrantResponse } from "../../ledger.ts";
import { useGuardedQuery } from "../../security/hooks";
import { MANUAL_REFRESH } from "../../security/query-client.ts";
import { normalizePaste } from "../../shell/palette-classifier.ts";
import { EventTime } from "../../ui/EventTime";
import { ObjectId } from "../../ui/ObjectId";
import { EmptyState, ErrorState } from "../../ui/states";
import "./investigation.css";
import "./identity.css";

type Kind = "grant" | "binding";

const kindText: Record<Kind, { tab: string; noun: string; prefix: string; label: string }> = {
  grant: { tab: "资格", noun: "资格 ID", prefix: "grant_", label: "资格 ID" },
  binding: { tab: "身份绑定", noun: "身份绑定 ID", prefix: "auth_", label: "身份绑定 ID" },
};

/** 身份与资格: the grant and the identity binding ledgers, read-only database observations. */
export function IdentityPage() {
  const pathname = useRouterState({ select: (router) => router.location.pathname });
  const params = useParams({ strict: false }) as { grantId?: string; bindingId?: string };
  const navigateTo = useInvestigationNavigate();
  const kind: Kind = pathname.startsWith(bindingListPath) ? "binding" : "grant";
  const id = kind === "grant" ? params.grantId : params.bindingId;
  return (
    <div className="xs-page">
      <section className="xs-card xs-identity" aria-label="身份与资格账本">
        <Tabs
          activeKey={kind}
          destroyOnHidden
          onChange={(key) => navigateTo.go(key === "binding" ? bindingListPath : grantListPath)}
          items={(Object.keys(kindText) as Kind[]).map((key) => ({
            key,
            label: kindText[key].tab,
            children:
              key === kind ? <Ledger key={`${key}:${id ?? ""}`} kind={key} id={id} /> : null,
          }))}
        />
        <p className="xs-foot">
          {ROLE_OBSERVER_TEXT}
          历史检索另需 Investigator；账本观察与历史索引各自查询。
        </p>
      </section>
    </div>
  );
}

function Ledger({ kind, id }: { kind: Kind; id: string | undefined }) {
  // A ledger snapshot is an observation at a database instant: looking an ID up again is a new
  // observation, so nothing is kept once the lookup is left (`gcTime: 0`).
  const grant = useGuardedQuery({
    key: ["investigation", "grant", id ?? "none"],
    fetch: (client, signal) => client.grant(id as string, signal),
    staleTime: MANUAL_REFRESH,
    gcTime: 0,
    enabled: kind === "grant" && id !== undefined,
  });
  const binding = useGuardedQuery({
    key: ["investigation", "binding", id ?? "none"],
    fetch: (client, signal) => client.binding(id as string, signal),
    staleTime: MANUAL_REFRESH,
    gcTime: 0,
    enabled: kind === "binding" && id !== undefined,
  });
  const active = kind === "grant" ? grant : binding;
  const loading = id !== undefined && active.isPending && active.isFetching;
  return (
    <div className="xs-ledger">
      <LookupForm kind={kind} current={id} onRepeat={() => void active.refetch()} />
      {id === undefined ? (
        <p className="xs-foot">
          输入{kindText[kind].noun}（{kindText[kind].prefix}…）读取数据库时刻的账本记录。
          也可以粘贴另一种 ID：{kind === "grant" ? "auth_…" : "grant_…"} 会自动切换到对应标签。
        </p>
      ) : loading ? (
        <Skeleton active paragraph={{ rows: 6 }} aria-label="正在读取账本" />
      ) : active.isError ? (
        <ErrorState
          error={active.error}
          onRetry={() => void active.refetch()}
          retryLabel="重新读取"
        />
      ) : kind === "grant" && grant.data ? (
        <GrantView response={grant.data} onRefresh={() => void grant.refetch()} />
      ) : kind === "binding" && binding.data ? (
        <BindingView response={binding.data} onRefresh={() => void binding.refetch()} />
      ) : null}
    </div>
  );
}

/** The ID box. A pasted ID of the other kind opens the other tab; nothing is sent for bad input. */
function LookupForm({
  kind,
  current,
  onRepeat,
}: {
  kind: Kind;
  current: string | undefined;
  onRepeat: () => void;
}) {
  const navigateTo = useInvestigationNavigate();
  const [value, setValue] = useState(current ?? "");
  const [problem, setProblem] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);

  function submit() {
    const target = normalizePaste(value);
    let found: Kind | null = null;
    if (grantPattern.test(target)) found = "grant";
    else if (bindingPattern.test(target)) found = "binding";
    if (!found) {
      setNote(null);
      setProblem(
        `请输入规范的${kindText[kind].noun}（${kindText[kind].prefix}加小写 UUIDv7），或另一种账本的 ID。`,
      );
      return;
    }
    setProblem(null);
    setNote(
      found === kind
        ? null
        : `这是${kindText[found].noun}，已切换到「${kindText[found].tab}」标签。`,
    );
    setValue(target);
    const path = found === "grant" ? grantPath(target) : bindingPath(target);
    if (found === kind && target === current) onRepeat();
    else navigateTo.go(path);
  }

  return (
    <div className="xs-lookup">
      <Input.Search
        aria-label={kindText[kind].label}
        placeholder={`${kindText[kind].prefix}…`}
        enterButton="查询"
        value={value}
        status={problem ? "error" : undefined}
        maxLength={64}
        autoComplete="off"
        spellCheck={false}
        onChange={(event) => {
          setValue(event.target.value);
          setProblem(null);
        }}
        onSearch={submit}
      />
      {problem ? <p className="xs-field-error">{problem}</p> : null}
      {note ? (
        <p className="xs-foot" role="status">
          {note}
        </p>
      ) : null}
    </div>
  );
}

type Tone = "allow" | "deny" | "observe" | "unknown";

const statusTone: Record<string, { label: string; tone: Tone }> = {
  active: { label: "有效", tone: "allow" },
  revoked: { label: "已撤销", tone: "deny" },
  expired: { label: "已过期", tone: "observe" },
  anonymous: { label: "匿名", tone: "unknown" },
};

const pillIcon: Record<Tone, ReactNode> = {
  allow: <CheckCircleFilled aria-hidden="true" />,
  deny: <CloseCircleFilled aria-hidden="true" />,
  observe: <ClockCircleOutlined aria-hidden="true" />,
  unknown: <QuestionCircleFilled aria-hidden="true" />,
};

/** Colour, an icon and a word: a state is never carried by colour alone. */
function Pill({ tone, children, code }: { tone: Tone; children: ReactNode; code?: string }) {
  return (
    <span className={`xs-decision xs-decision--${tone}`}>
      {pillIcon[tone]}
      <span>{children}</span>
      {code ? <span className="xs-decision-code mono">{code}</span> : null}
    </span>
  );
}

function Stored({ status }: { status: string }) {
  const entry = statusTone[status] ?? { label: "未识别", tone: "unknown" as const };
  return (
    <Pill tone={entry.tone} code={status}>
      {entry.label}
    </Pill>
  );
}

function Expiry({ expired }: { expired: boolean }) {
  return expired ? <Pill tone="observe">已到期</Pill> : <Pill tone="allow">未到期</Pill>;
}

function Observation({
  response,
  target,
}: {
  response: GrantResponse | BindingResponse;
  target: string;
}) {
  return (
    <Descriptions
      bordered
      size="small"
      column={{ xs: 1, md: 2 }}
      items={[
        {
          key: "target",
          label: "查询对象",
          children: <ObjectId value={target} wrap />,
        },
        {
          key: "as_of",
          label: "数据库时刻",
          children: response.as_of ? (
            <span className="xs-times">
              <EventTime value={response.as_of} precision="microsecond" />
              <span className="mono xs-sub">{response.as_of}</span>
            </span>
          ) : (
            "未返回观察时间"
          ),
        },
        {
          key: "request",
          label: "管理请求 ID",
          children: <ObjectId value={response.request_id} wrap />,
        },
      ]}
    />
  );
}

function Missing({ onHistory }: { onHistory: () => void }) {
  return (
    <>
      <EmptyState title="当前账本未找到" icon="search">
        当前范围未返回账本记录；历史事件可通过独立检索继续核对。
      </EmptyState>
      <HistoryButton onHistory={onHistory} />
    </>
  );
}

function HistoryButton({ onHistory }: { onHistory: () => void }) {
  return (
    <div className="xs-ledger-history">
      <Button icon={<HistoryOutlined aria-hidden="true" />} onClick={onHistory}>
        准备历史检索
      </Button>
      <p className="xs-foot">
        预填引用后需确认时间窗并提交。历史检索另需 Investigator；账本观察与历史索引各自查询。
      </p>
    </div>
  );
}

function Head({ title, onRefresh }: { title: string; onRefresh: () => void }) {
  return (
    <div className="xs-card-head">
      <h2>{title}</h2>
      <Button size="small" icon={<ReloadOutlined aria-hidden="true" />} onClick={onRefresh}>
        重新读取
      </Button>
    </div>
  );
}

function GrantView({ response, onRefresh }: { response: GrantResponse; onRefresh: () => void }) {
  const navigateTo = useInvestigationNavigate();
  const grant = response.grant;
  return (
    <section aria-label="资格账本详情" className="xs-ledger-result">
      <Head title="资格账本快照" onRefresh={onRefresh} />
      <Observation response={response} target={response.source_grant_id} />
      <p className="xs-foot">
        这是数据库时刻的账本观察。实际请求仍须校验完整身份、来源证明、策略、目标和期限。
      </p>
      {grant ? (
        <div className="xs-ledger-grid">
          <GrantRecord grant={grant} />
          <section aria-label="身份绑定记录">
            <h3>当前绑定（同一快照）</h3>
            <Descriptions
              bordered
              size="small"
              column={1}
              items={[
                {
                  key: "id",
                  label: "绑定 ID",
                  children: (
                    <ObjectId
                      value={grant.binding.binding_id}
                      wrap
                      href={bindingPath(grant.binding.binding_id)}
                      onOpen={() => navigateTo.go(bindingPath(grant.binding.binding_id))}
                    />
                  ),
                },
                {
                  key: "stored",
                  label: "持久状态",
                  children: <Stored status={grant.binding.stored_status} />,
                },
                {
                  key: "expired",
                  label: "时间到期",
                  children: <Expiry expired={grant.binding.time_expired} />,
                },
                { key: "epoch", label: "当前身份代际", children: grant.binding.current_auth_epoch },
                {
                  key: "match",
                  label: "发行代际对比",
                  children: grant.binding.epoch_matches_grant ? (
                    <Pill tone="allow">一致</Pill>
                  ) : (
                    <Pill tone="deny">不一致</Pill>
                  ),
                },
                {
                  key: "expires",
                  label: "到期时间",
                  children: <span className="mono">{grant.binding.expires_at}</span>,
                },
              ]}
            />
          </section>
        </div>
      ) : (
        <Missing
          onHistory={() =>
            navigateTo.openSearch({ kind: "grant_id", value: response.source_grant_id })
          }
        />
      )}
      {grant ? (
        <HistoryButton
          onHistory={() =>
            navigateTo.openSearch({ kind: "grant_id", value: response.source_grant_id })
          }
        />
      ) : null}
    </section>
  );
}

function GrantRecord({ grant }: { grant: Grant }) {
  const navigateTo = useInvestigationNavigate();
  return (
    <section aria-label="资格记录">
      <h3>资格记录</h3>
      <Descriptions
        bordered
        size="small"
        column={1}
        items={[
          { key: "stored", label: "持久状态", children: <Stored status={grant.stored_status} /> },
          { key: "expired", label: "时间到期", children: <Expiry expired={grant.time_expired} /> },
          { key: "epoch", label: "发行身份代际", children: grant.auth_epoch },
          {
            key: "issued",
            label: "发行时间",
            children: <span className="mono">{grant.issued_at}</span>,
          },
          {
            key: "expires",
            label: "到期时间",
            children: <span className="mono">{grant.expires_at}</span>,
          },
          { key: "resource", label: "资源类型", children: grant.resource_type },
          {
            key: "operation",
            label: "操作 ID",
            children: <span className="mono">{grant.operation_id}</span>,
          },
          {
            key: "view",
            label: "视图 ID",
            children: <span className="mono">{grant.view_id}</span>,
          },
          {
            key: "policy",
            label: "策略版本",
            children: <span className="mono">{grant.policy_revision}</span>,
          },
          {
            key: "event",
            label: "来源事件",
            children: (
              <ObjectId
                value={grant.source_event_id}
                wrap
                onOpen={() =>
                  navigateTo.openSearch({ kind: "event_id", value: grant.source_event_id })
                }
              />
            ),
          },
          {
            key: "request",
            label: "来源请求",
            children: (
              <ObjectId
                value={grant.source_request_id}
                wrap
                href={requestPath(grant.source_request_id)}
                onOpen={() => navigateTo.go(requestPath(grant.source_request_id))}
              />
            ),
          },
        ]}
      />
    </section>
  );
}

function BindingView({
  response,
  onRefresh,
}: {
  response: BindingResponse;
  onRefresh: () => void;
}) {
  const navigateTo = useInvestigationNavigate();
  const binding: Binding | null = response.binding;
  const history = () =>
    navigateTo.openSearch({ kind: "auth_binding_id", value: response.source_binding_id });
  return (
    <section aria-label="身份绑定账本详情" className="xs-ledger-result">
      <Head title="身份绑定账本快照" onRefresh={onRefresh} />
      <Observation response={response} target={response.source_binding_id} />
      <p className="xs-foot">
        这是数据库时刻的账本观察。实际请求仍须校验完整身份、来源证明、策略、目标和期限。
      </p>
      {binding ? (
        <>
          <section aria-label="身份绑定记录">
            <h3>身份绑定记录</h3>
            <Descriptions
              bordered
              size="small"
              column={{ xs: 1, md: 2 }}
              items={[
                {
                  key: "id",
                  label: "绑定 ID",
                  children: <ObjectId value={binding.binding_id} wrap />,
                },
                {
                  key: "stored",
                  label: "持久状态",
                  children: <Stored status={binding.stored_status} />,
                },
                {
                  key: "expired",
                  label: "时间到期",
                  children: <Expiry expired={binding.time_expired} />,
                },
                { key: "epoch", label: "当前身份代际", children: binding.current_auth_epoch },
                { key: "generation", label: "凭证代际", children: binding.credential_generation },
                {
                  key: "expires",
                  label: "到期时间",
                  children: <span className="mono">{binding.expires_at}</span>,
                },
                {
                  key: "updated",
                  label: "更新时间",
                  children: <span className="mono">{binding.updated_at}</span>,
                },
              ]}
            />
          </section>
          <HistoryButton onHistory={history} />
        </>
      ) : (
        <Missing onHistory={history} />
      )}
    </section>
  );
}
