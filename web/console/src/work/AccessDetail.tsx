import { DownloadOutlined, ReloadOutlined } from "@ant-design/icons";
import { App as AntdApp, Alert, Button, Input, InputNumber, Segmented, Space } from "antd";
import { useState } from "react";
import type { AccessDecision, AccessInspection } from "../evidence-access.ts";
import { useGuardedQuery } from "../security/hooks";
import { useShellActions } from "../shell/actions";
import { useAttachmentDownload } from "./downloads.ts";
import { textProblem, utf8Length } from "./format.ts";
import { owners } from "./operations.ts";
import { ErrorNotice, Facts, Field, IdChip, LoadState, Observed, StatePill, Time } from "./Parts";
import { domains, specs } from "./queries.ts";
import { isOwnRequest, role, useRoles } from "./roles.ts";
import { accessPill } from "./status.ts";
import { formatTtl, ttlPresets, ttlProblem } from "./ttl.ts";
import { useWrite } from "./use-write.ts";
import { FrozenOperation } from "./WriteDialog";

type DecideVars = {
  accessId: string;
  decision: "approve" | "deny";
  reason: string;
  ttl: number | null;
};

type Detail = AccessInspection["access_request"];

function whyNotLive(item: Detail): string[] {
  const reasons: string[] = [];
  if (item.case_status !== "open") reasons.push("案件已关闭");
  if (item.artifact_status !== "active") reasons.push("证据已删除");
  if (item.artifact_time_expired) reasons.push("证据已到期");
  return reasons;
}

/**
 * One access request, read fresh from the server (an audited read), with what the viewer may do
 * about it: an independent approver decides, the requester downloads once it is approved. Both
 * affordances are courtesy; the server re-checks role, subject, state and expiry on every call.
 */
export function AccessDetail({
  accessId,
  ownership,
}: {
  accessId: string;
  /** What the list this row came from says; otherwise the subject decides, when it is known. */
  ownership?: "mine" | "others";
}) {
  const query = useGuardedQuery(specs.accessDetail(accessId));
  const { has, subject } = useRoles();
  const shell = useShellActions();
  const response = query.data;
  const item = response?.access_request;
  const own = item
    ? ownership
      ? ownership === "mine"
      : isOwnRequest(item.requested_by, subject)
    : null;
  const download = useAttachmentDownload({
    target: accessId,
    fetch: (client, signal) => {
      if (!item) throw new Error("access request not loaded");
      return client.downloadEvidence(item.artifact_id, item.access_request_id, signal);
    },
    filename: (result) => `${result.artifact_id}.bin`,
  });

  return (
    <LoadState pending={query.isPending} error={query.error} onRetry={() => void query.refetch()}>
      {response && item && (
        <div className="xs-w-stack">
          <div className="xs-w-between">
            <Space wrap>
              <StatePill pill={accessPill[item.stored_status]} />
              <IdChip id={item.access_request_id} label="访问申请 ID" />
            </Space>
            <Button
              size="small"
              icon={<ReloadOutlined aria-hidden="true" />}
              loading={query.isFetching}
              onClick={() => void query.refetch()}
            >
              刷新
            </Button>
          </div>
          <Observed asOf={response.as_of} requestId={response.request_id} />
          <Notes item={item} own={own} />
          <Facts
            rows={[
              ["申请人", item.requested_by],
              [
                "申请理由",
                <span key="j" className="xs-w-text">
                  {item.justification}
                </span>,
              ],
              ["案件", <IdChip key="c" id={item.case_id} label="案件 ID" />],
              ["证据", <IdChip key="a" id={item.artifact_id} label="证据 ID" />],
              ["申请时间", <Time key="r" value={item.requested_at} />],
              ["案件状态", item.case_status === "open" ? "开放" : "已关闭"],
              ["证据目录", item.artifact_status === "active" ? "有效" : "已删除"],
              [
                "证据到期",
                <span key="e">
                  <Time value={item.artifact_expires_at} />
                  {item.artifact_time_expired ? "（已到期）" : ""}
                </span>,
              ],
              ["决策人", item.decided_by ?? "—"],
              [
                "决策理由",
                item.decision_reason ? (
                  <span key="d" className="xs-w-text">
                    {item.decision_reason}
                  </span>
                ) : (
                  "—"
                ),
              ],
              ["决策时间", <Time key="dt" value={item.decided_at} />],
              [
                "批准期限",
                item.decision_ttl_seconds === null ? "—" : formatTtl(item.decision_ttl_seconds),
              ],
              [
                "访问到期",
                <span key="ae">
                  <Time value={item.access_expires_at} />
                  {item.capability_time_expired ? "（已过期）" : ""}
                </span>,
              ],
            ]}
          />
          {item.stored_status === "approved" && (
            <section className="xs-w-card" aria-label="下载原文">
              <h4>下载原文</h4>
              <p className="xs-w-muted">
                需要 SensitiveEvidenceReader、最近 2 分钟内的 MFA
                再认证，并受独立批准、期限与案件、证据状态约束。 文件以 .bin
                附件交给浏览器保存，页面不显示、不解释内容。
              </p>
              {(() => {
                const reasons = whyNotLive(item);
                const expired = item.capability_time_expired === true;
                const downloadable = reasons.length === 0 && !expired;
                const blocked = !downloadable
                  ? `当前不可下载：${[...reasons, ...(expired ? ["访问期限已过"] : [])].join("、")}`
                  : !has(role.reader)
                    ? "需要 SensitiveEvidenceReader 角色"
                    : own === false
                      ? "只有申请人本人可以下载"
                      : null;
                return (
                  <Space orientation="vertical" size="small">
                    <Button
                      type="primary"
                      icon={<DownloadOutlined aria-hidden="true" />}
                      disabled={blocked !== null}
                      loading={download.state.phase === "working"}
                      onClick={download.start}
                    >
                      下载原文（.bin）
                    </Button>
                    {blocked && <span className="xs-w-muted">{blocked}</span>}
                  </Space>
                );
              })()}
              {download.state.phase === "saved" && (
                <Alert
                  type="success"
                  showIcon
                  title={`已发起附件保存：${download.state.saved.filename}（${download.state.saved.bytes} 字节）`}
                  description={`管理请求 ID ${download.state.saved.requestId}。界面不能证明文件已保存到磁盘，附件由你负责保管。`}
                />
              )}
              {download.state.phase === "failed" && <ErrorNotice error={download.state.error} />}
            </section>
          )}
          {item.stored_status === "pending" && own === true && (
            <Alert
              type="info"
              showIcon
              title="这是你自己提交的申请"
              description="职责分离：申请人不能批准或拒绝自己的申请，需要另一位具备审批权限的主体处理。这里不提供批准或拒绝。"
            />
          )}
          {item.stored_status === "pending" && own !== true && has(role.approver) && (
            <AccessDecisionForm item={item} maxTtl={response.max_approval_ttl_seconds} />
          )}
          {shell && has(role.investigator) && (
            <div>
              <Button
                size="small"
                onClick={() =>
                  shell.run({
                    type: "search",
                    preset: { kind: "evidence_access_request_id", value: item.access_request_id },
                  })
                }
              >
                准备历史检索
              </Button>
              <span className="xs-w-muted">
                {" "}
                仅预填该申请的引用，需填写 UTC 时间窗并由 Investigator 独立提交。
              </span>
            </div>
          )}
        </div>
      )}
    </LoadState>
  );
}

function Notes({ item, own }: { item: Detail; own: boolean | null }) {
  const reasons = whyNotLive(item);
  if (item.stored_status === "pending" && reasons.length > 0) {
    return (
      <Alert
        type="warning"
        showIcon
        title={`目标已失效：${reasons.join("、")}`}
        description="已失效的待决申请只能被拒绝以终结并释放配额，不能批准。"
      />
    );
  }
  if (item.stored_status === "approved" && own === false) {
    return (
      <Alert
        type="info"
        showIcon
        title="已批准的原文只有申请人本人能读取"
        description="审批人可以复核记录，但下载由申请人的 SensitiveEvidenceReader 身份发起并重新授权。"
      />
    );
  }
  return null;
}

function AccessDecisionForm({ item, maxTtl }: { item: Detail; maxTtl: number }) {
  const { message } = AntdApp.useApp();
  const presets = ttlPresets(maxTtl);
  const [reason, setReason] = useState("");
  const [preset, setPreset] = useState<number | "custom">(presets[0]?.seconds ?? "custom");
  const [custom, setCustom] = useState<number | null>(null);
  const decide = useWrite<DecideVars, AccessDecision>(
    {
      label: "原文访问审批",
      path: (vars) => `/control/v1/evidence-access-requests/${vars.accessId}/${vars.decision}`,
      body: (vars) =>
        vars.decision === "approve"
          ? { reason: vars.reason, ttl_seconds: vars.ttl }
          : { reason: vars.reason },
      run: (client, vars, context) =>
        client.decideEvidenceAccess(
          vars.accessId,
          vars.decision,
          vars.reason,
          vars.decision === "approve" ? vars.ttl : null,
          context.idempotencyKey,
          context.signal,
        ),
      owner: owners.decideAccess(item.access_request_id),
      invalidate: [domains.evidence],
    },
    (response) => {
      message.success(response.status === "approved" ? "已批准访问申请" : "已拒绝访问申请");
      setReason("");
    },
  );
  const ttl = preset === "custom" ? custom : preset;
  const reasonIssue = textProblem(reason, "审批理由");
  const ttlIssue = ttlProblem(ttl, maxTtl);
  const reasons = whyNotLive(item);
  const live = reasons.length === 0;
  const id = `access-${item.access_request_id.slice(-6)}`;
  const submit = (decision: DecideVars["decision"]) => {
    void decide.submit({
      accessId: item.access_request_id,
      decision,
      reason,
      ttl: decision === "approve" ? ttl : null,
    });
  };
  if (decide.operation) {
    return (
      <section className="xs-w-card" aria-label="审批决定">
        <h4>审批决定</h4>
        <FrozenOperation
          operation={decide.operation}
          busy={decide.busy}
          onRetry={() => void decide.retry()}
        />
      </section>
    );
  }
  return (
    <section className="xs-w-card" aria-label="审批决定">
      <h4>审批决定</h4>
      {decide.rejection !== null && <ErrorNotice error={decide.rejection} />}
      <Field
        id={`${id}-reason`}
        label="审批理由"
        help={`${utf8Length(reason)}/512 字节；写入审计与决定记录。`}
        error={reason.length > 0 ? reasonIssue : null}
      >
        <Input.TextArea
          id={`${id}-reason`}
          value={reason}
          rows={3}
          autoComplete="off"
          spellCheck={false}
          aria-describedby={`${id}-reason-help`}
          onChange={(event) => setReason(event.target.value)}
        />
      </Field>
      <Field
        id={`${id}-ttl`}
        label="批准期限"
        help={`服务端上限 ${formatTtl(maxTtl)}；实际访问期限还受证据到期时间限制。`}
        error={preset === "custom" && ttlIssue ? ttlIssue : null}
      >
        <Space wrap>
          <Segmented<number | "custom">
            id={`${id}-ttl`}
            value={preset}
            onChange={setPreset}
            options={[
              ...presets.map((option) => ({ label: option.label, value: option.seconds })),
              { label: "自定义", value: "custom" as const },
            ]}
          />
          {preset === "custom" && (
            <InputNumber
              aria-label="自定义批准期限（秒）"
              min={1}
              max={maxTtl}
              step={60}
              precision={0}
              value={custom}
              onChange={(value) => setCustom(typeof value === "number" ? value : null)}
              suffix="秒"
            />
          )}
        </Space>
      </Field>
      <Space wrap>
        <Button
          type="primary"
          loading={decide.busy}
          disabled={!live || reasonIssue !== null || ttlIssue !== null}
          title={!live ? "目标已失效，只能拒绝" : (reasonIssue ?? ttlIssue ?? undefined)}
          onClick={() => submit("approve")}
        >
          批准
        </Button>
        <Button
          danger
          loading={decide.busy}
          disabled={reasonIssue !== null}
          onClick={() => submit("deny")}
        >
          拒绝
        </Button>
      </Space>
    </section>
  );
}
