import { DownloadOutlined, ReloadOutlined } from "@ant-design/icons";
import { App as AntdApp, Alert, Button, Input, Space } from "antd";
import { useState } from "react";
import type { InvestigationExport } from "../exports.ts";
import { useGuardedQuery } from "../security/hooks";
import { useAttachmentDownload } from "./downloads.ts";
import { textProblem, utf8Length } from "./format.ts";
import { owners } from "./operations.ts";
import { ErrorNotice, Facts, Field, IdChip, LoadState, StatePill, Time } from "./Parts";
import { domains, specs } from "./queries.ts";
import { isOwnRequest, role, useRoles } from "./roles.ts";
import { exportLapsed, exportPill } from "./status.ts";
import { useWrite } from "./use-write.ts";
import { FrozenOperation } from "./WriteDialog";

const CLAIM_LIMIT = 2;

type DecideVars = { exportId: string; decision: "approve" | "deny"; reason: string };

/**
 * One metadata export, read fresh from the server. An independent approver decides (MFA step-up
 * required), and the requester downloads the package once it is ready (step-up required, at most
 * two claims). The package is a bounded JSON attachment; its content is never shown here.
 */
export function ExportDetail({
  exportId,
  ownership,
  observedAt,
}: {
  exportId: string;
  ownership?: "mine" | "others";
  /**
   * The database observation time of the list this export came from. The detail itself carries
   * no server time, so an expiry is only judged against a server observation, never against the
   * browser clock; a deep link without one shows the server's state as it is.
   */
  observedAt?: string;
}) {
  const query = useGuardedQuery(specs.exportDetail(exportId));
  const { has, subject } = useRoles();
  const item = query.data;
  const own = item
    ? ownership
      ? ownership === "mine"
      : isOwnRequest(item.requested_by, subject)
    : null;
  const download = useAttachmentDownload({
    target: exportId,
    fetch: (client, signal) => {
      if (!item || item.package_artifact_id === null || item.package_bytes === null) {
        throw new Error("export package is not ready");
      }
      return client.downloadExport(
        item.export_id,
        item.package_artifact_id,
        item.package_bytes,
        signal,
      );
    },
    filename: () => "investigation-export.json",
    onSaved: () => void query.refetch(),
  });
  const lapsed = item && observedAt ? exportLapsed(item, Date.parse(observedAt)) : false;

  return (
    <LoadState pending={query.isPending} error={query.error} onRetry={() => void query.refetch()}>
      {item && (
        <div className="xs-w-stack">
          <div className="xs-w-between">
            <Space wrap>
              <StatePill pill={exportPill(item.status, lapsed)} />
              <IdChip id={item.export_id} label="导出 ID" />
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
          <span className="xs-w-muted xs-w-observed">
            读取于 <Time value={new Date(query.dataUpdatedAt).toISOString()} />
            （本机时间）· 管理请求 <span className="mono">{item.request_id}</span>
          </span>
          <Facts
            rows={[
              [
                "用途",
                <span key="p" className="xs-w-text">
                  {item.purpose}
                </span>,
              ],
              ["申请人", item.requested_by],
              ["案件", <IdChip key="c" id={item.case_id} label="案件 ID" />],
              ["类型", "仅元数据（案件与证据目录，不含证据正文）"],
              ["申请时间", <Time key="r" value={item.created_at} />],
              ["决策人", item.decided_by ?? "—"],
              ["决策时间", <Time key="dt" value={item.decided_at} />],
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
              ["到期", <Time key="e" value={item.expires_at} />],
              [
                "包",
                item.package_bytes === null
                  ? "尚未生成"
                  : `${item.package_bytes.toLocaleString("en-US")} 字节`,
              ],
              ["已领取", `${item.download_count} / ${CLAIM_LIMIT} 次`],
            ]}
          />
          {item.status === "ready" && (
            <section className="xs-w-card" aria-label="下载导出包">
              <h4>下载导出包</h4>
              <p className="xs-w-muted">
                剩余领取 {Math.max(0, CLAIM_LIMIT - item.download_count)}/{CLAIM_LIMIT} 次，到期{" "}
                <Time value={item.expires_at} />
                。每次成功领取都会消耗一次；需要 SensitiveEvidenceReader 与最近 2 分钟内的 MFA
                再认证。包只含案件与证据目录元数据， 以 JSON 附件保存，页面不显示其内容。
              </p>
              {(() => {
                const blocked = lapsed
                  ? "导出包期限已过"
                  : item.download_count >= CLAIM_LIMIT
                    ? "领取次数已用完"
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
                      下载导出包
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
                  description={`管理请求 ID ${download.state.saved.requestId}。服务端已记录这次领取；界面不能证明文件已保存到磁盘。`}
                />
              )}
              {download.state.phase === "failed" && <ErrorNotice error={download.state.error} />}
            </section>
          )}
          {item.status === "approved" && (
            <Alert
              type="info"
              showIcon
              title="已批准，元数据包尚未生成完成"
              description="批准已提交但包尚未就绪；原批准人可用原请求原样重试以确认结果。读取状态不会产生下载能力。"
            />
          )}
          {item.status === "pending_approval" && own === true && (
            <Alert
              type="info"
              showIcon
              title="这是你自己提交的导出申请"
              description="职责分离：申请人不能批准或拒绝自己的导出，需要另一位具备审批权限的主体处理。这里不提供批准或拒绝。"
            />
          )}
          {item.status === "pending_approval" && own !== true && has(role.approver) && (
            <ExportDecisionForm item={item} />
          )}
        </div>
      )}
    </LoadState>
  );
}

function ExportDecisionForm({ item }: { item: InvestigationExport }) {
  const { message } = AntdApp.useApp();
  const [reason, setReason] = useState("");
  const decide = useWrite<DecideVars, InvestigationExport>(
    {
      label: "导出审批",
      path: (vars) => `/control/v1/exports/${vars.exportId}/${vars.decision}`,
      body: (vars) => ({ reason: vars.reason }),
      run: (client, vars, context) =>
        client.decideExport(
          vars.exportId,
          vars.decision,
          vars.reason,
          context.idempotencyKey,
          context.signal,
        ),
      owner: owners.decideExport(item.export_id),
      invalidate: [domains.evidence],
    },
    (response) => {
      message.success(response.status === "rejected" ? "已拒绝导出申请" : "已批准导出申请");
      setReason("");
    },
  );
  const issue = textProblem(reason, "审批理由");
  const id = `export-${item.export_id.slice(-6)}`;
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
  const submit = (decision: DecideVars["decision"]) =>
    void decide.submit({ exportId: item.export_id, decision, reason });
  return (
    <section className="xs-w-card" aria-label="审批决定">
      <h4>审批决定</h4>
      <p className="xs-w-muted">
        批准或拒绝都需要最近 2 分钟内的 MFA 再认证；批准会生成 15
        分钟内有效的元数据包，并最多可领取两次。
      </p>
      {decide.rejection !== null && <ErrorNotice error={decide.rejection} />}
      <Field
        id={`${id}-reason`}
        label="审批理由"
        help={`${utf8Length(reason)}/512 字节；写入审计与决定记录。`}
        error={reason.length > 0 ? issue : null}
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
      <Space wrap>
        <Button
          type="primary"
          loading={decide.busy}
          disabled={issue !== null}
          onClick={() => submit("approve")}
        >
          批准
        </Button>
        <Button
          danger
          loading={decide.busy}
          disabled={issue !== null}
          onClick={() => submit("deny")}
        >
          拒绝
        </Button>
      </Space>
    </section>
  );
}
