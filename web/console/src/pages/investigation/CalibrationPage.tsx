import { HistoryOutlined, ReloadOutlined } from "@ant-design/icons";
import { useParams } from "@tanstack/react-router";
import { Button, Descriptions, Skeleton } from "antd";
import { type ReactNode, useState } from "react";
import { calibrationReportPattern } from "../../api-contract.ts";
import type { CalibrationReport, CalibrationReportResponse } from "../../api.ts";
import { calibrationPath, useInvestigationNavigate } from "../../investigation/navigation.ts";
import { canAuditAdminister } from "../../investigation/roles.ts";
import { useSession } from "../../security/SessionProvider";
import { useGuardedQuery } from "../../security/hooks";
import { MANUAL_REFRESH } from "../../security/query-client.ts";
import { EventTime } from "../../ui/EventTime";
import { ObjectId } from "../../ui/ObjectId";
import { EmptyState, ErrorState } from "../../ui/states";
import { TonePill } from "../../ui/TonePill";
import { ArtifactDrawer } from "./ArtifactDrawer";
import { IdLookup } from "./IdLookup";
import "./investigation.css";
import "./lifecycle.css";

const ROLE_TEXT = "校准报告元数据需要 AuditAdministrator 角色，由服务端独立校验。";

/** 校准报告: the frozen metadata of one restricted calibration report, never its body. */
export function CalibrationPage() {
  const { reportId } = useParams({ strict: false }) as { reportId?: string };
  const navigateTo = useInvestigationNavigate();
  if (reportId) return <CalibrationDetail key={reportId} id={reportId} />;
  return (
    <div className="xs-page">
      <section className="xs-card" aria-label="校准报告调查说明">
        <div className="xs-card-head">
          <h2>受限校准报告元数据</h2>
        </div>
        <IdLookup
          label="校准报告 ID"
          prefix="calr_"
          pattern={calibrationReportPattern}
          buttonText="读取报告"
          onOpen={(id) => navigateTo.go(calibrationPath(id))}
        />
        <Explanation />
      </section>
    </div>
  );
}

function Explanation() {
  return (
    <>
      <p className="xs-foot">
        这里仅显示已冻结的报告元数据与正文 tombstone
        状态。它不显示或读取报告正文、样本、标签、概率、指标、提示词或任何内容读取能力。
      </p>
      <p className="xs-foot">
        每次读取均由服务端独立重新鉴权并写管理审计；控制台不会自动轮询。{ROLE_TEXT}
      </p>
    </>
  );
}

function CalibrationDetail({ id }: { id: string }) {
  const { state } = useSession();
  const navigateTo = useInvestigationNavigate();
  const query = useGuardedQuery({
    key: ["investigation", "calibration", id],
    fetch: (client, signal) => client.calibrationReport(id, signal),
    staleTime: MANUAL_REFRESH,
    gcTime: 0,
  });
  const [artifactId, setArtifactId] = useState<string | null>(null);
  const allowed = canAuditAdminister(state.roles);

  const head = (response: CalibrationReportResponse | undefined) => (
    <div className="xs-card-head">
      <h2>校准报告</h2>
      <ObjectId value={response?.source_report_id ?? id} wrap />
      <Button
        size="small"
        icon={<ReloadOutlined aria-hidden="true" />}
        disabled={query.isFetching}
        onClick={() => void query.refetch()}
      >
        手动刷新报告
      </Button>
    </div>
  );

  return (
    <div className="xs-page">
      <section className="xs-card" aria-label="校准报告调查说明">
        <h2>受限校准报告元数据</h2>
        <Explanation />
        {!allowed ? (
          <p className="xs-field-error" role="status">
            当前会话没有 AuditAdministrator 角色，读取很可能被服务端拒绝。
          </p>
        ) : null}
      </section>
      {query.isPending && query.isFetching ? (
        <Skeleton active paragraph={{ rows: 8 }} aria-label="正在读取校准报告" />
      ) : query.isError ? (
        <ErrorState
          error={query.error}
          onRetry={() => void query.refetch()}
          retryLabel="重新读取"
          title="无法读取校准报告"
        />
      ) : query.data ? (
        <section className="xs-card" aria-label="校准报告详情" aria-busy={query.isFetching}>
          {head(query.data)}
          {query.data.report ? (
            <ReportFacts
              response={query.data}
              report={query.data.report}
              onArtifact={setArtifactId}
              onHistory={() =>
                navigateTo.openSearch({
                  kind: "calibration_report_id",
                  value: (query.data.report as CalibrationReport).report_id,
                })
              }
            />
          ) : (
            <EmptyState title="当前范围内未找到报告" icon="search">
              该结果不推断报告不存在于其他范围，也不提供任何内容或读取能力。
            </EmptyState>
          )}
        </section>
      ) : null}
      <ArtifactDrawer
        artifactId={artifactId}
        onClose={() => setArtifactId(null)}
        canAddToCase={false}
        onAddToCase={() => undefined}
      />
    </div>
  );
}

function ReportFacts({
  response,
  report,
  onArtifact,
  onHistory,
}: {
  response: CalibrationReportResponse;
  report: CalibrationReport;
  onArtifact: (id: string) => void;
  onHistory: () => void;
}) {
  const mono = (value: string) => <span className="mono">{value}</span>;
  const artifact = (value: string): ReactNode => (
    <ObjectId value={value} wrap onOpen={() => onArtifact(value)} />
  );
  const unrecorded = "历史记录未提供";
  return (
    <div className="xs-detail-facts">
      <Descriptions
        bordered
        size="small"
        column={{ xs: 1, md: 2 }}
        title="冻结与保留"
        items={[
          {
            key: "request",
            label: "管理请求 ID",
            children: <ObjectId value={response.request_id} wrap />,
          },
          {
            key: "as_of",
            label: "数据库观察时间",
            children: response.as_of ? (
              <span className="xs-times">
                <EventTime value={response.as_of} precision="microsecond" />
                {mono(response.as_of)}
              </span>
            ) : (
              "未返回观察时间"
            ),
          },
          {
            key: "completed",
            label: "批次完成时间",
            children: <EventTime value={report.completed_at} precision="second" />,
          },
          {
            key: "reported",
            label: "报告冻结时间",
            children: <EventTime value={report.reported_at} precision="second" />,
          },
          {
            key: "event",
            label: "报告事件",
            children: <ObjectId value={report.reported_event_id} wrap />,
          },
          {
            key: "expires",
            label: "正文保留至",
            children: <EventTime value={report.body_expires_at} precision="second" />,
          },
          { key: "approval", label: "批准引用", children: mono(report.approval_ref) },
          {
            key: "tombstone",
            label: "报告正文 tombstone",
            children:
              report.body_status === "active" ? (
                <TonePill tone="allow">active（未记录终态删除）</TonePill>
              ) : (
                <TonePill tone="observe">deleted（已记录终态删除）</TonePill>
              ),
          },
        ]}
      />
      <Descriptions
        bordered
        size="small"
        column={{ xs: 1, md: 2 }}
        title="数据集与修订"
        items={[
          { key: "dataset", label: "数据集修订", children: mono(report.dataset_revision) },
          { key: "label", label: "标签集修订", children: mono(report.label_revision) },
          { key: "task", label: "任务语义修订", children: mono(report.task_revision) },
          {
            key: "threshold",
            label: "阈值策略修订",
            children: mono(report.threshold_policy_revision),
          },
          { key: "mapping", label: "风险映射修订", children: mono(report.mapping_revision) },
        ]}
      />
      <Descriptions
        bordered
        size="small"
        column={{ xs: 1, md: 2 }}
        title="证据引用（仅元数据）"
        items={[
          { key: "report", label: "报告 artifact", children: artifact(report.report_artifact_id) },
          {
            key: "evaluation",
            label: "评估 manifest",
            children: artifact(report.evaluation_manifest_artifact_id),
          },
          {
            key: "training",
            label: "训练 manifest",
            children: artifact(report.training_manifest_artifact_id),
          },
          {
            key: "calibration",
            label: "校准 manifest",
            children: artifact(report.calibration_manifest_artifact_id),
          },
          {
            key: "labels",
            label: "标签 manifest",
            children: artifact(report.label_manifest_artifact_id),
          },
        ]}
      />
      <Descriptions
        bordered
        size="small"
        column={{ xs: 1, md: 2 }}
        title="模型"
        items={[
          { key: "provider", label: "供应商", children: mono(report.provider) },
          {
            key: "providerModel",
            label: "供应商模型 ID",
            children: mono(report.provider_model_id),
          },
          { key: "revision", label: "内部模型修订", children: mono(report.model_revision) },
          { key: "prompt", label: "提示修订", children: mono(report.prompt_revision) },
          {
            key: "resolved",
            label: "已解析模型修订",
            children: report.resolved_model_revision
              ? mono(report.resolved_model_revision)
              : unrecorded,
          },
          {
            key: "lineage",
            label: "血缘审查",
            children: report.lineage_review_id ? mono(report.lineage_review_id) : unrecorded,
          },
        ]}
      />
      <p className="xs-foot">
        正文 tombstone
        状态只说明专用加密正文的保留观察；它不表示正文可读、质量已验证、阈值或策略已发布，亦不表示业务资格。
      </p>
      <div className="xs-actions">
        <Button icon={<HistoryOutlined aria-hidden="true" />} onClick={onHistory}>
          准备历史检索
        </Button>
      </div>
      <p className="xs-foot">历史检索仅预填报告引用，仍需输入时间窗并由 Investigator 独立鉴权。</p>
    </div>
  );
}
