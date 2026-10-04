import { Space } from "antd";
import type { JobView } from "../jobs.ts";
import { Facts, IdChip, StatePill, Time } from "./Parts";
import { jobPill } from "./status.ts";

/**
 * A case-analysis job as the server reports it: a metadata-only inventory count. It reads no
 * evidence content, calls no model and creates no capability.
 */
export function JobCard({ job, requestId }: { job: JobView; requestId: string }) {
  return (
    <div className="xs-w-stack">
      <Space wrap>
        <StatePill pill={jobPill[job.status]} />
        <IdChip id={job.job_id} label="任务 ID" />
      </Space>
      <Facts
        rows={[
          ["案件", <IdChip key="c" id={job.case_id} label="案件 ID" />],
          ["引用总数", job.artifact_count],
          ["当前有效引用", job.active_artifact_count],
          [
            "检查点",
            <span key="k" className="mono">
              {job.checkpoint}
            </span>,
          ],
          [
            "原因码",
            <span key="r" className="mono">
              {job.reason_code}
            </span>,
          ],
          ["可重试", job.retryable ? "是" : "否"],
          ["创建时间", <Time key="ct" value={job.created_at} />],
          ["更新时间", <Time key="ut" value={job.updated_at} />],
          ["完成时间", <Time key="dt" value={job.completed_at} />],
          [
            "管理请求 ID",
            <span key="rq" className="mono">
              {requestId}
            </span>,
          ],
        ]}
      />
    </div>
  );
}
