import type { AccessInspection } from "./evidence-access";
import { Rows } from "./panels";

/** This snapshot supports human review; every decision and read reauthorizes. */
export function AccessDetails({ response }: { response: AccessInspection }) {
  const item = response.access_request;
  return (
    <div className="detail-body case-snapshot">
      <Rows
        entries={[
          ["申请 ID", item.access_request_id],
          ["案件", item.case_id],
          ["证据", item.artifact_id],
          ["申请人", item.requested_by],
          ["访问种类", item.access_kind],
          ["申请理由", item.justification],
          ["持久状态", item.stored_status],
          ["申请时间", item.requested_at],
          ["申请事件", item.requested_event_id],
          ["案件状态", item.case_status],
          ["目录状态", item.artifact_status],
          ["证据到期时间", item.artifact_expires_at],
          ["证据已到期", item.artifact_time_expired ? "是" : "否"],
          ["决策人", item.decided_by ?? "—"],
          ["决策理由", item.decision_reason ?? "—"],
          ["决策期限（秒）", item.decision_ttl_seconds ?? "—"],
          ["决策事件", item.decision_event_id ?? "—"],
          ["决策时间", item.decided_at ?? "—"],
          ["访问到期时间", item.access_expires_at ?? "—"],
          [
            "访问期限已过",
            item.capability_time_expired === null
              ? "—"
              : item.capability_time_expired
                ? "是"
                : "否",
          ],
          ["当前批准期限上限（秒）", response.max_approval_ttl_seconds],
          ["数据库 as_of", response.as_of],
          ["管理请求 ID", response.request_id],
        ]}
      />
      <p className="footnote">
        以上为数据库观察时的历史事实。提交审批和下载时，服务端重新校验主体、角色、案件、目录、审批及期限。
      </p>
    </div>
  );
}
