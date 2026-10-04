import { Skeleton } from "antd";
import type { WorkspaceApi } from "../../workspace/use-workspace.ts";
import type { Release } from "./use-release.ts";

const SHOWN_PER_REASON = 4;

/**
 * 为什么需要审批, in the console's words. The server decides and reports only yes or no; the
 * reasons are rebuilt here from the two stored revisions with the server's own rules, so they
 * are an explanation, not a second opinion: where the two differ, the server's verdict stands
 * and the page says so.
 */
export function ApprovalCard({ ws, release }: { ws: WorkspaceApi; release: Release }) {
  const { view } = ws;
  const { need } = release;
  if (!release.known) return null;
  if (release.loading) {
    return (
      <section className="xs-card" aria-label="审批说明">
        <h3>审批</h3>
        <Skeleton active paragraph={{ rows: 2 }} />
      </section>
    );
  }
  // Nothing staged beyond what the edge serves: there is nothing to approve or explain.
  if (!release.pending && need.verdict !== true) return null;
  if (view.status === "draft" && need.verdict !== true) {
    return (
      <section className="xs-card" aria-label="审批说明">
        <h3>审批</h3>
        <p>
          草稿不会发布到
          edge，所以现在不涉及审批。把状态改为“启用”并保存后，它属于上线变更，需要另一位审批人批准后才会应用。
        </p>
      </section>
    );
  }

  const title =
    need.verdict === true ? "为什么需要审批" : need.verdict === false ? "无需审批" : "审批";
  const author = release.staged?.created_by ?? null;
  const explanation = need.explanation;
  return (
    <section className="xs-card" aria-label="审批说明">
      <h3>{title}</h3>
      {need.verdict === true && (
        <p>
          这次变更需要另一位具备审批人角色的操作者批准后才会发布
          {author ? (
            <>
              ；提交人 <span className="mono xs-wrap">{author}</span> 不能批准自己提交的修订
            </>
          ) : (
            "；提交人不能批准自己提交的修订"
          )}
          。
          {view.active_revision === null
            ? "在批准之前 edge 不会服务这个站点。"
            : `在批准之前 edge 继续使用 r${view.active_revision}。`}
        </p>
      )}
      {need.verdict === false && (
        <p>这次变更无需审批：涉及的字段都不在需要审批的范围内，可以直接应用。</p>
      )}
      {need.verdict === null && (
        <p>状态读取需要 observer 角色；是否需要审批由服务端在操作时判断。</p>
      )}

      {need.limitation && <p className="muted">{need.limitation}</p>}

      {explanation && explanation.reasons.length > 0 && (
        <ul className="xs-reasons">
          {explanation.reasons.map((reason) => (
            <li key={reason.token}>
              <strong>{reason.label}</strong>
              <span className="muted"> — {reason.detail}</span>
              {reason.changes.length > 0 && (
                <ul className="xs-reason-fields">
                  {reason.changes.slice(0, SHOWN_PER_REASON).map((change) => (
                    <li key={change.id}>
                      <span>{change.label}</span>{" "}
                      <span className="mono xs-wrap">
                        {change.before} → {change.after}
                      </span>
                    </li>
                  ))}
                  {reason.changes.length > SHOWN_PER_REASON && (
                    <li className="muted">
                      另有 {reason.changes.length - SHOWN_PER_REASON} 项，见“查看待发布差异”。
                    </li>
                  )}
                </ul>
              )}
            </li>
          ))}
        </ul>
      )}

      {explanation && explanation.free.length > 0 && (
        <p className="muted">
          无需审批的修改：{explanation.free.map((change) => change.label).join("、")}。
        </p>
      )}

      {need.disagrees && need.verdict === true && (
        <p className="muted">
          控制台没有在已知字段里找到具体原因：服务端对控制台尚未识别的字段一律要求审批。以服务端的结论为准。
        </p>
      )}
      {need.disagrees && need.verdict === false && (
        <p className="muted">
          控制台按已知规则推算这些改动通常需要审批，但服务端判定无需审批。以服务端的结论为准。
        </p>
      )}
    </section>
  );
}
