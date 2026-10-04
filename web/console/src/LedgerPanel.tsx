import type { GrantResponse, BindingResponse } from "./ledger";
import type { ReactNode } from "react";
import { Rows } from "./panels";
import type { SearchPreset } from "./SearchPanel";

/** Ledger facts share one database observation time and carry no admission decision. */
export function LedgerPanel({
  response,
  onBinding,
  onRequest,
  onHistory,
}: {
  response: GrantResponse | BindingResponse;
  onBinding: (id: string) => void;
  onRequest: (id: string) => void;
  onHistory: (preset: SearchPreset) => void;
}) {
  const grant = "grant" in response ? response.grant : null;
  const identity = "binding" in response ? response.binding : null;
  const binding = grant?.binding ?? identity;
  const isGrant = "source_grant_id" in response;
  const target = isGrant ? response.source_grant_id : response.source_binding_id;
  return (
    <section className="panel" aria-label={isGrant ? "资格账本详情" : "身份绑定账本详情"}>
      <div className="panel-heading ledger-heading">
        <h2>{isGrant ? "资格账本快照" : "身份绑定账本快照"}</h2>
        <span className="mono">{target}</span>
      </div>
      <div className="detail-body">
        <Rows
          entries={[
            ["数据库时刻", <span className="mono">{response.as_of ?? "未返回观察时间"}</span>],
            ["管理请求 ID", <span className="mono">{response.request_id}</span>],
          ]}
        />
        <p className="footnote">
          这是数据库时刻的账本观察。实际请求仍须校验完整身份、来源证明、策略、目标和期限。
        </p>
        {!response.found ? (
          <div className="ledger-missing" role="status">
            <h3>当前账本未找到</h3>
            <p className="muted">当前范围未返回账本记录；历史事件可通过独立检索继续核对。</p>
          </div>
        ) : (
          <div className={grant ? "ledger-grid" : "ledger-record"}>
            {grant && (
              <section aria-label="资格记录">
                <h3>资格记录</h3>
                <Rows
                  entries={[
                    ["持久状态", grant.stored_status],
                    ["时间到期", grant.time_expired ? "已到期" : "未到期"],
                    ["发行身份代际", grant.auth_epoch],
                    ["发行时间", <span className="mono">{grant.issued_at}</span>],
                    ["到期时间", <span className="mono">{grant.expires_at}</span>],
                    ["资源类型", grant.resource_type],
                    ["操作 ID", <span className="mono">{grant.operation_id}</span>],
                    ["视图 ID", <span className="mono">{grant.view_id}</span>],
                    ["策略版本", <span className="mono">{grant.policy_revision}</span>],
                    ["来源事件", <span className="mono">{grant.source_event_id}</span>],
                    [
                      "来源请求",
                      <button
                        className="artifact-link mono"
                        onClick={() => onRequest(grant.source_request_id)}
                      >
                        {grant.source_request_id}
                      </button>,
                    ],
                  ]}
                />
              </section>
            )}
            {binding && (
              <section aria-label="身份绑定记录">
                <h3>{grant ? "当前绑定（同一快照）" : "身份绑定记录"}</h3>
                <Rows
                  entries={[
                    [
                      "绑定 ID",
                      grant ? (
                        <button
                          className="artifact-link mono"
                          onClick={() => onBinding(binding.binding_id)}
                        >
                          {binding.binding_id}
                        </button>
                      ) : (
                        <span className="mono">{binding.binding_id}</span>
                      ),
                    ],
                    ["持久状态", binding.stored_status],
                    ["时间到期", binding.time_expired ? "已到期" : "未到期"],
                    ["当前身份代际", binding.current_auth_epoch],
                    ...(grant
                      ? ([
                          ["发行代际对比", grant.binding.epoch_matches_grant ? "一致" : "不一致"],
                        ] as [string, string][])
                      : []),
                    ...(identity
                      ? ([["凭证代际", identity.credential_generation]] as [string, number][])
                      : []),
                    ["到期时间", <span className="mono">{binding.expires_at}</span>],
                    ...(identity
                      ? ([["更新时间", <span className="mono">{identity.updated_at}</span>]] as [
                          string,
                          ReactNode,
                        ][])
                      : []),
                  ]}
                />
              </section>
            )}
          </div>
        )}
        <div className="ledger-history">
          <button
            className="outline"
            onClick={() =>
              onHistory({
                kind: isGrant ? "grant_id" : "auth_binding_id",
                value: target,
              })
            }
          >
            准备历史检索
          </button>
          <p className="footnote">
            预填引用后需确认时间窗并提交。历史检索另需 Investigator；账本观察与历史索引各自查询。
          </p>
        </div>
      </div>
    </section>
  );
}
