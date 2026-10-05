import { Alert, Button, Modal, Radio, Skeleton } from "antd";
import { useState } from "react";
import type { CaseItemAdded, CaseList } from "../../cases.ts";
import { useCursorPages } from "../../investigation/use-cursor-pages.ts";
import { useGuardedMutation, usePendingOperations } from "../../security/hooks";
import { ObjectId } from "../../ui/ObjectId";
import { EmptyState, ErrorState } from "../../ui/states";
import { EventTime } from "../../ui/EventTime";
import "./drawers.css";
import "./investigation.css";

type Vars = { caseId: string; artifactId: string };

const pathFor = (vars: Vars) => `/control/v1/cases/${vars.caseId}/items`;
const bodyFor = (vars: Vars) => ({ artifact_id: vars.artifactId });

type Props = {
  /** The evidence reference to add; `null` closes the dialog. */
  artifactId: string | null;
  onClose: () => void;
};

/**
 * Adds one evidence reference to one of the caller's OPEN cases. The write is frozen before it is
 * sent (path, body and idempotency key), so a result that cannot be established can only be
 * continued with the identical request. Association grants no content access.
 */
export function AddToCaseModal({ artifactId, onClose }: Props) {
  return (
    <Modal
      open={artifactId !== null}
      title="加入案件"
      footer={null}
      onCancel={onClose}
      destroyOnHidden
      width={560}
    >
      {artifactId ? (
        <AddToCaseBody key={artifactId} artifactId={artifactId} onClose={onClose} />
      ) : null}
    </Modal>
  );
}

function AddToCaseBody({ artifactId, onClose }: { artifactId: string; onClose: () => void }) {
  const cases = useCursorPages<CaseList>({
    key: ["investigation", "cases"],
    fetchPage: (client, cursor, signal) => client.cases(cursor, signal),
    // A case created on another page a moment ago must be offered: read the list on every open.
    discardOnUnmount: true,
  });
  const [selected, setSelected] = useState<string | null>(null);
  const operations = usePendingOperations();
  const mutation = useGuardedMutation<Vars, CaseItemAdded>({
    label: "将证据加入案件",
    method: "POST",
    path: pathFor,
    body: bodyFor,
    execute: (client, vars, { signal, idempotencyKey }) =>
      client.addCaseItem(vars.caseId, vars.artifactId, idempotencyKey, signal),
  });
  const result = mutation.result;
  const open = cases.pages.flatMap((page) => page.items).filter((item) => item.status === "open");

  // An unknown result keeps its frozen request in the registry; that entry is the retry handle.
  const frozen =
    result?.kind === "unknown" && selected
      ? operations.find(
          (operation) =>
            operation.phase === "unknown" &&
            operation.path === pathFor({ caseId: selected, artifactId }) &&
            operation.body === JSON.stringify(bodyFor({ caseId: selected, artifactId })),
        )
      : undefined;
  const locked = mutation.isPending || result?.kind === "unknown" || result?.kind === "confirmed";
  function confirm() {
    if (selected) void mutation.submit({ caseId: selected, artifactId });
  }

  return (
    <div className="xs-add-case">
      <p className="xs-foot">
        证据 <ObjectId value={artifactId} short quietCopy />{" "}
        将作为引用加入你名下的开放案件。加入不授予内容读取权限，也不延长证据的保留期限。
      </p>
      {cases.loading ? <Skeleton active paragraph={{ rows: 3 }} title={false} /> : null}
      {cases.firstError ? (
        <ErrorState error={cases.firstError} onRetry={cases.refresh} title="无法读取你的案件" />
      ) : null}
      {cases.pages.length > 0 && open.length === 0 ? (
        <EmptyState title="没有开放的案件">
          只有本人名下 open 状态的案件可以接收证据。请先到案件工作台创建案件。
        </EmptyState>
      ) : null}
      {open.length > 0 ? (
        <Radio.Group
          className="xs-case-list"
          value={selected}
          disabled={locked}
          onChange={(event) => setSelected(event.target.value as string)}
          aria-label="选择开放案件"
        >
          {open.map((item) => (
            <Radio key={item.case_id} value={item.case_id} className="xs-case-option">
              <span className="xs-case-purpose">{item.purpose}</span>
              <span className="xs-case-meta">
                <ObjectId value={item.case_id} short quietCopy copyable={false} />
                <EventTime value={item.created_at} />
              </span>
            </Radio>
          ))}
        </Radio.Group>
      ) : null}
      {cases.hasMore ? (
        <Button onClick={cases.loadMore} disabled={cases.loadingMore}>
          更多案件
        </Button>
      ) : null}

      {result?.kind === "confirmed" ? (
        <Alert
          type="success"
          showIcon
          role="status"
          title={result.response.replayed ? "原请求已确认，沿用既有关联" : "已加入案件"}
          description={
            <span>
              案件 <ObjectId value={result.response.case_id} short quietCopy />{" "}
              的证据集合已包含该引用。
            </span>
          }
        />
      ) : null}
      {result?.kind === "rejected" ? (
        <ErrorState error={result.error} title="服务端明确拒绝了这次加入" />
      ) : null}
      {result?.kind === "unknown" ? (
        <Alert
          type="warning"
          showIcon
          role="alert"
          title="结果未知：请求可能已经到达服务器"
          description={
            <div className="xs-fault">
              <span>
                只能用原幂等键和原参数确认。刷新页面、闲置或退出后这些信息会被清除；顶栏「待确认操作」里保留了原路径与幂等键。
              </span>
              {frozen ? (
                <Button
                  type="primary"
                  disabled={mutation.isPending}
                  onClick={() => void mutation.retry(frozen.id)}
                >
                  确认后原样重试
                </Button>
              ) : null}
            </div>
          }
        />
      ) : null}

      <div className="xs-modal-actions">
        {result?.kind === "confirmed" ? (
          <Button type="primary" onClick={onClose}>
            完成
          </Button>
        ) : (
          <>
            <Button onClick={onClose}>取消</Button>
            <Button type="primary" disabled={!selected || locked} onClick={confirm}>
              加入所选案件
            </Button>
          </>
        )}
      </div>
    </div>
  );
}
