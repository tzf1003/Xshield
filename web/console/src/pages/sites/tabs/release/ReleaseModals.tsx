import { Alert, Button, Modal, Select } from "antd";
import { useMemo, useState } from "react";
import { configFromStored } from "../../../../sites/model/config.ts";
import { diffConfigs } from "../../../../sites/model/diff.ts";
import { IdChip } from "../../../../ui/IdChip";
import { DiffTable } from "../../DiffView";
import type { WorkspaceApi } from "../../workspace/use-workspace.ts";
import { StepUpNotice } from "./StepUpNotice";
import type { Release } from "./use-release.ts";
import { useStepUpAdvice } from "./use-step-up.ts";

type ModalProps = {
  ws: WorkspaceApi;
  release: Release;
  open: boolean;
  onClose: () => void;
};

const revisionName = (revision: number | null) => (revision === null ? "当前修订" : `r${revision}`);
const servingName = (revision: number | null) => (revision === null ? "（尚无）" : `r${revision}`);

function Footer({
  onClose,
  confirm,
  disabled,
  danger = false,
  children,
}: {
  onClose: () => void;
  confirm: () => void;
  disabled: boolean;
  danger?: boolean;
  children: string;
}) {
  return (
    <>
      <Button onClick={onClose}>取消</Button>
      <Button type="primary" danger={danger} disabled={disabled} onClick={confirm}>
        {children}
      </Button>
    </>
  );
}

/** The field-level change the action carries, or why it cannot be shown. */
function ChangeSection({
  release,
  heading,
  note,
}: {
  release: Release;
  heading: string;
  note?: string;
}) {
  return (
    <section className="xs-modal-section">
      <h4>{heading}</h4>
      {note && release.changes && <p className="xs-modal-note muted">{note}</p>}
      {release.changes ? (
        <DiffTable
          changes={release.changes}
          showRisk={release.comparesServed}
          empty="与 edge 在用的版本没有字段差异。"
        />
      ) : (
        <p className="muted">{release.diffNote}</p>
      )}
    </section>
  );
}

export function ApproveModal({ ws, release, open, onClose }: ModalProps) {
  const advice = useStepUpAdvice(open);
  const { view } = ws;
  const { review } = release;
  const name = revisionName(view.desired_revision);
  const active = servingName(view.active_revision);

  function confirm() {
    onClose();
    void ws.run("approve", () => ws.writes.approve.submit({ digest: review.digest }));
  }

  return (
    <Modal
      open={open}
      onCancel={onClose}
      title={`批准并应用 ${name}`}
      width={800}
      destroyOnHidden
      footer={
        <Footer onClose={onClose} confirm={confirm} disabled={ws.locked || review.stale}>
          确认批准
        </Footer>
      }
    >
      {review.stale && (
        <Alert
          type="error"
          showIcon
          role="note"
          title="页面上读到的修订与服务端当前暂存的不一致"
          description="修订历史里的摘要和状态里报告的摘要不同，说明它在两次读取之间变了。请关闭后点“刷新站点”重新核对，再批准。"
        />
      )}
      <dl className="xs-release-meta xs-modal-facts">
        <div>
          <dt>要批准的修订</dt>
          <dd className="mono">{name}</dd>
        </div>
        <div>
          <dt>提交人</dt>
          <dd className="xs-wrap">{release.staged?.created_by ?? "未读取"}</dd>
        </div>
        <div>
          <dt>edge 正在服务</dt>
          <dd className="mono">{active}</dd>
        </div>
        <div>
          <dt>绑定的配置摘要</dt>
          <dd>
            {review.digest ? (
              <IdChip value={review.digest} label="绑定的配置摘要" maxLength={18} />
            ) : (
              "未绑定"
            )}
          </dd>
        </div>
      </dl>
      <p className="muted">
        {review.digest
          ? "批准会带上这个摘要：如果服务端暂存的修订已经不是它，会被拒绝，而不是批准另一个版本。"
          : "当前读不到配置摘要，批准不绑定摘要：服务端批准的是它此刻暂存的修订。"}
      </p>
      <ChangeSection release={release} heading="将要发布的变更" />
      <section className="xs-modal-section">
        <h4>批准之后</h4>
        <ul className="xs-consequences">
          <li>你的批准写入审计记录，并绑定到上面的配置摘要。</li>
          <li>
            控制面立即把 {name} 下发给 edge；edge 确认之前仍在服务 {active}。
          </li>
          <li>下发失败时站点显示“应用失败”，edge 继续服务上一版本；可以重试，也可以回滚。</li>
          <li>提交人不能批准自己的修订，服务端会拒绝。</li>
        </ul>
      </section>
      <StepUpNotice advice={advice} action="批准" />
    </Modal>
  );
}

export function ApplyModal({ ws, release, open, onClose }: ModalProps) {
  const { view } = ws;
  const name = revisionName(view.desired_revision);
  const active = servingName(view.active_revision);

  function confirm() {
    onClose();
    void ws.run("apply", () => ws.writes.apply.submit({}));
  }

  return (
    <Modal
      open={open}
      onCancel={onClose}
      title={`应用 ${name}`}
      width={800}
      destroyOnHidden
      footer={
        <Footer onClose={onClose} confirm={confirm} disabled={ws.locked}>
          确认应用
        </Footer>
      }
    >
      <ChangeSection release={release} heading="将要发布的变更" />
      <section className="xs-modal-section">
        <h4>应用之后</h4>
        <ul className="xs-consequences">
          <li>
            控制面把 {name} 下发给 edge；edge 确认之前仍在服务 {active}。
          </li>
          <li>
            {view.requires_approval === false
              ? "服务端判定这次变更无需审批。"
              : "是否需要审批由服务端判断；需要审批的修订会被拒绝，请先由审批人批准。"}
          </li>
          <li>下发失败时站点显示“应用失败”，edge 继续服务上一版本。</li>
          {view.active_revision !== null && view.active_revision === view.desired_revision && (
            <li>edge 已经确认这个修订；再次应用只会重新下发同一份内容。</li>
          )}
        </ul>
      </section>
    </Modal>
  );
}

/** What the server will restore, as far as the console can know it, and what happens next. */
function RollbackBody({ ws, release }: { ws: WorkspaceApi; release: Release }) {
  const { view, revisions } = ws;
  const { plan } = release;
  const [preview, setPreview] = useState<number | null>(null);

  const candidates = useMemo(
    () => revisions.filter((item) => plan.candidates.includes(item.revision)),
    [revisions, plan.candidates],
  );
  const previewChanges = useMemo(() => {
    const chosen = candidates.find((item) => item.revision === preview);
    const parsed = chosen ? configFromStored(chosen.config, chosen.policy_revision) : null;
    return parsed && release.servingConfig ? diffConfigs(release.servingConfig, parsed) : null;
  }, [candidates, preview, release.servingConfig]);

  const next = view.desired_revision === null ? "" : ` r${view.desired_revision + 1}`;
  const created = (
    <li>
      创建一个<strong>新修订</strong>
      {next}，内容等于被恢复的修订；不会删除或改写任何旧修订。
    </li>
  );

  if (!release.known) {
    return (
      <>
        <Alert
          type="info"
          showIcon
          role="note"
          title="当前角色读不到站点状态，无法预览回滚会恢复哪个修订。"
          description="服务端的规则：有待生效的变更时，恢复 edge 在用的修订；否则恢复上一个曾在 edge 生效的修订。"
        />
        <section className="xs-modal-section">
          <h4>回滚之后</h4>
          <ul className="xs-consequences">
            {created}
            <li>是否需要审批按普通变更的规则判断；需要时，另一位审批人批准后才会生效。</li>
          </ul>
        </section>
      </>
    );
  }

  return (
    <>
      <p>
        edge 正在服务 <span className="mono">r{view.active_revision}</span>，暂存{" "}
        <span className="mono">{revisionName(view.desired_revision)}</span>。
      </p>
      {plan.cancelsPendingChange ? (
        <>
          <Alert
            type="info"
            showIcon
            role="note"
            title={`有一项变更还没有生效：回滚会放弃它，恢复为 edge 在用的 r${plan.target}。`}
            description="服务端的规则：有待生效的变更时，回滚的目标就是 edge 在用的修订。"
          />
          <ChangeSection
            release={release}
            heading={`将被放弃的变更（r${plan.target} → ${revisionName(view.desired_revision)}）`}
            note="回滚之后，这些字段回到“修改前”的值，也就是 edge 一直在用的值。"
          />
        </>
      ) : (
        <>
          <Alert
            type="info"
            showIcon
            role="note"
            title="没有待生效的变更：回滚会恢复上一个曾在 edge 生效的修订。"
            description="那个修订由服务端按生效顺序选择；控制台读不到这个顺序，所以不能替你指定，也不能事先点名。它不一定是编号小一号的那个。"
          />
          {candidates.length > 0 && (
            <section className="xs-modal-section">
              <h4>预览较早的修订（只用来对比，不决定回滚目标）</h4>
              <Select
                aria-label="预览较早的修订"
                className="xs-preview-select"
                value={preview}
                onChange={setPreview}
                allowClear
                placeholder="选择一个较早的修订，对比它与在用版本的差异"
                options={candidates.map((item) => ({
                  value: item.revision,
                  label: `r${item.revision} · ${item.created_by}`,
                }))}
              />
              {preview !== null && previewChanges && (
                <DiffTable
                  changes={previewChanges}
                  showRisk
                  empty={`r${preview} 与在用的 r${view.active_revision} 没有字段差异。`}
                />
              )}
              {preview !== null && !previewChanges && (
                <p className="muted">无法读取这个修订的内容，不能预览。</p>
              )}
            </section>
          )}
        </>
      )}
      <section className="xs-modal-section">
        <h4>回滚之后</h4>
        <ul className="xs-consequences">
          {created}
          <li>
            {plan.cancelsPendingChange
              ? "新修订与 edge 在用的版本内容相同，没有差异，不需要审批，写入后立即下发。"
              : "是否需要审批按普通变更的规则判断（与 edge 在用的版本比较）；需要时，另一位审批人批准后才会生效。"}
          </li>
          <li>edge 确认之前仍在服务 r{view.active_revision}。</li>
          {ws.access.canObserve && (
            <li>回滚之后可以在修订历史里核对：新修订会标出“内容与 rN 相同”。</li>
          )}
        </ul>
      </section>
    </>
  );
}

export function RollbackModal({ ws, release, open, onClose }: ModalProps) {
  function confirm() {
    onClose();
    void ws.run("rollback", () => ws.writes.rollback.submit({}));
  }
  return (
    <Modal
      open={open}
      onCancel={onClose}
      title="回滚站点配置"
      width={800}
      destroyOnHidden
      footer={
        <Footer onClose={onClose} confirm={confirm} disabled={ws.locked} danger>
          确认回滚
        </Footer>
      }
    >
      <RollbackBody ws={ws} release={release} />
    </Modal>
  );
}
