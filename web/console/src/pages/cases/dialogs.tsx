/**
 * The write dialogs of the case center. Each one is mounted only while it is open, so its form
 * starts empty every time; what must outlive it (an unresolved write) lives in the pending
 * registry and reappears the next time the dialog opens.
 */
import { App as AntdApp, AutoComplete, Input, Segmented } from "antd";
import { useEffect, useRef, useState } from "react";
import { artifactPattern } from "../../api-contract.ts";
import type { CaseClosed, CaseCreated, CaseItem, CaseItemAdded } from "../../cases.ts";
import type { AccessRequested } from "../../evidence-access.ts";
import type { HoldMutation } from "../../evidence-holds.ts";
import type { InvestigationExport } from "../../exports.ts";
import { textProblem, utf8Length } from "../../work/format.ts";
import {
  formatUtcInput,
  HOLD_MAX_HOURS,
  HOLD_PRESETS,
  type HoldPreset,
  holdUntilOf,
  holdUntilProblem,
  holdWindow,
  parseUtcInput,
  presetDeadlineMs,
} from "../../work/holds.ts";
import { owners } from "../../work/operations.ts";
import { Field } from "../../work/Parts";
import { domains } from "../../work/queries.ts";
import { useWrite } from "../../work/use-write.ts";
import { WriteDialog } from "../../work/WriteDialog";

const reasonHelp = (value: string) => `${utf8Length(value)}/512 字节`;

/** 新建案件. */
export function CreateCaseDialog({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (created: CaseCreated) => void;
}) {
  const { message } = AntdApp.useApp();
  const [purpose, setPurpose] = useState("");
  // A reply that arrives after the operator left this dialog (or the page) is still announced,
  // but it must not pull them to the new case.
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  const write = useWrite<{ purpose: string }, CaseCreated>(
    {
      label: "创建案件",
      path: () => "/control/v1/cases",
      body: (vars) => ({ purpose: vars.purpose }),
      run: (client, vars, context) =>
        client.createCase(vars.purpose, context.idempotencyKey, context.signal),
      owner: owners.createCase(),
      invalidate: [domains.cases],
    },
    (created) => {
      message.success(created.replayed ? "案件已存在（返回原操作结果）" : "案件已创建");
      if (!alive.current) return;
      onClose();
      onCreated(created);
    },
  );
  const issue = textProblem(purpose, "调查目的");
  return (
    <WriteDialog
      title="新建案件"
      open
      onClose={onClose}
      write={write}
      submitText="创建案件"
      blocked={issue}
      onSubmit={() => void write.submit({ purpose })}
      onRetry={() => void write.retry()}
    >
      <Field
        id="case-purpose"
        label="调查目的"
        help={`${reasonHelp(purpose)}；创建案件只建立后续审批的上下文，不授予任何证据读取权。`}
        error={purpose.length > 0 ? issue : null}
      >
        <Input.TextArea
          id="case-purpose"
          value={purpose}
          rows={3}
          autoComplete="off"
          spellCheck={false}
          aria-describedby="case-purpose-help"
          onChange={(event) => setPurpose(event.target.value)}
        />
      </Field>
    </WriteDialog>
  );
}

/** 关闭案件. */
export function CloseCaseDialog({ caseId, onClose }: { caseId: string; onClose: () => void }) {
  const { message } = AntdApp.useApp();
  const [reason, setReason] = useState("");
  const write = useWrite<{ reason: string }, CaseClosed>(
    {
      label: "关闭案件",
      path: () => `/control/v1/cases/${caseId}/close`,
      body: (vars) => ({ reason: vars.reason }),
      run: (client, vars, context) =>
        client.closeCase(caseId, vars.reason, context.idempotencyKey, context.signal),
      owner: owners.closeCase(caseId),
      invalidate: [domains.cases],
    },
    (closed) => {
      message.success(closed.replayed ? "案件已关闭（返回原操作结果）" : "案件已关闭");
      onClose();
    },
  );
  const issue = textProblem(reason, "关闭理由");
  return (
    <WriteDialog
      title="关闭案件"
      open
      onClose={onClose}
      write={write}
      submitText="关闭案件"
      danger
      blocked={issue}
      onSubmit={() => void write.submit({ reason })}
      onRetry={() => void write.retry()}
    >
      <p>
        关闭后保留历史引用与原保留期限；新增关联、原文访问申请和后续读取校验都要求案件仍开放。已通过校验的在途读取可能完成，
        已释放的内容无法收回。
      </p>
      <Field
        id="case-close-reason"
        label="关闭理由"
        help={reasonHelp(reason)}
        error={reason.length > 0 ? issue : null}
      >
        <Input.TextArea
          id="case-close-reason"
          value={reason}
          rows={3}
          autoComplete="off"
          spellCheck={false}
          aria-describedby="case-close-reason-help"
          onChange={(event) => setReason(event.target.value)}
        />
      </Field>
    </WriteDialog>
  );
}

/** 关联证据. */
export function AddEvidenceDialog({ caseId, onClose }: { caseId: string; onClose: () => void }) {
  const { message } = AntdApp.useApp();
  const [artifactId, setArtifactId] = useState("");
  const write = useWrite<{ artifactId: string }, CaseItemAdded>(
    {
      label: "关联证据",
      path: () => `/control/v1/cases/${caseId}/items`,
      body: (vars) => ({ artifact_id: vars.artifactId }),
      run: (client, vars, context) =>
        client.addCaseItem(caseId, vars.artifactId, context.idempotencyKey, context.signal),
      owner: owners.addEvidence(caseId),
      invalidate: [domains.cases],
    },
    (added) => {
      message.success(added.replayed ? "证据已关联（返回原操作结果）" : "证据已关联");
      onClose();
    },
  );
  const issue = artifactPattern.test(artifactId)
    ? null
    : "请输入规范的证据 ID：artifact_ 前缀加小写 UUIDv7";
  return (
    <WriteDialog
      title="关联证据"
      open
      onClose={onClose}
      write={write}
      submitText="关联证据"
      blocked={issue}
      onSubmit={() => void write.submit({ artifactId })}
      onRetry={() => void write.retry()}
    >
      <Field
        id="add-artifact"
        label="证据 ID"
        help="新关联要求证据目录有效且未到期；每个案件最多 128 项。关联不授予读取权，也不延长保留期限。"
        error={artifactId.length > 0 ? issue : null}
      >
        <Input
          id="add-artifact"
          className="mono"
          value={artifactId}
          placeholder="artifact_…"
          autoComplete="off"
          spellCheck={false}
          aria-describedby="add-artifact-help"
          onChange={(event) => setArtifactId(event.target.value.trim())}
        />
      </Field>
    </WriteDialog>
  );
}

/** 申请原文访问: pick a member artifact (or paste one) and say why. */
export function RequestAccessDialog({
  caseId,
  members,
  initialArtifact,
  onClose,
}: {
  caseId: string;
  members: readonly CaseItem[];
  initialArtifact?: string;
  onClose: () => void;
}) {
  const { message } = AntdApp.useApp();
  const [artifactId, setArtifactId] = useState(initialArtifact ?? "");
  const [justification, setJustification] = useState("");
  const write = useWrite<{ artifactId: string; justification: string }, AccessRequested>(
    {
      label: "申请原文访问",
      path: (vars) => `/control/v1/artifacts/${vars.artifactId}/access`,
      body: (vars) => ({
        case_id: caseId,
        access_kind: "sensitive_raw",
        justification: vars.justification,
      }),
      run: (client, vars, context) =>
        client.requestEvidenceAccess(
          vars.artifactId,
          caseId,
          vars.justification,
          context.idempotencyKey,
          context.signal,
        ),
      owner: owners.requestAccess(caseId),
      invalidate: [domains.evidence],
    },
    (requested) => {
      message.success(
        requested.replayed ? "申请已存在（返回原操作结果）" : "访问申请已提交，等待独立审批",
      );
      onClose();
    },
  );
  const artifactIssue = artifactPattern.test(artifactId) ? null : "请选择或输入规范的证据 ID";
  const reasonIssue = textProblem(justification, "申请理由");
  const options = members.map((member) => ({
    value: member.artifact_id,
    label: `${member.artifact_id}（${member.catalog_status === "active" ? "目录有效" : "目录不可用于新申请"}）`,
  }));
  return (
    <WriteDialog
      title="申请原文访问"
      open
      onClose={onClose}
      write={write}
      submitText="提交申请"
      blocked={artifactIssue ?? reasonIssue}
      onSubmit={() => void write.submit({ artifactId, justification })}
      onRetry={() => void write.retry()}
    >
      <Field
        id="access-artifact"
        label="证据"
        help="从案件成员中选择，也可粘贴证据 ID。要求案件开放，且证据目录有效、未到期。"
        error={artifactId.length > 0 ? artifactIssue : null}
      >
        <AutoComplete
          id="access-artifact"
          className="mono"
          value={artifactId}
          options={options}
          placeholder="artifact_…"
          aria-describedby="access-artifact-help"
          onChange={(value: string) => setArtifactId(value.trim())}
          style={{ width: "100%" }}
        />
      </Field>
      <Field
        id="access-justification"
        label="申请理由"
        help={`${reasonHelp(justification)}；由另一位审批人复核，申请人不能自批。`}
        error={justification.length > 0 ? reasonIssue : null}
      >
        <Input.TextArea
          id="access-justification"
          value={justification}
          rows={3}
          autoComplete="off"
          spellCheck={false}
          aria-describedby="access-justification-help"
          onChange={(event) => setJustification(event.target.value)}
        />
      </Field>
    </WriteDialog>
  );
}

/** 申请导出. */
export function RequestExportDialog({ caseId, onClose }: { caseId: string; onClose: () => void }) {
  const { message } = AntdApp.useApp();
  const [purpose, setPurpose] = useState("");
  const write = useWrite<{ purpose: string }, InvestigationExport>(
    {
      label: "申请元数据导出",
      path: () => "/control/v1/exports",
      body: (vars) => ({ case_id: caseId, purpose: vars.purpose }),
      run: (client, vars, context) =>
        client.requestExport(caseId, vars.purpose, context.idempotencyKey, context.signal),
      owner: owners.requestExport(caseId),
      invalidate: [domains.evidence],
    },
    (requested) => {
      message.success(
        requested.replayed ? "导出申请已存在（返回原操作结果）" : "导出申请已提交，等待独立审批",
      );
      onClose();
    },
  );
  const issue = textProblem(purpose, "导出用途");
  return (
    <WriteDialog
      title="申请导出"
      open
      onClose={onClose}
      write={write}
      submitText="提交申请"
      blocked={issue}
      onSubmit={() => void write.submit({ purpose })}
      onRetry={() => void write.retry()}
    >
      <p>
        导出只包含案件与证据目录的元数据，不含证据正文、事件载荷或存储定位。需要另一位具备审批权限的主体批准；批准后包
        15 分钟内有效，最多领取两次。
      </p>
      <Field
        id="export-purpose"
        label="导出用途"
        help={reasonHelp(purpose)}
        error={purpose.length > 0 ? issue : null}
      >
        <Input.TextArea
          id="export-purpose"
          value={purpose}
          rows={3}
          autoComplete="off"
          spellCheck={false}
          aria-describedby="export-purpose-help"
          onChange={(event) => setPurpose(event.target.value)}
        />
      </Field>
    </WriteDialog>
  );
}

/** 创建保留锁, with a UTC-millisecond deadline limited to the server window. */
export function CreateHoldDialog({
  caseId,
  members,
  serverNow,
  onClose,
}: {
  caseId: string;
  members: readonly CaseItem[];
  /** The server clock, extrapolated from the history page's database observation. */
  serverNow: () => number;
  onClose: () => void;
}) {
  const { message } = AntdApp.useApp();
  const [artifactId, setArtifactId] = useState("");
  const [reason, setReason] = useState("");
  const [preset, setPreset] = useState<HoldPreset | "custom">("7d");
  const [custom, setCustom] = useState(() => formatUtcInput(presetDeadlineMs("7d", serverNow())));
  const write = useWrite<{ artifactId: string; reason: string; holdUntil: string }, HoldMutation>(
    {
      label: "创建保留锁",
      path: () => `/control/v1/cases/${caseId}/holds`,
      body: (vars) => ({
        artifact_id: vars.artifactId,
        reason: vars.reason,
        hold_until: vars.holdUntil,
      }),
      run: (client, vars, context) =>
        client.createEvidenceHold(
          caseId,
          vars.artifactId,
          vars.reason,
          vars.holdUntil,
          context.idempotencyKey,
          context.signal,
        ),
      owner: owners.createHold(caseId),
      invalidate: [domains.holds],
    },
    (created) => {
      message.success(created.replayed ? "保留锁已存在（返回原操作结果）" : "保留锁已创建");
      onClose();
    },
  );
  const now = serverNow();
  const untilMs = preset === "custom" ? parseUtcInput(custom) : presetDeadlineMs(preset, now);
  const deadlineIssue = holdUntilProblem(untilMs, now);
  const artifactIssue = artifactPattern.test(artifactId) ? null : "请选择或输入规范的证据 ID";
  const reasonIssue = textProblem(reason, "保留理由");
  const window = holdWindow(now);
  const options = members.map((member) => ({
    value: member.artifact_id,
    label: member.artifact_id,
  }));
  const submit = () => {
    // The deadline is fixed at the click, from the server clock estimate; the frozen request
    // keeps exactly this value for every retry.
    const at = serverNow();
    const ms = preset === "custom" ? parseUtcInput(custom) : presetDeadlineMs(preset, at);
    if (ms === null || holdUntilProblem(ms, at) !== null) return;
    void write.submit({ artifactId, reason, holdUntil: holdUntilOf(ms) });
  };
  return (
    <WriteDialog
      title="创建保留锁"
      open
      onClose={onClose}
      write={write}
      submitText="创建保留锁"
      blocked={artifactIssue ?? reasonIssue ?? deadlineIssue}
      onSubmit={submit}
      onRetry={() => void write.retry()}
    >
      <Field
        id="hold-artifact"
        label="证据"
        help="案件成员的证据 ID。要求案件开放；证据内容已到期时仍可保留。"
        error={artifactId.length > 0 ? artifactIssue : null}
      >
        <AutoComplete
          id="hold-artifact"
          className="mono"
          value={artifactId}
          options={options}
          placeholder="artifact_…"
          aria-describedby="hold-artifact-help"
          onChange={(value: string) => setArtifactId(value.trim())}
          style={{ width: "100%" }}
        />
      </Field>
      <Field
        id="hold-reason"
        label="保留理由"
        help={reasonHelp(reason)}
        error={reason.length > 0 ? reasonIssue : null}
      >
        <Input.TextArea
          id="hold-reason"
          value={reason}
          rows={3}
          autoComplete="off"
          spellCheck={false}
          aria-describedby="hold-reason-help"
          onChange={(event) => setReason(event.target.value)}
        />
      </Field>
      <Field
        id="hold-until"
        label="保留至（UTC）"
        help={
          untilMs !== null && deadlineIssue === null
            ? `将保留至 ${holdUntilOf(untilMs)}。上限为服务端当前时间之后 ${HOLD_MAX_HOURS} 小时。`
            : `须晚于服务端当前时间，且至多 ${HOLD_MAX_HOURS} 小时（最迟 ${holdUntilOf(window.maxMs)}）。`
        }
        error={preset === "custom" ? deadlineIssue : null}
      >
        <Segmented<HoldPreset | "custom">
          aria-label="保留期限"
          value={preset}
          onChange={setPreset}
          options={[
            ...HOLD_PRESETS.map((option) => ({ label: option.label, value: option.key })),
            { label: "自定义", value: "custom" as const },
          ]}
        />
        {preset === "custom" && (
          <Input
            id="hold-until"
            type="datetime-local"
            step={1}
            value={custom}
            min={formatUtcInput(window.minMs)}
            max={formatUtcInput(window.maxMs)}
            aria-label="自定义保留截止时间（UTC）"
            aria-describedby="hold-until-help"
            onChange={(event) => setCustom(event.target.value)}
          />
        )}
      </Field>
    </WriteDialog>
  );
}

/** 释放保留锁. */
export function ReleaseHoldDialog({ holdId, onClose }: { holdId: string; onClose: () => void }) {
  const { message } = AntdApp.useApp();
  const [reason, setReason] = useState("");
  const write = useWrite<{ reason: string }, HoldMutation>(
    {
      label: "释放保留锁",
      path: () => `/control/v1/evidence-holds/${holdId}/release`,
      body: (vars) => ({ reason: vars.reason }),
      run: (client, vars, context) =>
        client.releaseEvidenceHold(holdId, vars.reason, context.idempotencyKey, context.signal),
      owner: owners.releaseHold(holdId),
      invalidate: [domains.holds],
    },
    (released) => {
      message.success(released.replayed ? "保留锁已释放（返回原操作结果）" : "保留锁已释放");
      onClose();
    },
  );
  const issue = textProblem(reason, "释放理由");
  return (
    <WriteDialog
      title="释放保留锁"
      open
      onClose={onClose}
      write={write}
      submitText="释放保留锁"
      danger
      blocked={issue}
      onSubmit={() => void write.submit({ reason })}
      onRetry={() => void write.retry()}
    >
      <p>
        保留锁 <span className="mono">{holdId}</span>{" "}
        释放后，证据恢复按其原始期限被清理。释放可在案件关闭、内容到期后执行。
      </p>
      <Field
        id="hold-release-reason"
        label="释放理由"
        help={reasonHelp(reason)}
        error={reason.length > 0 ? issue : null}
      >
        <Input.TextArea
          id="hold-release-reason"
          value={reason}
          rows={3}
          autoComplete="off"
          spellCheck={false}
          aria-describedby="hold-release-reason-help"
          onChange={(event) => setReason(event.target.value)}
        />
      </Field>
    </WriteDialog>
  );
}
