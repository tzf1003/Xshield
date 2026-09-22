/** Sensitive access workflow. Frozen mutation attempts live only in this session. */
import { useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import { ApiError } from "./api";
import type { ControlClient, Envelope } from "./api";
import { artifactPattern } from "./api-contract";
import { casePattern, validCaseText, validIdempotencyKey } from "./cases";
import { accessPattern } from "./evidence-access";
import type {
  AccessDecision,
  AccessInspection,
  AccessRequested,
} from "./evidence-access";
import { AccessDetails } from "./AccessDetails";
import { AccessInbox } from "./AccessInbox";
import { Rows } from "./panels";

type Action = "request" | "approve" | "deny";
type FrozenRequest = {
  action: Action;
  key: string;
  caseId: string;
  artifactId: string;
  accessId: string;
  reason: string;
  ttl: number | null;
  recovery: boolean;
};
type MutationResult = AccessRequested | AccessDecision;
type Attempt = {
  request: FrozenRequest;
  phase: "pending" | "unknown" | "rejected" | "confirmed";
  result?: MutationResult;
  error?: unknown;
};
type Run = <T extends Envelope>(
  fetcher: (api: ControlClient, signal: AbortSignal) => Promise<T>,
  apply: (response: T) => void,
  fail: (error: unknown) => void,
) => Promise<boolean>;
const newKey = () => globalThis.crypto?.randomUUID?.() ?? "";
const labels = {
  request: "提交访问申请",
  approve: "批准访问",
  deny: "拒绝访问",
};

function AccessFailure({ error }: { error: unknown }) {
  return error ? (
    <div className="notice danger" role="alert">
      <div>
        {error instanceof ApiError
          ? error.message
          : "请求未完成，请核对结果后重试。"}
        <small className="mono">
          {error instanceof ApiError ? error.code : "CONSOLE_REQUEST_FAILED"}
          {error instanceof ApiError && error.requestId
            ? ` · ${error.requestId}`
            : ""}
        </small>
      </div>
    </div>
  ) : null;
}

export function EvidenceAccessPanel({
  active,
  busy,
  onInvalidate,
  onHistory,
  onRun,
}: {
  active: boolean;
  busy: boolean;
  onInvalidate: () => void;
  onHistory: (accessRequestId: string) => void;
  onRun: Run;
}) {
  const [action, setAction] = useState<Action>("request");
  const [caseId, setCaseId] = useState("");
  const [artifactId, setArtifactId] = useState("");
  const [accessId, setAccessId] = useState("");
  const [reason, setReason] = useState("");
  const [ttl, setTtl] = useState("");
  const [recover, setRecover] = useState(false);
  const [key, setKey] = useState<string>(newKey);
  const [inspection, setInspection] = useState<AccessInspection | null>(null);
  const [attempt, setAttempt] = useState<Attempt | null>(null);
  const [readError, setReadError] = useState<unknown>(null);
  const [downloadError, setDownloadError] = useState<unknown>(null);
  const [downloadNotice, setDownloadNotice] = useState<string | null>(null);
  const inFlight = useRef(false);
  const mounted = useRef(true);
  const downloadUrl = useRef<string | null>(null);
  const downloadTimer = useRef<ReturnType<typeof setTimeout> | undefined>(
    undefined,
  );
  function revokeDownload() {
    clearTimeout(downloadTimer.current);
    if (downloadUrl.current) URL.revokeObjectURL(downloadUrl.current);
    downloadUrl.current = null;
  }
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      revokeDownload();
    };
  }, []);
  useEffect(() => {
    if (!active) {
      setAttempt((value) =>
        value?.phase === "pending" ? { ...value, phase: "unknown" } : value,
      );
      setInspection(null);
      setReadError(null);
      setDownloadError(null);
      setDownloadNotice(null);
      revokeDownload();
    }
  }, [active]);
  const unresolved =
    attempt?.phase === "pending" || attempt?.phase === "unknown";
  useEffect(() => {
    if (!unresolved) return;
    const warn = (event: BeforeUnloadEvent) => event.preventDefault();
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [unresolved]);

  function invalidateInspection() {
    onInvalidate();
    setInspection(null);
    setReadError(null);
    setDownloadError(null);
    setDownloadNotice(null);
    revokeDownload();
  }
  function browse(target = accessId) {
    if (inFlight.current || busy || !accessPattern.test(target)) return;
    invalidateInspection();
    setAccessId(target);
    void onRun<AccessInspection>(
      (api, signal) => api.evidenceAccess(target, signal),
      setInspection,
      setReadError,
    );
  }
  async function mutate(request: FrozenRequest) {
    if (inFlight.current) return;
    inFlight.current = true;
    const wasUnknown = request.recovery || attempt?.phase === "unknown";
    setAttempt({ request, phase: "pending" });
    invalidateInspection();
    let handled = false;
    await onRun<MutationResult>(
      (api, signal) =>
        request.action === "request"
          ? api.requestEvidenceAccess(
              request.artifactId,
              request.caseId,
              request.reason,
              request.key,
              signal,
            )
          : api.decideEvidenceAccess(
              request.accessId,
              request.action,
              request.reason,
              request.ttl,
              request.key,
              signal,
            ),
      (result) => {
        if (
          result.case_id !== request.caseId ||
          result.artifact_id !== request.artifactId
        ) {
          throw new ApiError("INVALID_RESPONSE");
        }
        handled = true;
        setAttempt({ request, phase: "confirmed", result });
        setAccessId(result.access_request_id);
      },
      (error) => {
        handled = true;
        // A subsequent denial cannot resolve an earlier uncertain commit.
        const rejected =
          !wasUnknown &&
          error instanceof ApiError &&
          error.code.startsWith("CONTROL_") &&
          [400, 403, 404, 409, 422, 429].includes(error.status);
        setAttempt({
          request,
          phase: rejected ? "rejected" : "unknown",
          error,
        });
      },
    );
    inFlight.current = false;
    if (mounted.current && !handled) setAttempt({ request, phase: "unknown" });
  }

  const item = inspection?.access_request;
  const reviewed = Boolean(item && item.access_request_id === accessId);
  const liveArtifact =
    item?.case_status === "open" &&
    item.artifact_status === "active" &&
    !item.artifact_time_expired;
  const validTtl =
    /^\d+$/.test(ttl) &&
    Number.isSafeInteger(Number(ttl)) &&
    Number(ttl) > 0 &&
    Boolean(inspection && Number(ttl) <= inspection.max_approval_ttl_seconds);
  const targetValid =
    action === "request"
      ? casePattern.test(caseId) && artifactPattern.test(artifactId)
      : reviewed &&
        (recover ||
          (item?.stored_status === "pending" &&
            (action === "deny" || liveArtifact))) &&
        (action === "deny" || validTtl);
  function submit(event: FormEvent) {
    event.preventDefault();
    if (
      attempt ||
      busy ||
      !targetValid ||
      !validCaseText(reason) ||
      !validIdempotencyKey(key)
    )
      return;
    if (action !== "request" && !item) return;
    void mutate({
      action,
      key,
      caseId: action === "request" ? caseId : (item?.case_id ?? ""),
      artifactId: action === "request" ? artifactId : (item?.artifact_id ?? ""),
      accessId,
      reason,
      ttl: action === "approve" ? Number(ttl) : null,
      recovery: recover,
    });
  }
  const canDownload =
    reviewed &&
    liveArtifact &&
    item?.stored_status === "approved" &&
    item.capability_time_expired === false;
  function download() {
    if (!canDownload || !item || busy || inFlight.current) return;
    inFlight.current = true;
    const target = item;
    onInvalidate();
    revokeDownload();
    setDownloadError(null);
    setDownloadNotice(null);
    void onRun(
      (api, signal) =>
        api.downloadEvidence(
          target.artifact_id,
          target.access_request_id,
          signal,
        ),
      (response) => {
        // App calls apply only after epoch, abort and authenticated-scope checks.
        // Keep one bounded object URL; plaintext never enters React state or DOM.
        const url = URL.createObjectURL(response.blob);
        downloadUrl.current = url;
        const link = document.createElement("a");
        link.href = url;
        link.download = `${response.artifact_id}.bin`;
        link.hidden = true;
        document.body.appendChild(link);
        try {
          link.click();
          setDownloadNotice(
            `已发起附件保存：${response.artifact_id}.bin（${response.bytes} 字节）。管理请求 ID：${response.request_id}。`,
          );
        } finally {
          link.remove();
          downloadTimer.current = setTimeout(revokeDownload, 1000);
        }
      },
      setDownloadError,
    ).finally(() => {
      inFlight.current = false;
    });
  }
  const frozen = attempt?.request;
  const payload =
    frozen &&
    (frozen.action === "request"
      ? {
          case_id: frozen.caseId,
          access_kind: "sensitive_raw",
          justification: frozen.reason,
        }
      : frozen.action === "approve"
        ? { reason: frozen.reason, ttl_seconds: frozen.ttl }
        : { reason: frozen.reason });

  return (
    <div className="case-workbench access-workbench">
      <div className="notice">
        <div>
          Investigator 可申请本人案件的原文访问；SensitiveEvidenceApprover
          复核并独立批准或拒绝，禁止自批。SensitiveEvidenceReader
          仅可读取本人获批且仍有效的原文。角色与作用域由服务端校验。
          <p>
            申请详情对申请人（Investigator 或
            SensitiveEvidenceReader）及同域审批人开放。原文仅在点击下载后保存为
            .bin 附件。
          </p>
          <p>
            写入结果未知时保留原键与参数。刷新、断连、401、页面离开或闲置 15
            分钟会清空内存；请先手动保存需要恢复的请求。
          </p>
        </div>
      </div>
      <AccessInbox active={active} busy={busy} onInvalidate={invalidateInspection}
        onRun={onRun} onOpen={browse} />
      <div className="case-grid">
        <section className="panel" aria-label="证据访问操作">
          <div className="panel-heading">
            <h2>证据访问操作</h2>
            <span className="muted">申请 · 独立审批</span>
          </div>
          <form className="case-form" onSubmit={submit}>
            <label htmlFor="access-action">访问操作</label>
            <select
              id="access-action"
              value={action}
              disabled={Boolean(attempt)}
              onChange={(event) => {
                setAction(event.target.value as Action);
                setReason("");
                setTtl("");
                setRecover(false);
              }}
            >
              <option value="request">申请原文访问</option>
              <option value="approve">批准申请</option>
              <option value="deny">拒绝申请</option>
            </select>
            {action === "request" ? (
              <>
                <label htmlFor="access-case">申请案件 ID</label>
                <input
                  id="access-case"
                  className="mono"
                  value={caseId}
                  disabled={Boolean(attempt)}
                  onChange={(event) => setCaseId(event.target.value)}
                  maxLength={41}
                  autoComplete="off"
                  spellCheck={false}
                  required
                />
                <label htmlFor="access-artifact">申请证据 ID</label>
                <input
                  id="access-artifact"
                  className="mono"
                  value={artifactId}
                  disabled={Boolean(attempt)}
                  onChange={(event) => setArtifactId(event.target.value)}
                  maxLength={45}
                  autoComplete="off"
                  spellCheck={false}
                  required
                />
                <p className="muted">
                  填写本人开放案件及同作用域内的有效证据。
                </p>
              </>
            ) : (
              <p className="muted">
                目标申请：
                <span className="mono">
                  {frozen?.accessId ||
                    (reviewed ? accessId : "请先读取申请详情")}
                </span>
                。首次审批需复核详情；拒绝可终结已关闭案件或已到期证据的待决申请。
              </p>
            )}
            <label className="access-recovery" htmlFor="access-recover">
              <input
                id="access-recover"
                type="checkbox"
                checked={recover}
                disabled={Boolean(attempt)}
                onChange={(event) => setRecover(event.target.checked)}
              />
              {action === "request" ? "恢复原访问申请" : "恢复原审批请求"}
            </label>
            {recover && (
              <p className="notice warning">
                {action === "request"
                  ? "请填写保存的原案件、原证据、原理由及原幂等键。服务端校验精确重试；在确认成功前保留未知结果。"
                  : "请填写保存的原幂等键、原理由和原批准期限。历史状态仍可确认原操作；服务端校验精确重试，参数不同会拒绝。请先读取目标详情。"}
              </p>
            )}
            <label htmlFor="access-reason">
              {action === "request" ? "申请理由" : "审批理由"}
            </label>
            <textarea
              id="access-reason"
              value={reason}
              disabled={Boolean(attempt)}
              onChange={(event) => setReason(event.target.value)}
              maxLength={512}
              autoComplete="off"
              spellCheck={false}
              required
            />
            <p className="muted">1–512 UTF-8 字节，无首尾空白及控制字符。</p>
            {action === "approve" && (
              <>
                <label htmlFor="access-ttl">批准期限（秒）</label>
                <input
                  id="access-ttl"
                  type="number"
                  value={ttl}
                  disabled={Boolean(attempt)}
                  onChange={(event) => setTtl(event.target.value)}
                  min={1}
                  max={inspection?.max_approval_ttl_seconds}
                  step={1}
                  required
                />
                <p className="muted">
                  请显式填写期限；当前服务端上限为{" "}
                  {inspection?.max_approval_ttl_seconds ?? "读取详情后显示"}{" "}
                  秒，实际访问期限还受证据到期时间限制。
                </p>
              </>
            )}
            <label htmlFor="access-key">访问幂等键</label>
            <input
              id="access-key"
              className="mono"
              value={key}
              readOnly={Boolean(attempt)}
              onChange={(event) => setKey(event.target.value)}
              minLength={16}
              maxLength={128}
              autoComplete="off"
              spellCheck={false}
              required
            />
            <p className="muted">
              16–128 个 ASCII 字母、数字或
              -_.:；恢复请求时填写原键及全部原参数。
            </p>
            {!attempt && (
              <button
                type="submit"
                disabled={
                  busy ||
                  !targetValid ||
                  !validCaseText(reason) ||
                  !validIdempotencyKey(key)
                }
              >
                {labels[action]}
              </button>
            )}
          </form>
          {attempt && (
            <div className="case-result" aria-live="polite">
              <h3>
                {attempt.phase === "pending"
                  ? "提交中，等待结果"
                  : attempt.phase === "unknown"
                    ? "访问操作结果未知"
                    : attempt.phase === "rejected"
                      ? "本次访问操作被拒绝"
                      : `${labels[attempt.request.action]}已确认`}
              </h3>
              <AccessFailure error={attempt.error} />
              {unresolved && (
                <div className="notice warning">
                  服务端可能已经提交。请保存原键与参数，使用“原样重试访问操作”确认结果。
                </div>
              )}
              <Rows
                entries={[
                  [
                    "方法与路径",
                    <span className="mono">
                      POST{" "}
                      {frozen?.action === "request"
                        ? `/control/v1/artifacts/${frozen.artifactId}/access`
                        : `/control/v1/evidence-access-requests/${frozen?.accessId}/${frozen?.action}`}
                    </span>,
                  ],
                  ["原幂等键", <span className="mono">{frozen?.key}</span>],
                  ["冻结案件", frozen?.caseId],
                  ["冻结证据", frozen?.artifactId],
                ]}
              />
              <pre className="mono case-payload" aria-label="冻结访问请求参数">
                {JSON.stringify(payload, null, 2)}
              </pre>
              {attempt.result && (
                <Rows
                  entries={[
                    ["返回申请 ID", attempt.result.access_request_id],
                    ["返回状态", attempt.result.status],
                    ["管理请求 ID", attempt.result.request_id],
                    [
                      "replayed",
                      attempt.result.replayed
                        ? "true（返回原操作结果）"
                        : "false（首次提交）",
                    ],
                  ]}
                />
              )}
              <div className="case-actions">
                <button
                  className="outline"
                  disabled={busy || attempt.phase === "pending"}
                  onClick={() => void mutate(attempt.request)}
                >
                  原样重试访问操作
                </button>
                <button
                  className="text-button"
                  disabled={busy || unresolved}
                  onClick={() => {
                    setAttempt(null);
                    setReason("");
                    setTtl("");
                    setRecover(false);
                    setKey(newKey());
                  }}
                >
                  准备新的访问操作
                </button>
              </div>
            </div>
          )}
        </section>
        <section className="panel" aria-label="访问申请详情" aria-busy={busy}>
          <div className="panel-heading">
            <h2>访问申请详情</h2>
            <span className="muted">固定作用域 · 历史观察</span>
          </div>
          <form
            className="case-form"
            onSubmit={(event) => {
              event.preventDefault();
              browse();
            }}
          >
            <label htmlFor="access-id">访问申请 ID</label>
            <input
              id="access-id"
              className="mono"
              value={accessId}
              disabled={attempt?.phase === "pending"}
              onChange={(event) => {
                invalidateInspection();
                setAccessId(event.target.value);
              }}
              maxLength={43}
              autoComplete="off"
              spellCheck={false}
              required
            />
            <button
              type="submit"
              disabled={
                busy ||
                attempt?.phase === "pending" ||
                !accessPattern.test(accessId)
              }
            >
              读取申请 / 刷新
            </button>
          </form>
          <AccessFailure error={readError} />
          {inspection ? (
            <AccessDetails response={inspection} onHistory={onHistory} />
          ) : (
            <p className="empty">
              读取申请详情，复核申请人、理由、目标及历史决策。
            </p>
          )}
          <div className="case-form">
            <button
              disabled={busy || !canDownload || attempt?.phase === "pending"}
              onClick={download}
            >
              下载原文（.bin）
            </button>
            <p className="muted">
              需先读取当前申请详情，并由申请人的 SensitiveEvidenceReader
              凭证发起。保存后的附件由你负责保管。
            </p>
            <AccessFailure error={downloadError} />
            {downloadNotice && <p role="status">{downloadNotice}</p>}
          </div>
        </section>
      </div>
    </div>
  );
}
