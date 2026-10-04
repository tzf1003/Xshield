/** Metadata-only export workflow. Package bytes are never rendered in the DOM. */
import { useEffect, useRef, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import { ApiError } from "./api";
import type { ControlClient, Envelope } from "./api";
import { exportPattern } from "./exports";
import type { ExportDownload, InvestigationExport } from "./exports";
import { casePattern, validCaseText, validIdempotencyKey } from "./cases";
import { Rows } from "./panels";

type Action = "request" | "approve" | "deny";
type FrozenRequest = {
  action: Action;
  caseId: string;
  exportId: string;
  reason: string;
  key: string;
};
type Attempt = {
  request: FrozenRequest;
  phase: "pending" | "unknown" | "rejected" | "confirmed";
  result?: InvestigationExport;
  error?: unknown;
};
type Run = <T extends Envelope>(
  fetcher: (api: ControlClient, signal: AbortSignal) => Promise<T>,
  apply: (response: T) => void,
  fail: (error: unknown) => void,
) => Promise<boolean>;
const newKey = () => globalThis.crypto?.randomUUID?.() ?? "";
const labels = { request: "申请元数据导出", approve: "批准导出", deny: "拒绝导出" };

function ExportFailure({ error }: { error: unknown }) {
  return error ? (
    <div className="notice danger" role="alert">
      <div>
        {error instanceof ApiError ? error.message : "请求未完成，请核对结果后重试。"}
        <small className="mono">
          {error instanceof ApiError ? error.code : "CONSOLE_REQUEST_FAILED"}
          {error instanceof ApiError && error.requestId ? ` · ${error.requestId}` : ""}
        </small>
      </div>
    </div>
  ) : null;
}

function exportRows(result: InvestigationExport): [string, ReactNode][] {
  return [
    ["导出 ID", <span className="mono">{result.export_id}</span>],
    ["案件 ID", <span className="mono">{result.case_id}</span>],
    ["状态", <span className="badge">{result.status}</span>],
    ["调查用途", result.purpose],
    ["申请主体", result.requested_by],
    ["决策主体", result.decided_by ?? "尚未决策"],
    ["决策时间", result.decided_at ?? "尚未决策"],
    ["过期时间", result.expires_at ?? "不适用"],
    [
      "包 artifact",
      result.package_artifact_id ? (
        <span className="mono">{result.package_artifact_id}</span>
      ) : (
        "尚未生成"
      ),
    ],
    ["包大小", result.package_bytes === null ? "尚未生成" : `${result.package_bytes} bytes`],
    ["下载次数", `${result.download_count} / 2`],
    ["管理请求 ID", <span className="mono">{result.request_id}</span>],
  ];
}

export function ExportPanel({
  active,
  busy,
  onInvalidate,
  onRun,
}: {
  active: boolean;
  busy: boolean;
  onInvalidate: () => void;
  onRun: Run;
}) {
  const [action, setAction] = useState<Action>("request");
  const [caseId, setCaseId] = useState("");
  const [exportId, setExportId] = useState("");
  const [reason, setReason] = useState("");
  const [key, setKey] = useState<string>(newKey);
  const [inspection, setInspection] = useState<InvestigationExport | null>(null);
  const [readError, setReadError] = useState<unknown>(null);
  const [attempt, setAttempt] = useState<Attempt | null>(null);
  const [downloadError, setDownloadError] = useState<unknown>(null);
  const [downloadNotice, setDownloadNotice] = useState<string | null>(null);
  const inFlight = useRef(false);
  const mounted = useRef(true);
  const downloadUrl = useRef<string | null>(null);
  const downloadTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

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
      setInspection(null);
      setReadError(null);
      setDownloadError(null);
      setDownloadNotice(null);
      revokeDownload();
      setAttempt((value) => (value?.phase === "pending" ? { ...value, phase: "unknown" } : value));
    }
  }, [active]);
  const unresolved = attempt?.phase === "pending" || attempt?.phase === "unknown";
  useEffect(() => {
    if (!unresolved) return;
    const warn = (event: BeforeUnloadEvent) => event.preventDefault();
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [unresolved]);

  function clearInspection() {
    onInvalidate();
    setInspection(null);
    setReadError(null);
    setDownloadError(null);
    setDownloadNotice(null);
    revokeDownload();
  }
  function readStatus(target = exportId) {
    if (inFlight.current || busy || !exportPattern.test(target)) return;
    clearInspection();
    setExportId(target);
    void onRun<InvestigationExport>(
      (api, signal) => api.exportStatus(target, signal),
      setInspection,
      setReadError,
    );
  }
  async function mutate(request: FrozenRequest) {
    if (inFlight.current) return;
    inFlight.current = true;
    const wasUnknown = attempt?.phase === "unknown";
    setAttempt({ request, phase: "pending" });
    clearInspection();
    let handled = false;
    await onRun<InvestigationExport>(
      (api, signal) =>
        request.action === "request"
          ? api.requestExport(request.caseId, request.reason, request.key, signal)
          : api.decideExport(request.exportId, request.action, request.reason, request.key, signal),
      (result) => {
        handled = true;
        setAttempt({ request, phase: "confirmed", result });
        setExportId(result.export_id);
        setInspection(result);
      },
      (error) => {
        handled = true;
        const rejected =
          !wasUnknown &&
          error instanceof ApiError &&
          error.code.startsWith("CONTROL_") &&
          [400, 403, 404, 409, 422, 429].includes(error.status);
        setAttempt({ request, phase: rejected ? "rejected" : "unknown", error });
      },
    );
    inFlight.current = false;
    if (mounted.current && !handled) setAttempt({ request, phase: "unknown" });
  }
  function submit(event: FormEvent) {
    event.preventDefault();
    if (attempt || !validIdempotencyKey(key) || !validCaseText(reason)) return;
    if (action === "request" && !casePattern.test(caseId)) return;
    if (action !== "request" && !exportPattern.test(exportId)) return;
    void mutate({
      action,
      caseId: action === "request" ? caseId : "",
      exportId: action === "request" ? "" : exportId,
      reason,
      key,
    });
  }
  function download() {
    const ready = inspection;
    if (
      inFlight.current ||
      busy ||
      !ready ||
      ready.status !== "ready" ||
      ready.package_artifact_id === null ||
      ready.package_bytes === null
    )
      return;
    const artifactId = ready.package_artifact_id;
    const packageBytes = ready.package_bytes;
    inFlight.current = true;
    setDownloadError(null);
    setDownloadNotice(null);
    revokeDownload();
    let handled = false;
    void onRun<ExportDownload>(
      (api, signal) => api.downloadExport(ready.export_id, artifactId, packageBytes, signal),
      (result) => {
        handled = true;
        const url = URL.createObjectURL(result.blob);
        downloadUrl.current = url;
        const link = document.createElement("a");
        link.href = url;
        link.download = "investigation-export.json";
        link.click();
        setDownloadNotice(`已准备 ${result.bytes} bytes 的元数据包；服务端已记录本次下载。`);
        downloadTimer.current = setTimeout(revokeDownload, 1_000);
      },
      (error) => {
        handled = true;
        setDownloadError(error);
      },
    ).finally(() => {
      inFlight.current = false;
      if (mounted.current && !handled) setDownloadError(new Error("unknown"));
    });
  }
  const result = attempt?.result;
  const frozen = attempt?.request;
  const validMutation =
    validIdempotencyKey(key) &&
    validCaseText(reason) &&
    (action === "request" ? casePattern.test(caseId) : exportPattern.test(exportId));

  return (
    <div className="export-workbench">
      <div className="notice">
        <div>
          导出只包含案件和证据目录的元数据，不包含证据正文、凭据或存储定位。申请人不能自批；审批和下载都需要最近两分钟内的
          MFA 再认证。
          <p>写入操作会冻结原始参数与幂等键。结果未知时只使用“原样重试”确认，不能改键或改参数。</p>
        </div>
      </div>
      <div className="case-grid">
        <section className="panel" aria-label="导出操作">
          <div className="panel-heading">
            <h2>导出操作</h2>
            <span className="muted">双人审批 · 15 分钟有效</span>
          </div>
          <form className="case-form" onSubmit={submit}>
            <label htmlFor="export-action">导出操作</label>
            <select
              id="export-action"
              value={action}
              disabled={Boolean(attempt)}
              onChange={(event) => {
                setAction(event.target.value as Action);
                setReason("");
                setKey(newKey());
              }}
            >
              <option value="request">申请元数据导出</option>
              <option value="approve">批准导出</option>
              <option value="deny">拒绝导出</option>
            </select>
            {action === "request" ? (
              <>
                <label htmlFor="export-case-id">导出案件 ID</label>
                <input
                  id="export-case-id"
                  className="mono"
                  value={caseId}
                  disabled={Boolean(attempt)}
                  onChange={(event) => setCaseId(event.target.value)}
                  placeholder="case_…"
                  autoComplete="off"
                  spellCheck={false}
                  maxLength={41}
                  required
                />
                <label htmlFor="export-purpose">导出调查用途</label>
              </>
            ) : (
              <>
                <label htmlFor="export-id">导出 ID</label>
                <input
                  id="export-id"
                  className="mono"
                  value={exportId}
                  disabled={Boolean(attempt)}
                  onChange={(event) => setExportId(event.target.value)}
                  placeholder="export_…"
                  autoComplete="off"
                  spellCheck={false}
                  maxLength={44}
                  required
                />
                <label htmlFor="export-reason">导出决策理由</label>
              </>
            )}
            <textarea
              id={action === "request" ? "export-purpose" : "export-reason"}
              value={reason}
              disabled={Boolean(attempt)}
              onChange={(event) => setReason(event.target.value)}
              maxLength={512}
              required
            />
            <p className="muted">1–512 UTF-8 字节，无首尾空白及控制字符。</p>
            <label htmlFor="export-key">导出幂等键</label>
            <input
              id="export-key"
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
            {!attempt && (
              <button type="submit" disabled={busy || !validMutation}>
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
                    ? "操作结果未知"
                    : attempt.phase === "rejected"
                      ? "本次请求被拒绝"
                      : `${labels[attempt.request.action]}已确认`}
              </h3>
              <ExportFailure error={attempt.error} />
              {unresolved && (
                <div className="notice warning">
                  服务端可能已经提交。保留原幂等键与参数，使用下方“原样重试”确认结果。
                </div>
              )}
              <Rows
                entries={[
                  ["原幂等键", <span className="mono">{frozen?.key}</span>],
                  [
                    "冻结参数",
                    <pre className="mono case-payload">
                      {JSON.stringify(
                        frozen?.action === "request"
                          ? { case_id: frozen.caseId, purpose: frozen.reason }
                          : { reason: frozen?.reason },
                        null,
                        2,
                      )}
                    </pre>,
                  ],
                ]}
              />
              {result && <Rows entries={exportRows(result)} />}
              <div className="case-actions">
                <button
                  className="outline"
                  disabled={busy || attempt.phase === "pending"}
                  onClick={() => void mutate(attempt.request)}
                >
                  原样重试
                </button>
                <button
                  className="text-button"
                  disabled={busy || unresolved}
                  onClick={() => {
                    setAttempt(null);
                    setReason("");
                    setKey(newKey());
                  }}
                >
                  准备新操作
                </button>
              </div>
            </div>
          )}
        </section>
        <section className="panel" aria-label="导出状态" aria-busy={busy}>
          <div className="panel-heading">
            <h2>导出状态</h2>
            <span className="muted">不读取包正文</span>
          </div>
          <form
            className="case-form"
            onSubmit={(event) => {
              event.preventDefault();
              readStatus();
            }}
          >
            <label htmlFor="export-status-id">导出状态 ID</label>
            <input
              id="export-status-id"
              className="mono"
              value={exportId}
              onChange={(event) => {
                clearInspection();
                setExportId(event.target.value);
              }}
              placeholder="export_…"
              autoComplete="off"
              spellCheck={false}
              maxLength={44}
              required
            />
            <button type="submit" disabled={busy || !exportPattern.test(exportId)}>
              读取状态
            </button>
          </form>
          <ExportFailure error={readError} />
          {inspection && (
            <div className="case-result">
              <Rows entries={exportRows(inspection)} />
              {inspection.status === "ready" ? (
                <>
                  <button type="button" onClick={download} disabled={busy}>
                    下载元数据包
                  </button>
                  <ExportFailure error={downloadError} />
                  {downloadNotice && (
                    <p className="notice" role="status">
                      {downloadNotice}
                    </p>
                  )}
                </>
              ) : (
                <p className="footnote">
                  只有 ready 状态允许按需下载；状态读取本身不产生内容能力。
                </p>
              )}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
