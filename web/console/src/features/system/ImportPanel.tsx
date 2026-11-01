// The "导入" tab (docs/06 6.4.11, docs/07 7.9.9): a JSON-lines file from the gateway's file mode (for
// example decisions.jsonl) is checked against the 100 MiB limit before anything is read, sent once, and
// answered with the counts of imported, skipped and refused lines and the first refused line numbers.

import { type ChangeEvent, useId, useState } from "react";
import { useImport } from "../../api/queries.ts";
import type { ImportResult } from "../../api/types.ts";
import { fmtBytes, fmtInt } from "../../lib/format.ts";
import { ErrorBar, Notice } from "../../ui/Page.tsx";

const MAX_BYTES = 100 * 1024 * 1024;

function ImportOutcome({ result }: { result: ImportResult }) {
  const listed = result.error_lines.length;
  const summary = `导入 ${fmtInt(result.imported)} 条，跳过 ${fmtInt(result.skipped)} 条（同一请求 ID 与时间已存在），出错 ${fmtInt(result.errors)} 行。`;
  const lines =
    listed > 0
      ? `出错的行：第 ${result.error_lines.join("、")} 行${result.errors > listed ? `（只列出前 ${fmtInt(listed)} 行）` : ""}`
      : null;
  return (
    <Notice tone="info">
      {summary}
      {lines === null ? null : (
        <>
          <br />
          {lines}
        </>
      )}
    </Notice>
  );
}

export function ImportPanel() {
  const inputId = useId();
  const importer = useImport();
  const [file, setFile] = useState<File | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);
  const [reading, setReading] = useState(false);
  const busy = reading || importer.isPending;

  const choose = (event: ChangeEvent<HTMLInputElement>) => {
    const next = event.currentTarget.files?.[0] ?? null;
    importer.reset();
    setFileError(null);
    setFile(null);
    if (next === null) return;
    if (next.size === 0) {
      setFileError("这个文件是空的，没有可以导入的记录。");
      return;
    }
    if (next.size > MAX_BYTES) {
      setFileError(
        `这个文件是 ${fmtBytes(next.size)}，超过 100 MiB 的上限。请拆成较小的文件后再导入。`,
      );
      return;
    }
    setFile(next);
  };

  const submit = async () => {
    if (file === null) return;
    setReading(true);
    try {
      const text = await file.text();
      importer.mutate(text);
    } catch {
      setFileError("无法读取这个文件，请重新选择。");
    } finally {
      setReading(false);
    }
  };

  return (
    <div className="sys-import">
      <p className="muted">
        选择网关文件模式输出的 JSON 行文件（例如 <span className="mono">decisions.jsonl</span>
        ），最大 100 MiB。导入的记录网关实例记为 <span className="mono">import</span>
        ；没有追溯信息的旧格式记录会在详情页标注为“旧格式记录”。
      </p>
      <div className="sys-import-form">
        <label htmlFor={inputId}>选择文件</label>
        <input
          id={inputId}
          className="sys-file"
          type="file"
          accept=".jsonl,.ndjson,application/x-ndjson"
          disabled={busy}
          onChange={choose}
        />
        <button
          type="button"
          className="btn btn-primary"
          disabled={file === null || busy}
          onClick={() => void submit()}
        >
          导入
        </button>
      </div>
      {file === null ? null : (
        <p className="small muted">
          {file.name} · {fmtBytes(file.size)}
        </p>
      )}
      {fileError === null ? null : <Notice tone="bad">{fileError}</Notice>}
      {busy ? (
        <div role="status" className="small muted">
          正在上传并导入，文件较大时需要一些时间…
        </div>
      ) : null}
      {importer.error ? <ErrorBar error={importer.error} onRetry={() => void submit()} /> : null}
      {importer.data ? (
        <div role="status">
          <ImportOutcome result={importer.data} />
        </div>
      ) : null}
    </div>
  );
}
