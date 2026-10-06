import { CheckCircleFilled, CloseCircleFilled, WarningOutlined } from "@ant-design/icons";
import { Button, Input, Radio } from "antd";
import { useId, useRef, useState } from "react";
import {
  digestPageFile,
  digestPastedPage,
  type PageDigest,
  pageDigestAssumptions,
} from "../../../sites/model/page-digest.ts";
import { formatBytes } from "../../../sites/model/units.ts";
import { busy } from "../fields";

type Outcome =
  | { kind: "idle" }
  | { kind: "busy" }
  | { kind: "done"; digest: PageDigest }
  | { kind: "failed"; message: string };

/**
 * “从页面源码计算”: the operator pastes the page or chooses the saved file the origin serves, and
 * the console computes the build's SHA-256 and `</head>` byte offset in the browser
 * (sites/model/page-digest.ts) and fills both fields. The page is held only until the
 * computation finishes: the pasted text and the chosen file are dropped afterwards, nothing is
 * sent or stored, and the panel says exactly what it assumed.
 */
export function PageDigestPanel({
  id,
  maxResponseBytes,
  disabled,
  onDigest,
}: {
  /** Prefix for element ids (one panel per page build). */
  id: string;
  /** The route's response limit: a page above it is refused by the edge whatever its digest. */
  maxResponseBytes: number;
  disabled?: boolean;
  onDigest: (digest: PageDigest) => void;
}) {
  const [source, setSource] = useState<"file" | "paste">("file");
  const [text, setText] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [outcome, setOutcome] = useState<Outcome>({ kind: "idle" });
  const fileInput = useRef<HTMLInputElement>(null);
  const assumptionsId = useId();
  const ready = source === "file" ? file !== null : text !== "";

  async function compute() {
    setOutcome({ kind: "busy" });
    const result =
      source === "file" && file ? await digestPageFile(file) : await digestPastedPage(text);
    // The page is not kept beyond this computation, whatever its outcome.
    setText("");
    setFile(null);
    if (fileInput.current) fileInput.current.value = "";
    if (!result.ok) {
      setOutcome({ kind: "failed", message: result.message });
      return;
    }
    onDigest(result.digest);
    setOutcome({ kind: "done", digest: result.digest });
  }

  return (
    <fieldset className="xs-digest-panel">
      <legend className="xs-visually-hidden">从页面源码计算摘要与注入偏移</legend>
      <Radio.Group
        aria-label="页面来源"
        value={source}
        disabled={disabled}
        onChange={(event) => setSource(event.target.value)}
      >
        <Radio.Button value="file">选择文件</Radio.Button>
        <Radio.Button value="paste">粘贴源码</Radio.Button>
      </Radio.Group>
      {source === "file" ? (
        <div className="xs-digest-input">
          <label htmlFor={`${id}-file`}>页面文件</label>
          <input
            ref={fileInput}
            id={`${id}-file`}
            type="file"
            accept=".html,.htm,text/html"
            disabled={disabled}
            aria-describedby={assumptionsId}
            onChange={(event) => setFile(event.target.files?.[0] ?? null)}
          />
        </div>
      ) : (
        <div className="xs-digest-input">
          <label htmlFor={`${id}-text`}>页面源码</label>
          <Input.TextArea
            id={`${id}-text`}
            value={text}
            disabled={disabled}
            spellCheck={false}
            autoSize={{ minRows: 4, maxRows: 10 }}
            aria-describedby={assumptionsId}
            onChange={(event) => setText(event.target.value)}
          />
        </div>
      )}
      <ul id={assumptionsId} className="xs-digest-assumptions">
        {pageDigestAssumptions.map((line) => (
          <li key={line}>{line}</li>
        ))}
      </ul>
      <Button
        disabled={disabled || !ready || outcome.kind === "busy"}
        loading={busy(outcome.kind === "busy")}
        onClick={() => void compute()}
      >
        计算并填入摘要与偏移
      </Button>
      <div role="status" className="xs-digest-result">
        {outcome.kind === "failed" && (
          <p className="xs-field-issue xs-field-issue--error">
            <CloseCircleFilled aria-hidden="true" /> {outcome.message}
          </p>
        )}
        {outcome.kind === "done" && (
          <>
            <p>
              <CheckCircleFilled aria-hidden="true" className="xs-digest-ok" /> 已填入：摘要{" "}
              <span className="mono xs-wrap">{outcome.digest.sha256}</span>，注入偏移{" "}
              <span className="mono">{outcome.digest.injectionOffset}</span>（第一个 &lt;/head&gt;
              之前有 {outcome.digest.injectionOffset.toLocaleString("en-US")} 字节，页面共{" "}
              {outcome.digest.byteLength.toLocaleString("en-US")} 字节）。页面内容没有保留。
            </p>
            {outcome.digest.byteLength > maxResponseBytes && (
              <p className="xs-field-issue xs-field-issue--warning">
                <WarningOutlined aria-hidden="true" /> 页面共{" "}
                {outcome.digest.byteLength.toLocaleString("en-US")} 字节，超过这条路由的响应上限（
                {formatBytes(maxResponseBytes)}）：edge 会拒绝这份页面。请把“响应上限”调到不小于{" "}
                {outcome.digest.byteLength.toLocaleString("en-US")} 字节。
              </p>
            )}
          </>
        )}
      </div>
    </fieldset>
  );
}
