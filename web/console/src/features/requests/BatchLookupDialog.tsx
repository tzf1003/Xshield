// Batch lookup (docs/06 6.4.3): paste a test-suite table or any text with request ids, and see what
// the gateway recorded for each id next to the verdict the table expected.

import { Modal } from "antd";
import { useEffect, useMemo, useState } from "react";
import type { LookupResponse, Outcome } from "../../api/types.ts";
import { useLookup } from "../../api/queries.ts";
import { tsvLine } from "../../lib/csv.ts";
import { countRequestIds } from "../../lib/ids.ts";
import { ERROR_TEXT, OUTCOME_INFO } from "../../lib/vocab.ts";
import { readText, removeText } from "../../lib/storage.ts";
import { OutcomeTag, DecisionTag } from "../../ui/Badges.tsx";
import { RequestLink } from "../../ui/RequestRef.tsx";
import { BATCH_TEXT_KEY } from "../../app/CommandPalette.tsx";
import { compare, expectedOf, MAX_BATCH_IDS, parsePaste, rowId } from "./batch.ts";

type Props = {
  open: boolean;
  onClose: () => void;
};

const ACTUAL_LABEL: Record<Outcome, string> = {
  blocked: "拦截",
  would_block: "本应拦截",
  allowed: "放行",
  unjudged: "放行（未经判定）",
};

export function BatchLookupDialog({ open, onClose }: Props) {
  const lookup = useLookup();
  const [text, setText] = useState("");
  const [expectedOverride, setExpectedOverride] = useState<number | "none" | null>(null);
  const [result, setResult] = useState<LookupResponse | null>(null);
  const [onlyMismatch, setOnlyMismatch] = useState(false);
  const [onlyMissing, setOnlyMissing] = useState(false);

  useEffect(() => {
    if (!open) return;
    const stored = readText(BATCH_TEXT_KEY, "session");
    if (stored) {
      setText(stored);
      removeText(BATCH_TEXT_KEY, "session");
    }
    setResult(null);
    setExpectedOverride(null);
  }, [open]);

  const paste = useMemo(() => parsePaste(text), [text]);
  // docs/06 6.4.3: the count names the ids found, and the distinct ones when the two differ.
  const idsFound = useMemo(() => countRequestIds(text), [text]);
  const idCount =
    idsFound === paste.ids.length
      ? `识别到 ${idsFound} 个请求 ID`
      : `识别到 ${idsFound} 个请求 ID（去重后 ${paste.ids.length}）`;
  const expectedIndex =
    expectedOverride === "none" ? null : (expectedOverride ?? paste.expectedColumn);
  const tableRows = useMemo(() => {
    const byId = new Map<string, string[]>();
    for (const row of paste.table?.rows ?? []) {
      const id = rowId(row);
      if (id !== null && !byId.has(id)) byId.set(id, row);
    }
    return byId;
  }, [paste]);

  const extraColumns = (paste.table?.headers ?? [])
    .map((header, index) => ({ header, index }))
    .filter(({ index }) => index !== expectedIndex)
    .filter(({ header }) => !/request|请求|^x_xshield/i.test(header))
    .slice(0, 3);

  const rows = useMemo(() => {
    if (!result) return [];
    return result.rows.map((row) => {
      const source = tableRows.get(row.request_id);
      const expectedRaw = expectedIndex !== null && source ? source[expectedIndex] : undefined;
      const expected = expectedOf(expectedRaw);
      const outcome = row.summary?.outcome ?? null;
      return {
        row,
        extras: extraColumns.map(({ header, index }) => ({ header, value: source?.[index] ?? "" })),
        expectedRaw: expectedRaw ?? "",
        expected,
        comparison: compare(expected, row),
        outcome,
      };
    });
  }, [result, tableRows, expectedIndex, extraColumns]);

  const counts = {
    total: rows.length,
    found: rows.filter((item) => item.row.found).length,
    missing: rows.filter((item) => !item.row.found).length,
    mismatch: rows.filter((item) => item.comparison === "mismatch").length,
  };

  const visible = rows.filter((item) => {
    if (onlyMismatch && item.comparison !== "mismatch") return false;
    if (onlyMissing && item.row.found) return false;
    return true;
  });

  const run = () => {
    if (paste.ids.length === 0) return;
    if (paste.ids.length > MAX_BATCH_IDS) return;
    lookup.mutate(paste.ids.slice(0, MAX_BATCH_IDS), { onSuccess: (data) => setResult(data) });
  };

  const copyResult = () => {
    const header = [
      "request_id",
      ...extraColumns.map((c) => c.header),
      "expected",
      "actual",
      "decision",
      "status",
      "match",
    ];
    const lines = rows.map((item) =>
      tsvLine([
        item.row.request_id,
        ...item.extras.map((extra) => extra.value),
        item.expectedRaw,
        item.outcome ? ACTUAL_LABEL[item.outcome] : "查不到",
        item.row.summary?.decision_path ?? "",
        item.row.summary?.status ?? "",
        item.comparison,
      ]),
    );
    void navigator.clipboard?.writeText([tsvLine(header), ...lines].join("\n"));
  };

  const tooMany = paste.ids.length > MAX_BATCH_IDS;

  return (
    <Modal open={open} onCancel={onClose} footer={null} width={1000} title="批量对照">
      <div className="stack">
        <div className="field-label">
          ① 粘贴：测试套件的 TSV、日志或任意文本（最多 {MAX_BATCH_IDS} 个 ID）
        </div>
        <textarea
          className="native-input"
          style={{ height: 150, fontFamily: "var(--mono)", fontSize: 12, padding: 8 }}
          value={text}
          onChange={(event) => {
            setText(event.target.value);
            setResult(null);
          }}
          aria-label="粘贴的内容"
          placeholder={
            "x_xshield_request_id\toutcome\nreq_01a19741107477ff9224781077354552\tblocked"
          }
        />
        <div className="row" style={{ justifyContent: "space-between" }}>
          <span className="small muted">
            {idCount}
            {paste.table ? ` · 表头 ${paste.table.headers.length} 列` : ""}
            {paste.table ? (
              <>
                {" · 预期结论列："}
                <select
                  className="native-input"
                  aria-label="预期结论列"
                  value={expectedIndex === null ? "none" : String(expectedIndex)}
                  onChange={(event) =>
                    setExpectedOverride(
                      event.target.value === "none" ? "none" : Number(event.target.value),
                    )
                  }
                  style={{ width: 160, height: 24, fontSize: 12 }}
                >
                  <option value="none">不对照</option>
                  {paste.table.headers.map((header, index) => (
                    // biome-ignore lint/suspicious/noArrayIndexKey: the headers of one paste are a fixed list
                    <option key={`col-${index}`} value={String(index)}>
                      {header || `第 ${index + 1} 列`}
                    </option>
                  ))}
                </select>
              </>
            ) : null}
            {tooMany ? <span className="hint-bad"> · {ERROR_TEXT.TOO_MANY_IDS}</span> : null}
          </span>
          <button
            type="button"
            className="btn-primary"
            onClick={run}
            disabled={paste.ids.length === 0 || tooMany || lookup.isPending}
          >
            {lookup.isPending ? "正在对照…" : "对照 ⏎"}
          </button>
        </div>
        {lookup.isError ? (
          <div className="field-error" role="alert">
            {ERROR_TEXT.INTERNAL}
          </div>
        ) : null}

        {result ? (
          <>
            <div className="row" style={{ justifyContent: "space-between" }}>
              <span className="small">
                ② 结果：{counts.total} 个 · 找到 {counts.found} · 查不到 {counts.missing} ·
                预期不一致 {counts.mismatch}
              </span>
              <span className="row" style={{ gap: 12 }}>
                <label className="check">
                  <input
                    type="checkbox"
                    checked={onlyMismatch}
                    onChange={(e) => setOnlyMismatch(e.target.checked)}
                  />
                  只看不一致
                </label>
                <label className="check">
                  <input
                    type="checkbox"
                    checked={onlyMissing}
                    onChange={(e) => setOnlyMissing(e.target.checked)}
                  />
                  只看查不到
                </label>
                <button type="button" className="btn" onClick={copyResult}>
                  复制结果
                </button>
              </span>
            </div>
            <div className="tbl-wrap" style={{ maxHeight: 360 }}>
              <table className="tbl" aria-label="对照结果">
                <thead>
                  <tr>
                    <th scope="col">请求 ID</th>
                    {extraColumns.map((column) => (
                      <th scope="col" key={column.header}>
                        {column.header}
                      </th>
                    ))}
                    <th scope="col">预期</th>
                    <th scope="col">实际结论</th>
                    <th scope="col">判定路径</th>
                    <th scope="col">状态</th>
                    <th scope="col">一致</th>
                  </tr>
                </thead>
                <tbody>
                  {visible.map((item) => (
                    <tr key={item.row.request_id}>
                      <td>
                        <RequestLink id={item.row.request_id} />
                      </td>
                      {item.extras.map((extra) => (
                        <td key={extra.header} className="mono small">
                          {extra.value}
                        </td>
                      ))}
                      <td>
                        {item.expected === null ? (
                          <span className="dim">—</span>
                        ) : item.expected === "blocked" ? (
                          "拦截"
                        ) : (
                          "放行"
                        )}
                      </td>
                      <td>
                        {item.outcome ? (
                          <OutcomeTag outcome={item.outcome} />
                        ) : (
                          <span className="dim">查不到</span>
                        )}
                      </td>
                      <td>
                        {item.row.summary ? (
                          <DecisionTag path={item.row.summary.decision_path} />
                        ) : (
                          <span className="dim">—</span>
                        )}
                      </td>
                      <td className="tnum">
                        {item.row.summary?.status ?? <span className="dim">—</span>}
                      </td>
                      <td>
                        {item.comparison === "match" ? (
                          <span className="hint-ok">✓ 一致</span>
                        ) : item.comparison === "mismatch" ? (
                          <span className="hint-bad">✗ 不一致</span>
                        ) : item.comparison === "unknown" ? (
                          <span className="dim">? 查不到</span>
                        ) : (
                          <span className="dim">—</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="small dim">
              {OUTCOME_INFO.would_block.name} 与 {OUTCOME_INFO.blocked.name}{" "}
              都按“拦截”比较；未经判定按“放行”比较。
            </div>
          </>
        ) : null}
      </div>
    </Modal>
  );
}
