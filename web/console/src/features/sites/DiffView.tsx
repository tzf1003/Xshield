// A line diff of two configurations, unified or side by side (docs/06 6.4.9). Every line is a text node.

import type { LineOp } from "../../lib/diff.ts";

type Cell = { id: number; text: string; op: LineOp["op"] };
type Pair = { id: number; left: Cell | null; right: Cell | null };

/** Pairs deletions with additions in each changed block, so the two columns line up block by block. */
function sideBySide(ops: LineOp[]): Pair[] {
  const pairs: Pair[] = [];
  let id = 0;
  let deleted: Cell[] = [];
  let added: Cell[] = [];
  const flush = () => {
    const rows = Math.max(deleted.length, added.length);
    for (let row = 0; row < rows; row += 1) {
      id += 1;
      pairs.push({ id, left: deleted[row] ?? null, right: added[row] ?? null });
    }
    deleted = [];
    added = [];
  };
  for (const op of ops) {
    if (op.op === "del") {
      id += 1;
      deleted.push({ id, text: op.text, op: "del" });
    } else if (op.op === "add") {
      id += 1;
      added.push({ id, text: op.text, op: "add" });
    } else {
      flush();
      id += 1;
      pairs.push({
        id,
        left: { id, text: op.text, op: "eq" },
        right: { id, text: op.text, op: "eq" },
      });
    }
  }
  flush();
  return pairs;
}

const SIGN: Record<LineOp["op"], string> = { eq: " ", add: "+", del: "-" };

export function DiffView({ ops, mode = "unified" }: { ops: LineOp[]; mode?: "unified" | "split" }) {
  if (ops.every((op) => op.op === "eq")) {
    return <div className="small muted">没有差异。</div>;
  }
  if (mode === "split") {
    return (
      <div className="diff diff-split" role="table" aria-label="并排差异">
        {sideBySide(ops).map((pair) => (
          <div key={pair.id} className="diff-split-row" role="row">
            <div className={`diff-cell ${pair.left?.op ?? "empty"}`} role="cell">
              {pair.left ? (
                <>
                  <span className="sign" aria-hidden="true">
                    {SIGN[pair.left.op]}
                  </span>
                  <span>{pair.left.text}</span>
                </>
              ) : null}
            </div>
            <div className={`diff-cell ${pair.right?.op ?? "empty"}`} role="cell">
              {pair.right ? (
                <>
                  <span className="sign" aria-hidden="true">
                    {SIGN[pair.right.op]}
                  </span>
                  <span>{pair.right.text}</span>
                </>
              ) : null}
            </div>
          </div>
        ))}
      </div>
    );
  }
  let id = 0;
  const lines = ops.map((op) => {
    id += 1;
    return { id, op };
  });
  return (
    <div className="diff" aria-label="差异">
      {lines.map(({ id: lineId, op }) => (
        <div key={lineId} className={`diff-line ${op.op === "eq" ? "" : op.op}`}>
          <span className="sign" aria-hidden="true">
            {SIGN[op.op]}
          </span>
          <span>
            <span className="sr-only">
              {op.op === "add" ? "新增 " : op.op === "del" ? "删除 " : ""}
            </span>
            {op.text}
          </span>
        </div>
      ))}
    </div>
  );
}
