// A line diff of two configurations, unified or side by side (docs/06 6.4.9). Every line is a text node.

import type { LineOp } from "../../lib/diff.ts";

type Cell = { text: string; op: LineOp["op"] };
type Pair = { id: number; left: Cell | null; right: Cell | null };

/** Pairs deletions with additions in each changed block, so the two columns line up block by block. */
function sideBySide(ops: LineOp[]): Pair[] {
  const pairs: Pair[] = [];
  let deleted: Cell[] = [];
  let added: Cell[] = [];
  const flush = () => {
    const rows = Math.max(deleted.length, added.length);
    for (let row = 0; row < rows; row += 1) {
      pairs.push({ id: pairs.length, left: deleted[row] ?? null, right: added[row] ?? null });
    }
    deleted = [];
    added = [];
  };
  for (const op of ops) {
    if (op.op === "del") {
      deleted.push({ text: op.text, op: "del" });
    } else if (op.op === "add") {
      added.push({ text: op.text, op: "add" });
    } else {
      flush();
      pairs.push({
        id: pairs.length,
        left: { text: op.text, op: "eq" },
        right: { text: op.text, op: "eq" },
      });
    }
  }
  flush();
  return pairs;
}

const SIGN: Record<LineOp["op"], string> = { eq: " ", add: "+", del: "-" };
const WORD: Record<LineOp["op"], string> = { eq: "", add: "新增 ", del: "删除 " };

function DiffCell({ cell }: { cell: Cell | null }) {
  return (
    <td className={`diff-cell ${cell?.op ?? "empty"}`}>
      {cell ? (
        <>
          <span className="sign" aria-hidden="true">
            {SIGN[cell.op]}
          </span>
          <span className="sr-only">{WORD[cell.op]}</span>
          <span>{cell.text}</span>
        </>
      ) : null}
    </td>
  );
}

export function DiffView({ ops, mode = "unified" }: { ops: LineOp[]; mode?: "unified" | "split" }) {
  if (ops.every((op) => op.op === "eq")) {
    return <div className="small muted">没有差异。</div>;
  }
  if (mode === "split") {
    return (
      <div className="diff">
        <table className="diff-split" aria-label="并排差异">
          <tbody>
            {sideBySide(ops).map((pair) => (
              <tr key={pair.id}>
                <DiffCell cell={pair.left} />
                <DiffCell cell={pair.right} />
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }
  const lines = ops.map((op, position) => ({ id: position, op }));
  return (
    <section className="diff" aria-label="差异">
      {lines.map(({ id, op }) => (
        <div key={id} className={`diff-line ${op.op === "eq" ? "" : op.op}`}>
          <span className="sign" aria-hidden="true">
            {SIGN[op.op]}
          </span>
          <span>
            <span className="sr-only">{WORD[op.op]}</span>
            {op.text}
          </span>
        </div>
      ))}
    </section>
  );
}
