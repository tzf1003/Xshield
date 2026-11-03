// The change history of a model configuration (design agent-model-ui 2.6): the last twenty versions, what each one
// changed, its note and whether it tested. A restore starts the save dialog with the old values filled in; the key
// does not come back with a version, because the key it had was replaced.

import { useModelHistory } from "../../api/queries.ts";
import type { ModelKind, ModelValues } from "../../api/types.ts";
import { changeText } from "../../lib/model-form.ts";
import { MODEL_TEXT } from "../../lib/vocab.ts";
import { ErrorBar, Loading } from "../../ui/Page.tsx";
import { shortDateTime } from "./clock.ts";

export function ModelHistory({
  kind,
  onRestore,
}: {
  kind: ModelKind;
  onRestore: (version: number, config: ModelValues) => void;
}) {
  const history = useModelHistory(kind, true);
  if (history.isPending) return <Loading height={80} />;
  if (!history.data) {
    return <ErrorBar error={history.error} onRetry={() => void history.refetch()} />;
  }
  const items = history.data.items;
  if (items.length === 0) return <p className="muted small">{MODEL_TEXT.historyEmpty}</p>;
  return (
    <div className="tbl-wrap sys-history">
      <table className="tbl sys-mini">
        <caption className="sr-only">{MODEL_TEXT.historyTitle}</caption>
        <thead>
          <tr>
            <th scope="col" className="num">
              {MODEL_TEXT.colVersion}
            </th>
            <th scope="col">{MODEL_TEXT.colTime}</th>
            <th scope="col">{MODEL_TEXT.colChanges}</th>
            <th scope="col">{MODEL_TEXT.colNote}</th>
            <th scope="col">{MODEL_TEXT.colTest}</th>
            <th scope="col">
              <span className="sr-only">{MODEL_TEXT.colAction}</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => {
            const at = Date.parse(item.at);
            return (
              <tr key={item.version}>
                <td className="num tnum">{item.version}</td>
                <td className="tnum wrap">{Number.isNaN(at) ? "—" : shortDateTime(at)}</td>
                <td className="wrap">
                  {item.changes.length === 0 ? (
                    <span className="muted">{MODEL_TEXT.historyNoChange}</span>
                  ) : (
                    item.changes.map((change) => (
                      <div key={change.field}>{changeText(change, kind)}</div>
                    ))
                  )}
                </td>
                <td className="wrap">{item.note === "" ? "—" : item.note}</td>
                <td>{item.tested ? MODEL_TEXT.historyTested : MODEL_TEXT.historyUntested}</td>
                <td>
                  <button
                    type="button"
                    className="linkbtn"
                    onClick={() => onRestore(item.version, item.config)}
                  >
                    {MODEL_TEXT.btnRestore(item.version)}
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
