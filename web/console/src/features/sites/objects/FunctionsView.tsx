// The function view of the object map (docs/06 6.4.10, docs/07 7.9.18 to 7.9.20): what the function table holds, the
// candidates the learning saw, the administrator proposals, the switch for unknown functions with its estimate, and the
// confirmation of the table's changes. Every change of the table waits for the administrator's confirmation: loading the
// view, the default selection and the refreshes send nothing. The switch writes the draft, which the save dialog saves.

import { Modal, Switch } from "antd";
import { type ReactNode, useEffect, useRef, useState } from "react";
import { ApiError } from "../../../api/client.ts";
import { useChangeFunctions, useDismissFunctionProposal } from "../../../api/queries.ts";
import type { FunctionRow, FunctionChanges, SiteFunctions, SiteSpec } from "../../../api/types.ts";
import { fmtInt } from "../../../lib/format.ts";
import { errorText, FUNCTION_VIEW, OBJECT_JUDGEMENT } from "../../../lib/vocab.ts";
import { RequestLink } from "../../../ui/RequestRef.tsx";
import { Card, ErrorBar, Loading, Notice } from "../../../ui/Page.tsx";
import { SafeText } from "../../../ui/SafeText.tsx";
import {
  askEstimate,
  changesOf,
  countsOf,
  dayText,
  defaultPending,
  emptiesTable,
  keyOfField,
  NO_PENDING,
  noAdminWarning,
  type Pending,
  type PendingKind,
  place,
  prunePending,
  reliabilityWord,
  underBypass,
  withAskUnknown,
} from "./functions-model.ts";
import type { ApplyOptions } from "./objects-model.ts";

type Props = {
  site: string;
  /** The draft, or the saved configuration when there is none. The switch and the bypass rules read the draft. */
  working: SiteSpec;
  /** The function table as the list answers it; undefined while it loads. */
  data: SiteFunctions | undefined;
  /** The error of the read, or null. */
  failure: unknown;
  onRetry: () => void;
  /** The draft holds changes of its own: a confirmation waits for them to be saved or dropped. */
  dirty: boolean;
  onApply: (spec: SiteSpec, options?: ApplyOptions) => void;
};

type Flash = { tone: "info" | "bad"; text: string };

/** The message of a refused change: the code's text, and the key the refusal names in the batch, when it names one. */
function errorOf(failure: unknown, body: FunctionChanges | null = null): string {
  if (!(failure instanceof ApiError)) return errorText(undefined);
  const key = keyOfField(failure.field, body);
  const text = errorText(failure.code);
  return key === null ? text : `${text}：${key}`;
}

function tierText(row: FunctionRow): string {
  const tier = FUNCTION_VIEW.table.tier;
  if (row.tier !== "admin") return tier.known;
  if (row.reliability === "high") return tier.high;
  return row.reliability === "medium" ? tier.medium : tier.low;
}

export function FunctionsView({ site, working, data, failure, onRetry, dirty, onApply }: Props) {
  const change = useChangeFunctions();
  const dismiss = useDismissFunctionProposal();
  const [pending, setPending] = useState<Pending>(NO_PENDING);
  const [confirming, setConfirming] = useState(false);
  const [flash, setFlash] = useState<Flash | null>(null);
  const seeded = useRef(false);

  // The default selection is made once, when the list first arrives. Later reads keep what the administrator picked and
  // drop only the keys the list no longer has.
  useEffect(() => {
    if (data === undefined) return;
    setPending((current) => (seeded.current ? prunePending(current, data) : defaultPending(data)));
    seeded.current = true;
  }, [data]);

  if (data === undefined) {
    return failure === null ? (
      <Loading height={180} />
    ) : (
      <ErrorBar error={failure} onRetry={onRetry} />
    );
  }

  const counts = countsOf(pending);
  const body = changesOf(pending, data);
  const ask = working.objects?.ask_unknown_functions === true;
  const draftEmpty = (working.objects?.functions ?? []).length === 0;
  // A batch that would delete the table's last function is refused while the site asks about unknown functions.
  const empties = ask && counts.total > 0 && emptiesTable(pending, data);
  const switchDisabled = counts.total > 0 || (!ask && draftEmpty);
  const confirmDisabled = counts.total === 0 || dirty || empties || change.isPending;
  const estimate = askEstimate(data);
  const bypass = working.bypass;
  const onEntry = (key: string) =>
    data.candidates.some((item) => item.key === key && item.on_entry) ||
    data.functions.some((item) => item.key === key && item.on_entry);
  const pick = (kind: PendingKind, key: string, on: boolean) =>
    setPending((current) => place(current, kind, key, on));

  const allCandidates = data.candidates.map((item) => item.key);
  const allPicked = allCandidates.length > 0 && allCandidates.every((key) => pending.add.has(key));
  const somePicked = allCandidates.some((key) => pending.add.has(key));
  const pickAll = (on: boolean) =>
    setPending((current) =>
      allCandidates.reduce((next, key) => place(next, "add", key, on), current),
    );
  const resetDefaults = () =>
    setPending((current) => ({ ...current, add: defaultPending(data).add }));

  const confirmNow = () => {
    if (body === null) return;
    setFlash(null);
    change.mutate(
      { name: site, body },
      {
        onSuccess: () => {
          setConfirming(false);
          setPending(NO_PENDING);
          setFlash({ tone: "info", text: FUNCTION_VIEW.confirm.confirmed });
        },
        onError: (failed) => {
          setConfirming(false);
          setFlash({ tone: "bad", text: errorOf(failed, body) });
        },
      },
    );
  };

  const dismissOne = (key: string) => {
    setFlash(null);
    dismiss.mutate(
      { name: site, key },
      {
        onSuccess: () => setFlash({ tone: "info", text: FUNCTION_VIEW.proposals.dismissed }),
        onError: (failed) => setFlash({ tone: "bad", text: errorOf(failed) }),
      },
    );
  };

  // The estimate of the switch: the requests that the gateway lets through now and whose function the table does not list.
  let impact: string;
  if (estimate.total === 0) impact = FUNCTION_VIEW.unknownSwitch.impactNone;
  else if (ask) impact = FUNCTION_VIEW.unknownSwitch.impactOn(estimate.total);
  else
    impact = FUNCTION_VIEW.unknownSwitch.impactOff(
      estimate.total,
      estimate.candidateCount,
      estimate.candidateRequests,
      estimate.unlearned,
      estimate.unkeyed,
      estimate.complete,
    );
  const suggestedPending = data.candidates.filter(
    (item) => item.suggested && !item.sensitive,
  ).length;

  const addRows = data.candidates.filter((item) => pending.add.has(item.key));
  const adminRows = data.proposals.filter((item) => pending.admin.has(item.key));
  const openRows = data.functions.filter((item) => pending.open.has(item.key));
  const removeRows = data.functions.filter((item) => pending.remove.has(item.key));
  const sensitiveAdds = addRows.filter((item) => item.sensitive).map((item) => item.key);
  const confirmLines: ReactNode[] = [];
  if (addRows.length > 0) {
    confirmLines.push(
      <li key="add">
        <p>{FUNCTION_VIEW.confirm.add(addRows.length)}</p>
        {sensitiveAdds.length > 0 ? (
          <>
            <p>{FUNCTION_VIEW.confirm.addSensitive(sensitiveAdds.length)}</p>
            <ul>
              {sensitiveAdds.map((key) => (
                <li key={key}>
                  <span className="obj-code">
                    <SafeText text={key} />
                  </span>
                </li>
              ))}
            </ul>
          </>
        ) : null}
      </li>,
    );
  }
  if (adminRows.length > 0) {
    confirmLines.push(
      <li key="admin">
        <p>{FUNCTION_VIEW.confirm.admin(adminRows.length)}</p>
        <ul>
          {adminRows.map((item) => (
            <li key={item.key}>
              <span className="obj-code">
                <SafeText text={item.key} />
              </span>{" "}
              <span className="small muted">
                {FUNCTION_VIEW.proposals.reliability(reliabilityWord(item.reliability))}
              </span>
              {onEntry(item.key) ? <p className="small">{FUNCTION_VIEW.confirm.onEntry}</p> : null}
            </li>
          ))}
        </ul>
        {adminRows.some((item) => item.reliability === "medium") ? (
          <p className="small muted">{FUNCTION_VIEW.proposals.mediumNote}</p>
        ) : null}
        {data.admin_units === 0 ? <p>{FUNCTION_VIEW.status.noAdmin(data.window_days)}</p> : null}
      </li>,
    );
  }
  if (openRows.length > 0) {
    confirmLines.push(
      <li key="open">
        <p>{FUNCTION_VIEW.confirm.open(openRows.length)}</p>
        <p className="small muted">{FUNCTION_VIEW.confirm.openNote}</p>
        <ul>
          {openRows.map((item) => (
            <li key={item.key}>
              <span className="obj-code">
                <SafeText text={item.key} />
              </span>
            </li>
          ))}
        </ul>
      </li>,
    );
  }
  if (removeRows.length > 0) {
    confirmLines.push(
      <li key="remove">
        <p>{FUNCTION_VIEW.confirm.remove(removeRows.length)}</p>
        {ask ? <p className="small muted">{FUNCTION_VIEW.confirm.removeAsking}</p> : null}
        <ul>
          {removeRows.map((item) => (
            <li key={item.key}>
              <span className="obj-code">
                <SafeText text={item.key} />
              </span>
            </li>
          ))}
        </ul>
      </li>,
    );
  }

  return (
    <div className="obj-fn">
      {flash === null ? null : (
        <Notice tone={flash.tone === "bad" ? "bad" : "info"}>{flash.text}</Notice>
      )}

      <div className="obj-fn-status">
        <p className="small muted">
          {FUNCTION_VIEW.status.summary(
            data.window_days,
            data.ordinary_units,
            data.admin_units,
            data.identified,
          )}
        </p>
        {data.status === "over_limit" ? <Notice>{FUNCTION_VIEW.status.overLimit}</Notice> : null}
        {data.status === "learning_off" ? (
          <Notice tone="info">{FUNCTION_VIEW.status.learningOff}</Notice>
        ) : null}
        {noAdminWarning(data) ? (
          <Notice>{FUNCTION_VIEW.status.noAdmin(data.window_days)}</Notice>
        ) : null}
        <p className="small muted">{FUNCTION_VIEW.status.bypass}</p>
      </div>

      {data.proposals.length === 0 ? null : (
        <Card
          className="obj-judgements obj-fn-proposals"
          title={FUNCTION_VIEW.proposals.title(data.proposals.length)}
          aside={<span className="small muted">{FUNCTION_VIEW.proposals.lead}</span>}
        >
          <ul className="obj-judge-list">
            {data.proposals.map((item) => (
              <li key={item.key} className="obj-judge-row">
                <div className="obj-judge-where">
                  <span className="obj-code">
                    <SafeText text={item.key} />
                  </span>
                  {item.in_table ? (
                    <span className="tag tag-neutral">{FUNCTION_VIEW.proposals.inTable}</span>
                  ) : null}
                </div>
                <div className="obj-judge-what">
                  <span className="small muted">
                    {FUNCTION_VIEW.proposals.evidence(
                      item.admin_units,
                      item.refused_units,
                      reliabilityWord(item.reliability),
                    )}
                  </span>
                  {item.reliability === "medium" ? (
                    <div className="small muted">{FUNCTION_VIEW.proposals.mediumNote}</div>
                  ) : null}
                </div>
                <div className="obj-judge-actions">
                  <label className="adv-radio">
                    <input
                      type="checkbox"
                      aria-label={FUNCTION_VIEW.aria.admin(item.key)}
                      checked={pending.admin.has(item.key)}
                      onChange={(event) => pick("admin", item.key, event.target.checked)}
                    />
                    {FUNCTION_VIEW.proposals.confirm}
                  </label>
                  <button
                    type="button"
                    className="btn"
                    aria-label={FUNCTION_VIEW.aria.dismiss(item.key)}
                    disabled={dismiss.isPending}
                    onClick={() => dismissOne(item.key)}
                  >
                    {FUNCTION_VIEW.proposals.dismiss}
                  </button>
                </div>
              </li>
            ))}
          </ul>
        </Card>
      )}

      <Card className="obj-fn-table-card" title={FUNCTION_VIEW.table.title(data.functions.length)}>
        {data.functions.length === 0 ? (
          <div className="small muted">{FUNCTION_VIEW.table.empty}</div>
        ) : (
          <div className="tbl-wrap">
            <table className="tbl" aria-label={FUNCTION_VIEW.table.title(data.functions.length)}>
              <thead>
                <tr>
                  <th scope="col">{FUNCTION_VIEW.table.columns.key}</th>
                  <th scope="col">{FUNCTION_VIEW.table.columns.tier}</th>
                  <th scope="col">{FUNCTION_VIEW.table.columns.source}</th>
                  <th scope="col" className="num">
                    {FUNCTION_VIEW.table.columns.ordinary}
                  </th>
                  <th scope="col" className="num">
                    {FUNCTION_VIEW.table.columns.admin}
                  </th>
                  <th scope="col" className="num">
                    {FUNCTION_VIEW.table.columns.refused}
                  </th>
                  <th scope="col">{FUNCTION_VIEW.table.columns.last}</th>
                  <th scope="col">{FUNCTION_VIEW.table.columns.action}</th>
                </tr>
              </thead>
              <tbody>
                {data.functions.map((row) => {
                  const admin = row.tier === "admin";
                  const opening = pending.open.has(row.key);
                  const removing = pending.remove.has(row.key);
                  return (
                    <tr key={row.key}>
                      <td className="wrap">
                        <span className="obj-code">
                          <SafeText text={row.key} />
                        </span>{" "}
                        {admin && row.on_entry ? (
                          <span
                            className="tag tag-blocked"
                            title={FUNCTION_VIEW.table.onEntry.desc}
                          >
                            {FUNCTION_VIEW.table.onEntry.tag}
                          </span>
                        ) : null}
                        {underBypass(row.key, bypass) ? (
                          <span
                            className="tag tag-would"
                            title={FUNCTION_VIEW.table.underBypass.desc}
                          >
                            {FUNCTION_VIEW.table.underBypass.tag}
                          </span>
                        ) : null}
                      </td>
                      <td className="wrap">{tierText(row)}</td>
                      <td>{FUNCTION_VIEW.table.source[row.source]}</td>
                      <td className="num">{fmtInt(row.ordinary_units)}</td>
                      <td className="num">{fmtInt(row.admin_units)}</td>
                      <td className="num">{fmtInt(row.refused_units)}</td>
                      <td className="keep">{dayText(row.last_seen)}</td>
                      <td className="keep">
                        {admin ? (
                          <button
                            type="button"
                            className="btn"
                            aria-pressed={opening}
                            aria-label={FUNCTION_VIEW.aria.open(row.key)}
                            disabled={removing}
                            onClick={() => pick("open", row.key, !opening)}
                          >
                            {FUNCTION_VIEW.table.openAdmin}
                          </button>
                        ) : null}{" "}
                        <button
                          type="button"
                          className="btn"
                          aria-pressed={removing}
                          aria-label={FUNCTION_VIEW.aria.remove(row.key)}
                          onClick={() => pick("remove", row.key, !removing)}
                        >
                          {FUNCTION_VIEW.table.remove}
                        </button>
                        {opening ? (
                          <span className="tag tag-would">{FUNCTION_VIEW.table.pendingOpen}</span>
                        ) : null}
                        {removing ? (
                          <span className="tag tag-blocked">
                            {FUNCTION_VIEW.table.pendingRemove}
                          </span>
                        ) : null}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card
        className="obj-fn-candidates-card"
        title={FUNCTION_VIEW.candidates.title(data.candidates.length)}
        aside={
          <button type="button" className="linkbtn" onClick={resetDefaults}>
            {FUNCTION_VIEW.candidates.resetDefaults}
          </button>
        }
      >
        {data.status === "over_limit" ? null : (
          <>
            <div className="small muted">{FUNCTION_VIEW.candidates.lead}</div>
            {data.candidates.length === 0 ? (
              <div className="small muted">{FUNCTION_VIEW.candidates.none}</div>
            ) : (
              <div className="tbl-wrap">
                <table
                  className="tbl"
                  aria-label={FUNCTION_VIEW.candidates.title(data.candidates.length)}
                >
                  <thead>
                    <tr>
                      <th scope="col">
                        <input
                          type="checkbox"
                          aria-label={FUNCTION_VIEW.candidates.selectAll}
                          checked={allPicked}
                          ref={(element) => {
                            if (element) element.indeterminate = somePicked && !allPicked;
                          }}
                          onChange={(event) => pickAll(event.target.checked)}
                        />
                      </th>
                      <th scope="col">{FUNCTION_VIEW.candidates.columns.key}</th>
                      <th scope="col" className="num">
                        {FUNCTION_VIEW.candidates.columns.ordinary}
                      </th>
                      <th scope="col" className="num">
                        {FUNCTION_VIEW.candidates.columns.admin}
                      </th>
                      <th scope="col" className="num">
                        {FUNCTION_VIEW.candidates.columns.refused}
                      </th>
                      <th scope="col">{FUNCTION_VIEW.candidates.columns.last}</th>
                      <th scope="col" className="num">
                        {FUNCTION_VIEW.candidates.columns.requests}
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.candidates.map((item) => (
                      <tr key={item.key}>
                        <td>
                          <input
                            type="checkbox"
                            aria-label={FUNCTION_VIEW.aria.add(item.key)}
                            checked={pending.add.has(item.key)}
                            onChange={(event) => pick("add", item.key, event.target.checked)}
                          />
                        </td>
                        <td className="wrap">
                          <span className="obj-code">
                            <SafeText text={item.key} />
                          </span>{" "}
                          {item.sensitive ? (
                            <span
                              className="tag tag-would"
                              title={FUNCTION_VIEW.candidates.sensitive.desc}
                            >
                              {FUNCTION_VIEW.candidates.sensitive.tag}
                            </span>
                          ) : null}
                          {item.suggested ? null : (
                            <span className="tag tag-neutral">
                              {FUNCTION_VIEW.candidates.belowThreshold(data.threshold_units)}
                            </span>
                          )}
                          {item.on_entry ? (
                            <span className="tag tag-neutral">
                              {FUNCTION_VIEW.candidates.entry}
                            </span>
                          ) : null}
                        </td>
                        <td className="num">{fmtInt(item.ordinary_units)}</td>
                        <td className="num">{fmtInt(item.admin_units)}</td>
                        <td className="num">{fmtInt(item.refused_units)}</td>
                        <td className="keep">{dayText(item.last_seen)}</td>
                        <td className="num">{fmtInt(item.requests_24h)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </Card>

      <Card className="obj-fn-switch-card" title={FUNCTION_VIEW.unknownSwitch.title}>
        <div className="small muted">{FUNCTION_VIEW.unknownSwitch.lead}</div>
        <div className="obj-learning-row">
          <span>{FUNCTION_VIEW.unknownSwitch.title}</span>
          <Switch
            aria-label={FUNCTION_VIEW.unknownSwitch.title}
            checked={ask}
            disabled={switchDisabled}
            checkedChildren={FUNCTION_VIEW.unknownSwitch.on}
            unCheckedChildren={FUNCTION_VIEW.unknownSwitch.off}
            onChange={(checked) => onApply(withAskUnknown(working, checked))}
          />
          {counts.total > 0 ? (
            <span className="obj-learning-help">{FUNCTION_VIEW.unknownSwitch.pending}</span>
          ) : null}
          {!ask && draftEmpty ? (
            <span className="obj-learning-help">{FUNCTION_VIEW.unknownSwitch.emptyTable}</span>
          ) : null}
        </div>
        <p className="small">{impact}</p>
        {ask || suggestedPending === 0 ? null : (
          <Notice>{FUNCTION_VIEW.unknownSwitch.candidatesPending(suggestedPending)}</Notice>
        )}
        {working.mode === "observe" ? (
          <p className="small muted">{FUNCTION_VIEW.unknownSwitch.observe}</p>
        ) : null}
        {data.unlearned.top.length > 0 ? (
          <div className="obj-fn-unlearned">
            <h2 className="small">{FUNCTION_VIEW.unknownSwitch.unlearned.title}</h2>
            <div className="small muted">{FUNCTION_VIEW.unknownSwitch.unlearned.lead}</div>
            <div className="tbl-wrap">
              <table className="tbl" aria-label={FUNCTION_VIEW.unknownSwitch.unlearned.title}>
                <thead>
                  <tr>
                    <th scope="col">{FUNCTION_VIEW.unknownSwitch.unlearned.columns.key}</th>
                    <th scope="col" className="num">
                      {FUNCTION_VIEW.unknownSwitch.unlearned.columns.requests}
                    </th>
                    <th scope="col">{FUNCTION_VIEW.unknownSwitch.unlearned.columns.sample}</th>
                  </tr>
                </thead>
                <tbody>
                  {data.unlearned.top.map((item) => (
                    <tr key={item.key}>
                      <td className="wrap">
                        <span className="obj-code">
                          <SafeText text={item.key} />
                        </span>
                      </td>
                      <td className="num">{fmtInt(item.requests)}</td>
                      <td>
                        <RequestLink id={item.sample} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ) : null}
      </Card>

      <div className="obj-fn-bar">
        <div className="obj-fn-bar-text">
          <span>
            {FUNCTION_VIEW.bar.pending(counts.add, counts.admin, counts.open, counts.remove)}
          </span>
          {dirty && counts.total > 0 ? (
            <span className="small muted">{OBJECT_JUDGEMENT.panel.dirtyDraft}</span>
          ) : null}
          {empties ? <span className="small">{FUNCTION_VIEW.confirm.emptiesTable}</span> : null}
        </div>
        <button
          type="button"
          className="btn-primary"
          disabled={confirmDisabled}
          title={counts.total === 0 ? FUNCTION_VIEW.bar.none : undefined}
          onClick={() => setConfirming(true)}
        >
          {FUNCTION_VIEW.bar.confirm}
        </button>
      </div>

      <Modal
        open={confirming}
        title={FUNCTION_VIEW.confirm.title}
        okText={FUNCTION_VIEW.confirm.ok}
        cancelText={FUNCTION_VIEW.confirm.cancel}
        okButtonProps={{ loading: change.isPending }}
        onOk={confirmNow}
        onCancel={() => setConfirming(false)}
      >
        <ul className="obj-fn-confirm">{confirmLines}</ul>
        <p className="small">{FUNCTION_VIEW.confirm.afterNote}</p>
      </Modal>
    </div>
  );
}
