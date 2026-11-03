// The two cards of the "模型" tab (design agent-model-ui 2.1 to 2.6). A card shows the configuration in use, where
// it comes from, what the gateways run and how the last hour or day went. Editing turns the body into a form in
// place; a save goes through a dialog that lists the changes and the test result, and a test runs the form's values
// without saving them.

import { App } from "antd";
import { useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { type ReactNode, useCallback, useEffect, useRef, useState } from "react";
import { ApiError, api } from "../../api/client.ts";
import { keys, useDeleteJevModel, useSaveAgentModel, useSaveJevModel } from "../../api/queries.ts";
import type {
  AgentModelsState,
  JevModelsState,
  JevRoute,
  ModelKind,
  ModelsState,
  ModelTestBody,
  ModelValues,
} from "../../api/types.ts";
import { useNowBucket } from "../../app/scope.ts";
import { fmtInt, fmtMs } from "../../lib/format.ts";
import {
  type ChangeRow,
  type FormProblems,
  type ModelForm as Form,
  agentCanShare,
  agentEffective,
  agentForm,
  agentKeyRequired,
  agentProblems,
  agentTestable,
  agentValues,
  clockText,
  describeTest,
  formChanges,
  formFromValues,
  jevForm,
  jevProblems,
  jevValues,
  presetEndpoint,
  presetModel,
  sameForm,
  timeoutMsOf,
  type TestLine,
} from "../../lib/model-form.ts";
import {
  agentStatusLine,
  jevNotLoaded,
  jevStatusLine,
  notLoadedSummary,
  type StatusLine,
} from "../../lib/model-status.ts";
import { errorText, MODEL_PROVIDER_LABEL, MODEL_ROUTE_LABEL, MODEL_TEXT } from "../../lib/vocab.ts";
import { Card, Kv, Notice } from "../../ui/Page.tsx";
import { ModelForm } from "./ModelForm.tsx";
import { ModelHistory } from "./ModelHistory.tsx";
import { ModelSaveDialog } from "./ModelSaveDialog.tsx";
import { ModelTestResult } from "./ModelTestResult.tsx";
import { parseTime, shortDateTime } from "./clock.ts";

/** A test can be repeated after this long (design 2.4). */
const TEST_COOLDOWN_MS = 10_000;

/** A value shown in the monospace face (addresses and model names). */
function mono(text: string): ReactNode {
  return <span className="mono">{text}</span>;
}

function StatusLabel({ line }: { line: StatusLine }) {
  const tone = line.tone === "ok" ? "hint-ok" : line.tone === "warn" ? "hint-warn" : "muted";
  return (
    <span className={`sys-status ${tone}`}>
      <span aria-hidden="true">{line.icon}</span> {line.text}
    </span>
  );
}

/** A test that never reached an answer: too frequent, or a failure the server named. */
function failureLine(error: unknown): TestLine {
  if (error instanceof ApiError && error.status === 429) {
    return { tone: "warn", icon: "!", text: MODEL_TEXT.testTooOften, detail: null };
  }
  const code = error instanceof ApiError ? error.code : undefined;
  return { tone: "bad", icon: "✕", text: errorText(code), detail: null };
}

type Passed = { form: Form; at: string };

/**
 * The test of one model: runs a request with the given body, keeps the last line, remembers which form passed
 * (so a save can say whether it tested), and holds the ten-second cooldown.
 */
function useModelTest(kind: ModelKind, now: number) {
  const [line, setLine] = useState<TestLine | null>(null);
  const [busy, setBusy] = useState(false);
  const [cooldownUntil, setCooldownUntil] = useState(0);
  const [passed, setPassed] = useState<Passed | null>(null);
  const running = useRef<AbortController | null>(null);

  useEffect(
    () => () => {
      running.current?.abort();
    },
    [],
  );

  const run = useCallback(
    async (body: ModelTestBody, tried: Form, timeoutMs: number) => {
      const controller = new AbortController();
      running.current = controller;
      setBusy(true);
      try {
        const result = await api.testModel(kind, body, controller.signal);
        const at = new Date().toISOString();
        setLine(describeTest(kind, result, timeoutMs, at));
        if (result.ok) setPassed({ form: tried, at });
      } catch (error) {
        if (!controller.signal.aborted) setLine(failureLine(error));
      } finally {
        if (running.current === controller) running.current = null;
        setBusy(false);
        setCooldownUntil(Date.now() + TEST_COOLDOWN_MS);
      }
    },
    [kind],
  );

  const cancel = () => {
    running.current?.abort();
  };
  const cooldown = Math.max(0, Math.ceil((cooldownUntil - now) / 1000));
  return { line, busy, cooldown, passed, run, cancel };
}

function testLabel(busy: boolean, cooldown: number): string {
  if (busy) return MODEL_TEXT.btnTesting;
  if (cooldown > 0) return MODEL_TEXT.testCooldown(cooldown);
  return MODEL_TEXT.btnTest;
}

function whenText(iso: string | null): string {
  const at = iso === null ? null : parseTime(iso);
  return at === null ? "—" : shortDateTime(at);
}

function rateText(calls: number, failed: number): string {
  if (calls === 0) return "—";
  return `${((failed / calls) * 100).toFixed(1)}%`;
}

// ------------------------------------------------------------------ Jev

export function JevModelCard({ jev, now }: { jev: JevModelsState; now: number }) {
  const client = useQueryClient();
  const clock = useNowBucket(1_000);
  const test = useModelTest("jev", clock);
  const save = useSaveJevModel();
  const remove = useDeleteJevModel();
  const [editing, setEditing] = useState(false);
  const [form, setForm] = useState<Form>(() => jevForm(jev));
  const [historyOpen, setHistoryOpen] = useState(false);
  const [saveOpen, setSaveOpen] = useState(false);
  const [restored, setRestored] = useState<number | null>(null);
  const [conflict, setConflict] = useState<number | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [backError, setBackError] = useState<string | null>(null);
  // The version the form was read at: a save sends it, not the version the card has refreshed to since.
  const [readVersion, setReadVersion] = useState<number>(jev.version);
  const { modal } = App.useApp();

  const saved = jevForm(jev);
  const keyRequired = jev.source === "env" || !jev.key.set;
  const problems: FormProblems = jevProblems(form, keyRequired);
  const valid = Object.keys(problems).length === 0;
  const tested = test.passed !== null && sameForm(test.passed.form, form);
  const status = jevStatusLine(jev, now);
  const notLoaded = jevNotLoaded(jev, now);
  // A card without a saved configuration or a gateway's environment still shows the defaults of the gateway line.
  const route: JevRoute = jev.route ?? "gateway";

  const keySummary = !jev.key.set
    ? MODEL_TEXT.keyUnset
    : jev.source === "env"
      ? MODEL_TEXT.keyFromEnv(jev.key_env)
      : MODEL_TEXT.keySet(jev.key.last4 ?? "", whenText(jev.key.updated_at));
  const sourceText =
    jev.source === "console"
      ? `${MODEL_TEXT.sourceConsole(jev.version, whenText(jev.updated_at))}${
          jev.env_overridden.length > 0 ? MODEL_TEXT.overridden(jev.env_overridden.join("、")) : ""
        }`
      : MODEL_TEXT.sourceEnv;
  const usage = jev.usage;
  const usageLine =
    usage.calls === 0
      ? MODEL_TEXT.noUsageYet
      : MODEL_TEXT.usageJev(
          fmtInt(usage.calls),
          rateText(usage.calls, usage.failed),
          fmtMs(usage.p95_ms),
        );

  const openEdit = (next?: Form) => {
    setForm(next ?? jevForm(jev));
    setReadVersion(jev.version);
    setRestored(null);
    setConflict(null);
    setSaveError(null);
    setEditing(true);
  };
  const closeEdit = () => {
    // Leaving the form drops the key it held: nothing keeps a typed key after the form closes.
    setEditing(false);
    setForm(jevForm(jev));
    setRestored(null);
    setConflict(null);
    setSaveError(null);
  };

  const submit = (note: string) => {
    const key = form.key.trim();
    save.mutate(
      {
        ...jevValues(form),
        ...(key === "" ? {} : { key }),
        expected_version: readVersion,
        note,
        tested,
      },
      {
        onSuccess: () => {
          setSaveOpen(false);
          setEditing(false);
          setRestored(null);
          setSaveError(null);
        },
        onError: (error) => {
          if (
            error instanceof ApiError &&
            error.status === 409 &&
            error.currentVersion !== undefined
          ) {
            setConflict(error.currentVersion ?? 0);
            return;
          }
          setSaveError(errorText(error instanceof ApiError ? error.code : undefined));
        },
      },
    );
  };

  const reload = async () => {
    await client.refetchQueries({ queryKey: keys.models });
    const latest = client.getQueryData<ModelsState>(keys.models)?.jev;
    setSaveOpen(false);
    setConflict(null);
    setSaveError(null);
    if (latest !== undefined) {
      setForm(jevForm(latest));
      setReadVersion(latest.version);
    }
  };

  const restore = (version: number, config: ModelValues) => {
    const next = formFromValues("jev", config);
    setForm(next);
    setReadVersion(jev.version);
    setRestored(version);
    setEditing(true);
    setConflict(null);
    setSaveError(null);
    // The dialog opens only when the version saves as it is; otherwise the form asks for the key it needs first.
    setSaveOpen(Object.keys(jevProblems(next, keyRequired)).length === 0);
  };

  const backToEnv = () => {
    modal.confirm({
      title: MODEL_TEXT.backTitle,
      content: MODEL_TEXT.backBody,
      okText: MODEL_TEXT.backOk,
      cancelText: MODEL_TEXT.btnCancel,
      onOk: async () => {
        setBackError(null);
        try {
          await remove.mutateAsync(jev.version);
        } catch (error) {
          setBackError(errorText(error instanceof ApiError ? error.code : undefined));
        }
      },
    });
  };

  const changes: ChangeRow[] = formChanges("jev", saved, form, jev.key.last4, restored !== null);
  const impact = [
    MODEL_TEXT.impactJev(jev.impact.sites, jev.source === "console" ? jev.version : null),
  ];

  return (
    <Card className="sys-model" title={MODEL_TEXT.jevTitle} aside={<StatusLabel line={status} />}>
      {notLoaded.length > 0 && !editing ? (
        <Notice tone="warn">
          {MODEL_TEXT.attentionNotLoaded(
            jev.version,
            notLoadedSummary(notLoaded).edges,
            notLoadedSummary(notLoaded).reason,
          )}{" "}
          <Link to="/system" search={{ tab: "models" }}>
            {MODEL_TEXT.attentionAction}
          </Link>
        </Notice>
      ) : null}

      {editing ? (
        <ModelForm
          kind="jev"
          form={form}
          onChange={setForm}
          problems={problems}
          keyRequired={keyRequired}
          keySummary={keySummary}
          shareAllowed={false}
          test={{
            line: test.line,
            testing: test.busy,
            cooldown: test.cooldown,
            onTest: () =>
              void test.run(
                {
                  ...jevValues(form),
                  ...(form.key.trim() === "" ? {} : { key: form.key.trim() }),
                },
                form,
                timeoutMsOf("jev", form),
              ),
            onCancelTest: test.cancel,
          }}
          footnote={MODEL_TEXT.testFootJev}
          canSave={valid}
          onCancel={closeEdit}
          onSave={() => setSaveOpen(true)}
        />
      ) : jev.source === null ? (
        <>
          <p className="sys-lead">{MODEL_TEXT.jevUnset}</p>
          <div className="sys-actions">
            <button type="button" className="btn btn-primary" onClick={() => openEdit()}>
              {MODEL_TEXT.btnConfigure}
            </button>
          </div>
        </>
      ) : (
        <>
          <Kv
            items={[
              [MODEL_TEXT.rowRoute, MODEL_ROUTE_LABEL[route]],
              [
                MODEL_TEXT.rowEndpoint,
                mono(jev.endpoint ?? presetEndpoint(route) ?? jev.endpoint_host ?? "—"),
              ],
              [MODEL_TEXT.rowModel, mono(jev.model ?? presetModel(route) ?? "—")],
              [MODEL_TEXT.rowKey, keySummary],
              [MODEL_TEXT.rowTimeout, MODEL_TEXT.timeoutJev(fmtMs(jev.timeout_ms))],
              [MODEL_TEXT.rowSource, sourceText],
              [
                MODEL_TEXT.rowUsageWindow(usage.window_minutes),
                <>
                  {usageLine} <Link to="/jev">{MODEL_TEXT.linkJevCalls}</Link>
                </>,
              ],
            ]}
          />
          <div className="sys-actions">
            {jev.version > 0 ? (
              <button
                type="button"
                className="linkbtn"
                onClick={() => setHistoryOpen((open) => !open)}
              >
                {MODEL_TEXT.btnHistory}
              </button>
            ) : null}
            <button
              type="button"
              className="btn"
              disabled={test.busy || test.cooldown > 0 || jev.source === "env"}
              onClick={() => void test.run(jevValues(saved), saved, timeoutMsOf("jev", saved))}
            >
              {testLabel(test.busy, test.cooldown)}
            </button>
            {jev.source === "env" ? (
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => openEdit({ ...jevForm(jev), key: "" })}
              >
                {MODEL_TEXT.btnTakeOver}
              </button>
            ) : (
              <button type="button" className="btn btn-primary" onClick={() => openEdit()}>
                {MODEL_TEXT.btnEdit}
              </button>
            )}
            {jev.source === "console" && jev.env_available ? (
              <button type="button" className="btn" onClick={backToEnv}>
                {MODEL_TEXT.btnBackToEnv}
              </button>
            ) : null}
          </div>
          {jev.source === "env" ? <p className="muted small">{MODEL_TEXT.testNeedsKey}</p> : null}
          {test.line === null ? null : <ModelTestResult line={test.line} />}
          {backError === null ? null : <Notice tone="bad">{backError}</Notice>}
          {historyOpen ? <ModelHistory kind="jev" onRestore={restore} /> : null}
        </>
      )}

      {saveOpen ? (
        <ModelSaveDialog
          title={MODEL_TEXT.saveTitle(MODEL_TEXT.jevTitle, jev.version + 1)}
          defaultNote={restored === null ? "" : MODEL_TEXT.restoreNote(restored)}
          changes={changes}
          impact={impact}
          failClosed={jev.impact.fail_closed}
          tested={tested}
          testedLine={
            test.passed === null || !tested ? null : MODEL_TEXT.testedOk(clockText(test.passed.at))
          }
          saving={save.isPending}
          conflict={conflict}
          error={saveError}
          saveLabel={MODEL_TEXT.btnSaveVersion(jev.version + 1)}
          onSave={submit}
          onClose={() => setSaveOpen(false)}
          onReload={() => void reload()}
        />
      ) : null}
    </Card>
  );
}

// ------------------------------------------------------------------ learning agent

export function AgentModelCard({
  agent,
  jevRoute,
  jevConsole,
}: {
  agent: AgentModelsState;
  jevRoute: JevRoute | null;
  /** Jev's configuration is saved in the console, which holds the key that a share uses. */
  jevConsole: boolean;
}) {
  const client = useQueryClient();
  const clock = useNowBucket(1_000);
  const test = useModelTest("agent", clock);
  const save = useSaveAgentModel();
  const [editing, setEditing] = useState(false);
  const [draftForm, setForm] = useState<Form>(() => agentForm(agent));
  // The form as it is saved: a share that cannot apply is off, so the form asks for the key it needs instead.
  const form = agentEffective(draftForm, jevRoute, jevConsole);
  // The version the form was read at, as on the Jev card above.
  const [readVersion, setReadVersion] = useState<number>(agent.version);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [saveOpen, setSaveOpen] = useState(false);
  const [restored, setRestored] = useState<number | null>(null);
  const [conflict, setConflict] = useState<number | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);

  const saved = agentForm(agent);
  // The key is shared only when both sides run on the Vercel AI Gateway and the console holds Jev's key (design 2.2).
  const shareAllowed = agentCanShare(form, jevRoute, jevConsole);
  const keyRequired = agentKeyRequired(form.shareKey, agent.key);
  const problems: FormProblems = agentProblems(form, keyRequired);
  const valid = Object.keys(problems).length === 0;
  const tested = test.passed !== null && sameForm(test.passed.form, form);
  const status = agentStatusLine(agent);

  const keySummary = agent.key.shared_with_jev
    ? MODEL_TEXT.keyShared
    : !agent.key.set
      ? MODEL_TEXT.keyUnset
      : MODEL_TEXT.keySet(agent.key.last4 ?? "", whenText(agent.key.updated_at));
  const sourceText =
    agent.source === "console"
      ? MODEL_TEXT.sourceConsole(agent.version, whenText(agent.updated_at))
      : "—";

  const openEdit = (next?: Form) => {
    setForm(next ?? agentForm(agent));
    setReadVersion(agent.version);
    setRestored(null);
    setConflict(null);
    setSaveError(null);
    setEditing(true);
  };
  const closeEdit = () => {
    setEditing(false);
    setForm(agentForm(agent));
    setRestored(null);
    setConflict(null);
    setSaveError(null);
  };

  const submit = (note: string) => {
    const key = form.key.trim();
    save.mutate(
      {
        ...agentValues(form),
        ...(key === "" || form.shareKey ? {} : { key }),
        expected_version: readVersion,
        note,
        tested,
      },
      {
        onSuccess: () => {
          setSaveOpen(false);
          setEditing(false);
          setRestored(null);
          setSaveError(null);
        },
        onError: (error) => {
          if (
            error instanceof ApiError &&
            error.status === 409 &&
            error.currentVersion !== undefined
          ) {
            setConflict(error.currentVersion ?? 0);
            return;
          }
          setSaveError(errorText(error instanceof ApiError ? error.code : undefined));
        },
      },
    );
  };

  const reload = async () => {
    await client.refetchQueries({ queryKey: keys.models });
    const latest = client.getQueryData<ModelsState>(keys.models)?.agent;
    setSaveOpen(false);
    setConflict(null);
    setSaveError(null);
    if (latest !== undefined) {
      setForm(agentForm(latest));
      setReadVersion(latest.version);
    }
  };

  const restore = (version: number, config: ModelValues) => {
    const next = formFromValues("agent", config);
    const effective = agentEffective(next, jevRoute, jevConsole);
    const keyNeeded = agentKeyRequired(effective.shareKey, agent.key);
    setForm(next);
    setReadVersion(agent.version);
    setRestored(version);
    setEditing(true);
    setConflict(null);
    setSaveError(null);
    // The dialog opens only when the version saves as it is; otherwise the form asks for the key it needs first.
    setSaveOpen(Object.keys(agentProblems(effective, keyNeeded)).length === 0);
  };

  const changes = formChanges("agent", saved, form, agent.key.last4, restored !== null);
  const impact = [MODEL_TEXT.impactAgent];

  const body = editing ? (
    <ModelForm
      kind="agent"
      form={form}
      onChange={setForm}
      problems={problems}
      keyRequired={keyRequired}
      keySummary={keySummary}
      shareAllowed={shareAllowed}
      test={{
        line: test.line,
        testing: test.busy,
        cooldown: test.cooldown,
        onTest: () =>
          void test.run(
            {
              ...agentValues(form),
              ...(form.key.trim() === "" || form.shareKey ? {} : { key: form.key.trim() }),
            },
            form,
            timeoutMsOf("agent", form),
          ),
        onCancelTest: test.cancel,
        blocked: agentTestable(form, saved.shareKey) ? null : MODEL_TEXT.testNeedsSaveOrKey,
      }}
      footnote={MODEL_TEXT.testFootAgent}
      canSave={valid}
      onCancel={closeEdit}
      onSave={() => setSaveOpen(true)}
    />
  ) : agent.configured ? (
    <>
      <Kv
        items={[
          [MODEL_TEXT.rowProvider, MODEL_PROVIDER_LABEL[agent.provider]],
          [MODEL_TEXT.rowEndpoint, mono(agent.endpoint)],
          [MODEL_TEXT.rowModel, mono(agent.model ?? "—")],
          [MODEL_TEXT.rowKey, keySummary],
          [MODEL_TEXT.rowTimeout, MODEL_TEXT.timeoutAgent(Math.round(agent.timeout_ms / 1000))],
          [MODEL_TEXT.rowSource, sourceText],
        ]}
      />
      <div className="sys-actions">
        <button type="button" className="linkbtn" onClick={() => setHistoryOpen((open) => !open)}>
          {MODEL_TEXT.btnHistory}
        </button>
        <button
          type="button"
          className="btn"
          disabled={test.busy || test.cooldown > 0}
          onClick={() => void test.run(agentValues(saved), saved, timeoutMsOf("agent", saved))}
        >
          {testLabel(test.busy, test.cooldown)}
        </button>
        <button type="button" className="btn btn-primary" onClick={() => openEdit()}>
          {MODEL_TEXT.btnEdit}
        </button>
      </div>
      {test.line === null ? null : <ModelTestResult line={test.line} />}
      {historyOpen ? <ModelHistory kind="agent" onRestore={restore} /> : null}
    </>
  ) : (
    <>
      <p className="sys-lead">{MODEL_TEXT.agentLead}</p>
      <p className="muted small">{MODEL_TEXT.agentOff}</p>
      <div className="sys-actions">
        <button type="button" className="btn btn-primary" onClick={() => openEdit()}>
          {MODEL_TEXT.btnConfigure}
        </button>
      </div>
    </>
  );

  return (
    <Card className="sys-model" title={MODEL_TEXT.agentTitle} aside={<StatusLabel line={status} />}>
      {body}
      {saveOpen ? (
        <ModelSaveDialog
          title={MODEL_TEXT.saveTitle(MODEL_TEXT.agentTitle, agent.version + 1)}
          defaultNote={restored === null ? "" : MODEL_TEXT.restoreNote(restored)}
          changes={changes}
          impact={impact}
          failClosed={[]}
          tested={tested}
          testedLine={
            test.passed === null || !tested ? null : MODEL_TEXT.testedOk(clockText(test.passed.at))
          }
          saving={save.isPending}
          conflict={conflict}
          error={saveError}
          saveLabel={MODEL_TEXT.btnSaveVersion(agent.version + 1)}
          onSave={submit}
          onClose={() => setSaveOpen(false)}
          onReload={() => void reload()}
        />
      ) : null}
    </Card>
  );
}
