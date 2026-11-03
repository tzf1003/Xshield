// The model forms of the system page (design agent-model-ui 2.2 to 2.5): what a form holds, the checks that run
// before a request goes out, the change list a save shows, and what a test result says. Pure functions, so the
// unit tests can pin them. A form holds what the person typed; the key is the one exception that is never read
// back from the server, and an empty key means "keep the saved one".

import type {
  AgentModelsState,
  AgentModelValues,
  AgentProvider,
  JevModelsState,
  JevModelValues,
  JevRoute,
  ModelChange,
  ModelKind,
  ModelTestResult,
  ModelValues,
  ModelWireConfig,
} from "../api/types.ts";
import {
  MODEL_FAILURE_TEXT,
  MODEL_FIELD_LABEL,
  MODEL_PROVIDER_LABEL,
  MODEL_ROUTE_LABEL,
  MODEL_TEXT,
} from "./vocab.ts";

/** The model of every Jev line that has a preset (design 2.2). */
export const JEV_MODEL = "typesafe-ai/jev";
export const JEV_TIMEOUT = { min: 100, max: 30_000, fallback: 2_000 } as const;
/** Seconds in the form, milliseconds on the wire. */
export const AGENT_TIMEOUT = { min: 5, max: 120, fallback: 30 } as const;
export const ENDPOINT_MAX = 2048;
export const MODEL_MAX = 200;
export const NOTE_MAX = 200;
export const AGENT_GATEWAY_ENDPOINT = "https://ai-gateway.vercel.sh/v1";

const JEV_PRESETS: Record<JevRoute, { endpoint: string | null; model: string | null }> = {
  gateway: { endpoint: "https://ai-gateway.vercel.sh/typesafe/v1/systemone", model: JEV_MODEL },
  direct: { endpoint: "https://api.typesafe.ai/v1/systemone", model: JEV_MODEL },
  custom: { endpoint: null, model: null },
};

export type FormChoice = JevRoute | AgentProvider;

export type ModelForm = {
  /** Jev: the line. Agent: the provider. */
  choice: FormChoice;
  endpoint: string;
  model: string;
  /** Milliseconds for Jev, seconds for the agent, as typed. */
  timeout: string;
  /** Agent only: use Jev's Vercel AI Gateway key. */
  shareKey: boolean;
  /** The key typed in this form. Empty keeps the saved key. */
  key: string;
};

export type ProblemKey = "endpoint" | "model" | "timeout" | "key";
export type FormProblems = Partial<Record<ProblemKey, string>>;

/** One line of the save dialog's change list. */
export type ChangeRow = { label: string; detail: string };

export type Tone = "ok" | "warn" | "bad";
export type TestLine = {
  tone: Tone;
  icon: string;
  text: string;
  hint?: string;
  detail: string | null;
};

// ------------------------------------------------------------------ forms from and to values

/** The Jev values of the state, with what the state leaves open filled the way a form needs it. */
function jevStateValues(jev: JevModelsState): JevModelValues {
  return {
    route: jev.route ?? "gateway",
    endpoint: jev.endpoint,
    model: jev.model,
    timeout_ms: jev.timeout_ms ?? JEV_TIMEOUT.fallback,
  };
}

export function jevForm(jev: JevModelsState): ModelForm {
  return formFromValues("jev", jevStateValues(jev));
}

export function agentForm(agent: AgentModelsState): ModelForm {
  return formFromValues("agent", agent);
}

/**
 * A form for the values of a configuration: the saved one, the environment's, or a restored version. A preset line
 * has no address of its own in the saved values, so the form takes the route's.
 */
export function formFromValues(kind: ModelKind, values: ModelValues): ModelForm {
  if (kind === "jev") {
    const jev = values as JevModelValues;
    return {
      choice: jev.route,
      endpoint: jev.endpoint ?? presetEndpoint(jev.route) ?? "",
      model: jev.model ?? presetModel(jev.route) ?? "",
      timeout: String(jev.timeout_ms),
      shareKey: false,
      key: "",
    };
  }
  const agent = values as AgentModelValues;
  return {
    choice: agent.provider,
    endpoint: agent.endpoint,
    model: agent.model ?? "",
    timeout: String(Math.round(agent.timeout_ms / 1000)),
    shareKey: agent.share_key_with_jev,
    key: "",
  };
}

/** The Jev values a save or a test sends (the key is added separately). */
export function jevValues(form: ModelForm): JevModelValues {
  return {
    route: form.choice as JevRoute,
    endpoint: form.endpoint.trim(),
    model: form.model.trim(),
    timeout_ms: Number(form.timeout.trim()),
  };
}

export function agentValues(form: ModelForm): AgentModelValues {
  return {
    provider: form.choice as AgentProvider,
    endpoint: form.endpoint.trim(),
    model: form.model.trim(),
    timeout_ms: Number(form.timeout.trim()) * 1000,
    share_key_with_jev: form.shareKey,
  };
}

/**
 * Switching the line or the provider puts that line's own address and model in (design 2.2). A custom line keeps
 * what is there, because it is the person's to type.
 */
export function withChoice(kind: ModelKind, form: ModelForm, choice: FormChoice): ModelForm {
  if (kind === "jev") {
    const preset = JEV_PRESETS[choice as JevRoute];
    return {
      ...form,
      choice,
      endpoint: preset.endpoint ?? form.endpoint,
      model: preset.model ?? form.model,
    };
  }
  const gateway = choice === "gateway";
  return {
    ...form,
    choice,
    endpoint: gateway ? AGENT_GATEWAY_ENDPOINT : form.endpoint,
    shareKey: gateway ? form.shareKey : false,
  };
}

/**
 * A saved version's settings as the API sends them: the JSON the history stored, so a timeout is a number and a share
 * flag a boolean. This reads them back into the form's types, so a restored version keeps its timeout, its share flag
 * and its blanks as they were.
 */
export function modelValuesFromWire(kind: ModelKind, config: ModelWireConfig): ModelValues {
  const text = (field: string): string | null => {
    const value = config[field];
    return typeof value === "string" && value !== "" ? value : null;
  };
  const timeout = typeof config.timeout_ms === "number" ? config.timeout_ms : Number.NaN;
  if (kind === "jev") {
    const routes: readonly JevRoute[] = ["gateway", "direct", "custom"];
    return {
      route: routes.find((route) => route === config.route) ?? "gateway",
      endpoint: text("endpoint"),
      model: text("model"),
      timeout_ms: Number.isFinite(timeout) ? timeout : JEV_TIMEOUT.fallback,
    };
  }
  return {
    provider: config.provider === "custom" ? "custom" : "gateway",
    endpoint: text("endpoint") ?? "",
    model: text("model"),
    timeout_ms: Number.isFinite(timeout) ? timeout : AGENT_TIMEOUT.fallback * 1000,
    share_key_with_jev: config.share_key_with_jev === true,
  };
}

/** The address a line starts with, or null when the line has no preset (custom). */
export function presetEndpoint(choice: JevRoute): string | null {
  return JEV_PRESETS[choice].endpoint;
}

/** The model a line starts with, or null when the line has no preset (custom). */
export function presetModel(choice: JevRoute): string | null {
  return JEV_PRESETS[choice].model;
}

// ------------------------------------------------------------------ checks before a request

const LOOPBACK = new Set(["127.0.0.1", "::1", "[::1]", "localhost"]);
const MODEL_CHARS = /^[A-Za-z0-9._:/@-]+$/;

/** A problem with an address, or null. Only the check; the server checks again. */
export function endpointProblem(raw: string): string | null {
  const value = raw.trim();
  if (value.length === 0) return MODEL_TEXT.endpointRequired;
  if (value.length > ENDPOINT_MAX) return MODEL_TEXT.endpointLong;
  if (value.includes("?") || value.includes("#")) return MODEL_TEXT.endpointQuery;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return MODEL_TEXT.endpointUrl;
  }
  const loopback = LOOPBACK.has(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    return MODEL_TEXT.endpointScheme;
  }
  if (url.username !== "" || url.password !== "") return MODEL_TEXT.endpointCredentials;
  return null;
}

export function modelProblem(raw: string): string | null {
  const value = raw.trim();
  if (value.length === 0) return MODEL_TEXT.modelRequired;
  if (value.length > MODEL_MAX) return MODEL_TEXT.modelLong;
  if (!MODEL_CHARS.test(value)) return MODEL_TEXT.modelChars;
  return null;
}

export function timeoutProblem(
  raw: string,
  range: { min: number; max: number },
  unit: string,
): string | null {
  const value = raw.trim();
  if (!/^\d+$/.test(value)) return MODEL_TEXT.timeoutRange(range.min, range.max, unit);
  const n = Number(value);
  if (n < range.min || n > range.max) return MODEL_TEXT.timeoutRange(range.min, range.max, unit);
  return null;
}

/** A typed key: no blanks inside it, and present when the form needs one (a first save from the environment). */
export function keyProblem(raw: string, required: boolean): string | null {
  const value = raw.trim();
  if (value.length === 0) return required ? MODEL_TEXT.keyRequired : null;
  if (/\s/.test(value)) return MODEL_TEXT.keyWhitespace;
  return null;
}

function problems(entries: Array<[ProblemKey, string | null]>): FormProblems {
  const out: FormProblems = {};
  for (const [key, text] of entries) {
    if (text !== null) out[key] = text;
  }
  return out;
}

export function jevProblems(form: ModelForm, keyRequired: boolean): FormProblems {
  return problems([
    ["endpoint", endpointProblem(form.endpoint)],
    ["model", modelProblem(form.model)],
    ["timeout", timeoutProblem(form.timeout, JEV_TIMEOUT, MODEL_TEXT.unitMs)],
    ["key", keyProblem(form.key, keyRequired)],
  ]);
}

/**
 * Whether the agent form needs a key typed in. A form that shares Jev's key needs none. A form that stops sharing
 * needs one: sharing cleared the agent's own key, so a save without one would leave the agent with no key at all.
 */
export function agentKeyRequired(
  shareKey: boolean,
  key: Pick<AgentModelsState["key"], "set" | "shared_with_jev">,
): boolean {
  if (shareKey) return false;
  return !key.set || key.shared_with_jev;
}

/**
 * Whether the agent form can be tested as it stands. A test without a typed key uses the saved key, which is Jev's only
 * while the saved agent shares it. So a form that changes the sharing is tested with a key typed in (when it stops
 * sharing), or after a save (when it starts sharing).
 */
export function agentTestable(form: ModelForm, savedShare: boolean): boolean {
  if (form.shareKey === savedShare) return true;
  return !form.shareKey && form.key.trim() !== "";
}

export function agentProblems(form: ModelForm, keyRequired: boolean): FormProblems {
  return problems([
    ["endpoint", endpointProblem(form.endpoint)],
    ["model", modelProblem(form.model)],
    ["timeout", timeoutProblem(form.timeout, AGENT_TIMEOUT, MODEL_TEXT.unitSeconds)],
    ["key", keyProblem(form.key, keyRequired)],
  ]);
}

// ------------------------------------------------------------------ comparison and changes

/** Whether two forms hold the same configuration, key included: a test is only good for the values it tried. */
export function sameForm(a: ModelForm, b: ModelForm): boolean {
  return (
    a.choice === b.choice &&
    a.endpoint.trim() === b.endpoint.trim() &&
    a.model.trim() === b.model.trim() &&
    a.timeout.trim() === b.timeout.trim() &&
    a.shareKey === b.shareKey &&
    a.key.trim() === b.key.trim()
  );
}

function choiceText(kind: ModelKind, choice: FormChoice): string {
  if (kind === "jev") return MODEL_ROUTE_LABEL[choice as JevRoute];
  return MODEL_PROVIDER_LABEL[choice as AgentProvider];
}

function timeText(kind: ModelKind, timeout: string): string {
  const value = timeout.trim();
  return kind === "jev" ? `${value} ms` : `${value} 秒`;
}

/**
 * The change list of a save: each field that differs from the saved form, and the key as “replaced” with its last
 * four characters, never the key itself. `restoring` also says the key stays as it is.
 */
export function formChanges(
  kind: ModelKind,
  saved: ModelForm,
  next: ModelForm,
  savedKeyLast4: string | null,
  restoring = false,
): ChangeRow[] {
  const rows: ChangeRow[] = [];
  if (saved.choice !== next.choice) {
    rows.push({
      label: kind === "jev" ? MODEL_TEXT.rowRoute : MODEL_TEXT.rowProvider,
      detail: `${choiceText(kind, saved.choice)} → ${choiceText(kind, next.choice)}`,
    });
  }
  if (saved.endpoint.trim() !== next.endpoint.trim()) {
    rows.push({
      label: MODEL_TEXT.rowEndpoint,
      detail: `${saved.endpoint.trim()} → ${next.endpoint.trim()}`,
    });
  }
  if (saved.model.trim() !== next.model.trim()) {
    rows.push({
      label: MODEL_TEXT.rowModel,
      detail: `${saved.model.trim()} → ${next.model.trim()}`,
    });
  }
  if (saved.timeout.trim() !== next.timeout.trim()) {
    rows.push({
      label: MODEL_TEXT.rowTimeout,
      detail: `${timeText(kind, saved.timeout)} → ${timeText(kind, next.timeout)}`,
    });
  }
  if (kind === "agent" && saved.shareKey !== next.shareKey) {
    rows.push({
      label: MODEL_TEXT.shareKeyLabel,
      detail: `${next.shareKey ? MODEL_TEXT.changeYes : MODEL_TEXT.changeNo}`,
    });
  }
  const typed = next.key.trim();
  if (typed.length > 0) {
    rows.push({
      label: MODEL_TEXT.rowKey,
      detail: MODEL_TEXT.keyReplaced(savedKeyLast4, typed.slice(-4)),
    });
  } else if (restoring) {
    rows.push({ label: MODEL_TEXT.rowKey, detail: MODEL_TEXT.keyKept(savedKeyLast4) });
  }
  return rows;
}

// ------------------------------------------------------------------ test results

/** `11:02:31` from an RFC 3339 time, in local time. */
export function clockText(iso: string): string {
  const at = new Date(iso);
  if (Number.isNaN(at.getTime())) return "—";
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${pad(at.getHours())}:${pad(at.getMinutes())}:${pad(at.getSeconds())}`;
}

/** What a failed test says, in one line (design 2.4). */
export function testFailureText(
  status: number | null,
  failure: string | null,
  timeoutMs: number,
): string {
  if (status === 401) return MODEL_TEXT.testFailUnauthorized;
  if (status === 451) return MODEL_TEXT.testFailRegion;
  if (status === 429 || failure === "JEV_RATE_LIMITED") return MODEL_TEXT.testFailRate;
  if (failure === "JEV_TIMEOUT") {
    return MODEL_TEXT.testFailTimeout(timeoutMs.toLocaleString("en-US"));
  }
  if (failure === "dns") return MODEL_TEXT.testFailDns;
  if (failure === "tls") return MODEL_TEXT.testFailTls;
  if (failure === "JEV_TRANSPORT") return MODEL_TEXT.testFailTransport;
  const name = failure === null ? MODEL_TEXT.testUnknown : (MODEL_FAILURE_TEXT[failure] ?? failure);
  return MODEL_TEXT.testFailOther(status, name);
}

/** The line a test shows under its form: success, an answer that does not parse, or a failure. */
/** `at` is when the answer arrived, in RFC 3339: the server keeps no time for a test. */
export function describeTest(
  kind: ModelKind,
  result: ModelTestResult,
  timeoutMs: number,
  at: string,
): TestLine {
  if (result.ok) {
    const latency = `${result.latency_ms.toLocaleString("en-US")} ms`;
    return {
      tone: "ok",
      icon: "✓",
      text: `${clockText(at)} ${MODEL_TEXT.testSucceeded} · ${latency} · ${MODEL_TEXT.testOkJev}`,
      detail: null,
    };
  }
  if (result.failure === "answer_invalid" || result.answer_valid === false) {
    const reason = result.answer_reason ? `：${result.answer_reason}` : "";
    return {
      tone: "warn",
      icon: "!",
      text: `${MODEL_TEXT.testAnswerInvalid}${reason}`,
      hint: kind === "jev" ? MODEL_TEXT.testWrongModelHint : MODEL_TEXT.testWrongAgentHint,
      detail: result.detail,
    };
  }
  return {
    tone: "bad",
    icon: "✕",
    text: testFailureText(result.status, result.failure, timeoutMs),
    detail: result.detail,
  };
}

/** The timeout a form would use, in milliseconds, for the failure line. */
export function timeoutMsOf(kind: ModelKind, form: ModelForm): number {
  const value = Number(form.timeout.trim());
  if (!Number.isFinite(value)) return 0;
  return kind === "jev" ? value : value * 1000;
}

// ------------------------------------------------------------------ history

/** A history value in words. The history keeps every value as text, so an empty field is `""`. */
function valueText(field: string, value: string, kind: ModelKind): string {
  if (value === "") return "—";
  if (field === "route") return MODEL_ROUTE_LABEL[value as JevRoute] ?? value;
  if (field === "provider") return MODEL_PROVIDER_LABEL[value as AgentProvider] ?? value;
  if (field === "share_key_with_jev") {
    return value === "true" ? MODEL_TEXT.changeYes : MODEL_TEXT.changeNo;
  }
  if (field === "timeout_ms") {
    const millis = Number(value);
    return kind === "jev" ? `${millis} ms` : `${Math.round(millis / 1000)} 秒`;
  }
  return value;
}

/** One change of a saved version in words: the field, then its old and new values. The key shows its last four. */
export function changeText(change: ModelChange, kind: ModelKind): string {
  if (change.field === "key") {
    const before = change.old === "" ? null : change.old;
    return change.new === ""
      ? MODEL_TEXT.keyCleared(before)
      : MODEL_TEXT.keyReplaced(before, change.new);
  }
  const label = MODEL_FIELD_LABEL[change.field] ?? change.field;
  return `${label} ${valueText(change.field, change.old, kind)} → ${valueText(change.field, change.new, kind)}`;
}
