// Site configuration as YAML or JSON (docs/06 6.4.9). YAML is only an editing format: what is saved
// is the JSON object, and comments are not kept.

import { parseDocument, stringify } from "yaml";
import type {
  Advanced,
  FieldKindDeclaration,
  LearningSettings,
  ObjectFunctionEntry,
  ObjectsSpec,
  SiteSpec,
} from "../api/types.ts";
import { DEFAULT_LEARNING } from "./objects-validate.ts";
import { shapeIssues } from "./site-validate.ts";

const TOP_KEYS = [
  "name",
  "hosts",
  "origin",
  "session",
  "routes",
  "entries",
  "bypass",
  "mode",
  "on_jev_unavailable",
  "advanced",
  "objects",
] as const;

const ADVANCED_KEYS = [
  "jev_timeout_ms",
  "session_calls_per_minute",
  "address_calls_per_minute",
  "allow_cache_minutes",
  "secret_fields",
  "synonyms",
  "field_kinds",
] as const;

/** Keys in the order a person reads them, with empty optional parts left out. */
export function orderSpec(spec: SiteSpec): SiteSpec {
  const out: Record<string, unknown> = {};
  out.name = spec.name;
  out.hosts = spec.hosts;
  out.origin = spec.origin;
  out.session = spec.session;
  if (spec.routes && spec.routes.length > 0) out.routes = spec.routes;
  out.entries = spec.entries;
  if (spec.bypass && spec.bypass.length > 0) out.bypass = spec.bypass;
  if (spec.mode) out.mode = spec.mode;
  if (spec.on_jev_unavailable) out.on_jev_unavailable = spec.on_jev_unavailable;
  if (spec.advanced) {
    const advanced: Record<string, unknown> = {};
    for (const key of ADVANCED_KEYS) {
      const value = spec.advanced[key];
      if (value === undefined) continue;
      if (Array.isArray(value) && value.length === 0) continue;
      advanced[key] =
        key === "field_kinds" ? orderDeclarations(value as FieldKindDeclaration[]) : value;
    }
    if (Object.keys(advanced).length > 0) out.advanced = advanced;
  }
  const objects = orderObjects(spec.objects);
  if (objects) out.objects = objects;
  return out as unknown as SiteSpec;
}

/** Declarations in the order a person reads them: field, kind, then the scope when there is one. */
function orderDeclarations(list: FieldKindDeclaration[]): unknown[] {
  return list.map((item) =>
    item.in === undefined
      ? { field: item.field, kind: item.kind }
      : { field: item.field, kind: item.kind, in: item.in },
  );
}

/**
 * The object map section in a fixed key order, so the same settings always compare equal. Learning settings at their
 * defaults are left out: the gateway refuses the key until it accepts learning settings, so a save that does not change
 * them must not carry it. The gateway's `classes` and `slots` are passed on exactly as they are. The function table is
 * written with its entries in a fixed key order, and is left out when it is empty, as the gateway leaves it out.
 */
function orderObjects(objects: ObjectsSpec | undefined): ObjectsSpec | undefined {
  if (!objects) return undefined;
  const out: ObjectsSpec = {};
  if (objects.learning) {
    const learning = orderLearning(objects.learning);
    if (JSON.stringify(learning) !== JSON.stringify(orderLearning(DEFAULT_LEARNING))) {
      out.learning = learning;
    }
  }
  if (objects.classes !== undefined) out.classes = objects.classes;
  if (objects.slots !== undefined) out.slots = objects.slots;
  if (objects.functions !== undefined && objects.functions.length > 0) {
    out.functions = objects.functions.map(orderFunction);
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

/** A function in a fixed key order: its key and source, then the tier and the reliability when they are set. */
function orderFunction(item: ObjectFunctionEntry): ObjectFunctionEntry {
  const out: ObjectFunctionEntry = { key: item.key, source: item.source };
  if (item.tier !== undefined) out.tier = item.tier;
  if (item.reliability !== undefined) out.reliability = item.reliability;
  return out;
}

function orderLearning(learning: LearningSettings): LearningSettings {
  return {
    auto_learn: learning.auto_learn,
    auto_tighten: learning.auto_tighten,
    agent: { enabled: learning.agent.enabled, daily_limit: learning.agent.daily_limit },
    thresholds: { uses: learning.thresholds.uses, sessions: learning.thresholds.sessions },
    auto_pause: learning.auto_pause,
  };
}

export function specToYaml(spec: SiteSpec): string {
  return stringify(orderSpec(spec), { lineWidth: 0 });
}

export function specToJson(spec: SiteSpec): string {
  return `${JSON.stringify(orderSpec(spec), null, 2)}\n`;
}

export type ParseResult =
  | { ok: true; value: SiteSpec }
  | { ok: false; line: number | null; message: string };

/** The line a key first appears on, found by its text; null when it cannot be located. */
function lineOfKey(text: string | null, key: string): number | null {
  if (text === null) return null;
  const lines = text.split("\n");
  const index = lines.findIndex((line) => new RegExp(`^\\s*(?:- )?${key}:`).test(line));
  return index >= 0 ? index + 1 : null;
}

/** Parses YAML or JSON text into a site configuration. Unknown fields are errors. */
export function parseSiteText(text: string): ParseResult {
  const trimmed = text.trim();
  if (trimmed.length === 0) return { ok: false, line: 1, message: "内容为空" };
  if (trimmed.startsWith("{")) {
    try {
      return checkObject(JSON.parse(trimmed) as unknown, null);
    } catch {
      return { ok: false, line: null, message: "JSON 格式不正确" };
    }
  }
  const doc = parseDocument(text);
  if (doc.errors.length > 0) {
    const line = doc.errors[0]?.linePos?.[0]?.line ?? null;
    return { ok: false, line, message: `YAML 第 ${line ?? "?"} 行有错误` };
  }
  return checkObject(doc.toJS() as unknown, text);
}

function unknownIn(
  object: Record<string, unknown>,
  allowed: readonly string[],
  text: string | null,
): { ok: false; line: number | null; message: string } | null {
  for (const key of Object.keys(object)) {
    if (!allowed.includes(key)) {
      const line = lineOfKey(text, key);
      const where = line === null ? "" : `（第 ${line} 行）`;
      return { ok: false, line, message: `未知字段 ${key}${where}` };
    }
  }
  return null;
}

function checkObject(value: unknown, text: string | null): ParseResult {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return { ok: false, line: null, message: "配置必须是一个对象" };
  }
  const object = value as Record<string, unknown>;
  const topProblem = unknownIn(object, TOP_KEYS, text);
  if (topProblem) return topProblem;
  const session = object.session;
  if (session !== undefined && session !== null && typeof session === "object") {
    const sessionProblem = unknownIn(
      session as Record<string, unknown>,
      ["cookie", "header"],
      text,
    );
    if (sessionProblem) return sessionProblem;
  }
  const advanced = object.advanced;
  if (advanced !== undefined && advanced !== null && typeof advanced === "object") {
    const advancedProblem = unknownIn(advanced as Record<string, unknown>, ADVANCED_KEYS, text);
    if (advancedProblem) return advancedProblem;
  }
  // Types last: each value is checked for its type before any rule judges it (docs/07 7.10.8).
  const [problem] = shapeIssues(value);
  if (problem) {
    const line = lineOfKey(text, problem.field);
    const where = line === null ? "" : `（第 ${line} 行）`;
    return { ok: false, line, message: `${problem.message}${where}` };
  }
  return { ok: true, value: dropEmptyParams(object) as unknown as SiteSpec };
}

/** A parameter written with no value means its default, so it is dropped rather than kept as null. */
function dropEmptyParams(object: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(object)) {
    if (key !== "advanced") out[key] = value;
    else if (value !== null && value !== undefined) {
      const advanced = Object.fromEntries(
        Object.entries(value as Record<string, unknown>).filter(([, item]) => item !== null),
      );
      if (Object.keys(advanced).length > 0) out.advanced = advanced;
    }
  }
  return out;
}

export function advancedOf(spec: SiteSpec): Advanced {
  return spec.advanced ?? {};
}
