// Interface names (docs/console-design-objects-routes.md 4): where a request's name came from, the words
// for it in the lists, the detail and the explanation, and which trace values carry a name. Pure
// functions over the record; the words themselves live in vocab.ts.

import type { ApiInfo, ApiName, ApiUnknown, TraceSource, TraceValue } from "../api/types.ts";
import { API_LABEL, API_SOURCE_LABEL, UNKNOWN_API_REASON } from "./vocab.ts";

type SourceKind = keyof typeof API_SOURCE_LABEL;

function isSourceKind(value: string): value is SourceKind {
  return Object.hasOwn(API_SOURCE_LABEL, value);
}

/** A rule's source such as `header.X-Service-Id`, split into its kind and the name it reads. */
function parseSource(source: string): { kind: SourceKind | null; name: string } {
  const dot = source.indexOf(".");
  const head = dot < 0 ? source : source.slice(0, dot);
  const name = dot < 0 ? "" : source.slice(dot + 1);
  return isSourceKind(head) ? { kind: head, name } : { kind: null, name: source };
}

/** The label of a source: 请求头, 查询参数, 正文字段 or URL 路径. An unknown kind reads as it is written. */
function labelOf(source: string): string {
  const { kind } = parseSource(source);
  return kind === null ? source : API_SOURCE_LABEL[kind];
}

/** The name a source reads, for a reason: `header.X-Service-Method` reads X-Service-Method. */
function sourceName(source: string | undefined): string {
  if (source === undefined) return "接口名所在位置";
  const { kind, name } = parseSource(source);
  if (kind === null) return source;
  return name.length > 0 ? name : API_SOURCE_LABEL[kind];
}

/** The sources a name came from, by label, without repeats: 请求头、URL 路径. */
export function apiFromWords(api: ApiName): string {
  return [...new Set(api.from.map(labelOf))].join("、");
}

/** The hover of a name: each source with the names it reads, e.g. 接口名来自请求头 X-Service-Id、X-Service-Method. */
export function apiTitle(api: ApiName): string {
  const groups = new Map<string, string[]>();
  for (const source of api.from) {
    const { name } = parseSource(source);
    const label = labelOf(source);
    const names = groups.get(label) ?? [];
    if (name.length > 0) names.push(name);
    groups.set(label, names);
  }
  const words = [...groups].map(([label, names]) =>
    names.length > 0 ? `${label} ${names.join("、")}` : label,
  );
  return `接口名来自${words.join("；")}`;
}

/** The reason a name could not be read, as words. A code this console does not know reads 未知原因 with the code. */
export function unknownReasonText(code: string, source?: string): string {
  if (!Object.hasOwn(UNKNOWN_API_REASON, code)) return `未知原因（${code}）`;
  const info = UNKNOWN_API_REASON[code as keyof typeof UNKNOWN_API_REASON];
  return info.text.replace("{src}", sourceName(source));
}

/** The reason's hover text; the same words for an unknown code, which has none. */
export function unknownReasonDesc(code: string): string {
  if (!Object.hasOwn(UNKNOWN_API_REASON, code)) return "这个原因的说明还没有收录";
  return UNKNOWN_API_REASON[code as keyof typeof UNKNOWN_API_REASON].desc;
}

/** The unknown-interface line of the list, the detail and the explanation (design 4.2). */
export function unknownTitle(api: ApiUnknown): string {
  return `${API_LABEL.unknown}：${unknownReasonText(api.unknown, api.source)}，按${API_LABEL.unknown}处理（不算入口、不走绕过）`;
}

/** The trace locations that carry a name: a query parameter or a body field read as a name segment. */
export function apiValueLocations(api: ApiInfo | null | undefined): string[] {
  if (api === null || api === undefined || !("from" in api)) return [];
  return api.from.filter((source) => {
    const { kind } = parseSource(source);
    return kind === "query" || kind === "body";
  });
}

/** Whether a trace value is the name itself (or a part of a composite name) rather than a value to check. */
export function isNameValue(value: TraceValue, locations: readonly string[]): boolean {
  return locations.some((location) => value.at === location || value.at.startsWith(`${location}#`));
}

/**
 * The note for the classes the object map gave the checked values, e.g. （按对象表：医生、患者）; empty
 * when no checked value was matched by the map, so names inferred from fields add nothing.
 */
export function byMapNote(checked: TraceValue[]): string {
  const classes: string[] = [];
  for (const value of checked) {
    if (value.object_from !== "map" || value.object === undefined) continue;
    if (!classes.includes(value.object)) classes.push(value.object);
  }
  return classes.length > 0 ? `（按${API_LABEL.objectMap}：${classes.join("、")}）` : "";
}

/**
 * The origin showed the value as another class than the position it is used at (design 4.2): both
 * classes are known and they differ. `current` is the class of the position (the value's `object`).
 */
export function classMismatch(current: string | null | undefined, source: TraceSource): boolean {
  return current != null && source.object !== undefined && current !== source.object;
}
