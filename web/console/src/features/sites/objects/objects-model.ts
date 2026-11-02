// Pure helpers of the object map tab (console design 3): how a position's key reads as method, path and field,
// what a declaration, a cold start candidate or a migrated synonym group turns into in the configuration, and
// which words the path warnings name. No React and no requests, so the unit tests load it under plain node.

import type {
  Advanced,
  BootstrapCandidate,
  FieldKindDeclaration,
  ObjectClass,
  ObjectFlow,
  ObjectSlotRow,
  SiteSpec,
} from "../../../api/types.ts";
import { declarationKey, kindKey } from "../../../lib/objects-validate.ts";

export type KeyParts = { method: string; path: string; where: string };

/** A position key, e.g. `GET /api/appointments [].doc_id`, read into its method, path and the rest of the position. */
export function keyParts(key: string): KeyParts {
  const [method = "", path = "", ...rest] = key.split(" ");
  return { method, path, where: rest.join(" ") };
}

/** The field a position reads, e.g. `doc_id` for `[].doc_id` and `doc` for `query.doc`; null for a path
 *  position (`path[1]`) or a composite part (`who#2`), which no field declaration can name. */
export function fieldOfKey(key: string): string | null {
  const { where } = keyParts(key);
  if (where.length === 0 || where.startsWith("path[")) return null;
  const last = where.replace(/\[\]/g, "").split(".").pop() ?? "";
  if (last.length === 0 || /[[\]#]/.test(last)) return null;
  return last;
}

/** The interfaces a declaration is limited to by default: the position's path, and the paths under it when it
 *  has a `{id}` (`/api/records/{id}` gives `/api/records/*`). Written like an entry, with a trailing `*`. */
export function scopeOfKey(key: string): string {
  const { path } = keyParts(key);
  const cut = path.indexOf("{");
  return `${cut < 0 ? path : path.slice(0, cut)}*`;
}

/** The route template of a flow as a path filter: `/doctor/{id}/files` becomes `/doctor/*`. */
export function routeFilter(route: string): string {
  const cut = route.indexOf("{");
  return cut < 0 ? route : `${route.slice(0, cut)}*`;
}

/** The request list's condition for a flow: the class, when known, and the route it runs on. */
export function flowSearch(flow: ObjectFlow, cls: string | null): string {
  const terms = [cls === null ? null : `object:${cls}`, `path:${routeFilter(flow.route)}`];
  return terms.filter((term): term is string => term !== null).join(" ");
}

/** The declaration a position gets when the user confirms its proposed class; null when no field names it. */
export function declarationFor(slot: ObjectSlotRow): FieldKindDeclaration | null {
  const field = fieldOfKey(slot.key);
  if (field === null || slot.class === null) return null;
  return { field, kind: slot.class, in: [scopeOfKey(slot.key)] };
}

/** The declarations of a cold start candidate: one per named position, limited to its interface. */
export function candidateDeclarations(candidate: BootstrapCandidate): FieldKindDeclaration[] {
  const out: FieldKindDeclaration[] = [];
  const seen = new Set<string>();
  for (const key of candidate.slots) {
    const field = fieldOfKey(key);
    if (field === null) continue;
    const declaration: FieldKindDeclaration = {
      field,
      kind: candidate.kind,
      in: [scopeOfKey(key)],
    };
    const id = declarationKey(declaration);
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(declaration);
  }
  return out;
}

/** The configuration with these declarations added to its field kinds; ones already present are not repeated. */
export function withDeclarations(spec: SiteSpec, list: readonly FieldKindDeclaration[]): SiteSpec {
  const current = spec.advanced?.field_kinds ?? [];
  const keys = new Set(current.map(declarationKey));
  const added = list.filter((item) => {
    const id = declarationKey(item);
    if (keys.has(id)) return false;
    keys.add(id);
    return true;
  });
  return { ...spec, advanced: { ...spec.advanced, field_kinds: [...current, ...added] } };
}

/** The configuration with its learning settings replaced. */
export function withLearning(
  spec: SiteSpec,
  learning: NonNullable<SiteSpec["objects"]>["learning"],
): SiteSpec {
  return { ...spec, objects: { ...spec.objects, learning } };
}

/**
 * A synonym migration: the groups are removed from the site's synonyms and the declarations they became are added
 * to the field kinds (console design 3.4). The input is not changed.
 */
export function migrateSynonyms(
  spec: SiteSpec,
  removed: ReadonlyArray<readonly [string, string]>,
  declarations: readonly FieldKindDeclaration[],
): SiteSpec {
  const kept = (spec.advanced?.synonyms ?? []).filter(
    ([a, b]) => !removed.some(([x, y]) => x === a && y === b),
  );
  const advanced: Advanced = { ...(spec.advanced ?? {}) };
  advanced.synonyms = kept.length > 0 ? kept : undefined;
  const next: SiteSpec = { ...spec, advanced };
  return withDeclarations(next, declarations);
}

/** The path segments that one of two synonym words also names, as warnings: `会让路径里的 docs 也算成 doctor`. */
export function pathWordWarnings(
  spec: SiteSpec,
  pair: readonly [string, string],
  sentence: (word: string, other: string) => string,
): string[] {
  const paths = [
    ...spec.entries,
    ...(spec.bypass ?? []),
    ...(spec.routes ?? []).map((rule) => rule.path),
  ];
  const segments = new Set<string>();
  for (const path of paths) {
    for (const segment of path.split("/")) {
      if (segment.length === 0 || segment.includes("{") || segment.includes("*")) continue;
      segments.add(segment.toLowerCase());
    }
  }
  const [a, b] = pair;
  const out: string[] = [];
  for (const segment of [...segments].sort()) {
    if (kindKey(segment) === kindKey(a)) out.push(sentence(segment, b));
    else if (kindKey(segment) === kindKey(b)) out.push(sentence(segment, a));
  }
  return out;
}

/** The positions of a slot list that belong to one class (the class card's table). */
export function slotsOfClass(slots: readonly ObjectSlotRow[], cls: string): ObjectSlotRow[] {
  return slots.filter((slot) => slot.class === cls);
}

/** A class's name, or its id when the list does not hold it (a class the map has but the list dropped). */
export function classNameOf(classes: readonly ObjectClass[], id: string | null): string {
  if (id === null) return "—";
  return classes.find((item) => item.id === id)?.name ?? id;
}

const pad = (value: number) => String(value).padStart(2, "0");

/** The last appearance of a position: the clock on the same day, `MM-DD HH:mm` before that; `—` when never seen. */
export function seenText(iso: string | null, now: number): string {
  if (iso === null) return "—";
  const at = Date.parse(iso);
  if (Number.isNaN(at)) return "—";
  const date = new Date(at);
  const clock = `${pad(date.getHours())}:${pad(date.getMinutes())}`;
  if (date.toDateString() === new Date(now).toDateString()) return clock;
  return `${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${clock}`;
}

/** Whether a class's text, fields or routes match a search term (case-insensitive; empty matches all). */
export function classMatches(item: ObjectClass, term: string): boolean {
  const needle = term.trim().toLowerCase();
  if (needle.length === 0) return true;
  const haystack = [item.id, item.name, item.description, ...item.fields, ...item.routes];
  return haystack.some((text) => text.toLowerCase().includes(needle));
}
