// Pure helpers of the object map tab (console design 3): how a position's key reads as method, path and field,
// what a declaration, a cold start selection or a migrated synonym group turns into in the configuration, which
// entry an automatic change or a pause put there and how undoing it puts the old one back, and which words the path
// warnings name. No React and no requests, so the unit tests load it under plain node.

import type {
  Advanced,
  BootstrapCandidate,
  FieldKindDeclaration,
  ObjectClass,
  ObjectClassEntry,
  ObjectConfigEntry,
  ObjectEvent,
  ObjectFlow,
  ObjectSlotEntry,
  ObjectSlotRow,
  ObjectSource,
  ObjectsSpec,
  SiteSpec,
} from "../../../api/types.ts";
import { declarationKey, fieldKey, kindKey } from "../../../lib/objects-validate.ts";

/** The name a candidate goes by: its class's name, or its kind while the map has no class for it yet. */
export function candidateName(candidate: BootstrapCandidate): string {
  return candidate.name ?? candidate.kind;
}

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

/** The object slot a position gets when its class is confirmed (console design 4.3). */
export function slotEntryFor(
  slot: Pick<ObjectSlotRow, "key">,
  cls: string,
  source: ObjectSource,
): ObjectSlotEntry {
  return { key: slot.key, class: cls, source };
}

/** The declaration a position gets when the user confirms its proposed class; null when no field names it. */
export function declarationFor(slot: ObjectSlotRow): FieldKindDeclaration | null {
  const field = fieldOfKey(slot.key);
  if (field === null || slot.class === null) return null;
  return { field, kind: slot.class, in: [scopeOfKey(slot.key)] };
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

/** The configuration's `objects` section with the lists replaced; an empty list is left out, as the file would. */
function withObjectLists(
  spec: SiteSpec,
  classes: readonly ObjectClassEntry[],
  slots: readonly ObjectSlotEntry[],
): SiteSpec {
  const objects: ObjectsSpec = { ...spec.objects };
  if (classes.length > 0) objects.classes = [...classes];
  else delete objects.classes;
  if (slots.length > 0) objects.slots = [...slots];
  else delete objects.slots;
  const empty = Object.keys(objects).length === 0;
  return { ...spec, objects: empty ? undefined : objects };
}

/** The configuration with these classes added to the object map; a class already there is not repeated. */
export function withClasses(spec: SiteSpec, list: readonly ObjectClassEntry[]): SiteSpec {
  const current = spec.objects?.classes ?? [];
  const ids = new Set(current.map((item) => item.id));
  const added = list.filter((item) => {
    if (ids.has(item.id)) return false;
    ids.add(item.id);
    return true;
  });
  return withObjectLists(spec, [...current, ...added], spec.objects?.slots ?? []);
}

/** The configuration with one confirmed position put in place: it replaces the slot of its key (dropping a pause),
 *  or is added. A declaration goes to the field kinds instead. */
export function withSlot(spec: SiteSpec, entry: ObjectSlotEntry): SiteSpec {
  const current = spec.objects?.slots ?? [];
  const without = current.filter((item) => item.key !== entry.key);
  const { paused: _paused, ...plain } = entry;
  return withObjectLists(spec, spec.objects?.classes ?? [], [...without, plain]);
}

/** The configuration without the confirmed position of this key. */
export function withoutSlot(spec: SiteSpec, key: string): SiteSpec {
  const current = spec.objects?.slots ?? [];
  return withObjectLists(
    spec,
    spec.objects?.classes ?? [],
    current.filter((item) => item.key !== key),
  );
}

/** The configuration without this field declaration (the one with the same field, scope and class). */
export function withoutDeclaration(spec: SiteSpec, item: FieldKindDeclaration): SiteSpec {
  const id = declarationKey(item);
  const current = spec.advanced?.field_kinds ?? [];
  const next = current.filter((other) => declarationKey(other) !== id);
  if (next.length === current.length) return spec;
  const advanced: Advanced = { ...spec.advanced, field_kinds: next.length > 0 ? next : undefined };
  return { ...spec, advanced };
}

/** A configuration entry put in place: a declaration is added (once), a slot replaces the slot of its key. */
export function withEntry(spec: SiteSpec, entry: ObjectConfigEntry): SiteSpec {
  return isDeclaration(entry) ? withDeclarations(spec, [entry]) : withSlot(spec, entry);
}

/** A configuration entry taken out: a declaration by its place and class, a slot by its key. */
export function withoutEntry(spec: SiteSpec, entry: ObjectConfigEntry): SiteSpec {
  return isDeclaration(entry) ? withoutDeclaration(spec, entry) : withoutSlot(spec, entry.key);
}

export function isDeclaration(entry: ObjectConfigEntry): entry is FieldKindDeclaration {
  return "field" in entry;
}

/**
 * The draft with an automatic change undone (console design 2.4): the entry the change wrote is taken out and the one
 * from before it comes back. For a pause the entry from before the pause comes back, without its pause. Null when the
 * event holds nothing to put back (an anomaly changes nothing).
 */
export function revertEvent(spec: SiteSpec, event: ObjectEvent): SiteSpec | null {
  if (event.kind === "anomaly") return null;
  const before = event.before?.entry ?? null;
  if (event.kind === "auto_tighten") {
    const after = event.after?.entry ?? null;
    let next = after === null ? spec : withoutEntry(spec, after);
    if (before !== null) next = withEntry(next, before);
    return next;
  }
  if (before === null) return null;
  return withEntry(spec, before);
}

/** The position's entries in a configuration, as text: the declarations that name its field and the slot of its key. */
export function entriesOf(spec: SiteSpec, key: string): string[] {
  const field = fieldOfKey(key);
  const declared = (spec.advanced?.field_kinds ?? [])
    .filter((item) => field !== null && fieldKey(item.field) === fieldKey(field))
    .map((item) => JSON.stringify(item));
  const slots = (spec.objects?.slots ?? [])
    .filter((item) => item.key === key)
    .map((item) => JSON.stringify(item));
  return [...declared, ...slots];
}

/** Whether the draft changes the entries of this position compared with the saved configuration. */
export function draftTouches(saved: SiteSpec, working: SiteSpec, key: string): boolean {
  return entriesOf(saved, key).join("|") !== entriesOf(working, key).join("|");
}

/** What a confirmation in the object map carries into the save dialog: the note it opens with, and the automatic change
 *  it undoes or re-confirms. */
export type ApplyOptions = { note?: string; objectEvent?: string };

/** One chosen candidate of a cold start: the class it is written as, and the name it carries. */
export type BootstrapChoice = {
  candidate: BootstrapCandidate;
  kind: string;
  name: string;
  /** Whether the user changed the proposed class (the entry is then written as `admin`). */
  changed: boolean;
};

/** What the cold start writes: an object slot per chosen position, and the classes they need that the map lacks. */
export type BootstrapPlan = {
  slots: ObjectSlotEntry[];
  classes: ObjectClassEntry[];
};

/**
 * The entries a cold start selection writes (console design 1.6): every position becomes an object slot under its key,
 * and a class that neither the map nor the site has yet is added with its name. Field declarations are not written here;
 * they stay the hand-made tool of the advanced section.
 */
export function planBootstrap(
  choices: readonly BootstrapChoice[],
  known: readonly ObjectClass[],
  existing: ObjectsSpec | undefined,
): BootstrapPlan {
  const slots: ObjectSlotEntry[] = [];
  const classes: ObjectClassEntry[] = [];
  const seenSlots = new Set<string>();
  const haveClass = new Set([
    ...(existing?.classes ?? []).map((item) => item.id),
    ...known.map((item) => item.id),
  ]);
  for (const choice of choices) {
    const { candidate, kind, name } = choice;
    if (!seenSlots.has(candidate.key)) {
      seenSlots.add(candidate.key);
      slots.push(slotEntryFor(candidate, kind, choice.changed ? "admin" : "rule"));
    }
    if (!haveClass.has(kind)) {
      haveClass.add(kind);
      classes.push({ id: kind, name });
    }
  }
  return { slots, classes };
}

/** The configuration with a cold start plan written in: the classes they need, then the slots. */
export function withPlan(spec: SiteSpec, plan: BootstrapPlan): SiteSpec {
  let next = withClasses(spec, plan.classes);
  for (const slot of plan.slots) next = withSlot(next, slot);
  return next;
}

/** The learning state of each position, as the events it has in the banner: pauses and anomalies apart, and the
 *  tightenings of one learning pass together. */
export function bannerGroups(events: readonly ObjectEvent[]): {
  paused: ObjectEvent[];
  anomaly: ObjectEvent[];
  tightened: Array<{ at: string; events: ObjectEvent[] }>;
} {
  const paused: ObjectEvent[] = [];
  const anomaly: ObjectEvent[] = [];
  const passes = new Map<string, ObjectEvent[]>();
  for (const event of events) {
    if (event.kind === "auto_pause") paused.push(event);
    else if (event.kind === "anomaly") anomaly.push(event);
    else passes.set(event.at, [...(passes.get(event.at) ?? []), event]);
  }
  const tightened = [...passes.entries()].map(([at, list]) => ({ at, events: list }));
  return { paused, anomaly, tightened };
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

/** The configuration with these declarations and the synonyms they replace (console design 3.4). The input is not changed. */
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
