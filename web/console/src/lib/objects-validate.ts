// Hand-declared field kinds and the learning settings of a site's object map (field-kinds design 3, console
// design 3.3 to 3.5): what a field name, a kind and a scope may be, when two declarations contradict each other,
// how a change reads in the save dialog, and what a configuration's `objects` section may hold. Pure functions:
// the declare dialog, the synonym migration, the cold start, the spec helpers and diff.ts all use them.

import type {
  FieldKindDeclaration,
  LearningSettings,
  ObjectClassEntry,
  ObjectSlotEntry,
  ObjectSource,
  ObjectsSpec,
} from "../api/types.ts";
import { judgementKey, judgementWords } from "./judgement.ts";
import { parsePattern } from "./patterns.ts";
import { DECLARE_TEXT, LEARNING_TEXT, OBJECT_KIND_LABEL } from "./vocab.ts";

export const FIELD_MAX = 32;
export const KIND_MIN = 3;
export const KIND_MAX = 24;
export const DECLARATIONS_MAX = 32;
export const SCOPE_MAX = 8;
/** The gateway's limits of the object map (console design 6 A1). */
export const CLASSES_MAX = 64;
export const SLOTS_MAX = 2048;
export const CLASS_NAME_MAX = 32;
export const KEY_MAX = 256;

/** The defaults of the learning settings (console design 3.5). Absent settings mean these values. */
export const DEFAULT_LEARNING: LearningSettings = {
  auto_learn: true,
  auto_tighten: true,
  agent: { enabled: false, daily_limit: 200 },
  thresholds: { uses: 20, sessions: 5 },
  auto_pause: true,
};

/** The name a field is compared by: case, `_` and `-` are ignored, so `doc_id`, `docId` and `DocID` are one. */
export function fieldKey(field: string): string {
  return field.toLowerCase().replace(/[_-]/g, "");
}

/** The word a kind is compared by: a trailing `s` does not count, so `doctors` is `doctor`. */
export function kindKey(kind: string): string {
  const lower = kind.toLowerCase();
  return lower.length > KIND_MIN && lower.endsWith("s") ? lower.slice(0, -1) : lower;
}

/** A field name as the declaration stores it: 1 to 32 letters, digits, `_` or `-`. Returns the refusal. */
export function checkField(field: string): string | null {
  if (field.length === 0) return DECLARE_TEXT.fieldEmpty;
  if (field.length > FIELD_MAX) return DECLARE_TEXT.fieldLong;
  if (!/^[A-Za-z0-9_-]+$/.test(field)) return DECLARE_TEXT.fieldChars;
  return null;
}

/** A class id: 3 to 24 lowercase letters (KIND_MIN and KIND_MAX). */
export function checkKind(kind: string): string | null {
  return /^[a-z]{3,24}$/.test(kind) ? null : DECLARE_TEXT.kindFormat;
}

/** A scope: at most 8 path patterns, each written like an entry, none repeated. An empty scope is the whole site. */
export function checkScope(patterns: readonly string[]): string | null {
  if (patterns.length > SCOPE_MAX) return DECLARE_TEXT.scopeMany;
  for (const raw of patterns) {
    const parsed = parsePattern(raw);
    if (!parsed.ok) return parsed.reason;
  }
  if (new Set(patterns).size !== patterns.length) return DECLARE_TEXT.scopeDup;
  return null;
}

/** Two path patterns overlap when some path can match both (`/api/a*` and `/api/a/7` do; `/api/a*` and `/api/b*` do not). */
export function patternsOverlap(a: string, b: string): boolean {
  const left = parsePattern(a);
  const right = parsePattern(b);
  if (!left.ok || !right.ok) return false;
  const x = left.value;
  const y = right.value;
  if (!x.prefix && !y.prefix) return x.raw === y.raw;
  if (x.prefix && y.prefix)
    return x.literal.startsWith(y.literal) || y.literal.startsWith(x.literal);
  return x.prefix ? y.literal.startsWith(x.literal) : x.literal.startsWith(y.literal);
}

/** A missing or empty scope covers the whole site, so it overlaps everything. */
export function scopesOverlap(
  a: readonly string[] | undefined,
  b: readonly string[] | undefined,
): boolean {
  if (a === undefined || a.length === 0 || b === undefined || b.length === 0) return true;
  return a.some((left) => b.some((right) => patternsOverlap(left, right)));
}

/** True when a request path (without query) is inside a scope. A `{id}` in the scope's path is matched as the prefix before it. */
export function inScope(scope: readonly string[] | undefined, path: string): boolean {
  if (scope === undefined || scope.length === 0) return true;
  return scope.some((raw) => {
    const parsed = parsePattern(raw);
    if (!parsed.ok) return false;
    return parsed.value.prefix ? path.startsWith(parsed.value.literal) : path === parsed.value.raw;
  });
}

export type DeclarationProblem =
  | { kind: "duplicate"; with: FieldKindDeclaration }
  | { kind: "conflict"; with: FieldKindDeclaration };

/** A new declaration against the list: the same name in an overlapping scope is a duplicate or a conflict. */
export function declarationProblem(
  list: readonly FieldKindDeclaration[],
  next: FieldKindDeclaration,
): DeclarationProblem | null {
  for (const item of list) {
    if (fieldKey(item.field) !== fieldKey(next.field)) continue;
    if (!scopesOverlap(item.in, next.in)) continue;
    return kindKey(item.kind) === kindKey(next.kind)
      ? { kind: "duplicate", with: item }
      : { kind: "conflict", with: item };
  }
  return null;
}

/** The messages for a whole list of declarations: each entry's own checks, then the clashes between them. */
export function checkDeclarations(list: readonly FieldKindDeclaration[]): string[] {
  const messages: string[] = [];
  if (list.length > DECLARATIONS_MAX) messages.push(DECLARE_TEXT.countMax);
  list.forEach((item, index) => {
    const field = checkField(item.field);
    const kind = checkKind(item.kind);
    const scope = checkScope(item.in ?? []);
    if (field !== null || kind !== null || scope !== null) {
      messages.push(DECLARE_TEXT.shape(`第 ${index + 1} 条`));
    }
  });
  list.forEach((item, index) => {
    const earlier = list.slice(0, index);
    const problem = declarationProblem(earlier, item);
    if (problem === null) return;
    messages.push(
      problem.kind === "duplicate"
        ? DECLARE_TEXT.duplicate(item.field)
        : DECLARE_TEXT.conflict(item.field, problem.with.kind),
    );
  });
  return messages;
}

/** A class in words: its name when the vocabulary has one (医生), otherwise the id as it was written. */
export function classWord(kind: string): string {
  return OBJECT_KIND_LABEL[kind] ?? kind;
}

/** A declaration in words: `字段 doc_id 归为医生（仅 /api/appointments*）`. */
export function declarationLabel(item: FieldKindDeclaration): string {
  const scope = item.in !== undefined && item.in.length > 0 ? item.in.join("、") : null;
  return DECLARE_TEXT.label(item.field, classWord(item.kind), scope);
}

/** Where a declaration applies in words: a field under the scope it names, or a field in every response. */
function placeOf(item: FieldKindDeclaration): string {
  return item.in !== undefined && item.in.length > 0
    ? `响应 ${item.in.join("、")} ${item.field}`
    : `字段 ${item.field}`;
}

/** The learning settings with the defaults filled in. */
export function effectiveLearning(learning: LearningSettings | undefined): LearningSettings {
  if (learning === undefined) return DEFAULT_LEARNING;
  return {
    ...DEFAULT_LEARNING,
    ...learning,
    agent: { ...DEFAULT_LEARNING.agent, ...learning.agent },
    thresholds: { ...DEFAULT_LEARNING.thresholds, ...learning.thresholds },
  };
}

/** The learning settings in one line, for the version conflict choice. */
export function learningText(learning: LearningSettings | undefined): string {
  const value = effectiveLearning(learning);
  const on = (flag: boolean) => (flag ? LEARNING_TEXT.on : LEARNING_TEXT.off);
  return [
    `${LEARNING_TEXT.autoLearn} ${on(value.auto_learn)}`,
    `${LEARNING_TEXT.autoTighten} ${on(value.auto_tighten)}`,
    `${LEARNING_TEXT.agent} ${on(value.agent.enabled)}`,
    `${LEARNING_TEXT.uses} ${value.thresholds.uses}`,
    `${LEARNING_TEXT.sessions} ${value.thresholds.sessions}`,
    `${LEARNING_TEXT.autoPause} ${on(value.auto_pause)}`,
  ].join("、");
}

/** Two declarations with the same key say the same thing: the name, the class word and the scope match. */
export function declarationKey(item: FieldKindDeclaration): string {
  return `${fieldKey(item.field)}|${kindKey(item.kind)}|${(item.in ?? []).join(",")}`;
}

/**
 * The lines the save dialog lists for the field kinds a person declared (`advanced.field_kinds`): a declaration added
 * or removed, and a declaration whose class changed (console design 6: a change reads as what it does to which positions).
 */
export function declarationChanges(
  before: readonly FieldKindDeclaration[] | undefined,
  after: readonly FieldKindDeclaration[] | undefined,
): string[] {
  const changes: string[] = [];
  const old = before ?? [];
  const next = after ?? [];
  // A declaration is matched by its field and its scope: the same place with another class is a change of class.
  const placeKey = (item: FieldKindDeclaration) =>
    `${fieldKey(item.field)}|${(item.in ?? []).join(",")}`;
  const oldByPlace = new Map(
    old.map((item): [string, FieldKindDeclaration] => [placeKey(item), item]),
  );
  const nextByPlace = new Map(
    next.map((item): [string, FieldKindDeclaration] => [placeKey(item), item]),
  );
  for (const item of next) {
    const previous = oldByPlace.get(placeKey(item));
    if (previous === undefined) {
      changes.push(`对象表 ＋ ${declarationLabel(item)}`);
    } else if (kindKey(previous.kind) !== kindKey(item.kind)) {
      changes.push(`${placeOf(item)} 从${classWord(previous.kind)}改为${classWord(item.kind)}`);
    }
  }
  for (const item of old) {
    if (!nextByPlace.has(placeKey(item))) changes.push(`对象表 －1：${declarationLabel(item)}`);
  }
  return changes;
}

/** The lines the save dialog lists for the learning settings that differ (console design 6). */
export function objectChanges(
  before: ObjectsSpec | undefined,
  after: ObjectsSpec | undefined,
): string[] {
  const changes: string[] = [];
  const was = effectiveLearning(before?.learning);
  const now = effectiveLearning(after?.learning);
  const on = (flag: boolean) => (flag ? LEARNING_TEXT.on : LEARNING_TEXT.off);
  const flag = (label: string, a: boolean, b: boolean) => {
    if (a !== b) changes.push(`学习设置 ${label} ${on(a)} → ${on(b)}`);
  };
  flag(LEARNING_TEXT.autoLearn, was.auto_learn, now.auto_learn);
  flag(LEARNING_TEXT.autoTighten, was.auto_tighten, now.auto_tighten);
  flag(LEARNING_TEXT.agent, was.agent.enabled, now.agent.enabled);
  if (was.auto_pause !== now.auto_pause) {
    changes.push(
      now.auto_pause
        ? `${LEARNING_TEXT.autoPause} 关 → 开：之后出现异常的位置会自动暂停`
        : `${LEARNING_TEXT.autoPause} 开 → 关：已暂停的位置保持暂停，之后的异常只提示`,
    );
  }
  if (was.agent.daily_limit !== now.agent.daily_limit) {
    changes.push(
      `学习设置 ${LEARNING_TEXT.agentDaily} ${was.agent.daily_limit} 次 → ${now.agent.daily_limit} 次`,
    );
  }
  if (
    was.thresholds.uses !== now.thresholds.uses ||
    was.thresholds.sessions !== now.thresholds.sessions
  ) {
    changes.push(
      `学习设置 学习门槛 ${was.thresholds.uses} 次、${was.thresholds.sessions} 个会话 → ${now.thresholds.uses} 次、${now.thresholds.sessions} 个会话`,
    );
  }
  changes.push(...classChanges(before?.classes, after?.classes));
  changes.push(...slotChanges(before?.slots, after?.slots));
  return changes;
}

/** The classes of the object map that were added or removed. */
function classChanges(
  before: readonly ObjectClassEntry[] | undefined,
  after: readonly ObjectClassEntry[] | undefined,
): string[] {
  const old = new Set((before ?? []).map((item) => item.id));
  const next = new Set((after ?? []).map((item) => item.id));
  const changes: string[] = [];
  for (const item of after ?? []) {
    if (!old.has(item.id)) changes.push(`对象表 ＋ 类别 ${item.name}（${item.id}）`);
  }
  for (const item of before ?? []) {
    if (!next.has(item.id)) changes.push(`对象表 －1 类别 ${item.name}（${item.id}）`);
  }
  return changes;
}

/** The positions of the object map that were added, removed, moved to another class, or paused (console design 4.1). */
function slotChanges(
  before: readonly ObjectSlotEntry[] | undefined,
  after: readonly ObjectSlotEntry[] | undefined,
): string[] {
  const old = new Map((before ?? []).map((item): [string, ObjectSlotEntry] => [item.key, item]));
  const next = new Map((after ?? []).map((item): [string, ObjectSlotEntry] => [item.key, item]));
  const changes: string[] = [];
  for (const item of after ?? []) {
    const previous = old.get(item.key);
    if (previous === undefined) {
      changes.push(`对象表 ＋ ${positionWords(item.key)} = ${classWord(item.class)}`);
      continue;
    }
    if (kindKey(previous.class) !== kindKey(item.class)) {
      changes.push(
        `${positionWords(item.key)} 从${classWord(previous.class)}改为${classWord(item.class)}`,
      );
    }
    if ((previous.paused ?? false) !== (item.paused ?? false)) {
      changes.push(`${positionWords(item.key)} ${item.paused ? "暂停" : "恢复使用"}`);
    }
    if (judgementKey(previous) !== judgementKey(item)) {
      const was = judgementWords(previous) ?? "无";
      const now = judgementWords(item) ?? "无";
      changes.push(`${positionWords(item.key)} 判断 ${was} → ${now}`);
    }
  }
  for (const item of before ?? []) {
    if (!next.has(item.key)) changes.push(`对象表 －1：${positionWords(item.key)}`);
  }
  return changes;
}

/** A position in words for the change lists: a path parameter reads as its route and number (console design 4.1). */
export function positionWords(key: string): string {
  const slot = pathSlotOf(key);
  if (slot === null || slot.ordinal === null) return key;
  return `请求 ${slot.method} ${slot.route} 第 ${slot.ordinal} 个路径参数`;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);

const isCount = (value: unknown): value is number =>
  typeof value === "number" && Number.isInteger(value) && value >= 0;

/** The `learning` block: every key is a boolean or a count, and no other key is accepted. */
export function parseLearning(
  value: unknown,
): { ok: true; value: LearningSettings } | { ok: false; message: string } {
  if (!isRecord(value)) return { ok: false, message: DECLARE_TEXT.learningShape };
  for (const key of Object.keys(value)) {
    if (!["auto_learn", "auto_tighten", "agent", "thresholds", "auto_pause"].includes(key)) {
      return { ok: false, message: DECLARE_TEXT.unknownKey(key) };
    }
  }
  const { auto_learn, auto_tighten, agent, thresholds, auto_pause } = value;
  if (
    typeof auto_learn !== "boolean" ||
    typeof auto_tighten !== "boolean" ||
    typeof auto_pause !== "boolean" ||
    !isRecord(agent) ||
    typeof agent.enabled !== "boolean" ||
    !isCount(agent.daily_limit) ||
    !isRecord(thresholds) ||
    !isCount(thresholds.uses) ||
    !isCount(thresholds.sessions)
  ) {
    return { ok: false, message: DECLARE_TEXT.learningShape };
  }
  return {
    ok: true,
    value: {
      auto_learn,
      auto_tighten,
      agent: { enabled: agent.enabled, daily_limit: agent.daily_limit },
      thresholds: { uses: thresholds.uses, sessions: thresholds.sessions },
      auto_pause,
    },
  };
}

/** One declaration as written in the configuration: a field, a kind, and an optional scope of strings. */
function declarationOf(
  value: unknown,
  index: number,
): { ok: true; value: FieldKindDeclaration } | { ok: false; message: string } {
  const where = DECLARE_TEXT.shape(`第 ${index + 1} 条`);
  if (!isRecord(value)) return { ok: false, message: where };
  for (const key of Object.keys(value)) {
    if (!["field", "kind", "in"].includes(key))
      return { ok: false, message: DECLARE_TEXT.unknownKey(key) };
  }
  const { field, kind, in: scope } = value;
  if (typeof field !== "string" || typeof kind !== "string") return { ok: false, message: where };
  if (scope === undefined) return { ok: true, value: { field, kind } };
  if (!Array.isArray(scope)) return { ok: false, message: where };
  const words = scope.filter((item): item is string => typeof item === "string");
  if (words.length !== scope.length) return { ok: false, message: where };
  return { ok: true, value: { field, kind, in: words } };
}

/**
 * Reads the `advanced.field_kinds` list of a configuration: each declaration is checked the way the form checks one,
 * and a wrong item is refused with the message to show.
 */
export function declarationsOf(
  value: unknown,
): { ok: true; value: FieldKindDeclaration[] } | { ok: false; message: string } {
  if (!Array.isArray(value)) return { ok: false, message: DECLARE_TEXT.shape("field_kinds") };
  const list: FieldKindDeclaration[] = [];
  for (const [index, item] of value.entries()) {
    const parsed = declarationOf(item, index);
    if (!parsed.ok) return parsed;
    list.push(parsed.value);
  }
  return { ok: true, value: list };
}

const SOURCES: readonly ObjectSource[] = ["admin", "rule", "agent"];

const isSource = (value: unknown): value is ObjectSource =>
  typeof value === "string" && (SOURCES as readonly string[]).includes(value);

/** One class of `objects.classes`, read strictly: an id, a name and an optional description. */
function classOf(
  value: unknown,
  index: number,
): { ok: true; value: ObjectClassEntry } | { ok: false; message: string } {
  const where = DECLARE_TEXT.classShape(index + 1);
  if (!isRecord(value)) return { ok: false, message: where };
  for (const key of Object.keys(value)) {
    if (!["id", "name", "description"].includes(key))
      return { ok: false, message: DECLARE_TEXT.unknownKey(key) };
  }
  const { id, name, description } = value;
  if (typeof id !== "string" || typeof name !== "string") return { ok: false, message: where };
  if (description !== undefined && typeof description !== "string")
    return { ok: false, message: where };
  return {
    ok: true,
    value: description === undefined ? { id, name } : { id, name, description },
  };
}

/** The keys one position of `objects.slots` may hold (docs/07 7.9.15, 7.9.16). */
const SLOT_KEYS: readonly string[] = [
  "key",
  "class",
  "source",
  "paused",
  "identity",
  "tier",
  "accepts_public",
  "reliability",
];
const IDENTITIES: readonly string[] = ["user", "org", "role"];
const TIERS: readonly string[] = ["self", "org", "admin", "public"];
const RELIABILITIES: readonly string[] = ["high", "medium", "low"];

/**
 * One position of `objects.slots`, read strictly: the key, the class, the source, the paused flag and the judgement
 * fields (identity, tier, accepts_public, reliability). The gateway refuses a position with both a tier and an
 * acceptance, and a reliability with neither; the same two checks run here, so a form never shows what it would refuse.
 */
function slotOf(
  value: unknown,
  index: number,
): { ok: true; value: ObjectSlotEntry } | { ok: false; message: string } {
  const where = DECLARE_TEXT.slotShape(index + 1);
  if (!isRecord(value)) return { ok: false, message: where };
  for (const key of Object.keys(value)) {
    if (!SLOT_KEYS.includes(key)) return { ok: false, message: DECLARE_TEXT.unknownKey(key) };
  }
  const { key, class: cls, source, paused, identity, tier, accepts_public, reliability } = value;
  if (typeof key !== "string" || typeof cls !== "string" || !isSource(source)) {
    return { ok: false, message: where };
  }
  if (paused !== undefined && typeof paused !== "boolean") return { ok: false, message: where };
  if (identity !== undefined && !isOneOf(IDENTITIES, identity))
    return { ok: false, message: where };
  if (tier !== undefined && !isOneOf(TIERS, tier)) return { ok: false, message: where };
  if (accepts_public !== undefined && typeof accepts_public !== "boolean") {
    return { ok: false, message: where };
  }
  if (reliability !== undefined && !isOneOf(RELIABILITIES, reliability)) {
    return { ok: false, message: where };
  }
  const entry: ObjectSlotEntry = { key, class: cls, source };
  if (paused !== undefined) entry.paused = paused;
  if (identity !== undefined) entry.identity = identity as ObjectSlotEntry["identity"];
  if (tier !== undefined) entry.tier = tier as ObjectSlotEntry["tier"];
  if (accepts_public !== undefined) entry.accepts_public = accepts_public;
  if (reliability !== undefined) entry.reliability = reliability as ObjectSlotEntry["reliability"];
  const judgementProblem = judgementProblemOf(entry);
  if (judgementProblem !== null) return { ok: false, message: judgementProblem(index + 1) };
  return { ok: true, value: entry };
}

function isOneOf(list: readonly string[], value: unknown): boolean {
  return typeof value === "string" && list.includes(value);
}

/** The gateway's two judgement rules for one entry (docs/07 7.9.16), as the message for its place, or null. */
function judgementProblemOf(entry: ObjectSlotEntry): ((index: number) => string) | null {
  if (entry.tier !== undefined && entry.accepts_public !== undefined) {
    return DECLARE_TEXT.judgementConflict;
  }
  if (
    entry.reliability !== undefined &&
    entry.tier === undefined &&
    entry.accepts_public === undefined
  ) {
    return DECLARE_TEXT.reliabilityAlone;
  }
  return null;
}

/**
 * Reads the `objects` section of a configuration (YAML or JSON) into the typed value. Missing means no section. The
 * learning settings, the classes and the confirmed positions are read strictly; a wrong shape is refused with the
 * message to show, and the form is never given a value it cannot use.
 */
export function parseObjects(
  value: unknown,
): { ok: true; value: ObjectsSpec | undefined } | { ok: false; message: string } {
  if (value === undefined || value === null) return { ok: true, value: undefined };
  if (!isRecord(value)) return { ok: false, message: DECLARE_TEXT.shape("objects") };
  for (const key of Object.keys(value)) {
    if (key !== "learning" && key !== "classes" && key !== "slots")
      return { ok: false, message: DECLARE_TEXT.unknownKey(key) };
  }
  const out: ObjectsSpec = {};
  if (value.learning !== undefined && value.learning !== null) {
    const learning = parseLearning(value.learning);
    if (!learning.ok) return learning;
    out.learning = learning.value;
  }
  if (value.classes !== undefined && value.classes !== null) {
    if (!Array.isArray(value.classes)) return { ok: false, message: DECLARE_TEXT.classesShape };
    const classes: ObjectClassEntry[] = [];
    for (const [index, item] of value.classes.entries()) {
      const parsed = classOf(item, index);
      if (!parsed.ok) return parsed;
      classes.push(parsed.value);
    }
    out.classes = classes;
  }
  if (value.slots !== undefined && value.slots !== null) {
    if (!Array.isArray(value.slots)) return { ok: false, message: DECLARE_TEXT.slotsShape };
    const slots: ObjectSlotEntry[] = [];
    for (const [index, item] of value.slots.entries()) {
      const parsed = slotOf(item, index);
      if (!parsed.ok) return parsed;
      slots.push(parsed.value);
    }
    out.slots = slots;
  }
  return { ok: true, value: out };
}

/** The gateway's limits of one position key: `METHOD /template location`, 256 bytes at most (console design 6 A1). */
export function keyProblem(key: string): string | null {
  const parts = key.split(" ");
  if (parts.length !== 3) return DECLARE_TEXT.slotKeyFormat;
  const [method = "", template = "", location = ""] = parts;
  const shaped =
    /^[A-Z]{3,7}$/.test(method) &&
    template.startsWith("/") &&
    !/[?#]/.test(template) &&
    location.length > 0 &&
    ![...key].some((ch) => ch.charCodeAt(0) < 0x20 || ch.charCodeAt(0) === 0x7f);
  if (!shaped) return DECLARE_TEXT.slotKeyFormat;
  if (new TextEncoder().encode(key).length > KEY_MAX) return DECLARE_TEXT.slotKeyLong;
  return null;
}

/** A class of `objects.classes`: a lower-case id, and a name of 1 to 32 characters. */
export function classProblem(item: ObjectClassEntry): string | null {
  const id = checkKind(item.id);
  if (id !== null) return id;
  if (item.name.length === 0) return DECLARE_TEXT.classNameEmpty;
  if ([...item.name].length > CLASS_NAME_MAX) return DECLARE_TEXT.classNameLong;
  return null;
}

/**
 * The messages for the object map's classes and positions as the gateway checks them: the counts, each class and
 * position's own shape, no repeated id or key, and every position's class declared in the map.
 */
export function checkObjects(objects: ObjectsSpec | undefined): string[] {
  const messages: string[] = [];
  const classes = objects?.classes ?? [];
  const slots = objects?.slots ?? [];
  if (classes.length > CLASSES_MAX) messages.push(DECLARE_TEXT.classCountMax);
  if (slots.length > SLOTS_MAX) messages.push(DECLARE_TEXT.slotCountMax);
  const ids = new Set<string>();
  classes.forEach((item, index) => {
    const problem = classProblem(item);
    if (problem !== null) messages.push(DECLARE_TEXT.classShape(index + 1));
    if (ids.has(item.id)) messages.push(DECLARE_TEXT.classDuplicate(item.id));
    ids.add(item.id);
  });
  const keys = new Set<string>();
  slots.forEach((item, index) => {
    if (keyProblem(item.key) !== null) messages.push(DECLARE_TEXT.slotShape(index + 1));
    const judgementProblem = judgementProblemOf(item);
    if (judgementProblem !== null) messages.push(judgementProblem(index + 1));
    if (keys.has(item.key)) messages.push(DECLARE_TEXT.slotDuplicate(item.key));
    keys.add(item.key);
    if (!ids.has(item.class)) messages.push(DECLARE_TEXT.slotClassUnknown(item.key, item.class));
  });
  return messages;
}

/** A path position read apart (console design 4.1): the route template, the segment the judge reads (`path[n]`,
 *  counted from 0 over the template's segments) and, when that segment is a `{…}` parameter, its number among the
 *  parameters of the template (`第 2 个路径参数`). Null for a key that is not a path position. */
export type PathSlot = {
  method: string;
  route: string;
  segment: number;
  ordinal: number | null;
};

const isParamSegment = (text: string | undefined): boolean =>
  text !== undefined && /^\{[^{}]*\}$/.test(text);

export function pathSlotOf(key: string): PathSlot | null {
  const parts = key.split(" ");
  if (parts.length !== 3) return null;
  const [method = "", route = "", location = ""] = parts;
  const match = /^path\[(\d+)\]$/.exec(location);
  if (match === null) return null;
  const segment = Number(match[1]);
  const segments = route.replace(/^\//, "").split("/");
  const ordinal = isParamSegment(segments[segment])
    ? segments.slice(0, segment + 1).filter(isParamSegment).length
    : null;
  return { method, route, segment, ordinal };
}
