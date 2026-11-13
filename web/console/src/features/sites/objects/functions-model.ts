// The function table's pure logic (docs/06 6.4.10, docs/07 7.9.18 to 7.9.20): the default selection of the candidates, the
// administrator's pending changes and the body they send, the pruning when the list is read again, the estimate that the
// switch states, and whether a key falls under a bypass rule. No React and no request here: the view and its mutations use
// these functions, and the unit tests check them without a browser.

import type {
  FunctionChanges,
  FunctionRow,
  ObjectReliability,
  SiteFunctions,
  SiteSpec,
} from "../../../api/types.ts";
import { matchesPattern, parsePattern } from "../../../lib/patterns.ts";

/** The four kinds of change the view collects. A key takes at most one of them: the server reads a key once per batch. */
export type PendingKind = "add" | "admin" | "open" | "remove";

/** The changes the administrator has picked and not yet confirmed. They live in the view's state, never in the URL or the draft. */
export type Pending = {
  /** Candidates to add to the table as known functions. */
  readonly add: ReadonlySet<string>;
  /** Proposals to confirm as administrator functions. */
  readonly admin: ReadonlySet<string>;
  /** Administrator functions to open to every session. */
  readonly open: ReadonlySet<string>;
  /** Functions to delete from the table. */
  readonly remove: ReadonlySet<string>;
};

export const NO_PENDING: Pending = {
  add: new Set(),
  admin: new Set(),
  open: new Set(),
  remove: new Set(),
};

/** Whether a candidate is picked by default: suggested, not sensitive, and not proposed as an administrator's function.
 *  The count of suggested candidates in the view follows the same rule. */
export function isDefaultPick(
  item: SiteFunctions["candidates"][number],
  proposed: ReadonlySet<string>,
): boolean {
  return item.suggested && !item.sensitive && !proposed.has(item.key);
}

/** The default selection: the candidates `isDefaultPick` takes. A key the rules propose as an administrator's function is
 *  left to the proposal, because adding it as a known function would open it to every session. */
export function defaultPending(data: SiteFunctions): Pending {
  const proposed = new Set(data.proposals.map((proposal) => proposal.key));
  const add = data.candidates
    .filter((item) => isDefaultPick(item, proposed))
    .map((item) => item.key);
  return { ...NO_PENDING, add: new Set(add) };
}

/** Drops the keys the list no longer has. A refresh keeps the choices the administrator made and removes nothing else. */
export function prunePending(pending: Pending, data: SiteFunctions): Pending {
  const candidates = new Set(data.candidates.map((item) => item.key));
  const proposals = new Set(data.proposals.map((item) => item.key));
  const functions = new Set(data.functions.map((item) => item.key));
  const tiered = new Set(
    data.functions.filter((item) => item.tier === "admin").map((item) => item.key),
  );
  return {
    add: keep(pending.add, candidates),
    admin: keep(pending.admin, proposals),
    open: keep(pending.open, tiered),
    remove: keep(pending.remove, functions),
  };
}

function keep(set: ReadonlySet<string>, allowed: ReadonlySet<string>): Set<string> {
  return new Set([...set].filter((key) => allowed.has(key)));
}

/** Puts `key` into `kind` and out of the other kinds, or out of all of them when `on` is false. */
export function place(pending: Pending, kind: PendingKind, key: string, on: boolean): Pending {
  const next = {
    add: new Set(pending.add),
    admin: new Set(pending.admin),
    open: new Set(pending.open),
    remove: new Set(pending.remove),
  };
  for (const set of Object.values(next)) set.delete(key);
  if (on) next[kind].add(key);
  return next;
}

/** The number of changes of each kind, and of all of them. */
export function countsOf(pending: Pending): {
  add: number;
  admin: number;
  open: number;
  remove: number;
  total: number;
} {
  const add = pending.add.size;
  const admin = pending.admin.size;
  const open = pending.open.size;
  const remove = pending.remove.size;
  return { add, admin, open, remove, total: add + admin + open + remove };
}

/** The body the confirmation sends: only the lists that hold something, each in the order the list shows it. Null when
 *  nothing is pending, because an empty batch is refused (docs/07 7.9.20). */
export function changesOf(pending: Pending, data: SiteFunctions): FunctionChanges | null {
  const add = data.candidates.map((item) => item.key).filter((key) => pending.add.has(key));
  const admin = data.proposals
    .filter((item) => pending.admin.has(item.key))
    .map((item) => ({ key: item.key, reliability: item.reliability }));
  const open = data.functions.map((item) => item.key).filter((key) => pending.open.has(key));
  const remove = data.functions.map((item) => item.key).filter((key) => pending.remove.has(key));
  if (add.length + admin.length + open.length + remove.length === 0) return null;
  const body: FunctionChanges = {};
  if (add.length > 0) body.add = add;
  if (admin.length > 0) body.admin = admin;
  if (open.length > 0) body.open = open;
  if (remove.length > 0) body.remove = remove;
  return body;
}

/** Whether the batch leaves the table with no function at all: a removal of every entry, and no candidate or proposal
 *  added. The gateway refuses such a table while unknown functions are asked about (`ask_without_functions`). */
export function emptiesTable(pending: Pending, data: SiteFunctions): boolean {
  const kept = data.functions.filter((item) => !pending.remove.has(item.key));
  return kept.length === 0 && pending.add.size === 0 && pending.admin.size === 0;
}

/** What the switch for unknown functions states, from the list alone (docs/07 7.9.18, 7.9.20). Every figure is a count
 *  of requests of the last day that the gateway let through (fast or cached) and whose function the table does not list. */
export type AskEstimate = {
  /** The requests of all the candidates. */
  candidateRequests: number;
  candidateCount: number;
  /** The requests of the unlearned functions, not counting `unkeyed`. */
  unlearned: number;
  /** The requests whose function key cannot be written; at most this many of them reach Jev (preflights among them). */
  unkeyed: number;
  /** False when the counts are lower bounds. */
  complete: boolean;
  /** Every request above, once each. */
  total: number;
};

export function askEstimate(data: SiteFunctions): AskEstimate {
  const candidateRequests = data.candidates.reduce((sum, item) => sum + item.requests_24h, 0);
  const candidateCount = data.candidates.length;
  const unlearned = data.unlearned.requests;
  const unkeyed = data.unlearned.unkeyed_requests;
  return {
    candidateRequests,
    candidateCount,
    unlearned,
    unkeyed,
    complete: data.unlearned.complete,
    total: candidateRequests + unlearned + unkeyed,
  };
}

/** Whether a function key's path falls under a bypass rule. Such a path is never judged, so its entry does nothing. The
 *  path is the part of the key after its space; a key without one is not under any rule. */
export function underBypass(key: string, bypass: readonly string[] | undefined): boolean {
  const space = key.indexOf(" ");
  if (space < 0 || bypass === undefined || bypass.length === 0) return false;
  const path = key.slice(space + 1);
  return bypass.some((raw) => {
    const parsed = parsePattern(raw);
    return parsed.ok && matchesPattern(parsed.value, path);
  });
}

/** The draft with the switch for unknown functions set. Turning it off removes the key, as the saved file leaves it out. */
export function withAskUnknown(spec: SiteSpec, on: boolean): SiteSpec {
  const objects = { ...spec.objects };
  if (on) objects.ask_unknown_functions = true;
  else delete objects.ask_unknown_functions;
  return { ...spec, objects };
}

/** The date of a function's last sighting: the day as the server writes it (a UTC midnight), shown as the date only. */
export function dayText(iso: string | null): string {
  if (iso === null || !/^\d{4}-\d{2}-\d{2}T/.test(iso)) return "—";
  return iso.slice(0, 10);
}

/** A reliability in the words the table uses for a proposal (only `high` and `medium` are proposed). */
export function reliabilityWord(reliability: ObjectReliability): string {
  if (reliability === "high") return "高";
  if (reliability === "medium") return "中";
  return "低";
}

/** Whether the row is an administrator function that tightens the judgement: only `high` does (docs/07 7.9.18). */
export function tightens(row: Pick<FunctionRow, "tier" | "reliability">): boolean {
  return row.tier === "admin" && row.reliability === "high";
}

/** The status warning for an administrator table with no session counted as an administrator (docs/06 6.4.10). */
export function noAdminWarning(data: SiteFunctions): boolean {
  if (data.admin_units > 0) return false;
  return data.functions.some((item) => item.tier === "admin") || data.proposals.length > 0;
}

/** The field a refusal names when it names one of the change's own lists (`remove[0]`): the key the batch sent there. */
export function keyOfField(field: string | undefined, body: FunctionChanges | null): string | null {
  if (field === undefined || body === null) return null;
  const match = /^(add|admin|open|remove)\[(\d+)\]$/.exec(field);
  if (match === null) return null;
  const list = body[match[1] as keyof FunctionChanges];
  const at = Number(match[2]);
  if (!Array.isArray(list) || at >= list.length) return null;
  const item = list[at] as string | { key: string };
  return typeof item === "string" ? item : item.key;
}
