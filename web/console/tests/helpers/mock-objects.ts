// The object map's endpoints for mock-api.ts (console design 7): the map with its filters, a position's drawer, the two
// learning actions, and the cold start candidates. Learning state (a dismissed or ambiguous position) lives with each
// mockApi call, so a new call starts again from the fixtures. Sites other than emr have no map.

import type {
  ObjectCounts,
  ObjectSlotDetail,
  ObjectSlotRow,
  ObjectState,
  ObjectsResponse,
} from "../../src/api/types.ts";
import {
  bootstrapCandidates,
  objectRuns,
  objectSlotS2,
  objectSlotS8,
  objectsEmpty,
  objectsEmr,
} from "./fixtures.ts";

/** A status and a body, as mock-api.ts answers a call. */
export type ObjectAnswer = { status: number; body?: unknown };

type CountKey = keyof ObjectCounts;
const COUNT_KEYS: readonly CountKey[] = [
  "pending",
  "proposed",
  "confirmed",
  "ambiguous",
  "suspended",
];

type Store = { states: Map<string, ObjectState>; dismissed: Set<string>; counts: ObjectCounts };

const stores = new WeakMap<object, Map<string, Store>>();

function baseOf(site: string): ObjectsResponse {
  return site === "emr" ? objectsEmr : objectsEmpty;
}

/** The learning state of one mock: each position's state, and the counts that follow from it. */
function storeOf(owner: object, site: string): Store {
  let byName = stores.get(owner);
  if (byName === undefined) {
    byName = new Map();
    stores.set(owner, byName);
  }
  let store = byName.get(site);
  if (store === undefined) {
    const base = baseOf(site);
    store = {
      states: new Map(base.slots.map((row) => [row.id, row.state])),
      dismissed: new Set(),
      counts: { ...base.counts },
    };
    byName.set(site, store);
  }
  return store;
}

/** The positions of a site with the states the learning actions gave them. */
function rowsOf(site: string, owner: object): ObjectSlotRow[] {
  const store = storeOf(owner, site);
  return baseOf(site).slots.map((row) => ({
    ...row,
    state: store.states.get(row.id) ?? row.state,
    dismissed: store.dismissed.has(row.id) || row.dismissed,
  }));
}

function matchesText(row: ObjectSlotRow, needle: string): boolean {
  return (
    row.key.toLowerCase().includes(needle) ||
    row.basis.toLowerCase().includes(needle) ||
    (row.class ?? "").toLowerCase().includes(needle)
  );
}

/** `GET /api/sites/{name}/objects`: the whole map's counts and classes, and the positions the filters let through. */
export function objectsAnswer(site: string, params: URLSearchParams, owner: object): ObjectAnswer {
  const base = baseOf(site);
  const state = params.get("state");
  const cls = params.get("class");
  const needle = (params.get("q") ?? "").trim().toLowerCase();
  const slots = rowsOf(site, owner).filter(
    (row) =>
      (state === null || row.state === state) &&
      (cls === null || row.class === cls) &&
      (needle === "" || matchesText(row, needle)),
  );
  return {
    status: 200,
    body: {
      ...base,
      counts: storeOf(owner, site).counts,
      slots,
      events: base.events.filter((event) => event.status === "open"),
    },
  };
}

/** `GET .../objects/events`: the window's automatic changes, the open ones unless the status asks for all, and the kind it names. */
export function objectEventsAnswer(site: string, params: URLSearchParams): ObjectAnswer {
  const status = params.get("status") ?? "open";
  const kind = params.get("kind");
  const events = baseOf(site).events.filter(
    (event) =>
      (status === "all" || event.status === "open") && (kind === null || event.kind === kind),
  );
  return { status: 200, body: { events } };
}

/** `GET .../objects/slots/{id}`: the drawer of one position. The samples carry evidence for s2 only. */
export function objectSlotAnswer(site: string, id: string, owner: object): ObjectAnswer {
  const row = rowsOf(site, owner).find((item) => item.id === id);
  if (row === undefined) return { status: 404, body: { error: "SLOT_NOT_FOUND" } };
  const detail: ObjectSlotDetail =
    id === objectSlotS2.id
      ? { ...objectSlotS2, state: row.state, dismissed: row.dismissed }
      : id === objectSlotS8.id
        ? { ...objectSlotS8, state: row.state, dismissed: row.dismissed }
        : { ...row, flows_in: [], examples: [], shape: [], history: [], impact: [], agent: null };
  return { status: 200, body: detail };
}

/** `GET .../objects/runs`: the newest learning runs of the site (console design 3.3). */
export function runsAnswer(): ObjectAnswer {
  return { status: 200, body: { runs: objectRuns.runs } };
}

/** `GET .../objects/runs/{id}`: one run with its calls. Only run 40 is kept, so any other id is not found. */
export function runDetailAnswer(id: string): ObjectAnswer {
  if (id !== "40") return { status: 404, body: { error: "RUN_NOT_FOUND" } };
  return { status: 200, body: objectRuns.detail };
}

/** `POST .../slots/{id}/dismiss` (学习中) and `/ambiguous` (有歧义): the position's state moves, the counts follow. */
export function learnAnswer(
  site: string,
  id: string,
  action: "dismiss" | "ambiguous",
  owner: object,
): ObjectAnswer {
  const store = storeOf(owner, site);
  const row = rowsOf(site, owner).find((item) => item.id === id);
  if (row === undefined) return { status: 404, body: { error: "SLOT_NOT_FOUND" } };
  const from = row.state;
  const to: ObjectState = action === "dismiss" ? "pending" : "ambiguous";
  store.states.set(id, to);
  if (action === "dismiss") store.dismissed.add(id);
  const counts = { ...store.counts };
  const fromKey = COUNT_KEYS.find((key) => key === from);
  const toKey = COUNT_KEYS.find((key) => key === to);
  if (fromKey !== undefined) counts[fromKey] -= 1;
  if (toKey !== undefined) counts[toKey] += 1;
  store.counts = counts;
  return { status: 204 };
}

/** `GET .../objects/bootstrap`: juice's candidates; the other sites have their map already. */
export function bootstrapAnswer(site: string): ObjectAnswer {
  return {
    status: 200,
    body: site === "emr" ? { window_hours: 24, records: 0, candidates: [] } : bootstrapCandidates,
  };
}
