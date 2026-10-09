import type { SessionStore } from "./session-store.ts";

/** Runs reads one at a time in the order queued; a failed read does not block the reads behind it. */
export class ReadLane {
  #tail: Promise<unknown> = Promise.resolve();

  run<T>(read: () => Promise<T>): Promise<T> {
    const turn = this.#tail.then(read);
    this.#tail = turn.catch(() => undefined);
    return turn;
  }
}

const lanes = new WeakMap<SessionStore, ReadLane>();

/** One lane per session store, so the reads of one session never overlap each other. */
export function readLaneOf(store: SessionStore): ReadLane {
  let lane = lanes.get(store);
  if (!lane) {
    lane = new ReadLane();
    lanes.set(store, lane);
  }
  return lane;
}
