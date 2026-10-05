/**
 * The count beside "审批中心" in the navigation. It is the number of pending items the last
 * load of the approval center (or the badge's own refresh) found on the first page of each
 * source. Nothing here polls: the number changes only when one of those two loads runs, and it
 * is forgotten, with every other session fact, when the session ends.
 */
import { guardedQuery } from "../security/guarded-query.ts";
import type { SessionRuntime } from "../security/runtime.ts";
import { type BadgeCount, type BadgeSource, badgeCount, siteApprovals } from "./inbox.ts";
import { specs } from "./queries.ts";
import { hasRole, role } from "./roles.ts";

export type BadgeSnapshot = Readonly<{
  /** `false` until some load has produced a number. */
  known: boolean;
  busy: boolean;
  value: BadgeCount;
}>;

const empty: BadgeSnapshot = Object.freeze({
  known: false,
  busy: false,
  value: Object.freeze({ count: 0, more: false, partial: false }),
});

export class BadgeStore {
  #snapshot: BadgeSnapshot = empty;
  readonly #listeners = new Set<() => void>();

  getSnapshot = (): BadgeSnapshot => this.#snapshot;

  subscribe = (listener: () => void): (() => void) => {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  };

  publish(sources: readonly BadgeSource[]): void {
    this.#set({ known: true, busy: false, value: badgeCount(sources) });
  }

  setBusy(busy: boolean): void {
    this.#set({ ...this.#snapshot, busy });
  }

  reset(): void {
    this.#set(empty);
  }

  #set(next: BadgeSnapshot): void {
    this.#snapshot = Object.freeze(next);
    for (const listener of [...this.#listeners]) listener();
  }
}

const stores = new WeakMap<SessionRuntime, BadgeStore>();

/** One store per runtime; it clears itself whenever the session ends. */
export function badgeStore(runtime: SessionRuntime): BadgeStore {
  let store = stores.get(runtime);
  if (!store) {
    store = new BadgeStore();
    const fresh = store;
    runtime.store.onDisconnect(() => fresh.reset());
    stores.set(runtime, store);
  }
  return store;
}

const failed: BadgeSource = { loaded: false, count: 0, truncated: false };

/**
 * Reads the first page of every source this operator's roles can see and publishes the count.
 * The reads use the same keys as the approval center, so opening it afterwards reuses them.
 */
export async function refreshBadge(
  runtime: SessionRuntime,
  roles: readonly string[] | null,
): Promise<void> {
  const store = badgeStore(runtime);
  const epoch = runtime.store.getState().epoch;
  store.setBusy(true);
  const client = runtime.queryClient;
  const reads: Promise<BadgeSource>[] = [];
  if (hasRole(roles, role.approver)) {
    reads.push(
      client.fetchQuery(guardedQuery(runtime, specs.accessList("review"))).then(
        (page) => ({ loaded: true, count: page.items.length, truncated: page.truncated }),
        () => failed,
      ),
      client.fetchQuery(guardedQuery(runtime, specs.exportList("review"))).then(
        (page) => ({ loaded: true, count: page.items.length, truncated: page.truncated }),
        () => failed,
      ),
    );
  }
  if (hasRole(roles, role.policyApprover)) {
    reads.push(
      client.fetchQuery(guardedQuery(runtime, specs.siteApprovals())).then(
        (page) => ({
          loaded: true,
          count: siteApprovals(page.sites).length,
          truncated: page.truncated,
        }),
        () => failed,
      ),
    );
  }
  const sources = await Promise.all(reads);
  // A session that ended meanwhile has already reset the store; never repopulate it from a
  // reply that belongs to an earlier session lifetime.
  if (!runtime.store.isCurrent(epoch)) return;
  store.publish(sources);
}
