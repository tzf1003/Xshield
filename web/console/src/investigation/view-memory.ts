import { type Dispatch, type SetStateAction, useEffect, useState } from "react";
import type { SessionRuntime } from "../security/runtime.ts";
import { useSession } from "../security/SessionProvider";

/**
 * In-memory form drafts that survive moving between pages (open a request from the stream, come
 * back, and the filters are still there). Only drafts live here, never results, and the whole map
 * is dropped the moment the session ends, together with the query cache. Nothing is written to
 * web storage.
 */
const memories = new WeakMap<SessionRuntime, Map<string, unknown>>();

function memoryFor(runtime: SessionRuntime): Map<string, unknown> {
  let memory = memories.get(runtime);
  if (!memory) {
    const created = new Map<string, unknown>();
    memory = created;
    memories.set(runtime, created);
    runtime.store.onDisconnect(() => created.clear());
  }
  return memory;
}

export function useRemembered<T>(
  slot: string,
  initial: () => T,
  /** Fields that must not be kept, for example a subject reference. */
  scrub: (value: T) => T = (value) => value,
): [T, Dispatch<SetStateAction<T>>] {
  const { runtime } = useSession();
  const memory = memoryFor(runtime);
  const [value, setValue] = useState<T>(() =>
    memory.has(slot) ? (memory.get(slot) as T) : initial(),
  );
  useEffect(() => {
    memory.set(slot, scrub(value));
  }, [memory, slot, value, scrub]);
  return [value, setValue];
}

/** Forget one slot, for example when a preset from another page replaces the form. */
export function forgetRemembered(runtime: SessionRuntime, slot: string): void {
  memoryFor(runtime).delete(slot);
}
