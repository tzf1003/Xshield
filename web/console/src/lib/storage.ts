// Safe wrappers over localStorage and sessionStorage. Storage can be blocked, full, or hold a value
// from an older version of the console, so reads never throw: a missing or unexpected value reads as
// the fallback.

export type StorageKind = "local" | "session";

function storageOf(kind: StorageKind): Storage | null {
  try {
    return kind === "local" ? window.localStorage : window.sessionStorage;
  } catch {
    return null;
  }
}

export function readText(key: string, kind: StorageKind = "local"): string | null {
  try {
    return storageOf(kind)?.getItem(key) ?? null;
  } catch {
    return null;
  }
}

export function writeText(key: string, value: string, kind: StorageKind = "local"): void {
  try {
    storageOf(kind)?.setItem(key, value);
  } catch {
    // Quota exceeded or storage blocked: the value simply does not persist.
  }
}

export function removeText(key: string, kind: StorageKind = "local"): void {
  try {
    storageOf(kind)?.removeItem(key);
  } catch {
    // Nothing to remove when storage is unavailable.
  }
}

/** Reads JSON. `guard` checks the parsed shape; a value that fails it reads as the fallback. */
export function readJson<T>(
  key: string,
  fallback: T,
  guard: (value: unknown) => value is T,
  kind: StorageKind = "local",
): T {
  const raw = readText(key, kind);
  if (raw === null) return fallback;
  try {
    const parsed: unknown = JSON.parse(raw);
    return guard(parsed) ? parsed : fallback;
  } catch {
    return fallback;
  }
}

export function writeJson(key: string, value: unknown, kind: StorageKind = "local"): void {
  writeText(key, JSON.stringify(value), kind);
}

export function isArray(value: unknown): value is unknown[] {
  return Array.isArray(value);
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
