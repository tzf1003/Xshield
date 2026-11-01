// The last ten things the user opened, for the empty command palette (docs/06 6.3.3). Only the kind,
// the identifier and a title are stored, never record contents.

import { isRecord, readJson, writeJson } from "../lib/storage.ts";

export type RecentKind = "request" | "session" | "site";
export type RecentItem = { kind: RecentKind; id: string; title: string };

const KEY = "xshield.console.recent";
const LIMIT = 10;
const KINDS: readonly string[] = ["request", "session", "site"];

function isRecent(value: unknown): value is RecentItem[] {
  return (
    Array.isArray(value) &&
    value.every(
      (item) =>
        isRecord(item) &&
        typeof item.kind === "string" &&
        KINDS.includes(item.kind) &&
        typeof item.id === "string" &&
        typeof item.title === "string",
    )
  );
}

export function readRecent(): RecentItem[] {
  return readJson<RecentItem[]>(KEY, [], isRecent);
}

export function pushRecent(item: RecentItem): void {
  const rest = readRecent().filter((entry) => !(entry.kind === item.kind && entry.id === item.id));
  writeJson(KEY, [item, ...rest].slice(0, LIMIT));
}
