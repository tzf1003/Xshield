// What the site pages keep in the browser: the unsaved draft of each site (sessionStorage, so a refresh does
// not lose it), two hand-offs between pages (a copied configuration and a just-created site), and the
// suggestions the user chose to ignore (localStorage, docs/07 7.9.11).

import type { SiteSpec } from "../../api/types.ts";
import { isRecord, readJson, removeText, writeJson } from "../../lib/storage.ts";

export type DraftRecord = { base: number; spec: SiteSpec };

const DRAFT_PREFIX = "xshield.console.site-draft.";
const COPY_KEY = "xshield.console.copy-site";
const CREATED_KEY = "xshield.console.created-site";
const IGNORED_PREFIX = "xshield.console.ignored-suggestions.";

function isDraftRecord(value: unknown): value is DraftRecord | null {
  if (value === null) return true;
  return isRecord(value) && typeof value.base === "number" && isRecord(value.spec);
}

function isSpecLike(value: unknown): value is SiteSpec {
  return isRecord(value) && typeof value.name === "string" && Array.isArray(value.hosts);
}

function isStringList(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

/** The draft of a site, with the version it was started from. Null when there is none. */
export function readDraft(name: string): DraftRecord | null {
  return readJson<DraftRecord | null>(`${DRAFT_PREFIX}${name}`, null, isDraftRecord, "session");
}

export function writeDraft(name: string, draft: DraftRecord): void {
  writeJson(`${DRAFT_PREFIX}${name}`, draft, "session");
}

export function clearDraft(name: string): void {
  removeText(`${DRAFT_PREFIX}${name}`, "session");
}

/** A configuration handed from a site to the new-site page ("复制为新站点"). */
export function writeCopy(spec: SiteSpec): void {
  writeJson(COPY_KEY, spec, "session");
}

export function readCopy(): SiteSpec | null {
  return readJson<SiteSpec | null>(
    COPY_KEY,
    null,
    (value): value is SiteSpec | null => {
      return value === null || isSpecLike(value);
    },
    "session",
  );
}

export function clearCopy(): void {
  removeText(COPY_KEY, "session");
}

/** The site created last, so its page can say what to do next. */
export function writeCreated(name: string, version: number): void {
  writeJson(CREATED_KEY, { name, version }, "session");
}

export function readCreated(name: string): { name: string; version: number } | null {
  const value = readJson<{ name: string; version: number } | null>(
    CREATED_KEY,
    null,
    (candidate): candidate is { name: string; version: number } | null => {
      return (
        candidate === null ||
        (isRecord(candidate) &&
          typeof candidate.name === "string" &&
          typeof candidate.version === "number")
      );
    },
    "session",
  );
  return value !== null && value.name === name ? value : null;
}

export function clearCreated(): void {
  removeText(CREATED_KEY, "session");
}

export function readIgnored(name: string): string[] {
  return readJson<string[]>(`${IGNORED_PREFIX}${name}`, [], isStringList);
}

export function writeIgnored(name: string, ids: string[]): void {
  writeJson(`${IGNORED_PREFIX}${name}`, ids);
}
