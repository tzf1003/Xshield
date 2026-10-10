/** Owner-scoped saved investigation searches (`/control/v1/saved-views`). A view is parameters
 * only; running it is an ordinary, audited search. */
import {
  ApiError,
  ensure,
  envelope,
  id,
  list,
  object,
  pagination,
  text,
  timestamp,
  uuid,
} from "./api-contract.ts";
import type { Envelope } from "./api-contract.ts";
import { type SearchPlan, validateSearchPlan } from "./search.ts";

export const savedViewPattern = new RegExp(`^view_${uuid}(?![\\s\\S])`);
const NAME_BYTES_MAX = 160;
const BODY_BYTES_MAX = 9 * 1024;
const cursorPattern = new RegExp(`^v1\\.(view_${uuid})\\.[0-9a-f]{64}(?![\\s\\S])`);

export type SavedView = {
  view_id: string;
  name: string;
  search: SearchPlan;
  created_at: string;
};
export type SavedViewList = Envelope & {
  schema_version: 1;
  as_of: string;
  items: SavedView[];
  truncated: boolean;
  next_cursor: string | null;
};
export type SavedViewCreated = Envelope & {
  schema_version: 1;
  view_id: string;
  name: string;
  created_at: string;
};
export type SavedViewDeleted = Envelope & { schema_version: 1; view_id: string; deleted: true };

/** Names are 1–160 bytes and carry no control characters, matching the server. */
export function validateSavedViewName(name: string): string {
  const bytes = new TextEncoder().encode(name).byteLength;
  const control = [...name].some((character) => {
    const code = character.codePointAt(0) ?? 0;
    return code < 0x20 || code === 0x7f;
  });
  if (name.length === 0 || bytes > NAME_BYTES_MAX || control)
    throw new ApiError("CONTROL_SAVED_VIEW_REQUEST_INVALID");
  return name;
}

export function validateSavedViewId(value: string): string {
  const match = savedViewPattern.exec(value);
  if (!match || match[0] !== value) throw new ApiError("CONTROL_SAVED_VIEW_ID_INVALID");
  return value;
}

/** The create body; the search is checked as a complete plan before it leaves the browser. */
export function savedViewCreateBody(name: string, plan: SearchPlan): string {
  const body = JSON.stringify({
    schema_version: 1,
    name: validateSavedViewName(name),
    search: validateSearchPlan(plan),
  });
  if (new TextEncoder().encode(body).byteLength > BODY_BYTES_MAX)
    throw new ApiError("CONTROL_SAVED_VIEW_REQUEST_INVALID");
  return body;
}

/** Validates a cursor's shape only; the server authenticates owner and scope binding. */
export function validateSavedViewCursor(cursor?: string): string | undefined {
  if (cursor === undefined) return undefined;
  const match = cursorPattern.exec(cursor);
  if (!match) throw new ApiError("CONTROL_CURSOR_INVALID");
  return match[1];
}

function time(value: unknown): string {
  const result = timestamp(value);
  ensure(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z(?![\s\S])/.test(result));
  return result;
}

function savedView(value: unknown): SavedView {
  const row = object(value);
  let search: SearchPlan;
  try {
    search = validateSearchPlan(row.search);
  } catch {
    throw new ApiError("INVALID_RESPONSE");
  }
  return {
    view_id: id(row.view_id, savedViewPattern),
    name: validateSavedViewName(text(row.name, NAME_BYTES_MAX)),
    search,
    created_at: time(row.created_at),
  };
}

/** A live page of the caller's views, newest identity first, with a cursor naming the last row. */
export function decodeSavedViewList(value: unknown, cursor?: string): SavedViewList {
  const row = object(value);
  ensure(row.schema_version === 1);
  const result: SavedViewList = {
    ...envelope(row),
    schema_version: 1,
    as_of: timestamp(row.as_of),
    items: list(row.items, 128, savedView),
    ...pagination(row),
  };
  let previous = validateSavedViewCursor(cursor);
  for (const item of result.items) {
    ensure(previous === undefined || item.view_id < previous);
    previous = item.view_id;
  }
  if (result.next_cursor !== null) {
    const match = cursorPattern.exec(result.next_cursor);
    ensure(match && result.items.length > 0 && match[1] === previous);
  }
  return result;
}

export function decodeSavedViewCreated(value: unknown, name: string): SavedViewCreated {
  const row = object(value);
  ensure(row.schema_version === 1 && row.name === name);
  return {
    ...envelope(row),
    schema_version: 1,
    view_id: id(row.view_id, savedViewPattern),
    name,
    created_at: time(row.created_at),
  };
}

export function decodeSavedViewDeleted(value: unknown, viewId: string): SavedViewDeleted {
  const row = object(value);
  ensure(row.schema_version === 1 && row.view_id === viewId && row.deleted === true);
  return { ...envelope(row), schema_version: 1, view_id: viewId, deleted: true };
}
