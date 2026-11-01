// Batch lookup: reads what was pasted (a test-suite table, a log, or plain IDs), finds the request
// identifiers in it, and compares the expected verdict column with what the gateway recorded
// (docs/06 6.4.3). Pure functions, so the rules are tested without the page.

import { findRequestIds, isRequestId } from "../../lib/ids.ts";
import type { LookupRow } from "../../api/types.ts";

export const MAX_BATCH_IDS = 1000;

export type Table = { headers: string[]; rows: string[][]; delimiter: "\t" | "," };

export type Paste = {
  ids: string[];
  /** Present when the first line names columns; the other columns are kept for display. */
  table: Table | null;
  /** Index into the table headers of the expected-verdict column, or null when none is found. */
  expectedColumn: number | null;
};

const EXPECTED_HEADERS = /^(outcome|expected|expect|预期)$/i;

/** Splits a row on the delimiter of its header, without splitting inside quotes. */
function splitRow(line: string, delimiter: "\t" | ","): string[] {
  if (delimiter === "\t") return line.split("\t").map((cell) => cell.trim());
  const cells: string[] = [];
  let cell = "";
  let quoted = false;
  for (const char of line) {
    if (char === '"') {
      quoted = !quoted;
    } else if (char === "," && !quoted) {
      cells.push(cell.trim());
      cell = "";
    } else {
      cell += char;
    }
  }
  cells.push(cell.trim());
  return cells;
}

export function parsePaste(text: string): Paste {
  const ids = findRequestIds(text);
  const lines = text
    .split(/\r?\n/)
    .map((line) => line.trimEnd())
    .filter((line) => line.trim().length > 0);
  const header = lines[0];
  if (header === undefined) return { ids, table: null, expectedColumn: null };

  const delimiter = header.includes("\t") ? "\t" : header.includes(",") ? "," : null;
  if (delimiter === null) return { ids, table: null, expectedColumn: null };

  const headers = splitRow(header, delimiter);
  const hasIdColumn = headers.some((cell) => cell.includes("request_id") || cell.includes("请求"));
  const rows = lines.slice(1).map((line) => splitRow(line, delimiter));
  const hasIdCells = rows.some((row) => row.some((cell) => isRequestId(cell)));
  if (!hasIdColumn && !hasIdCells) return { ids, table: null, expectedColumn: null };

  const expectedIndex = headers.findIndex((cell) => EXPECTED_HEADERS.test(cell));
  return {
    ids,
    table: { headers, rows, delimiter },
    expectedColumn: expectedIndex >= 0 ? expectedIndex : null,
  };
}

/** The request id in one row of the table, when the row has one. */
export function rowId(row: string[]): string | null {
  return row.find((cell) => isRequestId(cell)) ?? null;
}

/** Normalises the value of a pasted expected column (docs/06 6.4.3); other values are not compared. */
export function expectedOf(raw: string | undefined): "blocked" | "allowed" | null {
  const value = (raw ?? "").trim().toLowerCase();
  if (["blocked", "block", "deny", "denied", "403", "401", "拦截"].includes(value))
    return "blocked";
  if (["allowed", "allow", "pass", "ok", "200", "放行"].includes(value)) return "allowed";
  return null;
}

export type Comparison = "match" | "mismatch" | "unknown" | "none";

/** Compares the expected verdict with the recorded one. A would-block counts as a block. */
export function compare(
  expected: "blocked" | "allowed" | null,
  row: LookupRow | undefined,
): Comparison {
  if (expected === null) return "none";
  if (!row || !row.found || !row.summary) return "unknown";
  const actual = row.summary.outcome;
  const blocked = actual === "blocked" || actual === "would_block";
  return (expected === "blocked") === blocked ? "match" : "mismatch";
}
