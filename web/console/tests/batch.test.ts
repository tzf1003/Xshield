import assert from "node:assert/strict";
import { test } from "node:test";

import type { LookupRow, Outcome, RequestRow } from "../src/api/types.ts";
import { compare, expectedOf, parsePaste, rowId } from "../src/features/requests/batch.ts";
import { lookup, requestList } from "./helpers/fixtures.ts";

// Request ids of the request-detail samples in tests/fixtures.
const LOGIN = "req_01a1971a07e079639a823d4257b43172";
const BASKET = "req_01a1973940107ebea1af2c54ce635f38";
const SEARCH = "req_01a1973ed5c0732b8f29804d7fc746d3";

/** The first row of the request list sample, the base for lookup rows with another outcome. */
function sampleRow(): RequestRow {
  const row = requestList.rows[0];
  assert.ok(row, "the request list sample has rows");
  return row;
}

function found(outcome: Outcome): LookupRow {
  const sample = sampleRow();
  return { request_id: sample.request_id, found: true, summary: { ...sample, outcome } };
}

test("a plain list of ids gives each id once, in the order it first appears", () => {
  const paste = parsePaste(`2026-11-01 13:20:01 ${LOGIN} 200\n${BASKET}\n${LOGIN}\n`);
  assert.deepEqual(paste.ids, [LOGIN, BASKET]);
  assert.equal(paste.table, null);
  assert.equal(paste.expectedColumn, null);
});

test("a tab-separated table keeps its cells and finds the expected column", () => {
  const paste = parsePaste(
    [
      "request_id\tpath\toutcome",
      `${LOGIN}\t/rest/products\tblocked`,
      `${BASKET}\t/rest/basket\tallowed`,
    ].join("\n"),
  );
  assert.deepEqual(paste.ids, [LOGIN, BASKET]);
  assert.deepEqual(paste.table, {
    headers: ["request_id", "path", "outcome"],
    rows: [
      [LOGIN, "/rest/products", "blocked"],
      [BASKET, "/rest/basket", "allowed"],
    ],
    delimiter: "\t",
  });
  assert.equal(paste.expectedColumn, 2);
});

test("a comma table keeps commas inside quotes", () => {
  const paste = parsePaste(`request_id,expected,note\n${SEARCH},allow,"login, then search"`);
  assert.equal(paste.table?.delimiter, ",");
  assert.deepEqual(paste.table?.rows, [[SEARCH, "allow", "login, then search"]]);
  assert.equal(paste.expectedColumn, 1);
});

test("a table without an id column is still read when its rows hold ids", () => {
  const paste = parsePaste(`path\texpected\n/rest/products\tallow\n${LOGIN}\tblocked`);
  assert.deepEqual(paste.ids, [LOGIN]);
  assert.deepEqual(paste.table?.headers, ["path", "expected"]);
  assert.equal(paste.expectedColumn, 1);
});

test("a header with neither an id column nor id cells is not a table", () => {
  const paste = parsePaste("path\texpected\n/rest/products\tallow");
  assert.deepEqual(paste, { ids: [], table: null, expectedColumn: null });
});

test("Chinese headers name the id column and the expected column", () => {
  const paste = parsePaste(`请求\t预期\n${LOGIN}\t拦截`);
  assert.deepEqual(paste.table?.headers, ["请求", "预期"]);
  assert.equal(paste.expectedColumn, 1);
});

test("the expected column matches the whole header in any letter case", () => {
  assert.equal(parsePaste(`request_id\tOutcome\n${LOGIN}\tblocked`).expectedColumn, 1);
  assert.equal(parsePaste(`request_id\toutcome_note\n${LOGIN}\tblocked`).expectedColumn, null);
});

test("CRLF line endings and blank lines are ignored", () => {
  const paste = parsePaste(`request_id\toutcome\r\n\r\n${LOGIN}\tblocked\r\n\r\n`);
  assert.deepEqual(paste.ids, [LOGIN]);
  assert.deepEqual(paste.table?.rows, [[LOGIN, "blocked"]]);
});

test("cells are trimmed", () => {
  const paste = parsePaste(`request_id\toutcome\n  ${LOGIN}  \t blocked `);
  assert.deepEqual(paste.table?.rows, [[LOGIN, "blocked"]]);
});

test("rowId returns the first id cell of a row, or null", () => {
  assert.equal(rowId(["1", LOGIN, "blocked"]), LOGIN);
  assert.equal(rowId(["blocked", "/rest/products"]), null);
  assert.equal(rowId([]), null);
});

test("expectedOf reads the verdict words, ignoring case and surrounding spaces", () => {
  for (const word of ["blocked", "block", "deny", "denied", "403", "401", "拦截", " BLOCK "]) {
    assert.equal(expectedOf(word), "blocked", word);
  }
  for (const word of ["allowed", "allow", "pass", "ok", "200", "放行", "Allow "]) {
    assert.equal(expectedOf(word), "allowed", word);
  }
  for (const word of ["", "maybe", undefined]) {
    assert.equal(expectedOf(word), null, String(word));
  }
});

test("compare is none without an expected verdict and unknown without a found row", () => {
  assert.equal(compare(null, found("blocked")), "none");
  assert.equal(compare("blocked", undefined), "unknown");
  assert.equal(compare("blocked", { request_id: LOGIN, found: false }), "unknown");
});

test("compare counts a would-block as a block and an unjudged row as not blocked", () => {
  assert.equal(compare("blocked", found("blocked")), "match");
  assert.equal(compare("blocked", found("would_block")), "match");
  assert.equal(compare("blocked", found("allowed")), "mismatch");
  assert.equal(compare("blocked", found("unjudged")), "mismatch");
  assert.equal(compare("allowed", found("allowed")), "match");
  assert.equal(compare("allowed", found("would_block")), "mismatch");
});

test("compare on the lookup sample agrees with the recorded outcome", () => {
  const hit = lookup.rows.find((row) => row.found);
  const missing = lookup.rows.find((row) => !row.found);
  assert.ok(hit, "the lookup sample has a found row");
  assert.ok(missing, "the lookup sample has a row that was not found");
  const outcome = hit.summary?.outcome;
  const blocked = outcome === "blocked" || outcome === "would_block";
  assert.equal(compare(blocked ? "blocked" : "allowed", hit), "match");
  assert.equal(compare("blocked", missing), "unknown");
});
