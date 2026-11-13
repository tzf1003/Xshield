// The destination after login (docs/06 6.4.1): only a path inside the console.

import assert from "node:assert/strict";
import { test } from "node:test";
import { validateLogin } from "../src/app/search-schema.ts";

test("a path inside the console is kept as the destination", () => {
  assert.equal(validateLogin({ next: "/requests?site=emr" }).next, "/requests?site=emr");
  assert.equal(validateLogin({ next: "/" }).next, "/");
});

test("anything a browser could read as another origin is dropped", () => {
  for (const next of [
    "//evil.test",
    "/\\evil.test",
    "/\\/evil.test",
    "/a\\b",
    "/\t/evil.test",
    "/\n/evil.test",
    "https://evil.test",
    "requests",
    "",
    7,
    null,
  ]) {
    assert.equal(validateLogin({ next }).next, undefined, JSON.stringify(next));
  }
  assert.equal(validateLogin({}).next, undefined);
});
