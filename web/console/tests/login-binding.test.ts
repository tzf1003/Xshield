import assert from "node:assert/strict";
import { test } from "node:test";
import type { LoginUnbound } from "../src/api/types.ts";
import { LOGIN_UNBOUND_TEXT } from "../src/lib/vocab.ts";

const REASONS: LoginUnbound[] = ["login_ambiguous", "login_expired", "login_unmatched"];

test("every reason a credential leaves a login unbound has a name and an explanation", () => {
  for (const reason of REASONS) {
    const text = LOGIN_UNBOUND_TEXT[reason];
    assert.ok(text.name.length > 0, `${reason} has a name`);
    assert.ok(text.desc.length > 0, `${reason} has an explanation`);
  }
});

test("the three reasons read as three different things", () => {
  const names = new Set(REASONS.map((reason) => LOGIN_UNBOUND_TEXT[reason].name));
  assert.equal(names.size, REASONS.length);
});

test("an expired login says how long a login waits for its credential", () => {
  assert.match(LOGIN_UNBOUND_TEXT.login_expired.desc, /5 分钟/);
});
