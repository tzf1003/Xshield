import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

const root = new URL("../src/", import.meta.url).pathname;

function* stylesheets(dir: string): Generator<string> {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) yield* stylesheets(path);
    else if (entry.name.endsWith(".css") && !path.endsWith("tokens.generated.css")) yield path;
  }
}

// Same rule as the legacy stylesheet (tests/theme.test.ts): colours come from --xs-* tokens only,
// and every token a stylesheet reads must exist, so new pages follow light, dark and system.
test("every stylesheet added since the shell uses tokens only and reads defined variables", () => {
  const defined = new Set(
    readFileSync(join(root, "theme/tokens.generated.css"), "utf8").match(/--xs-[a-z0-9-]+(?=:)/g),
  );
  const checked: string[] = [];
  for (const path of stylesheets(root)) {
    if (path.endsWith("/style.css") || path.endsWith("/shell/shell.css")) continue;
    checked.push(path);
    const css = readFileSync(path, "utf8").replace(/\/\*[\s\S]*?\*\//g, "");
    assert.deepEqual(css.match(/#[0-9a-fA-F]{3,8}\b|\brgba?\(|\bhsla?\(/g) ?? [], [], path);
    const used = [...css.matchAll(/var\((--xs-[a-z0-9-]+)\)/g)].map((match) => match[1] ?? "");
    assert.deepEqual(
      used.filter((name) => !defined.has(name)),
      [],
      path,
    );
  }
  assert.ok(checked.length > 0, "at least the shared UI stylesheet is checked");
});
