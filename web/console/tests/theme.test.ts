import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { cssVariableName, themeCss } from "../src/theme/css.ts";
import {
  DENSITY_STORAGE_KEY,
  documentAttributes,
  type PreferenceStorage,
  parseDensityPreference,
  parseThemePreference,
  readDensityPreference,
  readThemePreference,
  resolveThemeMode,
  THEME_STORAGE_KEY,
  writeDensityPreference,
  writeThemePreference,
} from "../src/theme/preference.ts";
import { type Palette, palettes } from "../src/theme/tokens.ts";

const read = (path: string) => readFileSync(new URL(path, import.meta.url), "utf8");

function luminance(hex: string): number {
  const value = Number.parseInt(hex.slice(1), 16);
  const channel = (shift: number) => {
    const c = ((value >> shift) & 255) / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel(16) + 0.7152 * channel(8) + 0.0722 * channel(0);
}

function contrast(foreground: string, background: string): number {
  const [light, dark] = [luminance(foreground), luminance(background)].sort((a, b) => b - a);
  return ((light ?? 0) + 0.05) / ((dark ?? 0) + 0.05);
}

test("the committed CSS variable layer is generated from the token object", () => {
  assert.equal(
    read("../src/theme/tokens.generated.css"),
    themeCss(),
    "run `npm run theme:css` after editing src/theme/tokens.ts",
  );
});

test("variable names are stable kebab-case", () => {
  assert.equal(cssVariableName("surfaceSubtle"), "--xs-surface-subtle");
  assert.equal(cssVariableName("ink2"), "--xs-ink-2");
  assert.equal(cssVariableName("sidebarInkMuted"), "--xs-sidebar-ink-muted");
});

test("brand palette keeps the owner-approved anchor colours", () => {
  assert.equal(palettes.light.primary, "#3550D4");
  assert.equal(palettes.dark.primary, "#8098FF");
  assert.equal(palettes.light.ink, "#121A2B");
  assert.equal(palettes.dark.ink, "#E6EBF4");
  assert.equal(palettes.light.canvas, "#F2F4F8");
  assert.equal(palettes.dark.canvas, "#0A0F1C");
  assert.equal(palettes.light.surface, "#FFFFFF");
  assert.equal(palettes.dark.surface, "#111929");
  assert.equal(palettes.light.sidebar, "#0F1A33");
  assert.equal(palettes.dark.sidebar, "#070C17");
  assert.deepEqual(
    [palettes.light.allow, palettes.light.deny, palettes.light.observe, palettes.light.info],
    ["#167A42", "#C2303B", "#A35F0A", "#1F6FB8"],
  );
  assert.deepEqual(
    [palettes.dark.allow, palettes.dark.deny, palettes.dark.observe, palettes.dark.info],
    ["#4FC37E", "#F2767F", "#E5A84C", "#6CB0F0"],
  );
  assert.equal(palettes.light.unknown, "#5F6B84");
  assert.equal(palettes.dark.unknown, "#94A0B6");
});

test("every text pairing meets WCAG AA (4.5:1) in light and dark", () => {
  for (const [mode, p] of Object.entries(palettes) as [string, Palette][]) {
    const pairs: [string, string, string][] = [];
    for (const surface of ["canvas", "surface", "surfaceSubtle"] as const) {
      for (const ink of ["ink", "ink2", "ink3", "primary"] as const) {
        pairs.push([ink, surface, `${ink} on ${surface}`]);
      }
    }
    pairs.push(["onPrimary", "primary", "button label"]);
    pairs.push(["onPrimary", "primaryHover", "hovered button label"]);
    pairs.push(["primary", "primarySoft", "link on tinted row"]);
    pairs.push(["ink", "primarySoft", "text on selected row"]);
    pairs.push(["sidebarInk", "sidebar", "sidebar link"]);
    pairs.push(["sidebarInkMuted", "sidebar", "sidebar group label"]);
    pairs.push(["sidebarActiveInk", "sidebarActive", "active sidebar link"]);
    pairs.push(["sidebarInk", "sidebarHover", "hovered sidebar link"]);
    for (const tone of ["allow", "deny", "observe", "info", "unknown"] as const) {
      pairs.push([tone, "surface", `${tone} on surface`]);
      pairs.push([tone, `${tone}Soft`, `${tone} on its soft background`]);
      pairs.push(["ink", `${tone}Soft`, `body text on ${tone}Soft`]);
    }
    for (const [foreground, background, label] of pairs) {
      const ratio = contrast(p[foreground as keyof Palette], p[background as keyof Palette]);
      assert.ok(ratio >= 4.5, `${mode}: ${label} is ${ratio.toFixed(2)}:1`);
    }
  }
});

test("the legacy and the case/approval stylesheets use tokens only and every variable they read exists", () => {
  const defined = new Set(read("../src/theme/tokens.generated.css").match(/--xs-[a-z0-9-]+(?=:)/g));
  for (const file of ["../src/style.css", "../src/work/work.css"]) {
    const style = read(file).replace(/\/\*[\s\S]*?\*\//g, "");
    assert.deepEqual(style.match(/#[0-9a-fA-F]{3,8}\b|\brgba?\(|\bhsla?\(/g) ?? [], [], file);
    const used = new Set(style.match(/var\((--xs-[a-z0-9-]+)\)/g)?.map((v) => v.slice(4, -1)));
    const missing = [...used].filter((name) => !defined.has(name));
    assert.deepEqual(missing, [], file);
  }
});

test("generated CSS follows the system theme without a script and honours explicit overrides", () => {
  const css = themeCss();
  assert.match(
    css,
    /@media \(prefers-color-scheme: dark\) \{\s*:root:not\(\[data-theme="light"\]\)/,
  );
  assert.match(css, /:root\[data-theme="dark"\] \{/);
  assert.match(css, /:root\[data-density="compact"\] \{/);
  assert.ok(css.indexOf("--xs-primary: #3550D4") < css.indexOf("--xs-primary: #8098FF"));
});

class MemoryStorage implements PreferenceStorage {
  readonly values = new Map<string, string>();
  getItem(key: string) {
    return this.values.get(key) ?? null;
  }
  setItem(key: string, value: string) {
    this.values.set(key, value);
  }
  removeItem(key: string) {
    this.values.delete(key);
  }
}

test("theme and density preferences fall back to safe defaults", () => {
  for (const raw of [null, undefined, "", "blue", 1, {}, "LIGHT"]) {
    assert.equal(parseThemePreference(raw), "system");
    assert.equal(parseDensityPreference(raw), "comfortable");
  }
  assert.equal(parseThemePreference("dark"), "dark");
  assert.equal(parseThemePreference("light"), "light");
  assert.equal(parseDensityPreference("compact"), "compact");
});

test("system preference resolves through the operating system, explicit choices do not", () => {
  assert.equal(resolveThemeMode("system", true), "dark");
  assert.equal(resolveThemeMode("system", false), "light");
  assert.equal(resolveThemeMode("light", true), "light");
  assert.equal(resolveThemeMode("dark", false), "dark");
});

test("only the two presentation keys are ever written, and defaults leave storage empty", () => {
  const storage = new MemoryStorage();
  assert.equal(writeThemePreference(storage, "system"), true);
  assert.equal(writeDensityPreference(storage, "comfortable"), true);
  assert.equal(storage.values.size, 0);
  writeThemePreference(storage, "dark");
  writeDensityPreference(storage, "compact");
  assert.deepEqual([...storage.values.entries()].sort(), [
    [DENSITY_STORAGE_KEY, "compact"],
    [THEME_STORAGE_KEY, "dark"],
  ]);
  assert.equal(readThemePreference(storage), "dark");
  assert.equal(readDensityPreference(storage), "compact");
  writeThemePreference(storage, "system");
  assert.equal(storage.getItem(THEME_STORAGE_KEY), null);
});

test("blocked or throwing storage never breaks the preference path", () => {
  const throwing: PreferenceStorage = {
    getItem() {
      throw new DOMException("blocked", "SecurityError");
    },
    setItem() {
      throw new DOMException("quota", "QuotaExceededError");
    },
    removeItem() {
      throw new DOMException("blocked", "SecurityError");
    },
  };
  assert.equal(readThemePreference(throwing), "system");
  assert.equal(readDensityPreference(throwing), "comfortable");
  assert.equal(writeThemePreference(throwing, "dark"), false);
  assert.equal(writeThemePreference(throwing, "system"), false);
  assert.equal(readThemePreference(null), "system");
  assert.equal(writeDensityPreference(null, "compact"), false);
});

test("document attributes are only set for explicit choices", () => {
  assert.deepEqual(documentAttributes("system", "comfortable"), { theme: null, density: null });
  assert.deepEqual(documentAttributes("dark", "compact"), { theme: "dark", density: "compact" });
  assert.deepEqual(documentAttributes("light", "comfortable"), { theme: "light", density: null });
});
